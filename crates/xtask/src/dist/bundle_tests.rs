use std::os::unix::fs::PermissionsExt;

use super::*;

/// Fake build outputs for a release, under `dir`.
fn fake_inputs(dir: &Path, binaries: &[&str]) -> Inputs {
    let built = dir.join("built");
    let mut pairs = Vec::new();
    for name in binaries {
        let path = built.join(name);
        write_file(&path, format!("binary {name}\n").as_bytes(), true).unwrap();
        pairs.push(((*name).to_owned(), path));
    }
    let client = dir.join("client");
    write_file(
        &client.join("package.json"),
        b"{\"type\":\"module\"}\n",
        false,
    )
    .unwrap();
    write_file(&client.join("package-lock.json"), b"{}\n", false).unwrap();
    write_file(&client.join("dist/cli.js"), b"console.log('hi')\n", true).unwrap();
    write_file(&client.join("dist/commands/a.js"), b"export {}\n", false).unwrap();
    let node = dir.join("node");
    write_file(&node.join("bin/node"), b"node\n", true).unwrap();
    write_file(&node.join("LICENSE"), b"node license\n", false).unwrap();
    let license = dir.join("LICENSE");
    write_file(&license, b"MIT\n", false).unwrap();
    Inputs {
        binaries: pairs,
        client_package: client.clone(),
        client_dist: client.join("dist"),
        node,
        license,
    }
}

fn info() -> ReleaseInfo {
    ReleaseInfo {
        version: "0.6.0".into(),
        target: Target::MacosArm64,
        commit: "0123456789abcdef0123456789abcdef01234567".into(),
        dirty: false,
        source_date_epoch: 1_700_000_000,
        node_version: "24.22.2".into(),
    }
}

/// Assembles a complete fake release named after `info()` and returns its directory.
fn fake_release(dir: &Path) -> PathBuf {
    let inputs = fake_inputs(
        &dir.join("inputs"),
        &["agentpay-daemon", "agentpay-paymentd", "agentpay-setup"],
    );
    let release = dir
        .join("stage")
        .join(Target::MacosArm64.release_name("0.6.0"));
    assemble(&release, &inputs).unwrap();
    write_manifest(&release, &info()).unwrap();
    release
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o7777
}

#[test]
fn assemble_lays_out_bin_libexec_client_and_node() {
    let dir = tempfile::tempdir().unwrap();
    let release = fake_release(dir.path());
    let paths: Vec<String> = walk(&release)
        .unwrap()
        .into_iter()
        .map(|entry| entry.path)
        .collect();
    assert_eq!(
        paths,
        [
            "LICENSE",
            "bin",
            "bin/agentpay",
            "bin/agentpay-setup",
            "client",
            "client/dist",
            "client/dist/cli.js",
            "client/dist/commands",
            "client/dist/commands/a.js",
            "client/package-lock.json",
            "client/package.json",
            "libexec",
            "libexec/agentpay-daemon",
            "libexec/agentpay-paymentd",
            "libexec/agentpay-setup",
            "manifest.json",
            "node",
            "node/LICENSE",
            "node/bin",
            "node/bin/node",
        ]
    );
    assert_eq!(mode(&release.join("bin/agentpay")), 0o755);
    assert_eq!(mode(&release.join("libexec/agentpay-daemon")), 0o755);
    assert_eq!(mode(&release.join("node/bin/node")), 0o755);
    assert_eq!(mode(&release.join("client/package.json")), 0o644);
    assert_eq!(
        std::fs::read_link(release.join("bin/agentpay-setup")).unwrap(),
        Path::new("../libexec/agentpay-setup")
    );
    assert_eq!(
        std::fs::read_to_string(release.join("bin/agentpay")).unwrap(),
        LAUNCHER
    );
}

#[test]
fn assemble_refuses_an_existing_directory_and_a_release_without_setup() {
    let dir = tempfile::tempdir().unwrap();
    let inputs = fake_inputs(dir.path(), &["agentpay-daemon"]);
    let error = assemble(&dir.path().join("release"), &inputs).unwrap_err();
    assert!(error.to_string().contains("agentpay-setup"), "{error:#}");
    let error = assemble(dir.path(), &inputs).unwrap_err();
    assert!(error.to_string().contains("already exists"), "{error:#}");
}

#[test]
fn launcher_runs_the_bundled_client_on_the_bundled_node() {
    assert!(LAUNCHER.starts_with("#!/bin/sh\n"));
    assert!(LAUNCHER.contains("node=\"$root/node/bin/node\""));
    assert!(LAUNCHER.contains("entry=\"$root/client/dist/cli.js\""));
    assert!(LAUNCHER.contains("PATH=\"$root/libexec:$PATH\""));
    assert!(LAUNCHER.contains("exec \"$node\" \"$entry\" \"$@\""));
}

#[test]
fn manifest_lists_files_and_links_with_digests() {
    let dir = tempfile::tempdir().unwrap();
    let release = fake_release(dir.path());
    let text = std::fs::read_to_string(release.join(MANIFEST)).unwrap();
    let manifest: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(manifest["schema"], 1);
    assert_eq!(manifest["version"], "0.6.0");
    assert_eq!(manifest["os"], "macos");
    assert_eq!(manifest["arch"], "arm64");
    assert_eq!(manifest["target"], "aarch64-apple-darwin");
    assert_eq!(manifest["node"], "24.22.2");
    // The installer reads these fields with sed, one per line.
    for line in [
        "  \"version\": \"0.6.0\"",
        "  \"os\": \"macos\"",
        "  \"arch\": \"arm64\"",
    ] {
        assert!(
            text.lines().any(|l| l.trim_end_matches(',') == line),
            "{line}"
        );
    }

    let files = manifest["files"].as_array().unwrap();
    let paths: Vec<&str> = files.iter().map(|f| f["path"].as_str().unwrap()).collect();
    let mut sorted = paths.clone();
    sorted.sort_unstable();
    assert_eq!(paths, sorted);
    assert!(!paths.contains(&MANIFEST));
    assert!(!paths.contains(&"bin"), "directories are not listed");

    let launcher = files.iter().find(|f| f["path"] == "bin/agentpay").unwrap();
    assert_eq!(launcher["mode"], "0755");
    assert_eq!(launcher["size"], LAUNCHER.len());
    assert_eq!(
        launcher["sha256"],
        sha256_file(&release.join("bin/agentpay")).unwrap()
    );
    let link = files
        .iter()
        .find(|f| f["path"] == "bin/agentpay-setup")
        .unwrap();
    assert_eq!(link["link"], "../libexec/agentpay-setup");
    let package = files
        .iter()
        .find(|f| f["path"] == "client/package.json")
        .unwrap();
    assert_eq!(package["mode"], "0644");
}

#[test]
fn tarballs_are_byte_for_byte_reproducible() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let release_a = fake_release(first.path());
    let release_b = fake_release(second.path());
    // Different on-disk metadata must not leak into the archive.
    std::fs::set_permissions(
        release_b.join("LICENSE"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let a = write_tarball(&release_a, &first.path().join("a.tar.gz"), 1_700_000_000).unwrap();
    let b = write_tarball(&release_b, &second.path().join("b.tar.gz"), 1_700_000_000).unwrap();
    // LICENSE's mode is normalized from its executable bit, so 0600 still packs as 0644.
    assert_eq!(a, b);
    let c = write_tarball(&release_a, &first.path().join("c.tar.gz"), 1_700_000_001).unwrap();
    assert_ne!(a, c, "the mtime is part of the archive");
}

#[test]
fn tarball_entries_are_sorted_normalized_and_under_one_directory() {
    let dir = tempfile::tempdir().unwrap();
    let release = fake_release(dir.path());
    let out = dir.path().join("release.tar.gz");
    write_tarball(&release, &out, 1_700_000_000).unwrap();

    let file = File::open(&out).unwrap();
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(file));
    let mut seen = Vec::new();
    for entry in archive.entries().unwrap() {
        let entry = entry.unwrap();
        let header = entry.header();
        let path = entry.path().unwrap().to_string_lossy().into_owned();
        assert_eq!(header.uid().unwrap(), 0, "{path}");
        assert_eq!(header.gid().unwrap(), 0, "{path}");
        assert_eq!(header.mtime().unwrap(), 1_700_000_000, "{path}");
        assert_eq!(header.username().unwrap(), Some(""), "{path}");
        let mode = header.mode().unwrap();
        match header.entry_type() {
            tar::EntryType::Directory => assert_eq!(mode, 0o755, "{path}"),
            tar::EntryType::Symlink => {
                assert_eq!(
                    entry.link_name().unwrap().unwrap(),
                    Path::new("../libexec/agentpay-setup")
                );
            }
            _ => assert!(mode == 0o755 || mode == 0o644, "{path}: {mode:o}"),
        }
        seen.push(path.trim_end_matches('/').to_owned());
    }
    let top = "agentpay-0.6.0-macos-arm64";
    assert_eq!(seen[0], top);
    assert!(seen[1..]
        .iter()
        .all(|path| path.starts_with(&format!("{top}/"))));
    let mut sorted = seen.clone();
    sorted.sort();
    assert_eq!(seen, sorted);
    for required in [
        "bin/agentpay",
        "bin/agentpay-setup",
        "libexec/agentpay-setup",
        "client/dist/cli.js",
        "node/bin/node",
        "manifest.json",
    ] {
        assert!(seen.contains(&format!("{top}/{required}")), "{required}");
    }
}

#[test]
fn checksums_cover_only_this_versions_tarballs_sorted() {
    let dir = tempfile::tempdir().unwrap();
    for name in [
        "agentpay-0.6.0-macos-x86_64.tar.gz",
        "agentpay-0.6.0-linux-x86_64.tar.gz",
        "agentpay-0.5.0-linux-x86_64.tar.gz",
        "agentpay-0.6.0-notes.txt",
    ] {
        std::fs::write(dir.path().join(name), name).unwrap();
    }
    let path = write_checksums(dir.path(), "0.6.0").unwrap();
    let text = std::fs::read_to_string(path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert!(lines[0].ends_with("  agentpay-0.6.0-linux-x86_64.tar.gz"));
    assert!(lines[1].ends_with("  agentpay-0.6.0-macos-x86_64.tar.gz"));
    let digest = sha256_file(&dir.path().join("agentpay-0.6.0-linux-x86_64.tar.gz")).unwrap();
    assert_eq!(
        lines[0],
        format!("{digest}  agentpay-0.6.0-linux-x86_64.tar.gz")
    );
}

#[test]
fn checksum_text_is_sorted_by_name() {
    let text = checksums_text(vec![
        ("b.tar.gz".into(), "22".into()),
        ("a.tar.gz".into(), "11".into()),
    ]);
    assert_eq!(text, "11  a.tar.gz\n22  b.tar.gz\n");
}

#[test]
fn leak_scan_finds_builder_paths_outside_skipped_prefixes() {
    let dir = tempfile::tempdir().unwrap();
    let release = fake_release(dir.path());
    assert!(find_leaks(&release, &["/Users/builder".into()], &[])
        .unwrap()
        .is_empty());
    write_file(
        &release.join("libexec/agentpay-daemon"),
        b"panic at /Users/builder/src/main.rs",
        true,
    )
    .unwrap();
    write_file(&release.join("node/bin/node"), b"/Users/builder/node", true).unwrap();
    assert_eq!(
        find_leaks(&release, &["/Users/builder".into()], &["node/"]).unwrap(),
        ["libexec/agentpay-daemon"]
    );
    // A one-character needle (HOME=/) would match everything; it is ignored.
    assert!(find_leaks(&release, &["/".into()], &[]).unwrap().is_empty());
}

#[test]
fn sha256_matches_a_known_vector() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("abc");
    std::fs::write(&path, b"abc").unwrap();
    assert_eq!(
        sha256_file(&path).unwrap(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
