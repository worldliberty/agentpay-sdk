//! The `test-install` scenarios. Each one gets its own home directory.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};

use super::fixture::Releases;
use super::{Ctx, OLD_VERSION};
use crate::dist::bundle::{self, Kind};
use crate::dist::target::Os;

type Scenario = fn(&Ctx) -> Result<()>;

/// Every scenario, in run order.
pub const ALL: &[(&str, Scenario)] = &[
    ("fresh install of the latest release", fresh_install),
    ("rerun is idempotent", rerun_is_idempotent),
    ("curl | sh with the script on stdin", piped_install),
    ("pinned AGENTPAY_VERSION", pinned_version),
    ("checksum mismatch fails closed", checksum_mismatch),
    (
        "missing checksum entry fails closed",
        missing_checksum_entry,
    ),
    ("AGENTPAY_SHA256 pin", sha256_pin),
    (
        "protected and unknown directories are refused",
        protected_dirs,
    ),
    ("custom install directory", custom_install_dir),
    (
        "rc block replaces the old installer's block",
        rc_block_replaces_legacy,
    ),
    ("symlinked rc file stays a symlink", symlinked_rc),
    ("unfinished rc block is left alone", unfinished_rc_block),
    ("bash and fish startup files", other_shells),
    ("--no-modify-path", no_modify_path),
    ("previous TypeScript install is moved aside", legacy_install),
    (
        "downgrade needs --yes, upgrade does not",
        downgrade_and_upgrade,
    ),
    ("plain http is refused", http_refused),
    ("--verbose, --help and unknown options", flags),
    (
        "next step when agentpay is already on PATH",
        already_on_path,
    ),
];

const BLOCK_BEGIN: &str = "# >>> agentpay >>>";

fn install_dir(home: &Path) -> PathBuf {
    home.join(".agentpay")
}

fn read(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
}

fn link(path: &Path) -> Result<String> {
    let target =
        std::fs::read_link(path).with_context(|| format!("{} is not a link", path.display()))?;
    Ok(target.to_string_lossy().into_owned())
}

/// Checks a completed install of `version` in `dir`.
fn check_layout(ctx: &Ctx, dir: &Path, version: &str) -> Result<()> {
    ensure!(link(&dir.join("current"))? == format!("versions/{version}"));
    ensure!(link(&dir.join("bin/agentpay"))? == "../current/bin/agentpay");
    ensure!(link(&dir.join("bin/agentpay-setup"))? == "../current/bin/agentpay-setup");
    let release = dir.join("versions").join(version);
    // agentpay-setup copies the daemon binaries from its own (resolved) directory.
    ensure!(
        std::fs::canonicalize(dir.join("bin/agentpay-setup"))?
            == std::fs::canonicalize(release.join("libexec/agentpay-setup"))?,
        "bin/agentpay-setup does not resolve into libexec"
    );
    for name in ctx.target.cargo_binaries() {
        let mode = std::fs::metadata(release.join("libexec").join(name))?
            .permissions()
            .mode();
        ensure!(mode & 0o111 != 0, "libexec/{name} is not executable");
    }
    if ctx.target.os() == Os::Macos {
        ensure!(release.join("libexec/agentpay-auth").is_file());
    }
    ensure!(release.join("manifest.json").is_file());
    ensure!(release.join("node/bin/node").is_file());
    ensure!(release.join("client/dist/cli.js").is_file());
    // agentpay-setup refuses source binaries in directories others can write to.
    for entry in bundle::walk(&release)? {
        if matches!(entry.kind, Kind::Symlink { .. }) {
            continue;
        }
        let mode = std::fs::metadata(release.join(&entry.path))?
            .permissions()
            .mode();
        ensure!(mode & 0o022 == 0, "{} is group/other-writable", entry.path);
    }
    let versions: Vec<String> = std::fs::read_dir(dir.join("versions"))?
        .map(|item| item.map(|item| item.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<_>>()?;
    ensure!(versions == [version], "versions/ holds {versions:?}");
    ensure!(!dir.join(".install-lock").exists(), "lock left behind");
    let record = read(&dir.join("installer.json"))?;
    ensure!(
        record.contains(&format!("\"version\": \"{version}\"")),
        "{record}"
    );
    Ok(())
}

/// Runs the installed `agentpay --version` and checks the answer.
fn check_runs(ctx: &Ctx, home: &Path, version: &str) -> Result<()> {
    let agentpay = install_dir(home).join("bin/agentpay");
    let run = ctx.run_program(home, &agentpay, &["--version"])?;
    run.expect_ok()?;
    ensure!(
        run.stdout.trim() == version,
        "--version printed {:?}",
        run.stdout
    );
    Ok(())
}

fn block_count(text: &str) -> usize {
    text.lines().filter(|line| *line == BLOCK_BEGIN).count()
}

fn fresh_install(ctx: &Ctx) -> Result<()> {
    let home = ctx.home("fresh")?;
    let run = ctx.install(&home, &[], &[])?;
    run.expect_ok()?;
    ensure!(
        run.stderr.is_empty(),
        "quiet by default\n{}",
        run.transcript()
    );
    for needle in [
        format!("AgentPay {} is installed.", ctx.version),
        "  1  ✓  Platform".to_owned(),
        "✓  Checksum".to_owned(),
        "SHA-256 verified".to_owned(),
        "Next: ~/.agentpay/bin/agentpay setup".to_owned(),
    ] {
        ensure!(
            run.stdout.contains(&needle),
            "missing {needle:?}\n{}",
            run.transcript()
        );
    }
    let dir = install_dir(&home);
    check_layout(ctx, &dir, ctx.version)?;
    let mode = std::fs::metadata(&dir)?.permissions().mode() & 0o777;
    ensure!(mode == 0o700, "new install directory has mode {mode:o}");
    let rc = read(&home.join(".zshrc"))?;
    ensure!(block_count(&rc) == 1, "{rc}");
    ensure!(
        rc.contains("export PATH=\"$HOME/.agentpay/bin:$PATH\""),
        "{rc}"
    );
    let leftovers = std::fs::read_dir(home.join("tmp"))?.count();
    ensure!(
        leftovers == 0,
        "the installer left {leftovers} temp entries"
    );
    check_runs(ctx, &home, ctx.version)?;
    if ctx.real {
        let help = ctx.run_program(&home, &dir.join("bin/agentpay"), &["--help"])?;
        help.expect_ok()?;
        ensure!(help.stdout.contains("setup"), "{}", help.transcript());
        let setup = ctx.run_program(&home, &dir.join("bin/agentpay-setup"), &["--version"])?;
        setup.expect_ok()?;
        ensure!(setup.stdout.contains(ctx.version), "{}", setup.transcript());
    }
    Ok(())
}

fn rerun_is_idempotent(ctx: &Ctx) -> Result<()> {
    let home = ctx.home("rerun")?;
    ctx.install(&home, &[], &[])?.expect_ok()?;
    let rc_before = std::fs::read(home.join(".zshrc"))?;
    let run = ctx.install(&home, &[], &[])?;
    run.expect_ok()?;
    ensure!(
        std::fs::read(home.join(".zshrc"))? == rc_before,
        "rc file changed"
    );
    ensure!(
        run.stdout.contains("already set in ~/.zshrc"),
        "{}",
        run.transcript()
    );
    ensure!(run.stdout.contains("(reinstalled)"), "{}", run.transcript());
    check_layout(ctx, &install_dir(&home), ctx.version)
}

fn piped_install(ctx: &Ctx) -> Result<()> {
    let home = ctx.home("piped")?;
    ctx.install_piped(&home, &["--yes"])?.expect_ok()?;
    check_layout(ctx, &install_dir(&home), ctx.version)?;
    check_runs(ctx, &home, ctx.version)
}

fn pinned_version(ctx: &Ctx) -> Result<()> {
    let home = ctx.home("pinned")?;
    let tag = format!("v{}", ctx.version);
    let run = ctx.install(&home, &[("AGENTPAY_VERSION", &tag)], &[])?;
    run.expect_ok()?;
    ensure!(!run.stdout.contains("(latest)"), "{}", run.transcript());
    check_layout(ctx, &install_dir(&home), ctx.version)?;

    let missing = ctx.home("pinned-missing")?;
    ctx.install(&missing, &[("AGENTPAY_VERSION", "9.9.9")], &[])?
        .expect_failure("could not download")?;
    ctx.install(&missing, &[("AGENTPAY_VERSION", "1.0;rm -rf")], &[])?
        .expect_failure("is not a version")?;
    ensure!(
        !install_dir(&missing).exists(),
        "a failed install created files"
    );
    Ok(())
}

/// A copy of the good release tree for `ctx.version`, published as latest.
fn release_copy(ctx: &Ctx, name: &str) -> Result<Releases> {
    let releases = Releases::new(ctx.work.join(name))?;
    releases.publish(ctx.version, &ctx.tarball, true)?;
    Ok(releases)
}

fn checksum_mismatch(ctx: &Ctx) -> Result<()> {
    let releases = release_copy(ctx, "releases-tampered")?;
    let asset = ctx.target.asset_name(ctx.version);
    let tampered = releases.file(ctx.version, &asset);
    let mut bytes = std::fs::read(&tampered)?;
    bytes.push(0);
    std::fs::write(&tampered, bytes)?;

    let home = ctx.home("tampered")?;
    let url = releases.url();
    let run = ctx.install(&home, &[("AGENTPAY_RELEASES_URL", &url)], &["--yes"])?;
    run.expect_failure("SHA-256 mismatch")?;
    ensure!(run.stderr.contains("✗  Checksum"), "{}", run.transcript());
    ensure!(
        run.stderr.contains("Nothing was installed"),
        "{}",
        run.transcript()
    );
    ensure!(
        !install_dir(&home).exists(),
        "files were installed from a bad tarball"
    );
    Ok(())
}

fn missing_checksum_entry(ctx: &Ctx) -> Result<()> {
    let releases = release_copy(ctx, "releases-no-entry")?;
    let other = format!(
        "{}  agentpay-{}-plan9-mips.tar.gz\n",
        "0".repeat(64),
        ctx.version
    );
    std::fs::write(releases.checksums(ctx.version), other)?;
    let home = ctx.home("no-entry")?;
    let url = releases.url();
    ctx.install(
        &home,
        &[
            ("AGENTPAY_RELEASES_URL", &url),
            ("AGENTPAY_VERSION", ctx.version),
        ],
        &[],
    )?
    .expect_failure("has no valid entry")?;
    ensure!(!install_dir(&home).exists());
    Ok(())
}

fn sha256_pin(ctx: &Ctx) -> Result<()> {
    let home = ctx.home("pin-wrong")?;
    let zeros = "0".repeat(64);
    ctx.install(&home, &[("AGENTPAY_SHA256", &zeros)], &[])?
        .expect_failure("not the pinned AGENTPAY_SHA256")?;
    ensure!(!install_dir(&home).exists());

    let home = ctx.home("pin-right")?;
    let digest = bundle::sha256_file(&ctx.tarball)?.to_uppercase();
    ctx.install(&home, &[("AGENTPAY_SHA256", &digest)], &[])?
        .expect_ok()?;
    check_layout(ctx, &install_dir(&home), ctx.version)
}

fn protected_dirs(ctx: &Ctx) -> Result<()> {
    let home = ctx.home("protected")?;
    let home_str = home.display().to_string();
    let usr_local_existed = Path::new("/usr/local/agentpay").exists();
    for dir in [
        home_str.as_str(),
        "~",
        "/",
        "/usr",
        "/usr/local/agentpay",
        "/opt",
        "/opt/agentpay",
        "/Library/AgentPay",
    ] {
        ctx.install(&home, &[("AGENTPAY_INSTALL_DIR", dir)], &["--yes"])?
            .expect_failure("refusing to install")
            .with_context(|| format!("AGENTPAY_INSTALL_DIR={dir}"))?;
    }
    ensure!(usr_local_existed || !Path::new("/usr/local/agentpay").exists());

    let unknown = home.join("projects");
    std::fs::create_dir_all(&unknown)?;
    std::fs::write(unknown.join("notes.txt"), "mine")?;
    let unknown_str = unknown.display().to_string();
    ctx.install(&home, &[("AGENTPAY_INSTALL_DIR", &unknown_str)], &["--yes"])?
        .expect_failure("is not empty and is not an AgentPay directory")?;
    ensure!(read(&unknown.join("notes.txt"))? == "mine");
    ensure!(
        std::fs::read_dir(&unknown)?.count() == 1,
        "files were added"
    );

    let odd = format!("{home_str}/a$b");
    ctx.install(&home, &[("AGENTPAY_INSTALL_DIR", &odd)], &["--yes"])?
        .expect_failure("contains quotes")?;
    ensure!(!install_dir(&home).exists() && !home.join(".zshrc").exists());
    Ok(())
}

fn custom_install_dir(ctx: &Ctx) -> Result<()> {
    let home = ctx.home("custom")?;
    ctx.install(&home, &[("AGENTPAY_INSTALL_DIR", "~/apps/agentpay")], &[])?
        .expect_ok()?;
    let dir = home.join("apps/agentpay");
    check_layout(ctx, &dir, ctx.version)?;
    let rc = read(&home.join(".zshrc"))?;
    ensure!(rc.contains("\"$HOME/apps/agentpay/bin:$PATH\""), "{rc}");
    let record = read(&dir.join("installer.json"))?;
    ensure!(
        record.contains(&format!("\"path_rc\": \"{}/.zshrc\"", home.display())),
        "{record}"
    );
    Ok(())
}

const LEGACY_BLOCK: &str = "# >>> agentpay-sdk >>>\n\
    export AGENTPAY_HOME=\"/somewhere/.agentpay\"\n\
    export PATH=\"$AGENTPAY_HOME/bin:$PATH\"\n\
    # <<< agentpay-sdk <<<\n";

fn rc_block_replaces_legacy(ctx: &Ctx) -> Result<()> {
    let home = ctx.home("rc-legacy")?;
    let before = format!("# mine\nexport FOO=1\n\n{LEGACY_BLOCK}alias ll='ls -l'\n");
    std::fs::write(home.join(".zshrc"), &before)?;
    ctx.install(&home, &[], &[])?.expect_ok()?;
    let rc = read(&home.join(".zshrc"))?;
    ensure!(
        rc.starts_with(&format!("# mine\nexport FOO=1\n\n{BLOCK_BEGIN}\n")),
        "{rc}"
    );
    ensure!(
        rc.ends_with("# <<< agentpay <<<\nalias ll='ls -l'\n"),
        "{rc}"
    );
    ensure!(
        !rc.contains("AGENTPAY_HOME") && !rc.contains("agentpay-sdk"),
        "{rc}"
    );
    ensure!(block_count(&rc) == 1, "{rc}");
    Ok(())
}

fn symlinked_rc(ctx: &Ctx) -> Result<()> {
    let home = ctx.home("rc-symlink")?;
    std::fs::create_dir_all(home.join("dotfiles"))?;
    std::fs::write(home.join("dotfiles/zshrc"), "# dotfiles\n")?;
    std::os::unix::fs::symlink("dotfiles/zshrc", home.join(".zshrc"))?;
    ctx.install(&home, &[], &[])?.expect_ok()?;
    ensure!(
        link(&home.join(".zshrc"))? == "dotfiles/zshrc",
        "the symlink was replaced"
    );
    let rc = read(&home.join("dotfiles/zshrc"))?;
    ensure!(rc.starts_with("# dotfiles\n\n# >>> agentpay >>>\n"), "{rc}");
    Ok(())
}

fn unfinished_rc_block(ctx: &Ctx) -> Result<()> {
    let home = ctx.home("rc-unfinished")?;
    let before = "# >>> agentpay >>>\nexport PATH=/mine:$PATH\nalias x=y\n";
    std::fs::write(home.join(".zshrc"), before)?;
    let run = ctx.install(&home, &[], &[])?;
    run.expect_ok()?;
    ensure!(
        read(&home.join(".zshrc"))? == before,
        "user lines were changed"
    );
    ensure!(
        run.stdout.contains("unfinished AgentPay block"),
        "{}",
        run.transcript()
    );
    check_layout(ctx, &install_dir(&home), ctx.version)
}

fn other_shells(ctx: &Ctx) -> Result<()> {
    let home = ctx.home("bash")?;
    ctx.install(&home, &[("SHELL", "/bin/bash")], &[])?
        .expect_ok()?;
    let expected = if ctx.target.os() == Os::Macos {
        ".bash_profile"
    } else {
        ".bashrc"
    };
    let rc = read(&home.join(expected))?;
    ensure!(block_count(&rc) == 1, "{expected}: {rc}");

    // On macOS an existing ~/.profile is used rather than shadowed by a new ~/.bash_profile.
    if ctx.target.os() == Os::Macos {
        let home = ctx.home("bash-profile")?;
        std::fs::write(home.join(".profile"), "# login\n")?;
        ctx.install(&home, &[("SHELL", "/bin/bash")], &[])?
            .expect_ok()?;
        ensure!(
            !home.join(".bash_profile").exists(),
            ".bash_profile shadows .profile"
        );
        ensure!(block_count(&read(&home.join(".profile"))?) == 1);
    }

    let home = ctx.home("fish")?;
    ctx.install(&home, &[("SHELL", "/usr/local/bin/fish")], &[])?
        .expect_ok()?;
    let fish = read(&home.join(".config/fish/conf.d/agentpay.fish"))?;
    ensure!(
        fish.contains("set -gx PATH \"$HOME/.agentpay/bin\" $PATH"),
        "{fish}"
    );

    let home = ctx.home("dash")?;
    ctx.install(&home, &[("SHELL", "/bin/dash")], &[])?
        .expect_ok()?;
    ensure!(block_count(&read(&home.join(".profile"))?) == 1);
    Ok(())
}

fn no_modify_path(ctx: &Ctx) -> Result<()> {
    let home = ctx.home("no-path")?;
    let run = ctx.install(&home, &[], &["--no-modify-path"])?;
    run.expect_ok()?;
    ensure!(!home.join(".zshrc").exists(), "an rc file was written");
    ensure!(
        run.stdout.contains("not changed (--no-modify-path)"),
        "{}",
        run.transcript()
    );
    ensure!(
        !run.stdout.contains("New terminals"),
        "{}",
        run.transcript()
    );
    let record = read(&install_dir(&home).join("installer.json"))?;
    ensure!(record.contains("\"path_rc\": null"), "{record}");
    Ok(())
}

fn legacy_install(ctx: &Ctx) -> Result<()> {
    let home = ctx.home("legacy")?;
    let dir = install_dir(&home);
    std::fs::create_dir_all(dir.join("bin"))?;
    std::fs::create_dir_all(dir.join("app/dist"))?;
    std::fs::write(dir.join("one-click-install-manifest.json"), "{}")?;
    std::fs::write(dir.join("app/dist/cli.cjs"), "old")?;
    std::fs::write(dir.join("config.json"), "{\"keep\":true}")?;
    std::fs::write(dir.join("telemetry.json"), "{}")?;
    for name in [
        "agentpay",
        "agentpay-admin",
        "agentpay-agent",
        "agentpay-daemon",
    ] {
        bundle::write_file(&dir.join("bin").join(name), b"#!/bin/sh\n", true)?;
    }
    std::fs::write(home.join(".zshrc"), LEGACY_BLOCK)?;

    let run = ctx.install(&home, &[("AGENTPAY_HOME", "/somewhere/.agentpay")], &[])?;
    run.expect_ok()?;
    ensure!(
        run.stdout.contains("Previous install"),
        "{}",
        run.transcript()
    );
    ensure!(
        run.stdout.contains("AGENTPAY_HOME is set"),
        "{}",
        run.transcript()
    );
    for moved in [
        "one-click-install-manifest.json",
        "app/dist/cli.cjs",
        "bin/agentpay",
        "bin/agentpay-admin",
        "bin/agentpay-agent",
        "bin/agentpay-daemon",
    ] {
        ensure!(
            dir.join("legacy").join(moved).exists(),
            "{moved} was not moved aside"
        );
    }
    ensure!(
        read(&dir.join("config.json"))? == "{\"keep\":true}",
        "config.json changed"
    );
    ensure!(dir.join("telemetry.json").exists());
    ensure!(!dir.join("bin/agentpay-admin").exists());
    check_layout(ctx, &dir, ctx.version)?;
    let rc = read(&home.join(".zshrc"))?;
    ensure!(
        !rc.contains("AGENTPAY_HOME") && block_count(&rc) == 1,
        "{rc}"
    );
    Ok(())
}

fn downgrade_and_upgrade(ctx: &Ctx) -> Result<()> {
    let home = ctx.home("downgrade")?;
    let dir = install_dir(&home);
    ctx.install(&home, &[], &[])?.expect_ok()?;

    ctx.install(&home, &[("AGENTPAY_VERSION", OLD_VERSION)], &[])?
        .expect_failure("Rerun with --yes to downgrade")?;
    ensure!(link(&dir.join("current"))? == format!("versions/{}", ctx.version));

    let run = ctx.install(&home, &[("AGENTPAY_VERSION", OLD_VERSION)], &["--yes"])?;
    run.expect_ok()?;
    ensure!(
        run.stdout.contains(&format!("(was {})", ctx.version)),
        "{}",
        run.transcript()
    );
    check_layout(ctx, &dir, OLD_VERSION)?;
    check_runs(ctx, &home, OLD_VERSION)?;

    let run = ctx.install(&home, &[], &[])?;
    run.expect_ok()?;
    ensure!(
        run.stdout.contains(&format!("(was {OLD_VERSION})")),
        "{}",
        run.transcript()
    );
    check_layout(ctx, &dir, ctx.version)
}

fn http_refused(ctx: &Ctx) -> Result<()> {
    let home = ctx.home("http")?;
    ctx.install(
        &home,
        &[("AGENTPAY_RELEASES_URL", "http://127.0.0.1:9/releases")],
        &[],
    )?
    .expect_failure("refusing to download")?;
    ensure!(!install_dir(&home).exists());
    Ok(())
}

fn flags(ctx: &Ctx) -> Result<()> {
    let home = ctx.home("flags")?;
    let run = ctx.install(&home, &[], &["--verbose", "--yes"])?;
    run.expect_ok()?;
    ensure!(
        run.stderr.contains("· download file://"),
        "{}",
        run.transcript()
    );

    let help = ctx.install(&home, &[], &["--help"])?;
    help.expect_ok()?;
    ensure!(
        help.stdout.contains("Usage: install.sh"),
        "{}",
        help.transcript()
    );

    let bad = ctx.install(&home, &[], &["--frobnicate"])?;
    ensure!(
        bad.code == Some(2),
        "unknown option exited with {:?}",
        bad.code
    );
    ensure!(
        bad.stderr.contains("unknown option --frobnicate"),
        "{}",
        bad.transcript()
    );
    Ok(())
}

fn already_on_path(ctx: &Ctx) -> Result<()> {
    let home = ctx.home("on-path")?;
    let path = format!(
        "{}/.agentpay/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        home.display()
    );
    let run = ctx.install(&home, &[("PATH", &path)], &[])?;
    run.expect_ok()?;
    ensure!(
        run.stdout.contains("\nNext: agentpay setup\n"),
        "{}",
        run.transcript()
    );
    Ok(())
}
