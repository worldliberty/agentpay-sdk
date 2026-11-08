//! Repository maintenance tasks for the AgentPay workspace.
//!
//! Run through the cargo alias defined in `.cargo/config.toml`:
//!
//! ```text
//! cargo xtask check-file-length
//! cargo xtask check-no-js
//! cargo xtask gen-api [--check]
//! cargo xtask build-macos-auth [--arch arm64 --arch x86_64] [--profile debug|release]
//! AGENTPAY_SE_TESTS=1 cargo xtask test-macos-auth
//! cargo xtask dist [--target <triple>] [--out-dir <dir>]
//! cargo xtask test-install [--dist <dir>]
//! ```

mod dist;
mod gen_api;
mod macos_auth;
mod macos_auth_e2e;
mod test_install;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

/// Source extensions whose files must stay under the line limit.
const LENGTH_CHECKED_EXTENSIONS: &[&str] = &["rs", "ts", "tsx"];

/// JavaScript extensions that are not allowed anywhere in the repository.
const FORBIDDEN_JS_EXTENSIONS: &[&str] = &["js", "mjs", "cjs", "jsx"];

/// Directory names that only ever hold generated build output.
const BUILD_OUTPUT_DIRS: &[&str] = &["dist", "target", "node_modules"];

#[derive(Debug, Parser)]
#[command(name = "xtask", about = "AgentPay repository maintenance tasks")]
struct Cli {
    #[command(subcommand)]
    command: Task,
}

#[derive(Debug, Subcommand)]
enum Task {
    /// Fail if any .rs/.ts/.tsx file in the repository (tracked, or untracked and not ignored)
    /// is longer than the line limit.
    CheckFileLength {
        /// Maximum number of lines a file may have.
        #[arg(long, default_value_t = 1000)]
        max_lines: usize,
    },
    /// Fail if any .js/.mjs/.cjs/.jsx file in the repository (tracked, or untracked and not
    /// ignored) exists outside build output directories.
    CheckNoJs,
    /// Generate the daemon API's JSON Schema (docs/api/schema.json) and TypeScript
    /// bindings (client/src/generated/) from crates/agentpay-api.
    GenApi {
        /// Do not write anything; fail if the checked-in files are out of date.
        #[arg(long)]
        check: bool,
    },
    /// Build the macOS admin-auth helper (native/macos/AgentPayAuth.swift) into
    /// target/<profile>/agentpay-auth.
    BuildMacosAuth(macos_auth::BuildArgs),
    /// Build the macOS admin-auth helper and run its end-to-end checks. The Secure Enclave
    /// checks only run with AGENTPAY_SE_TESTS=1.
    TestMacosAuth(macos_auth::BuildArgs),
    /// Build the release tarball for one target into dist/ and update dist/SHA256SUMS.
    Dist(dist::DistArgs),
    /// Run scripts/install.sh end to end against a locally served release in temp homes.
    TestInstall(test_install::TestInstallArgs),
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("xtask: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// Runs a task and returns whether the check passed.
fn run(cli: Cli) -> Result<bool> {
    let root = repo_root()?;
    match cli.command {
        Task::CheckFileLength { max_lines } => {
            check_file_length(&root, &repo_files(&root)?, max_lines)
        }
        Task::CheckNoJs => Ok(check_no_js(&repo_files(&root)?)),
        Task::GenApi { check: true } => gen_api::check(&root),
        Task::GenApi { check: false } => gen_api::write(&root),
        Task::BuildMacosAuth(args) => {
            let binary = macos_auth::build(&root, &args)?;
            println!("build-macos-auth: built {}", binary.display());
            Ok(true)
        }
        Task::TestMacosAuth(args) => {
            let binary = macos_auth::build(&root, &args)?;
            macos_auth_e2e::run(&root, &binary)
        }
        Task::Dist(args) => dist::run(&root, &args).map(|_| true),
        Task::TestInstall(args) => test_install::run(&root, &args),
    }
}

fn check_file_length(root: &Path, files: &[PathBuf], max_lines: usize) -> Result<bool> {
    let mut offenders = Vec::new();
    for path in files
        .iter()
        .filter(|path| has_extension(path, LENGTH_CHECKED_EXTENSIONS))
    {
        let full = root.join(path);
        // Only regular files are read; a path can still be a directory (a nested repository).
        if !full.is_file() {
            continue;
        }
        let content = std::fs::read_to_string(&full)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let lines = count_lines(&content);
        if lines > max_lines {
            offenders.push((lines, path.clone()));
        }
    }
    sort_offenders(&mut offenders);

    if offenders.is_empty() {
        println!("check-file-length: all source files have at most {max_lines} lines");
        return Ok(true);
    }
    eprintln!(
        "check-file-length: {} file(s) exceed {max_lines} lines:",
        offenders.len()
    );
    for (lines, path) in &offenders {
        eprintln!("{lines:>8}  {}", path.display());
    }
    Ok(false)
}

fn check_no_js(files: &[PathBuf]) -> bool {
    let offenders = find_js_files(files);
    if offenders.is_empty() {
        println!("check-no-js: the repository has no JavaScript files");
        return true;
    }
    eprintln!("check-no-js: {} JavaScript file(s) found:", offenders.len());
    for path in &offenders {
        eprintln!("  {}", path.display());
    }
    false
}

/// Returns the sorted JavaScript files in `files`, ignoring build output directories.
fn find_js_files(files: &[PathBuf]) -> Vec<PathBuf> {
    let mut offenders: Vec<PathBuf> = files
        .iter()
        .filter(|path| has_extension(path, FORBIDDEN_JS_EXTENSIONS))
        .filter(|path| !is_build_output(path))
        .cloned()
        .collect();
    offenders.sort();
    offenders
}

/// Sorts offenders longest first, then by path, so the output is stable.
fn sort_offenders(offenders: &mut [(usize, PathBuf)]) {
    offenders.sort_by(|(a_lines, a_path), (b_lines, b_path)| {
        b_lines.cmp(a_lines).then_with(|| a_path.cmp(b_path))
    });
}

/// Counts lines the way editors do: a trailing newline does not start a new line.
fn count_lines(content: &str) -> usize {
    content.lines().count()
}

fn has_extension(path: &Path, extensions: &[&str]) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            extensions
                .iter()
                .any(|candidate| ext.eq_ignore_ascii_case(candidate))
        })
}

fn is_build_output(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|name| BUILD_OUTPUT_DIRS.contains(&name))
    })
}

/// The workspace root is two levels above this crate (`crates/xtask`).
fn repo_root() -> Result<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .context("xtask must live two levels below the repository root")
}

/// Lists the repository's files relative to `root`: everything tracked by git plus untracked
/// files that are not ignored, minus tracked files deleted from the working tree.
fn repo_files(root: &Path) -> Result<Vec<PathBuf>> {
    let listing = git_ls_files(root, &["--cached", "--others", "--exclude-standard"])?;
    let deleted = git_ls_files(root, &["--deleted"])?;
    Ok(parse_file_list(&listing, &deleted))
}

/// Runs `git ls-files -z` with `args` and returns its NUL-separated output.
fn git_ls_files(root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .args(args)
        .output()
        .context("failed to run `git ls-files`")?;
    if !output.status.success() {
        bail!(
            "`git ls-files` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout).context("`git ls-files` returned non-UTF-8")
}

/// Turns a NUL-separated `git ls-files` listing into a sorted, de-duplicated path list without
/// the paths in the NUL-separated `deleted` listing.
fn parse_file_list(listing: &str, deleted: &str) -> Vec<PathBuf> {
    let deleted: BTreeSet<&str> = split_nul(deleted).collect();
    split_nul(listing)
        .filter(|entry| !deleted.contains(entry))
        .map(PathBuf::from)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn split_nul(listing: &str) -> impl Iterator<Item = &str> {
    listing.split('\0').filter(|entry| !entry.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(items: &[&str]) -> Vec<PathBuf> {
        items.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn count_lines_handles_trailing_newlines_and_empty_input() {
        assert_eq!(count_lines(""), 0);
        assert_eq!(count_lines("one"), 1);
        assert_eq!(count_lines("one\n"), 1);
        assert_eq!(count_lines("one\ntwo\n"), 2);
        assert_eq!(count_lines("one\r\ntwo"), 2);
        assert_eq!(count_lines("\n\n"), 2);
    }

    #[test]
    fn length_filter_matches_only_source_extensions() {
        assert!(has_extension(
            Path::new("crates/a/src/lib.rs"),
            LENGTH_CHECKED_EXTENSIONS
        ));
        assert!(has_extension(
            Path::new("client/src/app.tsx"),
            LENGTH_CHECKED_EXTENSIONS
        ));
        assert!(has_extension(
            Path::new("client/src/x.TS"),
            LENGTH_CHECKED_EXTENSIONS
        ));
        assert!(!has_extension(
            Path::new("README.md"),
            LENGTH_CHECKED_EXTENSIONS
        ));
        assert!(!has_extension(
            Path::new("Makefile"),
            LENGTH_CHECKED_EXTENSIONS
        ));
        assert!(!has_extension(
            Path::new("src/rs"),
            LENGTH_CHECKED_EXTENSIONS
        ));
    }

    #[test]
    fn find_js_files_flags_all_js_flavours_and_skips_build_output() {
        let files = paths(&[
            "scripts/run.mjs",
            "tools/a.js",
            "client/dist/bundle.js",
            "client/src/app.tsx",
            "legacy/config.cjs",
            "web/component.jsx",
            "target/debug/build/x.js",
            "docs/notes.md",
        ]);
        assert_eq!(
            find_js_files(&files),
            paths(&[
                "legacy/config.cjs",
                "scripts/run.mjs",
                "tools/a.js",
                "web/component.jsx"
            ])
        );
    }

    #[test]
    fn build_output_matches_whole_components_only() {
        assert!(is_build_output(Path::new("client/dist/index.js")));
        assert!(!is_build_output(Path::new("client/distribution/index.js")));
        assert!(!is_build_output(Path::new("src/dist.js")));
    }

    #[test]
    fn offenders_sort_longest_first_then_by_path() {
        let mut offenders = vec![
            (1200, PathBuf::from("b.rs")),
            (5000, PathBuf::from("z.rs")),
            (1200, PathBuf::from("a.rs")),
        ];
        sort_offenders(&mut offenders);
        assert_eq!(
            offenders,
            vec![
                (5000, PathBuf::from("z.rs")),
                (1200, PathBuf::from("a.rs")),
                (1200, PathBuf::from("b.rs"))
            ]
        );
    }

    #[test]
    fn parse_file_list_splits_on_nul() {
        assert_eq!(
            parse_file_list("a.rs\0dir/b c.ts\0", ""),
            paths(&["a.rs", "dir/b c.ts"])
        );
        assert!(parse_file_list("", "").is_empty());
    }

    #[test]
    fn parse_file_list_drops_deleted_files_and_sorts_untracked_in() {
        // `--cached --others` lists tracked files first, then untracked ones; a tracked file
        // deleted from the working tree is still listed by `--cached` and must be dropped.
        let listing = "src/b.rs\0src/gone.rs\0src/a.rs\0new/untracked.ts\0";
        let deleted = "src/gone.rs\0";
        assert_eq!(
            parse_file_list(listing, deleted),
            paths(&["new/untracked.ts", "src/a.rs", "src/b.rs"])
        );
    }

    #[test]
    fn parse_file_list_removes_duplicate_entries() {
        // Unmerged paths are listed once per conflict stage.
        assert_eq!(
            parse_file_list("x.rs\0x.rs\0y.rs\0", ""),
            paths(&["x.rs", "y.rs"])
        );
    }
}
