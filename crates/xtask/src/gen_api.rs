//! `cargo xtask gen-api`: writes the daemon API's JSON Schema and TypeScript
//! bindings from `crates/agentpay-api`, or checks them for drift with `--check`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Where the JSON Schema is written, relative to the repository root.
pub(crate) const SCHEMA_PATH: &str = "docs/api/schema.json";

/// Directory that holds only generated TypeScript, relative to the repository root.
pub(crate) const TS_DIR: &str = "client/src/generated";

/// Every generated file: repository-relative path -> contents.
fn generated_files() -> Result<BTreeMap<PathBuf, String>> {
    let mut files = BTreeMap::new();
    let schema = serde_json::to_string_pretty(&agentpay_api::codegen::json_schema())
        .context("failed to render the JSON Schema")?;
    files.insert(PathBuf::from(SCHEMA_PATH), format!("{schema}\n"));
    let bindings = agentpay_api::codegen::typescript_bindings()
        .map_err(|error| anyhow::anyhow!("failed to render TypeScript bindings: {error}"))?;
    for (name, contents) in bindings {
        files.insert(Path::new(TS_DIR).join(name), contents);
    }
    Ok(files)
}

/// Writes every generated file and removes stale files from [`TS_DIR`].
pub(crate) fn write(root: &Path) -> Result<bool> {
    let files = generated_files()?;
    for stale in stale_files(root, &files)? {
        std::fs::remove_file(root.join(&stale))
            .with_context(|| format!("failed to remove stale {}", stale.display()))?;
    }
    for (path, contents) in &files {
        let full = root.join(path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        if std::fs::read_to_string(&full).ok().as_deref() != Some(contents.as_str()) {
            std::fs::write(&full, contents)
                .with_context(|| format!("failed to write {}", path.display()))?;
        }
    }
    println!(
        "gen-api: wrote {SCHEMA_PATH} and {} files in {TS_DIR}",
        files.len() - 1
    );
    Ok(true)
}

/// Returns whether every generated file is up to date, listing the ones that are not.
pub(crate) fn check(root: &Path) -> Result<bool> {
    let files = generated_files()?;
    let mut drifted: Vec<PathBuf> = files
        .iter()
        .filter(|(path, contents)| {
            std::fs::read_to_string(root.join(path)).ok().as_deref() != Some(contents.as_str())
        })
        .map(|(path, _)| path.clone())
        .collect();
    drifted.extend(stale_files(root, &files)?);
    drifted.sort();
    if drifted.is_empty() {
        println!("gen-api: {SCHEMA_PATH} and {TS_DIR} are up to date");
        return Ok(true);
    }
    eprintln!(
        "gen-api: {} generated file(s) are out of date; run `cargo xtask gen-api`:",
        drifted.len()
    );
    for path in &drifted {
        eprintln!("  {}", path.display());
    }
    Ok(false)
}

/// Files in [`TS_DIR`] that the generator no longer produces.
fn stale_files(root: &Path, files: &BTreeMap<PathBuf, String>) -> Result<Vec<PathBuf>> {
    let dir = root.join(TS_DIR);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut stale = Vec::new();
    for entry in std::fs::read_dir(&dir).with_context(|| format!("failed to list {TS_DIR}"))? {
        let path = Path::new(TS_DIR).join(entry?.file_name());
        if !files.contains_key(&path) {
            stale.push(path);
        }
    }
    Ok(stale)
}
