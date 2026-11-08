//! End-to-end checks for `agentpay-auth`, driven entirely through its command line by
//! `cargo xtask test-macos-auth`.
//!
//! The basic checks (argument validation and key file safety) never reach the Secure Enclave,
//! so they run wherever the helper builds, including CI runners. The Secure Enclave checks
//! need real hardware and only run on macOS with `AGENTPAY_SE_TESTS=1`. The most important of
//! them creates a key that requires user presence and proves that `sign --no-ui` is refused:
//! the key's access control must be enforced on every signature.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{symlink, DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, ensure, Context, Result};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde_json::{json, Value};

use crate::macos_auth::target_dir;

/// Environment variable that enables the Secure Enclave checks.
pub const SE_TESTS_ENV: &str = "AGENTPAY_SE_TESTS";

const KEY_FILE_KIND: &str = "agentpay-admin-key";
const INVALID_INPUT: &str = "invalid_input";
const KEY_NOT_FOUND: &str = "key_not_found";
const KEY_INVALIDATED: &str = "key_invalidated";
const INTERACTION_NOT_ALLOWED: &str = "interaction_not_allowed";
const REASON: &str = "run the agentpay-auth self-test";

/// A check gets the helper and a fresh private (`0700`) directory of its own.
type Check = fn(&Helper, &Path) -> Result<()>;

const BASIC_CHECKS: &[(&str, Check)] = &[
    ("status-reports-capabilities", status_reports_capabilities),
    ("command-line-errors-are-json", command_line_errors_are_json),
    (
        "sign-validates-reason-and-message",
        sign_validates_reason_and_message,
    ),
    ("symlinks-are-refused", symlinks_are_refused),
    ("create-refuses-to-overwrite", create_refuses_to_overwrite),
    (
        "create-requires-a-private-directory",
        create_requires_a_private_directory,
    ),
    (
        "unsafe-or-malformed-key-files-are-refused",
        unsafe_or_malformed_key_files_are_refused,
    ),
    (
        "delete-removes-only-key-files",
        delete_removes_only_key_files,
    ),
];

const SECURE_ENCLAVE_CHECKS: &[(&str, Check)] = &[
    (
        "se-status-reports-secure-enclave",
        se_status_reports_secure_enclave,
    ),
    ("se-create-sign-verify-delete", se_create_sign_verify_delete),
    (
        "se-public-key-mismatch-is-invalidated",
        se_public_key_mismatch_is_invalidated,
    ),
    (
        "se-corrupted-blob-is-invalidated",
        se_corrupted_blob_is_invalidated,
    ),
    (
        "se-user-presence-key-refuses-to-sign-without-ui",
        se_user_presence_key_refuses_to_sign_without_ui,
    ),
];

/// Runs every enabled check against `binary` and returns whether all of them passed.
pub fn run(root: &Path, binary: &Path) -> Result<bool> {
    let helper = Helper {
        binary: binary.to_path_buf(),
    };
    let scratch = ScratchDir::new(&target_dir(root).join("tmp"))?;
    let mut checks = BASIC_CHECKS.to_vec();
    if secure_enclave_checks_enabled() {
        checks.extend_from_slice(SECURE_ENCLAVE_CHECKS);
    } else {
        println!(
            "skipping Secure Enclave checks: set {SE_TESTS_ENV}=1 on a Mac with a Secure Enclave"
        );
    }

    let mut failed = 0;
    for (name, check) in &checks {
        let dir = scratch.path().join(name);
        create_private_dir(&dir)?;
        match check(&helper, &dir) {
            Ok(()) => println!("ok      {name}"),
            Err(error) => {
                failed += 1;
                println!("FAILED  {name}: {error:#}");
            }
        }
    }
    println!(
        "test-macos-auth: {} passed, {failed} failed",
        checks.len() - failed
    );
    Ok(failed == 0)
}

fn secure_enclave_checks_enabled() -> bool {
    cfg!(target_os = "macos") && std::env::var(SE_TESTS_ENV).is_ok_and(|value| value == "1")
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

struct Helper {
    binary: PathBuf,
}

/// One invocation: the single JSON object printed on stdout and whether the helper exited 0.
struct Reply {
    success: bool,
    json: Value,
}

impl Reply {
    fn error_code(&self) -> Option<&str> {
        self.json["error"]["code"].as_str()
    }
}

impl Helper {
    /// Runs the helper and checks the output contract: exactly one JSON line on stdout, exit
    /// status 0 without an `error` object and 1 with one.
    fn invoke(&self, args: &[&str]) -> Result<Reply> {
        let output = Command::new(&self.binary)
            .args(args)
            .output()
            .with_context(|| format!("failed to run {}", self.binary.display()))?;
        let stdout = String::from_utf8(output.stdout).context("stdout is not UTF-8")?;
        ensure!(
            stdout.trim_end().lines().count() == 1,
            "expected one line of JSON on stdout, got {stdout:?}"
        );
        let json: Value = serde_json::from_str(&stdout)
            .with_context(|| format!("stdout is not JSON: {stdout:?}"))?;
        let has_error = json.get("error").is_some();
        match output.status.code() {
            Some(0) if !has_error => {}
            Some(1) if has_error && json["error"]["message"].is_string() => {}
            code => bail!("exit status {code:?} does not match output {json}"),
        }
        Ok(Reply {
            success: output.status.success(),
            json,
        })
    }

    fn ok(&self, args: &[&str]) -> Result<Value> {
        let reply = self.invoke(args)?;
        ensure!(
            reply.success,
            "agentpay-auth {args:?} failed: {}",
            reply.json
        );
        Ok(reply.json)
    }

    fn fails_with(&self, args: &[&str], code: &str) -> Result<()> {
        let reply = self.invoke(args)?;
        ensure!(
            reply.error_code() == Some(code),
            "agentpay-auth {}: expected error {code}, got {}",
            abbreviate(&args.join(" ")),
            reply.json
        );
        Ok(())
    }

    fn create(&self, key: &Path, user_presence: bool) -> Result<Vec<u8>> {
        let mut args = vec!["create", "--key-file", utf8(key)?];
        if !user_presence {
            args.push("--no-user-presence");
        }
        let created = self.ok(&args)?;
        let public_hex = created["publicKeySec1Hex"]
            .as_str()
            .context("create did not return publicKeySec1Hex")?;
        hex::decode(public_hex).context("publicKeySec1Hex is not hex")
    }

    fn sign_args<'a>(key: &'a str, message_hex: &'a str, no_ui: bool) -> Vec<&'a str> {
        let mut args = vec![
            "sign",
            "--key-file",
            key,
            "--reason",
            REASON,
            "--message-hex",
            message_hex,
        ];
        if no_ui {
            args.push("--no-ui");
        }
        args
    }

    fn sign(&self, key: &Path, message: &[u8], no_ui: bool) -> Result<Signature> {
        let message_hex = hex::encode(message);
        let reply = self.ok(&Self::sign_args(utf8(key)?, &message_hex, no_ui))?;
        let der = reply["signatureDerHex"]
            .as_str()
            .context("sign did not return signatureDerHex")?;
        let der = hex::decode(der).context("signatureDerHex is not hex")?;
        Signature::from_der(&der).map_err(|error| anyhow!("signature is not DER ECDSA: {error}"))
    }
}

/// A private scratch directory under `target/tmp`, removed when dropped.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(base: &Path) -> Result<Self> {
        fs::create_dir_all(base).with_context(|| format!("failed to create {}", base.display()))?;
        let dir = base.join(format!("agentpay-auth-e2e-{}", std::process::id()));
        // A leftover from a crashed run with a recycled pid; nothing else writes here.
        let _ = fs::remove_dir_all(&dir);
        create_private_dir(&dir)?;
        Ok(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        // Deleting the key files also destroys the Secure Enclave keys they hold.
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn create_private_dir(dir: &Path) -> Result<()> {
    DirBuilder::new()
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("failed to create {}", dir.display()))?;
    // The umask may have cleared bits, never added them, but be explicit.
    set_mode(dir, 0o700)
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to chmod {}", path.display()))
}

fn mode_of(path: &Path) -> Result<u32> {
    let metadata =
        fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    Ok(metadata.permissions().mode() & 0o777)
}

/// Creates `path` (which must not exist) with mode `0600`.
fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn read_json(path: &Path) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("{} is not JSON", path.display()))
}

/// Replaces a key file with `value`, keeping mode `0600`.
fn rewrite_json(path: &Path, value: &Value) -> Result<()> {
    fs::remove_file(path).with_context(|| format!("failed to remove {}", path.display()))?;
    write_private(path, value.to_string().as_bytes())
}

/// A well-formed key file whose blob is not a real Secure Enclave key.
fn fake_key_file() -> Result<Value> {
    let signing_key =
        SigningKey::from_slice(&[0x11; 32]).map_err(|error| anyhow!("bad test scalar: {error}"))?;
    let public = signing_key.verifying_key().to_encoded_point(false);
    Ok(json!({
        "kind": KEY_FILE_KIND,
        "version": 1,
        "publicKeySec1Hex": hex::encode(public.as_bytes()),
        "dataRepresentationHex": "ab".repeat(48),
    }))
}

fn utf8(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("{} is not UTF-8", path.display()))
}

fn abbreviate(text: &str) -> String {
    const LIMIT: usize = 120;
    if text.chars().count() <= LIMIT {
        return text.to_owned();
    }
    let head: String = text.chars().take(LIMIT).collect();
    format!("{head}...")
}

// ---------------------------------------------------------------------------------------------
// Basic checks (no Secure Enclave)
// ---------------------------------------------------------------------------------------------

fn status_reports_capabilities(helper: &Helper, _dir: &Path) -> Result<()> {
    let status = helper.ok(&["status"])?;
    for field in ["secureEnclaveAvailable", "userPresenceAvailable"] {
        ensure!(
            status[field].is_boolean(),
            "status.{field} is not a boolean: {status}"
        );
    }
    ensure!(
        status["biometry"]["available"].is_boolean(),
        "status.biometry.available is not a boolean: {status}"
    );
    let kind = status["biometry"]["kind"].as_str().unwrap_or_default();
    ensure!(
        ["touch_id", "face_id", "none"].contains(&kind),
        "unexpected biometry kind in {status}"
    );
    helper.fails_with(&["status", "--verbose"], INVALID_INPUT)
}

fn command_line_errors_are_json(helper: &Helper, dir: &Path) -> Result<()> {
    let help = Command::new(&helper.binary)
        .arg("help")
        .output()
        .context("failed to run help")?;
    ensure!(
        help.status.success() && String::from_utf8_lossy(&help.stdout).contains("USAGE"),
        "`agentpay-auth help` did not print usage"
    );

    let key_path = dir.join("key.json");
    let key = utf8(&key_path)?;
    helper.fails_with(&[], INVALID_INPUT)?;
    helper.fails_with(&["frobnicate"], INVALID_INPUT)?;
    helper.fails_with(&["create"], INVALID_INPUT)?;
    helper.fails_with(&["create", "--key-file"], INVALID_INPUT)?;
    helper.fails_with(&["create", "--key-file", key, "--no-ui"], INVALID_INPUT)?;
    helper.fails_with(
        &["delete", "--key-file", key, "--key-file", key],
        INVALID_INPUT,
    )?;
    helper.fails_with(
        &["sign", "--key-file", key, "--reason", REASON],
        INVALID_INPUT,
    )?;
    helper.fails_with(&["status", "--no-user-presence"], INVALID_INPUT)?;
    ensure!(!key_path.exists(), "a rejected command created a key file");
    Ok(())
}

fn sign_validates_reason_and_message(helper: &Helper, dir: &Path) -> Result<()> {
    // The key file does not exist, so input that passes validation fails with key_not_found.
    let key_path = dir.join("missing.json");
    let key = utf8(&key_path)?;
    let longest_reason = "a".repeat(200);
    let too_long_reason = "a".repeat(201);
    let largest_message = "00".repeat(16 * 1024);
    let too_large_message = "00".repeat(16 * 1024 + 1);
    let cases: &[(&str, &str, &str)] = &[
        ("approve sending 25 USD1", "00", KEY_NOT_FOUND),
        (&longest_reason, "0xdeadbeef", KEY_NOT_FOUND),
        ("approve", &largest_message, KEY_NOT_FOUND),
        ("", "00", INVALID_INPUT),
        ("   ", "00", INVALID_INPUT),
        ("approve\nsending", "00", INVALID_INPUT),
        ("approve\u{7}", "00", INVALID_INPUT),
        ("approve \u{202e}gnidnes", "00", INVALID_INPUT),
        (&too_long_reason, "00", INVALID_INPUT),
        ("approve", "", INVALID_INPUT),
        ("approve", "0x", INVALID_INPUT),
        ("approve", "abc", INVALID_INPUT),
        ("approve", "zz", INVALID_INPUT),
        ("approve", &too_large_message, INVALID_INPUT),
    ];
    for (reason, message, code) in cases {
        let args = [
            "sign",
            "--key-file",
            key,
            "--reason",
            reason,
            "--message-hex",
            message,
        ];
        helper.fails_with(&args, code)?;
    }
    helper.fails_with(&["delete", "--key-file", key], KEY_NOT_FOUND)
}

fn symlinks_are_refused(helper: &Helper, dir: &Path) -> Result<()> {
    let real = dir.join("real.json");
    write_private(&real, fake_key_file()?.to_string().as_bytes())?;
    let link = dir.join("link.json");
    symlink(&real, &link).context("failed to create symlink")?;
    let link_str = utf8(&link)?;

    helper.fails_with(&Helper::sign_args(link_str, "00", true), INVALID_INPUT)?;
    helper.fails_with(&["delete", "--key-file", link_str], INVALID_INPUT)?;
    ensure!(
        real.is_file(),
        "delete through a symlink removed its target"
    );
    ensure!(
        link.symlink_metadata().is_ok(),
        "delete removed the symlink"
    );
    helper.fails_with(
        &["create", "--key-file", link_str, "--no-user-presence"],
        INVALID_INPUT,
    )?;

    let target = dir.join("target.json");
    let dangling = dir.join("dangling.json");
    symlink(&target, &dangling).context("failed to create symlink")?;
    helper.fails_with(
        &[
            "create",
            "--key-file",
            utf8(&dangling)?,
            "--no-user-presence",
        ],
        INVALID_INPUT,
    )?;
    ensure!(!target.exists(), "create wrote through a dangling symlink");
    Ok(())
}

fn create_refuses_to_overwrite(helper: &Helper, dir: &Path) -> Result<()> {
    let key = dir.join("key.json");
    let original = fake_key_file()?.to_string();
    write_private(&key, original.as_bytes())?;
    for extra in [&["--no-user-presence"][..], &[]] {
        let mut args = vec!["create", "--key-file", utf8(&key)?];
        args.extend_from_slice(extra);
        helper.fails_with(&args, INVALID_INPUT)?;
    }
    ensure!(
        fs::read_to_string(&key)? == original,
        "create modified an existing key file"
    );
    ensure!(
        fs::read_dir(dir)?.count() == 1,
        "create left a temporary file behind"
    );
    Ok(())
}

fn create_requires_a_private_directory(helper: &Helper, dir: &Path) -> Result<()> {
    for mode in [0o777, 0o770, 0o702] {
        let shared = dir.join(format!("shared-{mode:o}"));
        create_private_dir(&shared)?;
        set_mode(&shared, mode)?;
        let key = shared.join("key.json");
        helper.fails_with(
            &["create", "--key-file", utf8(&key)?, "--no-user-presence"],
            INVALID_INPUT,
        )?;
        ensure!(
            fs::read_dir(&shared)?.next().is_none(),
            "create wrote into a directory with mode {mode:o}"
        );
    }
    let missing = dir.join("missing").join("key.json");
    helper.fails_with(
        &[
            "create",
            "--key-file",
            utf8(&missing)?,
            "--no-user-presence",
        ],
        INVALID_INPUT,
    )?;
    let directory = format!("{}/", utf8(dir)?);
    helper.fails_with(
        &["create", "--key-file", &directory, "--no-user-presence"],
        INVALID_INPUT,
    )
}

fn unsafe_or_malformed_key_files_are_refused(helper: &Helper, dir: &Path) -> Result<()> {
    let valid = fake_key_file()?;
    let with = |field: &str, value: Value| {
        let mut changed = valid.clone();
        changed[field] = value;
        changed.to_string()
    };
    let mut unknown_field = valid.clone();
    unknown_field["requiresBiometry"] = json!(true);
    let mut missing_field = valid.clone();
    if let Some(object) = missing_field.as_object_mut() {
        object.remove("dataRepresentationHex");
    }
    let compressed = SigningKey::from_slice(&[0x11; 32])
        .map_err(|error| anyhow!("bad test scalar: {error}"))?
        .verifying_key()
        .to_encoded_point(true);

    let cases: Vec<(&str, String, u32)> = vec![
        ("group-writable", valid.to_string(), 0o620),
        ("world-writable", valid.to_string(), 0o602),
        ("not-json", "not json".to_owned(), 0o600),
        (
            "wrong-kind",
            with("kind", json!("agentpay-touchid-admin-key")),
            0o600,
        ),
        ("wrong-version", with("version", json!(2)), 0o600),
        ("unknown-field", unknown_field.to_string(), 0o600),
        ("missing-field", missing_field.to_string(), 0o600),
        (
            "compressed-public-key",
            with(
                "publicKeySec1Hex",
                json!(hex::encode(compressed.as_bytes())),
            ),
            0o600,
        ),
        (
            "off-curve-public-key",
            with("publicKeySec1Hex", json!(format!("04{}", "00".repeat(64)))),
            0o600,
        ),
        (
            "non-hex-blob",
            with("dataRepresentationHex", json!("xyz")),
            0o600,
        ),
        (
            "empty-blob",
            with("dataRepresentationHex", json!("")),
            0o600,
        ),
    ];
    for (name, contents, mode) in cases {
        let path = dir.join(format!("{name}.json"));
        write_private(&path, contents.as_bytes())?;
        set_mode(&path, mode)?;
        helper
            .fails_with(&Helper::sign_args(utf8(&path)?, "00", true), INVALID_INPUT)
            .with_context(|| format!("key file case {name}"))?;
    }

    let directory = dir.join("directory.json");
    create_private_dir(&directory)?;
    helper.fails_with(
        &Helper::sign_args(utf8(&directory)?, "00", true),
        INVALID_INPUT,
    )
}

fn delete_removes_only_key_files(helper: &Helper, dir: &Path) -> Result<()> {
    let key = dir.join("key.json");
    write_private(&key, fake_key_file()?.to_string().as_bytes())?;
    let deleted = helper.ok(&["delete", "--key-file", utf8(&key)?])?;
    ensure!(
        deleted == json!({ "deleted": true }),
        "unexpected delete output {deleted}"
    );
    ensure!(!key.exists(), "delete left the key file in place");
    helper.fails_with(&["delete", "--key-file", utf8(&key)?], KEY_NOT_FOUND)?;

    let notes = dir.join("notes.txt");
    write_private(&notes, b"not a key")?;
    helper.fails_with(&["delete", "--key-file", utf8(&notes)?], INVALID_INPUT)?;
    ensure!(
        notes.exists(),
        "delete removed a file that is not a key file"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Secure Enclave checks (macOS with AGENTPAY_SE_TESTS=1)
// ---------------------------------------------------------------------------------------------

fn se_status_reports_secure_enclave(helper: &Helper, _dir: &Path) -> Result<()> {
    let status = helper.ok(&["status"])?;
    ensure!(
        status["secureEnclaveAvailable"] == json!(true),
        "status reports no Secure Enclave ({status}); unset {SE_TESTS_ENV} on this machine"
    );
    Ok(())
}

fn se_create_sign_verify_delete(helper: &Helper, dir: &Path) -> Result<()> {
    let key = dir.join("admin-key.json");
    let public = helper.create(&key, false)?;
    ensure!(
        public.len() == 65 && public.first() == Some(&0x04),
        "public key is not uncompressed SEC1"
    );
    let verifying_key = VerifyingKey::from_sec1_bytes(&public)
        .map_err(|error| anyhow!("public key is not a P-256 point: {error}"))?;
    ensure!(
        mode_of(&key)? == 0o600,
        "key file mode is {:o}",
        mode_of(&key)?
    );
    let stored = read_json(&key)?;
    ensure!(
        stored["kind"] == json!(KEY_FILE_KIND)
            && stored["version"] == json!(1)
            && stored["publicKeySec1Hex"] == json!(hex::encode(&public)),
        "unexpected key file contents {stored}"
    );

    for (message, no_ui) in [
        (&b"agentpay-challenge-1"[..], false),
        (&b"agentpay-challenge-2"[..], true),
    ] {
        let signature = helper.sign(&key, message, no_ui)?;
        verifying_key
            .verify(message, &signature)
            .map_err(|error| anyhow!("signature does not verify with p256: {error}"))?;
        ensure!(
            verifying_key
                .verify(b"another message", &signature)
                .is_err(),
            "signature verifies for a different message"
        );
    }
    helper.ok(&Helper::sign_args(utf8(&key)?, "0x00ff", true))?;

    helper.fails_with(
        &["create", "--key-file", utf8(&key)?, "--no-user-presence"],
        INVALID_INPUT,
    )?;
    ensure!(
        read_json(&key)? == stored,
        "create overwrote an existing key"
    );
    helper.ok(&["delete", "--key-file", utf8(&key)?])?;
    helper.fails_with(&Helper::sign_args(utf8(&key)?, "00", true), KEY_NOT_FOUND)
}

fn se_public_key_mismatch_is_invalidated(helper: &Helper, dir: &Path) -> Result<()> {
    let key = dir.join("admin-key.json");
    let other = dir.join("other-key.json");
    helper.create(&key, false)?;
    helper.create(&other, false)?;
    // Pair this key's blob with another key's public key: the helper must refuse to sign.
    let mut tampered = read_json(&key)?;
    tampered["publicKeySec1Hex"] = read_json(&other)?["publicKeySec1Hex"].clone();
    rewrite_json(&key, &tampered)?;
    helper.fails_with(&Helper::sign_args(utf8(&key)?, "00", true), KEY_INVALIDATED)
}

fn se_corrupted_blob_is_invalidated(helper: &Helper, dir: &Path) -> Result<()> {
    let key = dir.join("admin-key.json");
    helper.create(&key, false)?;
    let mut contents = read_json(&key)?;
    let mut blob = hex::decode(
        contents["dataRepresentationHex"]
            .as_str()
            .context("key file has no dataRepresentationHex")?,
    )?;
    let middle = blob.len() / 2;
    blob[middle] ^= 0xff;
    contents["dataRepresentationHex"] = json!(hex::encode(blob));
    rewrite_json(&key, &contents)?;
    helper.fails_with(&Helper::sign_args(utf8(&key)?, "00", true), KEY_INVALIDATED)
}

/// Regression test for the defect that retired the Rust implementation: reloading the key
/// through `SecKeyCreateWithData` dropped its access control, so a key that should require a
/// prompt signed silently. A user-presence key must never sign when no prompt may be shown.
fn se_user_presence_key_refuses_to_sign_without_ui(helper: &Helper, dir: &Path) -> Result<()> {
    let status = helper.ok(&["status"])?;
    ensure!(
        status["userPresenceAvailable"] == json!(true),
        "user presence is unavailable ({status}); set a login password to run this check"
    );
    let key = dir.join("admin-key.json");
    helper.create(&key, true)?;
    let reply = helper.invoke(&Helper::sign_args(utf8(&key)?, "00", true))?;
    ensure!(
        !reply.success,
        "SECURITY: a user-presence key signed without user interaction: {}",
        reply.json
    );
    ensure!(
        reply.error_code() == Some(INTERACTION_NOT_ALLOWED),
        "expected {INTERACTION_NOT_ALLOWED}, got {}",
        reply.json
    );
    Ok(())
}
