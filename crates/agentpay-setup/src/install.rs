//! `agentpay-setup install`: idempotent install or upgrade of the root daemon.
//!
//! Steps, in order:
//! 1. resolve the user the daemon serves;
//! 2. verify the source binaries;
//! 3. create the payments service account;
//! 4. create the root-owned directories;
//! 5. inspect the existing install and decide what to do with secrets ([`SecretPlan`]);
//! 6. install binaries and the embedded runner script;
//! 7. generate (first install) or keep the machine secret;
//! 8. migrate a legacy vault-password install, if any;
//! 9. write the launchd plist / systemd unit;
//! 10. start or restart the daemon only when something changed or it is not running;
//! 11. wait until the root-owned socket accepts connections;
//! 12. write the payments service definition (run as the service account, whose uid is on the
//!     daemon's agent allowlist from step 9), start or restart it the same way, and wait for its
//!     socket, owned by the service account;
//! 13. record the install manifest.
//!
//! The payments service's own directories (macOS) are created with the other directories in
//! step 4, owned by the service account.
//!
//! Re-running install on an up-to-date machine changes nothing and leaves the daemon running.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::layout::SecretLocation;
use crate::layout::{Layout, Platform, KEYCHAIN_HELPER_BIN};
use crate::manifest::{self, Manifest};
use crate::payments::{self, PaymentsServiceConfig};
use crate::report::{actionable, Done, Failure, Reporter};
use crate::secret::{self, MachineSecret};
use crate::service::{self, DaemonConfig};
use crate::system::{Account, FileKind, System};
use crate::{migrate, trust, users};

/// Options for [`install`].
#[derive(Debug, Clone)]
pub struct InstallOptions {
    /// Login name of the user the daemon is installed for.
    pub user: String,
    /// Directory holding the freshly built/downloaded binaries.
    pub source_dir: PathBuf,
    /// macOS recovery: the keychain helper of the release that wrote the legacy vault password.
    pub legacy_helper: Option<PathBuf>,
    /// How long to wait for the daemon socket.
    pub socket_timeout: Duration,
}

/// What install does with the daemon secrets, decided before anything is modified.
enum SecretPlan {
    /// No secret and no state: generate a new secret.
    Generate,
    /// A secret exists. `restore` holds it when it must be re-stored (macOS: the keychain item's
    /// ACL trusts only the helper binary that wrote it, so a helper upgrade re-writes it).
    Keep { restore: Option<MachineSecret> },
    /// Legacy vault password and state exist: migrate. `reuse` is a new secret left behind by an
    /// interrupted migration.
    Migrate {
        legacy: Zeroizing<String>,
        reuse: Option<MachineSecret>,
    },
    /// Legacy vault password without state: discard it and generate a new secret.
    DropLegacy,
}

/// What remains to be done about a legacy vault password after the secret step.
enum LegacyAction {
    /// No legacy password; `secret_changed` tells whether the stored secret was (re)written.
    None { secret_changed: bool },
    /// Delete the legacy password (there is no state to migrate).
    Discard,
    /// Migrate the state from `legacy` to `secret`, then delete the legacy password.
    Migrate {
        legacy: Zeroizing<String>,
        secret: MachineSecret,
    },
}

/// Validates a login name before it is used in paths, keychain attributes or commands.
pub fn validate_user_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if valid {
        Ok(())
    } else {
        Err(anyhow!("invalid user name '{name}'"))
    }
}

fn resolve_user(sys: &dyn System, name: &str) -> Result<Account> {
    validate_user_name(name)?;
    let account = sys.lookup_user(name)?.ok_or_else(|| {
        actionable(
            format!("user '{name}' does not exist"),
            "Pass your own login name with --user.",
        )
    })?;
    if account.uid == 0 {
        return Err(actionable(
            "the daemon must be installed for a regular user, not root",
            "Rerun from your own account: sudo agentpay-setup install --user \"$USER\"",
        ));
    }
    Ok(account)
}

/// Installs or upgrades the daemon. Returns the JSON `result` on success.
pub fn install(
    sys: &dyn System,
    layout: &Layout,
    options: &InstallOptions,
    reporter: &mut Reporter<'_>,
) -> Result<Value, Failure> {
    let user = reporter.step("Installing for", || {
        let account = resolve_user(sys, &options.user)?;
        let detail = format!("{} (uid {})", account.name, account.uid);
        Ok((account, Done::unchanged(detail)))
    })?;

    reporter.step("Source binaries", || {
        for binary in &layout.binaries {
            trust::check_source_binary(sys, &options.source_dir.join(binary.name), user.uid)
                .map_err(|error| {
                    actionable(
                        format!("{error:#}"),
                        "Reinstall AgentPay so the binaries are complete, then rerun setup.",
                    )
                })?;
        }
        Ok((
            (),
            Done::unchanged(options.source_dir.display().to_string()),
        ))
    })?;

    let service_account = reporter.step("Service account", || {
        let result = users::ensure_service_account(sys, layout)?;
        let account = &result.account;
        let detail = format!("{} (uid {})", account.name, account.uid);
        let done = if result.created {
            Done::changed(format!("{detail}, created"))
        } else {
            Done::unchanged(detail)
        };
        Ok((result.account, done))
    })?;

    reporter.step("Directories", || {
        let mut created = 0;
        for (dir, mode) in layout.directories() {
            let before = sys.lstat(&dir)?;
            sys.ensure_dir(&dir, mode)?;
            if before.map(|meta| (meta.uid, meta.mode)) != Some((0, mode)) {
                created += 1;
            }
        }
        let done = match created {
            0 => Done::unchanged("in place"),
            n => Done::changed(format!("{n} prepared")),
        };
        Ok(((), done))
    })?;

    reporter.step("Payments directories", || {
        let done = match payments::ensure_directories(sys, layout, &service_account)? {
            0 if layout.payments_directories().is_empty() => Done::unchanged("managed by systemd"),
            0 => Done::unchanged("in place"),
            n => Done::changed(format!("{n} prepared for {}", service_account.name)),
        };
        Ok(((), done))
    })?;

    let plan = reporter.step("Existing install", || {
        if let Some(path) = &options.legacy_helper {
            adopt_legacy_helper(sys, layout, path)?;
        }
        plan_secrets(sys, layout, &options.source_dir, &user)
    })?;
    let migrating = matches!(plan, SecretPlan::Migrate { .. });

    let binaries_changed = reporter.step("Binaries", || {
        let marker = layout.restart_marker();
        let pending = sys.lstat(&marker)?.is_some();
        let mut updated = 0;
        for binary in &layout.binaries {
            let (src, dest) = (
                options.source_dir.join(binary.name),
                layout.managed(binary.name),
            );
            if !file_matches(sys, &dest, binary.mode, |d| sys.same_contents(&src, d))? {
                if updated == 0 && !pending {
                    sys.write_file(&marker, b"", 0o600)?;
                }
                if migrating {
                    preserve_previous_helper(sys, layout, &dest)?;
                }
                sys.copy_file(&src, &dest, binary.mode)?;
                updated += 1;
            }
        }
        let runner = layout.runner_script().as_bytes();
        let runner_path = layout.runner();
        if !file_matches(sys, &runner_path, 0o755, |d| {
            Ok(*sys.read_file(d)? == *runner)
        })? {
            if updated == 0 && !pending {
                sys.write_file(&marker, b"", 0o600)?;
            }
            sys.write_file(&runner_path, runner, 0o755)?;
            updated += 1;
        }
        let done = match (updated, pending) {
            (0, false) => Done::unchanged("up to date"),
            (0, true) => Done::unchanged("up to date; services still need a restart"),
            (n, _) => Done::changed(format!("{n} updated in {}", layout.bin_dir.display())),
        };
        Ok((updated > 0 || pending, done))
    })?;

    let helper = layout.keychain_helper();
    let legacy_action = reporter.step("Machine secret", || {
        let location = layout.secret.describe();
        let store = |secret: &MachineSecret| {
            secret::store(sys, &layout.secret, helper.as_deref(), secret.expose())
        };
        let generated = || Done::changed(format!("generated, stored in {location}"));
        Ok(match plan {
            SecretPlan::Keep { restore: None } => (
                LegacyAction::None {
                    secret_changed: false,
                },
                Done::unchanged(format!("present in {location}")),
            ),
            SecretPlan::Keep {
                restore: Some(secret),
            } => {
                store(&secret)?;
                // A helper adopted to read it (`--legacy-helper`) is no longer needed.
                if let Some(previous) = layout.previous_keychain_helper() {
                    if sys.lstat(&previous)?.is_some() {
                        sys.remove_file(&previous)?;
                    }
                }
                let done = Done::changed(format!("re-sealed in {location}"));
                (
                    LegacyAction::None {
                        secret_changed: true,
                    },
                    done,
                )
            }
            SecretPlan::Generate => {
                store(&MachineSecret::generate(sys)?)?;
                (
                    LegacyAction::None {
                        secret_changed: true,
                    },
                    generated(),
                )
            }
            SecretPlan::DropLegacy => {
                store(&MachineSecret::generate(sys)?)?;
                (LegacyAction::Discard, generated())
            }
            SecretPlan::Migrate { legacy, reuse } => {
                let secret = match reuse {
                    Some(secret) => secret,
                    None => MachineSecret::generate(sys)?,
                };
                store(&secret)?;
                (LegacyAction::Migrate { legacy, secret }, generated())
            }
        })
    })?;

    let secret_changed = match &legacy_action {
        LegacyAction::None { secret_changed } => *secret_changed,
        LegacyAction::Discard | LegacyAction::Migrate { .. } => true,
    };
    let migrated = match legacy_action {
        LegacyAction::None { .. } => false,
        action => reporter.step("Wallet state", || {
            let detail = match &action {
                LegacyAction::Migrate { legacy, secret } => {
                    service::stop(sys, &layout.signer_unit())?;
                    migrate::run(sys, layout, legacy, secret)?;
                    "migrated from the vault password to the machine secret"
                }
                _ => "no wallet state; old vault password discarded",
            };
            // Only after a successful migration: the legacy password is the rollback path.
            secret::delete(sys, &layout.legacy_secret(&user.name))?;
            // The old helper was only kept to read that password.
            if let Some(previous) = layout.previous_keychain_helper() {
                sys.remove_file(&previous)?;
            }
            let migrated = matches!(action, LegacyAction::Migrate { .. });
            Ok((migrated, Done::changed(detail)))
        })?,
    };

    let definition_changed = reporter.step("Service definition", || {
        let config = DaemonConfig {
            admin_uids: vec![user.uid],
            agent_uids: vec![user.uid, service_account.uid],
        };
        let definition = service::render_definition(layout, &config);
        let path = &layout.service_file;
        let current = |p: &Path| Ok(*sys.read_file(p)? == *definition.as_bytes());
        if file_matches(sys, path, 0o644, current)? {
            return Ok((false, Done::unchanged(path.display().to_string())));
        }
        sys.write_file(path, definition.as_bytes(), 0o644)?;
        Ok((true, Done::changed(path.display().to_string())))
    })?;

    reporter.step("Daemon", || {
        let unit = layout.signer_unit();
        let state = service::state(sys, &unit)?;
        let changed = binaries_changed || secret_changed || migrated || definition_changed;
        if state.running && !changed {
            return Ok(((), Done::unchanged("already running")));
        }
        service::start(sys, &unit, definition_changed || !state.loaded)?;
        let verb = if state.running {
            "restarted"
        } else {
            "started"
        };
        Ok(((), Done::changed(verb)))
    })?;

    reporter.step("Daemon socket", || {
        trust::wait_for_socket(sys, &layout.socket, options.socket_timeout)
            .map_err(|error| actionable(format!("{error:#}"), log_hint(layout)))?;
        Ok((
            (),
            Done::unchanged(format!("ready at {}", layout.socket.display())),
        ))
    })?;

    let payments_definition_changed = reporter.step("Payments definition", || {
        let config = PaymentsServiceConfig {
            client_uids: vec![user.uid],
        };
        let definition = payments::render_definition(layout, &service_account, &config);
        let path = &layout.payments.service_file;
        let current = |p: &Path| Ok(*sys.read_file(p)? == *definition.as_bytes());
        if file_matches(sys, path, 0o644, current)? {
            return Ok((false, Done::unchanged(path.display().to_string())));
        }
        sys.write_file(path, definition.as_bytes(), 0o644)?;
        Ok((true, Done::changed(path.display().to_string())))
    })?;

    reporter.step("Payments service", || {
        let unit = layout.payments_unit();
        let state = service::state(sys, &unit)?;
        let changed = binaries_changed || payments_definition_changed;
        if state.running && !changed {
            return Ok(((), Done::unchanged("already running")));
        }
        service::start(sys, &unit, payments_definition_changed || !state.loaded)?;
        let verb = if state.running {
            "restarted"
        } else {
            "started"
        };
        Ok(((), Done::changed(verb)))
    })?;

    reporter.step("Payments socket", || {
        let socket = &layout.payments.socket;
        trust::wait_for_socket_owned_by(sys, socket, service_account.uid, options.socket_timeout)
            .map_err(|error| actionable(format!("{error:#}"), payments_log_hint(layout)))?;
        // Both services now run the installed binaries.
        if binaries_changed {
            sys.remove_file(&layout.restart_marker())?;
        }
        Ok((
            (),
            Done::unchanged(format!("ready at {}", socket.display())),
        ))
    })?;

    reporter.step("Install record", || {
        let record = Manifest {
            schema: manifest::SCHEMA,
            version: env!("CARGO_PKG_VERSION").into(),
            user: user.name.clone(),
            uid: user.uid,
            service_user: service_account.name.clone(),
            service_uid: service_account.uid,
        };
        if manifest::read(sys, layout).ok().flatten().as_ref() == Some(&record) {
            return Ok(((), Done::unchanged(layout.manifest.display().to_string())));
        }
        sys.write_file(&layout.manifest, &record.to_bytes()?, 0o644)?;
        Ok(((), Done::changed(layout.manifest.display().to_string())))
    })?;

    Ok(json!({
        "platform": layout.platform,
        "user": user.name,
        "uid": user.uid,
        "service_user": service_account.name,
        "service_uid": service_account.uid,
        "socket": layout.socket,
        "payments_socket": layout.payments.socket,
        "state_file": layout.state_file,
        "secret_location": layout.secret.describe(),
        "migrated": migrated,
        "changed": reporter.steps().iter().any(|step| step.changed),
    }))
}

/// Where to look when the daemon does not come up.
pub fn log_hint(layout: &Layout) -> String {
    match &layout.log_dir {
        Some(dir) => format!(
            "Check the daemon log: sudo tail -n 50 {}/{}.err.log",
            dir.display(),
            layout.label
        ),
        None => format!(
            "Check the daemon log: sudo journalctl -u {}.service -n 50",
            layout.label
        ),
    }
}

/// Where to look when the payments service does not come up.
pub fn payments_log_hint(layout: &Layout) -> String {
    match &layout.payments.log_dir {
        Some(dir) => format!(
            "Check the payments service log: sudo tail -n 50 {}/{}.err.log",
            dir.display(),
            layout.payments.label
        ),
        None => format!(
            "Check the payments service log: sudo journalctl -u {}.service -n 50",
            layout.payments.label
        ),
    }
}

/// Whether `path` is a root-owned regular file with `mode` whose contents pass `same`.
fn file_matches(
    sys: &dyn System,
    path: &Path,
    mode: u32,
    same: impl FnOnce(&Path) -> Result<bool>,
) -> Result<bool> {
    match sys.lstat(path)? {
        Some(meta) if meta.kind == FileKind::File && meta.uid == 0 && meta.mode == mode => {
            same(path)
        }
        _ => Ok(false),
    }
}

/// The helper used to read existing keychain items: the installed one (whose binary the item
/// ACL trusts) when present, otherwise the new one.
fn reading_helper(sys: &dyn System, layout: &Layout, source_dir: &Path) -> Result<Option<PathBuf>> {
    let Some(managed) = layout.keychain_helper() else {
        return Ok(None);
    };
    Ok(Some(if sys.lstat(&managed)?.is_some() {
        managed
    } else {
        source_dir.join(KEYCHAIN_HELPER_BIN)
    }))
}

/// Reads the legacy vault password, falling back to the preserved previous helper (macOS): the
/// item's ACL trusts the helper build that wrote it, which a newer helper is not.
fn read_legacy_password(
    sys: &dyn System,
    layout: &Layout,
    legacy: &SecretLocation,
    helper: Option<&Path>,
) -> Result<Zeroizing<String>> {
    let first = match secret::read(sys, legacy, helper) {
        Ok(password) => return Ok(password),
        Err(error) => error,
    };
    if let Some(previous) = layout.previous_keychain_helper() {
        if sys.lstat(&previous)?.is_some() {
            if let Ok(password) = secret::read(sys, legacy, Some(&previous)) {
                return Ok(password);
            }
        }
    }
    if layout.platform == Platform::Linux {
        return Err(actionable(
            format!("found a legacy install but could not read its vault password: {first:#}"),
            "Restore the wallet from your encrypted backup with a fresh setup.",
        ));
    }
    // The helper build the item trusts is gone (e.g. a local build an older setup replaced):
    // ask an administrator to approve this one read in the macOS dialog.
    secret::read_with_approval(sys, legacy).map_err(|error| {
        actionable(
            format!("could not read the old vault password: {error:#}"),
            "Your wallet state was not changed. Rerun setup in a logged-in session and click \
             Allow (not Always Allow) when macOS asks to use \"agentpay-daemon-password\"; or \
             pass --legacy-helper with the helper that wrote it; or restore from your backup.",
        )
    })
}

/// Keeps the currently installed keychain helper before it is replaced, so a legacy vault
/// password stays readable until it has been migrated. An existing copy is never overwritten:
/// it is the build that wrote the legacy item.
fn preserve_previous_helper(sys: &dyn System, layout: &Layout, managed: &Path) -> Result<()> {
    let Some(previous) = layout.previous_keychain_helper() else {
        return Ok(());
    };
    if Some(managed) != layout.keychain_helper().as_deref() || sys.lstat(&previous)?.is_some() {
        return Ok(());
    }
    if !matches!(sys.lstat(managed)?, Some(meta) if meta.kind == FileKind::File && meta.uid == 0) {
        return Ok(());
    }
    ensure_previous_dir(sys, &previous)?;
    sys.copy_file(managed, &previous, 0o700)
}

/// Copies a user-supplied legacy keychain helper into the root-owned previous-helper slot, so it
/// can no longer be swapped while setup runs it as root.
fn adopt_legacy_helper(sys: &dyn System, layout: &Layout, path: &Path) -> Result<()> {
    let Some(previous) = layout.previous_keychain_helper() else {
        return Err(actionable(
            "--legacy-helper is only used on macOS",
            "Rerun setup without --legacy-helper.",
        ));
    };
    match sys.lstat(path)? {
        Some(meta) if meta.kind == FileKind::File => {}
        _ => {
            return Err(actionable(
                format!("{} is not a regular file", path.display()),
                "Pass the agentpay-system-keychain binary itself (not a symlink or folder).",
            ))
        }
    }
    ensure_previous_dir(sys, &previous)?;
    sys.copy_file(path, &previous, 0o700)
}

fn ensure_previous_dir(sys: &dyn System, previous: &Path) -> Result<()> {
    match previous.parent() {
        Some(dir) => sys.ensure_dir(dir, 0o700),
        None => Ok(()),
    }
}

/// Whether installing will replace the keychain helper binary.
fn helper_will_change(sys: &dyn System, layout: &Layout, source_dir: &Path) -> Result<bool> {
    let Some(managed) = layout.keychain_helper() else {
        return Ok(false);
    };
    if sys.lstat(&managed)?.is_none() {
        return Ok(true);
    }
    Ok(!sys.same_contents(&source_dir.join(KEYCHAIN_HELPER_BIN), &managed)?)
}

/// Reads the machine secret that the installed helper cannot read, so it can be re-sealed for
/// that helper: with the helper build that wrote it (`--legacy-helper`), else through the macOS
/// approval dialog.
fn recover_secret(
    sys: &dyn System,
    layout: &Layout,
    first: &anyhow::Error,
) -> Result<MachineSecret> {
    if let Some(previous) = layout.previous_keychain_helper() {
        if sys.lstat(&previous)?.is_some() {
            if let Ok(text) = secret::read(sys, &layout.secret, Some(&previous)) {
                return MachineSecret::parse(&text);
            }
        }
    }
    let text = secret::read_with_approval(sys, &layout.secret).map_err(|error| {
        actionable(
            format!(
                "the installed keychain helper cannot read the machine secret ({first:#}), and \
                 reading it with approval failed: {error:#}"
            ),
            "Your wallet state was not changed. Rerun setup in a logged-in session and click \
             Allow (not Always Allow) when macOS asks to use \"agentpay-daemon-secret\"; or \
             pass --legacy-helper with the agentpay-system-keychain that wrote it; or restore \
             the wallet from your backup.",
        )
    })?;
    MachineSecret::parse(&text)
}

fn plan_secrets(
    sys: &dyn System,
    layout: &Layout,
    source_dir: &Path,
    user: &Account,
) -> Result<(SecretPlan, Done)> {
    let state_exists = sys.lstat(&layout.state_file)?.is_some();
    let secret_present = secret::is_present(sys, &layout.secret)?;
    let legacy = layout.legacy_secret(&user.name);
    let legacy_present = secret::is_present(sys, &legacy)?;
    let helper = reading_helper(sys, layout, source_dir)?;
    let read_current = || -> Result<MachineSecret> {
        let text = secret::read(sys, &layout.secret, helper.as_deref())?;
        MachineSecret::parse(&text)
    };

    if legacy_present && state_exists {
        let legacy_password = read_legacy_password(sys, layout, &legacy, helper.as_deref())?;
        let reuse = if secret_present {
            Some(read_current()?)
        } else {
            None
        };
        let plan = SecretPlan::Migrate {
            legacy: legacy_password,
            reuse,
        };
        return Ok((
            plan,
            Done::unchanged("vault-password install found, will migrate"),
        ));
    }
    if legacy_present {
        return Ok((
            SecretPlan::DropLegacy,
            Done::unchanged("old vault password, no wallet state"),
        ));
    }
    if !secret_present {
        if state_exists {
            return Err(actionable(
                format!(
                    "wallet state exists at {} but its machine secret is missing",
                    layout.state_file.display()
                ),
                "Restore the machine secret, or run `sudo agentpay-setup uninstall` and set up \
                 again from your wallet backup.",
            ));
        }
        return Ok((SecretPlan::Generate, Done::unchanged("none, fresh install")));
    }
    // On macOS the installed helper must be able to read the secret, because the daemon's runner
    // reads it with that helper at every start. It is re-sealed when the helper changes, and
    // also when the installed helper already cannot read it (a setup that stopped after
    // replacing the binaries): then macOS asks an administrator to allow one read.
    let restore = match layout.platform {
        Platform::Linux => {
            read_current()?;
            None
        }
        Platform::Macos => {
            let changing = helper_will_change(sys, layout, source_dir)?;
            match read_current() {
                Ok(secret) => changing.then_some(secret),
                Err(error) if state_exists => Some(recover_secret(sys, layout, &error)?),
                // Nothing is encrypted with the unreadable secret yet, so a new one is safe.
                Err(_) => {
                    return Ok((
                        SecretPlan::Generate,
                        Done::unchanged("unreadable secret, no state"),
                    ))
                }
            }
        }
    };
    let detail = if state_exists {
        "existing install with wallet state"
    } else {
        "existing install"
    };
    Ok((SecretPlan::Keep { restore }, Done::unchanged(detail)))
}
