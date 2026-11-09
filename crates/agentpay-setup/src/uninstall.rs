//! `agentpay-setup uninstall`: remove the managed daemon.
//!
//! Without `--keep-state` this deletes the encrypted wallet state, the payments service's
//! configuration and the machine secret, which is irreversible; the calling client is responsible for confirming that with the user (this
//! binary never prompts). With `--keep-state` both are kept so a later install picks the wallet
//! up again; on macOS the installed keychain helper is kept too, because the keychain item's ACL
//! only trusts the helper binary that wrote it.
//!
//! The payments service account is left in place: removing accounts can orphan files they own,
//! and install reuses it.

use anyhow::Result;
use serde_json::{json, Value};

use crate::layout::{Layout, Platform, KEYCHAIN_HELPER_BIN};
use crate::manifest;
use crate::report::{Done, Failure, Reporter};
use crate::secret;
use crate::service;
use crate::system::System;

/// Options for [`uninstall`].
#[derive(Debug, Clone, Default)]
pub struct UninstallOptions {
    /// Keep the wallet state and machine secret.
    pub keep_state: bool,
    /// Installing user, used to find a legacy macOS keychain item when there is no manifest.
    pub user: Option<String>,
}

fn removed(any: bool, what: String) -> Done {
    if any {
        Done::changed(format!("removed {what}"))
    } else {
        Done::unchanged("not present")
    }
}

/// Removes the managed install. Returns the JSON `result` on success.
pub fn uninstall(
    sys: &dyn System,
    layout: &Layout,
    options: &UninstallOptions,
    reporter: &mut Reporter<'_>,
) -> Result<Value, Failure> {
    // A corrupt manifest must not block removal.
    let record = manifest::read(sys, layout).ok().flatten();
    let user = record
        .as_ref()
        .map(|r| r.user.clone())
        .or(options.user.clone());

    // The payments service depends on the signer daemon, so it goes first.
    reporter.step("Payments service", || {
        let any = service::remove(sys, &layout.payments_unit())?;
        Ok((
            (),
            removed(any, layout.payments.service_file.display().to_string()),
        ))
    })?;

    reporter.step("Service", || {
        let any = service::remove(sys, &layout.signer_unit())?;
        Ok(((), removed(any, layout.service_file.display().to_string())))
    })?;

    reporter.step("Binaries", || {
        let any = if options.keep_state && layout.platform == Platform::Macos {
            remove_prefix_except(sys, layout, KEYCHAIN_HELPER_BIN)?
        } else {
            sys.remove_dir_all(&layout.prefix)?
        };
        Ok(((), removed(any, layout.prefix.display().to_string())))
    })?;

    let log_dirs: Vec<_> = [&layout.log_dir, &layout.payments.log_dir]
        .into_iter()
        .flatten()
        .collect();
    if !log_dirs.is_empty() {
        reporter.step("Logs", || {
            let mut any = false;
            for dir in &log_dirs {
                any |= sys.remove_dir_all(dir)?;
            }
            let shown: Vec<String> = log_dirs.iter().map(|d| d.display().to_string()).collect();
            Ok(((), removed(any, shown.join(", "))))
        })?;
    }

    if options.keep_state {
        reporter.step("Wallet state", || {
            Ok((
                (),
                Done::unchanged(format!(
                    "kept in {} and {}",
                    layout.state_dir.display(),
                    layout.payments.state_dir.display()
                )),
            ))
        })?;
        reporter.step("Machine secret", || {
            Ok((
                (),
                Done::unchanged(format!("kept in {}", layout.secret.describe())),
            ))
        })?;
    } else {
        // State goes first: a leftover secret is harmless, leftover state without its secret
        // is an unusable wallet.
        reporter.step("Wallet state", || {
            let mut any = sys.remove_dir_all(&layout.state_dir)?;
            any |= sys.remove_dir_all(&layout.payments.state_dir)?;
            let what = format!(
                "{} and {}",
                layout.state_dir.display(),
                layout.payments.state_dir.display()
            );
            Ok(((), removed(any, what)))
        })?;
        reporter.step("Machine secret", || {
            let mut any = secret::delete(sys, &layout.secret)?;
            if let Some(user) = &user {
                any |= secret::delete(sys, &layout.legacy_secret(user))?;
            }
            Ok(((), removed(any, layout.secret.describe())))
        })?;
    }

    Ok(json!({
        "platform": layout.platform,
        "kept_state": options.keep_state,
        "service_account_kept": layout.service_user,
    }))
}

/// Removes everything under the prefix except `bin/<keep>`.
fn remove_prefix_except(sys: &dyn System, layout: &Layout, keep: &str) -> Result<bool> {
    let mut any = false;
    for binary in layout.binaries.iter().filter(|binary| binary.name != keep) {
        any |= sys.remove_file(&layout.managed(binary.name))?;
    }
    any |= sys.remove_file(&layout.runner())?;
    any |= sys.remove_file(&layout.manifest)?;
    any |= sys.remove_dir_all(&layout.run_dir)?;
    any |= sys.remove_dir_all(&layout.payments.run_dir)?;
    Ok(any)
}
