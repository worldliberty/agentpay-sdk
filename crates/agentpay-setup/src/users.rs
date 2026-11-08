//! The dedicated unprivileged account for the payments service.
//!
//! The payments service (`agentpay-paymentd`) does all network I/O and must not run as the
//! user or as root. Install creates a hidden system account for it:
//! - macOS: `_agentpay` user and group created with `dscl` in the system id range (300–499);
//! - Linux: `agentpay` system user and group created with `useradd --system`.
//!
//! An existing account with the same name is reused only if its uid is in the system range, so
//! a personal login that happens to share the name is never granted daemon access.

use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};

use crate::layout::{Layout, Platform};
use crate::report::actionable;
use crate::system::{run_checked, Account, Cmd, System};

/// First id tried for a new macOS service account.
const MACOS_FIRST_ID: u32 = 300;
/// Exclusive upper bound of the macOS system id range.
const MACOS_ID_LIMIT: u32 = 500;
/// Exclusive upper bound of the Linux system uid range (`SYS_UID_MAX` default).
const LINUX_SYSTEM_UID_LIMIT: u32 = 1000;
/// Human-readable description stored on the account.
const REAL_NAME: &str = "AgentPay payments service";

/// Result of [`ensure_service_account`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccount {
    /// The account.
    pub account: Account,
    /// Whether it was created by this run.
    pub created: bool,
}

/// Creates the service account if it does not exist yet.
pub fn ensure_service_account(sys: &dyn System, layout: &Layout) -> Result<ServiceAccount> {
    let name = layout.service_user;
    if let Some(account) = sys.lookup_user(name)? {
        check_system_range(layout, &account)?;
        return Ok(ServiceAccount {
            account,
            created: false,
        });
    }
    match layout.platform {
        Platform::Macos => create_macos(sys, name)?,
        Platform::Linux => create_linux(sys, name)?,
    }
    // Directory services can take a moment to publish a new record.
    for _ in 0..10 {
        if let Some(account) = sys.lookup_user(name)? {
            return Ok(ServiceAccount {
                account,
                created: true,
            });
        }
        sys.sleep(Duration::from_millis(200));
    }
    bail!("created service account {name} but it is not visible in the user database")
}

fn check_system_range(layout: &Layout, account: &Account) -> Result<()> {
    let limit = match layout.platform {
        Platform::Macos => MACOS_ID_LIMIT,
        Platform::Linux => LINUX_SYSTEM_UID_LIMIT,
    };
    if account.uid == 0 || account.uid >= limit {
        return Err(actionable(
            format!(
                "account {} already exists with uid {}, which is not a system service account",
                account.name, account.uid
            ),
            format!(
                "Rename or remove the existing {} account, then rerun setup.",
                account.name
            ),
        ));
    }
    Ok(())
}

/// Parses `dscl . -list <dir> <attr>` output (`name value` per line) into the set of ids.
pub fn parse_dscl_ids(output: &str) -> BTreeSet<u32> {
    output
        .lines()
        .filter_map(|line| line.split_whitespace().last()?.parse().ok())
        .collect()
}

/// Lowest id in the macOS system range unused as both a uid and a gid.
pub fn pick_macos_id(used_uids: &BTreeSet<u32>, used_gids: &BTreeSet<u32>) -> Option<u32> {
    (MACOS_FIRST_ID..MACOS_ID_LIMIT).find(|id| !used_uids.contains(id) && !used_gids.contains(id))
}

fn dscl(sys: &dyn System, record: &str, attribute: Option<(&str, &str)>) -> Result<()> {
    let mut cmd = Cmd::new("dscl").args([".", "-create", record]);
    if let Some((key, value)) = attribute {
        cmd = cmd.args([key, value]);
    }
    run_checked(sys, &cmd).map(|_| ())
}

fn create_macos(sys: &dyn System, name: &str) -> Result<()> {
    let list = |dir: &str, attr: &str| -> Result<BTreeSet<u32>> {
        let output = run_checked(sys, &Cmd::new("dscl").args([".", "-list", dir, attr]))?;
        Ok(parse_dscl_ids(&output.stdout_text()))
    };
    let used_uids = list("/Users", "UniqueID")?;
    let used_gids = list("/Groups", "PrimaryGroupID")?;

    let gid = match sys.lookup_group(name)? {
        Some(gid) => gid,
        None => {
            let gid = pick_macos_id(&used_uids, &used_gids)
                .ok_or_else(|| anyhow!("no free system group id between 300 and 499"))?;
            let group = format!("/Groups/{name}");
            dscl(sys, &group, None)?;
            dscl(sys, &group, Some(("PrimaryGroupID", &gid.to_string())))?;
            dscl(sys, &group, Some(("RealName", REAL_NAME)))?;
            dscl(sys, &group, Some(("Password", "*")))?;
            gid
        }
    };
    let uid = if used_uids.contains(&gid) {
        pick_macos_id(&used_uids, &BTreeSet::new())
            .ok_or_else(|| anyhow!("no free system user id between 300 and 499"))?
    } else {
        gid
    };
    let user = format!("/Users/{name}");
    dscl(sys, &user, None)?;
    for (key, value) in [
        ("UniqueID", uid.to_string()),
        ("PrimaryGroupID", gid.to_string()),
        ("UserShell", "/usr/bin/false".to_string()),
        ("NFSHomeDirectory", "/var/empty".to_string()),
        ("RealName", REAL_NAME.to_string()),
        ("Password", "*".to_string()),
        ("IsHidden", "1".to_string()),
    ] {
        dscl(sys, &user, Some((key, &value)))?;
    }
    Ok(())
}

fn create_linux(sys: &dyn System, name: &str) -> Result<()> {
    let mut cmd = Cmd::new("useradd").args([
        "--system",
        "--no-create-home",
        "--home-dir",
        "/nonexistent",
        "--shell",
        "/usr/sbin/nologin",
        "--comment",
        REAL_NAME,
    ]);
    cmd = if sys.lookup_group(name)?.is_some() {
        cmd.args(["--gid", name])
    } else {
        cmd.arg("--user-group")
    };
    run_checked(sys, &cmd.arg(name)).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::fake::FakeSystem;

    #[test]
    fn dscl_ids_are_parsed_and_allocation_skips_used_ids() {
        let uids = parse_dscl_ids("root 0\n_www 70\nfoo 300\nbad line x\n");
        assert_eq!(uids, BTreeSet::from([0, 70, 300]));
        let gids = BTreeSet::from([301]);
        assert_eq!(pick_macos_id(&uids, &gids), Some(302));
    }

    #[test]
    fn macos_account_is_created_once() {
        let sys = FakeSystem::macos();
        let layout = Layout::for_platform(Platform::Macos);
        let first = ensure_service_account(&sys, &layout).unwrap();
        assert!(first.created);
        assert_eq!(first.account.uid, 300);
        assert_eq!(first.account.gid, 300);
        let commands = sys.command_lines();
        assert!(
            commands.contains(&"dscl . -create /Users/_agentpay UserShell /usr/bin/false".into())
        );
        assert!(commands.contains(&"dscl . -create /Users/_agentpay IsHidden 1".into()));

        sys.clear_logs();
        let second = ensure_service_account(&sys, &layout).unwrap();
        assert!(!second.created);
        assert_eq!(second.account, first.account);
        assert!(sys.command_lines().is_empty());
    }

    #[test]
    fn linux_account_reuses_an_existing_group() {
        let sys = FakeSystem::linux();
        sys.state.borrow_mut().groups.insert("agentpay".into(), 998);
        let layout = Layout::for_platform(Platform::Linux);
        let created = ensure_service_account(&sys, &layout).unwrap();
        assert!(created.created);
        let command = sys.command_lines().pop().unwrap();
        assert!(command.contains("--gid agentpay"));
        assert!(command.starts_with("useradd --system"));
    }

    #[test]
    fn existing_login_account_with_the_same_name_is_refused() {
        let sys = FakeSystem::linux();
        sys.add_user("agentpay", 1001, 1001);
        let layout = Layout::for_platform(Platform::Linux);
        let error = ensure_service_account(&sys, &layout).unwrap_err();
        assert!(error.to_string().contains("not a system service account"));
    }
}
