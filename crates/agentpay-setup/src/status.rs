//! `agentpay-setup status`: read-only health report of the managed daemon and payments service.
//!
//! Status never reads secret values: keychain presence is checked with `security
//! find-generic-password` (attributes only) and the Linux secret file with `lstat`.

use serde::Serialize;
use serde_json::Value;

use anyhow::Result;

use crate::install::{log_hint, payments_log_hint};
use crate::layout::Layout;
use crate::manifest::{self, Manifest};
use crate::report::Reporter;
use crate::secret;
use crate::service::{self, ServiceState};
use crate::system::{Account, FileKind, System};
use crate::trust::{self, SocketCheck};

/// Machine-readable status.
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    /// Platform of this machine.
    pub platform: crate::layout::Platform,
    /// Version of this `agentpay-setup` binary.
    pub setup_version: &'static str,
    /// Whether any part of a managed install is present.
    pub installed: bool,
    /// The install manifest, if present (holds the installed version).
    pub manifest: Option<Manifest>,
    /// Managed binaries that are missing.
    pub missing_binaries: Vec<String>,
    /// Whether the launchd plist / systemd unit exists.
    pub service_file_present: bool,
    /// Service manager state.
    pub service: ServiceState,
    /// Daemon socket path.
    pub socket: String,
    /// Socket readiness (`ready`, `missing`, `untrusted: ...`, ...).
    pub socket_state: String,
    /// Whether the socket is trusted (root-owned in root-owned directories).
    pub socket_trusted: bool,
    /// Where the machine secret lives.
    pub secret_location: String,
    /// Whether the machine secret is stored.
    pub secret_present: bool,
    /// Whether a legacy vault password is still stored (migration pending); `None` when the
    /// installing user is unknown on macOS.
    pub legacy_secret_present: Option<bool>,
    /// Encrypted wallet state path.
    pub state_file: String,
    /// Whether the wallet state exists.
    pub state_present: bool,
    /// The payments service account, if it exists.
    pub service_account: Option<Account>,
    /// Payments service manager state.
    pub payments_service: ServiceState,
    /// Payments socket path.
    pub payments_socket: String,
    /// Payments socket readiness; it must belong to the service account.
    pub payments_socket_state: String,
}

impl Status {
    /// Whether everything a working install needs is in place.
    pub fn healthy(&self) -> bool {
        self.installed
            && self.missing_binaries.is_empty()
            && self.secret_present
            && self.legacy_secret_present != Some(true)
            && self.service.running
            && self.socket_state == SocketCheck::Ready.describe()
            && self.service_account.is_some()
            && self.payments_service.running
            && self.payments_socket_state == SocketCheck::Ready.describe()
    }
}

/// Collects the status of the install described by `layout`.
pub fn collect(sys: &dyn System, layout: &Layout) -> Result<Status> {
    let manifest = manifest::read(sys, layout)?;
    let mut missing_binaries = Vec::new();
    for name in layout
        .binaries
        .iter()
        .map(|binary| binary.name)
        .chain([crate::layout::RUNNER_SCRIPT])
    {
        let present = sys
            .lstat(&layout.managed(name))?
            .is_some_and(|meta| meta.kind == FileKind::File);
        if !present {
            missing_binaries.push(name.to_string());
        }
    }
    let service_file_present = sys.lstat(&layout.service_file)?.is_some();
    let socket = trust::check_socket(sys, &layout.socket)?;
    let legacy_secret_present = match (&manifest, layout.platform) {
        (Some(record), _) => Some(secret::is_present(
            sys,
            &layout.legacy_secret(&record.user),
        )?),
        (None, crate::layout::Platform::Linux) => {
            Some(secret::is_present(sys, &layout.legacy_secret(""))?)
        }
        (None, crate::layout::Platform::Macos) => None,
    };
    let service_account = sys.lookup_user(layout.service_user)?;
    let payments_socket = match &service_account {
        Some(account) => trust::check_socket_owned_by(sys, &layout.payments.socket, account.uid)?,
        None => SocketCheck::Untrusted(format!("{} is missing", layout.service_user)),
    };
    let installed = manifest.is_some()
        || service_file_present
        || missing_binaries.len() < layout.binaries.len() + 1;
    Ok(Status {
        platform: layout.platform,
        setup_version: env!("CARGO_PKG_VERSION"),
        installed,
        missing_binaries,
        service_file_present,
        service: service::state(sys, &layout.signer_unit())?,
        socket: layout.socket.display().to_string(),
        socket_trusted: matches!(socket, SocketCheck::Ready | SocketCheck::NotAccepting),
        socket_state: socket.describe(),
        secret_location: layout.secret.describe(),
        secret_present: secret::is_present(sys, &layout.secret)?,
        legacy_secret_present,
        state_file: layout.state_file.display().to_string(),
        state_present: sys.lstat(&layout.state_file)?.is_some(),
        service_account,
        payments_service: service::state(sys, &layout.payments_unit())?,
        payments_socket: layout.payments.socket.display().to_string(),
        payments_socket_state: payments_socket.describe(),
        manifest,
    })
}

const INSTALL_HINT: &str = "Run setup: sudo agentpay-setup install --user \"$USER\"";

/// Renders `status` as checks; returns the first failing check's next action, if any.
pub fn report(status: &Status, layout: &Layout, reporter: &mut Reporter<'_>) -> Option<String> {
    let mut next: Option<String> = None;
    let mut check =
        |reporter: &mut Reporter<'_>, title: &str, ok: bool, detail: String, hint: &str| {
            reporter.check(title, ok, detail);
            if !ok && next.is_none() {
                next = Some(hint.to_string());
            }
        };

    let installed = match &status.manifest {
        Some(record) => format!("version {} for {}", record.version, record.user),
        None if status.installed => "partial install (no install record)".into(),
        None => "not installed".into(),
    };
    check(
        reporter,
        "Installed",
        status.manifest.is_some(),
        installed,
        INSTALL_HINT,
    );
    if !status.installed {
        return next;
    }

    let binaries = if status.missing_binaries.is_empty() {
        "complete".to_string()
    } else {
        format!("missing {}", status.missing_binaries.join(", "))
    };
    check(
        reporter,
        "Binaries",
        status.missing_binaries.is_empty(),
        binaries,
        INSTALL_HINT,
    );

    let (secret_ok, secret_detail) = match (status.secret_present, status.legacy_secret_present) {
        (_, Some(true)) => (
            false,
            "old vault password still stored, migration pending".into(),
        ),
        (true, _) => (true, format!("present in {}", status.secret_location)),
        (false, _) => (false, format!("missing from {}", status.secret_location)),
    };
    check(
        reporter,
        "Machine secret",
        secret_ok,
        secret_detail,
        INSTALL_HINT,
    );

    let account = match &status.service_account {
        Some(account) => format!("{} (uid {})", account.name, account.uid),
        None => format!("{} missing", layout.service_user),
    };
    check(
        reporter,
        "Service account",
        status.service_account.is_some(),
        account,
        INSTALL_HINT,
    );

    let (service_detail, service_hint) = match (status.service.loaded, status.service.running) {
        (_, true) => ("running".to_string(), INSTALL_HINT.to_string()),
        (true, false) => ("loaded but not running".into(), log_hint(layout)),
        (false, false) => ("not loaded".into(), INSTALL_HINT.to_string()),
    };
    check(
        reporter,
        "Daemon",
        status.service.running,
        service_detail,
        &service_hint,
    );

    let socket_ok = status.socket_state == SocketCheck::Ready.describe();
    let socket_detail = format!("{} ({})", status.socket_state, status.socket);
    let socket_hint = if status.socket_trusted {
        log_hint(layout)
    } else {
        INSTALL_HINT.to_string()
    };
    check(
        reporter,
        "Daemon socket",
        socket_ok,
        socket_detail,
        &socket_hint,
    );

    let (payments_detail, payments_hint) = match (
        status.payments_service.loaded,
        status.payments_service.running,
    ) {
        (_, true) => ("running".to_string(), INSTALL_HINT.to_string()),
        (true, false) => ("loaded but not running".into(), payments_log_hint(layout)),
        (false, false) => ("not loaded".into(), INSTALL_HINT.to_string()),
    };
    check(
        reporter,
        "Payments service",
        status.payments_service.running,
        payments_detail,
        &payments_hint,
    );
    let payments_socket_ok = status.payments_socket_state == SocketCheck::Ready.describe();
    check(
        reporter,
        "Payments socket",
        payments_socket_ok,
        format!(
            "{} ({})",
            status.payments_socket_state, status.payments_socket
        ),
        &payments_log_hint(layout),
    );

    let state = if status.state_present {
        format!("present ({})", status.state_file)
    } else {
        "not created yet".to_string()
    };
    check(reporter, "Wallet state", true, state, INSTALL_HINT);
    next
}

/// Serializes the status for the JSON `result` field.
pub fn to_json(status: &Status) -> Value {
    serde_json::to_value(status).unwrap_or(Value::Null)
}
