//! Startup orchestration and signer-backend selection.
//!
//! [`run_cli_with_runtime`] resolves paths, takes the state-file lock, builds
//! the peer allowlists, and then dispatches to the [`DaemonRuntime`] method for
//! the selected signer backend. The trait seam lets tests verify dispatch
//! without binding sockets or touching key material.

use std::path::PathBuf;
use std::sync::Arc;

#[cfg(target_os = "linux")]
use agentpay_signer::LinuxTpmSignerBackend;
use agentpay_signer::{SoftwareSignerBackend, VaultSignerBackend};
use agentpay_signerd::{DaemonConfig, InMemoryDaemon, PersistentStoreConfig};
use anyhow::{Context, Result};
use async_trait::async_trait;

use crate::config::args::{Cli, SignerBackendKind};
use crate::config::paths::{resolve_socket_path, resolve_state_file_path};
use crate::config::peers::{resolve_allowed_peer_euids, AllowedPeerEuids};
use crate::config::secret::StateUnlock;
use crate::server::{bind_server, run_bound_daemon};
use crate::state_lock::acquire_state_file_lock;

/// Starts and runs the daemon for one signer backend.
// `async_trait` adds `#[must_use]` to methods that already return a boxed future.
#[allow(clippy::double_must_use)]
#[async_trait]
pub(crate) trait DaemonRuntime {
    async fn run_software(
        &self,
        daemon_socket: PathBuf,
        allowed_peer_euids: AllowedPeerEuids,
        unlock: StateUnlock,
        state_file: PathBuf,
    ) -> Result<()>;

    #[cfg(target_os = "linux")]
    async fn run_tpm(
        &self,
        daemon_socket: PathBuf,
        allowed_peer_euids: AllowedPeerEuids,
        unlock: StateUnlock,
        state_file: PathBuf,
        tpm_device: PathBuf,
    ) -> Result<()>;
}

/// Production runtime: binds the socket, unlocks persistent state, and serves until shutdown.
pub(crate) struct RealDaemonRuntime;

/// Resolves configuration, holds the state lock, and runs the selected backend to completion.
pub(crate) async fn run_cli_with_runtime<R>(
    cli: Cli,
    unlock: StateUnlock,
    runtime: &R,
) -> Result<()>
where
    R: DaemonRuntime + ?Sized,
{
    let state_file = resolve_state_file_path(cli.state_file.clone())?;
    // Migration never binds the socket, and `agentpay-setup` runs it with an empty environment,
    // so the socket default (which needs `HOME`/`AGENTPAY_HOME`) is only resolved when serving.
    let daemon_socket = if unlock.is_migration() {
        cli.daemon_socket.clone().unwrap_or_default()
    } else {
        resolve_socket_path(cli.daemon_socket.clone())?
    };
    let _state_lock = acquire_state_file_lock(&state_file)?;

    let allowed_peer_euids = resolve_allowed_peer_euids(
        &cli.allow_admin_euid,
        &cli.allow_agent_euid,
        &cli.allow_client_euid,
    )?;
    if !cli.allow_client_euid.is_empty() {
        eprintln!(
            "==> warning: --allow-client-euid grants both admin and agent access; prefer --allow-admin-euid and --allow-agent-euid"
        );
    }

    dispatch_runtime(
        cli,
        unlock,
        state_file,
        daemon_socket,
        allowed_peer_euids,
        runtime,
    )
    .await
}

async fn dispatch_runtime<R>(
    cli: Cli,
    unlock: StateUnlock,
    state_file: PathBuf,
    daemon_socket: PathBuf,
    allowed_peer_euids: AllowedPeerEuids,
    runtime: &R,
) -> Result<()>
where
    R: DaemonRuntime + ?Sized,
{
    match cli.signer_backend {
        SignerBackendKind::Software => {
            runtime
                .run_software(daemon_socket, allowed_peer_euids, unlock, state_file)
                .await
        }
        #[cfg(target_os = "linux")]
        SignerBackendKind::Tpm => {
            runtime
                .run_tpm(
                    daemon_socket,
                    allowed_peer_euids,
                    unlock,
                    state_file,
                    cli.tpm_device,
                )
                .await
        }
    }
}

#[async_trait]
impl DaemonRuntime for RealDaemonRuntime {
    async fn run_software(
        &self,
        daemon_socket: PathBuf,
        allowed_peer_euids: AllowedPeerEuids,
        unlock: StateUnlock,
        state_file: PathBuf,
    ) -> Result<()> {
        if unlock.is_migration() {
            return migrate_only(SoftwareSignerBackend::default(), unlock, state_file);
        }
        let server = bind_server(daemon_socket, &allowed_peer_euids).await?;
        let daemon = open_daemon(SoftwareSignerBackend::default(), unlock, state_file)?;
        run_bound_daemon(server, daemon).await
    }

    #[cfg(target_os = "linux")]
    async fn run_tpm(
        &self,
        daemon_socket: PathBuf,
        allowed_peer_euids: AllowedPeerEuids,
        unlock: StateUnlock,
        state_file: PathBuf,
        tpm_device: PathBuf,
    ) -> Result<()> {
        if unlock.is_migration() {
            return migrate_only(LinuxTpmSignerBackend::new(tpm_device), unlock, state_file);
        }
        let server = bind_server(daemon_socket, &allowed_peer_euids).await?;
        let daemon = open_daemon(LinuxTpmSignerBackend::new(tpm_device), unlock, state_file)?;
        run_bound_daemon(server, daemon).await
    }
}

/// Migration is a one-shot operation run by `agentpay-setup` while the service is stopped:
/// opening the store re-encrypts a legacy file under the state secret (a no-op when it is already
/// migrated), then the process exits without serving RPCs.
fn migrate_only<B>(signer_backend: B, unlock: StateUnlock, state_file: PathBuf) -> Result<()>
where
    B: VaultSignerBackend,
{
    open_daemon(signer_backend, unlock, state_file)?;
    eprintln!("==> state file is encrypted under the state secret");
    Ok(())
}

/// Opens the persistent daemon state, migrating a legacy password-encrypted file when requested.
fn open_daemon<B>(
    signer_backend: B,
    unlock: StateUnlock,
    state_file: PathBuf,
) -> Result<Arc<InMemoryDaemon<B>>>
where
    B: VaultSignerBackend,
{
    let (secret, store_config) = match unlock {
        StateUnlock::Secret(secret) => (secret, PersistentStoreConfig::new(state_file)),
        StateUnlock::MigrateFromPassword {
            secret,
            legacy_password,
        } => {
            eprintln!(
                "==> migrating legacy vault-password state file to the state secret (if needed)"
            );
            let store_config = PersistentStoreConfig::new(state_file)
                .with_legacy_password_migration(legacy_password);
            (secret, store_config)
        }
    };
    let daemon = InMemoryDaemon::new_with_persistent_store(
        &secret,
        signer_backend,
        DaemonConfig::default(),
        store_config,
    )
    .context("failed to initialize daemon")?;
    Ok(Arc::new(daemon))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use agentpay_signerd::StateSecret;
    use anyhow::{anyhow, Result};
    use async_trait::async_trait;

    use super::{dispatch_runtime, run_cli_with_runtime, DaemonRuntime};
    use crate::config::args::{Cli, SignerBackendKind};
    use crate::config::peers::AllowedPeerEuids;
    use crate::config::secret::StateUnlock;

    fn test_unlock() -> StateUnlock {
        StateUnlock::Secret(StateSecret::generate())
    }
    use crate::test_support::temp_path;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum RuntimeCall {
        Software {
            daemon_socket: PathBuf,
            allowed_admin: BTreeSet<u32>,
            allowed_agent: BTreeSet<u32>,
            migrating: bool,
            state_file: PathBuf,
        },
        #[cfg(target_os = "linux")]
        Tpm {
            daemon_socket: PathBuf,
            allowed_admin: BTreeSet<u32>,
            allowed_agent: BTreeSet<u32>,
            migrating: bool,
            state_file: PathBuf,
            tpm_device: PathBuf,
        },
    }

    struct FakeRuntime {
        calls: Mutex<Vec<RuntimeCall>>,
        fail_message: Option<&'static str>,
    }

    #[async_trait]
    impl DaemonRuntime for FakeRuntime {
        async fn run_software(
            &self,
            daemon_socket: PathBuf,
            allowed_peer_euids: AllowedPeerEuids,
            unlock: StateUnlock,
            state_file: PathBuf,
        ) -> Result<()> {
            self.calls
                .lock()
                .expect("lock")
                .push(RuntimeCall::Software {
                    daemon_socket,
                    allowed_admin: allowed_peer_euids.admin,
                    allowed_agent: allowed_peer_euids.agent,
                    migrating: matches!(unlock, StateUnlock::MigrateFromPassword { .. }),
                    state_file,
                });
            match self.fail_message {
                Some(message) => Err(anyhow!(message)),
                None => Ok(()),
            }
        }

        #[cfg(target_os = "linux")]
        async fn run_tpm(
            &self,
            daemon_socket: PathBuf,
            allowed_peer_euids: AllowedPeerEuids,
            unlock: StateUnlock,
            state_file: PathBuf,
            tpm_device: PathBuf,
        ) -> Result<()> {
            self.calls.lock().expect("lock").push(RuntimeCall::Tpm {
                daemon_socket,
                allowed_admin: allowed_peer_euids.admin,
                allowed_agent: allowed_peer_euids.agent,
                migrating: matches!(unlock, StateUnlock::MigrateFromPassword { .. }),
                state_file,
                tpm_device,
            });
            match self.fail_message {
                Some(message) => Err(anyhow!(message)),
                None => Ok(()),
            }
        }
    }

    fn sample_cli(root: &Path, signer_backend: SignerBackendKind) -> Cli {
        Cli {
            state_secret_stdin: true,
            migrate_from_password_stdin: false,
            state_file: Some(root.join("state").join("daemon-state.enc")),
            daemon_socket: Some(root.join("socket").join("daemon.sock")),
            signer_backend,
            #[cfg(target_os = "linux")]
            tpm_device: "/dev/tpmrm0".into(),
            allow_admin_euid: vec![11],
            allow_agent_euid: vec![22],
            allow_client_euid: vec![33],
        }
    }

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    /// `agentpay-setup` migrates with an empty environment (no `HOME`), so migration must not
    /// resolve the default socket path; serving still does.
    #[test]
    fn migration_does_not_resolve_the_default_socket_path() {
        let runtime = test_runtime();
        let root = temp_path("agentpay-daemon-migrate-no-socket");
        let mut cli = sample_cli(&root, SignerBackendKind::Software);
        cli.daemon_socket = None;
        cli.state_secret_stdin = false;
        cli.migrate_from_password_stdin = true;
        let fake_runtime = FakeRuntime {
            calls: Mutex::new(Vec::new()),
            fail_message: None,
        };
        let unlock = StateUnlock::MigrateFromPassword {
            secret: StateSecret::generate(),
            legacy_password: vault_daemon_legacy_password(),
        };

        runtime
            .block_on(run_cli_with_runtime(cli, unlock, &fake_runtime))
            .expect("migration dispatch");

        let calls = fake_runtime.calls.lock().expect("lock");
        match calls.as_slice() {
            [RuntimeCall::Software {
                daemon_socket,
                migrating: true,
                ..
            }] => assert_eq!(daemon_socket, &PathBuf::new()),
            other => panic!("unexpected runtime calls: {other:?}"),
        }
    }

    fn vault_daemon_legacy_password() -> agentpay_signerd::LegacyStatePassword {
        agentpay_signerd::LegacyStatePassword::new(zeroize::Zeroizing::new("legacy".to_string()))
            .expect("legacy password")
    }

    #[test]
    fn dispatch_runtime_routes_to_expected_backend() {
        let runtime = test_runtime();
        let root = temp_path("agentpay-daemon-dispatch");
        let state_file = root.join("state.enc");
        let daemon_socket = root.join("daemon.sock");
        let allowed = AllowedPeerEuids {
            admin: BTreeSet::from([0, 11, 33]),
            agent: BTreeSet::from([0, 22, 33]),
        };

        let software_runtime = FakeRuntime {
            calls: Mutex::new(Vec::new()),
            fail_message: None,
        };
        runtime
            .block_on(dispatch_runtime(
                sample_cli(&root, SignerBackendKind::Software),
                test_unlock(),
                state_file.clone(),
                daemon_socket.clone(),
                allowed,
                &software_runtime,
            ))
            .expect("software dispatch");
        assert_eq!(
            software_runtime.calls.lock().expect("lock").as_slice(),
            &[RuntimeCall::Software {
                daemon_socket,
                allowed_admin: BTreeSet::from([0, 11, 33]),
                allowed_agent: BTreeSet::from([0, 22, 33]),
                migrating: false,
                state_file,
            }]
        );
    }

    #[test]
    fn run_cli_with_runtime_resolves_paths_and_lock_before_invoking_runtime() {
        let runtime = test_runtime();
        let root = temp_path("agentpay-daemon-run-runtime");
        let cli = sample_cli(&root, SignerBackendKind::Software);
        let fake_runtime = FakeRuntime {
            calls: Mutex::new(Vec::new()),
            fail_message: None,
        };

        runtime
            .block_on(run_cli_with_runtime(cli, test_unlock(), &fake_runtime))
            .expect("runtime dispatch");

        assert!(root.join("state").exists());
        assert!(root.join("socket").exists());
        assert!(root.join("state").join("daemon-state.enc.lock").exists());
        assert_eq!(fake_runtime.calls.lock().expect("lock").len(), 1);

        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn dispatch_runtime_bubbles_runtime_failures() {
        let runtime = test_runtime();
        let root = temp_path("agentpay-daemon-runtime-error");
        let err_runtime = FakeRuntime {
            calls: Mutex::new(Vec::new()),
            fail_message: Some("runtime boom"),
        };

        let err = runtime
            .block_on(dispatch_runtime(
                sample_cli(&root, SignerBackendKind::Software),
                test_unlock(),
                root.join("daemon-state.enc"),
                root.join("daemon.sock"),
                AllowedPeerEuids {
                    admin: BTreeSet::from([0]),
                    agent: BTreeSet::from([0]),
                },
                &err_runtime,
            ))
            .expect_err("runtime failure must bubble");
        assert!(err.to_string().contains("runtime boom"));
    }
}

#[cfg(test)]
mod migration_tests {
    use std::collections::BTreeSet;

    use agentpay_signerd::{LegacyStatePassword, StateSecret};
    use zeroize::Zeroizing;

    use super::{DaemonRuntime, RealDaemonRuntime};
    use crate::config::peers::AllowedPeerEuids;
    use crate::config::secret::StateUnlock;
    use crate::test_support::temp_path;

    /// `agentpay-setup` runs migration and waits for the process to exit, so migration mode must
    /// never bind the socket or start serving, even when it fails.
    #[test]
    fn migration_mode_exits_without_binding_the_socket() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let root = temp_path("agentpay-daemon-migrate-only");
        crate::test_support::create_private_dir(&root);
        let daemon_socket = root.join("daemon.sock");
        let unlock = StateUnlock::MigrateFromPassword {
            secret: StateSecret::generate(),
            legacy_password: LegacyStatePassword::new(Zeroizing::new("legacy".to_string()))
                .expect("legacy password"),
        };
        let allowed = AllowedPeerEuids {
            admin: BTreeSet::from([0]),
            agent: BTreeSet::from([0]),
        };

        let result = runtime.block_on(RealDaemonRuntime.run_software(
            daemon_socket.clone(),
            allowed,
            unlock,
            root.join("missing-state.enc"),
        ));

        assert!(result.is_err(), "migrating a missing state file must fail");
        assert!(
            !daemon_socket.exists(),
            "migration mode must not bind the socket"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
