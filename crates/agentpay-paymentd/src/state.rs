//! [`AppState`]: what every request handler can reach.

use std::sync::Arc;

use crate::chains::evm::EvmProvider;
use crate::chains::solana::SolanaProvider;
use crate::chains::ChainRegistry;
use crate::config::ConfigStore;
use crate::features::mpp::SessionLocks;
use crate::proxy::ProxyManager;
use crate::signer::{ApprovalWait, SignerClient};
use crate::telemetry::Telemetry;

/// Release version reported by `Hello`.
pub const SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Shared service state, built once at startup.
pub struct AppState {
    /// The payments configuration.
    pub config: ConfigStore,
    /// The signer daemon.
    pub signer: Arc<dyn SignerClient>,
    /// Chain providers by family.
    pub chains: ChainRegistry,
    /// Default manual-approval wait for signing; methods may ask for less.
    pub approval_wait: ApprovalWait,
    /// Anonymous telemetry. Inactive (never sends) unless the runtime
    /// replaces it with [`Telemetry::start`].
    pub telemetry: Telemetry,
    /// Serializes calls that use the same persisted MPP session channel.
    pub mpp_sessions: Arc<SessionLocks>,
    /// The local paying proxy, when running.
    pub proxy: ProxyManager,
}

impl AppState {
    /// Builds the state and registers the chain providers.
    ///
    /// Feature work registers its provider here, one line per family, for
    /// example `chains.register(Arc::new(EvmProvider::new()));`.
    #[must_use]
    pub fn new(config: ConfigStore, signer: Arc<dyn SignerClient>) -> Self {
        let mut chains = ChainRegistry::new();
        chains.register(Arc::new(EvmProvider::new()));
        // Pending Solana approvals live next to config.json in the state directory.
        let state_dir = config.path().parent().map(std::path::Path::to_path_buf);
        if let Some(state_dir) = &state_dir {
            chains.register(Arc::new(SolanaProvider::new(state_dir)));
        }
        let telemetry = Telemetry::inactive(&state_dir.unwrap_or_default());
        Self {
            config,
            signer,
            chains,
            approval_wait: ApprovalWait::none(),
            telemetry,
            mpp_sessions: Arc::default(),
            proxy: ProxyManager::default(),
        }
    }
}
