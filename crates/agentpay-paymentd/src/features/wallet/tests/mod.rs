//! Wallet feature tests: every method through [`dispatch`] with a real
//! in-memory signer daemon (signing with the documented example key), the
//! loopback mock EVM endpoint for BSC, an unreachable Ethereum endpoint, and
//! the in-process Solana devnet.

mod activity;
mod balances;
mod examples;
mod funding;
mod status;

use std::collections::BTreeMap;
use std::sync::Arc;

use agentpay_api::payments::{
    ChainFamily, ChainProfile, PaymentsConfig, PaymentsRpcRequest as Req,
    PaymentsRpcResponse as Res, TokenChainProfile, TokenProfile,
};
use agentpay_api::AgentAuth;
use agentpay_domain::{AdminAuth, PolicyAttachment, SpendingPolicy};
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use agentpay_signerd::{DaemonConfig, InMemoryDaemon, KeyManagerDaemonApi};
use alloy_primitives::U256;
use solana_sdk::program_pack::Pack;
use solana_sdk::pubkey::Pubkey;
use spl_token_2022_interface::state::Mint;

use super::{handle_with, Budget};
use crate::auth::{authenticate, AuthenticatedAgent};
use crate::chains::evm::mock_rpc::MockRpc;
use crate::chains::solana::accounts::{associated_token_account, system_program_id};
use crate::chains::solana::testing::FakeCluster;
use crate::config::ConfigStore;
use crate::dispatch::dispatch;
use crate::error::PaymentsError;
use crate::signer::testing::InProcessSigner;
use crate::signer::SignerClient;
use crate::state::AppState;
use crate::test_support::TempDir;

/// The signer daemon's example wallet key (held by the `ExportWalletBackup` example backup).
pub(super) const EXAMPLE_KEY: &str =
    "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
/// The example key's EVM address.
pub(super) const EVM_WALLET: &str = "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23";
/// The example key's Solana address.
pub(super) const SOLANA_WALLET: &str = "9fijMemJYwXS5QD85Qxsq7iKqvSebgb6LvpGftgkeigk";
/// USD1 (18 decimals) on BSC and Ethereum.
pub(super) const USD1: &str = "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d";
/// USDC on Solana devnet (6 decimals).
pub(super) const DEVNET_USDC: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
/// An Ethereum endpoint nobody listens on.
pub(super) const DEAD_RPC: &str = "http://127.0.0.1:1";
/// The devnet RPC URL; the fake cluster answers for it.
const DEVNET_RPC: &str = "https://api.devnet.solana.com";

/// Short budgets so failing reads end quickly.
pub(super) const FAST: Budget = Budget {
    connect: std::time::Duration::from_millis(500),
    read: std::time::Duration::from_millis(500),
    check: std::time::Duration::from_millis(500),
};

/// paymentd wired to an in-memory signer daemon, a mock BSC, an unreachable
/// Ethereum, and a fake Solana devnet.
pub(super) struct Harness {
    pub(super) dir: TempDir,
    pub(super) state: AppState,
    pub(super) signer: Arc<InProcessSigner>,
    pub(super) auth: AgentAuth,
    pub(super) bsc: MockRpc,
    pub(super) cluster: FakeCluster,
}

impl Harness {
    /// A harness whose example-key agent is bound by `policies`.
    pub(super) async fn new(policies: Vec<SpendingPolicy>) -> Self {
        let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
            .expect("daemon");
        let admin = AdminAuth::PeerCredentials;
        for policy in policies {
            daemon.add_policy(&admin, policy).await.expect("policy");
        }
        let vault_key = daemon
            .create_vault_key(
                &admin,
                KeyCreateRequest::Import {
                    private_key_hex: EXAMPLE_KEY.to_string().into(),
                },
            )
            .await
            .expect("vault key");
        let credentials = daemon
            .create_agent_key(&admin, vault_key.id, PolicyAttachment::AllPolicies)
            .await
            .expect("agent");
        let auth = AgentAuth {
            agent_key_id: credentials.agent_key.id,
            agent_auth_token: credentials.auth_token.clone(),
        };
        let signer = Arc::new(InProcessSigner {
            daemon: Arc::new(daemon),
        });
        Self::with_signer(signer.clone(), signer, auth).await
    }

    /// A harness reaching `signer` through `client`.
    pub(super) async fn with_signer(
        signer: Arc<InProcessSigner>,
        client: Arc<dyn SignerClient>,
        auth: AgentAuth,
    ) -> Self {
        let dir = TempDir::new("wallet");
        let bsc = MockRpc::start(56).await;
        bsc.chain().token_balance = U256::from(25_500_000_000_000_000_000_u128);
        let cluster = FakeCluster::devnet();
        let mut state = AppState::new(ConfigStore::open(dir.path()).expect("config"), client);
        state.chains.register(Arc::new(cluster.provider()));
        state
            .config
            .set(example_config(bsc.url()))
            .await
            .expect("config");
        fund_solana(&cluster);
        Self {
            dir,
            state,
            signer,
            auth,
            bsc,
            cluster,
        }
    }

    pub(super) async fn call(&self, request: Req) -> Result<Res, PaymentsError> {
        dispatch(&self.state, request).await
    }

    /// Calls the wallet feature directly with `budget`.
    pub(super) async fn call_with(
        &self,
        request: Req,
        budget: Budget,
    ) -> Result<Res, PaymentsError> {
        let agent = self.agent().await;
        handle_with(&self.state, &agent, request, budget).await
    }

    pub(super) async fn agent(&self) -> AuthenticatedAgent {
        authenticate(self.state.signer.as_ref(), &self.auth)
            .await
            .expect("authenticated")
    }

    /// Replaces the configuration after editing it.
    pub(super) async fn edit_config(&self, edit: impl FnOnce(&mut PaymentsConfig)) {
        let mut config = self.state.config.get().await;
        edit(&mut config);
        self.state.config.set(config).await.expect("config");
    }
}

/// BSC (mock), Ethereum (unreachable), and Solana devnet (fake), with BNB,
/// ETH, USD1, SOL, and USDC; defaults USD1 on BSC.
pub(super) fn example_config(bsc_url: &str) -> PaymentsConfig {
    let chain = |chain_id, name: &str, family, url: &str| ChainProfile {
        chain_id,
        name: name.into(),
        family,
        rpc_url: Some(url.into()),
        fallback_rpc_urls: Vec::new(),
    };
    let deployment = |chain_id, address: Option<&str>, decimals| TokenChainProfile {
        chain_id,
        is_native: address.is_none(),
        address: address.map(str::to_string),
        decimals,
    };
    let token = |name: &str, symbol: &str, chains: Vec<(&str, TokenChainProfile)>| TokenProfile {
        name: name.into(),
        symbol: symbol.into(),
        recommended_limits: None,
        chains: chains
            .into_iter()
            .map(|(key, deployment)| (key.to_string(), deployment))
            .collect(),
    };
    PaymentsConfig {
        default_network: "bsc".into(),
        default_asset: "usd1".into(),
        chains: BTreeMap::from([
            ("bsc".into(), chain(56, "BSC", ChainFamily::Evm, bsc_url)),
            ("eth".into(), chain(1, "ETH", ChainFamily::Evm, DEAD_RPC)),
            (
                "solana-devnet".into(),
                chain(
                    900_000_002,
                    "Solana Devnet",
                    ChainFamily::Solana,
                    DEVNET_RPC,
                ),
            ),
        ]),
        tokens: BTreeMap::from([
            (
                "bnb".into(),
                token("BNB", "BNB", vec![("bsc", deployment(56, None, 18))]),
            ),
            (
                "eth".into(),
                token("ETH", "ETH", vec![("eth", deployment(1, None, 18))]),
            ),
            (
                "usd1".into(),
                token(
                    "USD1",
                    "USD1",
                    vec![
                        ("bsc", deployment(56, Some(USD1), 18)),
                        ("eth", deployment(1, Some(USD1), 18)),
                    ],
                ),
            ),
            (
                "sol".into(),
                token(
                    "Solana",
                    "SOL",
                    vec![("solana-devnet", deployment(900_000_002, None, 9))],
                ),
            ),
            (
                "usdc".into(),
                token(
                    "USDC",
                    "USDC",
                    vec![(
                        "solana-devnet",
                        deployment(900_000_002, Some(DEVNET_USDC), 6),
                    )],
                ),
            ),
        ]),
    }
}

/// The wallet holds 0.001 SOL (the fake's fixed lamports) and 12.5 USDC.
fn fund_solana(cluster: &FakeCluster) {
    let wallet: Pubkey = SOLANA_WALLET.parse().expect("wallet");
    let mint: Pubkey = DEVNET_USDC.parse().expect("mint");
    cluster.put_account(wallet, system_program_id(), Vec::new());
    let mut mint_data = vec![0; Mint::LEN];
    Mint::pack(
        Mint {
            mint_authority: None.into(),
            supply: 1_000_000_000_000,
            decimals: 6,
            is_initialized: true,
            freeze_authority: None.into(),
        },
        &mut mint_data,
    )
    .expect("mint");
    cluster.put_account(mint, spl_token::ID, mint_data);
    let mut token_account = vec![0; 165];
    token_account[64..72].copy_from_slice(&12_500_000_u64.to_le_bytes());
    cluster.put_account(
        associated_token_account(&wallet, &mint, &spl_token::ID),
        spl_token::ID,
        token_account,
    );
}
