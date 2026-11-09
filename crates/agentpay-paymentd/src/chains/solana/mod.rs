//! The Solana chain provider.
//!
//! [`SolanaProvider`] owns the RPC clients (one per configured URL, created
//! on first use), checks that each endpoint serves the cluster its chain id
//! names (falling back to the chain's backup endpoints, see [`Failover`]), serializes transactions that share a durable nonce account, and
//! keeps the [`PendingStore`] of actions waiting for manual approval.
//! Transaction building is the signer daemon's job: paymentd reads chain
//! state ([`accounts`], [`budget`]), asks for a typed action to be signed,
//! and [`verify`]s the result before broadcasting it through [`SolanaRpc`].

pub mod accounts;
pub mod budget;
pub mod pending;
pub mod rpc;
#[cfg(test)]
pub(crate) mod testing;
pub mod verify;
#[cfg(test)]
mod verify_tests;

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentpay_api::payments::ChainFamily;
use agentpay_domain::{SOLANA_DEVNET_CHAIN_ID, SOLANA_MAINNET_CHAIN_ID, SOLANA_TESTNET_CHAIN_ID};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_rpc_client_api::config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;

pub use pending::{PendingStore, PENDING_FILE_NAME};
pub use rpc::{ConfirmationWait, SolanaRpc};

use super::failover::Failover;
use super::ChainProvider;
use crate::error::PaymentsError;

/// Timeout of one RPC request.
const RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds an RPC client for a URL. Production uses HTTP; tests inject a
/// scripted cluster.
pub type Connector = Arc<dyn Fn(&str) -> RpcClient + Send + Sync>;

/// A configured Solana chain, resolved from the payments configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolanaChain {
    /// The chain key, for example `"solana-devnet"`.
    pub key: String,
    /// Internal Solana network id.
    pub chain_id: u64,
    /// RPC endpoint. Never log it: it may embed an API key.
    pub rpc_url: String,
    /// Backup endpoints, tried in order when `rpc_url` fails. Never logged.
    pub fallback_rpc_urls: Vec<String>,
}

/// The Solana provider registered in [`crate::chains::ChainRegistry`].
pub struct SolanaProvider {
    connector: Connector,
    clients: Mutex<HashMap<String, Arc<RpcClient>>>,
    verified: tokio::sync::Mutex<HashSet<(String, u64)>>,
    nonce_locks: Mutex<HashMap<Pubkey, Arc<tokio::sync::Mutex<()>>>>,
    /// Actions waiting for manual approval.
    pub pending: PendingStore,
    /// How long broadcasts wait for confirmation.
    pub confirmation: ConfirmationWait,
    /// Which endpoint of each network is preferred after a failover.
    pub failover: Failover,
}

impl ChainProvider for SolanaProvider {
    const FAMILY: ChainFamily = ChainFamily::Solana;
}

impl SolanaProvider {
    /// The production provider: HTTP clients with confirmed commitment, and
    /// pending actions in `<state_dir>/solana-pending.json`.
    #[must_use]
    pub fn new(state_dir: &Path) -> Self {
        let connector: Connector = Arc::new(|url: &str| {
            RpcClient::new_with_timeout_and_commitment(
                url.to_string(),
                RPC_TIMEOUT,
                CommitmentConfig::confirmed(),
            )
        });
        Self::with_connector(
            connector,
            PendingStore::open(state_dir.join(PENDING_FILE_NAME)),
        )
    }

    /// A provider with a custom connector and pending store.
    #[must_use]
    pub fn with_connector(connector: Connector, pending: PendingStore) -> Self {
        Self {
            connector,
            clients: Mutex::new(HashMap::new()),
            verified: tokio::sync::Mutex::new(HashSet::new()),
            nonce_locks: Mutex::new(HashMap::new()),
            pending,
            confirmation: ConfirmationWait::default(),
            failover: Failover::default(),
        }
    }

    /// The RPC endpoint of `chain`, after checking that it serves that
    /// chain's cluster.
    ///
    /// Without backups the check runs once per URL and chain. With
    /// `fallback_rpc_urls`, `getGenesisHash` is asked on every call (also of
    /// loopback endpoints, as a liveness check) so a dead endpoint is noticed
    /// and the next one used; the returned [`SolanaRpc`] says whether it is a
    /// backup.
    pub async fn rpc(&self, chain: &SolanaChain) -> Result<SolanaRpc, PaymentsError> {
        if chain.fallback_rpc_urls.is_empty() {
            return self.rpc_at(chain, &chain.rpc_url, false).await;
        }
        let endpoints: Vec<String> = std::iter::once(chain.rpc_url.clone())
            .chain(chain.fallback_rpc_urls.iter().cloned())
            .collect();
        let connected = self
            .failover
            .connect(&chain.key, chain.chain_id, &endpoints, |index| {
                self.rpc_at(chain, &endpoints[index], true)
            })
            .await?;
        Ok(connected.value.on_backup(connected.backup))
    }

    /// The client for `url`, checked to serve `chain`'s cluster: every time
    /// when `probe`, else once per URL and chain.
    async fn rpc_at(
        &self,
        chain: &SolanaChain,
        url: &str,
        probe: bool,
    ) -> Result<SolanaRpc, PaymentsError> {
        let client = {
            let mut clients = self
                .clients
                .lock()
                .map_err(|_| PaymentsError::Internal("Solana client cache poisoned".into()))?;
            clients
                .entry(url.to_string())
                .or_insert_with(|| Arc::new((self.connector)(url)))
                .clone()
        };
        let rpc = SolanaRpc::new(client);
        if probe {
            check_cluster(&rpc, chain, url, true).await?;
            return Ok(rpc);
        }
        let mut verified = self.verified.lock().await;
        let key = (url.to_string(), chain.chain_id);
        if !verified.contains(&key) {
            check_cluster(&rpc, chain, url, false).await?;
            verified.insert(key);
        }
        Ok(rpc)
    }

    /// The lock that serializes transactions advancing `nonce_account`: a
    /// second transaction built on the same nonce value would fail on chain.
    pub fn nonce_lock(
        &self,
        nonce_account: &Pubkey,
    ) -> Result<Arc<tokio::sync::Mutex<()>>, PaymentsError> {
        let mut locks = self
            .nonce_locks
            .lock()
            .map_err(|_| PaymentsError::Internal("Solana nonce locks poisoned".into()))?;
        Ok(locks.entry(*nonce_account).or_default().clone())
    }
}

/// Genesis hash of each public cluster.
fn expected_genesis_hash(chain_id: u64) -> Option<&'static str> {
    match chain_id {
        SOLANA_MAINNET_CHAIN_ID => Some("5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"),
        SOLANA_DEVNET_CHAIN_ID => Some("EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"),
        SOLANA_TESTNET_CHAIN_ID => Some("4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY"),
        _ => None,
    }
}

/// Refuses an endpoint whose genesis hash is not the cluster's, so a
/// devnet URL configured under the mainnet id (or the reverse) cannot sign
/// against one cluster and broadcast to another. Loopback URLs are local
/// test validators with their own genesis: their hash is not compared, and
/// they are only asked for it when `liveness` is set.
async fn check_cluster(
    rpc: &SolanaRpc,
    chain: &SolanaChain,
    url: &str,
    liveness: bool,
) -> Result<(), PaymentsError> {
    if is_loopback(url) {
        if liveness {
            rpc.genesis_hash().await?;
        }
        return Ok(());
    }
    let expected = expected_genesis_hash(chain.chain_id).ok_or_else(|| {
        PaymentsError::InvalidRequest(format!(
            "chain id {} is not a Solana cluster",
            chain.chain_id
        ))
    })?;
    let genesis = rpc.genesis_hash().await?;
    if genesis.to_string() != expected {
        return Err(PaymentsError::ChainRpc(format!(
            "the RPC endpoint of '{}' serves another Solana cluster (genesis hash {genesis})",
            chain.key
        )));
    }
    Ok(())
}

fn is_loopback(rpc_url: &str) -> bool {
    url::Url::parse(rpc_url)
        .ok()
        .and_then(|url| match url.host() {
            Some(url::Host::Domain(domain)) => Some(domain.eq_ignore_ascii_case("localhost")),
            Some(url::Host::Ipv4(ip)) => Some(ip.is_loopback()),
            Some(url::Host::Ipv6(ip)) => Some(ip.is_loopback()),
            None => None,
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::solana::testing::FakeCluster;

    fn chain(url: &str, chain_id: u64) -> SolanaChain {
        SolanaChain {
            key: "solana-devnet".into(),
            chain_id,
            rpc_url: url.into(),
            fallback_rpc_urls: Vec::new(),
        }
    }

    #[test]
    fn loopback_urls_are_recognized() {
        assert!(is_loopback("http://127.0.0.1:8899"));
        assert!(is_loopback("http://localhost:8899"));
        assert!(is_loopback("http://[::1]:8899"));
        assert!(!is_loopback("https://api.devnet.solana.com"));
        assert!(!is_loopback("not a url"));
    }

    /// A provider whose `https://primary.example` endpoint is `primary` and
    /// every other endpoint `backup`.
    fn split_provider(primary: &FakeCluster, backup: &FakeCluster) -> SolanaProvider {
        use solana_rpc_client::rpc_client::RpcClientConfig;
        let (primary, backup) = (primary.clone(), backup.clone());
        SolanaProvider::with_connector(
            Arc::new(move |url: &str| {
                let cluster = if url.starts_with("https://primary.") {
                    primary.clone()
                } else {
                    backup.clone()
                };
                RpcClient::new_sender(
                    cluster,
                    RpcClientConfig::with_commitment(CommitmentConfig::confirmed()),
                )
            }),
            PendingStore::in_memory(),
        )
    }

    #[tokio::test]
    async fn a_failing_primary_falls_back_to_a_backup_of_the_same_cluster() {
        let primary = FakeCluster::devnet();
        primary.with(|s| s.failing.push("getGenesisHash".into()));
        let backup = FakeCluster::devnet();
        let provider = split_provider(&primary, &backup);
        let mut devnet = chain("https://primary.example", SOLANA_DEVNET_CHAIN_ID);
        devnet.fallback_rpc_urls = vec!["https://backup.example".into()];

        let rpc = provider.rpc(&devnet).await.expect("backup");
        assert!(rpc.using_backup());
        rpc.latest_blockhash().await.expect("served by the backup");
        assert_eq!(backup.calls("getLatestBlockhash"), 1);

        // Preferred now: the primary is not asked again.
        assert!(provider.rpc(&devnet).await.expect("sticky").using_backup());
        assert_eq!(primary.calls("getGenesisHash"), 1);

        // Every endpoint failing reports the primary's error and the count.
        backup.with(|s| s.failing.push("getGenesisHash".into()));
        let err = provider.rpc(&devnet).await.err().expect("all fail");
        let PaymentsError::ChainRpc(reason) = err else {
            panic!("expected ChainRpc, got {err:?}");
        };
        assert!(
            reason.contains("getGenesisHash") && reason.ends_with("(1 backup RPC also failed)"),
            "{reason}"
        );
        assert!(!reason.contains("example"), "{reason} leaks a URL");
    }

    #[tokio::test]
    async fn the_cluster_is_checked_once_per_url() {
        let cluster = FakeCluster::devnet();
        let provider = cluster.provider();
        let devnet = chain("https://api.devnet.solana.com", SOLANA_DEVNET_CHAIN_ID);
        provider.rpc(&devnet).await.expect("devnet");
        provider.rpc(&devnet).await.expect("cached");
        assert_eq!(cluster.calls("getGenesisHash"), 1);

        let err = provider
            .rpc(&chain(
                "https://api.devnet.solana.com",
                SOLANA_MAINNET_CHAIN_ID,
            ))
            .await
            .err()
            .expect("devnet genesis under the mainnet id");
        let PaymentsError::ChainRpc(reason) = err else {
            panic!("expected ChainRpc, got {err:?}");
        };
        assert!(reason.contains("another Solana cluster"));
        assert!(!reason.contains("https://"), "the URL must not leak");

        provider
            .rpc(&chain("http://127.0.0.1:8899", SOLANA_MAINNET_CHAIN_ID))
            .await
            .expect("loopback is not checked");
        assert_eq!(cluster.calls("getGenesisHash"), 2);
    }
}
