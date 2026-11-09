//! [`SolanaRpc`]: the JSON-RPC calls the Solana flows make, on
//! `solana-rpc-client`, with errors mapped to [`PaymentsError::ChainRpc`].
//!
//! Error messages name the RPC method and a short reason, never the URL
//! (which may embed a provider API key) or transport details that quote it.

use std::sync::Arc;
use std::time::Duration;

use agentpay_api::payments::{SolanaBroadcast, SolanaTxStatus};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_rpc_client_api::client_error::{Error as ClientError, ErrorKind};
use solana_rpc_client_api::config::{
    CommitmentConfig, RpcAccountInfoConfig, RpcSendTransactionConfig, UiAccountEncoding,
};
use solana_rpc_client_api::request::RpcError;
use solana_rpc_client_api::response::{TransactionConfirmationStatus, UiAccount};
use solana_sdk::account::Account;
use solana_sdk::hash::Hash;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_sdk::transaction::Transaction;

use crate::error::PaymentsError;

/// Largest number of accounts in one `getMultipleAccounts` request.
pub const MAX_MULTIPLE_ACCOUNTS: usize = 100;

/// How long and how often [`SolanaRpc::wait_for_confirmation`] polls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmationWait {
    /// Total time to poll before reporting `timed_out`.
    pub timeout: Duration,
    /// Delay between polls.
    pub interval: Duration,
}

impl Default for ConfirmationWait {
    /// 30 seconds, polling every 2 seconds.
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            interval: Duration::from_secs(2),
        }
    }
}

/// A Solana JSON-RPC endpoint.
#[derive(Clone)]
pub struct SolanaRpc {
    client: Arc<RpcClient>,
    backup: bool,
}

impl SolanaRpc {
    /// Wraps a client (of the chain's `rpc_url`).
    #[must_use]
    pub fn new(client: Arc<RpcClient>) -> Self {
        Self {
            client,
            backup: false,
        }
    }

    /// Marks whether this endpoint is one of the chain's backups.
    #[must_use]
    pub fn on_backup(mut self, backup: bool) -> Self {
        self.backup = backup;
        self
    }

    /// Whether this endpoint is one of the chain's `fallback_rpc_urls`,
    /// used because `rpc_url` failed.
    #[must_use]
    pub fn using_backup(&self) -> bool {
        self.backup
    }

    /// The cluster's genesis hash (`getGenesisHash`).
    pub async fn genesis_hash(&self) -> Result<Hash, PaymentsError> {
        self.client
            .get_genesis_hash()
            .await
            .map_err(|err| rpc_error("getGenesisHash", &err))
    }

    /// A finalized recent blockhash (`getLatestBlockhash`).
    pub async fn latest_blockhash(&self) -> Result<Hash, PaymentsError> {
        self.client
            .get_latest_blockhash_with_commitment(CommitmentConfig::finalized())
            .await
            .map(|(hash, _)| hash)
            .map_err(|err| rpc_error("getLatestBlockhash", &err))
    }

    /// The account at `address` with confirmed commitment, or `None` when it
    /// does not exist (`getAccountInfo`, base64).
    ///
    /// The data is requested as plain base64 and decoded here, so an endpoint
    /// that answers in another encoding is an error rather than a panic.
    pub async fn account(&self, address: &Pubkey) -> Result<Option<Account>, PaymentsError> {
        let response = self
            .client
            .get_ui_account_with_config(address, account_config())
            .await
            .map_err(|err| rpc_error("getAccountInfo", &err))?;
        response
            .value
            .map(|account| decode_account("getAccountInfo", &account))
            .transpose()
    }

    /// The accounts at `addresses`, in order, `None` for each that does not
    /// exist (`getMultipleAccounts`, base64, at most
    /// [`MAX_MULTIPLE_ACCOUNTS`] per request), with confirmed commitment.
    pub async fn accounts(
        &self,
        addresses: &[Pubkey],
    ) -> Result<Vec<Option<Account>>, PaymentsError> {
        let mut accounts = Vec::with_capacity(addresses.len());
        for chunk in addresses.chunks(MAX_MULTIPLE_ACCOUNTS) {
            let response = self
                .client
                .get_multiple_ui_accounts_with_config(chunk, account_config())
                .await
                .map_err(|err| rpc_error("getMultipleAccounts", &err))?;
            if response.value.len() != chunk.len() {
                return Err(PaymentsError::ChainRpc(
                    "Solana RPC getMultipleAccounts failed: wrong number of accounts".into(),
                ));
            }
            for account in response.value {
                accounts.push(
                    account
                        .map(|account| decode_account("getMultipleAccounts", &account))
                        .transpose()?,
                );
            }
        }
        Ok(accounts)
    }

    /// Lamports that make an account of `data_len` bytes rent-exempt.
    pub async fn rent_exemption(&self, data_len: usize) -> Result<u64, PaymentsError> {
        self.client
            .get_minimum_balance_for_rent_exemption(data_len)
            .await
            .map_err(|err| rpc_error("getMinimumBalanceForRentExemption", &err))
    }

    /// The current epoch (`getEpochInfo`).
    pub async fn epoch(&self) -> Result<u64, PaymentsError> {
        self.client
            .get_epoch_info()
            .await
            .map(|info| info.epoch)
            .map_err(|err| rpc_error("getEpochInfo", &err))
    }

    /// Recent prioritization fees in micro-lamports per compute unit
    /// (`getRecentPrioritizationFees`, cluster-wide).
    pub async fn prioritization_fees(&self) -> Result<Vec<u64>, PaymentsError> {
        self.client
            .get_recent_prioritization_fees(&[])
            .await
            .map(|fees| fees.into_iter().map(|fee| fee.prioritization_fee).collect())
            .map_err(|err| rpc_error("getRecentPrioritizationFees", &err))
    }

    /// Submits a signed transaction (`sendTransaction`, base64, with
    /// preflight at confirmed commitment). The client checks that the node
    /// answers with the transaction's own signature.
    pub async fn send(&self, transaction: &Transaction) -> Result<Signature, PaymentsError> {
        let config = RpcSendTransactionConfig {
            preflight_commitment: Some(CommitmentConfig::confirmed().commitment),
            ..RpcSendTransactionConfig::default()
        };
        self.client
            .send_transaction_with_config(transaction, config)
            .await
            .map_err(|err| rpc_error("sendTransaction", &err))
    }

    /// Polls `getSignatureStatuses` until the transaction is confirmed or
    /// failed, or `wait.timeout` passes.
    ///
    /// The transaction is already on its way, so polling errors are not
    /// fatal: they are retried, and if none succeeds in time the result is
    /// `timed_out`.
    pub async fn wait_for_confirmation(
        &self,
        signature: &Signature,
        wait: ConfirmationWait,
    ) -> SolanaBroadcast {
        let deadline = tokio::time::Instant::now() + wait.timeout;
        let mut last_slot = None;
        loop {
            if let Ok(response) = self.client.get_signature_statuses(&[*signature]).await {
                if let Some(Some(status)) = response.value.into_iter().next() {
                    last_slot = Some(status.slot);
                    if let Some(error) = status.err {
                        return SolanaBroadcast {
                            status: SolanaTxStatus::Failed,
                            slot: Some(status.slot),
                            error: Some(error.to_string()),
                        };
                    }
                    if status.confirmation_status == Some(TransactionConfirmationStatus::Finalized)
                    {
                        return broadcast(SolanaTxStatus::Finalized, Some(status.slot));
                    }
                    if status.satisfies_commitment(CommitmentConfig::confirmed()) {
                        return broadcast(SolanaTxStatus::Confirmed, Some(status.slot));
                    }
                }
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return broadcast(SolanaTxStatus::TimedOut, last_slot);
            }
            tokio::time::sleep(wait.interval.min(deadline - now)).await;
        }
    }
}

/// Plain base64 account data with confirmed commitment.
fn account_config() -> RpcAccountInfoConfig {
    RpcAccountInfoConfig {
        encoding: Some(UiAccountEncoding::Base64),
        commitment: Some(CommitmentConfig::confirmed()),
        data_slice: None,
        min_context_slot: None,
    }
}

/// Decodes an account requested as base64.
fn decode_account(method: &str, account: &UiAccount) -> Result<Account, PaymentsError> {
    account.to_account().ok_or_else(|| {
        PaymentsError::ChainRpc(format!(
            "Solana RPC {method} failed: account data is not base64"
        ))
    })
}

fn broadcast(status: SolanaTxStatus, slot: Option<u64>) -> SolanaBroadcast {
    SolanaBroadcast {
        status,
        slot,
        error: None,
    }
}

/// Maps a client error to `ChainRpc` without quoting the URL.
pub(crate) fn rpc_error(method: &str, error: &ClientError) -> PaymentsError {
    let reason = match error.kind() {
        ErrorKind::Reqwest(err) if err.is_timeout() => "request timed out".to_string(),
        ErrorKind::Reqwest(err) if err.is_connect() => "connection failed".to_string(),
        ErrorKind::Reqwest(err) => match err.status() {
            Some(status) => format!("HTTP status {status}"),
            None => "transport error".to_string(),
        },
        ErrorKind::Io(_) => "I/O error".to_string(),
        ErrorKind::RpcError(RpcError::RpcResponseError { code, message, .. }) => {
            format!("node error {code}: {message}")
        }
        ErrorKind::RpcError(RpcError::ParseError(_)) | ErrorKind::SerdeJson(_) => {
            "unexpected response".to_string()
        }
        ErrorKind::TransactionError(err) => format!("transaction rejected: {err}"),
        ErrorKind::RpcError(_)
        | ErrorKind::Middleware(_)
        | ErrorKind::SigningError(_)
        | ErrorKind::Custom(_) => "request failed".to_string(),
    };
    PaymentsError::ChainRpc(format!("Solana RPC {method} failed: {reason}"))
}
