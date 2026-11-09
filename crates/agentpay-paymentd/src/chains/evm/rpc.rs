//! [`EvmRpc`]: typed JSON-RPC calls on one verified EVM chain.

use std::sync::Arc;
use std::time::Duration;

use agentpay_api::payments::{EvmReceipt, EvmTransactionInfo};
use alloy_network::TransactionBuilder;
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_provider::{DynProvider, Provider};
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::{sol, SolCall};
use alloy_transport::{RpcError, TransportError, TransportErrorKind};

use super::batch::MulticallSupport;
use super::convert;
use crate::error::PaymentsError;

sol! {
    function decimals() returns (uint8);
    function symbol() returns (string);
    function balanceOf(address owner) returns (uint256);
    function allowance(address owner, address spender) returns (uint256);
    function name() returns (string);
    function version() returns (string);
    function eip712Domain() returns (bytes1 fields, string name, string version, uint256 chainId, address verifyingContract, bytes32 salt, uint256[] extensions);
}

/// Delay between receipt polls.
pub const RECEIPT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Longest node error message quoted in an error.
const MAX_NODE_MESSAGE: usize = 200;

/// Node messages meaning "this exact signed transaction is already known",
/// which counts as a successful broadcast (ported from `packages/rpc`).
const ALREADY_KNOWN: &[&str] = &[
    "already known",
    "already_exists",
    "known transaction",
    "transaction already imported",
    "already in mempool",
    "already in the mempool",
];

/// EIP-1559 fees for a new transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeEstimate {
    /// `maxFeePerGas` in wei.
    pub max_fee_per_gas: u128,
    /// `maxPriorityFeePerGas` in wei.
    pub max_priority_fee_per_gas: u128,
}

/// A connection to one EVM chain whose chain id has been verified. Clones
/// share the connection.
#[derive(Clone)]
pub struct EvmRpc {
    provider: DynProvider,
    network: String,
    chain_id: u64,
    multicall: Arc<MulticallSupport>,
    backup: bool,
}

impl EvmRpc {
    pub(super) fn new(
        provider: DynProvider,
        network: &str,
        chain_id: u64,
        multicall: Arc<MulticallSupport>,
    ) -> Self {
        Self {
            provider,
            network: network.to_string(),
            chain_id,
            multicall,
            backup: false,
        }
    }

    /// Marks whether this connection uses one of the chain's backup endpoints.
    pub(super) fn on_backup(mut self, backup: bool) -> Self {
        self.backup = backup;
        self
    }

    /// Whether this connection uses one of the chain's `fallback_rpc_urls`
    /// because `rpc_url` failed.
    #[must_use]
    pub fn using_backup(&self) -> bool {
        self.backup
    }

    /// The underlying provider.
    pub(super) fn provider(&self) -> &DynProvider {
        &self.provider
    }

    /// The provider-wide record of which chains have Multicall3.
    pub(super) fn multicall_support(&self) -> &MulticallSupport {
        &self.multicall
    }

    /// The chain key.
    #[must_use]
    pub fn network(&self) -> &str {
        &self.network
    }

    /// The verified chain id.
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Fails unless the endpoint reports the configured chain id.
    pub(super) async fn check_chain_id(&self) -> Result<(), PaymentsError> {
        let actual = self
            .provider
            .get_chain_id()
            .await
            .map_err(|err| rpc_error("eth_chainId", &err))?;
        if actual != self.chain_id {
            return Err(PaymentsError::ChainRpc(format!(
                "the RPC endpoint of network '{}' reports chain id {actual}, expected {}",
                self.network, self.chain_id
            )));
        }
        Ok(())
    }

    /// The latest block number.
    pub async fn block_number(&self) -> Result<u64, PaymentsError> {
        self.provider
            .get_block_number()
            .await
            .map_err(|err| rpc_error("eth_blockNumber", &err))
    }

    /// The account's pending transaction count.
    pub async fn pending_nonce(&self, address: Address) -> Result<u64, PaymentsError> {
        self.provider
            .get_transaction_count(address)
            .pending()
            .await
            .map_err(|err| rpc_error("eth_getTransactionCount", &err))
    }

    /// The native balance in wei.
    pub async fn native_balance(&self, address: Address) -> Result<U256, PaymentsError> {
        self.provider
            .get_balance(address)
            .await
            .map_err(|err| rpc_error("eth_getBalance", &err))
    }

    /// `balanceOf(owner)` of an ERC-20 token.
    pub async fn erc20_balance(
        &self,
        token: Address,
        owner: Address,
    ) -> Result<U256, PaymentsError> {
        let output = self
            .call(token, balanceOfCall { owner }.abi_encode())
            .await?;
        balanceOfCall::abi_decode_returns(&output)
            .map_err(|_| PaymentsError::ChainRpc("balanceOf returned an invalid value".into()))
    }

    /// `allowance(owner, spender)` of an ERC-20 token.
    pub async fn erc20_allowance(
        &self,
        token: Address,
        owner: Address,
        spender: Address,
    ) -> Result<U256, PaymentsError> {
        let output = self
            .call(token, allowanceCall { owner, spender }.abi_encode())
            .await?;
        allowanceCall::abi_decode_returns(&output)
            .map_err(|_| PaymentsError::ChainRpc("allowance returned an invalid value".into()))
    }

    /// `decimals()` of an ERC-20 token.
    pub async fn erc20_decimals(&self, token: Address) -> Result<u8, PaymentsError> {
        let output = self.call(token, decimalsCall {}.abi_encode()).await?;
        decimalsCall::abi_decode_returns(&output)
            .map_err(|_| PaymentsError::ChainRpc("decimals() returned an invalid value".into()))
    }

    /// `symbol()` of an ERC-20 token; `None` when the token has none.
    pub async fn erc20_symbol(&self, token: Address) -> Option<String> {
        let output = self.call(token, symbolCall {}.abi_encode()).await.ok()?;
        let symbol = symbolCall::abi_decode_returns(&output).ok()?;
        let valid = !symbol.trim().is_empty()
            && symbol.len() <= 32
            && !symbol.chars().any(char::is_control);
        valid.then_some(symbol)
    }

    /// The token's EIP-712 domain `(name, version)`: from ERC-5267
    /// `eip712Domain()` when the token implements it, else `name()` and
    /// `version()` (a token without `version()` gets `None`).
    pub async fn eip712_name_version(
        &self,
        token: Address,
    ) -> Result<(String, Option<String>), PaymentsError> {
        if let Ok(output) = self.call(token, eip712DomainCall {}.abi_encode()).await {
            if let Ok(domain) = eip712DomainCall::abi_decode_returns(&output) {
                // Bit 0 says the domain has a name, bit 1 a version.
                let fields = domain.fields.0[0];
                if fields & 0b01 != 0 && !domain.name.is_empty() {
                    let version = (fields & 0b10 != 0).then_some(domain.version);
                    return Ok((domain.name, version));
                }
            }
        }
        let output = self.call(token, nameCall {}.abi_encode()).await?;
        let name = nameCall::abi_decode_returns(&output)
            .ok()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                PaymentsError::ChainRpc("the token's EIP-712 domain could not be read".into())
            })?;
        let version = match self.call(token, versionCall {}.abi_encode()).await {
            Ok(output) => versionCall::abi_decode_returns(&output).ok(),
            Err(_) => None,
        };
        Ok((name, version.filter(|version| !version.is_empty())))
    }

    async fn call(&self, to: Address, input: Vec<u8>) -> Result<Bytes, PaymentsError> {
        let request = TransactionRequest::default().with_to(to).with_input(input);
        self.provider
            .call(request)
            .await
            .map_err(|err| rpc_error("eth_call", &err))
    }

    /// `eth_gasPrice` in wei.
    pub async fn gas_price(&self) -> Result<u128, PaymentsError> {
        self.provider
            .get_gas_price()
            .await
            .map_err(|err| rpc_error("eth_gasPrice", &err))
    }

    /// The EIP-1559 estimate from `eth_feeHistory`; an error on chains without base fees.
    pub async fn eip1559_fees(&self) -> Result<FeeEstimate, PaymentsError> {
        let estimate = self
            .provider
            .estimate_eip1559_fees()
            .await
            .map_err(|err| rpc_error("eth_feeHistory", &err))?;
        Ok(FeeEstimate {
            max_fee_per_gas: estimate.max_fee_per_gas,
            max_priority_fee_per_gas: estimate.max_priority_fee_per_gas,
        })
    }

    /// Fees for a new transaction: the EIP-1559 estimate, or `eth_gasPrice`
    /// for both values on chains without base fees.
    pub async fn fees(&self) -> Result<FeeEstimate, PaymentsError> {
        match self.eip1559_fees().await {
            Ok(estimate) if estimate.max_fee_per_gas > 0 => Ok(estimate),
            _ => {
                let gas_price = self.gas_price().await?;
                Ok(FeeEstimate {
                    max_fee_per_gas: gas_price,
                    max_priority_fee_per_gas: gas_price,
                })
            }
        }
    }

    /// `eth_estimateGas` for a call from `from`.
    pub async fn estimate_gas(
        &self,
        from: Address,
        to: Address,
        value: U256,
        input: Vec<u8>,
    ) -> Result<u64, PaymentsError> {
        let request = TransactionRequest::default()
            .with_from(from)
            .with_to(to)
            .with_value(value)
            .with_input(input);
        self.provider
            .estimate_gas(request)
            .await
            .map_err(|err| rpc_error("eth_estimateGas", &err))
    }

    /// Sends a signed transaction once (never retried) and returns its hash.
    /// A node that already knows the transaction counts as success.
    pub async fn send_raw_transaction(&self, raw: &[u8]) -> Result<B256, PaymentsError> {
        self.try_send_raw_transaction(raw)
            .await
            .map_err(|failure| failure.error)
    }

    /// Like [`send_raw_transaction`](Self::send_raw_transaction), but says
    /// whether a failed send certainly never reached the network
    /// ([`SendFailure::not_submitted`]).
    pub async fn try_send_raw_transaction(&self, raw: &[u8]) -> Result<B256, SendFailure> {
        match self.provider.send_raw_transaction(raw).await {
            Ok(pending) => Ok(*pending.tx_hash()),
            Err(err) if is_already_known(&err) => Ok(keccak256(raw)),
            Err(err) => Err(SendFailure {
                not_submitted: definitely_not_submitted(&err),
                error: rpc_error("eth_sendRawTransaction", &err),
            }),
        }
    }

    /// The receipt of `hash`; `None` while pending or unknown.
    pub async fn receipt(&self, hash: B256) -> Result<Option<EvmReceipt>, PaymentsError> {
        self.provider
            .get_transaction_receipt(hash)
            .await
            .map_err(|err| rpc_error("eth_getTransactionReceipt", &err))?
            .as_ref()
            .map(convert::receipt)
            .transpose()
    }

    /// Polls for the receipt of `hash` every [`RECEIPT_POLL_INTERVAL`] until
    /// `timeout`; `None` when it did not appear in time (checked at least once).
    pub async fn wait_for_receipt(
        &self,
        hash: B256,
        timeout: Duration,
    ) -> Result<Option<EvmReceipt>, PaymentsError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(receipt) = self.receipt(hash).await? {
                return Ok(Some(receipt));
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            tokio::time::sleep(RECEIPT_POLL_INTERVAL.min(deadline - now)).await;
        }
    }

    /// The transaction `hash`; `None` when unknown.
    pub async fn transaction(
        &self,
        hash: B256,
    ) -> Result<Option<EvmTransactionInfo>, PaymentsError> {
        self.provider
            .get_transaction_by_hash(hash)
            .await
            .map_err(|err| rpc_error("eth_getTransactionByHash", &err))?
            .as_ref()
            .map(convert::transaction)
            .transpose()
    }

    /// The code at `address` (empty for an account without code).
    pub async fn code(&self, address: Address) -> Result<Bytes, PaymentsError> {
        self.provider
            .get_code_at(address)
            .await
            .map_err(|err| rpc_error("eth_getCode", &err))
    }
}

/// A failed `eth_sendRawTransaction`.
#[derive(Debug)]
pub struct SendFailure {
    /// The error to report.
    pub error: PaymentsError,
    /// `true` only when the transaction certainly never reached the network,
    /// so its nonce may be handed out again (`ReleaseSignedNonce`):
    ///
    /// - the node answered with a JSON-RPC error: it rejected the transaction,
    ///   and nodes do not relay transactions their pool refused;
    /// - the connection could not be established, so the request was never sent.
    ///
    /// Everything else (a timeout, a dropped connection, an HTTP error from a
    /// proxy, an unreadable answer) is ambiguous: the node may have the
    /// transaction, and reusing its nonce could replace it.
    pub not_submitted: bool,
}

/// See [`SendFailure::not_submitted`].
fn definitely_not_submitted(error: &TransportError) -> bool {
    match error {
        RpcError::ErrorResp(_) => true,
        RpcError::Transport(TransportErrorKind::Custom(source)) => source
            .downcast_ref::<reqwest::Error>()
            .is_some_and(|error| error.is_connect() && !error.is_timeout()),
        _ => false,
    }
}

/// Whether a send failure means the node already has the transaction.
fn is_already_known(error: &TransportError) -> bool {
    let RpcError::ErrorResp(payload) = error else {
        return false;
    };
    let message = payload.message.to_ascii_lowercase();
    ALREADY_KNOWN
        .iter()
        .any(|pattern| message.contains(pattern))
}

/// A [`PaymentsError::ChainRpc`] for a failed `call`, without the endpoint URL.
pub(super) fn rpc_error(call: &str, error: &TransportError) -> PaymentsError {
    let reason = match error {
        RpcError::ErrorResp(payload) => {
            let message: String = payload
                .message
                .chars()
                .filter(|c| !c.is_control())
                .take(MAX_NODE_MESSAGE)
                .collect();
            format!("node error {}: {message}", payload.code)
        }
        RpcError::NullResp => "empty response".to_string(),
        RpcError::DeserError { .. } => "invalid response".to_string(),
        RpcError::Transport(TransportErrorKind::HttpError(http)) => {
            format!("HTTP status {}", http.status)
        }
        RpcError::Transport(_) => "endpoint unreachable".to_string(),
        _ => "request failed".to_string(),
    };
    PaymentsError::ChainRpc(format!("{call} failed: {reason}"))
}
