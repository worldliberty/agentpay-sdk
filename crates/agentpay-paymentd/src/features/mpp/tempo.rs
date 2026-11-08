//! Tempo (type `0x76`) transactions for session opens and top-ups, and the
//! Tempo JSON-RPC calls they need (chain id, gas price, gas estimate).
//!
//! The signer daemon signs a session transaction from its semantic fields
//! (`TempoSessionV2OpenTransaction` / `TopUpTransaction`) and rebuilds the
//! envelope itself. This module rebuilds the same transaction with
//! `tempo-alloy`'s types, independently of the daemon's encoder, and only
//! accepts a signature that recovers to the agent's wallet over
//! `tempo-alloy`'s signing hash. The signed transaction is then encoded with
//! `tempo-alloy` (or as MPP's `0x78` fee-payer envelope when the merchant
//! sponsors the fee).

use std::num::NonZeroU64;
use std::str::FromStr;
use std::time::Duration;

use agentpay_api::payments::{ChainFamily, PaymentsConfig};
use agentpay_domain::{EvmAddress, TempoTxParams};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_client::RpcClient;
use alloy_transport_http::Http;
use mpp::client::tempo::charge::tx_builder::estimate_gas;
use mpp::protocol::methods::tempo::FeePayerEnvelope78;
use tempo_alloy::primitives::transaction::{
    Call, PrimitiveSignature, SignatureType, TempoSignature, TempoTransaction,
};
use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_alloy::TempoNetwork;

use crate::chains::evm::to_alloy_address;
use crate::config::check_rpc_url;
use crate::error::PaymentsError;

/// Lifetime of a session transaction's expiring nonce, as `mpp` sets it.
pub(super) const EXPIRING_NONCE_VALID_SECS: u64 = 25;
/// Gas limit of a fee-sponsored session transaction (the sponsor estimates).
pub(super) const SPONSORED_GAS_LIMIT: u64 = 2_000_000;
/// RPC timeouts.
const RPC_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The configured chain key and RPC URL for `chain_id`: the first EVM chain
/// (in key order) with that id and an `rpc_url`.
pub(super) fn network_for_chain(
    config: &PaymentsConfig,
    chain_id: u64,
) -> Result<(String, agentpay_api::payments::ChainProfile), PaymentsError> {
    config
        .chains
        .iter()
        .find(|(_, chain)| {
            chain.family == ChainFamily::Evm && chain.chain_id == chain_id && chain.rpc_url.is_some()
        })
        .map(|(key, chain)| (key.clone(), chain.clone()))
        .ok_or_else(|| {
            PaymentsError::InvalidRequest(format!(
                "no configured EVM network with an rpc_url has chain id {chain_id}; nothing was signed"
            ))
        })
}

/// A Tempo JSON-RPC endpoint whose chain id has been checked.
pub(super) struct TempoRpc {
    provider: RootProvider<TempoNetwork>,
}

impl TempoRpc {
    /// Connects to the configured endpoint for `chain_id`.
    pub(super) async fn connect(
        config: &PaymentsConfig,
        chain_id: u64,
    ) -> Result<Self, PaymentsError> {
        let (network, chain) = network_for_chain(config, chain_id)?;
        let url = chain.rpc_url.as_deref().unwrap_or_default();
        check_rpc_url(url).map_err(|reason| {
            PaymentsError::InvalidRequest(format!("network '{network}' rpc_url {reason}"))
        })?;
        let url = url::Url::parse(url).map_err(|_| {
            PaymentsError::InvalidRequest(format!("network '{network}' rpc_url is not a valid URL"))
        })?;
        let http = reqwest::Client::builder()
            .timeout(RPC_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| PaymentsError::Internal("the HTTP client is unavailable".into()))?;
        let is_local = url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        let provider = RootProvider::new(RpcClient::new(Http::with_client(http, url), is_local));
        let actual = provider.get_chain_id().await.map_err(|_| {
            PaymentsError::ChainRpc(format!("eth_chainId failed on network '{network}'"))
        })?;
        if actual != chain_id {
            return Err(PaymentsError::ChainRpc(format!(
                "the RPC endpoint of network '{network}' reports chain id {actual}, expected {chain_id}"
            )));
        }
        Ok(Self { provider })
    }

    /// `eth_gasPrice`.
    pub(super) async fn gas_price(&self) -> Result<u128, PaymentsError> {
        self.provider
            .get_gas_price()
            .await
            .map_err(|_| PaymentsError::ChainRpc("eth_gasPrice failed".into()))
    }

    /// `eth_estimateGas` for `tx` sent by `from`, through `mpp`'s estimator
    /// (gas cap and safety buffer).
    pub(super) async fn estimate(
        &self,
        tx: &TempoTransaction,
        from: Address,
    ) -> Result<u64, PaymentsError> {
        let mut request = TempoTransactionRequest {
            calls: tx.calls.clone(),
            valid_before: tx.valid_before,
            valid_after: tx.valid_after,
            ..Default::default()
        }
        .with_nonce_key(tx.nonce_key);
        if let Some(fee_token) = tx.fee_token {
            request = request.with_fee_token(fee_token);
        }
        request.inner.from = Some(from);
        request.inner.chain_id = Some(tx.chain_id);
        request.inner.nonce = Some(tx.nonce);
        request.inner.max_fee_per_gas = Some(tx.max_fee_per_gas);
        request.inner.max_priority_fee_per_gas = Some(tx.max_priority_fee_per_gas);
        request.key_type = Some(SignatureType::Secp256k1);
        estimate_gas(&self.provider, request)
            .await
            .map_err(|error| PaymentsError::ChainRpc(format!("eth_estimateGas failed: {error}")))
    }
}

/// Envelope parameters for a session transaction: the expiring nonce key
/// (`uint256` max) with nonce 0, valid for [`EXPIRING_NONCE_VALID_SECS`];
/// the fee paid in `fee_token`, or sponsored by the merchant.
pub(super) fn session_tx_params(
    gas_price: u128,
    gas_limit: u64,
    now: u64,
    valid_after: Option<u64>,
    sponsored: bool,
    fee_token: &EvmAddress,
) -> TempoTxParams {
    TempoTxParams {
        nonce: 0,
        nonce_key: Some(format!("{:#x}", U256::MAX)),
        gas_limit,
        max_fee_per_gas_wei: gas_price,
        max_priority_fee_per_gas_wei: gas_price,
        valid_before: Some(now + EXPIRING_NONCE_VALID_SECS),
        valid_after,
        fee_token: (!sponsored).then(|| fee_token.clone()),
        fee_payer: sponsored,
    }
}

/// The `tempo-alloy` transaction for `params` and `calls` (as the signer
/// daemon's action encodes them).
pub(super) fn transaction(
    chain_id: u64,
    params: &TempoTxParams,
    calls: Vec<(EvmAddress, Vec<u8>)>,
) -> Result<TempoTransaction, PaymentsError> {
    let invalid = |what: &str| PaymentsError::Internal(format!("invalid Tempo transaction {what}"));
    let nonce_key = match params.nonce_key.as_deref() {
        Some(key) => U256::from_str(key).map_err(|_| invalid("nonce key"))?,
        None => U256::ZERO,
    };
    let calls = calls
        .into_iter()
        .map(|(to, data)| {
            Ok(Call {
                to: TxKind::Call(to_alloy_address(&to)?),
                value: U256::ZERO,
                input: Bytes::from(data),
            })
        })
        .collect::<Result<Vec<_>, PaymentsError>>()?;
    let fee_token = params
        .fee_token
        .as_ref()
        .map(to_alloy_address)
        .transpose()?;
    Ok(TempoTransaction {
        chain_id,
        fee_token,
        max_priority_fee_per_gas: params.max_priority_fee_per_gas_wei,
        max_fee_per_gas: params.max_fee_per_gas_wei,
        gas_limit: params.gas_limit,
        calls,
        access_list: Default::default(),
        nonce_key,
        nonce: params.nonce,
        // The placeholder marks the transaction as sponsored in the sender's
        // signing hash; the merchant replaces it when it co-signs.
        fee_payer_signature: params
            .fee_payer
            .then(|| alloy_primitives::Signature::new(U256::ZERO, U256::ZERO, false)),
        valid_before: params.valid_before.and_then(NonZeroU64::new),
        valid_after: params.valid_after.and_then(NonZeroU64::new),
        key_authorization: None,
        tempo_authorization_list: Vec::new(),
    })
}

/// The signed transaction bytes the merchant receives: `0x76` EIP-2718
/// bytes, or MPP's `0x78` fee-payer envelope when sponsored.
pub(super) fn encode_signed(
    tx: TempoTransaction,
    signature: alloy_primitives::Signature,
    sender: Address,
) -> Vec<u8> {
    let signature = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature));
    if tx.fee_payer_signature.is_some() {
        FeePayerEnvelope78::from_signing_tx(tx, sender, signature).encoded_envelope()
    } else {
        tx.into_signed(signature).encoded_2718()
    }
}

/// The canonical TIP-1020 bytes of a secp256k1 voucher signature.
pub(super) fn primitive_signature_bytes(signature: alloy_primitives::Signature) -> Vec<u8> {
    PrimitiveSignature::Secp256k1(signature).to_bytes().to_vec()
}
