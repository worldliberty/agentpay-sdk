//! The `Rpc*` read helpers (ported from the TypeScript `rpc` commands and
//! `packages/rpc`). They sign nothing and change nothing.

use agentpay_api::payments::{
    EvmAccountParams, EvmBalance, EvmBalanceParams, EvmChainInfo, EvmCode, EvmFees, EvmGasEstimate,
    EvmGasEstimateParams, EvmNetworkParams, EvmNonce, EvmReceiptLookup, EvmTransactionLookup,
    EvmTxHashParams, PaymentsRpcResponse,
};
use alloy_primitives::U256;

use super::resolve;
use super::Session;
use crate::auth::AuthenticatedAgent;
use crate::chains::evm::{
    evm_address, hex_prefixed, parse_calldata, parse_tx_hash, to_alloy_address,
};
use crate::error::PaymentsError;
use crate::state::AppState;

/// `RpcChainInfo` and `RpcBlockNumber`.
pub(super) async fn chain_info(
    state: &AppState,
    agent: &AuthenticatedAgent,
    params: EvmNetworkParams,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let session = Session::open(state, agent, params.network.as_deref()).await?;
    let rpc = session.rpc().await?;
    Ok(PaymentsRpcResponse::EvmChainInfo(EvmChainInfo {
        network: rpc.network().to_string(),
        chain_id: rpc.chain_id(),
        block_number: rpc.block_number().await?,
    }))
}

/// `RpcBalance`: the native coin without `asset`.
pub(super) async fn balance(
    state: &AppState,
    agent: &AuthenticatedAgent,
    params: EvmBalanceParams,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let session = Session::open(state, agent, params.network.as_deref()).await?;
    let account = session.account(params.address.as_ref())?;
    let asset = match params.asset.as_deref() {
        None => resolve::native_asset(&session.config, &session.network),
        Some(requested) => session.asset(Some(requested), true).await?,
    };
    let rpc = session.rpc().await?;
    let balance: U256 = match &asset.token {
        None => rpc.native_balance(account).await?,
        Some(token) => rpc.erc20_balance(to_alloy_address(token)?, account).await?,
    };
    Ok(PaymentsRpcResponse::EvmBalance(EvmBalance {
        network: rpc.network().to_string(),
        chain_id: rpc.chain_id(),
        address: evm_address(account)?,
        balance_wei: balance.to_string(),
        balance: resolve::format_units(balance, asset.decimals),
        asset,
    }))
}

/// `RpcNonce`.
pub(super) async fn nonce(
    state: &AppState,
    agent: &AuthenticatedAgent,
    params: EvmAccountParams,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let session = Session::open(state, agent, params.network.as_deref()).await?;
    let account = session.account(params.address.as_ref())?;
    let rpc = session.rpc().await?;
    Ok(PaymentsRpcResponse::EvmNonce(EvmNonce {
        network: rpc.network().to_string(),
        chain_id: rpc.chain_id(),
        address: evm_address(account)?,
        nonce: rpc.pending_nonce(account).await?,
    }))
}

/// `RpcFees`: the EIP-1559 estimate is `null` where the chain has none.
pub(super) async fn fees(
    state: &AppState,
    agent: &AuthenticatedAgent,
    params: EvmNetworkParams,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let session = Session::open(state, agent, params.network.as_deref()).await?;
    let rpc = session.rpc().await?;
    let gas_price_wei = rpc.gas_price().await?;
    let estimate = rpc.eip1559_fees().await.ok();
    Ok(PaymentsRpcResponse::EvmFees(EvmFees {
        network: rpc.network().to_string(),
        chain_id: rpc.chain_id(),
        gas_price_wei,
        max_fee_per_gas_wei: estimate.map(|fees| fees.max_fee_per_gas),
        max_priority_fee_per_gas_wei: estimate.map(|fees| fees.max_priority_fee_per_gas),
    }))
}

/// `RpcGasEstimate`.
pub(super) async fn gas_estimate(
    state: &AppState,
    agent: &AuthenticatedAgent,
    params: EvmGasEstimateParams,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let data = parse_calldata(&params.data_hex)?;
    let session = Session::open(state, agent, params.network.as_deref()).await?;
    let from = session.account(params.from.as_ref())?;
    let to = to_alloy_address(&params.to)?;
    let rpc = session.rpc().await?;
    Ok(PaymentsRpcResponse::EvmGasEstimate(EvmGasEstimate {
        network: rpc.network().to_string(),
        chain_id: rpc.chain_id(),
        gas_limit: rpc
            .estimate_gas(from, to, U256::from(params.value_wei), data)
            .await?,
    }))
}

/// `RpcTx`.
pub(super) async fn transaction(
    state: &AppState,
    agent: &AuthenticatedAgent,
    params: EvmTxHashParams,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let hash = parse_tx_hash(&params.tx_hash)?;
    let session = Session::open(state, agent, params.network.as_deref()).await?;
    let rpc = session.rpc().await?;
    Ok(PaymentsRpcResponse::EvmTransactionLookup(
        EvmTransactionLookup {
            network: rpc.network().to_string(),
            chain_id: rpc.chain_id(),
            transaction: rpc.transaction(hash).await?,
        },
    ))
}

/// `RpcReceipt`.
pub(super) async fn receipt(
    state: &AppState,
    agent: &AuthenticatedAgent,
    params: EvmTxHashParams,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let hash = parse_tx_hash(&params.tx_hash)?;
    let session = Session::open(state, agent, params.network.as_deref()).await?;
    let rpc = session.rpc().await?;
    Ok(PaymentsRpcResponse::EvmReceiptLookup(EvmReceiptLookup {
        network: rpc.network().to_string(),
        chain_id: rpc.chain_id(),
        receipt: rpc.receipt(hash).await?,
    }))
}

/// `RpcCode`.
pub(super) async fn code(
    state: &AppState,
    agent: &AuthenticatedAgent,
    params: EvmAccountParams,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let session = Session::open(state, agent, params.network.as_deref()).await?;
    let account = session.account(params.address.as_ref())?;
    let rpc = session.rpc().await?;
    Ok(PaymentsRpcResponse::EvmCode(EvmCode {
        network: rpc.network().to_string(),
        chain_id: rpc.chain_id(),
        address: evm_address(account)?,
        code_hex: hex_prefixed(&rpc.code(account).await?),
    }))
}
