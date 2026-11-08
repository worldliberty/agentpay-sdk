//! `Transfer`, `TransferNative`, `Approve`, `Broadcast`, `SignTypedData`, and
//! `ResumeApproved` (ported from the TypeScript `transfer`, `transfer-native`,
//! `approve`, `broadcast`, and `sign-typed-data` commands).

use agentpay_api::payments::{
    ApproveParams, BroadcastParams, EvmPayment, EvmTxOptions, PaymentsRpcResponse,
    ResumeApprovedParams, SignTypedDataParams, TransferNativeParams, TransferParams,
};
use agentpay_domain::{AgentAction, BroadcastTx, Eip712TypedData, EvmAddress};
use alloy_primitives::U256;
use alloy_sol_types::{sol, SolCall};

use super::pending::Delivery;
use super::resolve;
use super::transaction::{self, Intent, Submission};
use super::Session;
use crate::auth::AuthenticatedAgent;
use crate::chains::evm::{parse_calldata, to_alloy_address};
use crate::error::PaymentsError;
use crate::state::AppState;

sol! {
    function transfer(address to, uint256 value);
    function approve(address spender, uint256 value);
}

/// `Transfer`.
pub(super) async fn transfer(
    state: &AppState,
    agent: &AuthenticatedAgent,
    params: TransferParams,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let TransferParams {
        network,
        asset,
        to,
        amount,
        options,
        ..
    } = params;
    resolve::check_options(&options, options.broadcast)?;
    let session = Session::open(state, agent, network.as_deref()).await?;
    let asset = session.asset(asset.as_deref(), false).await?;
    let token = asset.token.clone().ok_or_else(missing_token)?;
    let (amount, amount_wei) = resolve::parse_amount(&amount, asset.decimals)?;
    let payment = EvmPayment {
        asset,
        counterparty: to.clone(),
        amount,
        amount_wei,
    };
    let chain_id = session.network.chain.chain_id;
    if !options.broadcast {
        let action = AgentAction::Transfer {
            chain_id,
            token,
            to,
            amount_wei,
        };
        return sign_only(&session, "Transfer", payment, action, &options).await;
    }
    let data = transferCall {
        to: to_alloy_address(&to)?,
        value: U256::from(amount_wei),
    }
    .abi_encode();
    submit(
        &session,
        "Transfer",
        Some(payment),
        &token,
        0,
        data,
        &options,
    )
    .await
}

/// `TransferNative`.
pub(super) async fn transfer_native(
    state: &AppState,
    agent: &AuthenticatedAgent,
    params: TransferNativeParams,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let TransferNativeParams {
        network,
        to,
        amount,
        options,
        ..
    } = params;
    resolve::check_options(&options, options.broadcast)?;
    let session = Session::open(state, agent, network.as_deref()).await?;
    let asset = resolve::native_asset(&session.config, &session.network);
    let (amount, amount_wei) = resolve::parse_amount(&amount, asset.decimals)?;
    let payment = EvmPayment {
        asset,
        counterparty: to.clone(),
        amount,
        amount_wei,
    };
    if !options.broadcast {
        let action = AgentAction::TransferNative {
            chain_id: session.network.chain.chain_id,
            to,
            amount_wei,
        };
        return sign_only(&session, "TransferNative", payment, action, &options).await;
    }
    submit(
        &session,
        "TransferNative",
        Some(payment),
        &to,
        amount_wei,
        Vec::new(),
        &options,
    )
    .await
}

/// `Approve`.
pub(super) async fn approve(
    state: &AppState,
    agent: &AuthenticatedAgent,
    params: ApproveParams,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let ApproveParams {
        network,
        asset,
        spender,
        amount,
        options,
        ..
    } = params;
    resolve::check_options(&options, options.broadcast)?;
    let session = Session::open(state, agent, network.as_deref()).await?;
    let asset = session.asset(asset.as_deref(), false).await?;
    let token = asset.token.clone().ok_or_else(missing_token)?;
    let (amount, amount_wei) = resolve::parse_amount(&amount, asset.decimals)?;
    let payment = EvmPayment {
        asset,
        counterparty: spender.clone(),
        amount,
        amount_wei,
    };
    if !options.broadcast {
        let action = AgentAction::Approve {
            chain_id: session.network.chain.chain_id,
            token,
            spender,
            amount_wei,
        };
        return sign_only(&session, "Approve", payment, action, &options).await;
    }
    let data = approveCall {
        spender: to_alloy_address(&spender)?,
        value: U256::from(amount_wei),
    }
    .abi_encode();
    submit(
        &session,
        "Approve",
        Some(payment),
        &token,
        0,
        data,
        &options,
    )
    .await
}

/// `Broadcast`.
pub(super) async fn broadcast(
    state: &AppState,
    agent: &AuthenticatedAgent,
    params: BroadcastParams,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let BroadcastParams {
        network,
        to,
        value_wei,
        data_hex,
        options,
        ..
    } = params;
    resolve::check_options(&options, true)?;
    if options.wait_for_receipt && !options.broadcast {
        return Err(PaymentsError::InvalidRequest(
            "wait_for_receipt requires broadcast: true".into(),
        ));
    }
    let data = parse_calldata(&data_hex)?;
    let session = Session::open(state, agent, network.as_deref()).await?;
    submit(&session, "Broadcast", None, &to, value_wei, data, &options).await
}

/// `SignTypedData`.
pub(super) async fn sign_typed_data(
    state: &AppState,
    agent: &AuthenticatedAgent,
    params: SignTypedDataParams,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let typed_data = Eip712TypedData {
        typed_data_json: params.typed_data_json,
    };
    let chain_id = typed_data
        .chain_id()
        .map_err(|err| PaymentsError::InvalidRequest(err.to_string()))?;
    let action = AgentAction::Eip712TypedData { typed_data };
    action
        .validate()
        .map_err(|err| PaymentsError::InvalidRequest(err.to_string()))?;
    let intent = Intent {
        method: "SignTypedData".into(),
        network: None,
        chain_id,
        payment: None,
    };
    let wait = resolve::approval_wait(params.approval_wait_secs, state.approval_wait);
    transaction::sign_only(state, agent, intent, action, wait).await
}

/// `ResumeApproved`: resends a stored action and settles its record.
pub(super) async fn resume(
    state: &AppState,
    agent: &AuthenticatedAgent,
    params: ResumeApprovedParams,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let id = params.approval_request_id;
    let store = transaction::pending_store(state)?;
    let record = store.load(id, agent.credentials.agent_key_id)?;
    let wait = resolve::approval_wait(params.approval_wait_secs, state.approval_wait);
    let intent = Intent {
        method: record.method.clone(),
        network: record.network.clone(),
        chain_id: record.chain_id,
        payment: record.payment.clone(),
    };
    let result = match (&record.action, record.delivery) {
        (AgentAction::BroadcastTx { tx }, Some(delivery)) => {
            resume_transaction(state, agent, intent, tx.clone(), delivery, wait).await
        }
        (AgentAction::BroadcastTx { .. }, None) => Err(PaymentsError::Persistence(
            "a pending approval file is invalid".into(),
        )),
        (action, _) => transaction::sign_only(state, agent, intent, action.clone(), wait).await,
    };
    // Keep the record while the same request is still pending, or after a
    // failure worth retrying; otherwise the request is settled.
    let keep = match &result {
        Ok(PaymentsRpcResponse::ManualApprovalPending(pending)) => {
            pending.approval_request_id == id
        }
        Ok(_) => false,
        Err(error) => matches!(
            error,
            PaymentsError::SignerUnavailable(_)
                | PaymentsError::ChainRpc(_)
                | PaymentsError::Persistence(_)
                | PaymentsError::Internal(_)
        ),
    };
    if !keep {
        if let Err(error) = store.remove(id) {
            tracing::warn!(
                kind = error.kind(),
                "failed to delete a settled pending approval"
            );
        }
    }
    result
}

async fn resume_transaction(
    state: &AppState,
    agent: &AuthenticatedAgent,
    intent: Intent,
    tx: BroadcastTx,
    delivery: Delivery,
    wait: crate::signer::ApprovalWait,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let network = intent
        .network
        .clone()
        .ok_or_else(|| PaymentsError::Persistence("a pending approval file is invalid".into()))?;
    let session = Session::open(state, agent, Some(&network)).await?;
    if session.network.chain.chain_id != tx.chain_id {
        return Err(PaymentsError::InvalidRequest(format!(
            "network '{network}' is now configured with another chain id; start a new payment"
        )));
    }
    let rpc = session.rpc().await?;
    let pending_nonce = rpc.pending_nonce(session.wallet()?).await?;
    if pending_nonce > tx.nonce {
        return Err(PaymentsError::InvalidRequest(format!(
            "nonce {} was used on chain in the meantime; start a new payment",
            tx.nonce
        )));
    }
    let submission = Submission {
        tx,
        exact_nonce: true,
        delivery,
    };
    transaction::execute(state, agent, rpc, intent, submission, wait).await
}

/// Plans the transaction and runs the pipeline.
async fn submit(
    session: &Session<'_>,
    method: &str,
    payment: Option<EvmPayment>,
    to: &EvmAddress,
    value_wei: u128,
    data: Vec<u8>,
    options: &EvmTxOptions,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let rpc = session.rpc().await?;
    let tx = transaction::plan(rpc, session.wallet()?, to, value_wei, data, options).await?;
    let intent = Intent {
        method: method.to_string(),
        network: Some(session.network.key.clone()),
        chain_id: tx.chain_id,
        payment,
    };
    let submission = Submission {
        tx,
        exact_nonce: options.nonce.is_some(),
        delivery: Delivery {
            broadcast: options.broadcast,
            wait_for_receipt: options.wait_for_receipt,
            receipt_timeout_secs: resolve::receipt_timeout(options.receipt_timeout_secs).as_secs(),
        },
    };
    let wait = resolve::approval_wait(options.approval_wait_secs, session.state.approval_wait);
    transaction::execute(session.state, session.agent, rpc, intent, submission, wait).await
}

/// Signs a typed transfer or approval without a transaction.
async fn sign_only(
    session: &Session<'_>,
    method: &str,
    payment: EvmPayment,
    action: AgentAction,
    options: &EvmTxOptions,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let intent = Intent {
        method: method.to_string(),
        network: Some(session.network.key.clone()),
        chain_id: session.network.chain.chain_id,
        payment: Some(payment),
    };
    let wait = resolve::approval_wait(options.approval_wait_secs, session.state.approval_wait);
    transaction::sign_only(session.state, session.agent, intent, action, wait).await
}

fn missing_token() -> PaymentsError {
    PaymentsError::Internal("an ERC-20 asset without a contract address".into())
}
