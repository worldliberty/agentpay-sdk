//! `TransferSol` and `TransferSpl`.
//!
//! This module resolves a request into a [`flow::Transfer`]: the configured
//! Solana chain, the agent's wallet, the amount in base units, and for
//! tokens the mint, both associated token accounts (which must exist), and
//! the Token-2022 transfer fee. [`flow`] then signs it through the signer
//! daemon, verifies, and broadcasts. The wire contract and the behavior are
//! documented on `agentpay_api::payments::solana`.
//!
//! A transfer held for an operator returns `ManualApprovalPending` (the
//! shape shared with the EVM methods). It resumes when the same call is
//! sent again, or through [`resume_approved`], the hook `ResumeApproved`
//! uses for approval requests that belong to a Solana transfer.

mod amount;
mod flow;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use agentpay_api::payments::solana::SOLANA_MAX_APPROVAL_WAIT_SECS;
use agentpay_api::payments::{
    ChainFamily, PaymentsRpcRequest, PaymentsRpcResponse, SolanaAmount, SolanaTransferOptions,
    TransferSolParams, TransferSplParams,
};
use agentpay_domain::SolanaAddress;
use serde::Serialize;
use solana_sdk::pubkey::Pubkey;
use uuid::Uuid;

use crate::auth::AuthenticatedAgent;
use crate::chains::solana::accounts::{associated_token_account, parse_mint, token_program_id};
use crate::chains::solana::budget::{
    SOL_TRANSFER_COMPUTE_UNIT_LIMIT, SPL_TRANSFER_COMPUTE_UNIT_LIMIT,
};
use crate::chains::solana::pending::intent_key;
use crate::chains::solana::{SolanaChain, SolanaProvider, SolanaRpc};
use crate::error::PaymentsError;
use crate::state::AppState;

use flow::{Outcome, SplDetails, Transfer, TransferKind};

/// Decimals of native SOL.
const SOL_DECIMALS: u8 = 9;

/// Handles the Solana transfer methods.
pub async fn handle(
    state: &AppState,
    agent: &AuthenticatedAgent,
    request: PaymentsRpcRequest,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let provider = state.chains.get::<SolanaProvider>()?;
    let outcome = match request {
        PaymentsRpcRequest::TransferSol(params) => {
            let transfer = prepare_sol(state, &provider, agent, &params).await?;
            flow::run(state, &provider, agent, transfer).await
        }
        PaymentsRpcRequest::TransferSpl(params) => {
            let transfer = prepare_spl(state, &provider, agent, &params).await?;
            flow::run(state, &provider, agent, transfer).await
        }
        other => Err(PaymentsError::Internal(format!(
            "the solana feature cannot handle {}",
            other.method_name()
        ))),
    }?;
    Ok(response(outcome))
}

fn response(outcome: Outcome) -> PaymentsRpcResponse {
    match outcome {
        Outcome::Done(result) => PaymentsRpcResponse::SolanaTransfer(result),
        Outcome::Pending(pending) => PaymentsRpcResponse::ManualApprovalPending(pending),
    }
}

/// Resumes the Solana transfer waiting for `approval_request_id`, if it
/// belongs to `agent`; `None` when no stored Solana action has that id (it
/// may be an EVM one).
///
/// The stored action is resent unchanged with the original call's options
/// (`approval_wait_secs` overridden when given). It still uses its durable
/// nonce: if the nonce account was advanced in the meantime the transaction
/// could never land, so the call fails with `InvalidRequest` and the stale
/// entry is dropped.
pub async fn resume_approved(
    state: &AppState,
    agent: &AuthenticatedAgent,
    approval_request_id: Uuid,
    approval_wait_secs: Option<u64>,
) -> Option<Result<PaymentsRpcResponse, PaymentsError>> {
    let provider = state.chains.get::<SolanaProvider>().ok()?;
    let (intent_key, entry) = provider
        .pending
        .find(agent.credentials.agent_key_id, approval_request_id)
        .await?;
    Some(
        async {
            let kind = TransferKind::from_action(&entry.action)?;
            let method = match &kind {
                TransferKind::Sol { .. } => "TransferSol",
                TransferKind::Spl(_) => "TransferSpl",
            };
            let chain = resolve_chain(state, &entry.network).await?;
            let rpc = provider.rpc(&chain).await?;
            let mut options = entry.options.clone();
            if approval_wait_secs.is_some() {
                options.approval_wait_secs =
                    approval_wait_secs.map(|secs| secs.min(SOLANA_MAX_APPROVAL_WAIT_SECS));
            }
            let transfer = Transfer {
                method,
                intent_key,
                resume: true,
                agent_key_id: agent.credentials.agent_key_id,
                chain,
                rpc,
                fee_payer: wallet(agent)?,
                options,
                default_compute_unit_limit: SOL_TRANSFER_COMPUTE_UNIT_LIMIT,
                kind,
            };
            flow::run(state, &provider, agent, transfer)
                .await
                .map(response)
        }
        .await,
    )
}

/// What identifies a call for resuming a pending approval: the request
/// without credentials and without the options that do not change the action.
#[derive(Serialize)]
struct Intent<'a> {
    network: &'a str,
    to: &'a SolanaAddress,
    mint: Option<&'a SolanaAddress>,
    amount: &'a SolanaAmount,
    options: SolanaTransferOptions,
}

impl<'a> Intent<'a> {
    fn key(self, agent: &AuthenticatedAgent, method: &str) -> String {
        intent_key(agent.credentials.agent_key_id, method, &self)
    }

    fn new(
        network: &'a str,
        to: &'a SolanaAddress,
        mint: Option<&'a SolanaAddress>,
        amount: &'a SolanaAmount,
        options: &SolanaTransferOptions,
    ) -> Self {
        Self {
            network,
            to,
            mint,
            amount,
            options: SolanaTransferOptions {
                wait_for_confirmation: true,
                approval_wait_secs: None,
                reveal_raw_tx: false,
                ..options.clone()
            },
        }
    }
}

async fn prepare_sol(
    state: &AppState,
    provider: &Arc<SolanaProvider>,
    agent: &AuthenticatedAgent,
    params: &TransferSolParams,
) -> Result<Transfer, PaymentsError> {
    let chain = resolve_chain(state, &params.network).await?;
    let fee_payer = wallet(agent)?;
    let lamports = amount::base_units(&params.amount, SOL_DECIMALS)?;
    let rpc = provider.rpc(&chain).await?;
    Ok(Transfer {
        method: "TransferSol",
        intent_key: Intent::new(
            &params.network,
            &params.to,
            None,
            &params.amount,
            &params.options,
        )
        .key(agent, "TransferSol"),
        resume: false,
        agent_key_id: agent.credentials.agent_key_id,
        chain,
        rpc,
        fee_payer,
        options: params.options.clone(),
        default_compute_unit_limit: SOL_TRANSFER_COMPUTE_UNIT_LIMIT,
        kind: TransferKind::Sol {
            to: pubkey(&params.to)?,
            lamports,
        },
    })
}

async fn prepare_spl(
    state: &AppState,
    provider: &Arc<SolanaProvider>,
    agent: &AuthenticatedAgent,
    params: &TransferSplParams,
) -> Result<Transfer, PaymentsError> {
    let chain = resolve_chain(state, &params.network).await?;
    let fee_payer = wallet(agent)?;
    let rpc = provider.rpc(&chain).await?;
    let mint = pubkey(&params.mint)?;
    let recipient_owner = pubkey(&params.to)?;

    let mint_account = rpc
        .account(&mint)
        .await?
        .ok_or_else(|| PaymentsError::InvalidRequest("the mint account does not exist".into()))?;
    let mint_info = parse_mint(&mint_account)?;
    let program = token_program_id(mint_info.token_program);
    let source = associated_token_account(&fee_payer, &mint, &program);
    let destination = associated_token_account(&recipient_owner, &mint, &program);
    require_token_account(&rpc, &source, &program, "the wallet's", "fund it first").await?;
    require_token_account(
        &rpc,
        &destination,
        &program,
        "the recipient's",
        "create it before sending",
    )
    .await?;

    let amount = amount::base_units(&params.amount, mint_info.decimals)?;
    let transfer_fee = match mint_info.transfer_fee {
        Some(_) => mint_info.transfer_fee(rpc.epoch().await?, amount)?,
        None => None,
    };
    Ok(Transfer {
        method: "TransferSpl",
        intent_key: Intent::new(
            &params.network,
            &params.to,
            Some(&params.mint),
            &params.amount,
            &params.options,
        )
        .key(agent, "TransferSpl"),
        resume: false,
        agent_key_id: agent.credentials.agent_key_id,
        chain,
        rpc,
        fee_payer,
        options: params.options.clone(),
        default_compute_unit_limit: SPL_TRANSFER_COMPUTE_UNIT_LIMIT,
        kind: TransferKind::Spl(SplDetails {
            mint,
            recipient_owner,
            token_program: mint_info.token_program,
            decimals: mint_info.decimals,
            amount,
            transfer_fee,
        }),
    })
}

/// Fails unless `address` is a token account of `program`.
async fn require_token_account(
    rpc: &SolanaRpc,
    address: &Pubkey,
    program: &Pubkey,
    whose: &str,
    remedy: &str,
) -> Result<(), PaymentsError> {
    match rpc.account(address).await? {
        Some(account) if account.owner == *program => Ok(()),
        Some(_) => Err(PaymentsError::InvalidRequest(format!(
            "{whose} associated token account for this mint is not owned by the mint's token program"
        ))),
        None => Err(PaymentsError::InvalidRequest(format!(
            "{whose} associated token account for this mint does not exist; {remedy}"
        ))),
    }
}

/// The configured Solana chain named `network`.
async fn resolve_chain(state: &AppState, network: &str) -> Result<SolanaChain, PaymentsError> {
    let config = state.config.get().await;
    let key = network.trim().to_ascii_lowercase();
    let chain = config
        .chains
        .get(&key)
        .ok_or_else(|| PaymentsError::InvalidRequest(format!("unknown network '{key}'")))?;
    if chain.family != ChainFamily::Solana {
        return Err(PaymentsError::InvalidRequest(format!(
            "network '{key}' is not a Solana network"
        )));
    }
    let rpc_url = chain.rpc_url.clone().ok_or_else(|| {
        PaymentsError::InvalidRequest(format!("network '{key}' has no RPC URL configured"))
    })?;
    Ok(SolanaChain {
        key,
        chain_id: chain.chain_id,
        rpc_url,
        fallback_rpc_urls: chain.fallback_rpc_urls.clone(),
    })
}

/// The agent's Solana wallet.
fn wallet(agent: &AuthenticatedAgent) -> Result<Pubkey, PaymentsError> {
    let address = agent.identity.solana_address.as_ref().ok_or_else(|| {
        PaymentsError::InvalidRequest("the agent's vault key cannot sign for Solana".into())
    })?;
    pubkey(address)
}

pub(crate) fn pubkey(address: &SolanaAddress) -> Result<Pubkey, PaymentsError> {
    address
        .to_bytes()
        .map(Pubkey::new_from_array)
        .map_err(|_| PaymentsError::InvalidRequest("invalid Solana address".into()))
}

pub(crate) fn address(pubkey: &Pubkey) -> Result<SolanaAddress, PaymentsError> {
    pubkey
        .to_string()
        .parse()
        .map_err(|_| PaymentsError::Internal("a public key did not encode as an address".into()))
}
