//! The Solana transfer flow: blockhash or durable nonce (creating the
//! managed nonce account when needed), the signing action (fresh, or the
//! stored one of a pending approval), the policy-checked signature,
//! verification, broadcast, and confirmation.
//!
//! A signature held for an operator ends the flow with
//! [`Outcome::Pending`] after the exact action is stored; resending the same
//! call or `ResumeApproved` resends that action.

use std::time::Duration;

use agentpay_api::payments::solana::SOLANA_MAX_APPROVAL_WAIT_SECS;
use agentpay_api::payments::{
    ManualApprovalPendingResult, SolanaBroadcast, SolanaDurableNonce, SolanaNonceMode,
    SolanaTransferDetails, SolanaTransferOptions, SolanaTransferResult, SolanaTxStatus,
};
use agentpay_domain::{
    AgentAction, Signature, SolanaNonceAccountCreate, SolanaSolTransfer, SolanaSplTransfer,
    SolanaTokenProgram,
};
use solana_sdk::hash::Hash;
use solana_sdk::pubkey::Pubkey;
use uuid::Uuid;

use super::{address, pubkey};
use crate::auth::AuthenticatedAgent;
use crate::chains::solana::accounts::{
    associated_token_account, managed_nonce_account, parse_nonce_account, token_program_id,
    ManagedNonceAccount, NONCE_ACCOUNT_LEN,
};
use crate::chains::solana::budget::{self, ComputeBudget};
use crate::chains::solana::pending::PendingAction;
use crate::chains::solana::verify::{verify, Expected, ExpectedOperation, Verified};
use crate::chains::solana::{SolanaChain, SolanaProvider, SolanaRpc};
use crate::error::PaymentsError;
use crate::signer::{AgentSigner, ApprovalWait};
use crate::state::AppState;

/// A resolved transfer request.
pub(super) struct Transfer {
    /// `TransferSol` or `TransferSpl`.
    pub method: &'static str,
    /// Pending-store key of this call ([`crate::chains::solana::pending::intent_key`]).
    pub intent_key: String,
    /// Only resend the stored action (`ResumeApproved`); never build a new one.
    pub resume: bool,
    /// The calling agent.
    pub agent_key_id: Uuid,
    pub chain: SolanaChain,
    pub rpc: SolanaRpc,
    /// The agent's wallet.
    pub fee_payer: Pubkey,
    pub options: SolanaTransferOptions,
    pub default_compute_unit_limit: u32,
    pub kind: TransferKind,
}

/// What moves.
pub(super) enum TransferKind {
    Sol { to: Pubkey, lamports: u64 },
    Spl(SplDetails),
}

impl TransferKind {
    /// The transfer a stored signing action performs.
    pub(super) fn from_action(action: &AgentAction) -> Result<Self, PaymentsError> {
        let units = |value: u128| {
            u64::try_from(value).map_err(|_| {
                PaymentsError::Internal("amount out of range in a stored action".into())
            })
        };
        match action {
            AgentAction::SolanaSolTransfer { transfer: t } => Ok(Self::Sol {
                to: pubkey(&t.to)?,
                lamports: units(t.amount_wei)?,
            }),
            AgentAction::SolanaSplTransfer { transfer: t } => Ok(Self::Spl(SplDetails {
                mint: pubkey(&t.mint)?,
                recipient_owner: pubkey(&t.recipient_owner)?,
                token_program: t.token_program,
                decimals: t.decimals,
                amount: units(t.amount_wei)?,
                transfer_fee: t.transfer_fee_wei.map(units).transpose()?,
            })),
            _ => Err(PaymentsError::Internal(
                "not a Solana transfer action".into(),
            )),
        }
    }
}

/// A token transfer between associated token accounts.
pub(super) struct SplDetails {
    pub mint: Pubkey,
    pub recipient_owner: Pubkey,
    pub token_program: SolanaTokenProgram,
    pub decimals: u8,
    pub amount: u64,
    pub transfer_fee: Option<u64>,
}

/// How a transfer ended.
pub(super) enum Outcome {
    /// Signed, verified, and (if asked) broadcast.
    Done(SolanaTransferResult),
    /// Waiting for an operator; the action is stored for resuming.
    Pending(ManualApprovalPendingResult),
}

/// The durable nonce a transfer uses.
struct NonceInUse {
    account: Pubkey,
    value: Hash,
    managed: bool,
    created_signature: Option<String>,
}

/// Runs `transfer` for `agent`.
pub(super) async fn run(
    state: &AppState,
    provider: &SolanaProvider,
    agent: &AuthenticatedAgent,
    transfer: Transfer,
) -> Result<Outcome, PaymentsError> {
    let signer = agent.signer(state.signer.as_ref());
    let options = &transfer.options;
    let fees = match options.compute_unit_price_micro_lamports {
        Some(_) => None,
        None => transfer.rpc.prioritization_fees().await.ok(),
    };
    let compute_budget = budget::resolve(
        transfer.default_compute_unit_limit,
        options.compute_unit_limit,
        options.compute_unit_price_micro_lamports,
        fees,
    )?;

    let managed = managed_nonce_account(&transfer.fee_payer, transfer.chain.chain_id)?;
    let nonce_account = match &options.nonce {
        SolanaNonceMode::Auto if options.broadcast => Some((managed.address, Some(managed))),
        SolanaNonceMode::Auto | SolanaNonceMode::RecentBlockhash => None,
        SolanaNonceMode::Managed => Some((managed.address, Some(managed))),
        SolanaNonceMode::Account(account) => Some((pubkey(account)?, None)),
    };
    // Transactions sharing a nonce account are serialized: the second one
    // built on the same nonce value would fail on chain.
    let lock = match &nonce_account {
        Some((account, _)) => Some(provider.nonce_lock(account)?),
        None => None,
    };
    let _guard = match &lock {
        Some(lock) => Some(lock.lock().await),
        None => None,
    };
    let nonce = match nonce_account {
        Some((account, managed)) => {
            Some(durable_nonce(provider, &transfer, &signer, account, managed).await?)
        }
        None => None,
    };

    let action = match stored_action(provider, &transfer, nonce.as_ref()).await? {
        Some(action) => action,
        None if transfer.resume => {
            return Err(PaymentsError::InvalidRequest(
                "the durable nonce advanced after the approval was requested, so the approved \
                 transaction can no longer land; send the transfer again"
                    .into(),
            ))
        }
        None => {
            let recent_blockhash = match &nonce {
                Some(nonce) => nonce.value,
                None => transfer.rpc.latest_blockhash().await?,
            };
            build_action(&transfer, nonce.as_ref(), recent_blockhash, compute_budget)?
        }
    };
    let signature = match sign(state, provider, &signer, &transfer, &action).await? {
        Signed::Signature(signature) => signature,
        Signed::Pending(pending) => return Ok(Outcome::Pending(*pending)),
    };
    let verified = verify_signed(&signature, &action)?;

    let broadcast = if options.broadcast {
        let sent = transfer.rpc.send(&verified.transaction).await?;
        Some(if options.wait_for_confirmation {
            transfer
                .rpc
                .wait_for_confirmation(&sent, provider.confirmation)
                .await
        } else {
            SolanaBroadcast {
                status: SolanaTxStatus::Submitted,
                slot: None,
                error: None,
            }
        })
    } else {
        None
    };
    tracing::info!(
        network = transfer.chain.key.as_str(),
        broadcast = options.broadcast,
        status = ?broadcast.as_ref().map(|b| b.status),
        "solana transfer signed"
    );
    let raw_tx_base64 = (!options.broadcast || options.reveal_raw_tx)
        .then(|| signature.raw_tx_base64.clone())
        .flatten();
    result(
        &transfer,
        &action,
        &verified,
        nonce,
        raw_tx_base64,
        broadcast,
    )
    .map(Outcome::Done)
}

/// Reads the nonce of `account`, creating the managed account first when it
/// does not exist yet.
async fn durable_nonce(
    provider: &SolanaProvider,
    transfer: &Transfer,
    signer: &AgentSigner<'_>,
    account: Pubkey,
    managed: Option<ManagedNonceAccount>,
) -> Result<NonceInUse, PaymentsError> {
    let in_use = |value, created_signature| NonceInUse {
        account,
        value,
        managed: managed.is_some(),
        created_signature,
    };
    if let Some(existing) = transfer.rpc.account(&account).await? {
        return Ok(in_use(
            parse_nonce_account(&existing, &transfer.fee_payer)?,
            None,
        ));
    }
    let Some(managed_account) = &managed else {
        return Err(PaymentsError::InvalidRequest(
            "the durable nonce account does not exist".into(),
        ));
    };
    let created = create_managed_nonce(provider, transfer, signer, managed_account).await;
    // Another request may have created it meanwhile; what is on chain decides.
    match (created, transfer.rpc.account(&account).await?) {
        (Ok(signature), Some(existing)) => Ok(in_use(
            parse_nonce_account(&existing, &transfer.fee_payer)?,
            Some(signature),
        )),
        (Err(_), Some(existing)) => Ok(in_use(
            parse_nonce_account(&existing, &transfer.fee_payer)?,
            None,
        )),
        (Err(error), None) => Err(error),
        (Ok(_), None) => Err(PaymentsError::ChainRpc(
            "the managed nonce account was created but is not visible yet; retry".into(),
        )),
    }
}

/// Signs, verifies, and sends `SolanaNonceAccountCreate` for the managed
/// nonce account and waits for it to confirm. Returns the signature.
async fn create_managed_nonce(
    provider: &SolanaProvider,
    transfer: &Transfer,
    signer: &AgentSigner<'_>,
    managed: &ManagedNonceAccount,
) -> Result<String, PaymentsError> {
    let rent_lamports = transfer.rpc.rent_exemption(NONCE_ACCOUNT_LEN).await?;
    let blockhash = transfer.rpc.latest_blockhash().await?;
    let action = AgentAction::SolanaNonceAccountCreate {
        create: SolanaNonceAccountCreate {
            chain_id: transfer.chain.chain_id,
            recent_blockhash: blockhash.to_string(),
            fee_payer: address(&transfer.fee_payer)?,
            nonce_account: address(&managed.address)?,
            seed: managed.seed.clone(),
            rent_lamports: u128::from(rent_lamports),
        },
    };
    // Wallet maintenance: signerd does not hold it for approval.
    let signature = signer.sign(action.clone(), ApprovalWait::none()).await?;
    let verified = verify_signed(&signature, &action)?;
    let sent = transfer.rpc.send(&verified.transaction).await?;
    let outcome = transfer
        .rpc
        .wait_for_confirmation(&sent, provider.confirmation)
        .await;
    tracing::info!(status = ?outcome.status, "managed solana nonce account creation");
    match outcome.status {
        SolanaTxStatus::Confirmed | SolanaTxStatus::Finalized => Ok(sent.to_string()),
        SolanaTxStatus::Failed => Err(PaymentsError::ChainRpc(format!(
            "creating the managed nonce account failed on chain: {}",
            outcome.error.unwrap_or_default()
        ))),
        SolanaTxStatus::Submitted | SolanaTxStatus::TimedOut => Err(PaymentsError::ChainRpc(
            "timed out waiting for the managed nonce account to be created".into(),
        )),
    }
}

/// The action stored for this call by an earlier `ManualApprovalPending`,
/// if it is still usable: same chain, wallet, and nonce account, and the
/// nonce has not moved on. A stale one is discarded.
async fn stored_action(
    provider: &SolanaProvider,
    transfer: &Transfer,
    nonce: Option<&NonceInUse>,
) -> Result<Option<AgentAction>, PaymentsError> {
    let Some(entry) = provider.pending.get(&transfer.intent_key).await else {
        return Ok(None);
    };
    let fee_payer = address(&transfer.fee_payer)?;
    let current = match nonce {
        Some(nonce) => Some((address(&nonce.account)?, nonce.value.to_string())),
        None => None,
    };
    let stored = match &entry.action {
        AgentAction::SolanaSolTransfer { transfer: t } => Some((
            t.chain_id,
            &t.fee_payer,
            t.durable_nonce_account.clone(),
            &t.recent_blockhash,
        )),
        AgentAction::SolanaSplTransfer { transfer: t } => Some((
            t.chain_id,
            &t.fee_payer,
            t.durable_nonce_account.clone(),
            &t.recent_blockhash,
        )),
        _ => None,
    };
    let usable = match (stored, current) {
        (Some((chain_id, payer, Some(account), blockhash)), Some((now_account, now_value))) => {
            chain_id == transfer.chain.chain_id
                && *payer == fee_payer
                && account == now_account
                && *blockhash == now_value
        }
        _ => false,
    };
    if usable {
        return Ok(Some(entry.action));
    }
    forget(provider, &transfer.intent_key).await;
    Ok(None)
}

/// The signing action for a fresh transfer on `recent_blockhash` (the
/// nonce value when `nonce` is set).
fn build_action(
    transfer: &Transfer,
    nonce: Option<&NonceInUse>,
    recent_blockhash: Hash,
    compute_budget: ComputeBudget,
) -> Result<AgentAction, PaymentsError> {
    let recent_blockhash = recent_blockhash.to_string();
    let durable_nonce_account = nonce.map(|nonce| address(&nonce.account)).transpose()?;
    let fee_payer = address(&transfer.fee_payer)?;
    let chain_id = transfer.chain.chain_id;
    Ok(match &transfer.kind {
        TransferKind::Sol { to, lamports } => AgentAction::SolanaSolTransfer {
            transfer: SolanaSolTransfer {
                chain_id,
                recent_blockhash,
                durable_nonce_account,
                fee_payer,
                to: address(to)?,
                amount_wei: u128::from(*lamports),
                compute_unit_limit: compute_budget.unit_limit,
                compute_unit_price_micro_lamports: compute_budget.unit_price,
            },
        },
        TransferKind::Spl(spl) => AgentAction::SolanaSplTransfer {
            transfer: SolanaSplTransfer {
                chain_id,
                recent_blockhash,
                durable_nonce_account,
                fee_payer,
                mint: address(&spl.mint)?,
                recipient_owner: address(&spl.recipient_owner)?,
                amount_wei: u128::from(spl.amount),
                decimals: spl.decimals,
                token_program: spl.token_program,
                transfer_fee_wei: spl.transfer_fee.map(u128::from),
                compute_unit_limit: compute_budget.unit_limit,
                compute_unit_price_micro_lamports: compute_budget.unit_price,
            },
        },
    })
}

/// What signing produced.
enum Signed {
    Signature(Signature),
    Pending(Box<ManualApprovalPendingResult>),
}

/// Signs `action`, storing it when it ends up waiting for an operator and
/// forgetting it once the signer daemon has decided.
async fn sign(
    state: &AppState,
    provider: &SolanaProvider,
    signer: &AgentSigner<'_>,
    transfer: &Transfer,
    action: &AgentAction,
) -> Result<Signed, PaymentsError> {
    let wait = match transfer.options.approval_wait_secs {
        Some(secs) => ApprovalWait {
            max_wait: Duration::from_secs(secs.min(SOLANA_MAX_APPROVAL_WAIT_SECS)),
            ..state.approval_wait
        },
        None => state.approval_wait,
    };
    match signer.sign(action.clone(), wait).await {
        Ok(signature) => {
            forget(provider, &transfer.intent_key).await;
            Ok(Signed::Signature(signature))
        }
        Err(PaymentsError::ManualApprovalPending {
            approval_request_id,
        }) => {
            let entry = PendingAction {
                agent_key_id: transfer.agent_key_id,
                method: transfer.method.to_string(),
                network: transfer.chain.key.clone(),
                options: transfer.options.clone(),
                action: action.clone(),
                approval_request_id,
                stored_at: 0,
            };
            provider.pending.put(&transfer.intent_key, entry).await?;
            Ok(Signed::Pending(Box::new(ManualApprovalPendingResult {
                approval_request_id,
                method: transfer.method.to_string(),
                network: Some(transfer.chain.key.clone()),
                chain_id: transfer.chain.chain_id,
                payment: None,
                action: action.clone(),
            })))
        }
        Err(error @ PaymentsError::Signer(_)) => {
            forget(provider, &transfer.intent_key).await;
            Err(error)
        }
        Err(error) => Err(error),
    }
}

async fn forget(provider: &SolanaProvider, key: &str) {
    if let Err(error) = provider.pending.remove(key).await {
        tracing::warn!(
            kind = error.kind(),
            "could not drop a pending solana action"
        );
    }
}

/// What the signer daemon must have signed for `action`.
pub(crate) fn expected_for(action: &AgentAction) -> Result<Expected, PaymentsError> {
    let hash = |value: &str| {
        value
            .parse::<Hash>()
            .map_err(|_| PaymentsError::Internal("invalid blockhash in a signing action".into()))
    };
    let units = |value: u128| {
        u64::try_from(value)
            .map_err(|_| PaymentsError::Internal("amount out of range in a signing action".into()))
    };
    let budget = |unit_limit, unit_price| ComputeBudget {
        unit_limit,
        unit_price,
    };
    Ok(match action {
        AgentAction::SolanaSolTransfer { transfer: t } => Expected {
            fee_payer: pubkey(&t.fee_payer)?,
            recent_blockhash: hash(&t.recent_blockhash)?,
            durable_nonce_account: t.durable_nonce_account.as_ref().map(pubkey).transpose()?,
            compute_budget: budget(t.compute_unit_limit, t.compute_unit_price_micro_lamports),
            operation: ExpectedOperation::SolTransfer {
                to: pubkey(&t.to)?,
                lamports: units(t.amount_wei)?,
            },
        },
        AgentAction::SolanaSplTransfer { transfer: t } => {
            let fee_payer = pubkey(&t.fee_payer)?;
            let mint = pubkey(&t.mint)?;
            let program = token_program_id(t.token_program);
            Expected {
                fee_payer,
                recent_blockhash: hash(&t.recent_blockhash)?,
                durable_nonce_account: t.durable_nonce_account.as_ref().map(pubkey).transpose()?,
                compute_budget: budget(t.compute_unit_limit, t.compute_unit_price_micro_lamports),
                operation: ExpectedOperation::SplTransfer {
                    program,
                    mint,
                    source: associated_token_account(&fee_payer, &mint, &program),
                    destination: associated_token_account(
                        &pubkey(&t.recipient_owner)?,
                        &mint,
                        &program,
                    ),
                    amount: units(t.amount_wei)?,
                    decimals: t.decimals,
                    fee: t.transfer_fee_wei.map(units).transpose()?,
                },
            }
        }
        AgentAction::SolanaNonceAccountCreate { create } => Expected {
            fee_payer: pubkey(&create.fee_payer)?,
            recent_blockhash: hash(&create.recent_blockhash)?,
            durable_nonce_account: None,
            compute_budget: budget(None, None),
            operation: ExpectedOperation::NonceAccountCreate {
                nonce_account: pubkey(&create.nonce_account)?,
                seed: create.seed.clone(),
                rent_lamports: units(create.rent_lamports)?,
            },
        },
        _ => {
            return Err(PaymentsError::Internal(
                "not a Solana signing action".into(),
            ))
        }
    })
}

/// Verifies the signer daemon's answer for `action`, including that the
/// reported transaction id is the transaction's own signature.
fn verify_signed(signature: &Signature, action: &AgentAction) -> Result<Verified, PaymentsError> {
    let raw = signature.raw_tx_base64.as_deref().ok_or_else(|| {
        PaymentsError::SignedTransactionMismatch(
            "the signer daemon returned no Solana transaction".into(),
        )
    })?;
    let verified = verify(raw, &expected_for(action)?)?;
    let own = transaction_id(&verified)?;
    if signature.tx_id.as_deref() != Some(own.as_str()) {
        return Err(PaymentsError::SignedTransactionMismatch(
            "signed Solana transaction id does not match its signature".into(),
        ));
    }
    Ok(verified)
}

/// The transaction's id: its (only) signature, base58.
fn transaction_id(verified: &Verified) -> Result<String, PaymentsError> {
    verified
        .transaction
        .signatures
        .first()
        .map(ToString::to_string)
        .ok_or_else(|| {
            PaymentsError::SignedTransactionMismatch("signed Solana transaction is unsigned".into())
        })
}

fn result(
    transfer: &Transfer,
    action: &AgentAction,
    verified: &Verified,
    nonce: Option<NonceInUse>,
    raw_tx_base64: Option<String>,
    broadcast: Option<SolanaBroadcast>,
) -> Result<SolanaTransferResult, PaymentsError> {
    let (fee_payer, recent_blockhash, details) = match action {
        AgentAction::SolanaSolTransfer { transfer: t } => (
            t.fee_payer.clone(),
            t.recent_blockhash.clone(),
            SolanaTransferDetails::Sol {
                to: t.to.clone(),
                amount_wei: t.amount_wei,
            },
        ),
        AgentAction::SolanaSplTransfer { transfer: t } => {
            let fee_payer = pubkey(&t.fee_payer)?;
            let mint = pubkey(&t.mint)?;
            let program = token_program_id(t.token_program);
            let source = associated_token_account(&fee_payer, &mint, &program);
            let destination =
                associated_token_account(&pubkey(&t.recipient_owner)?, &mint, &program);
            (
                t.fee_payer.clone(),
                t.recent_blockhash.clone(),
                SolanaTransferDetails::Spl {
                    mint: t.mint.clone(),
                    recipient_owner: t.recipient_owner.clone(),
                    source_token_account: address(&source)?,
                    destination_token_account: address(&destination)?,
                    token_program: t.token_program,
                    decimals: t.decimals,
                    amount_wei: t.amount_wei,
                    transfer_fee_wei: t.transfer_fee_wei,
                },
            )
        }
        _ => return Err(PaymentsError::Internal("not a Solana transfer".into())),
    };
    let durable_nonce = nonce
        .map(|nonce| {
            Ok::<_, PaymentsError>(SolanaDurableNonce {
                account: address(&nonce.account)?,
                managed: nonce.managed,
                created_signature: nonce.created_signature,
            })
        })
        .transpose()?;
    Ok(SolanaTransferResult {
        network: transfer.chain.key.clone(),
        chain_id: transfer.chain.chain_id,
        fee_payer,
        transfer: details,
        recent_blockhash,
        durable_nonce,
        compute_unit_limit: verified.compute_budget.unit_limit,
        compute_unit_price_micro_lamports: verified.compute_budget.unit_price,
        signature: transaction_id(verified)?,
        raw_tx_base64,
        broadcast,
    })
}
