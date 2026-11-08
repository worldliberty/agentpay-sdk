//! Solana payment transactions (`SolanaPaymentTransaction`): a v0 transaction
//! with a primary transfer, optional splits and memos, and a fee payer that may
//! be someone other than the agent, in the instruction order of the MPP
//! `solana` charge reference SDK.

use agentpay_domain::{
    DomainError, Signature, SolanaPaymentAsset, SolanaPaymentTransaction, VaultKey,
};
use agentpay_signer::{SignerError, VaultSignerBackend};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::message::{v0, VersionedMessage};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction::VersionedTransaction;

use super::signing::map_domain_to_signer_error;
use super::solana::{
    build_solana_token_transfer_instruction, decode_public_key_hex_32, decode_solana_pubkey,
    set_solana_compute_unit_limit_instruction, set_solana_compute_unit_price_instruction,
    solana_system_program_id, solana_system_transfer_instruction, solana_token_program_id,
};
use crate::{DaemonError, InMemoryDaemon};

/// SPL Memo program (v2).
pub(super) const SOLANA_MEMO_PROGRAM_ID: Pubkey =
    solana_sdk::pubkey!("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");

/// Associated Token Account program instruction tag for `CreateIdempotent`.
const ATA_CREATE_IDEMPOTENT: u8 = 1;

/// Mint, decimals, and token program of an SPL payment.
struct SplPaymentAsset {
    mint: Pubkey,
    decimals: u8,
    token_program_id: Pubkey,
}

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    /// Builds and signs a payment transaction as the transfer authority.
    ///
    /// When `fee_payer` is the agent the transaction is fully signed. When it
    /// is a foreign fee payer, only the agent's signature slot is filled and
    /// the fee payer's slot stays all zero (a partially signed transaction);
    /// `tx_id` is then omitted because the transaction id is the fee payer's
    /// signature.
    pub(super) async fn sign_solana_payment_transaction(
        &self,
        vault_key: &VaultKey,
        payment: &SolanaPaymentTransaction,
    ) -> Result<Signature, DaemonError> {
        let agent = Pubkey::new_from_array(decode_public_key_hex_32(
            &self
                .signer_backend
                .solana_public_key_hex(vault_key.id)
                .map_err(DaemonError::Signer)?,
        )?);
        let fee_payer = decode_solana_pubkey(&payment.fee_payer)?;
        let recent_blockhash = payment
            .recent_blockhash
            .parse::<solana_sdk::hash::Hash>()
            .map_err(|_| map_domain_to_signer_error(DomainError::InvalidSolanaRecentBlockhash))?;
        let instructions = build_solana_payment_instructions(payment, &agent, &fee_payer)?;

        let message = VersionedMessage::V0(
            v0::Message::try_compile(&fee_payer, &instructions, &[], recent_blockhash).map_err(
                |err| {
                    DaemonError::Signer(SignerError::Unsupported(format!(
                        "failed to compile solana payment message: {err}"
                    )))
                },
            )?,
        );
        let required_signatures = usize::from(message.header().num_required_signatures);
        let agent_index = message
            .static_account_keys()
            .iter()
            .take(required_signatures)
            .position(|key| *key == agent)
            .ok_or_else(|| {
                DaemonError::Signer(SignerError::Internal(
                    "agent is not a signer of the solana payment message".to_string(),
                ))
            })?;

        let signed = self
            .signer_backend
            .sign_solana_payload(vault_key.id, &message.serialize())
            .await?;
        let signature_bytes = <[u8; 64]>::try_from(signed.bytes.as_slice()).map_err(|_| {
            DaemonError::Signer(SignerError::Internal(
                "ed25519 backend returned invalid signature length".to_string(),
            ))
        })?;
        let agent_signature = solana_sdk::signature::Signature::from(signature_bytes);
        let mut signatures = vec![solana_sdk::signature::Signature::default(); required_signatures];
        signatures[agent_index] = agent_signature;
        let transaction = VersionedTransaction {
            signatures,
            message,
        };
        let raw_tx = bincode::serialize(&transaction).map_err(|err| {
            DaemonError::Signer(SignerError::Internal(format!(
                "failed to serialize signed solana transaction: {err}"
            )))
        })?;
        let agent_signature_base58 = agent_signature.to_string();
        let fully_signed = required_signatures == 1;

        Ok(Signature {
            bytes: signature_bytes.to_vec(),
            signature_base58: Some(agent_signature_base58.clone()),
            r_hex: None,
            s_hex: None,
            v: None,
            raw_tx_hex: None,
            tx_hash_hex: None,
            raw_tx_base64: Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                raw_tx,
            )),
            tx_id: fully_signed.then_some(agent_signature_base58),
        })
    }
}

/// Builds the payment's instructions in the reference SDK order: compute unit
/// price, compute unit limit, primary transfer, transaction memo, then per
/// split: `CreateIdempotent` (when requested), transfer, split memo.
pub(super) fn build_solana_payment_instructions(
    payment: &SolanaPaymentTransaction,
    agent: &Pubkey,
    fee_payer: &Pubkey,
) -> Result<Vec<Instruction>, DaemonError> {
    let spl = match &payment.asset {
        SolanaPaymentAsset::NativeSol => None,
        SolanaPaymentAsset::SplToken {
            mint,
            decimals,
            token_program,
        } => Some(SplPaymentAsset {
            mint: decode_solana_pubkey(mint)?,
            decimals: *decimals,
            token_program_id: solana_token_program_id(*token_program),
        }),
    };

    let mut instructions = Vec::with_capacity(4 + payment.transfers.len() * 3);
    if let Some(price) = payment.compute_unit_price_micro_lamports {
        instructions.push(set_solana_compute_unit_price_instruction(price));
    }
    if let Some(limit) = payment.compute_unit_limit {
        instructions.push(set_solana_compute_unit_limit_instruction(limit));
    }
    for (index, leg) in payment.transfers.iter().enumerate() {
        let recipient_owner = decode_solana_pubkey(&leg.recipient_owner)?;
        let amount = u64::try_from(leg.amount_wei)
            .map_err(|_| map_domain_to_signer_error(DomainError::AmountOutOfRange))?;
        let is_primary = index == 0;
        if leg.create_ata {
            // Validation already refuses these; the signer refuses them again
            // so a primary recipient account is never created.
            let Some(spl) = spl.as_ref().filter(|_| !is_primary) else {
                return Err(map_domain_to_signer_error(
                    DomainError::InvalidSolanaPaymentTransaction(
                        "create_ata is only valid for SPL token splits",
                    ),
                ));
            };
            instructions.push(solana_create_ata_idempotent_instruction(
                fee_payer,
                &recipient_owner,
                spl,
            ));
        }
        instructions.push(match &spl {
            None => solana_system_transfer_instruction(agent, &recipient_owner, amount),
            Some(spl) => build_solana_token_transfer_instruction(
                spl.token_program_id,
                &spl_associated_token_account::get_associated_token_address_with_program_id(
                    agent,
                    &spl.mint,
                    &spl.token_program_id,
                ),
                &spl.mint,
                &spl_associated_token_account::get_associated_token_address_with_program_id(
                    &recipient_owner,
                    &spl.mint,
                    &spl.token_program_id,
                ),
                agent,
                amount,
                spl.decimals,
                None,
            )?,
        });
        let memo = if is_primary {
            payment.memo.as_deref()
        } else {
            leg.memo.as_deref()
        };
        if let Some(memo) = memo {
            instructions.push(solana_memo_instruction(memo));
        }
    }
    Ok(instructions)
}

/// Memo program instruction with no accounts; the data is the raw UTF-8 memo.
fn solana_memo_instruction(memo: &str) -> Instruction {
    Instruction {
        program_id: SOLANA_MEMO_PROGRAM_ID,
        accounts: vec![],
        data: memo.as_bytes().to_vec(),
    }
}

/// Associated Token Account `CreateIdempotent`, funded by `payer`.
fn solana_create_ata_idempotent_instruction(
    payer: &Pubkey,
    wallet: &Pubkey,
    spl: &SplPaymentAsset,
) -> Instruction {
    let associated_account =
        spl_associated_token_account::get_associated_token_address_with_program_id(
            wallet,
            &spl.mint,
            &spl.token_program_id,
        );
    Instruction {
        program_id: spl_associated_token_account::ID,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(associated_account, false),
            AccountMeta::new_readonly(*wallet, false),
            AccountMeta::new_readonly(spl.mint, false),
            AccountMeta::new_readonly(solana_system_program_id(), false),
            AccountMeta::new_readonly(spl.token_program_id, false),
        ],
        data: vec![ATA_CREATE_IDEMPOTENT],
    }
}
