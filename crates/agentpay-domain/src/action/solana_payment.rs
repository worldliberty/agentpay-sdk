//! Solana payment transactions: one policy-checked transfer with optional
//! splits, memos, and a fee payer that may be someone other than the agent
//! (the MPP `solana` charge intent, draft-solana-charge-00).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::solana::{
    decode_base58_32, validate_solana_amount, validate_solana_compute_budget, SolanaTokenProgram,
};
use crate::constants::{
    is_solana_chain_id, SOLANA_PAYMENT_MAX_COMPUTE_UNIT_LIMIT, SOLANA_PAYMENT_MAX_LEGS,
    SOLANA_PAYMENT_MAX_MEMO_BYTES,
};
use crate::schema::DecimalU128;
use crate::u128_as_decimal_string;
use crate::{AssetId, DomainError, RecipientId, SolanaAddress};

/// Asset a [`SolanaPaymentTransaction`] moves; every leg pays in this asset.
///
/// JSON: `{"kind": "native_sol"}` or
/// `{"kind": "spl_token", "mint": "<base58>", "decimals": 6, "token_program": "token"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SolanaPaymentAsset {
    /// Native SOL; leg amounts are lamports.
    NativeSol,
    /// SPL token; leg amounts are token base units.
    SplToken {
        /// Mint pubkey.
        mint: SolanaAddress,
        /// Mint decimals enforced by `TransferChecked`.
        decimals: u8,
        /// Token program that owns the mint (SPL Token or Token-2022).
        token_program: SolanaTokenProgram,
    },
}

/// One transfer of a [`SolanaPaymentTransaction`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SolanaPaymentLeg {
    /// Recipient wallet (owner) pubkey. For SPL payments the tokens go to this
    /// owner's associated token account for the mint and token program.
    pub recipient_owner: SolanaAddress,
    /// Amount in lamports (SOL) or token base units (SPL); greater than zero
    /// and at most `u64::MAX`.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub amount_wei: u128,
    /// Create the recipient's associated token account first, with an
    /// idempotent `CreateIdempotent` instruction paid for by `fee_payer`.
    /// SPL splits only: never allowed for the primary (first) leg or for SOL.
    #[serde(default)]
    pub create_ata: bool,
    /// Memo (UTF-8, 1 to 566 bytes) written by a Memo program instruction
    /// right after this leg's transfer. Splits only: the primary leg's memo
    /// is the transaction's `memo`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub memo: Option<String>,
}

/// A Solana payment the daemon builds as a v0 transaction and signs as the
/// transfer authority: a primary transfer plus up to 8 splits, all in one
/// asset, paid for (fees and created token accounts) by `fee_payer`.
///
/// `fee_payer` may be someone other than the agent (a merchant's fee payer).
/// The daemon then signs only the agent's slot and returns a partially signed
/// transaction whose fee-payer signature is all zero; the fee payer adds its
/// signature before broadcasting.
///
/// Instruction order (that of the MPP `solana` charge reference SDK):
/// `SetComputeUnitPrice` (when set), `SetComputeUnitLimit` (when set), the
/// primary transfer, the `memo` (when set), then for each split in order: its
/// `CreateIdempotent` (when `create_ata`), its transfer, its memo (when set).
/// SOL transfers are System `Transfer`s; SPL transfers are `TransferChecked`
/// from the agent's associated token account.
///
/// Policies see one payment: the sum of all legs, in `asset`, to the primary
/// recipient, on the Solana policy network. Recipient scopes must cover every
/// leg's recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SolanaPaymentTransaction {
    /// Internal Solana network id (`SOLANA_*_CHAIN_ID`).
    pub chain_id: u64,
    /// Recent blockhash as base58.
    pub recent_blockhash: String,
    /// Fee payer pubkey: the agent's Solana address, or a foreign fee payer
    /// whose signature slot the daemon leaves empty.
    pub fee_payer: SolanaAddress,
    /// Asset every leg transfers.
    pub asset: SolanaPaymentAsset,
    /// Transfers: the first is the primary payment, the rest are splits.
    /// 1 to 9 legs.
    pub transfers: Vec<SolanaPaymentLeg>,
    /// Memo (UTF-8, 1 to 566 bytes) written right after the primary transfer,
    /// for example the challenge's `externalId`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub memo: Option<String>,
    /// Optional compute unit limit, 1 to 200000.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub compute_unit_limit: Option<u32>,
    /// Optional compute unit price in micro-lamports, greater than zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub compute_unit_price_micro_lamports: Option<u64>,
}

impl SolanaPaymentTransaction {
    pub fn validate(&self) -> Result<(), DomainError> {
        if !is_solana_chain_id(self.chain_id) {
            return Err(DomainError::InvalidChainId);
        }
        decode_base58_32(&self.recent_blockhash)?;
        let _ = self.fee_payer.to_bytes()?;
        let is_spl = match &self.asset {
            SolanaPaymentAsset::NativeSol => false,
            SolanaPaymentAsset::SplToken { mint, .. } => {
                let _ = mint.to_bytes()?;
                true
            }
        };
        if self.transfers.is_empty() {
            return Err(DomainError::InvalidSolanaPaymentTransaction(
                "at least one transfer is required",
            ));
        }
        if self.transfers.len() > SOLANA_PAYMENT_MAX_LEGS {
            return Err(DomainError::InvalidSolanaPaymentTransaction(
                "at most 9 transfers (the primary payment and 8 splits) are allowed",
            ));
        }
        let mut total = 0u128;
        for (index, leg) in self.transfers.iter().enumerate() {
            let _ = leg.recipient_owner.to_bytes()?;
            validate_solana_amount(leg.amount_wei)?;
            total = total
                .checked_add(leg.amount_wei)
                .ok_or(DomainError::AmountOutOfRange)?;
            if leg.create_ata && !is_spl {
                return Err(DomainError::InvalidSolanaPaymentTransaction(
                    "create_ata is only valid for SPL token payments",
                ));
            }
            if index == 0 && leg.create_ata {
                return Err(DomainError::InvalidSolanaPaymentTransaction(
                    "the primary recipient's token account is never created",
                ));
            }
            if index == 0 && leg.memo.is_some() {
                return Err(DomainError::InvalidSolanaPaymentTransaction(
                    "the primary transfer's memo is the transaction memo",
                ));
            }
            validate_memo(leg.memo.as_deref())?;
        }
        if total > u128::from(u64::MAX) {
            return Err(DomainError::AmountOutOfRange);
        }
        validate_memo(self.memo.as_deref())?;
        if self
            .compute_unit_limit
            .is_some_and(|limit| limit > SOLANA_PAYMENT_MAX_COMPUTE_UNIT_LIMIT)
        {
            return Err(DomainError::InvalidSolanaComputeBudget);
        }
        validate_solana_compute_budget(
            self.compute_unit_limit,
            self.compute_unit_price_micro_lamports,
        )
    }

    /// Sum of all leg amounts: what spending policies check and record.
    /// Saturates instead of overflowing; [`Self::validate`] rejects totals
    /// above `u64::MAX`.
    #[must_use]
    pub fn total_amount_wei(&self) -> u128 {
        self.transfers
            .iter()
            .fold(0u128, |total, leg| total.saturating_add(leg.amount_wei))
    }

    /// Policy asset of the payment.
    #[must_use]
    pub fn policy_asset(&self) -> AssetId {
        match &self.asset {
            SolanaPaymentAsset::NativeSol => AssetId::NativeSol,
            SolanaPaymentAsset::SplToken { mint, .. } => AssetId::SplToken(mint.clone()),
        }
    }

    /// The primary recipient (first leg). Falls back to the fee payer for a
    /// payment without legs, which [`Self::validate`] rejects.
    #[must_use]
    pub fn primary_recipient(&self) -> RecipientId {
        let owner = self
            .transfers
            .first()
            .map_or(&self.fee_payer, |leg| &leg.recipient_owner);
        RecipientId::Solana(owner.clone())
    }

    /// Every leg's recipient, primary first, in leg order.
    #[must_use]
    pub fn recipients(&self) -> Vec<RecipientId> {
        self.transfers
            .iter()
            .map(|leg| RecipientId::Solana(leg.recipient_owner.clone()))
            .collect()
    }
}

fn validate_memo(memo: Option<&str>) -> Result<(), DomainError> {
    match memo {
        Some("") => Err(DomainError::InvalidSolanaPaymentTransaction(
            "memo must not be empty (omit it instead)",
        )),
        Some(memo) if memo.len() > SOLANA_PAYMENT_MAX_MEMO_BYTES => Err(
            DomainError::InvalidSolanaPaymentTransaction("memo must be at most 566 UTF-8 bytes"),
        ),
        _ => Ok(()),
    }
}
