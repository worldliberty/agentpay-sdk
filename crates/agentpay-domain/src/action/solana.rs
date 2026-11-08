//! Constrained Solana transfers and durable nonce account maintenance.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use ts_rs::TS;

use crate::constants::{is_solana_chain_id, SOLANA_NONCE_ACCOUNT_MAX_RENT_LAMPORTS};
use crate::schema::DecimalU128;
use crate::u128_as_decimal_string;
use crate::{DomainError, SolanaAddress};

/// Supported Solana token program variants for constrained token transfers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum SolanaTokenProgram {
    /// Original SPL Token program.
    #[default]
    Token,
    /// Token-2022 program.
    Token2022,
}

impl std::fmt::Display for SolanaTokenProgram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token => f.write_str("token"),
            Self::Token2022 => f.write_str("token_2022"),
        }
    }
}

impl FromStr for SolanaTokenProgram {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "token" | "spl-token" | "spl_token" => Ok(Self::Token),
            "token_2022" | "token-2022" | "spl-token-2022" | "spl_token_2022" => {
                Ok(Self::Token2022)
            }
            _ => Err(DomainError::InvalidSolanaTokenProgram),
        }
    }
}

/// Constrained native SOL transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SolanaSolTransfer {
    /// Internal Solana network id.
    pub chain_id: u64,
    /// Recent blockhash as base58.
    ///
    /// When `durable_nonce_account` is set, this must be the durable nonce value
    /// currently stored in that nonce account.
    pub recent_blockhash: String,
    /// Durable nonce account to advance as the first transaction instruction.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub durable_nonce_account: Option<SolanaAddress>,
    /// Fee payer and signing authority pubkey.
    pub fee_payer: SolanaAddress,
    /// Recipient wallet pubkey.
    pub to: SolanaAddress,
    /// Transfer amount in lamports.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub amount_wei: u128,
    /// Optional compute unit limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub compute_unit_limit: Option<u32>,
    /// Optional compute unit price in micro-lamports.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub compute_unit_price_micro_lamports: Option<u64>,
}

impl SolanaSolTransfer {
    pub fn validate(&self) -> Result<(), DomainError> {
        if !is_solana_chain_id(self.chain_id) {
            return Err(DomainError::InvalidChainId);
        }
        validate_solana_amount(self.amount_wei)?;
        if let Some(nonce_account) = &self.durable_nonce_account {
            let _ = nonce_account.to_bytes()?;
        }
        let _ = self.fee_payer.to_bytes()?;
        let _ = self.to.to_bytes()?;
        decode_base58_32(&self.recent_blockhash)?;
        validate_solana_compute_budget(
            self.compute_unit_limit,
            self.compute_unit_price_micro_lamports,
        )
    }
}

/// Constrained Solana SPL token transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SolanaSplTransfer {
    /// Internal Solana network id.
    pub chain_id: u64,
    /// Recent blockhash as base58.
    ///
    /// When `durable_nonce_account` is set, this must be the durable nonce value
    /// currently stored in that nonce account.
    pub recent_blockhash: String,
    /// Durable nonce account to advance as the first transaction instruction.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub durable_nonce_account: Option<SolanaAddress>,
    /// Fee payer and signing authority pubkey.
    pub fee_payer: SolanaAddress,
    /// SPL mint pubkey under the original token program.
    pub mint: SolanaAddress,
    /// Recipient wallet owner pubkey.
    pub recipient_owner: SolanaAddress,
    /// Transfer amount in token base units.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub amount_wei: u128,
    /// Mint decimals enforced by `TransferChecked`.
    pub decimals: u8,
    /// Token program that owns the mint.
    #[serde(default)]
    pub token_program: SolanaTokenProgram,
    /// Optional expected transfer fee for Token-2022 fee mints.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(as = "Option<DecimalU128>")]
    pub transfer_fee_wei: Option<u128>,
    /// Optional compute unit limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub compute_unit_limit: Option<u32>,
    /// Optional compute unit price in micro-lamports.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub compute_unit_price_micro_lamports: Option<u64>,
}

impl SolanaSplTransfer {
    pub fn validate(&self) -> Result<(), DomainError> {
        if !is_solana_chain_id(self.chain_id) {
            return Err(DomainError::InvalidChainId);
        }
        validate_solana_amount(self.amount_wei)?;
        if let Some(nonce_account) = &self.durable_nonce_account {
            let _ = nonce_account.to_bytes()?;
        }
        let _ = self.fee_payer.to_bytes()?;
        let _ = self.mint.to_bytes()?;
        let _ = self.recipient_owner.to_bytes()?;
        decode_base58_32(&self.recent_blockhash)?;
        if let Some(fee) = self.transfer_fee_wei {
            if self.token_program != SolanaTokenProgram::Token2022 {
                return Err(DomainError::InvalidSolanaTokenProgram);
            }
            if fee > u128::from(u64::MAX) {
                return Err(DomainError::AmountOutOfRange);
            }
        }
        validate_solana_compute_budget(
            self.compute_unit_limit,
            self.compute_unit_price_micro_lamports,
        )
    }
}

/// Internal Solana durable nonce account creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SolanaNonceAccountCreate {
    /// Internal Solana network id.
    pub chain_id: u64,
    /// Recent blockhash as base58.
    pub recent_blockhash: String,
    /// Fee payer and nonce authority pubkey.
    pub fee_payer: SolanaAddress,
    /// Derived nonce account pubkey.
    pub nonce_account: SolanaAddress,
    /// Seed used with `fee_payer` and the system program to derive `nonce_account`.
    pub seed: String,
    /// Rent-exempt lamports to fund the nonce account.
    ///
    /// Nonce creation is wallet maintenance and bypasses spending policies, so
    /// this is capped at [`SOLANA_NONCE_ACCOUNT_MAX_RENT_LAMPORTS`] (twice the
    /// rent-exempt minimum for an 80-byte nonce account).
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub rent_lamports: u128,
}

impl SolanaNonceAccountCreate {
    pub fn validate(&self) -> Result<(), DomainError> {
        if !is_solana_chain_id(self.chain_id) {
            return Err(DomainError::InvalidChainId);
        }
        if self.rent_lamports == 0 {
            return Err(DomainError::InvalidAmount);
        }
        if self.rent_lamports > SOLANA_NONCE_ACCOUNT_MAX_RENT_LAMPORTS {
            return Err(DomainError::SolanaNonceRentTooHigh {
                max_lamports: SOLANA_NONCE_ACCOUNT_MAX_RENT_LAMPORTS,
            });
        }
        let seed = self.seed.as_bytes();
        if seed.is_empty() || seed.len() > 32 || !seed.is_ascii() {
            return Err(DomainError::InvalidSolanaNonceSeed);
        }
        let _ = self.fee_payer.to_bytes()?;
        let _ = self.nonce_account.to_bytes()?;
        decode_base58_32(&self.recent_blockhash)?;
        Ok(())
    }
}

/// Solana lamport and token amounts are `u64` on chain and must be non-zero.
pub(super) fn validate_solana_amount(amount: u128) -> Result<(), DomainError> {
    if amount == 0 {
        return Err(DomainError::InvalidAmount);
    }
    if amount > u128::from(u64::MAX) {
        return Err(DomainError::AmountOutOfRange);
    }
    Ok(())
}

pub(super) fn validate_solana_compute_budget(
    compute_unit_limit: Option<u32>,
    compute_unit_price_micro_lamports: Option<u64>,
) -> Result<(), DomainError> {
    if matches!(compute_unit_limit, Some(0)) || matches!(compute_unit_price_micro_lamports, Some(0))
    {
        return Err(DomainError::InvalidSolanaComputeBudget);
    }
    Ok(())
}

pub(super) fn decode_base58_32(value: &str) -> Result<[u8; 32], DomainError> {
    let decoded = bs58::decode(value.trim())
        .into_vec()
        .map_err(|_| DomainError::InvalidSolanaRecentBlockhash)?;
    <[u8; 32]>::try_from(decoded.as_slice()).map_err(|_| DomainError::InvalidSolanaRecentBlockhash)
}
