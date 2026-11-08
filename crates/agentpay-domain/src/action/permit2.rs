//! Permit2 `SignatureTransfer` permits with an MPP payment witness: the
//! `permit2` credential of the MPP `evm` (`draft-evm-charge-00`,
//! `@bnb-chain/mpp`) and `arbitrum` (`@arbitrum/mpp`) charge methods.
//!
//! The agent signs `PermitWitnessTransferFrom` (one entry) or
//! `PermitBatchWitnessTransferFrom` (a payment with splits: the primary
//! recipient first, then each split) for the canonical Permit2 deployment;
//! the merchant's `spender` redeems it. The signature binds the token, the
//! amounts, the spender, a single-use nonce, a deadline, and the witness
//! (which binds the MPP challenge), but not the recipients: whoever holds the
//! spender key chooses them. Policies therefore see the spender as the
//! recipient and the sum of the amounts as the spend.

use alloy_primitives::{Address, U256};
use alloy_sol_types::{Eip712Domain, SolStruct};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use ts_rs::TS;

use super::encoding::{decode_hex_32, evm_to_alloy_address};
use crate::schema::DecimalU128;
use crate::u128_as_decimal_string;
use crate::{DomainError, EvmAddress};

/// The canonical Permit2 deployment (the same address on every EVM chain).
pub const PERMIT2_ADDRESS: &str = "0x000000000022d473030f116ddee9f6b43ac78ba3";

/// Most entries in one permit: the primary payment and up to 10 splits.
pub const PERMIT2_MAX_ENTRIES: usize = 11;

/// Longest `externalId` a witness carries, in UTF-8 bytes.
pub const PERMIT2_MAX_EXTERNAL_ID_BYTES: usize = 256;

/// Furthest in the future a permit's deadline may be, in seconds.
pub const PERMIT2_MAX_DEADLINE_SECS: u64 = 3_600;

mod single_with_external_id {
    alloy_sol_types::sol! {
        struct TokenPermissions { address token; uint256 amount; }
        struct PaymentWitness { bytes32 challengeHash; string externalId; }
        struct PermitWitnessTransferFrom {
            TokenPermissions permitted;
            address spender;
            uint256 nonce;
            uint256 deadline;
            PaymentWitness witness;
        }
        struct PermitBatchWitnessTransferFrom {
            TokenPermissions[] permitted;
            address spender;
            uint256 nonce;
            uint256 deadline;
            PaymentWitness witness;
        }
    }
}

mod challenge_only {
    alloy_sol_types::sol! {
        struct TokenPermissions { address token; uint256 amount; }
        struct PaymentWitness { bytes32 challengeHash; }
        struct PermitWitnessTransferFrom {
            TokenPermissions permitted;
            address spender;
            uint256 nonce;
            uint256 deadline;
            PaymentWitness witness;
        }
        struct PermitBatchWitnessTransferFrom {
            TokenPermissions[] permitted;
            address spender;
            uint256 nonce;
            uint256 deadline;
            PaymentWitness witness;
        }
    }
}

/// The MPP payment witness a Permit2 permit carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Permit2Witness {
    /// `PaymentWitness(bytes32 challengeHash,string externalId)`, as
    /// `draft-evm-charge-00` and `@bnb-chain/mpp` define it.
    ChallengeExternalId {
        /// `0x` + 64 hex.
        challenge_hash: String,
        /// The charge's `externalId`, or `""` when it has none.
        external_id: String,
    },
    /// `PaymentWitness(bytes32 challengeHash)`, as `@arbitrum/mpp` defines it.
    Challenge {
        /// `0x` + 64 hex.
        challenge_hash: String,
    },
}

/// One entry of a permit: an amount of the permit's token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct Permit2Permission {
    /// Base units.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub amount_wei: u128,
}

/// A Permit2 `SignatureTransfer` permit with an MPP payment witness, for the
/// canonical Permit2 deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct Permit2WitnessTransfer {
    /// EVM network chain id.
    pub chain_id: u64,
    /// ERC-20 token every entry moves.
    pub token: EvmAddress,
    /// One entry: `PermitWitnessTransferFrom`; more (at most
    /// [`PERMIT2_MAX_ENTRIES`]): `PermitBatchWitnessTransferFrom`.
    pub permitted: Vec<Permit2Permission>,
    /// The address allowed to redeem the permit (Permit2 checks it against
    /// `msg.sender`).
    pub spender: EvmAddress,
    /// Permit2 unordered nonce, a decimal `uint256`.
    pub nonce: String,
    /// Unix seconds after which the permit cannot be redeemed.
    pub deadline: u64,
    /// The payment witness.
    pub witness: Permit2Witness,
}

impl Permit2WitnessTransfer {
    /// Sum of the entries' amounts, or `None` if it overflows.
    #[must_use]
    pub fn checked_total(&self) -> Option<u128> {
        self.permitted
            .iter()
            .try_fold(0u128, |sum, entry| sum.checked_add(entry.amount_wei))
    }

    /// Sum of the entries' amounts (saturating; [`validate`](Self::validate)
    /// refuses an overflow).
    #[must_use]
    pub fn total_amount_wei(&self) -> u128 {
        self.checked_total().unwrap_or(u128::MAX)
    }

    fn invalid(reason: &'static str) -> DomainError {
        DomainError::InvalidPermit2Transfer(reason)
    }

    fn nonce_u256(&self) -> Result<U256, DomainError> {
        let digits = self.nonce.as_str();
        if digits.is_empty()
            || (digits.len() > 1 && digits.starts_with('0'))
            || !digits.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Self::invalid("nonce must be a decimal uint256"));
        }
        U256::from_str_radix(digits, 10)
            .map_err(|_| Self::invalid("nonce must be a decimal uint256"))
    }

    fn challenge_hash(&self) -> Result<[u8; 32], DomainError> {
        let hash = match &self.witness {
            Permit2Witness::ChallengeExternalId { challenge_hash, .. }
            | Permit2Witness::Challenge { challenge_hash } => challenge_hash,
        };
        decode_hex_32(hash, "permit2 challenge_hash")
    }

    /// Validates the permit's structure (no clock).
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.chain_id == 0 {
            return Err(DomainError::InvalidChainId);
        }
        if self.permitted.is_empty() || self.permitted.len() > PERMIT2_MAX_ENTRIES {
            return Err(Self::invalid("a permit has 1 to 11 entries"));
        }
        if self.permitted.iter().any(|entry| entry.amount_wei == 0) {
            return Err(DomainError::InvalidAmount);
        }
        if self.checked_total().is_none() {
            return Err(Self::invalid("the entries' total overflows"));
        }
        let _ = evm_to_alloy_address(&self.token)?;
        if evm_to_alloy_address(&self.spender)? == Address::ZERO {
            return Err(Self::invalid("spender must not be the zero address"));
        }
        self.nonce_u256()?;
        self.challenge_hash()?;
        if let Permit2Witness::ChallengeExternalId { external_id, .. } = &self.witness {
            if external_id.len() > PERMIT2_MAX_EXTERNAL_ID_BYTES {
                return Err(Self::invalid("external_id must be at most 256 bytes"));
            }
        }
        Ok(())
    }

    /// Validates the permit for signing at `now`: the deadline is in the
    /// future and at most [`PERMIT2_MAX_DEADLINE_SECS`] away.
    pub fn validate_at(&self, now: OffsetDateTime) -> Result<(), DomainError> {
        self.validate()?;
        let now = u64::try_from(now.unix_timestamp())
            .map_err(|_| Self::invalid("the clock is before 1970"))?;
        if self.deadline <= now {
            return Err(Self::invalid("the deadline has passed"));
        }
        if self.deadline > now.saturating_add(PERMIT2_MAX_DEADLINE_SECS) {
            return Err(Self::invalid("the deadline is more than an hour away"));
        }
        Ok(())
    }

    /// The EIP-712 domain: `Permit2` on `chain_id` at [`PERMIT2_ADDRESS`].
    pub fn eip712_domain(&self) -> Result<Eip712Domain, DomainError> {
        let permit2 = evm_to_alloy_address(&PERMIT2_ADDRESS.parse()?)?;
        Ok(Eip712Domain::new(
            Some("Permit2".into()),
            None,
            Some(U256::from(self.chain_id)),
            Some(permit2),
            None,
        ))
    }

    /// The EIP-712 signing digest.
    pub fn signing_hash(&self) -> Result<[u8; 32], DomainError> {
        self.validate()?;
        let domain = self.eip712_domain()?;
        let token = evm_to_alloy_address(&self.token)?;
        let spender = evm_to_alloy_address(&self.spender)?;
        let nonce = self.nonce_u256()?;
        let deadline = U256::from(self.deadline);
        let challenge_hash = self.challenge_hash()?.into();
        let amounts: Vec<U256> = self
            .permitted
            .iter()
            .map(|entry| U256::from(entry.amount_wei))
            .collect();
        let batch = amounts.len() > 1;
        let digest = match &self.witness {
            Permit2Witness::ChallengeExternalId { external_id, .. } => {
                use single_with_external_id as t;
                let witness = t::PaymentWitness {
                    challengeHash: challenge_hash,
                    externalId: external_id.clone(),
                };
                let entry = |amount| t::TokenPermissions { token, amount };
                if batch {
                    t::PermitBatchWitnessTransferFrom {
                        permitted: amounts.into_iter().map(entry).collect(),
                        spender,
                        nonce,
                        deadline,
                        witness,
                    }
                    .eip712_signing_hash(&domain)
                } else {
                    t::PermitWitnessTransferFrom {
                        permitted: entry(amounts[0]),
                        spender,
                        nonce,
                        deadline,
                        witness,
                    }
                    .eip712_signing_hash(&domain)
                }
            }
            Permit2Witness::Challenge { .. } => {
                use challenge_only as t;
                let witness = t::PaymentWitness {
                    challengeHash: challenge_hash,
                };
                let entry = |amount| t::TokenPermissions { token, amount };
                if batch {
                    t::PermitBatchWitnessTransferFrom {
                        permitted: amounts.into_iter().map(entry).collect(),
                        spender,
                        nonce,
                        deadline,
                        witness,
                    }
                    .eip712_signing_hash(&domain)
                } else {
                    t::PermitWitnessTransferFrom {
                        permitted: entry(amounts[0]),
                        spender,
                        nonce,
                        deadline,
                        witness,
                    }
                    .eip712_signing_hash(&domain)
                }
            }
        };
        Ok(digest.0)
    }
}
