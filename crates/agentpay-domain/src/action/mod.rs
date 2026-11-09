//! Actions an agent can ask the daemon to authorize and sign.

mod eip712;
mod encoding;
mod evm;
mod permit2;
mod solana;
mod solana_payment;
mod tempo;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use ts_rs::TS;

pub use eip712::Eip712TypedData;
pub use evm::{
    action_from_erc20_calldata, parse_erc20_call, BroadcastTx, Eip3009Transfer, Erc20Call,
};
pub use permit2::{
    Permit2Permission, Permit2Witness, Permit2WitnessTransfer, PERMIT2_ADDRESS,
    PERMIT2_MAX_DEADLINE_SECS, PERMIT2_MAX_ENTRIES, PERMIT2_MAX_EXTERNAL_ID_BYTES,
};
pub use solana::{
    SolanaNonceAccountCreate, SolanaSolTransfer, SolanaSplTransfer, SolanaTokenProgram,
};
pub use solana_payment::{SolanaPaymentAsset, SolanaPaymentLeg, SolanaPaymentTransaction};
pub use tempo::{
    TempoSessionV2CloseAuthorization, TempoSessionV2OpenTransaction,
    TempoSessionV2TopUpTransaction, TempoSessionV2Voucher, TempoTxParams,
};

use crate::constants::canonical_policy_chain_id;
use crate::schema::DecimalU128;
use crate::u128_as_decimal_string;
use crate::{AssetId, DomainError, EvmAddress, RecipientId};
use encoding::zero_evm_address;
use evm::{parse_broadcast_policy_call, BroadcastPolicyProjection};

/// Actions an agent can request the daemon to sign.
///
/// JSON: an object whose `kind` field names the variant and whose other fields
/// are the variant's fields, for example
/// `{"kind": "Transfer", "chain_id": 56, "token": "0x...", "to": "0x...", "amount_wei": "1000000"}`.
/// Amounts are decimal strings in the asset's base units; chain ids are JSON
/// numbers (EVM chain ids, or the internal Solana ids from `SOLANA_*_CHAIN_ID`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "kind")]
pub enum AgentAction {
    /// ERC-20 approve.
    Approve {
        /// EVM network chain ID.
        chain_id: u64,
        /// Token contract address.
        token: EvmAddress,
        /// Spender address.
        spender: EvmAddress,
        /// Approved amount in wei.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        amount_wei: u128,
    },
    /// ERC-20 transfer.
    Transfer {
        /// EVM network chain ID.
        chain_id: u64,
        /// Token contract address.
        token: EvmAddress,
        /// Recipient address.
        to: EvmAddress,
        /// Transfer amount in wei.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        amount_wei: u128,
    },
    /// Native ETH transfer.
    TransferNative {
        /// EVM network chain ID.
        chain_id: u64,
        /// Recipient address.
        to: EvmAddress,
        /// Transfer amount in wei.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        amount_wei: u128,
    },
    /// EIP-3009 `transferWithAuthorization`.
    Eip3009TransferWithAuthorization {
        /// Typed authorization payload.
        authorization: Eip3009Transfer,
    },
    /// EIP-3009 `receiveWithAuthorization`.
    Eip3009ReceiveWithAuthorization {
        /// Typed authorization payload.
        authorization: Eip3009Transfer,
    },
    /// Tempo sessions v2 (TIP-1034 reserve) open transaction digest.
    TempoSessionV2OpenTransaction {
        /// Typed digest payload.
        authorization: TempoSessionV2OpenTransaction,
    },
    /// Tempo sessions v2 (TIP-1034 reserve) top-up transaction digest.
    TempoSessionV2TopUpTransaction {
        /// Typed digest payload.
        authorization: TempoSessionV2TopUpTransaction,
    },
    /// Tempo sessions v2 (TIP-1034 reserve) voucher digest.
    TempoSessionV2Voucher {
        /// Typed digest payload.
        authorization: TempoSessionV2Voucher,
    },
    /// Tempo sessions v2 (TIP-1034 reserve) cooperative close authorization digest.
    TempoSessionV2CloseAuthorization {
        /// Typed digest payload.
        authorization: TempoSessionV2CloseAuthorization,
    },
    /// Arbitrary EIP-712 typed data payload.
    Eip712TypedData {
        /// Raw typed-data payload.
        typed_data: Eip712TypedData,
    },
    /// Raw transaction broadcast request.
    BroadcastTx {
        /// Unsigned tx fields to authorize and sign.
        tx: BroadcastTx,
    },
    /// Constrained native SOL transfer request.
    SolanaSolTransfer {
        /// Transfer to build and sign.
        transfer: SolanaSolTransfer,
    },
    /// Constrained Solana SPL token transfer request.
    SolanaSplTransfer {
        /// Transfer to build and sign.
        transfer: SolanaSplTransfer,
    },
    /// Internal durable nonce account creation request (wallet maintenance;
    /// bypasses spending policies, rent capped at twice the rent-exempt minimum).
    SolanaNonceAccountCreate {
        /// Nonce account to create.
        create: SolanaNonceAccountCreate,
    },
    /// Solana payment transaction (v0) with optional splits, memos, and a
    /// foreign fee payer, as the MPP `solana` charge intent needs. New in API
    /// 1.1.0.
    ///
    /// Policies check and record the sum of all legs; every leg's recipient
    /// must be covered by an applicable policy.
    SolanaPaymentTransaction {
        /// Payment to build and sign.
        payment: SolanaPaymentTransaction,
    },
    /// Permit2 `SignatureTransfer` permit with an MPP payment witness (the
    /// MPP `evm`/`arbitrum` `permit2` credential), for the canonical Permit2
    /// deployment. New in API 1.1.0.
    ///
    /// Policies check and record the sum of the entries, with the spender
    /// (who redeems the permit and chooses where the tokens go) as the
    /// recipient.
    Permit2WitnessTransfer {
        /// Permit to sign.
        permit: Permit2WitnessTransfer,
    },
}

impl AgentAction {
    /// Returns action amount in wei: the amount policies check and spend
    /// events record. An approval of the canonical Permit2
    /// ([`Self::is_permit2_approval`]) moves nothing by itself, so its
    /// policy amount is 0.
    #[must_use]
    pub fn amount_wei(&self) -> u128 {
        if self.is_permit2_approval() {
            return 0;
        }
        match self {
            Self::Approve { amount_wei, .. }
            | Self::Transfer { amount_wei, .. }
            | Self::TransferNative { amount_wei, .. } => *amount_wei,
            Self::Eip3009TransferWithAuthorization { authorization }
            | Self::Eip3009ReceiveWithAuthorization { authorization } => authorization.amount_wei,
            Self::TempoSessionV2OpenTransaction { authorization } => authorization.deposit_wei,
            Self::TempoSessionV2TopUpTransaction { authorization } => {
                authorization.additional_deposit_wei
            }
            // Vouchers are evaluated statelessly on the full cumulative amount; see
            // `is_escrow_redistribution` for how window limits treat them.
            Self::TempoSessionV2Voucher { authorization } => authorization.cumulative_amount_wei,
            Self::TempoSessionV2CloseAuthorization { authorization } => {
                authorization.voucher.cumulative_amount_wei
            }
            Self::Eip712TypedData { .. } => 0,
            Self::BroadcastTx { tx } => self.broadcast_effective_amount_wei(tx),
            Self::SolanaSolTransfer { transfer } => transfer.amount_wei,
            Self::SolanaSplTransfer { transfer } => transfer.amount_wei,
            Self::SolanaNonceAccountCreate { create } => create.rent_lamports,
            Self::SolanaPaymentTransaction { payment } => payment.total_amount_wei(),
            Self::Permit2WitnessTransfer { permit } => permit.total_amount_wei(),
        }
    }

    /// Returns action chain id.
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        match self {
            Self::Approve { chain_id, .. }
            | Self::Transfer { chain_id, .. }
            | Self::TransferNative { chain_id, .. } => *chain_id,
            Self::Eip3009TransferWithAuthorization { authorization }
            | Self::Eip3009ReceiveWithAuthorization { authorization } => authorization.chain_id,
            Self::TempoSessionV2OpenTransaction { authorization } => authorization.chain_id,
            Self::TempoSessionV2TopUpTransaction { authorization } => authorization.chain_id,
            Self::TempoSessionV2Voucher { authorization } => authorization.chain_id,
            Self::TempoSessionV2CloseAuthorization { authorization } => {
                authorization.voucher.chain_id
            }
            Self::Eip712TypedData { typed_data } => typed_data.chain_id().unwrap_or_default(),
            Self::BroadcastTx { tx } => tx.chain_id,
            Self::SolanaSolTransfer { transfer } => canonical_policy_chain_id(transfer.chain_id),
            Self::SolanaSplTransfer { transfer } => canonical_policy_chain_id(transfer.chain_id),
            Self::SolanaNonceAccountCreate { create } => canonical_policy_chain_id(create.chain_id),
            Self::SolanaPaymentTransaction { payment } => {
                canonical_policy_chain_id(payment.chain_id)
            }
            Self::Permit2WitnessTransfer { permit } => permit.chain_id,
        }
    }

    /// Returns action asset id.
    #[must_use]
    pub fn asset(&self) -> AssetId {
        match self {
            Self::Approve { token, .. } | Self::Transfer { token, .. } => {
                AssetId::Erc20(token.clone())
            }
            Self::TransferNative { .. } => AssetId::NativeEth,
            Self::Eip3009TransferWithAuthorization { authorization }
            | Self::Eip3009ReceiveWithAuthorization { authorization } => {
                AssetId::Erc20(authorization.token.clone())
            }
            Self::TempoSessionV2OpenTransaction { authorization } => {
                AssetId::Erc20(authorization.token.clone())
            }
            Self::TempoSessionV2TopUpTransaction { authorization } => {
                AssetId::Erc20(authorization.token.clone())
            }
            Self::TempoSessionV2Voucher { authorization } => {
                AssetId::Erc20(authorization.token.clone())
            }
            Self::TempoSessionV2CloseAuthorization { authorization } => {
                AssetId::Erc20(authorization.voucher.token.clone())
            }
            Self::Eip712TypedData { .. } => AssetId::NativeEth,
            Self::BroadcastTx { tx } => self.broadcast_effective_asset(tx),
            Self::SolanaSolTransfer { .. } => AssetId::NativeSol,
            Self::SolanaSplTransfer { transfer } => AssetId::SplToken(transfer.mint.clone()),
            Self::SolanaNonceAccountCreate { .. } => AssetId::NativeSol,
            Self::SolanaPaymentTransaction { payment } => payment.policy_asset(),
            Self::Permit2WitnessTransfer { permit } => AssetId::Erc20(permit.token.clone()),
        }
    }

    /// Returns recipient/spender address used for policy scope matching.
    #[must_use]
    pub fn recipient(&self) -> RecipientId {
        match self {
            Self::Approve { spender, .. } => RecipientId::Evm(spender.clone()),
            Self::Transfer { to, .. } | Self::TransferNative { to, .. } => {
                RecipientId::Evm(to.clone())
            }
            Self::Eip3009TransferWithAuthorization { authorization }
            | Self::Eip3009ReceiveWithAuthorization { authorization } => {
                RecipientId::Evm(authorization.to.clone())
            }
            Self::TempoSessionV2OpenTransaction { authorization } => {
                RecipientId::Evm(authorization.recipient.clone())
            }
            Self::TempoSessionV2TopUpTransaction { authorization } => {
                RecipientId::Evm(authorization.recipient.clone())
            }
            Self::TempoSessionV2Voucher { authorization } => {
                RecipientId::Evm(authorization.recipient.clone())
            }
            Self::TempoSessionV2CloseAuthorization { authorization } => {
                RecipientId::Evm(authorization.voucher.recipient.clone())
            }
            Self::Eip712TypedData { typed_data } => RecipientId::Evm(
                typed_data
                    .verifying_contract()
                    .ok()
                    .flatten()
                    .unwrap_or_else(zero_evm_address),
            ),
            Self::BroadcastTx { tx } => self.broadcast_effective_recipient(tx),
            Self::SolanaSolTransfer { transfer } => RecipientId::Solana(transfer.to.clone()),
            Self::SolanaSplTransfer { transfer } => {
                RecipientId::Solana(transfer.recipient_owner.clone())
            }
            Self::SolanaNonceAccountCreate { create } => {
                RecipientId::Solana(create.nonce_account.clone())
            }
            Self::SolanaPaymentTransaction { payment } => payment.primary_recipient(),
            Self::Permit2WitnessTransfer { permit } => RecipientId::Evm(permit.spender.clone()),
        }
    }

    /// Returns every recipient the action pays, for policy recipient scopes.
    ///
    /// One entry (`recipient()`) for every action except
    /// `SolanaPaymentTransaction`, which lists each leg's recipient, primary
    /// first.
    #[must_use]
    pub fn recipients(&self) -> Vec<RecipientId> {
        match self {
            Self::SolanaPaymentTransaction { payment } => payment.recipients(),
            _ => vec![self.recipient()],
        }
    }

    /// Returns optional max gas spend in wei for actions that contain tx gas metadata.
    #[must_use]
    pub fn max_gas_spend_wei(&self) -> Option<u128> {
        match self {
            Self::BroadcastTx { tx } => tx.max_gas_spend_wei().ok(),
            _ => None,
        }
    }

    /// Returns optional transaction max-fee-per-gas in wei.
    #[must_use]
    pub fn max_fee_per_gas_wei(&self) -> Option<u128> {
        match self {
            Self::BroadcastTx { tx } => Some(tx.max_fee_per_gas_wei),
            _ => None,
        }
    }

    /// Returns optional transaction priority-fee-per-gas in wei.
    #[must_use]
    pub fn max_priority_fee_per_gas_wei(&self) -> Option<u128> {
        match self {
            Self::BroadcastTx { tx } => Some(tx.max_priority_fee_per_gas_wei),
            _ => None,
        }
    }

    /// Returns optional calldata length in bytes.
    #[must_use]
    pub fn calldata_len_bytes(&self) -> Option<usize> {
        match self {
            Self::BroadcastTx { tx } => tx.data_bytes().ok().map(|data| data.len()),
            _ => None,
        }
    }

    /// Returns the EIP-712 signing digest for typed-data actions.
    pub fn signing_hash(&self) -> Result<Option<[u8; 32]>, DomainError> {
        match self {
            Self::Eip3009TransferWithAuthorization { authorization } => {
                authorization.transfer_signing_hash().map(Some)
            }
            Self::Eip3009ReceiveWithAuthorization { authorization } => {
                authorization.receive_signing_hash().map(Some)
            }
            Self::TempoSessionV2OpenTransaction { authorization } => {
                authorization.signing_hash().map(Some)
            }
            Self::TempoSessionV2TopUpTransaction { authorization } => {
                authorization.signing_hash().map(Some)
            }
            Self::TempoSessionV2Voucher { authorization } => authorization.signing_hash().map(Some),
            Self::TempoSessionV2CloseAuthorization { authorization } => {
                authorization.signing_hash().map(Some)
            }
            Self::Eip712TypedData { typed_data } => typed_data.signing_hash().map(Some),
            Self::Permit2WitnessTransfer { permit } => permit.signing_hash().map(Some),
            Self::Approve { .. }
            | Self::Transfer { .. }
            | Self::TransferNative { .. }
            | Self::BroadcastTx { .. }
            | Self::SolanaSolTransfer { .. }
            | Self::SolanaSplTransfer { .. }
            | Self::SolanaNonceAccountCreate { .. }
            | Self::SolanaPaymentTransaction { .. } => Ok(None),
        }
    }

    /// Returns whether a successful signature appends a spend event to the
    /// rolling spend log that window policies sum over.
    #[must_use]
    pub fn records_spend_event(&self) -> bool {
        !matches!(
            self,
            Self::Eip712TypedData { .. } | Self::SolanaNonceAccountCreate { .. }
        ) && !self.is_escrow_redistribution()
    }

    /// Returns the channel payer for Tempo session actions. The daemon requires
    /// it to equal the signing wallet so a channel cannot be opened, topped up,
    /// or vouched for on behalf of another account.
    #[must_use]
    pub fn tempo_payer(&self) -> Option<&EvmAddress> {
        match self {
            Self::TempoSessionV2OpenTransaction { authorization } => Some(&authorization.payer),
            Self::TempoSessionV2TopUpTransaction { authorization } => Some(&authorization.payer),
            Self::TempoSessionV2Voucher { authorization } => Some(&authorization.payer),
            Self::TempoSessionV2CloseAuthorization { authorization } => {
                Some(&authorization.voucher.payer)
            }
            Self::Approve { .. }
            | Self::Transfer { .. }
            | Self::TransferNative { .. }
            | Self::Eip3009TransferWithAuthorization { .. }
            | Self::Eip3009ReceiveWithAuthorization { .. }
            | Self::Eip712TypedData { .. }
            | Self::BroadcastTx { .. }
            | Self::SolanaSolTransfer { .. }
            | Self::SolanaSplTransfer { .. }
            | Self::SolanaNonceAccountCreate { .. }
            | Self::SolanaPaymentTransaction { .. }
            | Self::Permit2WitnessTransfer { .. } => None,
        }
    }

    /// Returns whether the action only redistributes funds already locked in an
    /// escrow by an earlier policy-checked action.
    ///
    /// Tempo session vouchers authorize the payee to claim from a channel whose
    /// deposit was already charged against spending windows when the open or
    /// top-up transaction was signed. Vouchers therefore skip daily/weekly
    /// spending and tx-count windows and record no spend event, while per-tx
    /// caps and manual approval still evaluate the full cumulative amount.
    ///
    /// Policy evaluation itself is stateless. The daemon keeps a per-channel
    /// registry and only accepts vouchers (and top-ups) for channels it opened
    /// for the same agent key, with the cumulative voucher amount capped at the
    /// total that agent deposited into the channel. Close authorizations are
    /// bounded the same way.
    ///
    /// The match is exhaustive on purpose: a new variant must decide here
    /// whether it may bypass window limits.
    #[must_use]
    pub fn is_escrow_redistribution(&self) -> bool {
        match self {
            Self::TempoSessionV2Voucher { .. } | Self::TempoSessionV2CloseAuthorization { .. } => {
                true
            }
            Self::Approve { .. }
            | Self::Transfer { .. }
            | Self::TransferNative { .. }
            | Self::Eip3009TransferWithAuthorization { .. }
            | Self::Eip3009ReceiveWithAuthorization { .. }
            | Self::TempoSessionV2OpenTransaction { .. }
            | Self::TempoSessionV2TopUpTransaction { .. }
            | Self::Eip712TypedData { .. }
            | Self::BroadcastTx { .. }
            | Self::SolanaSolTransfer { .. }
            | Self::SolanaSplTransfer { .. }
            | Self::SolanaNonceAccountCreate { .. }
            | Self::SolanaPaymentTransaction { .. }
            | Self::Permit2WitnessTransfer { .. } => false,
        }
    }

    /// Returns whether the action is an ERC-20 `approve` (typed, or as
    /// broadcast calldata with no value) whose spender is the canonical
    /// Permit2 deployment ([`PERMIT2_ADDRESS`]).
    ///
    /// Such an approval moves nothing by itself: Permit2 only moves the
    /// tokens for a signed permit, and the daemon signs Permit2 permits only
    /// as policy-checked [`Self::Permit2WitnessTransfer`] actions (generic
    /// typed data bound to Permit2 is refused). So its policy amount is 0
    /// and policies' recipient scopes do not apply to it (Permit2 is not a
    /// payee); everything else does: a policy must cover its network and the
    /// token, and transaction-count, fee, gas, and manual-approval policies
    /// apply. It records a zero-amount spend event.
    #[must_use]
    pub fn is_permit2_approval(&self) -> bool {
        let is_permit2 = |spender: &EvmAddress| spender.as_str() == PERMIT2_ADDRESS;
        match self {
            Self::Approve { spender, .. } => is_permit2(spender),
            Self::BroadcastTx { tx } => {
                tx.value_wei == 0
                    && tx.data_bytes().ok().is_some_and(|data| {
                        matches!(
                            parse_erc20_call(&data),
                            Ok(Erc20Call::Approve { spender, .. }) if is_permit2(&spender)
                        )
                    })
            }
            _ => false,
        }
    }

    #[must_use]
    pub fn is_wallet_maintenance(&self) -> bool {
        matches!(self, Self::SolanaNonceAccountCreate { .. })
    }

    #[must_use]
    pub fn requires_eip712_policy(&self) -> bool {
        matches!(self, Self::Eip712TypedData { .. })
    }

    pub fn eip712_primary_type(&self) -> Result<Option<String>, DomainError> {
        match self {
            Self::Eip712TypedData { typed_data } => typed_data.primary_type().map(Some),
            _ => Ok(None),
        }
    }

    pub fn eip712_verifying_contract(&self) -> Result<Option<EvmAddress>, DomainError> {
        match self {
            Self::Eip712TypedData { typed_data } => typed_data.verifying_contract(),
            _ => Ok(None),
        }
    }

    /// Returns whether action has valid fundamental invariants.
    pub fn validate(&self) -> Result<(), DomainError> {
        self.validate_at(OffsetDateTime::now_utc())
    }

    /// Returns whether action is valid to sign at the supplied timestamp.
    pub fn validate_at(&self, now: OffsetDateTime) -> Result<(), DomainError> {
        match self {
            Self::Approve { amount_wei, .. }
            | Self::Transfer { amount_wei, .. }
            | Self::TransferNative { amount_wei, .. } => {
                if *amount_wei == 0 {
                    return Err(DomainError::InvalidAmount);
                }
                if self.chain_id() == 0 {
                    return Err(DomainError::InvalidChainId);
                }
                Ok(())
            }
            Self::BroadcastTx { tx } => tx.validate(),
            Self::Eip3009TransferWithAuthorization { authorization }
            | Self::Eip3009ReceiveWithAuthorization { authorization } => {
                authorization.validate_at(now)
            }
            Self::TempoSessionV2OpenTransaction { authorization } => authorization.validate(),
            Self::TempoSessionV2TopUpTransaction { authorization } => authorization.validate(),
            Self::TempoSessionV2Voucher { authorization } => authorization.validate(),
            Self::TempoSessionV2CloseAuthorization { authorization } => authorization.validate(),
            Self::Eip712TypedData { typed_data } => typed_data.validate(),
            Self::SolanaSolTransfer { transfer } => transfer.validate(),
            Self::SolanaSplTransfer { transfer } => transfer.validate(),
            Self::SolanaNonceAccountCreate { create } => create.validate(),
            Self::SolanaPaymentTransaction { payment } => payment.validate(),
            Self::Permit2WitnessTransfer { permit } => permit.validate_at(now),
        }
    }

    fn broadcast_effective_asset(&self, tx: &BroadcastTx) -> AssetId {
        if let Some(projection) = self.broadcast_policy_projection(tx) {
            return projection.asset;
        }
        AssetId::NativeEth
    }

    fn broadcast_effective_recipient(&self, tx: &BroadcastTx) -> RecipientId {
        if let Some(projection) = self.broadcast_policy_projection(tx) {
            return projection.recipient;
        }
        RecipientId::Evm(tx.to.clone())
    }

    fn broadcast_effective_amount_wei(&self, tx: &BroadcastTx) -> u128 {
        if let Some(projection) = self.broadcast_policy_projection(tx) {
            return projection.amount_wei;
        }
        tx.value_wei
    }

    fn broadcast_policy_projection(&self, tx: &BroadcastTx) -> Option<BroadcastPolicyProjection> {
        let data = tx.data_bytes().ok()?;
        parse_broadcast_policy_call(tx, &data).ok()
    }
}
