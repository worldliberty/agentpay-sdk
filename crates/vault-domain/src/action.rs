use alloy_primitives::{aliases::U48, Address, U160, U256};
use alloy_sol_types::{eip712_domain, sol, Eip712Domain, SolCall, SolStruct};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::u128_as_decimal_string;
use crate::{AssetId, DomainError, EvmAddress};

sol! {
    function approve(address spender, uint256 value);
    function transfer(address to, uint256 value);
    function permit(address owner, PermitSingle permitSingle, bytes signature);
    function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes signature);
    function receiveWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes signature);

    struct PermitDetails {
        address token;
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }

    struct PermitSingle {
        PermitDetails details;
        address spender;
        uint256 sigDeadline;
    }

    struct TransferWithAuthorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }

    struct ReceiveWithAuthorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }
}

/// Decoded ERC-20 method call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Erc20Call {
    /// `approve(spender, value)`
    Approve {
        /// Spender address.
        spender: EvmAddress,
        /// Approved amount in wei.
        amount_wei: u128,
    },
    /// `transfer(to, value)`
    Transfer {
        /// Recipient address.
        to: EvmAddress,
        /// Transfer amount in wei.
        amount_wei: u128,
    },
}

/// Permit2 `PermitSingle` authorization signed for the Permit2 contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permit2Permit {
    /// EVM network chain ID.
    pub chain_id: u64,
    /// Permit2 verifying contract address.
    pub permit2_contract: EvmAddress,
    /// ERC-20 token contract address.
    pub token: EvmAddress,
    /// Authorized spender.
    pub spender: EvmAddress,
    /// Approved amount in wei.
    #[serde(with = "u128_as_decimal_string")]
    pub amount_wei: u128,
    /// Permit expiration timestamp.
    pub expiration: u64,
    /// Permit nonce.
    pub nonce: u64,
    /// Signature deadline timestamp.
    pub sig_deadline: u64,
}

impl Permit2Permit {
    /// Validates structural constraints, address encoding, and Permit2 field widths.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.chain_id == 0 {
            return Err(DomainError::InvalidChainId);
        }
        if self.amount_wei == 0 {
            return Err(DomainError::InvalidAmount);
        }
        validate_permit2_u48("expiration", self.expiration)?;
        validate_permit2_u48("nonce", self.nonce)?;
        if self.sig_deadline == 0 {
            return Err(DomainError::InvalidSignatureDeadline);
        }
        let _ = evm_to_alloy_address(&self.permit2_contract)?;
        let _ = evm_to_alloy_address(&self.token)?;
        let _ = evm_to_alloy_address(&self.spender)?;
        Ok(())
    }

    /// Validates the permit against the supplied timestamp for signing.
    pub fn validate_at(&self, now: OffsetDateTime) -> Result<(), DomainError> {
        let now = u64::try_from(now.unix_timestamp())
            .map_err(|_| DomainError::InvalidPermitExpiration)?;
        self.validate()?;
        if self.expiration <= now {
            return Err(DomainError::InvalidPermitExpiration);
        }
        if self.sig_deadline <= now {
            return Err(DomainError::InvalidSignatureDeadline);
        }
        Ok(())
    }

    /// Returns the Permit2 EIP-712 domain.
    #[must_use]
    pub fn eip712_domain(&self) -> Result<Eip712Domain, DomainError> {
        Ok(eip712_domain! {
            name: "Permit2",
            chain_id: self.chain_id,
            verifying_contract: evm_to_alloy_address(&self.permit2_contract)?,
        })
    }

    /// Returns the EIP-712 signing digest for this authorization.
    pub fn signing_hash(&self) -> Result<[u8; 32], DomainError> {
        self.validate()?;
        let details = PermitDetails {
            token: evm_to_alloy_address(&self.token)?,
            amount: u128_to_u160(self.amount_wei),
            expiration: u64_to_u48(self.expiration)?,
            nonce: u64_to_u48(self.nonce)?,
        };
        let permit = PermitSingle {
            details,
            spender: evm_to_alloy_address(&self.spender)?,
            sigDeadline: U256::from(self.sig_deadline),
        };
        Ok(permit.eip712_signing_hash(&self.eip712_domain()?).0)
    }
}

/// EIP-3009 transfer authorization signed for a token contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Eip3009Transfer {
    /// EVM network chain ID.
    pub chain_id: u64,
    /// Token contract address used as EIP-712 verifying contract.
    pub token: EvmAddress,
    /// Token name used by the token's EIP-712 domain separator.
    pub token_name: String,
    /// Token version used by the token's EIP-712 domain separator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_version: Option<String>,
    /// Authorization signer / owner.
    pub from: EvmAddress,
    /// Authorized recipient.
    pub to: EvmAddress,
    /// Transfer amount in wei.
    #[serde(with = "u128_as_decimal_string")]
    pub amount_wei: u128,
    /// Authorization validity lower bound.
    pub valid_after: u64,
    /// Authorization validity upper bound.
    pub valid_before: u64,
    /// Authorization nonce as `0x`-prefixed 32-byte hex.
    pub nonce_hex: String,
}

impl Eip3009Transfer {
    /// Validates structural constraints and alloy-compatible address encoding.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.chain_id == 0 {
            return Err(DomainError::InvalidChainId);
        }
        if self.amount_wei == 0 {
            return Err(DomainError::InvalidAmount);
        }
        if self.token_name.trim().is_empty() {
            return Err(DomainError::InvalidTypedDataDomain(
                "token_name must not be empty".to_string(),
            ));
        }
        if self.valid_before <= self.valid_after {
            return Err(DomainError::InvalidAuthorizationWindow);
        }
        let _ = evm_to_alloy_address(&self.token)?;
        let _ = evm_to_alloy_address(&self.from)?;
        let _ = evm_to_alloy_address(&self.to)?;
        let _ = self.nonce_bytes32()?;
        Ok(())
    }

    /// Validates the authorization against the supplied timestamp for signing.
    pub fn validate_at(&self, now: OffsetDateTime) -> Result<(), DomainError> {
        let now = u64::try_from(now.unix_timestamp())
            .map_err(|_| DomainError::InvalidAuthorizationWindow)?;
        self.validate()?;
        if self.valid_before <= now {
            return Err(DomainError::InvalidAuthorizationWindow);
        }
        Ok(())
    }

    /// Parses the nonce as a strict 32-byte value.
    pub fn nonce_bytes32(&self) -> Result<[u8; 32], DomainError> {
        decode_hex_32(&self.nonce_hex, "eip3009 nonce")
    }

    /// Returns the EIP-712 domain for this token authorization.
    #[must_use]
    pub fn eip712_domain(&self) -> Result<Eip712Domain, DomainError> {
        Ok(Eip712Domain::new(
            Some(self.token_name.clone().into()),
            self.token_version
                .as_ref()
                .filter(|value| !value.is_empty())
                .cloned()
                .map(Into::into),
            Some(U256::from(self.chain_id)),
            Some(evm_to_alloy_address(&self.token)?),
            None,
        ))
    }

    /// Returns the EIP-712 signing digest for `transferWithAuthorization`.
    pub fn transfer_signing_hash(&self) -> Result<[u8; 32], DomainError> {
        self.validate()?;
        let auth = TransferWithAuthorization {
            from: evm_to_alloy_address(&self.from)?,
            to: evm_to_alloy_address(&self.to)?,
            value: U256::from(self.amount_wei),
            validAfter: U256::from(self.valid_after),
            validBefore: U256::from(self.valid_before),
            nonce: self.nonce_bytes32().map(Into::into)?,
        };
        Ok(auth.eip712_signing_hash(&self.eip712_domain()?).0)
    }

    /// Returns the EIP-712 signing digest for `receiveWithAuthorization`.
    pub fn receive_signing_hash(&self) -> Result<[u8; 32], DomainError> {
        self.validate()?;
        let auth = ReceiveWithAuthorization {
            from: evm_to_alloy_address(&self.from)?,
            to: evm_to_alloy_address(&self.to)?,
            value: U256::from(self.amount_wei),
            validAfter: U256::from(self.valid_after),
            validBefore: U256::from(self.valid_before),
            nonce: self.nonce_bytes32().map(Into::into)?,
        };
        Ok(auth.eip712_signing_hash(&self.eip712_domain()?).0)
    }
}

/// Tempo session open-transaction digest signed for a payment-channel request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TempoSessionOpenTransaction {
    /// EVM network chain ID.
    pub chain_id: u64,
    /// ERC-20 token contract address funding the channel.
    pub token: EvmAddress,
    /// Channel payee / merchant recipient.
    pub recipient: EvmAddress,
    /// Total channel deposit in token base units.
    #[serde(with = "u128_as_decimal_string")]
    pub deposit_wei: u128,
    /// Initial authorized spend included in the opening voucher.
    #[serde(with = "u128_as_decimal_string")]
    pub initial_amount_wei: u128,
    /// Precomputed Tempo transaction signing hash as `0x`-prefixed 32-byte hex.
    pub signing_hash_hex: String,
}

impl TempoSessionOpenTransaction {
    /// Validates structural constraints and address encoding.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.chain_id == 0 {
            return Err(DomainError::InvalidChainId);
        }
        if self.deposit_wei == 0 || self.initial_amount_wei == 0 {
            return Err(DomainError::InvalidAmount);
        }
        if self.initial_amount_wei > self.deposit_wei {
            return Err(DomainError::InvalidAmount);
        }
        let _ = evm_to_alloy_address(&self.token)?;
        let _ = evm_to_alloy_address(&self.recipient)?;
        let _ = self.signing_hash()?;
        Ok(())
    }

    /// Returns the precomputed signing digest bytes.
    pub fn signing_hash(&self) -> Result<[u8; 32], DomainError> {
        decode_hex_32(&self.signing_hash_hex, "tempo session open signing hash")
    }
}

/// Tempo session top-up transaction digest signed for an existing payment channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TempoSessionTopUpTransaction {
    /// EVM network chain ID.
    pub chain_id: u64,
    /// ERC-20 token contract address funding the channel.
    pub token: EvmAddress,
    /// Channel payee / merchant recipient.
    pub recipient: EvmAddress,
    /// Channel id as `0x`-prefixed 32-byte hex.
    pub channel_id_hex: String,
    /// Incremental additional deposit in token base units.
    #[serde(with = "u128_as_decimal_string")]
    pub additional_deposit_wei: u128,
    /// Precomputed Tempo transaction signing hash as `0x`-prefixed 32-byte hex.
    pub signing_hash_hex: String,
}

impl TempoSessionTopUpTransaction {
    /// Validates structural constraints and address encoding.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.chain_id == 0 {
            return Err(DomainError::InvalidChainId);
        }
        if self.additional_deposit_wei == 0 {
            return Err(DomainError::InvalidAmount);
        }
        let _ = evm_to_alloy_address(&self.token)?;
        let _ = evm_to_alloy_address(&self.recipient)?;
        let _ = self.channel_id_bytes32()?;
        let _ = self.signing_hash()?;
        Ok(())
    }

    /// Parses the channel id as a strict 32-byte value.
    pub fn channel_id_bytes32(&self) -> Result<[u8; 32], DomainError> {
        decode_hex_32(&self.channel_id_hex, "tempo session channel id")
    }

    /// Returns the precomputed signing digest bytes.
    pub fn signing_hash(&self) -> Result<[u8; 32], DomainError> {
        decode_hex_32(&self.signing_hash_hex, "tempo session topUp signing hash")
    }
}

/// Tempo session voucher digest signed for an MPP channel credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TempoSessionVoucher {
    /// EVM network chain ID.
    pub chain_id: u64,
    /// Escrow contract address used as the EIP-712 verifying contract.
    pub escrow_contract: EvmAddress,
    /// ERC-20 token contract address used by the channel.
    pub token: EvmAddress,
    /// Channel payee / merchant recipient.
    pub recipient: EvmAddress,
    /// Channel id as `0x`-prefixed 32-byte hex.
    pub channel_id_hex: String,
    /// Incremental amount being newly authorized for policy evaluation.
    #[serde(with = "u128_as_decimal_string")]
    pub amount_wei: u128,
    /// Full cumulative voucher amount being signed.
    #[serde(with = "u128_as_decimal_string")]
    pub cumulative_amount_wei: u128,
    /// Precomputed voucher signing hash as `0x`-prefixed 32-byte hex.
    pub signing_hash_hex: String,
}

impl TempoSessionVoucher {
    /// Validates structural constraints and address encoding.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.chain_id == 0 {
            return Err(DomainError::InvalidChainId);
        }
        if self.amount_wei == 0 || self.cumulative_amount_wei == 0 {
            return Err(DomainError::InvalidAmount);
        }
        if self.amount_wei > self.cumulative_amount_wei {
            return Err(DomainError::InvalidAmount);
        }
        let _ = evm_to_alloy_address(&self.escrow_contract)?;
        let _ = evm_to_alloy_address(&self.token)?;
        let _ = evm_to_alloy_address(&self.recipient)?;
        let _ = self.channel_id_bytes32()?;
        let _ = self.signing_hash()?;
        Ok(())
    }

    /// Parses the channel id as a strict 32-byte value.
    pub fn channel_id_bytes32(&self) -> Result<[u8; 32], DomainError> {
        decode_hex_32(&self.channel_id_hex, "tempo session channel id")
    }

    /// Returns the precomputed signing digest bytes.
    pub fn signing_hash(&self) -> Result<[u8; 32], DomainError> {
        decode_hex_32(&self.signing_hash_hex, "tempo session voucher signing hash")
    }
}

/// Agent-submitted broadcast transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BroadcastTx {
    /// EVM network chain id.
    pub chain_id: u64,
    /// Sender account nonce.
    pub nonce: u64,
    /// Destination address.
    pub to: EvmAddress,
    /// Native value in wei.
    #[serde(with = "u128_as_decimal_string")]
    pub value_wei: u128,
    /// Transaction calldata as hex (`0x`-prefixed or plain).
    pub data_hex: String,
    /// Gas limit.
    pub gas_limit: u64,
    /// Max fee per gas in wei.
    #[serde(with = "u128_as_decimal_string")]
    pub max_fee_per_gas_wei: u128,
    /// Max priority fee per gas in wei.
    #[serde(with = "u128_as_decimal_string")]
    pub max_priority_fee_per_gas_wei: u128,
    /// Transaction type id (`0x02` for EIP-1559, `0x04` for EIP-7702).
    pub tx_type: u8,
    /// Whether tx includes delegation authorization material.
    pub delegation_enabled: bool,
}

impl BroadcastTx {
    /// Returns calldata bytes after strict hex decode.
    pub fn data_bytes(&self) -> Result<Vec<u8>, DomainError> {
        decode_hex_payload(&self.data_hex)
    }

    /// Returns maximum fee exposure for this tx (`gas_limit * max_fee_per_gas_wei`).
    pub fn max_gas_spend_wei(&self) -> Result<u128, DomainError> {
        u128::from(self.gas_limit)
            .checked_mul(self.max_fee_per_gas_wei)
            .ok_or(DomainError::InvalidGasConfiguration)
    }

    /// Validates structural tx constraints.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.chain_id == 0 {
            return Err(DomainError::InvalidChainId);
        }
        if self.gas_limit == 0 || self.max_fee_per_gas_wei == 0 {
            return Err(DomainError::InvalidGasConfiguration);
        }
        if self.max_priority_fee_per_gas_wei > self.max_fee_per_gas_wei {
            return Err(DomainError::InvalidGasConfiguration);
        }
        if self.delegation_enabled {
            return Err(DomainError::DelegationNotAllowed);
        }
        let data = self.data_bytes()?;
        if validate_token_broadcast_calldata(&data)? && self.value_wei > 0 {
            return Err(DomainError::Erc20CallWithNativeValue);
        }
        let _ = self.max_gas_spend_wei()?;
        Ok(())
    }

    /// Returns typed EIP-1559 signing message (`0x02 || rlp(unsigned_fields)`).
    pub fn eip1559_signing_message(&self) -> Result<Vec<u8>, DomainError> {
        self.validate()?;
        if self.tx_type != 0x02 {
            return Err(DomainError::UnsupportedTransactionType(self.tx_type));
        }

        let data = self.data_bytes()?;
        let to = decode_hex_payload(self.to.as_str())?;
        let unsigned_fields = vec![
            rlp_encode_u64(self.chain_id),
            rlp_encode_u64(self.nonce),
            rlp_encode_u128(self.max_priority_fee_per_gas_wei),
            rlp_encode_u128(self.max_fee_per_gas_wei),
            rlp_encode_u64(self.gas_limit),
            rlp_encode_bytes(&to),
            rlp_encode_u128(self.value_wei),
            rlp_encode_bytes(&data),
            rlp_encode_list(&[]), // empty access list
        ];

        let mut out = vec![0x02];
        out.extend(rlp_encode_list(&unsigned_fields));
        Ok(out)
    }

    /// Builds typed EIP-1559 signed raw transaction bytes.
    pub fn eip1559_signed_raw_transaction(
        &self,
        y_parity: u8,
        r: [u8; 32],
        s: [u8; 32],
    ) -> Result<Vec<u8>, DomainError> {
        if y_parity > 1 {
            return Err(DomainError::InvalidSignatureParity);
        }

        self.validate()?;
        if self.tx_type != 0x02 {
            return Err(DomainError::UnsupportedTransactionType(self.tx_type));
        }

        let data = self.data_bytes()?;
        let to = decode_hex_payload(self.to.as_str())?;

        let signed_fields = vec![
            rlp_encode_u64(self.chain_id),
            rlp_encode_u64(self.nonce),
            rlp_encode_u128(self.max_priority_fee_per_gas_wei),
            rlp_encode_u128(self.max_fee_per_gas_wei),
            rlp_encode_u64(self.gas_limit),
            rlp_encode_bytes(&to),
            rlp_encode_u128(self.value_wei),
            rlp_encode_bytes(&data),
            rlp_encode_list(&[]), // empty access list
            rlp_encode_u64(u64::from(y_parity)),
            rlp_encode_u256_bytes(&r),
            rlp_encode_u256_bytes(&s),
        ];

        let mut out = vec![0x02];
        out.extend(rlp_encode_list(&signed_fields));
        Ok(out)
    }
}

/// Actions an agent can request the daemon to sign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        amount_wei: u128,
    },
    /// Permit2 `PermitSingle` approval.
    Permit2Permit {
        /// Typed authorization payload.
        permit: Permit2Permit,
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
    /// Tempo session open transaction digest.
    TempoSessionOpenTransaction {
        /// Typed digest payload.
        authorization: TempoSessionOpenTransaction,
    },
    /// Tempo session top-up transaction digest.
    TempoSessionTopUpTransaction {
        /// Typed digest payload.
        authorization: TempoSessionTopUpTransaction,
    },
    /// Tempo session voucher digest.
    TempoSessionVoucher {
        /// Typed digest payload.
        authorization: TempoSessionVoucher,
    },
    /// Raw transaction broadcast request.
    BroadcastTx {
        /// Unsinged tx fields to authorize and sign.
        tx: BroadcastTx,
    },
}

impl AgentAction {
    /// Returns action amount in wei.
    #[must_use]
    pub fn amount_wei(&self) -> u128 {
        match self {
            Self::Approve { amount_wei, .. }
            | Self::Transfer { amount_wei, .. }
            | Self::TransferNative { amount_wei, .. } => *amount_wei,
            Self::Permit2Permit { permit } => permit.amount_wei,
            Self::Eip3009TransferWithAuthorization { authorization }
            | Self::Eip3009ReceiveWithAuthorization { authorization } => authorization.amount_wei,
            Self::TempoSessionOpenTransaction { authorization } => authorization.deposit_wei,
            Self::TempoSessionTopUpTransaction { authorization } => authorization.additional_deposit_wei,
            Self::TempoSessionVoucher { authorization } => authorization.amount_wei,
            Self::BroadcastTx { tx } => self.broadcast_effective_amount_wei(tx),
        }
    }

    /// Returns action chain id.
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        match self {
            Self::Approve { chain_id, .. }
            | Self::Transfer { chain_id, .. }
            | Self::TransferNative { chain_id, .. } => *chain_id,
            Self::Permit2Permit { permit } => permit.chain_id,
            Self::Eip3009TransferWithAuthorization { authorization }
            | Self::Eip3009ReceiveWithAuthorization { authorization } => authorization.chain_id,
            Self::TempoSessionOpenTransaction { authorization } => authorization.chain_id,
            Self::TempoSessionTopUpTransaction { authorization } => authorization.chain_id,
            Self::TempoSessionVoucher { authorization } => authorization.chain_id,
            Self::BroadcastTx { tx } => tx.chain_id,
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
            Self::Permit2Permit { permit } => AssetId::Erc20(permit.token.clone()),
            Self::Eip3009TransferWithAuthorization { authorization }
            | Self::Eip3009ReceiveWithAuthorization { authorization } => {
                AssetId::Erc20(authorization.token.clone())
            }
            Self::TempoSessionOpenTransaction { authorization } => {
                AssetId::Erc20(authorization.token.clone())
            }
            Self::TempoSessionTopUpTransaction { authorization } => {
                AssetId::Erc20(authorization.token.clone())
            }
            Self::TempoSessionVoucher { authorization } => AssetId::Erc20(authorization.token.clone()),
            Self::BroadcastTx { tx } => self.broadcast_effective_asset(tx),
        }
    }

    /// Returns recipient/spender address used for policy scope matching.
    #[must_use]
    pub fn recipient(&self) -> EvmAddress {
        match self {
            Self::Approve { spender, .. } => spender.clone(),
            Self::Transfer { to, .. } | Self::TransferNative { to, .. } => to.clone(),
            Self::Permit2Permit { permit } => permit.spender.clone(),
            Self::Eip3009TransferWithAuthorization { authorization }
            | Self::Eip3009ReceiveWithAuthorization { authorization } => authorization.to.clone(),
            Self::TempoSessionOpenTransaction { authorization } => authorization.recipient.clone(),
            Self::TempoSessionTopUpTransaction { authorization } => authorization.recipient.clone(),
            Self::TempoSessionVoucher { authorization } => authorization.recipient.clone(),
            Self::BroadcastTx { tx } => self.broadcast_effective_recipient(tx),
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
            Self::Permit2Permit { permit } => permit.signing_hash().map(Some),
            Self::Eip3009TransferWithAuthorization { authorization } => {
                authorization.transfer_signing_hash().map(Some)
            }
            Self::Eip3009ReceiveWithAuthorization { authorization } => {
                authorization.receive_signing_hash().map(Some)
            }
            Self::TempoSessionOpenTransaction { authorization } => authorization.signing_hash().map(Some),
            Self::TempoSessionTopUpTransaction { authorization } => authorization.signing_hash().map(Some),
            Self::TempoSessionVoucher { authorization } => authorization.signing_hash().map(Some),
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
            Self::BroadcastTx { tx } => tx.validate(),
            Self::Permit2Permit { permit } => permit.validate_at(now),
            Self::Eip3009TransferWithAuthorization { authorization }
            | Self::Eip3009ReceiveWithAuthorization { authorization } => {
                authorization.validate_at(now)
            }
            Self::TempoSessionOpenTransaction { authorization } => authorization.validate(),
            Self::TempoSessionTopUpTransaction { authorization } => authorization.validate(),
            Self::TempoSessionVoucher { authorization } => authorization.validate(),
            _ => {
                if self.amount_wei() == 0 {
                    return Err(DomainError::InvalidAmount);
                }
                if self.chain_id() == 0 {
                    return Err(DomainError::InvalidChainId);
                }
                Ok(())
            }
        }
    }

    fn broadcast_effective_asset(&self, tx: &BroadcastTx) -> AssetId {
        if let Some(projection) = self.broadcast_policy_projection(tx) {
            return projection.asset;
        }
        AssetId::NativeEth
    }

    fn broadcast_effective_recipient(&self, tx: &BroadcastTx) -> EvmAddress {
        if let Some(projection) = self.broadcast_policy_projection(tx) {
            return projection.recipient;
        }
        tx.to.clone()
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct BroadcastPolicyProjection {
    asset: AssetId,
    recipient: EvmAddress,
    amount_wei: u128,
}

/// Parses ERC-20 call data and returns a strongly-typed call description.
///
/// Supported methods:
/// - `approve(address spender, uint256 value)`
/// - `transfer(address to, uint256 value)`
pub fn parse_erc20_call(calldata: &[u8]) -> Result<Erc20Call, DomainError> {
    if calldata.len() < 4 {
        return Err(DomainError::InvalidErc20Calldata(
            "missing 4-byte selector".to_string(),
        ));
    }

    let selector = &calldata[..4];
    if selector == approveCall::SELECTOR {
        let decoded = approveCall::abi_decode(calldata, true)
            .map_err(|err| DomainError::InvalidErc20Calldata(err.to_string()))?;
        return Ok(Erc20Call::Approve {
            spender: alloy_address_to_evm(decoded.spender)?,
            amount_wei: u256_to_u128(decoded.value)?,
        });
    }

    if selector == transferCall::SELECTOR {
        let decoded = transferCall::abi_decode(calldata, true)
            .map_err(|err| DomainError::InvalidErc20Calldata(err.to_string()))?;
        return Ok(Erc20Call::Transfer {
            to: alloy_address_to_evm(decoded.to)?,
            amount_wei: u256_to_u128(decoded.value)?,
        });
    }

    Err(DomainError::InvalidErc20Calldata(format!(
        "unsupported selector 0x{}",
        hex::encode(selector)
    )))
}

fn validate_token_broadcast_calldata(calldata: &[u8]) -> Result<bool, DomainError> {
    if calldata.len() < 4 {
        return Ok(false);
    }

    let selector = &calldata[..4];
    if selector == approveCall::SELECTOR || selector == transferCall::SELECTOR {
        parse_erc20_call(calldata)?;
        return Ok(true);
    }

    if selector == permitCall::SELECTOR {
        permitCall::abi_decode(calldata, true)
            .map_err(|err| DomainError::InvalidErc20Calldata(err.to_string()))?;
        return Ok(true);
    }

    if selector == transferWithAuthorizationCall::SELECTOR {
        transferWithAuthorizationCall::abi_decode(calldata, true)
            .map_err(|err| DomainError::InvalidErc20Calldata(err.to_string()))?;
        return Ok(true);
    }

    if selector == receiveWithAuthorizationCall::SELECTOR {
        receiveWithAuthorizationCall::abi_decode(calldata, true)
            .map_err(|err| DomainError::InvalidErc20Calldata(err.to_string()))?;
        return Ok(true);
    }

    Ok(false)
}

/// Constructs an [`AgentAction`] from ERC-20 calldata for a given contract and network.
pub fn action_from_erc20_calldata(
    chain_id: u64,
    token: EvmAddress,
    calldata: &[u8],
) -> Result<AgentAction, DomainError> {
    if chain_id == 0 {
        return Err(DomainError::InvalidChainId);
    }

    match parse_erc20_call(calldata)? {
        Erc20Call::Approve {
            spender,
            amount_wei,
        } => Ok(AgentAction::Approve {
            chain_id,
            token,
            spender,
            amount_wei,
        }),
        Erc20Call::Transfer { to, amount_wei } => Ok(AgentAction::Transfer {
            chain_id,
            token,
            to,
            amount_wei,
        }),
    }
}

fn parse_broadcast_policy_call(
    tx: &BroadcastTx,
    calldata: &[u8],
) -> Result<BroadcastPolicyProjection, DomainError> {
    if calldata.len() >= 4 {
        let selector = &calldata[..4];
        if selector == approveCall::SELECTOR || selector == transferCall::SELECTOR {
            let call = parse_erc20_call(calldata)?;
            let asset = AssetId::Erc20(tx.to.clone());
            return Ok(match call {
                Erc20Call::Approve {
                    spender,
                    amount_wei,
                } => BroadcastPolicyProjection {
                    asset,
                    recipient: spender,
                    amount_wei,
                },
                Erc20Call::Transfer { to, amount_wei } => BroadcastPolicyProjection {
                    asset,
                    recipient: to,
                    amount_wei,
                },
            });
        }
    }

    if calldata.len() >= 4 {
        if let Ok(decoded) = permitCall::abi_decode(calldata, true) {
            return Ok(BroadcastPolicyProjection {
                asset: AssetId::Erc20(alloy_address_to_evm(decoded.permitSingle.details.token)?),
                recipient: alloy_address_to_evm(decoded.permitSingle.spender)?,
                amount_wei: u160_to_u128(decoded.permitSingle.details.amount)?,
            });
        }

        if let Ok(decoded) = transferWithAuthorizationCall::abi_decode(calldata, true) {
            return Ok(BroadcastPolicyProjection {
                asset: AssetId::Erc20(tx.to.clone()),
                recipient: alloy_address_to_evm(decoded.to)?,
                amount_wei: u256_to_u128(decoded.value)?,
            });
        }

        if let Ok(decoded) = receiveWithAuthorizationCall::abi_decode(calldata, true) {
            return Ok(BroadcastPolicyProjection {
                asset: AssetId::Erc20(tx.to.clone()),
                recipient: alloy_address_to_evm(decoded.to)?,
                amount_wei: u256_to_u128(decoded.value)?,
            });
        }
    }

    Err(DomainError::InvalidErc20Calldata(
        "unsupported broadcast policy projection".to_string(),
    ))
}

fn evm_to_alloy_address(address: &EvmAddress) -> Result<Address, DomainError> {
    Address::parse_checksummed(address.as_str(), None)
        .or_else(|_| address.as_str().parse())
        .map_err(|_| DomainError::InvalidAddress)
}

fn alloy_address_to_evm(address: alloy_primitives::Address) -> Result<EvmAddress, DomainError> {
    let value = format!("0x{}", hex::encode(address.as_slice()));
    value.parse::<EvmAddress>()
}

fn decode_hex_payload(input: &str) -> Result<Vec<u8>, DomainError> {
    let trimmed = input.trim();
    let payload = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if payload.is_empty() {
        return Ok(Vec::new());
    }
    if !payload.len().is_multiple_of(2) || !payload.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(DomainError::InvalidTransactionDataHex);
    }
    hex::decode(payload).map_err(|_| DomainError::InvalidTransactionDataHex)
}

fn decode_hex_32(input: &str, label: &str) -> Result<[u8; 32], DomainError> {
    let bytes = decode_hex_payload(input).map_err(|_| {
        DomainError::InvalidTypedDataDomain(format!("{label} must be a 32-byte hex value"))
    })?;
    if bytes.len() != 32 {
        return Err(DomainError::InvalidTypedDataDomain(format!(
            "{label} must be exactly 32 bytes"
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn u256_to_u128(value: U256) -> Result<u128, DomainError> {
    if value > U256::from(u128::MAX) {
        return Err(DomainError::AmountOutOfRange);
    }
    Ok(value.to::<u128>())
}

fn u160_to_u128(value: U160) -> Result<u128, DomainError> {
    let bytes = value.to_be_bytes::<20>();
    if bytes[..4].iter().any(|byte| *byte != 0) {
        return Err(DomainError::AmountOutOfRange);
    }
    Ok(u128::from_be_bytes(
        bytes[4..].try_into().expect("16-byte slice"),
    ))
}

fn u128_to_u160(value: u128) -> U160 {
    U160::from_be_slice(&value.to_be_bytes())
}

fn u64_to_u48(value: u64) -> Result<U48, DomainError> {
    if value > permit2_max_timestamp() {
        return Err(DomainError::AmountOutOfRange);
    }
    Ok(U48::from_be_slice(&value.to_be_bytes()[2..]))
}

fn validate_permit2_u48(field: &'static str, value: u64) -> Result<(), DomainError> {
    if value > permit2_max_timestamp() {
        return Err(DomainError::Permit2FieldOutOfRange { field });
    }
    Ok(())
}

fn permit2_max_timestamp() -> u64 {
    (1u64 << 48) - 1
}
fn rlp_encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return rlp_encode_bytes(&[]);
    }
    let mut bytes = value.to_be_bytes().to_vec();
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    bytes.drain(..first_non_zero);
    rlp_encode_bytes(&bytes)
}

fn rlp_encode_u128(value: u128) -> Vec<u8> {
    if value == 0 {
        return rlp_encode_bytes(&[]);
    }
    let mut bytes = value.to_be_bytes().to_vec();
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    bytes.drain(..first_non_zero);
    rlp_encode_bytes(&bytes)
}

fn rlp_encode_u256_bytes(value: &[u8; 32]) -> Vec<u8> {
    let first_non_zero = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    rlp_encode_bytes(&value[first_non_zero..])
}

fn rlp_encode_bytes(value: &[u8]) -> Vec<u8> {
    if value.len() == 1 && value[0] < 0x80 {
        return vec![value[0]];
    }
    if value.len() <= 55 {
        let mut out = Vec::with_capacity(1 + value.len());
        out.push(0x80 + value.len() as u8);
        out.extend(value);
        return out;
    }

    let len_bytes = usize_to_be_bytes_no_leading_zero(value.len());
    let mut out = Vec::with_capacity(1 + len_bytes.len() + value.len());
    out.push(rlp_long_length_prefix(0xb7, len_bytes.len()));
    out.extend(len_bytes);
    out.extend(value);
    out
}

fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_len: usize = items.iter().map(Vec::len).sum();
    let mut payload: Vec<u8> = Vec::with_capacity(payload_len);
    for item in items {
        payload.extend_from_slice(item);
    }

    if payload.len() <= 55 {
        let mut out = Vec::with_capacity(1 + payload.len());
        out.push(0xc0 + payload.len() as u8);
        out.extend(payload);
        return out;
    }

    let len_bytes = usize_to_be_bytes_no_leading_zero(payload.len());
    let mut out = Vec::with_capacity(1 + len_bytes.len() + payload.len());
    out.push(rlp_long_length_prefix(0xf7, len_bytes.len()));
    out.extend(len_bytes);
    out.extend(payload);
    out
}

fn rlp_long_length_prefix(offset: u8, len_of_len: usize) -> u8 {
    assert!(
        len_of_len <= 8,
        "RLP payload length-of-length must be <= 8 bytes"
    );
    offset + u8::try_from(len_of_len).expect("RLP payload length-of-length must fit in u8")
}

fn usize_to_be_bytes_no_leading_zero(value: usize) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    bytes.drain(..first_non_zero);
    bytes
}

#[cfg(test)]
mod action_tests {
    use super::*;

    #[test]
    fn rlp_long_length_prefix_accepts_u64_sized_lengths() {
        assert_eq!(rlp_long_length_prefix(0xb7, 1), 0xb8);
        assert_eq!(rlp_long_length_prefix(0xb7, 8), 0xbf);
        assert_eq!(rlp_long_length_prefix(0xf7, 1), 0xf8);
        assert_eq!(rlp_long_length_prefix(0xf7, 8), 0xff);
    }

    #[test]
    #[should_panic(expected = "RLP payload length-of-length must be <= 8 bytes")]
    fn rlp_long_length_prefix_rejects_lengths_larger_than_u64() {
        let _ = rlp_long_length_prefix(0xb7, 9);
    }

    #[test]
    fn u64_to_u48_rejects_values_above_48_bits() {
        assert!(u64_to_u48(permit2_max_timestamp()).is_ok());
        assert!(matches!(
            u64_to_u48(permit2_max_timestamp() + 1),
            Err(DomainError::AmountOutOfRange)
        ));
    }
}
