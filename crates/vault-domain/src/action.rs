use alloy_dyn_abi::eip712::TypedData;
use alloy_primitives::{aliases::U48, Address, U160, U256};
use alloy_sol_types::{eip712_domain, sol, Eip712Domain, SolCall, SolStruct};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use time::OffsetDateTime;

use crate::constants::{canonical_policy_chain_id, is_solana_chain_id};
use crate::u128_as_decimal_string;
use crate::{AssetId, DomainError, EvmAddress, RecipientId, SolanaAddress};

const MAX_SOLANA_SIGNING_MESSAGE_BYTES: usize = 4 * 1024;

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

/// Arbitrary EIP-712 typed data payload signed through daemon policy checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Eip712TypedData {
    /// Raw typed-data JSON object as provided by the caller.
    pub typed_data_json: String,
}

impl Eip712TypedData {
    fn parse(&self) -> Result<TypedData, DomainError> {
        let raw = self.typed_data_json.trim();
        if raw.is_empty() {
            return Err(DomainError::InvalidTypedDataDomain(
                "typed_data_json must not be empty".to_string(),
            ));
        }

        serde_json::from_str::<TypedData>(raw).map_err(|err| {
            DomainError::InvalidTypedDataDomain(format!("typed_data_json is invalid: {err}"))
        })
    }

    pub fn primary_type(&self) -> Result<String, DomainError> {
        let typed_data = self.parse()?;
        let primary_type = typed_data.primary_type.trim().to_string();
        if primary_type.is_empty() {
            return Err(DomainError::InvalidTypedDataDomain(
                "primaryType must not be empty".to_string(),
            ));
        }
        Ok(primary_type)
    }

    pub fn chain_id(&self) -> Result<u64, DomainError> {
        let typed_data = self.parse()?;
        let chain_id = typed_data.domain.chain_id.ok_or_else(|| {
            DomainError::InvalidTypedDataDomain("domain.chainId is required".to_string())
        })?;
        let chain_id = u64::try_from(chain_id).map_err(|_| {
            DomainError::InvalidTypedDataDomain(
                "domain.chainId exceeds supported range".to_string(),
            )
        })?;
        if chain_id == 0 {
            return Err(DomainError::InvalidChainId);
        }
        Ok(chain_id)
    }

    pub fn verifying_contract(&self) -> Result<Option<EvmAddress>, DomainError> {
        let typed_data = self.parse()?;
        typed_data
            .domain
            .verifying_contract
            .map(alloy_address_to_evm)
            .transpose()
    }

    pub fn signing_hash(&self) -> Result<[u8; 32], DomainError> {
        let typed_data = self.parse()?;
        typed_data
            .eip712_signing_hash()
            .map(|hash| hash.0)
            .map_err(|err| DomainError::InvalidTypedDataDomain(err.to_string()))
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        let _ = self.primary_type()?;
        let _ = self.chain_id()?;
        let _ = self.verifying_contract()?;
        let _ = self.signing_hash()?;
        Ok(())
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

/// Supported Solana token program variants for constrained token transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolanaTokenProgram {
    /// Original SPL Token program.
    Token,
    /// Token-2022 program.
    Token2022,
}

impl Default for SolanaTokenProgram {
    fn default() -> Self {
        Self::Token
    }
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

/// Scoped Solana message signing request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaMessageSigning {
    /// Internal Solana network id.
    pub chain_id: u64,
    /// Solana wallet address expected to sign the message.
    pub address: SolanaAddress,
    /// External domain requesting the signature.
    pub domain: String,
    /// UTF-8 message bytes to sign.
    pub message: String,
}

impl SolanaMessageSigning {
    pub fn validate(&self) -> Result<(), DomainError> {
        if !is_solana_chain_id(self.chain_id) {
            return Err(DomainError::InvalidChainId);
        }
        let _ = self.address.to_bytes()?;
        let domain = self.domain.trim();
        if domain != "solayer" {
            return Err(DomainError::InvalidSolanaMessage);
        }
        let message = self.message.as_bytes();
        if message.is_empty() || message.len() > MAX_SOLANA_SIGNING_MESSAGE_BYTES {
            return Err(DomainError::InvalidSolanaMessage);
        }
        Ok(())
    }
}

/// Constrained native SOL transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub durable_nonce_account: Option<SolanaAddress>,
    /// Fee payer and signing authority pubkey.
    pub fee_payer: SolanaAddress,
    /// Recipient wallet pubkey.
    pub to: SolanaAddress,
    /// Transfer amount in lamports.
    #[serde(with = "u128_as_decimal_string")]
    pub amount_wei: u128,
    /// Optional compute unit limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compute_unit_limit: Option<u32>,
    /// Optional compute unit price in micro-lamports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compute_unit_price_micro_lamports: Option<u64>,
}

impl SolanaSolTransfer {
    pub fn validate(&self) -> Result<(), DomainError> {
        if !is_solana_chain_id(self.chain_id) {
            return Err(DomainError::InvalidChainId);
        }
        if self.amount_wei == 0 {
            return Err(DomainError::InvalidAmount);
        }
        if self.amount_wei > u128::from(u64::MAX) {
            return Err(DomainError::AmountOutOfRange);
        }
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub durable_nonce_account: Option<SolanaAddress>,
    /// Fee payer and signing authority pubkey.
    pub fee_payer: SolanaAddress,
    /// SPL mint pubkey under the original token program.
    pub mint: SolanaAddress,
    /// Recipient wallet owner pubkey.
    pub recipient_owner: SolanaAddress,
    /// Transfer amount in token base units.
    #[serde(with = "u128_as_decimal_string")]
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
    pub transfer_fee_wei: Option<u128>,
    /// Optional compute unit limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compute_unit_limit: Option<u32>,
    /// Optional compute unit price in micro-lamports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compute_unit_price_micro_lamports: Option<u64>,
}

impl SolanaSplTransfer {
    pub fn validate(&self) -> Result<(), DomainError> {
        if !is_solana_chain_id(self.chain_id) {
            return Err(DomainError::InvalidChainId);
        }
        if self.amount_wei == 0 {
            return Err(DomainError::InvalidAmount);
        }
        if self.amount_wei > u128::from(u64::MAX) {
            return Err(DomainError::AmountOutOfRange);
        }
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(with = "u128_as_decimal_string")]
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
        if self.rent_lamports > u128::from(u64::MAX) {
            return Err(DomainError::AmountOutOfRange);
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
    /// Arbitrary EIP-712 typed data payload.
    Eip712TypedData {
        /// Raw typed-data payload.
        typed_data: Eip712TypedData,
    },
    /// Raw transaction broadcast request.
    BroadcastTx {
        /// Unsinged tx fields to authorize and sign.
        tx: BroadcastTx,
    },
    /// Scoped Solana message signing request.
    SolanaMessageSigning { message: SolanaMessageSigning },
    /// Constrained native SOL transfer request.
    SolanaSolTransfer { transfer: SolanaSolTransfer },
    /// Constrained Solana SPL token transfer request.
    SolanaSplTransfer { transfer: SolanaSplTransfer },
    /// Internal durable nonce account creation request.
    SolanaNonceAccountCreate { create: SolanaNonceAccountCreate },
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
            Self::TempoSessionTopUpTransaction { authorization } => {
                authorization.additional_deposit_wei
            }
            Self::TempoSessionVoucher { authorization } => authorization.amount_wei,
            Self::Eip712TypedData { .. } => 0,
            Self::BroadcastTx { tx } => self.broadcast_effective_amount_wei(tx),
            Self::SolanaMessageSigning { .. } => 0,
            Self::SolanaSolTransfer { transfer } => transfer.amount_wei,
            Self::SolanaSplTransfer { transfer } => transfer.amount_wei,
            Self::SolanaNonceAccountCreate { create } => create.rent_lamports,
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
            Self::Eip712TypedData { typed_data } => typed_data.chain_id().unwrap_or_default(),
            Self::BroadcastTx { tx } => tx.chain_id,
            Self::SolanaMessageSigning { message } => canonical_policy_chain_id(message.chain_id),
            Self::SolanaSolTransfer { transfer } => canonical_policy_chain_id(transfer.chain_id),
            Self::SolanaSplTransfer { transfer } => canonical_policy_chain_id(transfer.chain_id),
            Self::SolanaNonceAccountCreate { create } => canonical_policy_chain_id(create.chain_id),
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
            Self::TempoSessionVoucher { authorization } => {
                AssetId::Erc20(authorization.token.clone())
            }
            Self::Eip712TypedData { .. } => AssetId::NativeEth,
            Self::BroadcastTx { tx } => self.broadcast_effective_asset(tx),
            Self::SolanaMessageSigning { .. } => AssetId::NativeSol,
            Self::SolanaSolTransfer { .. } => AssetId::NativeSol,
            Self::SolanaSplTransfer { transfer } => AssetId::SplToken(transfer.mint.clone()),
            Self::SolanaNonceAccountCreate { .. } => AssetId::NativeSol,
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
            Self::Permit2Permit { permit } => RecipientId::Evm(permit.spender.clone()),
            Self::Eip3009TransferWithAuthorization { authorization }
            | Self::Eip3009ReceiveWithAuthorization { authorization } => {
                RecipientId::Evm(authorization.to.clone())
            }
            Self::TempoSessionOpenTransaction { authorization } => {
                RecipientId::Evm(authorization.recipient.clone())
            }
            Self::TempoSessionTopUpTransaction { authorization } => {
                RecipientId::Evm(authorization.recipient.clone())
            }
            Self::TempoSessionVoucher { authorization } => {
                RecipientId::Evm(authorization.recipient.clone())
            }
            Self::Eip712TypedData { typed_data } => RecipientId::Evm(
                typed_data
                    .verifying_contract()
                    .ok()
                    .flatten()
                    .unwrap_or_else(zero_evm_address),
            ),
            Self::BroadcastTx { tx } => self.broadcast_effective_recipient(tx),
            Self::SolanaMessageSigning { message } => RecipientId::Solana(message.address.clone()),
            Self::SolanaSolTransfer { transfer } => RecipientId::Solana(transfer.to.clone()),
            Self::SolanaSplTransfer { transfer } => {
                RecipientId::Solana(transfer.recipient_owner.clone())
            }
            Self::SolanaNonceAccountCreate { create } => {
                RecipientId::Solana(create.nonce_account.clone())
            }
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
            Self::TempoSessionOpenTransaction { authorization } => {
                authorization.signing_hash().map(Some)
            }
            Self::TempoSessionTopUpTransaction { authorization } => {
                authorization.signing_hash().map(Some)
            }
            Self::TempoSessionVoucher { authorization } => authorization.signing_hash().map(Some),
            Self::Eip712TypedData { typed_data } => typed_data.signing_hash().map(Some),
            _ => Ok(None),
        }
    }

    #[must_use]
    pub fn records_spend_event(&self) -> bool {
        !matches!(
            self,
            Self::Eip712TypedData { .. }
                | Self::SolanaMessageSigning { .. }
                | Self::SolanaNonceAccountCreate { .. }
        )
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
            Self::BroadcastTx { tx } => tx.validate(),
            Self::Permit2Permit { permit } => permit.validate_at(now),
            Self::Eip3009TransferWithAuthorization { authorization }
            | Self::Eip3009ReceiveWithAuthorization { authorization } => {
                authorization.validate_at(now)
            }
            Self::TempoSessionOpenTransaction { authorization } => authorization.validate(),
            Self::TempoSessionTopUpTransaction { authorization } => authorization.validate(),
            Self::TempoSessionVoucher { authorization } => authorization.validate(),
            Self::Eip712TypedData { typed_data } => typed_data.validate(),
            Self::SolanaMessageSigning { message } => message.validate(),
            Self::SolanaSolTransfer { transfer } => transfer.validate(),
            Self::SolanaSplTransfer { transfer } => transfer.validate(),
            Self::SolanaNonceAccountCreate { create } => create.validate(),
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

fn validate_solana_compute_budget(
    compute_unit_limit: Option<u32>,
    compute_unit_price_micro_lamports: Option<u64>,
) -> Result<(), DomainError> {
    if matches!(compute_unit_limit, Some(0)) || matches!(compute_unit_price_micro_lamports, Some(0))
    {
        return Err(DomainError::InvalidSolanaComputeBudget);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BroadcastPolicyProjection {
    asset: AssetId,
    recipient: RecipientId,
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
                    recipient: RecipientId::Evm(spender),
                    amount_wei,
                },
                Erc20Call::Transfer { to, amount_wei } => BroadcastPolicyProjection {
                    asset,
                    recipient: RecipientId::Evm(to),
                    amount_wei,
                },
            });
        }
    }

    if calldata.len() >= 4 {
        if let Ok(decoded) = permitCall::abi_decode(calldata, true) {
            return Ok(BroadcastPolicyProjection {
                asset: AssetId::Erc20(alloy_address_to_evm(decoded.permitSingle.details.token)?),
                recipient: RecipientId::Evm(alloy_address_to_evm(decoded.permitSingle.spender)?),
                amount_wei: u160_to_u128(decoded.permitSingle.details.amount)?,
            });
        }

        if let Ok(decoded) = transferWithAuthorizationCall::abi_decode(calldata, true) {
            return Ok(BroadcastPolicyProjection {
                asset: AssetId::Erc20(tx.to.clone()),
                recipient: RecipientId::Evm(alloy_address_to_evm(decoded.to)?),
                amount_wei: u256_to_u128(decoded.value)?,
            });
        }

        if let Ok(decoded) = receiveWithAuthorizationCall::abi_decode(calldata, true) {
            return Ok(BroadcastPolicyProjection {
                asset: AssetId::Erc20(tx.to.clone()),
                recipient: RecipientId::Evm(alloy_address_to_evm(decoded.to)?),
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

fn decode_base58_32(value: &str) -> Result<[u8; 32], DomainError> {
    let decoded = bs58::decode(value.trim())
        .into_vec()
        .map_err(|_| DomainError::InvalidSolanaRecentBlockhash)?;
    <[u8; 32]>::try_from(decoded.as_slice()).map_err(|_| DomainError::InvalidSolanaRecentBlockhash)
}

fn zero_evm_address() -> EvmAddress {
    "0x0000000000000000000000000000000000000000"
        .parse()
        .expect("zero address literal must be valid")
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
