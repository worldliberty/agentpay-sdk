//! EVM token actions: ERC-20 calldata, EIP-3009 authorizations, and raw broadcast transactions.

use alloy_primitives::U256;
use alloy_sol_types::abi::AbiDecoderConfig;
use alloy_sol_types::{sol, Eip712Domain, SolCall, SolStruct};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use ts_rs::TS;

use super::encoding::{
    alloy_address_to_evm, decode_hex_32, decode_hex_payload, evm_to_alloy_address,
    rlp_encode_bytes, rlp_encode_list, rlp_encode_u128, rlp_encode_u256_bytes, rlp_encode_u64,
    u160_to_u128, u256_to_u128,
};
use super::AgentAction;
use crate::schema::DecimalU128;
use crate::u128_as_decimal_string;
use crate::{AssetId, DomainError, EvmAddress, RecipientId};

sol! {
    function approve(address spender, uint256 value);
    function transfer(address to, uint256 value);
    /// TIP-20 (Tempo) transfer with a 32-byte memo, used by MPP charge payments.
    function transferWithMemo(address to, uint256 amount, bytes32 memo);
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

/// EIP-3009 transfer authorization signed for a token contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct Eip3009Transfer {
    /// EVM network chain ID.
    pub chain_id: u64,
    /// Token contract address used as EIP-712 verifying contract.
    pub token: EvmAddress,
    /// Token name used by the token's EIP-712 domain separator.
    pub token_name: String,
    /// Token version used by the token's EIP-712 domain separator.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub token_version: Option<String>,
    /// Authorization signer / owner.
    pub from: EvmAddress,
    /// Authorized recipient.
    pub to: EvmAddress,
    /// Transfer amount in wei.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
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

/// Agent-submitted broadcast transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct BroadcastTx {
    /// EVM network chain id.
    pub chain_id: u64,
    /// Sender account nonce.
    pub nonce: u64,
    /// Destination address.
    pub to: EvmAddress,
    /// Native value in wei.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub value_wei: u128,
    /// Transaction calldata as hex (`0x`-prefixed or plain).
    pub data_hex: String,
    /// Gas limit.
    pub gas_limit: u64,
    /// Max fee per gas in wei.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub max_fee_per_gas_wei: u128,
    /// Max priority fee per gas in wei.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
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
    ///
    /// Non-empty calldata must be one of the recognized token calls (ERC-20
    /// `approve`/`transfer`, TIP-20 `transferWithMemo`, Permit2 `permit`, EIP-3009
    /// `transferWithAuthorization`/`receiveWithAuthorization`); anything else
    /// is rejected with [`DomainError::UnrecognizedCalldata`]. Empty calldata
    /// (a plain native transfer) is always structurally valid.
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
        let recognized_token_call = validate_token_broadcast_calldata(&data)?;
        if recognized_token_call && self.value_wei > 0 {
            return Err(DomainError::Erc20CallWithNativeValue);
        }
        // Calldata the policy engine cannot project onto (asset, recipient,
        // amount) would otherwise be evaluated as a plain native transfer of
        // `value_wei`, letting arbitrary contract calls (`increaseAllowance`,
        // `setApprovalForAll`, swaps, ...) bypass spending scopes entirely.
        if !recognized_token_call && !data.is_empty() {
            return Err(DomainError::UnrecognizedCalldata);
        }
        let _ = self.max_gas_spend_wei()?;
        Ok(())
    }

    /// Returns typed EIP-1559 signing message (`0x02 || rlp(unsigned_fields)`).
    pub fn eip1559_signing_message(&self) -> Result<Vec<u8>, DomainError> {
        let unsigned_fields = self.eip1559_unsigned_fields()?;
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

        let mut signed_fields = self.eip1559_unsigned_fields()?;
        signed_fields.extend([
            rlp_encode_u64(u64::from(y_parity)),
            rlp_encode_u256_bytes(&r),
            rlp_encode_u256_bytes(&s),
        ]);

        let mut out = vec![0x02];
        out.extend(rlp_encode_list(&signed_fields));
        Ok(out)
    }

    /// Validates the tx and returns its RLP-encoded unsigned EIP-1559 fields.
    fn eip1559_unsigned_fields(&self) -> Result<Vec<Vec<u8>>, DomainError> {
        self.validate()?;
        if self.tx_type != 0x02 {
            return Err(DomainError::UnsupportedTransactionType(self.tx_type));
        }

        let data = self.data_bytes()?;
        let to = decode_hex_payload(self.to.as_str())?;
        Ok(vec![
            rlp_encode_u64(self.chain_id),
            rlp_encode_u64(self.nonce),
            rlp_encode_u128(self.max_priority_fee_per_gas_wei),
            rlp_encode_u128(self.max_fee_per_gas_wei),
            rlp_encode_u64(self.gas_limit),
            rlp_encode_bytes(&to),
            rlp_encode_u128(self.value_wei),
            rlp_encode_bytes(&data),
            rlp_encode_list(&[]), // empty access list
        ])
    }
}

/// Spending-policy view (asset, recipient, amount) of a recognized broadcast token call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BroadcastPolicyProjection {
    pub(super) asset: AssetId,
    pub(super) recipient: RecipientId,
    pub(super) amount_wei: u128,
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
        let decoded = decode_strict::<approveCall>(calldata)
            .map_err(|err| DomainError::InvalidErc20Calldata(err.to_string()))?;
        return Ok(Erc20Call::Approve {
            spender: alloy_address_to_evm(decoded.spender)?,
            amount_wei: u256_to_u128(decoded.value)?,
        });
    }

    if selector == transferCall::SELECTOR {
        let decoded = decode_strict::<transferCall>(calldata)
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

/// ABI-decodes `calldata` (selector included) as `C`, rejecting anything that
/// is not the canonical encoding: dirty padding, non-canonical offsets,
/// invalid token values, and trailing bytes. This is alloy-sol-types 0.8's
/// `abi_decode(data, true)` ("validate and re-encode equals input") behavior.
fn decode_strict<C: SolCall>(calldata: &[u8]) -> Result<C, alloy_sol_types::Error> {
    C::abi_decode_with_config(calldata, AbiDecoderConfig::new().strict(true))
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

    if selector == transferWithMemoCall::SELECTOR {
        decode_strict::<transferWithMemoCall>(calldata)
            .map_err(|err| DomainError::InvalidErc20Calldata(err.to_string()))?;
        return Ok(true);
    }

    if selector == permitCall::SELECTOR {
        decode_strict::<permitCall>(calldata)
            .map_err(|err| DomainError::InvalidErc20Calldata(err.to_string()))?;
        return Ok(true);
    }

    if selector == transferWithAuthorizationCall::SELECTOR {
        decode_strict::<transferWithAuthorizationCall>(calldata)
            .map_err(|err| DomainError::InvalidErc20Calldata(err.to_string()))?;
        return Ok(true);
    }

    if selector == receiveWithAuthorizationCall::SELECTOR {
        decode_strict::<receiveWithAuthorizationCall>(calldata)
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

pub(super) fn parse_broadcast_policy_call(
    tx: &BroadcastTx,
    calldata: &[u8],
) -> Result<BroadcastPolicyProjection, DomainError> {
    if calldata.len() < 4 {
        return Err(DomainError::InvalidErc20Calldata(
            "unsupported broadcast policy projection".to_string(),
        ));
    }

    let selector = &calldata[..4];
    if selector == approveCall::SELECTOR || selector == transferCall::SELECTOR {
        let asset = AssetId::Erc20(tx.to.clone());
        return Ok(match parse_erc20_call(calldata)? {
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

    if let Ok(decoded) = decode_strict::<transferWithMemoCall>(calldata) {
        // The memo carries no value: policy sees a plain token transfer.
        return Ok(BroadcastPolicyProjection {
            asset: AssetId::Erc20(tx.to.clone()),
            recipient: RecipientId::Evm(alloy_address_to_evm(decoded.to)?),
            amount_wei: u256_to_u128(decoded.amount)?,
        });
    }

    if let Ok(decoded) = decode_strict::<permitCall>(calldata) {
        return Ok(BroadcastPolicyProjection {
            asset: AssetId::Erc20(alloy_address_to_evm(decoded.permitSingle.details.token)?),
            recipient: RecipientId::Evm(alloy_address_to_evm(decoded.permitSingle.spender)?),
            amount_wei: u160_to_u128(decoded.permitSingle.details.amount)?,
        });
    }

    if let Ok(decoded) = decode_strict::<transferWithAuthorizationCall>(calldata) {
        return Ok(BroadcastPolicyProjection {
            asset: AssetId::Erc20(tx.to.clone()),
            recipient: RecipientId::Evm(alloy_address_to_evm(decoded.to)?),
            amount_wei: u256_to_u128(decoded.value)?,
        });
    }

    if let Ok(decoded) = decode_strict::<receiveWithAuthorizationCall>(calldata) {
        return Ok(BroadcastPolicyProjection {
            asset: AssetId::Erc20(tx.to.clone()),
            recipient: RecipientId::Evm(alloy_address_to_evm(decoded.to)?),
            amount_wei: u256_to_u128(decoded.value)?,
        });
    }

    Err(DomainError::InvalidErc20Calldata(
        "unsupported broadcast policy projection".to_string(),
    ))
}
