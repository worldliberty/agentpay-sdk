//! Tempo sessions v2: TIP-1034 channel reserve transactions, vouchers, and close authorizations.

use alloy_primitives::{aliases::U96, keccak256, Address, FixedBytes, U256};
use alloy_sol_types::{eip712_domain, Eip712Domain, SolCall, SolStruct, SolValue};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use ts_rs::TS;

use super::encoding::{
    alloy_address_to_evm, decode_hex_32, evm_to_alloy_address, rlp_encode_bytes, rlp_encode_list,
    rlp_encode_u128, rlp_encode_u256_bytes, rlp_encode_u64,
};
use crate::constants::{
    is_tempo_chain_id, TEMPO_CHANNEL_RESERVE_CONTRACT, TEMPO_CHANNEL_RESERVE_DOMAIN_NAME,
    TEMPO_CHANNEL_RESERVE_DOMAIN_VERSION, TEMPO_TX_TYPE,
};
use crate::schema::DecimalU128;
use crate::u128_as_decimal_string;
use crate::{DomainError, EvmAddress};

/// TIP-1034 channel reserve precompile ABI.
mod tip1034 {
    alloy_sol_types::sol! {
        struct ChannelDescriptor {
            address payer;
            address payee;
            address operator;
            address token;
            bytes32 salt;
            address authorizedSigner;
            bytes32 expiringNonceHash;
        }

        function open(address payee, address operator, address token, uint96 deposit, bytes32 salt, address authorizedSigner);
        function topUp(ChannelDescriptor descriptor, uint96 additionalDeposit);

        struct Voucher {
            bytes32 channelId;
            uint96 cumulativeAmount;
        }

        struct CloseAuthorization {
            bytes32 channelId;
            uint96 cumulativeAmount;
        }
    }
}

/// Tempo transaction envelope parameters committed to by the sender signature.
///
/// The daemon never accepts a precomputed Tempo digest. Instead it rebuilds the
/// type-`0x76` envelope from these fields plus calls it encodes itself from the
/// semantic channel fields, so every policy input is bound into the digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct TempoTxParams {
    /// Sequence nonce within `nonce_key`.
    pub nonce: u64,
    /// 2D nonce key as a decimal (or `0x` hex) `uint256`; omitted means the protocol nonce key 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_key: Option<String>,
    /// Gas limit.
    pub gas_limit: u64,
    /// EIP-1559 max fee per gas in wei.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub max_fee_per_gas_wei: u128,
    /// EIP-1559 max priority fee per gas in wei.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub max_priority_fee_per_gas_wei: u128,
    /// Optional `validBefore` unix timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_before: Option<u64>,
    /// Optional `validAfter` unix timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_after: Option<u64>,
    /// Fee token the sender pays gas in. Must be absent for sponsored transactions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_token: Option<EvmAddress>,
    /// Whether a fee payer sponsors gas. Sponsored senders sign the spec layout
    /// with an empty fee token and a `0x00` fee-payer marker.
    #[serde(default)]
    pub fee_payer: bool,
}

impl TempoTxParams {
    /// Validates transaction parameter invariants.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.gas_limit == 0 {
            return Err(DomainError::InvalidTempoTransactionParams(
                "gas_limit must be greater than zero".to_string(),
            ));
        }
        if self.max_fee_per_gas_wei == 0 {
            return Err(DomainError::InvalidTempoTransactionParams(
                "max_fee_per_gas_wei must be greater than zero".to_string(),
            ));
        }
        if self.max_priority_fee_per_gas_wei > self.max_fee_per_gas_wei {
            return Err(DomainError::InvalidTempoTransactionParams(
                "max_priority_fee_per_gas_wei must not exceed max_fee_per_gas_wei".to_string(),
            ));
        }
        // A zero timestamp would serialize differently in the reference encoder
        // (`0x0` instead of the empty string), so it is rejected outright.
        if matches!(self.valid_before, Some(0)) || matches!(self.valid_after, Some(0)) {
            return Err(DomainError::InvalidTempoTransactionParams(
                "valid_before and valid_after must be greater than zero when set".to_string(),
            ));
        }
        if let (Some(before), Some(after)) = (self.valid_before, self.valid_after) {
            if before <= after {
                return Err(DomainError::InvalidTempoTransactionParams(
                    "valid_before must be greater than valid_after".to_string(),
                ));
            }
        }
        if self.fee_payer && self.fee_token.is_some() {
            return Err(DomainError::InvalidTempoTransactionParams(
                "fee_token must be omitted for fee-payer sponsored transactions".to_string(),
            ));
        }
        if let Some(fee_token) = &self.fee_token {
            let _ = evm_to_alloy_address(fee_token)?;
        }
        let _ = self.nonce_key_u256()?;
        Ok(())
    }

    /// Parses the optional nonce key as a `uint256`.
    pub fn nonce_key_u256(&self) -> Result<U256, DomainError> {
        match self.nonce_key.as_deref().map(str::trim) {
            None | Some("") => Ok(U256::ZERO),
            Some(value) => U256::from_str(value).map_err(|_| {
                DomainError::InvalidTempoTransactionParams(
                    "nonce_key must be a uint256 integer".to_string(),
                )
            }),
        }
    }
}

/// One call inside a Tempo batched transaction.
struct TempoCall {
    to: Address,
    data: Vec<u8>,
}

/// Returns `0x76 || rlp(envelope)` for an unsigned Tempo transaction, mirroring ox
/// `TxEnvelopeTempo.encodeForSigning()` as driven by viem `Transaction.serialize()`.
fn tempo_sender_signing_preimage(
    chain_id: u64,
    tx: &TempoTxParams,
    calls: &[TempoCall],
) -> Result<Vec<u8>, DomainError> {
    let encoded_calls = calls
        .iter()
        .map(|call| {
            rlp_encode_list(&[
                rlp_encode_bytes(call.to.as_slice()),
                // Calls carry no native value.
                rlp_encode_bytes(&[]),
                rlp_encode_bytes(&call.data),
            ])
        })
        .collect::<Vec<_>>();
    let nonce_key = tx.nonce_key_u256()?.to_be_bytes::<32>();
    let optional_u64 = |value: Option<u64>| match value {
        Some(value) => rlp_encode_u64(value),
        None => rlp_encode_bytes(&[]),
    };
    let (fee_token, fee_payer_marker) = if tx.fee_payer {
        // Sponsored: the sender does not commit to the fee token, and the fee
        // payer slot carries the single-byte `0x00` placeholder.
        (rlp_encode_bytes(&[]), rlp_encode_bytes(&[0x00]))
    } else {
        let fee_token = match &tx.fee_token {
            Some(token) => rlp_encode_bytes(evm_to_alloy_address(token)?.as_slice()),
            None => rlp_encode_bytes(&[]),
        };
        (fee_token, rlp_encode_bytes(&[]))
    };
    let envelope = rlp_encode_list(&[
        rlp_encode_u64(chain_id),
        rlp_encode_u128(tx.max_priority_fee_per_gas_wei),
        rlp_encode_u128(tx.max_fee_per_gas_wei),
        rlp_encode_u64(tx.gas_limit),
        rlp_encode_list(&encoded_calls),
        // accessList
        rlp_encode_list(&[]),
        rlp_encode_u256_bytes(&nonce_key),
        rlp_encode_u64(tx.nonce),
        optional_u64(tx.valid_before),
        optional_u64(tx.valid_after),
        fee_token,
        fee_payer_marker,
        // authorizationList
        rlp_encode_list(&[]),
    ]);
    let mut payload = Vec::with_capacity(1 + envelope.len());
    payload.push(TEMPO_TX_TYPE);
    payload.extend_from_slice(&envelope);
    Ok(payload)
}

/// Returns `keccak256(0x76 || rlp(envelope))`, the sender signing digest.
fn tempo_sender_signing_hash(
    chain_id: u64,
    tx: &TempoTxParams,
    calls: &[TempoCall],
) -> Result<[u8; 32], DomainError> {
    Ok(keccak256(tempo_sender_signing_preimage(chain_id, tx, calls)?).0)
}

/// Converts calls to `(to, calldata)` pairs in envelope order.
fn encode_calls(calls: Vec<TempoCall>) -> Result<Vec<(EvmAddress, Vec<u8>)>, DomainError> {
    calls
        .into_iter()
        .map(|call| Ok((alloy_address_to_evm(call.to)?, call.data)))
        .collect()
}

/// Returns the TIP-1034 channel reserve precompile address.
fn tempo_channel_reserve() -> Result<Address, DomainError> {
    Address::from_str(TEMPO_CHANNEL_RESERVE_CONTRACT).map_err(|_| DomainError::InvalidAddress)
}

/// Converts a token amount to the TIP-1034 `uint96` amount type.
fn tempo_u96(amount_wei: u128) -> Result<U96, DomainError> {
    U96::try_from(amount_wei).map_err(|_| DomainError::TempoAmountOverflow)
}

fn validate_tempo_reserve_amount(amount_wei: u128) -> Result<(), DomainError> {
    if amount_wei == 0 {
        return Err(DomainError::InvalidAmount);
    }
    let _ = tempo_u96(amount_wei)?;
    Ok(())
}

/// Borrowed view of the fields that identify a TIP-1034 reserve channel,
/// excluding the transaction-derived `expiringNonceHash`.
struct TempoReserveChannel<'a> {
    chain_id: u64,
    token: &'a EvmAddress,
    recipient: &'a EvmAddress,
    operator: &'a EvmAddress,
    payer: &'a EvmAddress,
    authorized_signer: &'a EvmAddress,
    salt_hex: &'a str,
}

impl TempoReserveChannel<'_> {
    fn validate(&self) -> Result<(), DomainError> {
        if !is_tempo_chain_id(self.chain_id) {
            return Err(DomainError::UnsupportedTempoChain(self.chain_id));
        }
        let _ = evm_to_alloy_address(self.token)?;
        let _ = evm_to_alloy_address(self.recipient)?;
        let _ = evm_to_alloy_address(self.operator)?;
        let payer = evm_to_alloy_address(self.payer)?;
        if evm_to_alloy_address(self.authorized_signer)? != payer {
            return Err(DomainError::InvalidTempoTransactionParams(
                "authorized_signer must equal payer".to_string(),
            ));
        }
        let _ = self.salt()?;
        Ok(())
    }

    fn salt(&self) -> Result<[u8; 32], DomainError> {
        decode_hex_32(self.salt_hex, "tempo session salt")
    }

    fn descriptor(
        &self,
        expiring_nonce_hash: [u8; 32],
    ) -> Result<tip1034::ChannelDescriptor, DomainError> {
        Ok(tip1034::ChannelDescriptor {
            payer: evm_to_alloy_address(self.payer)?,
            payee: evm_to_alloy_address(self.recipient)?,
            operator: evm_to_alloy_address(self.operator)?,
            token: evm_to_alloy_address(self.token)?,
            salt: FixedBytes::<32>::from(self.salt()?),
            authorizedSigner: evm_to_alloy_address(self.authorized_signer)?,
            expiringNonceHash: FixedBytes::<32>::from(expiring_nonce_hash),
        })
    }

    /// `keccak256(abi.encode(payer, payee, operator, token, salt, authorizedSigner,
    /// expiringNonceHash, reserve, chainId))`.
    fn channel_id(&self, expiring_nonce_hash: [u8; 32]) -> Result<[u8; 32], DomainError> {
        let encoded = (
            evm_to_alloy_address(self.payer)?,
            evm_to_alloy_address(self.recipient)?,
            evm_to_alloy_address(self.operator)?,
            evm_to_alloy_address(self.token)?,
            FixedBytes::<32>::from(self.salt()?),
            evm_to_alloy_address(self.authorized_signer)?,
            FixedBytes::<32>::from(expiring_nonce_hash),
            tempo_channel_reserve()?,
            U256::from(self.chain_id),
        )
            .abi_encode_params();
        Ok(keccak256(encoded).0)
    }

    fn ensure_channel_id(
        &self,
        expiring_nonce_hash_hex: &str,
        channel_id_hex: &str,
    ) -> Result<([u8; 32], [u8; 32]), DomainError> {
        let expiring_nonce_hash =
            decode_hex_32(expiring_nonce_hash_hex, "tempo session expiring nonce hash")?;
        let claimed = decode_hex_32(channel_id_hex, "tempo session channel id")?;
        if claimed != self.channel_id(expiring_nonce_hash)? {
            return Err(DomainError::TempoChannelIdMismatch);
        }
        Ok((expiring_nonce_hash, claimed))
    }

    fn eip712_domain(&self) -> Result<Eip712Domain, DomainError> {
        Ok(eip712_domain! {
            name: TEMPO_CHANNEL_RESERVE_DOMAIN_NAME,
            version: TEMPO_CHANNEL_RESERVE_DOMAIN_VERSION,
            chain_id: self.chain_id,
            verifying_contract: tempo_channel_reserve()?,
        })
    }
}

/// Tempo sessions v2 channel-open transaction (`reserve.open`) signed by the payer.
///
/// The open must use an expiring nonce (TIP-1009), because the channel id commits to
/// `expiringNonceHash = keccak256(encodeForSigning(tx) || payer)`. The daemon derives that hash
/// and the channel id from the transaction it signs, so a caller cannot choose either.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct TempoSessionV2OpenTransaction {
    /// Tempo chain ID (4217 mainnet or 42431 testnet).
    pub chain_id: u64,
    /// TIP-20 token contract funding the channel.
    pub token: EvmAddress,
    /// Channel payee / merchant recipient.
    pub recipient: EvmAddress,
    /// Optional relayer allowed to settle for the payee; the zero address when unused.
    pub operator: EvmAddress,
    /// Channel payer; must be the signing wallet.
    pub payer: EvmAddress,
    /// Voucher signer authorized by the channel; must equal `payer`.
    pub authorized_signer: EvmAddress,
    /// Channel salt as `0x`-prefixed 32-byte hex.
    pub salt_hex: String,
    /// Channel deposit in token base units.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub deposit_wei: u128,
    /// Transaction envelope parameters; must use the expiring nonce key.
    pub tx: TempoTxParams,
}

impl TempoSessionV2OpenTransaction {
    fn channel(&self) -> TempoReserveChannel<'_> {
        TempoReserveChannel {
            chain_id: self.chain_id,
            token: &self.token,
            recipient: &self.recipient,
            operator: &self.operator,
            payer: &self.payer,
            authorized_signer: &self.authorized_signer,
            salt_hex: &self.salt_hex,
        }
    }

    /// Validates chain, signer, amount, and expiring-nonce transaction parameters.
    pub fn validate(&self) -> Result<(), DomainError> {
        self.channel().validate()?;
        validate_tempo_reserve_amount(self.deposit_wei)?;
        self.tx.validate()?;
        if self.tx.nonce_key_u256()? != U256::MAX || self.tx.nonce != 0 {
            return Err(DomainError::InvalidTempoTransactionParams(
                "sessions v2 open must use the expiring nonce key (uint256 max) with nonce 0"
                    .to_string(),
            ));
        }
        if self.tx.valid_before.is_none() {
            return Err(DomainError::InvalidTempoTransactionParams(
                "sessions v2 open must set valid_before for its expiring nonce".to_string(),
            ));
        }
        Ok(())
    }

    fn calls(&self) -> Result<Vec<TempoCall>, DomainError> {
        let channel = self.channel();
        Ok(vec![TempoCall {
            to: tempo_channel_reserve()?,
            data: tip1034::openCall {
                payee: evm_to_alloy_address(&self.recipient)?,
                operator: evm_to_alloy_address(&self.operator)?,
                token: evm_to_alloy_address(&self.token)?,
                deposit: tempo_u96(self.deposit_wei)?,
                salt: FixedBytes::<32>::from(channel.salt()?),
                authorizedSigner: evm_to_alloy_address(&self.authorized_signer)?,
            }
            .abi_encode(),
        }])
    }

    /// Returns the ABI-encoded calls in envelope order.
    pub fn encoded_calls(&self) -> Result<Vec<(EvmAddress, Vec<u8>)>, DomainError> {
        self.validate()?;
        encode_calls(self.calls()?)
    }

    /// Returns `keccak256(encodeForSigning(tx) || payer)`, the descriptor's `expiringNonceHash`.
    pub fn expiring_nonce_hash(&self) -> Result<[u8; 32], DomainError> {
        self.validate()?;
        let mut preimage = tempo_sender_signing_preimage(self.chain_id, &self.tx, &self.calls()?)?;
        preimage.extend_from_slice(evm_to_alloy_address(&self.payer)?.as_slice());
        Ok(keccak256(preimage).0)
    }

    /// Returns the channel id this transaction opens.
    pub fn channel_id(&self) -> Result<[u8; 32], DomainError> {
        self.channel().channel_id(self.expiring_nonce_hash()?)
    }

    /// Returns the sender signing digest rebuilt from the structured fields.
    pub fn signing_hash(&self) -> Result<[u8; 32], DomainError> {
        self.validate()?;
        tempo_sender_signing_hash(self.chain_id, &self.tx, &self.calls()?)
    }
}

/// Tempo sessions v2 top-up transaction (`reserve.topUp(descriptor, amount)`) signed by the payer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct TempoSessionV2TopUpTransaction {
    /// Tempo chain ID (4217 mainnet or 42431 testnet).
    pub chain_id: u64,
    /// TIP-20 token contract funding the channel.
    pub token: EvmAddress,
    /// Channel payee / merchant recipient.
    pub recipient: EvmAddress,
    /// Channel operator; the zero address when unused.
    pub operator: EvmAddress,
    /// Channel payer; must be the signing wallet.
    pub payer: EvmAddress,
    /// Voucher signer authorized by the channel; must equal `payer`.
    pub authorized_signer: EvmAddress,
    /// Channel salt as `0x`-prefixed 32-byte hex.
    pub salt_hex: String,
    /// Descriptor `expiringNonceHash` as `0x`-prefixed 32-byte hex.
    pub expiring_nonce_hash_hex: String,
    /// Channel id as `0x`-prefixed 32-byte hex; must match the recomputed id.
    pub channel_id_hex: String,
    /// Incremental additional deposit in token base units.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub additional_deposit_wei: u128,
    /// Transaction envelope parameters.
    pub tx: TempoTxParams,
}

impl TempoSessionV2TopUpTransaction {
    fn channel(&self) -> TempoReserveChannel<'_> {
        TempoReserveChannel {
            chain_id: self.chain_id,
            token: &self.token,
            recipient: &self.recipient,
            operator: &self.operator,
            payer: &self.payer,
            authorized_signer: &self.authorized_signer,
            salt_hex: &self.salt_hex,
        }
    }

    /// Validates chain, signer, channel id, amount, and transaction parameters.
    pub fn validate(&self) -> Result<(), DomainError> {
        let channel = self.channel();
        channel.validate()?;
        let _ = channel.ensure_channel_id(&self.expiring_nonce_hash_hex, &self.channel_id_hex)?;
        validate_tempo_reserve_amount(self.additional_deposit_wei)?;
        self.tx.validate()
    }

    /// Parses the channel id as a strict 32-byte value.
    pub fn channel_id_bytes32(&self) -> Result<[u8; 32], DomainError> {
        decode_hex_32(&self.channel_id_hex, "tempo session channel id")
    }

    fn calls(&self) -> Result<Vec<TempoCall>, DomainError> {
        let channel = self.channel();
        let (expiring_nonce_hash, _) =
            channel.ensure_channel_id(&self.expiring_nonce_hash_hex, &self.channel_id_hex)?;
        Ok(vec![TempoCall {
            to: tempo_channel_reserve()?,
            data: tip1034::topUpCall {
                descriptor: channel.descriptor(expiring_nonce_hash)?,
                additionalDeposit: tempo_u96(self.additional_deposit_wei)?,
            }
            .abi_encode(),
        }])
    }

    /// Returns the ABI-encoded calls in envelope order.
    pub fn encoded_calls(&self) -> Result<Vec<(EvmAddress, Vec<u8>)>, DomainError> {
        self.validate()?;
        encode_calls(self.calls()?)
    }

    /// Returns the sender signing digest rebuilt from the structured fields.
    pub fn signing_hash(&self) -> Result<[u8; 32], DomainError> {
        self.validate()?;
        tempo_sender_signing_hash(self.chain_id, &self.tx, &self.calls()?)
    }
}

/// Tempo sessions v2 voucher (EIP-712 `Voucher(bytes32 channelId,uint96 cumulativeAmount)` on the
/// reserve domain). Its fields are shared with [`TempoSessionV2CloseAuthorization`].
///
/// A voucher moves funds that already left the wallet through a policy-checked
/// open or top-up, so it is an escrow redistribution rather than a new spend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct TempoSessionV2Voucher {
    /// Tempo chain ID (4217 mainnet or 42431 testnet).
    pub chain_id: u64,
    /// TIP-20 token contract used by the channel.
    pub token: EvmAddress,
    /// Channel payee / merchant recipient.
    pub recipient: EvmAddress,
    /// Channel operator; the zero address when unused.
    pub operator: EvmAddress,
    /// Channel payer; must be the signing wallet.
    pub payer: EvmAddress,
    /// Voucher signer authorized by the channel; must equal `payer`.
    pub authorized_signer: EvmAddress,
    /// Channel salt as `0x`-prefixed 32-byte hex.
    pub salt_hex: String,
    /// Descriptor `expiringNonceHash` as `0x`-prefixed 32-byte hex.
    pub expiring_nonce_hash_hex: String,
    /// Channel id as `0x`-prefixed 32-byte hex; must match the recomputed id.
    pub channel_id_hex: String,
    /// Full cumulative amount being signed.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub cumulative_amount_wei: u128,
}

impl TempoSessionV2Voucher {
    fn channel(&self) -> TempoReserveChannel<'_> {
        TempoReserveChannel {
            chain_id: self.chain_id,
            token: &self.token,
            recipient: &self.recipient,
            operator: &self.operator,
            payer: &self.payer,
            authorized_signer: &self.authorized_signer,
            salt_hex: &self.salt_hex,
        }
    }

    /// Validates chain, signer, channel id, and amount.
    pub fn validate(&self) -> Result<(), DomainError> {
        let channel = self.channel();
        channel.validate()?;
        let _ = channel.ensure_channel_id(&self.expiring_nonce_hash_hex, &self.channel_id_hex)?;
        validate_tempo_reserve_amount(self.cumulative_amount_wei)
    }

    /// Parses the channel id as a strict 32-byte value.
    pub fn channel_id_bytes32(&self) -> Result<[u8; 32], DomainError> {
        decode_hex_32(&self.channel_id_hex, "tempo session channel id")
    }

    /// Returns the TIP-1034 reserve EIP-712 domain.
    pub fn eip712_domain(&self) -> Result<Eip712Domain, DomainError> {
        self.channel().eip712_domain()
    }

    /// Returns the EIP-712 `Voucher(bytes32 channelId,uint96 cumulativeAmount)` digest.
    pub fn signing_hash(&self) -> Result<[u8; 32], DomainError> {
        self.validate()?;
        let voucher = tip1034::Voucher {
            channelId: FixedBytes::<32>::from(self.channel_id_bytes32()?),
            cumulativeAmount: tempo_u96(self.cumulative_amount_wei)?,
        };
        Ok(voucher.eip712_signing_hash(&self.eip712_domain()?).0)
    }
}

/// Tempo sessions v2 cooperative close authorization
/// (EIP-712 `CloseAuthorization(bytes32 channelId,uint96 cumulativeAmount)` on the reserve domain).
///
/// Like a voucher, it only redistributes funds already deposited into the channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct TempoSessionV2CloseAuthorization {
    /// Channel and final cumulative amount being authorized.
    #[serde(flatten)]
    pub voucher: TempoSessionV2Voucher,
}

impl TempoSessionV2CloseAuthorization {
    /// Validates chain, signer, channel id, and amount.
    pub fn validate(&self) -> Result<(), DomainError> {
        self.voucher.validate()
    }

    /// Returns the EIP-712 close-authorization digest.
    pub fn signing_hash(&self) -> Result<[u8; 32], DomainError> {
        self.validate()?;
        let authorization = tip1034::CloseAuthorization {
            channelId: FixedBytes::<32>::from(self.voucher.channel_id_bytes32()?),
            cumulativeAmount: tempo_u96(self.voucher.cumulative_amount_wei)?,
        };
        Ok(authorization
            .eip712_signing_hash(&self.voucher.eip712_domain()?)
            .0)
    }
}
