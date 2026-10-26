use alloy_primitives::Address;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::DomainError;

/// Canonical lower-case EVM address (`0x` + 40 hex chars).
///
/// Mixed-case inputs must satisfy the EIP-55 checksum.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct EvmAddress(String);

impl EvmAddress {
    /// Returns the normalized address string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn new_unchecked(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl Display for EvmAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for EvmAddress {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let payload = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .ok_or(DomainError::InvalidAddress)?;

        if payload.len() != 40 || !payload.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(DomainError::InvalidAddress);
        }

        let prefixed = format!("0x{payload}");
        if is_mixed_case_hex(payload) {
            Address::parse_checksummed(&prefixed, None).map_err(|_| DomainError::InvalidAddress)?;
        }

        Ok(Self(prefixed.to_ascii_lowercase()))
    }
}

impl<'de> Deserialize<'de> for EvmAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

/// Bech32 data-part alphabet (BIP-173); Railgun `0zk` addresses are bech32m.
const BECH32_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/// Railgun human-readable part `0zk` followed by the bech32 separator `1`.
const RAILGUN_ADDRESS_PREFIX: &str = "0zk1";

/// Canonical lower-case Railgun shielded-pool address (`0zk1...` bech32m).
///
/// Railgun encodes the spending + viewing public keys into a single address
/// prefixed with `0zk1`. Full bech32m decoding and key parsing happens inside
/// the Railgun-aware signer backend; the domain layer normalizes case (bech32
/// is case-insensitive) and enforces the prefix, length, and data-part
/// alphabet so policy scope matching compares one canonical spelling.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct RailgunAddress(String);

impl RailgunAddress {
    /// Returns the normalized address string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for RailgunAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for RailgunAddress {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.trim().to_ascii_lowercase();
        let data_part = normalized
            .strip_prefix(RAILGUN_ADDRESS_PREFIX)
            .ok_or(DomainError::InvalidRailgunAddress)?;
        // Railgun addresses are ~127 chars; keep the bound loose to allow
        // protocol evolution while rejecting obviously malformed input.
        if normalized.len() < 32 || normalized.len() > 256 {
            return Err(DomainError::InvalidRailgunAddress);
        }
        if data_part.is_empty() || !data_part.chars().all(|c| BECH32_CHARSET.contains(c)) {
            return Err(DomainError::InvalidRailgunAddress);
        }
        Ok(Self(normalized))
    }
}

impl<'de> Deserialize<'de> for RailgunAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

/// Canonical Solana address as base58-encoded 32-byte pubkey.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct SolanaAddress(String);

impl SolanaAddress {
    /// Returns the normalized address string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the decoded 32-byte pubkey bytes.
    pub fn to_bytes(&self) -> Result<[u8; 32], DomainError> {
        let decoded = bs58::decode(&self.0)
            .into_vec()
            .map_err(|_| DomainError::InvalidSolanaAddress)?;
        <[u8; 32]>::try_from(decoded.as_slice()).map_err(|_| DomainError::InvalidSolanaAddress)
    }
}

impl Display for SolanaAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SolanaAddress {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.trim();
        if normalized.is_empty() {
            return Err(DomainError::InvalidSolanaAddress);
        }
        let decoded = bs58::decode(normalized)
            .into_vec()
            .map_err(|_| DomainError::InvalidSolanaAddress)?;
        if decoded.len() != 32 {
            return Err(DomainError::InvalidSolanaAddress);
        }
        Ok(Self(normalized.to_string()))
    }
}

impl<'de> Deserialize<'de> for SolanaAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

/// Recipient scope identifier that can target multiple chain families.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum RecipientId {
    Evm(EvmAddress),
    Solana(SolanaAddress),
    Railgun(RailgunAddress),
}

#[derive(Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum RecipientIdTagged {
    Evm(EvmAddress),
    Solana(SolanaAddress),
    Railgun(RailgunAddress),
}

impl<'de> Deserialize<'de> for RecipientId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RecipientIdVisitor;

        impl<'de> Visitor<'de> for RecipientIdVisitor {
            type Value = RecipientId;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an EVM/Solana recipient string or a tagged recipient object")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                RecipientId::from_str(value).map_err(E::custom)
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&value)
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let tagged = RecipientIdTagged::deserialize(
                    serde::de::value::MapAccessDeserializer::new(map),
                )?;
                Ok(match tagged {
                    RecipientIdTagged::Evm(address) => RecipientId::Evm(address),
                    RecipientIdTagged::Solana(address) => RecipientId::Solana(address),
                    RecipientIdTagged::Railgun(address) => RecipientId::Railgun(address),
                })
            }
        }

        deserializer.deserialize_any(RecipientIdVisitor)
    }
}

impl Display for RecipientId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Evm(address) => Display::fmt(address, f),
            Self::Solana(address) => Display::fmt(address, f),
            Self::Railgun(address) => Display::fmt(address, f),
        }
    }
}

impl From<EvmAddress> for RecipientId {
    fn from(value: EvmAddress) -> Self {
        Self::Evm(value)
    }
}

impl From<SolanaAddress> for RecipientId {
    fn from(value: SolanaAddress) -> Self {
        Self::Solana(value)
    }
}

impl From<RailgunAddress> for RecipientId {
    fn from(value: RailgunAddress) -> Self {
        Self::Railgun(value)
    }
}

impl FromStr for RecipientId {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(address) = EvmAddress::from_str(s) {
            return Ok(Self::Evm(address));
        }
        if let Ok(address) = RailgunAddress::from_str(s) {
            return Ok(Self::Railgun(address));
        }
        Ok(Self::Solana(SolanaAddress::from_str(s)?))
    }
}

impl PartialEq<EvmAddress> for RecipientId {
    fn eq(&self, other: &EvmAddress) -> bool {
        matches!(self, Self::Evm(address) if address == other)
    }
}

impl PartialEq<RecipientId> for EvmAddress {
    fn eq(&self, other: &RecipientId) -> bool {
        other == self
    }
}

impl PartialEq<SolanaAddress> for RecipientId {
    fn eq(&self, other: &SolanaAddress) -> bool {
        matches!(self, Self::Solana(address) if address == other)
    }
}

impl PartialEq<RecipientId> for SolanaAddress {
    fn eq(&self, other: &RecipientId) -> bool {
        other == self
    }
}

impl PartialEq<RailgunAddress> for RecipientId {
    fn eq(&self, other: &RailgunAddress) -> bool {
        matches!(self, Self::Railgun(address) if address == other)
    }
}

impl PartialEq<RecipientId> for RailgunAddress {
    fn eq(&self, other: &RecipientId) -> bool {
        other == self
    }
}

fn is_mixed_case_hex(value: &str) -> bool {
    let has_lower = value.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = value.chars().any(|c| c.is_ascii_uppercase());

    has_lower && has_upper
}
