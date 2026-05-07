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
}

#[derive(Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum RecipientIdTagged {
    Evm(EvmAddress),
    Solana(SolanaAddress),
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

impl FromStr for RecipientId {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(address) = EvmAddress::from_str(s) {
            return Ok(Self::Evm(address));
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

fn is_mixed_case_hex(value: &str) -> bool {
    let has_lower = value.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = value.chars().any(|c| c.is_ascii_uppercase());

    has_lower && has_upper
}
