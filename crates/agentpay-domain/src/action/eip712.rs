//! Arbitrary EIP-712 typed-data payloads.

use alloy_dyn_abi::eip712::TypedData;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::encoding::alloy_address_to_evm;
use crate::{DomainError, EvmAddress};

/// Arbitrary EIP-712 typed data payload signed through daemon policy checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
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
