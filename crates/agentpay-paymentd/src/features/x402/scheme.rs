//! The exact EIP-3009 scheme for x402 v1 and v2, implemented on
//! `x402-types`' open client traits ([`X402SchemeClient`],
//! [`PaymentCandidateSigner`]) with every signature coming from the signer
//! daemon's policy-checked `Eip3009TransferWithAuthorization` action. No key
//! ever exists in this process.

use std::sync::{Arc, Mutex};

use agentpay_domain::{Eip3009Transfer, EvmAddress};
use alloy_primitives::{B256, U256};
use async_trait::async_trait;
use base64::Engine;
use serde_json::{json, Value};
use x402_types::chain::ChainId;
use x402_types::proto;
use x402_types::scheme::client::{
    PaymentCandidate, PaymentCandidateSigner, PaymentSelector, X402Error, X402SchemeClient,
};
use x402_types::scheme::X402SchemeId;

use super::requirements::{requirements, Echo, Requirement};
use crate::chains::evm::evm_address;
use crate::error::PaymentsError;
use crate::features::eip3009;
use crate::features::payer::{unix_now, ErrorSlot, Payer};

/// How far back `validAfter` reaches, as the x402 reference clients set it.
const VALID_AFTER_SKEW_SECS: u64 = 600;
/// Bounds on the authorization's lifetime (`maxTimeoutSeconds`).
const MIN_VALIDITY_SECS: u64 = 30;
const MAX_VALIDITY_SECS: u64 = 3600;

/// What was signed, for the result.
#[derive(Debug, Clone)]
pub(super) struct Signed {
    pub(super) requirement: Requirement,
    pub(super) from: EvmAddress,
    pub(super) valid_after: u64,
    pub(super) valid_before: u64,
    pub(super) nonce_hex: String,
}

/// Shared between the scheme client, its candidate signers, and the handler.
#[derive(Clone, Default)]
pub(super) struct Outcome {
    pub(super) error: ErrorSlot,
    pub(super) signed: Arc<Mutex<Option<Signed>>>,
}

impl Outcome {
    pub(super) fn take_signed(&self) -> Option<Signed> {
        self.signed.lock().ok().and_then(|mut signed| signed.take())
    }
}

/// The exact EIP-3009 scheme client for one x402 version.
pub(super) struct ExactEip3009 {
    version: u8,
    payer: Payer,
    outcome: Outcome,
}

impl ExactEip3009 {
    pub(super) fn new(version: u8, payer: Payer, outcome: Outcome) -> Self {
        Self {
            version,
            payer,
            outcome,
        }
    }
}

impl X402SchemeId for ExactEip3009 {
    fn x402_version(&self) -> u8 {
        self.version
    }

    fn namespace(&self) -> &str {
        "eip155"
    }

    fn scheme(&self) -> &str {
        "exact"
    }
}

#[async_trait]
impl X402SchemeClient for ExactEip3009 {
    fn accept(&self, payment_required: &proto::PaymentRequired) -> Vec<PaymentCandidate> {
        let version = match payment_required {
            proto::PaymentRequired::V1(_) => 1,
            proto::PaymentRequired::V2(_) => 2,
        };
        if version != self.version {
            return Vec::new();
        }
        let (all, echo) = requirements(payment_required);
        all.into_iter()
            .filter_map(Result::ok)
            .map(|requirement| PaymentCandidate {
                chain_id: ChainId::new("eip155", requirement.chain_id.to_string()),
                asset: requirement.asset.to_string(),
                amount: U256::from(requirement.amount),
                scheme: requirement.scheme.clone(),
                x402_version: requirement.version,
                pay_to: requirement.pay_to.to_string(),
                signer: Box::new(CandidateSigner {
                    requirement,
                    echo: echo.clone(),
                    payer: self.payer.clone(),
                    outcome: self.outcome.clone(),
                }),
            })
            .collect()
    }
}

/// Picks the first candidate within the caller's amount limits.
pub(super) struct WithinLimits {
    pub(super) expected_amount: Option<u128>,
    pub(super) max_amount: Option<u128>,
}

impl WithinLimits {
    /// Why `amount` is refused, if it is.
    pub(super) fn refusal(&self, amount: U256) -> Option<String> {
        if let Some(expected) = self.expected_amount {
            if amount != U256::from(expected) {
                return Some(format!(
                    "the requirement asks for {amount} base units, not the expected {expected}"
                ));
            }
        }
        match self.max_amount {
            Some(max) if amount > U256::from(max) => Some(format!(
                "the requirement asks for {amount} base units, above max_amount {max}"
            )),
            _ => None,
        }
    }
}

impl PaymentSelector for WithinLimits {
    fn select<'a>(&self, candidates: &'a [PaymentCandidate]) -> Option<&'a PaymentCandidate> {
        candidates
            .iter()
            .find(|candidate| self.refusal(candidate.amount).is_none())
    }
}

/// Signs one requirement through the signer daemon.
struct CandidateSigner {
    requirement: Requirement,
    echo: Echo,
    payer: Payer,
    outcome: Outcome,
}

#[async_trait]
impl PaymentCandidateSigner for CandidateSigner {
    async fn sign_payment(&self) -> Result<String, X402Error> {
        match self.sign().await {
            Ok(header) => Ok(header),
            Err(error) => {
                let message = error.to_string();
                self.outcome.error.put(error);
                Err(X402Error::SigningError(message))
            }
        }
    }
}

impl CandidateSigner {
    async fn sign(&self) -> Result<String, PaymentsError> {
        let requirement = &self.requirement;
        let now = unix_now();
        let validity = requirement
            .max_timeout_seconds
            .clamp(MIN_VALIDITY_SECS, MAX_VALIDITY_SECS);
        let valid_after = now.saturating_sub(VALID_AFTER_SKEW_SECS);
        let valid_before = now + validity;
        let nonce = B256::from(rand::random::<[u8; 32]>());
        let from = evm_address(self.payer.wallet)?;
        let authorization = Eip3009Transfer {
            chain_id: requirement.chain_id,
            token: requirement.asset.clone(),
            token_name: requirement.token_name.clone(),
            token_version: requirement.token_version.clone(),
            from: from.clone(),
            to: requirement.pay_to.clone(),
            amount_wei: requirement.amount,
            valid_after,
            valid_before,
            nonce_hex: format!("{nonce:#x}"),
        };
        let signature = eip3009::sign(&self.payer, &authorization).await?;
        let payload = json!({
            "signature": signature,
            "authorization": {
                "from": from.to_string(),
                "to": requirement.pay_to.to_string(),
                "value": requirement.amount.to_string(),
                "validAfter": valid_after.to_string(),
                "validBefore": valid_before.to_string(),
                "nonce": authorization.nonce_hex,
            },
        });
        let message = match requirement.version {
            1 => json!({
                "x402Version": 1,
                "scheme": requirement.scheme,
                "network": requirement.network,
                "payload": payload,
            }),
            _ => {
                let accepted: Value = serde_json::from_str(requirement.original.get())
                    .map_err(|_| PaymentsError::Internal("the requirement is not JSON".into()))?;
                let mut message = json!({
                    "x402Version": 2,
                    "payload": payload,
                    "accepted": accepted,
                });
                if let Some(resource) = &self.echo.resource {
                    message["resource"] = resource.clone();
                }
                if let Some(extensions) = &self.echo.extensions {
                    message["extensions"] = extensions.clone();
                }
                message
            }
        };
        if let Ok(mut signed) = self.outcome.signed.lock() {
            *signed = Some(Signed {
                requirement: requirement.clone(),
                from,
                valid_after,
                valid_before,
                nonce_hex: authorization.nonce_hex.clone(),
            });
        }
        Ok(base64::engine::general_purpose::STANDARD.encode(message.to_string()))
    }
}
