//! [`Payer`]: what a paid-HTTP flow (`X402Fetch`, `MppFetch`, the paying
//! proxy) needs to pay as one agent, owned so it can outlive a single
//! request; and checks of the signatures the signer daemon returns.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use agentpay_api::payments::PaymentsConfig;
use agentpay_api::AgentAuth;
use agentpay_domain::Signature;
use alloy_primitives::{Address, B256, U256};
use uuid::Uuid;

use super::mpp::SessionLocks;
use crate::auth::AuthenticatedAgent;
use crate::chains::evm::{to_alloy_address, EvmProvider};
use crate::chains::solana::SolanaProvider;
use crate::error::PaymentsError;
use crate::signer::{AgentSigner, ApprovalWait, SignerClient};
use crate::state::AppState;

/// One agent's paying context.
#[derive(Clone)]
pub(crate) struct Payer {
    /// The signer daemon.
    pub(crate) signer: Arc<dyn SignerClient>,
    /// The agent's credentials (wiped when the last copy drops).
    pub(crate) auth: AgentAuth,
    /// The agent's EVM wallet.
    pub(crate) wallet: Address,
    /// A configuration snapshot.
    pub(crate) config: PaymentsConfig,
    /// EVM RPC access.
    pub(crate) evm: Arc<EvmProvider>,
    /// The agent's Solana wallet, when its key can sign for Solana.
    pub(crate) solana_wallet: Option<solana_sdk::pubkey::Pubkey>,
    /// Solana RPC access, when the service has it.
    pub(crate) solana: Option<Arc<SolanaProvider>>,
    /// The service's state directory (persisted MPP sessions live here).
    pub(crate) state_dir: PathBuf,
    /// Serializes calls that share an MPP session.
    pub(crate) sessions: Arc<SessionLocks>,
    /// How long a signature may wait for an operator.
    pub(crate) wait: ApprovalWait,
}

impl Payer {
    /// The paying context of the authenticated `agent`, waiting up to
    /// `approval_wait_secs` (default 0, capped at 600) for operators.
    pub(crate) async fn new(
        state: &AppState,
        agent: &AuthenticatedAgent,
        approval_wait_secs: Option<u64>,
    ) -> Result<Self, PaymentsError> {
        let address = agent.identity.evm_address.as_ref().ok_or_else(|| {
            PaymentsError::InvalidRequest("the agent's key cannot sign EVM payments".into())
        })?;
        let state_dir = state
            .config
            .path()
            .parent()
            .map(PathBuf::from)
            .ok_or_else(|| PaymentsError::Internal("the state directory is unknown".into()))?;
        Ok(Self {
            signer: state.signer.clone(),
            auth: agent.credentials.clone(),
            wallet: to_alloy_address(address)?,
            config: state.config.get().await,
            evm: state.chains.get::<EvmProvider>()?,
            solana_wallet: agent
                .identity
                .solana_address
                .as_ref()
                .and_then(|address| address.to_bytes().ok())
                .map(solana_sdk::pubkey::Pubkey::new_from_array),
            solana: state.chains.get::<SolanaProvider>().ok(),
            state_dir,
            sessions: state.mpp_sessions.clone(),
            wait: ApprovalWait::up_to(Duration::from_secs(approval_wait_secs.unwrap_or(0))),
        })
    }

    /// Signer daemon operations as this agent.
    pub(crate) fn signer(&self) -> AgentSigner<'_> {
        AgentSigner::new(self.signer.as_ref(), &self.auth)
    }

    /// The agent key id.
    pub(crate) fn agent_key_id(&self) -> Uuid {
        self.auth.agent_key_id
    }
}

/// The recoverable ECDSA signature in a signer daemon answer.
pub(crate) fn recoverable(
    signature: &Signature,
) -> Result<alloy_primitives::Signature, PaymentsError> {
    let incomplete = || {
        PaymentsError::SignerUnavailable(
            "the signer daemon returned an incomplete signature".into(),
        )
    };
    let scalar = |value: &Option<String>| {
        value
            .as_deref()
            .and_then(|hex| hex.strip_prefix("0x"))
            .filter(|digits| digits.len() == 64)
            .and_then(|digits| U256::from_str_radix(digits, 16).ok())
            .ok_or_else(incomplete)
    };
    let y_parity = match signature.v {
        Some(0 | 27) => false,
        Some(1 | 28) => true,
        _ => return Err(incomplete()),
    };
    Ok(alloy_primitives::Signature::new(
        scalar(&signature.r_hex)?,
        scalar(&signature.s_hex)?,
        y_parity,
    ))
}

/// Fails with `SignedTransactionMismatch` unless `signature` over `digest`
/// recovers to `wallet`. `what` names the signed object in the error.
pub(crate) fn ensure_signed_by(
    signature: &alloy_primitives::Signature,
    digest: B256,
    wallet: Address,
    what: &str,
) -> Result<(), PaymentsError> {
    match signature.recover_address_from_prehash(&digest) {
        Ok(signer) if signer == wallet => Ok(()),
        _ => Err(PaymentsError::SignedTransactionMismatch(format!(
            "the {what} signature does not recover to the agent's wallet over the expected digest"
        ))),
    }
}

/// `r || s || v` with `v` = 27 or 28, the form EIP-3009 and x402 use.
pub(crate) fn rsv_bytes(signature: &alloy_primitives::Signature) -> [u8; 65] {
    let mut bytes = [0_u8; 65];
    bytes[..32].copy_from_slice(&signature.r().to_be_bytes::<32>());
    bytes[32..64].copy_from_slice(&signature.s().to_be_bytes::<32>());
    bytes[64] = 27 + u8::from(signature.v());
    bytes
}

/// Seconds since the Unix epoch.
pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// A stash for the typed error of a callback whose interface (x402 or
/// `mpp` traits) only carries strings, so the handler can report it as
/// the original [`PaymentsError`].
#[derive(Clone, Default)]
pub(crate) struct ErrorSlot(Arc<std::sync::Mutex<Option<PaymentsError>>>);

impl ErrorSlot {
    /// Keeps the first error.
    pub(crate) fn put(&self, error: PaymentsError) {
        if let Ok(mut slot) = self.0.lock() {
            slot.get_or_insert(error);
        }
    }

    /// Takes the stashed error, if any.
    pub(crate) fn take(&self) -> Option<PaymentsError> {
        self.0.lock().ok().and_then(|mut slot| slot.take())
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::keccak256;

    use super::*;

    #[test]
    fn signer_answers_convert_and_verify() {
        // A fixed secp256k1 signature over keccak256("x") by a known key.
        let key = k256::ecdsa::SigningKey::from_slice(&[7_u8; 32]).expect("key");
        let digest = keccak256(b"x");
        let (sig, recovery) = key
            .sign_prehash_recoverable(digest.as_slice())
            .expect("sign");
        let bytes = sig.to_bytes();
        let answer = Signature {
            r_hex: Some(format!("0x{}", alloy_primitives::hex::encode(&bytes[..32]))),
            s_hex: Some(format!("0x{}", alloy_primitives::hex::encode(&bytes[32..]))),
            v: Some(u64::from(recovery.to_byte())),
            ..Signature::default()
        };
        let signature = recoverable(&answer).expect("recoverable");
        let wallet = signature
            .recover_address_from_prehash(&digest)
            .expect("recover");
        ensure_signed_by(&signature, digest, wallet, "test").expect("verifies");
        assert!(ensure_signed_by(&signature, keccak256(b"y"), wallet, "test").is_err());
        assert_eq!(rsv_bytes(&signature)[64], 27 + recovery.to_byte());

        let mut missing = answer.clone();
        missing.v = None;
        assert!(recoverable(&missing).is_err());
    }
}
