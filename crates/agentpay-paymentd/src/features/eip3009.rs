//! EIP-3009 `transferWithAuthorization` signatures, shared by x402 (`exact`
//! scheme) and MPP (`evm` / `arbitrum` charge, `authorization` credential).
//!
//! The signer daemon signs the policy-checked
//! `Eip3009TransferWithAuthorization` action (the spend is recorded there);
//! this module recomputes the EIP-712 digest with its own type definition and
//! refuses a signature that does not recover to the agent's wallet.

use agentpay_domain::{AgentAction, Eip3009Transfer, EvmAddress};
use alloy_primitives::{hex, Address, B256, U256};
use alloy_sol_types::{eip712_domain, sol, SolStruct};

use crate::chains::evm::to_alloy_address;
use crate::error::PaymentsError;
use crate::features::payer::{ensure_signed_by, recoverable, rsv_bytes, Payer};

sol! {
    /// EIP-3009 `TransferWithAuthorization`, recomputed here independently
    /// of the signer daemon to check its signature.
    struct TransferWithAuthorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }
}

/// Signs `authorization` as the payer's agent and returns the 65-byte
/// `r ‖ s ‖ v` signature (`v` = 27 or 28), `0x`-prefixed hex, after checking
/// that it recovers to the payer's wallet.
pub(crate) async fn sign(
    payer: &Payer,
    authorization: &Eip3009Transfer,
) -> Result<String, PaymentsError> {
    let answer = payer
        .signer()
        .sign(
            AgentAction::Eip3009TransferWithAuthorization {
                authorization: authorization.clone(),
            },
            payer.wait,
        )
        .await?;
    let signature = recoverable(&answer)?;
    ensure_signed_by(
        &signature,
        transfer_digest(authorization)?,
        payer.wallet,
        "EIP-3009 authorization",
    )?;
    Ok(format!("0x{}", hex::encode(rsv_bytes(&signature))))
}

/// The EIP-712 digest of `transferWithAuthorization`, computed with this
/// crate's own type definition.
pub(crate) fn transfer_digest(authorization: &Eip3009Transfer) -> Result<B256, PaymentsError> {
    let address =
        |value: &EvmAddress| -> Result<Address, PaymentsError> { to_alloy_address(value) };
    let nonce = authorization
        .nonce_hex
        .strip_prefix("0x")
        .and_then(|digits| hex::decode(digits).ok())
        .filter(|bytes| bytes.len() == 32)
        .map(|bytes| B256::from_slice(&bytes))
        .ok_or_else(|| PaymentsError::Internal("the authorization nonce is malformed".into()))?;
    let message = TransferWithAuthorization {
        from: address(&authorization.from)?,
        to: address(&authorization.to)?,
        value: U256::from(authorization.amount_wei),
        validAfter: U256::from(authorization.valid_after),
        validBefore: U256::from(authorization.valid_before),
        nonce,
    };
    let token = address(&authorization.token)?;
    let domain = match authorization
        .token_version
        .as_deref()
        .filter(|v| !v.is_empty())
    {
        Some(version) => eip712_domain! {
            name: authorization.token_name.clone(),
            version: version.to_string(),
            chain_id: authorization.chain_id,
            verifying_contract: token,
        },
        None => eip712_domain! {
            name: authorization.token_name.clone(),
            chain_id: authorization.chain_id,
            verifying_contract: token,
        },
    };
    Ok(message.eip712_signing_hash(&domain))
}
