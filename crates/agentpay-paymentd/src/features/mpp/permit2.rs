//! The `permit2` credential of an `evm` or `arbitrum` charge: a Permit2
//! `SignatureTransfer` permit with an MPP payment witness, which the
//! merchant redeems (so the agent pays no gas for the payment itself).
//!
//! Permit2 pulls the tokens through an ERC-20 allowance, so the first
//! payment in a token on a chain sends one `approve(Permit2, max)` from the
//! wallet (gas, once), after the permit itself has passed the agent's
//! policies, so a refused payment never spends gas. The signer daemon exempts that approval from spending
//! limits: Permit2 moves nothing without a signed permit, and every permit
//! is a policy-checked `Permit2WitnessTransfer` action.
//!
//! The two SDKs build the permit differently:
//!
//! | | `evm` (`@bnb-chain/mpp`) | `arbitrum` (`@arbitrum/mpp`) |
//! |---|---|---|
//! | spender | `methodDetails.permit2Spender` | the recipient |
//! | witness | `{challengeHash, externalId}` | `{challengeHash}` |
//! | `challengeHash` | `keccak256(id ‖ realm)` | over id, realm, and the transfers |
//! | nonce | random | the challenge hash |

use agentpay_domain::{
    AgentAction, EvmAddress, Permit2Permission, Permit2Witness, Permit2WitnessTransfer,
    PERMIT2_ADDRESS,
};
use alloy_primitives::{hex, keccak256, Address, B256, U256};
use alloy_sol_types::{sol, SolCall};
use mpp::protocol::core::{PaymentChallenge, PaymentCredential};
use serde_json::{json, Value};

use super::charge::Charged;
use super::evm_charge::EvmCharge;
use super::evm_tx::{self, Delivery};
use crate::chains::evm::{to_alloy_address, EvmRpc};
use crate::error::PaymentsError;
use crate::features::payer::{ensure_signed_by, recoverable, rsv_bytes, unix_now, Payer};

sol! {
    function approve(address spender, uint256 value) returns (bool);
}

/// How long a permit stays valid at most.
const MAX_PERMIT_SECS: u64 = 600;

/// Which SDK's permit the merchant expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Flavour {
    /// `evm`: the merchant's settlement signer redeems the permit.
    Evm {
        spender: EvmAddress,
        /// The request's `externalId`, or `""`.
        external_id: String,
    },
    /// `arbitrum`: the recipient redeems the permit.
    Arbitrum,
}

/// One transfer the permit pays, with the recipient spelled exactly as the
/// challenge spells it (the `arbitrum` challenge hash covers the text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Transfer {
    pub(super) to: String,
    pub(super) amount: u128,
}

/// The canonical Permit2 address.
pub(super) fn permit2_address() -> Result<Address, PaymentsError> {
    PERMIT2_ADDRESS
        .parse()
        .map_err(|_| PaymentsError::Internal("the Permit2 address is malformed".into()))
}

/// `@arbitrum/mpp`'s challenge hash: `keccak256(abi.encodePacked(string id,
/// string realm, string[] tos, uint256[] amounts))`, where packed strings are
/// their UTF-8 bytes and packed `uint256` array elements are 32 bytes each.
pub(super) fn arbitrum_challenge_hash(id: &str, realm: &str, transfers: &[Transfer]) -> B256 {
    let mut packed = Vec::new();
    packed.extend_from_slice(id.as_bytes());
    packed.extend_from_slice(realm.as_bytes());
    for transfer in transfers {
        packed.extend_from_slice(transfer.to.as_bytes());
    }
    for transfer in transfers {
        packed.extend_from_slice(&U256::from(transfer.amount).to_be_bytes::<32>());
    }
    keccak256(packed)
}

/// `approve(Permit2, max)` calldata.
fn approve_permit2() -> Result<Vec<u8>, PaymentsError> {
    Ok(approveCall {
        spender: permit2_address()?,
        value: U256::from(u128::MAX),
    }
    .abi_encode())
}

/// Whether the wallet's allowance for Permit2 is below the charge, so the
/// payment needs the one-time approval. Reads only.
async fn needs_approval(
    payer: &Payer,
    rpc: &EvmRpc,
    charge: &EvmCharge,
) -> Result<bool, PaymentsError> {
    let token = to_alloy_address(&charge.currency)?;
    let allowance = rpc
        .erc20_allowance(token, payer.wallet, permit2_address()?)
        .await?;
    Ok(allowance < U256::from(charge.amount))
}

/// Sends the one-time `approve(Permit2, max)` after the permit was signed. A
/// failure says so: the permit was signed (and counted) but never sent.
async fn approve(
    payer: &Payer,
    rpc: &EvmRpc,
    network: &str,
    charge: &EvmCharge,
) -> Result<(), PaymentsError> {
    let sent = evm_tx::sign_call(
        payer,
        rpc,
        network,
        charge.chain_id,
        &charge.currency,
        approve_permit2()?,
        Delivery::Send,
    )
    .await
    .map_err(|error| {
        let after = |reason: &str| {
            format!(
                "the Permit2 approval failed: {}; the signed permit was not sent and the \
                 merchant was not paid",
                reason.trim_end_matches("; nothing was signed")
            )
        };
        match error {
            PaymentsError::InvalidRequest(reason) => PaymentsError::InvalidRequest(after(&reason)),
            PaymentsError::ChainRpc(reason) => PaymentsError::ChainRpc(after(&reason)),
            other => other,
        }
    })?;
    tracing::info!(
        network,
        tx = %sent.hash,
        "approved Permit2 for the token (once per token and chain)"
    );
    Ok(())
}

/// Pays `charge` (from `challenge`) with a Permit2 permit for `flavour`.
pub(super) async fn pay(
    payer: &Payer,
    rpc: &EvmRpc,
    network: &str,
    challenge: &PaymentChallenge,
    charge: &EvmCharge,
    flavour: &Flavour,
) -> Result<Charged, PaymentsError> {
    let now = unix_now();
    let latest = now + MAX_PERMIT_SECS;
    let deadline = charge.expires.map_or(latest, |at| at.min(latest));
    if deadline <= now {
        return Err(PaymentsError::InvalidRequest(
            "the challenge has expired; nothing was signed".into(),
        ));
    }

    // Read-only checks first, so a payment that cannot go through signs
    // nothing: the approval's gas, when one is needed.
    let approval = needs_approval(payer, rpc, charge).await?;
    if approval {
        evm_tx::check_gas(
            payer,
            rpc,
            network,
            charge.chain_id,
            &charge.currency,
            approve_permit2()?,
        )
        .await?;
    }

    let transfers = charge.transfers();
    let (spender, nonce, challenge_hash, witness, witness_json) = match flavour {
        Flavour::Evm {
            spender,
            external_id,
        } => {
            let hash = keccak256([challenge.id.as_bytes(), challenge.realm.as_bytes()].concat());
            let witness = Permit2Witness::ChallengeExternalId {
                challenge_hash: format!("{hash:#x}"),
                external_id: external_id.clone(),
            };
            let json = json!({"challengeHash": format!("{hash:#x}"), "externalId": external_id});
            let nonce = U256::from_be_bytes(rand::random::<[u8; 32]>());
            (spender.clone(), nonce, hash, witness, json)
        }
        Flavour::Arbitrum => {
            let hash = arbitrum_challenge_hash(&challenge.id, &challenge.realm, &transfers);
            let witness = Permit2Witness::Challenge {
                challenge_hash: format!("{hash:#x}"),
            };
            let json = json!({"challengeHash": format!("{hash:#x}")});
            let nonce = U256::from_be_bytes(hash.0);
            (charge.recipient.clone(), nonce, hash, witness, json)
        }
    };
    let permit = Permit2WitnessTransfer {
        chain_id: charge.chain_id,
        token: charge.currency.clone(),
        permitted: transfers
            .iter()
            .map(|transfer| Permit2Permission {
                amount_wei: transfer.amount,
            })
            .collect(),
        spender,
        nonce: nonce.to_string(),
        deadline,
        witness,
    };
    let action = AgentAction::Permit2WitnessTransfer {
        permit: permit.clone(),
    };
    let digest = action
        .signing_hash()
        .map_err(|error| PaymentsError::InvalidRequest(format!("the permit is invalid: {error}")))?
        .ok_or_else(|| PaymentsError::Internal("a permit has no signing digest".into()))?;
    let answer = payer.signer().sign(action, payer.wait).await?;
    let signature = recoverable(&answer)?;
    ensure_signed_by(
        &signature,
        B256::from(digest),
        payer.wallet,
        "Permit2 permit",
    )?;
    tracing::debug!(challenge_hash = %challenge_hash, "signed a Permit2 permit");
    // Only now, with the permit through the agent's policies, spend gas on
    // the one-time approval (the permit needs it only when redeemed).
    if approval {
        approve(payer, rpc, network, charge).await?;
    }

    let token = charge.currency.to_string();
    let payload = json!({
        "type": "permit2",
        "permit": {
            "permitted": transfers
                .iter()
                .map(|transfer| json!({"token": token, "amount": transfer.amount.to_string()}))
                .collect::<Vec<Value>>(),
            "nonce": permit.nonce,
            "deadline": deadline.to_string(),
        },
        "transferDetails": transfers
            .iter()
            .map(|transfer| json!({"to": transfer.to, "requestedAmount": transfer.amount.to_string()}))
            .collect::<Vec<Value>>(),
        "witness": witness_json,
        "signature": format!("0x{}", hex::encode(rsv_bytes(&signature))),
    });
    let source = PaymentCredential::evm_did(charge.chain_id, &payer.wallet.to_string());
    Ok(Charged {
        network: network.to_string(),
        credential_type: "permit2",
        tx_hash: None,
        memo_hex: None,
        credential: PaymentCredential::with_source(challenge.to_echo(), source, payload),
        unsent: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors from `@arbitrum/mpp`'s `createChallengeHash` (viem
    /// `encodePacked`) for id `chal-2` and realm `arb.example.com`.
    #[test]
    fn the_arbitrum_challenge_hash_matches_the_sdk() {
        let transfer = |to: &str, amount| Transfer {
            to: to.into(),
            amount,
        };
        let primary = "0x2222222222222222222222222222222222222222";
        let split = "0x3333333333333333333333333333333333333333";
        assert_eq!(
            format!(
                "{:#x}",
                arbitrum_challenge_hash("chal-2", "arb.example.com", &[transfer(primary, 1_000)])
            ),
            "0xea14c6a8a053be342a76703d6aad2cac544580a208aaeb7d4154619677f6fe97"
        );
        assert_eq!(
            format!(
                "{:#x}",
                arbitrum_challenge_hash(
                    "chal-2",
                    "arb.example.com",
                    &[transfer(primary, 900), transfer(split, 100)]
                )
            ),
            "0x5ff63be43dd233019197c032b0ef4f0baf146499aa29d21b08f4a78699e1d1ad"
        );
    }
}
