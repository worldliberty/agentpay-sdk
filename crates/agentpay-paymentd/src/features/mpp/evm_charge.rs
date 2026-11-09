//! Paying an `evm` or `arbitrum` `charge` challenge (MPP `draft-evm-charge-00`;
//! `arbitrum` is `@arbitrum/mpp`'s name for the same request and payloads):
//! a one-time ERC-20 payment on any configured EVM chain.
//!
//! Among the merchant's `credentialTypes`, AgentPay picks the first it can
//! use in this order, gasless first (like `@bnb-chain/mpp`'s own
//! `prefer-gasless` buyer):
//!
//! 1. `authorization`: an EIP-3009 `transferWithAuthorization` the merchant
//!    submits; nonce `keccak256(id ‖ realm)`;
//! 2. `permit2`: a Permit2 permit the merchant redeems (see [`super::permit2`];
//!    the first payment in a token on a chain also approves Permit2, once);
//! 3. `hash`: an ERC-20 `transfer` AgentPay sends and confirms;
//! 4. `transaction`: the same transfer, signed and handed to the merchant
//!    (after `hash`: AgentPay then never hands out a signed transaction that
//!    might not be sent).
//!
//! Split payments need `permit2` (a batch permit). `hash` and `transaction`
//! need the chain's native coin for gas; a wallet without enough is refused
//! before anything is signed. Every signature goes through the signer
//! daemon, so the agent's limits apply.

use agentpay_domain::{Eip3009Transfer, EvmAddress};
use alloy_primitives::{keccak256, U256};
use alloy_sol_types::{sol, SolCall};
use mpp::protocol::core::{PaymentChallenge, PaymentCredential, PaymentPayload};
use serde_json::{json, Value};

use super::charge::Charged;
use super::evm_tx::{self, Delivery};
use super::permit2::{self, Flavour, Transfer};
use super::tempo::network_for_chain;
use crate::chains::evm::{evm_address, to_alloy_address};
use crate::error::PaymentsError;
use crate::features::eip3009;
use crate::features::payer::{unix_now, Payer};

sol! {
    function transfer(address to, uint256 amount) returns (bool);
}

/// Chains `@arbitrum/mpp` accepts: Arbitrum One and Arbitrum Sepolia.
const ARBITRUM_CHAIN_IDS: [u64; 2] = [42_161, 421_614];

/// How long an `authorization` stays valid at most.
const MAX_AUTHORIZATION_SECS: u64 = 600;

/// How far back an `authorization`'s `validAfter` reaches (clock skew).
const VALID_AFTER_SKEW_SECS: u64 = 60;

/// Most splits a charge may name (`draft-evm-charge-00`).
const MAX_SPLITS: usize = 10;

/// A credential type AgentPay can produce for an EVM charge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Credential {
    Authorization,
    Permit2(Flavour),
    Hash,
    Transaction,
}

impl Credential {
    fn name(&self) -> &'static str {
        match self {
            Self::Authorization => "authorization",
            Self::Permit2(_) => "permit2",
            Self::Hash => "hash",
            Self::Transaction => "transaction",
        }
    }

    /// Whether the agent pays no gas for the payment itself.
    pub(super) fn is_gasless(&self) -> bool {
        matches!(self, Self::Authorization | Self::Permit2(_))
    }
}

/// A payable `evm` / `arbitrum` charge, normalized.
#[derive(Debug, Clone)]
pub(super) struct EvmCharge {
    pub(super) chain_id: u64,
    pub(super) currency: EvmAddress,
    pub(super) recipient: EvmAddress,
    /// Base units.
    pub(super) amount: u128,
    pub(super) credential: Credential,
    /// The challenge's `expires`, Unix seconds.
    pub(super) expires: Option<u64>,
    /// The recipient exactly as the challenge spells it.
    pub(super) recipient_text: String,
    /// Splits (only with `permit2`), recipients spelled as in the challenge.
    pub(super) splits: Vec<Transfer>,
}

impl EvmCharge {
    /// Every transfer the payment makes: the primary recipient (the amount
    /// less the splits) first, then each split.
    pub(super) fn transfers(&self) -> Vec<Transfer> {
        let split_total: u128 = self.splits.iter().map(|split| split.amount).sum();
        let primary = Transfer {
            to: self.recipient_text.clone(),
            amount: self.amount - split_total,
        };
        std::iter::once(primary)
            .chain(self.splits.iter().cloned())
            .collect()
    }
}

fn address(value: Option<&Value>, field: &str) -> Result<EvmAddress, String> {
    value
        .and_then(Value::as_str)
        .and_then(|text| text.trim().parse::<EvmAddress>().ok())
        .ok_or_else(|| format!("{field} is not an EVM address"))
}

/// A positive integer in base units (no sign, no leading zero, ≤ 78 digits).
fn amount(value: Option<&Value>) -> Result<u128, String> {
    let text = value
        .and_then(Value::as_str)
        .ok_or("the charge names no amount")?;
    let valid = !text.is_empty()
        && text.len() <= 78
        && !text.starts_with('0')
        && text.bytes().all(|b| b.is_ascii_digit());
    if !valid {
        return Err("amount is not a positive integer in base units".into());
    }
    text.parse()
        .map_err(|_| "amount is too large to pay".to_string())
}

/// Unix seconds of an RFC 3339 `expires`.
fn expires(challenge: &PaymentChallenge) -> Result<Option<u64>, String> {
    let Some(text) = challenge.expires.as_deref() else {
        return Ok(None);
    };
    let at = time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
        .map_err(|_| "the challenge's expires is not an RFC 3339 time".to_string())?;
    Ok(Some(u64::try_from(at.unix_timestamp()).unwrap_or(0)))
}

/// Picks the credential among the merchant's `credentialTypes`: gasless
/// first (`authorization`, then `permit2` when `permit2` is usable), then
/// `hash`, then `transaction`. A charge with splits can only be paid with
/// `permit2`.
fn credential(
    method: &str,
    listed: Option<&Vec<Value>>,
    permit2: Result<Flavour, String>,
    has_splits: bool,
) -> Result<Credential, String> {
    let names: Vec<&str> = match listed {
        Some(list) => list.iter().filter_map(Value::as_str).collect(),
        // `draft-evm-charge-00`: without a list, servers accept `transaction`
        // (and should accept `hash`); `@arbitrum/mpp` expects `permit2`.
        None if method == "arbitrum" => vec!["permit2"],
        None => vec!["transaction", "hash"],
    };
    let listed = |name: &str| names.contains(&name);
    let permit2 = if listed("permit2") {
        Some(permit2)
    } else {
        None
    };
    if has_splits {
        return match permit2 {
            Some(Ok(flavour)) => Ok(Credential::Permit2(flavour)),
            Some(Err(why)) => Err(format!("split payments need permit2, and {why}")),
            None => Err(
                "split payments need a permit2 credential, which the merchant does not \
                         accept"
                    .into(),
            ),
        };
    }
    if listed("authorization") {
        return Ok(Credential::Authorization);
    }
    let unusable = match permit2 {
        Some(Ok(flavour)) => return Ok(Credential::Permit2(flavour)),
        Some(Err(why)) => Some(why),
        None => None,
    };
    if listed("hash") {
        return Ok(Credential::Hash);
    }
    if listed("transaction") {
        return Ok(Credential::Transaction);
    }
    Err(match unusable {
        Some(why) => format!("the merchant only accepts permit2, and {why}"),
        None => format!(
            "the merchant only accepts {} credentials; AgentPay pays EVM charges with \
             authorization (EIP-3009), permit2, hash, or transaction",
            names.join(", ")
        ),
    })
}

/// The Permit2 terms the challenge names, or why a permit cannot be used:
/// the Permit2 contract must be the canonical deployment, and an `evm`
/// challenge must name the spender (`methodDetails.permit2Spender`).
fn permit2_flavour(method: &str, request: &Value, details: &Value) -> Result<Flavour, String> {
    if let Some(named) = details.get("permit2Address") {
        let canonical = named.as_str().is_some_and(|text| {
            text.trim()
                .eq_ignore_ascii_case(agentpay_domain::PERMIT2_ADDRESS)
        });
        if !canonical {
            return Err(format!(
                "its permit2Address {named} is not the canonical Permit2 deployment"
            ));
        }
    }
    if method == "arbitrum" {
        return Ok(Flavour::Arbitrum);
    }
    let spender = address(
        details.get("permit2Spender"),
        "methodDetails.permit2Spender",
    )
    .map_err(|_| "the challenge names no valid methodDetails.permit2Spender".to_string())?;
    let external_id = request
        .get("externalId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Ok(Flavour::Evm {
        spender,
        external_id,
    })
}

/// The charge's splits: at most [`MAX_SPLITS`], each a positive amount to an
/// EVM address, together less than `amount`.
fn splits(value: Option<&Value>, amount: u128) -> Result<Vec<Transfer>, String> {
    let Some(list) = value.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    if list.len() > MAX_SPLITS {
        return Err(format!("a charge has at most {MAX_SPLITS} splits"));
    }
    let mut total = 0u128;
    let mut transfers = Vec::with_capacity(list.len());
    for split in list {
        address(split.get("recipient"), "a split recipient")?;
        let to = split
            .get("recipient")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_string();
        let split_amount =
            self::amount(split.get("amount")).map_err(|why| format!("a split's {why}"))?;
        total = total
            .checked_add(split_amount)
            .ok_or("the splits overflow")?;
        transfers.push(Transfer {
            to,
            amount: split_amount,
        });
    }
    if total >= amount {
        return Err("the splits must total less than the amount".into());
    }
    Ok(transfers)
}

/// Normalizes an `evm` / `arbitrum` charge challenge, or says why it cannot
/// be paid. Nothing is signed here.
pub(super) fn parse(challenge: &PaymentChallenge) -> Result<EvmCharge, String> {
    let method = challenge.method.as_str();
    let request: Value = challenge
        .request
        .decode()
        .map_err(|_| "the charge request is malformed".to_string())?;
    let details = request.get("methodDetails").cloned().unwrap_or(Value::Null);
    let chain_id = details
        .get("chainId")
        .and_then(Value::as_u64)
        .ok_or("the challenge names no methodDetails.chainId")?;
    if method == "arbitrum" && !ARBITRUM_CHAIN_IDS.contains(&chain_id) {
        return Err(format!("chain {chain_id} is not an Arbitrum chain"));
    }
    let amount = amount(request.get("amount"))?;
    let splits = splits(details.get("splits"), amount)?;
    let credential = credential(
        method,
        details.get("credentialTypes").and_then(Value::as_array),
        permit2_flavour(method, &request, &details),
        !splits.is_empty(),
    )?;
    Ok(EvmCharge {
        chain_id,
        currency: address(request.get("currency"), "currency")?,
        recipient: address(request.get("recipient"), "recipient")?,
        amount,
        credential,
        expires: expires(challenge)?,
        recipient_text: request
            .get("recipient")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_string(),
        splits,
    })
}

/// Pays `charge` (from `challenge`) and returns the credential.
pub(super) async fn pay(
    payer: &Payer,
    challenge: &PaymentChallenge,
    charge: &EvmCharge,
) -> Result<Charged, PaymentsError> {
    let (network, chain) = network_for_chain(&payer.config, charge.chain_id)?;
    let rpc = payer.evm.connect(&network, &chain).await?;
    let token = to_alloy_address(&charge.currency)?;
    let balance = rpc.erc20_balance(token, payer.wallet).await?;
    if balance < U256::from(charge.amount) {
        return Err(PaymentsError::InvalidRequest(format!(
            "the wallet holds {balance} base units of {} on {network}, and the charge is {}; \
             nothing was signed",
            charge.currency, charge.amount
        )));
    }
    let source = PaymentCredential::evm_did(charge.chain_id, &payer.wallet.to_string());
    let echo = challenge.to_echo();
    let paid = |credential, tx_hash, unsent| Charged {
        network: network.clone(),
        credential_type: charge.credential.name(),
        tx_hash,
        memo_hex: None,
        credential,
        unsent,
    };
    match &charge.credential {
        Credential::Permit2(flavour) => {
            permit2::pay(payer, &rpc, &network, challenge, charge, flavour).await
        }
        Credential::Authorization => {
            let (name, version) = rpc.eip712_name_version(token).await?;
            let now = unix_now();
            let latest = now + MAX_AUTHORIZATION_SECS;
            let valid_before = charge.expires.map_or(latest, |at| at.min(latest));
            if valid_before <= now {
                return Err(PaymentsError::InvalidRequest(
                    "the challenge has expired; nothing was signed".into(),
                ));
            }
            let nonce = keccak256([challenge.id.as_bytes(), challenge.realm.as_bytes()].concat());
            let authorization = Eip3009Transfer {
                chain_id: charge.chain_id,
                token: charge.currency.clone(),
                token_name: name,
                token_version: version,
                from: evm_address(payer.wallet)?,
                to: charge.recipient.clone(),
                amount_wei: charge.amount,
                valid_after: now.saturating_sub(VALID_AFTER_SKEW_SECS),
                valid_before,
                nonce_hex: format!("{nonce:#x}"),
            };
            let signature = eip3009::sign(payer, &authorization).await?;
            let payload = json!({
                "type": "authorization",
                "from": authorization.from.to_string(),
                "to": authorization.to.to_string(),
                "value": charge.amount.to_string(),
                "validAfter": authorization.valid_after.to_string(),
                "validBefore": authorization.valid_before.to_string(),
                "nonce": authorization.nonce_hex,
                "signature": signature,
            });
            let credential = PaymentCredential::with_source(echo, source, payload);
            Ok(paid(credential, None, None))
        }
        Credential::Hash | Credential::Transaction => {
            let data = transferCall {
                to: to_alloy_address(&charge.recipient)?,
                amount: U256::from(charge.amount),
            }
            .abi_encode();
            let delivery = if charge.credential == Credential::Hash {
                Delivery::Send
            } else {
                Delivery::SignOnly
            };
            let signed = evm_tx::sign_call(
                payer,
                &rpc,
                &network,
                charge.chain_id,
                &charge.currency,
                data,
                delivery,
            )
            .await?;
            if delivery == Delivery::Send {
                let payload = PaymentPayload::hash(&signed.hash);
                let credential = PaymentCredential::with_source(echo, source, payload);
                Ok(paid(credential, Some(signed.hash), None))
            } else {
                let payload = PaymentPayload::transaction(&signed.raw_hex);
                let credential = PaymentCredential::with_source(echo, source, payload);
                let unsent = Some((signed.tx, signed.hash.clone()));
                Ok(paid(credential, Some(signed.hash), unsent))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(names: &[&str]) -> Vec<Value> {
        names.iter().map(|name| json!(name)).collect()
    }

    fn usable() -> Result<Flavour, String> {
        Ok(Flavour::Arbitrum)
    }

    fn unusable() -> Result<Flavour, String> {
        Err("the challenge names no valid methodDetails.permit2Spender".into())
    }

    #[test]
    fn gasless_credentials_come_first_then_hash_then_transaction() {
        let pick = |names: &[&str], permit2: Result<Flavour, String>| {
            credential("evm", Some(&list(names)), permit2, false)
        };
        let permit2 = Ok(Credential::Permit2(Flavour::Arbitrum));
        // Whatever the merchant's order, gasless wins.
        assert_eq!(
            pick(&["hash", "transaction", "authorization"], usable()),
            Ok(Credential::Authorization)
        );
        assert_eq!(pick(&["hash", "permit2"], usable()), permit2);
        assert_eq!(
            pick(&["permit2", "authorization"], usable()),
            Ok(Credential::Authorization)
        );
        // An unusable permit2 falls through to what else is listed.
        assert_eq!(pick(&["permit2", "hash"], unusable()), Ok(Credential::Hash));
        assert!(pick(&["permit2"], unusable()).is_err_and(|why| why.contains("permit2Spender")));
        assert_eq!(
            pick(&["transaction", "hash"], usable()),
            Ok(Credential::Hash)
        );
        assert_eq!(
            pick(&["transaction"], usable()),
            Ok(Credential::Transaction)
        );
        assert!(pick(&["nope"], usable()).is_err_and(|why| why.contains("nope")));
        // Without a list: the spec default for `evm`, permit2 for `arbitrum`.
        assert_eq!(
            credential("evm", None, usable(), false),
            Ok(Credential::Hash)
        );
        assert_eq!(credential("arbitrum", None, usable(), false), permit2);
    }

    #[test]
    fn splits_are_paid_only_with_permit2() {
        let pick = |names: &[&str], permit2| credential("evm", Some(&list(names)), permit2, true);
        assert_eq!(
            pick(&["authorization", "permit2"], usable()),
            Ok(Credential::Permit2(Flavour::Arbitrum))
        );
        assert!(pick(&["authorization", "hash"], usable()).is_err_and(|why| why.contains("split")));
        assert!(pick(&["permit2"], unusable()).is_err_and(|why| why.contains("permit2Spender")));
    }

    #[test]
    fn permit2_needs_the_canonical_contract_and_for_evm_a_spender() {
        let spender = "0x1111111111111111111111111111111111111111";
        let request = json!({"externalId": "order-7"});
        assert_eq!(
            permit2_flavour("evm", &request, &json!({"permit2Spender": spender})),
            Ok(Flavour::Evm {
                spender: spender.parse().expect("spender"),
                external_id: "order-7".into(),
            })
        );
        assert!(permit2_flavour("evm", &request, &json!({})).is_err());
        let canonical = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
        assert_eq!(
            permit2_flavour(
                "arbitrum",
                &json!({}),
                &json!({"permit2Address": canonical})
            ),
            Ok(Flavour::Arbitrum)
        );
        let fork = json!({"permit2Address": spender, "permit2Spender": spender});
        assert!(permit2_flavour("evm", &request, &fork)
            .is_err_and(|why| why.contains("not the canonical Permit2")));
        assert!(permit2_flavour("arbitrum", &request, &fork).is_err());
    }

    #[test]
    fn splits_are_bounded_and_leave_the_primary_recipient_something() {
        let split = |amount: &str| json!({"recipient": "0x3333333333333333333333333333333333333333", "amount": amount});
        assert_eq!(splits(None, 1_000), Ok(Vec::new()));
        let two = splits(Some(&json!([split("100"), split("200")])), 1_000).expect("splits");
        assert_eq!(two.iter().map(|t| t.amount).sum::<u128>(), 300);
        assert!(
            splits(Some(&json!([split("1000")])), 1_000).is_err(),
            "nothing left"
        );
        assert!(splits(Some(&json!([split("0")])), 1_000).is_err());
        assert!(splits(Some(&json!(vec![split("1"); 11])), 1_000).is_err());
        assert!(splits(Some(&json!([{"recipient": "nope", "amount": "1"}])), 1_000).is_err());
    }

    #[test]
    fn amounts_are_positive_integers_in_base_units() {
        assert_eq!(amount(Some(&json!("1000"))), Ok(1000));
        for bad in ["0", "01", "-1", "1.5", "", "1e3", &"9".repeat(79)] {
            assert!(amount(Some(&json!(bad))).is_err(), "{bad}");
        }
        assert!(
            amount(Some(&json!(1000))).is_err(),
            "numbers must be strings"
        );
        assert!(amount(Some(&json!("9".repeat(60)))).is_err_and(|why| why.contains("large")));
    }
}
