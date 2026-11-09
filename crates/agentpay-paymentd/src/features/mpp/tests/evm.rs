//! `evm` and `arbitrum` charges (`draft-evm-charge-00`) end to end against a
//! mock merchant that checks each credential on its own: the EIP-3009
//! authorization's EIP-712 signature (its own type definitions), nonce
//! binding, and amounts; the Permit2 permit's digest (rebuilt as JSON typed
//! data the way the SDKs build it), witness, transfers, and the Permit2
//! allowance; and the transfer transactions decoded from raw bytes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{keccak256, Address, Signature, B256, U256};
use alloy_sol_types::{eip712_domain, sol, SolCall, SolStruct};
use mpp::protocol::core::{
    format_www_authenticate, parse_authorization, Base64UrlJson, PaymentChallenge, Receipt,
};
use serde_json::{json, Value};

use super::{Harness, RECIPIENT};
use crate::chains::evm::mock_rpc::MockRpc;
use crate::error::PaymentsError;
use crate::features::http::merchant::{Merchant, Reply, Seen};
use crate::signer::testing::per_tx_limit;

sol! {
    function transfer(address to, uint256 amount) returns (bool);
    function approve(address spender, uint256 value) returns (bool);

    struct TransferWithAuthorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }
}

/// USDC-like token the merchant charges in.
const TOKEN: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const AMOUNT: u128 = 1_000;

/// The merchant's settlement signer (`methodDetails.permit2Spender`).
const SETTLEMENT: &str = "0x5e771e5e771e5e771e5e771e5e771e5e771e5e77";
const SPLIT_RECIPIENT: &str = "0x3333333333333333333333333333333333333333";

/// What the merchant asks for.
#[derive(Clone)]
struct EvmTerms {
    method: &'static str,
    chain_id: u64,
    credential_types: Option<Vec<&'static str>>,
    splits: bool,
    /// `methodDetails.permit2Spender`.
    permit2_spender: Option<&'static str>,
    /// `methodDetails.permit2Address`.
    permit2_address: Option<&'static str>,
    external_id: Option<&'static str>,
    /// Answer every credential with a fresh 402 (after logging it).
    reject: bool,
}

impl EvmTerms {
    fn evm(chain_id: u64, types: &[&'static str]) -> Self {
        Self {
            method: "evm",
            chain_id,
            credential_types: Some(types.to_vec()),
            splits: false,
            permit2_spender: None,
            permit2_address: None,
            external_id: None,
            reject: false,
        }
    }

    /// A `@bnb-chain/mpp`-style permit2 merchant.
    fn permit2(chain_id: u64, types: &[&'static str]) -> Self {
        Self {
            permit2_spender: Some(SETTLEMENT),
            permit2_address: Some("0x000000000022D473030F116dDEE9F6B43aC78BA3"),
            external_id: Some("order-9"),
            ..Self::evm(chain_id, types)
        }
    }

    fn split_total(&self) -> u128 {
        if self.splits {
            10
        } else {
            0
        }
    }
}

struct EvmMerchant {
    http: Merchant,
    log: Arc<Mutex<Vec<String>>>,
}

impl EvmMerchant {
    async fn start(terms: EvmTerms, rpc: Arc<MockRpc>) -> Self {
        let log = Arc::new(Mutex::new(Vec::new()));
        let issued = Arc::new(Mutex::new(HashMap::<String, PaymentChallenge>::new()));
        let shared = log.clone();
        let http =
            Merchant::start(move |seen: &Seen| serve(&terms, &rpc, &issued, &shared, seen)).await;
        Self { http, log }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.http.url())
    }

    fn log(&self) -> Vec<String> {
        self.log.lock().expect("log").clone()
    }
}

fn challenge(terms: &EvmTerms, id: usize) -> PaymentChallenge {
    let mut details = json!({ "chainId": terms.chain_id, "decimals": 6 });
    if let Some(types) = &terms.credential_types {
        details["credentialTypes"] = json!(types);
    }
    if terms.splits {
        details["splits"] = json!([{ "recipient": SPLIT_RECIPIENT, "amount": "10" }]);
    }
    if let Some(spender) = terms.permit2_spender {
        details["permit2Spender"] = json!(spender);
    }
    if let Some(address) = terms.permit2_address {
        details["permit2Address"] = json!(address);
    }
    let mut request = json!({
        "amount": AMOUNT.to_string(),
        "currency": TOKEN,
        "recipient": RECIPIENT,
        "methodDetails": details,
    });
    if let Some(external_id) = terms.external_id {
        request["externalId"] = json!(external_id);
    }
    let expires = time::OffsetDateTime::now_utc() + time::Duration::minutes(5);
    PaymentChallenge::new(
        format!("evm-challenge-{id}"),
        "api.example.com",
        terms.method,
        "charge",
        Base64UrlJson::from_value(&request).expect("request"),
    )
    .with_expires(
        expires
            .format(&time::format_description::well_known::Rfc3339)
            .expect("expires"),
    )
}

fn serve(
    terms: &EvmTerms,
    rpc: &MockRpc,
    issued: &Mutex<HashMap<String, PaymentChallenge>>,
    log: &Mutex<Vec<String>>,
    seen: &Seen,
) -> Reply {
    let mut issued = issued.lock().expect("issued");
    let Some(header) = seen.header("authorization") else {
        let challenge = challenge(terms, issued.len());
        issued.insert(challenge.id.clone(), challenge.clone());
        return Reply::new(402, "payment required").header(
            "WWW-Authenticate",
            format_www_authenticate(&challenge).expect("challenge header"),
        );
    };
    let credential = parse_authorization(header).expect("credential");
    let challenge = issued
        .get(&credential.challenge.id)
        .cloned()
        .expect("a challenge the merchant issued");
    assert_eq!(
        credential.challenge.request.raw(),
        challenge.to_echo().request.raw()
    );
    let payload = &credential.payload;
    let kind = payload["type"].as_str().expect("type").to_string();
    if terms.reject {
        log.lock().expect("log").push(format!("rejected {kind}"));
        let fresh = self::challenge(terms, issued.len());
        issued.insert(fresh.id.clone(), fresh.clone());
        return Reply::new(402, "payment required").header(
            "WWW-Authenticate",
            format_www_authenticate(&fresh).expect("challenge header"),
        );
    }
    let reference = match kind.as_str() {
        "authorization" => check_authorization(terms, &challenge, payload),
        "permit2" => check_permit2(
            terms,
            &challenge,
            payload,
            credential.source.as_deref(),
            rpc,
        ),
        "hash" => {
            let hash: B256 = payload["hash"]
                .as_str()
                .expect("hash")
                .parse()
                .expect("hash");
            let raw = rpc
                .sent()
                .into_iter()
                .find(|raw| keccak256(raw) == hash)
                .expect("AgentPay sent the transaction");
            check_transfer(terms, &raw);
            format!("{hash:#x}")
        }
        "transaction" => {
            let raw = alloy_primitives::hex::decode(
                payload["signature"]
                    .as_str()
                    .expect("signature")
                    .trim_start_matches("0x"),
            )
            .expect("hex");
            assert!(
                rpc.sent().is_empty(),
                "the merchant broadcasts, not AgentPay"
            );
            check_transfer(terms, &raw);
            format!("{:#x}", keccak256(&raw))
        }
        other => panic!("unexpected credential type {other}"),
    };
    log.lock().expect("log").push(kind);
    let receipt = Receipt::success(terms.method, reference);
    Reply::new(200, "{\"ok\":true}")
        .header("content-type", "application/json")
        .header("Payment-Receipt", receipt.to_header().expect("receipt"))
}

/// Checks an EIP-3009 authorization like a merchant would before submitting
/// it, and returns a stand-in settlement reference.
fn check_authorization(terms: &EvmTerms, challenge: &PaymentChallenge, payload: &Value) -> String {
    let field = |name: &str| payload[name].as_str().expect(name).to_string();
    let number = |name: &str| U256::from_str_radix(&field(name), 10).expect(name);
    let token: Address = TOKEN.parse().expect("token");
    let from: Address = field("from").parse().expect("from");
    assert_eq!(field("to").to_lowercase(), RECIPIENT);
    assert_eq!(number("value"), U256::from(AMOUNT));
    let nonce: B256 = field("nonce").parse().expect("nonce");
    assert_eq!(
        nonce,
        keccak256([challenge.id.as_bytes(), challenge.realm.as_bytes()].concat()),
        "the nonce binds the challenge"
    );
    let message = TransferWithAuthorization {
        from,
        to: RECIPIENT.parse().expect("recipient"),
        value: number("value"),
        validAfter: number("validAfter"),
        validBefore: number("validBefore"),
        nonce,
    };
    let domain = eip712_domain! {
        name: "USD Coin",
        version: "2",
        chain_id: terms.chain_id,
        verifying_contract: token,
    };
    let bytes = alloy_primitives::hex::decode(field("signature").trim_start_matches("0x"))
        .expect("signature hex");
    let signature = Signature::from_raw(&bytes).expect("signature");
    let signer = signature
        .recover_address_from_prehash(&message.eip712_signing_hash(&domain))
        .expect("recover");
    assert_eq!(signer, from, "signed by the payer");
    format!("{:#x}", keccak256(&bytes))
}

/// Checks a Permit2 permit like `@bnb-chain/mpp` / `@arbitrum/mpp` servers do
/// before redeeming it, and returns a stand-in settlement reference.
fn check_permit2(
    terms: &EvmTerms,
    challenge: &PaymentChallenge,
    payload: &Value,
    source: Option<&str>,
    rpc: &MockRpc,
) -> String {
    let text = |value: &Value| value.as_str().expect("string").to_string();
    let permitted = payload["permit"]["permitted"]
        .as_array()
        .expect("permitted");
    let details = payload["transferDetails"]
        .as_array()
        .expect("transferDetails");
    let mut expected = vec![(RECIPIENT.to_string(), AMOUNT - terms.split_total())];
    if terms.splits {
        expected.push((SPLIT_RECIPIENT.to_string(), 10));
    }
    assert_eq!(permitted.len(), expected.len());
    assert_eq!(details.len(), expected.len());
    for ((entry, detail), (to, amount)) in permitted.iter().zip(details).zip(&expected) {
        assert_eq!(text(&entry["token"]).to_lowercase(), TOKEN);
        assert_eq!(text(&entry["amount"]), amount.to_string());
        assert_eq!(text(&detail["requestedAmount"]), amount.to_string());
        assert_eq!(
            &text(&detail["to"]),
            to,
            "recipients as the challenge spells them"
        );
    }
    let id_realm = [challenge.id.as_bytes(), challenge.realm.as_bytes()].concat();
    let (spender, witness_type, witness) = if terms.method == "arbitrum" {
        let mut packed = id_realm;
        for (to, _) in &expected {
            packed.extend_from_slice(to.as_bytes());
        }
        for (_, amount) in &expected {
            packed.extend_from_slice(&U256::from(*amount).to_be_bytes::<32>());
        }
        let hash = format!("{:#x}", keccak256(packed));
        assert_eq!(text(&payload["witness"]["challengeHash"]), hash);
        (
            RECIPIENT,
            json!([{"name": "challengeHash", "type": "bytes32"}]),
            json!({"challengeHash": hash}),
        )
    } else {
        let hash = format!("{:#x}", keccak256(id_realm));
        assert_eq!(text(&payload["witness"]["challengeHash"]), hash);
        let external_id = terms.external_id.unwrap_or_default();
        assert_eq!(text(&payload["witness"]["externalId"]), external_id);
        (
            SETTLEMENT,
            json!([
                {"name": "challengeHash", "type": "bytes32"},
                {"name": "externalId", "type": "string"}
            ]),
            json!({"challengeHash": hash, "externalId": external_id}),
        )
    };
    let now = u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).expect("now");
    let deadline: u64 = text(&payload["permit"]["deadline"])
        .parse()
        .expect("deadline");
    assert!(deadline > now && deadline <= now + 600, "a short deadline");
    let batch = expected.len() > 1;
    let primary = if batch {
        "PermitBatchWitnessTransferFrom"
    } else {
        "PermitWitnessTransferFrom"
    };
    let entries: Vec<Value> = expected
        .iter()
        .map(|(_, amount)| json!({"token": TOKEN, "amount": amount.to_string()}))
        .collect();
    let typed = json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            primary: [
                {"name": "permitted", "type": if batch { "TokenPermissions[]" } else { "TokenPermissions" }},
                {"name": "spender", "type": "address"},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"},
                {"name": "witness", "type": "PaymentWitness"}
            ],
            "TokenPermissions": [
                {"name": "token", "type": "address"},
                {"name": "amount", "type": "uint256"}
            ],
            "PaymentWitness": witness_type,
        },
        "primaryType": primary,
        "domain": {
            "name": "Permit2",
            "chainId": terms.chain_id,
            "verifyingContract": agentpay_domain::PERMIT2_ADDRESS
        },
        "message": {
            "permitted": if batch { json!(entries) } else { entries[0].clone() },
            "spender": spender,
            "nonce": text(&payload["permit"]["nonce"]),
            "deadline": deadline.to_string(),
            "witness": witness,
        }
    });
    let digest = agentpay_domain::Eip712TypedData {
        typed_data_json: typed.to_string(),
    }
    .signing_hash()
    .expect("typed data digest");
    let bytes = alloy_primitives::hex::decode(text(&payload["signature"]).trim_start_matches("0x"))
        .expect("signature hex");
    let signer = Signature::from_raw(&bytes)
        .expect("signature")
        .recover_address_from_prehash(&B256::from(digest))
        .expect("recover");
    let source = source.expect("permit2 needs a source");
    let payer: Address = source
        .rsplit(':')
        .next()
        .expect("address")
        .parse()
        .expect("payer");
    assert_eq!(signer, payer, "signed by the payer");
    assert!(
        rpc.chain().token_allowance >= U256::from(AMOUNT),
        "Permit2 can pull the tokens"
    );
    format!("{:#x}", keccak256(&bytes))
}

/// Checks a signed ERC-20 `transfer` of the charge on the right chain.
fn check_transfer(terms: &EvmTerms, raw: &[u8]) {
    let TxEnvelope::Eip1559(signed) = TxEnvelope::decode_2718_exact(raw).expect("envelope") else {
        panic!("an EIP-1559 transaction");
    };
    let tx = signed.tx();
    assert_eq!(tx.chain_id, terms.chain_id);
    assert_eq!(tx.to.to().copied(), Some(TOKEN.parse().expect("token")));
    assert_eq!(tx.value, U256::ZERO);
    let call = transferCall::abi_decode(&tx.input).expect("transfer call");
    assert_eq!(call.to, RECIPIENT.parse::<Address>().expect("recipient"));
    assert_eq!(call.amount, U256::from(AMOUNT));
}

#[tokio::test]
async fn an_eip3009_authorization_pays_without_gas_and_binds_the_challenge() {
    let harness = Harness::open().await;
    let rpc = harness.add_evm_chain("base", 8_453).await;
    let merchant = EvmMerchant::start(
        EvmTerms::evm(8_453, &["permit2", "authorization", "transaction"]),
        rpc.clone(),
    )
    .await;
    let result = harness
        .fetch(harness.params(merchant.url("/v1/data")))
        .await
        .expect("paid");
    assert_eq!(result.response.status, 200);
    let payment = result.payment.expect("payment");
    assert_eq!(
        (
            payment.method.as_str(),
            payment.network.as_str(),
            payment.chain_id
        ),
        ("evm", "base", 8_453)
    );
    assert_eq!(payment.currency, TOKEN);
    let charge = payment.charge.expect("charge");
    assert_eq!(charge.credential_type, "authorization");
    assert_eq!(charge.tx_hash, None);
    assert_eq!(merchant.log(), ["authorization"]);
    assert!(rpc.sent().is_empty(), "nothing was broadcast");
}

#[tokio::test]
async fn the_domain_comes_from_eip5267_when_the_token_has_it() {
    let harness = Harness::open().await;
    let rpc = harness.add_evm_chain("base", 8_453).await;
    {
        // `version()` reverts, so only the ERC-5267 domain gives the version
        // the merchant verifies with.
        let mut chain = rpc.chain();
        chain.eip5267_version = Some("2".into());
        chain.token_version = None;
    }
    let merchant = EvmMerchant::start(EvmTerms::evm(8_453, &["authorization"]), rpc.clone()).await;
    harness
        .fetch(harness.params(merchant.url("/x")))
        .await
        .expect("paid");
    assert_eq!(merchant.log(), ["authorization"]);
    assert!(rpc.calls().iter().any(|call| call == "eth_call"));
}

#[tokio::test]
async fn hash_is_sent_and_confirmed_and_preferred_over_transaction() {
    let harness = Harness::open().await;
    let rpc = harness.add_evm_chain("base", 8_453).await;
    let merchant =
        EvmMerchant::start(EvmTerms::evm(8_453, &["transaction", "hash"]), rpc.clone()).await;
    let payment = harness
        .fetch(harness.params(merchant.url("/x")))
        .await
        .expect("paid")
        .payment
        .expect("payment");
    let charge = payment.charge.expect("charge");
    assert_eq!(charge.credential_type, "hash");
    assert_eq!(merchant.log(), ["hash"]);
    assert_eq!(rpc.sent().len(), 1);
}

#[tokio::test]
async fn a_transaction_credential_is_signed_and_left_to_the_merchant() {
    let harness = Harness::open().await;
    let rpc = harness.add_evm_chain("base", 8_453).await;
    let merchant = EvmMerchant::start(EvmTerms::evm(8_453, &["transaction"]), rpc.clone()).await;
    let charge = harness
        .fetch(harness.params(merchant.url("/x")))
        .await
        .expect("paid")
        .payment
        .and_then(|payment| payment.charge)
        .expect("charge");
    assert_eq!(charge.credential_type, "transaction");
    assert!(charge.tx_hash.is_some());
    assert_eq!(merchant.log(), ["transaction"]);
}

#[tokio::test]
async fn arbitrum_pays_with_authorization_only_when_listed() {
    let harness = Harness::open().await;
    let rpc = harness.add_evm_chain("arbitrum-sepolia", 421_614).await;
    let listed = EvmMerchant::start(
        EvmTerms {
            method: "arbitrum",
            ..EvmTerms::evm(421_614, &["authorization"])
        },
        rpc.clone(),
    )
    .await;
    let payment = harness
        .fetch(harness.params(listed.url("/x")))
        .await
        .expect("paid")
        .payment
        .expect("payment");
    assert_eq!(payment.method, "arbitrum");
    assert_eq!(listed.log(), ["authorization"]);

    // Without a list `@arbitrum/mpp` expects permit2.
    let unlisted = EvmMerchant::start(
        EvmTerms {
            method: "arbitrum",
            credential_types: None,
            ..EvmTerms::evm(421_614, &[])
        },
        rpc.clone(),
    )
    .await;
    harness
        .fetch(harness.params(unlisted.url("/x")))
        .await
        .expect("paid with permit2");
    assert_eq!(unlisted.log(), ["permit2"]);
}

#[tokio::test]
async fn unsupported_requests_are_refused_before_signing() {
    let harness = Harness::open().await;
    let rpc = harness.add_evm_chain("base", 8_453).await;
    for terms in [
        // Splits need permit2.
        EvmTerms {
            splits: true,
            ..EvmTerms::evm(8_453, &["authorization", "hash"])
        },
        // A chain AgentPay has not configured.
        EvmTerms::evm(59_144, &["authorization"]),
        // Only permit2.
        EvmTerms::evm(8_453, &["permit2"]),
    ] {
        let merchant = EvmMerchant::start(terms, rpc.clone()).await;
        let error = harness
            .fetch(harness.params(merchant.url("/x")))
            .await
            .expect_err("refused");
        assert!(
            matches!(&error, PaymentsError::InvalidRequest(reason) if reason.contains("nothing was signed")),
            "{error:?}"
        );
        assert!(merchant.log().is_empty());
    }
    assert!(rpc.sent().is_empty());
}

#[tokio::test]
async fn evm_charges_are_policy_checked() {
    let harness = Harness::new(vec![per_tx_limit(AMOUNT - 1)]).await;
    let rpc = harness.add_evm_chain("base", 8_453).await;
    for types in [&["authorization"][..], &["hash"][..]] {
        let merchant = EvmMerchant::start(EvmTerms::evm(8_453, types), rpc.clone()).await;
        let error = harness
            .fetch(harness.params(merchant.url("/x")))
            .await
            .expect_err("over the limit");
        assert!(
            matches!(
                &error,
                PaymentsError::Signer(_) | PaymentsError::ManualApprovalPending { .. }
            ),
            "{error:?}"
        );
        assert!(merchant.log().is_empty());
    }
    assert!(rpc.sent().is_empty());
}

#[tokio::test]
async fn permit2_approves_once_after_the_permit_is_signed_then_only_signs() {
    let harness = Harness::open().await;
    let rpc = harness.add_evm_chain("base", 8_453).await;
    let merchant =
        EvmMerchant::start(EvmTerms::permit2(8_453, &["permit2", "hash"]), rpc.clone()).await;
    for round in 1..=2 {
        let charge = harness
            .fetch(harness.params(merchant.url("/x")))
            .await
            .expect("paid")
            .payment
            .and_then(|payment| payment.charge)
            .expect("charge");
        assert_eq!(charge.credential_type, "permit2");
        assert_eq!(charge.tx_hash, None);
        assert_eq!(rpc.sent().len(), 1, "round {round}: one approval in all");
    }
    assert_eq!(merchant.log(), ["permit2", "permit2"]);
    // The one transaction is `approve(Permit2, u128::MAX)` on the token.
    let TxEnvelope::Eip1559(signed) = TxEnvelope::decode_2718_exact(&rpc.sent()[0]).expect("tx")
    else {
        panic!("an EIP-1559 transaction");
    };
    assert_eq!(
        signed.tx().to.to().copied(),
        Some(TOKEN.parse().expect("token"))
    );
    let approval = approveCall::abi_decode(&signed.tx().input).expect("approve");
    assert_eq!(
        approval.spender,
        agentpay_domain::PERMIT2_ADDRESS
            .parse::<Address>()
            .expect("permit2")
    );
    assert_eq!(approval.value, U256::from(u128::MAX));
}

#[tokio::test]
async fn arbitrum_permit2_pays_splits_with_a_batch_permit() {
    let harness = Harness::open().await;
    let rpc = harness.add_evm_chain("arbitrum-sepolia", 421_614).await;
    rpc.chain().token_allowance = U256::MAX;
    let merchant = EvmMerchant::start(
        EvmTerms {
            method: "arbitrum",
            splits: true,
            ..EvmTerms::evm(421_614, &["authorization", "permit2"])
        },
        rpc.clone(),
    )
    .await;
    harness
        .fetch(harness.params(merchant.url("/x")))
        .await
        .expect("paid");
    assert_eq!(merchant.log(), ["permit2"], "splits need permit2");
    assert!(rpc.sent().is_empty(), "the allowance was already there");
}

#[tokio::test]
async fn permit2_with_an_allowance_needs_no_gas_but_hash_does() {
    let harness = Harness::open().await;
    let rpc = harness.add_evm_chain("base", 8_453).await;
    rpc.chain().balance = U256::ZERO;

    let hash_only = EvmMerchant::start(EvmTerms::evm(8_453, &["hash"]), rpc.clone()).await;
    let error = harness
        .fetch(harness.params(hash_only.url("/x")))
        .await
        .expect_err("no gas");
    assert!(
        matches!(&error, PaymentsError::InvalidRequest(reason)
            if reason.contains("for gas") && reason.contains("ETH") && reason.contains("nothing was signed")),
        "{error:?}"
    );
    // The first permit2 payment needs gas for the approval; nothing is sent.
    let permit2 = EvmMerchant::start(EvmTerms::permit2(8_453, &["permit2"]), rpc.clone()).await;
    let error = harness
        .fetch(harness.params(permit2.url("/x")))
        .await
        .expect_err("no gas for the approval");
    assert!(
        matches!(&error, PaymentsError::InvalidRequest(reason) if reason.contains("for gas")),
        "{error:?}"
    );
    assert!(rpc.sent().is_empty());
    assert!(hash_only.log().is_empty() && permit2.log().is_empty());

    // With the allowance in place, permit2 pays with no native coin at all.
    rpc.chain().token_allowance = U256::MAX;
    harness
        .fetch(harness.params(permit2.url("/x")))
        .await
        .expect("paid without gas");
    assert_eq!(permit2.log(), ["permit2"]);
    assert!(rpc.sent().is_empty());
}

#[tokio::test]
async fn a_refused_permit_spends_no_gas_on_the_approval() {
    let harness = Harness::new(vec![per_tx_limit(AMOUNT - 1)]).await;
    let rpc = harness.add_evm_chain("base", 8_453).await;
    let merchant = EvmMerchant::start(EvmTerms::permit2(8_453, &["permit2"]), rpc.clone()).await;
    let error = harness
        .fetch(harness.params(merchant.url("/x")))
        .await
        .expect_err("over the limit");
    assert!(
        matches!(
            &error,
            PaymentsError::Signer(_) | PaymentsError::ManualApprovalPending { .. }
        ),
        "{error:?}"
    );
    assert!(rpc.sent().is_empty(), "no approval was sent");
    assert!(merchant.log().is_empty());
}

#[tokio::test]
async fn a_non_canonical_permit2_is_never_used() {
    let harness = Harness::open().await;
    let rpc = harness.add_evm_chain("base", 8_453).await;
    let fork = EvmTerms {
        permit2_address: Some(SETTLEMENT),
        ..EvmTerms::permit2(8_453, &["permit2", "hash"])
    };
    let merchant = EvmMerchant::start(fork.clone(), rpc.clone()).await;
    harness
        .fetch(harness.params(merchant.url("/x")))
        .await
        .expect("paid");
    assert_eq!(merchant.log(), ["hash"], "fell through to hash");

    let only = EvmMerchant::start(
        EvmTerms {
            credential_types: Some(vec!["permit2"]),
            ..fork
        },
        rpc.clone(),
    )
    .await;
    let error = harness
        .fetch(harness.params(only.url("/x")))
        .await
        .expect_err("refused");
    assert!(
        matches!(&error, PaymentsError::InvalidRequest(reason) if reason.contains("canonical Permit2")),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_refused_charge_credential_is_never_followed_by_a_second_one() {
    let harness = Harness::open().await;
    let rpc = harness.add_evm_chain("base", 8_453).await;
    rpc.chain().token_allowance = U256::MAX;
    for types in [
        &["authorization"][..],
        &["permit2"][..],
        &["transaction"][..],
    ] {
        let merchant = EvmMerchant::start(
            EvmTerms {
                reject: true,
                ..EvmTerms::permit2(8_453, types)
            },
            rpc.clone(),
        )
        .await;
        let error = harness
            .fetch(harness.params(merchant.url("/x")))
            .await
            .expect_err("refused");
        assert!(
            matches!(&error, PaymentsError::Merchant(reason) if reason.contains("second charge")),
            "{types:?}: {error:?}"
        );
        assert_eq!(
            merchant.log(),
            [format!("rejected {}", types[0])],
            "one credential only"
        );
    }
    assert!(rpc.sent().is_empty());
}
