//! A mock MPP merchant that issues real `mpp` challenges and verifies the
//! credentials it receives with `mpp`'s and `tempo-alloy`'s own code.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{hex, keccak256, Address, TxKind, B256};
use alloy_sol_types::{sol, SolCall};
use mpp::client::tempo::session::channel_ops::{
    compute_expiring_nonce_hash, compute_fee_payer_expiring_nonce_hash,
    compute_precompile_channel_id_from_descriptor,
};
use mpp::protocol::core::{
    format_www_authenticate, parse_authorization, Base64UrlJson, PaymentChallenge,
    PaymentCredential, Receipt,
};
use mpp::protocol::methods::tempo::precompile_voucher::{
    precompile_close_authorization_signing_hash_with_escrow, verify_precompile_voucher_signature,
};
use mpp::protocol::methods::tempo::session::SessionCredentialPayload;
use mpp::protocol::methods::tempo::{FeePayerEnvelope78, SessionReceipt};
use mpp::tempo::attribution;
use serde_json::{json, Value};
use tempo_alloy::contracts::precompiles::{ITIP20ChannelReserve, TIP20_CHANNEL_RESERVE_ADDRESS};
use tempo_alloy::primitives::transaction::{TempoSignature, TempoTransaction};
use tempo_alloy::primitives::TempoTxEnvelope;

use super::{CHAIN_ID, PATH_USD, RECIPIENT};
use crate::chains::evm::mock_rpc::MockRpc;
use crate::features::http::merchant::{Merchant, Reply, Seen};

sol! {
    function transferWithMemo(address to, uint256 amount, bytes32 memo);
}

/// The realm the merchant names.
pub(crate) const REALM: &str = "llm.example.com";

/// What the merchant charges and how.
#[derive(Debug, Clone)]
pub(crate) struct Terms {
    pub(crate) intent: &'static str,
    pub(crate) amount: u128,
    pub(crate) suggested_deposit: Option<u128>,
    pub(crate) fee_payer: bool,
    /// `methodDetails` overrides merged into the request.
    pub(crate) details: Value,
    /// Ask for the credential in `Payment-Authorization`.
    pub(crate) payment_authorization: bool,
    pub(crate) opaque: Option<Value>,
    /// Answer paid session requests with an event stream that asks for one
    /// more voucher.
    pub(crate) stream: bool,
    /// Recipient override.
    pub(crate) recipient: &'static str,
    /// Tokens offered in extra challenges listed before the pathUSD one (like a merchant that
    /// accepts several); only pathUSD challenges are ever paid.
    pub(crate) other_currencies: Vec<&'static str>,
}

impl Terms {
    pub(crate) fn charge(amount: u128) -> Self {
        Self {
            intent: "charge",
            amount,
            suggested_deposit: None,
            fee_payer: false,
            details: json!({}),
            payment_authorization: false,
            opaque: None,
            stream: false,
            recipient: RECIPIENT,
            other_currencies: Vec::new(),
        }
    }

    pub(crate) fn session(amount: u128, suggested_deposit: Option<u128>) -> Self {
        Self {
            intent: "session",
            suggested_deposit,
            fee_payer: true,
            details: json!({"sessionProtocol": "v2"}),
            ..Self::charge(amount)
        }
    }
}

/// A channel as the merchant sees it.
#[derive(Debug, Clone, Default)]
pub(crate) struct Channel {
    pub(crate) payer: Address,
    /// The token the channel was opened in.
    pub(crate) token: Address,
    pub(crate) deposit: u128,
    pub(crate) accepted: u128,
    pub(crate) closed: bool,
}

/// The merchant's books.
#[derive(Debug)]
pub(crate) struct Book {
    /// The current terms; tests may change them between calls.
    pub(crate) terms: Terms,
    challenges: HashMap<String, PaymentChallenge>,
    pub(crate) channels: HashMap<B256, Channel>,
    /// What happened, in order: `charge`, `open`, `voucher`, `top-up`, `close`.
    pub(crate) log: Vec<String>,
    next_id: u32,
}

/// A running MPP merchant.
pub(crate) struct MppMerchant {
    pub(crate) http: Merchant,
    pub(crate) book: Arc<Mutex<Book>>,
}

impl MppMerchant {
    pub(crate) async fn start(terms: Terms, rpc: Arc<MockRpc>) -> Self {
        let book = Arc::new(Mutex::new(Book {
            terms,
            challenges: HashMap::new(),
            channels: HashMap::new(),
            log: Vec::new(),
            next_id: 0,
        }));
        let shared = book.clone();
        let http = Merchant::start(move |seen: &Seen| {
            let mut book = shared.lock().expect("book");
            let terms = book.terms.clone();
            serve(&terms, &rpc, &mut book, seen)
        })
        .await;
        Self { http, book }
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}{path}", self.http.url())
    }

    /// Forgets every channel, as a merchant that lost its state.
    pub(crate) fn forget_channels(&self) {
        self.book.lock().expect("book").channels.clear();
    }

    /// Changes the terms of later challenges.
    pub(crate) fn set_terms(&self, terms: Terms) {
        self.book.lock().expect("book").terms = terms;
    }

    pub(crate) fn log(&self) -> Vec<String> {
        self.book.lock().expect("book").log.clone()
    }

    pub(crate) fn channel(&self) -> Channel {
        let book = self.book.lock().expect("book");
        assert_eq!(book.channels.len(), 1, "one channel");
        book.channels.values().next().cloned().unwrap_or_default()
    }
}

fn challenge(terms: &Terms, book: &mut Book, currency: &str) -> PaymentChallenge {
    book.next_id += 1;
    let mut details = json!({"chainId": CHAIN_ID});
    if terms.intent == "session" && terms.fee_payer {
        details["feePayer"] = Value::Bool(true);
    }
    if let (Some(target), Some(extra)) = (details.as_object_mut(), terms.details.as_object()) {
        target.extend(extra.clone());
    }
    let mut request = json!({
        "amount": terms.amount.to_string(),
        "currency": currency,
        "recipient": terms.recipient,
        "methodDetails": details,
    });
    if let Some(deposit) = terms.suggested_deposit {
        request["suggestedDeposit"] = Value::String(deposit.to_string());
    }
    let mut challenge = PaymentChallenge::new(
        format!("challenge-{}", book.next_id),
        REALM,
        "tempo",
        terms.intent,
        Base64UrlJson::from_value(&request).expect("request"),
    )
    .with_expires("2099-01-01T00:00:00Z");
    if let Some(opaque) = &terms.opaque {
        challenge = challenge.with_opaque(Base64UrlJson::from_value(opaque).expect("opaque"));
    }
    if terms.payment_authorization {
        challenge = challenge.with_header("Payment-Authorization");
    }
    book.challenges
        .insert(challenge.id.clone(), challenge.clone());
    challenge
}

fn serve(terms: &Terms, rpc: &MockRpc, book: &mut Book, seen: &Seen) -> Reply {
    let header = if terms.payment_authorization {
        assert!(
            seen.header("authorization").is_none(),
            "credential in the wrong header"
        );
        seen.header("payment-authorization")
    } else {
        seen.header("authorization")
    };
    let Some(header) = header else {
        let offered: Vec<String> = terms
            .other_currencies
            .iter()
            .copied()
            .chain([PATH_USD])
            .map(|currency| {
                format_www_authenticate(&challenge(terms, book, currency))
                    .expect("challenge header")
            })
            .collect();
        return Reply::new(402, "payment required").header("WWW-Authenticate", offered.join(", "));
    };
    let credential = parse_authorization(header).expect("credential");
    let issued = book
        .challenges
        .get(&credential.challenge.id)
        .cloned()
        .expect("a challenge the merchant issued");
    let echo = issued.to_echo();
    assert_eq!(
        credential.challenge.request.raw(),
        echo.request.raw(),
        "request echoed"
    );
    assert_eq!(
        credential.challenge.opaque.as_ref().map(Base64UrlJson::raw),
        echo.opaque.as_ref().map(Base64UrlJson::raw),
        "opaque echoed unchanged"
    );
    assert_eq!(credential.challenge.header, echo.header);
    if terms.intent == "charge" {
        return charge(terms, rpc, book, &credential);
    }
    session(terms, book, seen, &credential)
}

fn charge(terms: &Terms, rpc: &MockRpc, book: &mut Book, credential: &PaymentCredential) -> Reply {
    let payload = credential.charge_payload().expect("charge payload");
    let hash: B256 = payload
        .tx_hash()
        .expect("hash credential")
        .parse()
        .expect("hash");
    let raw = rpc
        .sent()
        .into_iter()
        .find(|raw| keccak256(raw) == hash)
        .expect("the transaction was sent");
    let TxEnvelope::Eip1559(signed) = TxEnvelope::decode_2718_exact(&raw).expect("envelope") else {
        panic!("an EIP-1559 transaction");
    };
    let tx = signed.tx();
    assert_eq!(tx.to, TxKind::Call(PATH_USD.parse().expect("token")));
    let call = transferWithMemoCall::abi_decode(&tx.input).expect("transferWithMemo");
    assert_eq!(call.to, RECIPIENT.parse::<Address>().expect("recipient"));
    assert_eq!(call.amount, alloy_primitives::U256::from(terms.amount));
    let memo: [u8; 32] = call.memo.0;
    assert!(
        attribution::verify_server(&memo, REALM),
        "memo names the realm"
    );
    assert!(
        attribution::verify_challenge_binding(&memo, &credential.challenge.id),
        "memo binds the challenge"
    );
    book.log.push("charge".into());
    let receipt = Receipt::success("tempo", format!("{hash:#x}"));
    Reply::new(200, "{\"answer\":42}")
        .header("content-type", "application/json")
        .header("Payment-Receipt", receipt.to_header().expect("receipt"))
}

/// Decodes a session transaction (`0x76`, or the `0x78` fee-payer envelope)
/// and returns it with its recovered sender.
fn session_transaction(hex_tx: &str, sponsored: bool) -> (TempoTransaction, Address) {
    let bytes = hex::decode(hex_tx.trim_start_matches("0x")).expect("transaction hex");
    if sponsored {
        let envelope = FeePayerEnvelope78::decode_envelope(&bytes).expect("0x78 envelope");
        let signed = envelope.to_recoverable_signed();
        let sender = signed
            .signature()
            .recover_signer(&signed.tx().signature_hash())
            .expect("recover");
        assert_eq!(sender, envelope.sender);
        return (signed.tx().clone(), sender);
    }
    let TempoTxEnvelope::AA(signed) =
        TempoTxEnvelope::decode_2718(&mut bytes.as_slice()).expect("0x76 envelope")
    else {
        panic!("a Tempo transaction");
    };
    assert!(matches!(signed.signature(), TempoSignature::Primitive(_)));
    let sender = signed
        .signature()
        .recover_signer(&signed.tx().signature_hash())
        .expect("recover");
    (signed.tx().clone(), sender)
}

fn verify_voucher(channel_id: B256, payer: Address, cumulative: u128, signature: &str) {
    let bytes = hex::decode(signature.trim_start_matches("0x")).expect("signature hex");
    assert!(
        verify_precompile_voucher_signature(
            &bytes,
            payer,
            channel_id,
            cumulative,
            TIP20_CHANNEL_RESERVE_ADDRESS,
            CHAIN_ID
        )
        .expect("verifiable"),
        "voucher signature"
    );
}

fn receipt(credential: &PaymentCredential, channel_id: B256, accepted: u128) -> String {
    SessionReceipt::new(
        "2026-11-05T12:00:00Z",
        credential.challenge.id.clone(),
        format!("{channel_id:#x}"),
        accepted.to_string(),
        accepted.to_string(),
    )
    .to_header()
    .expect("receipt")
}

fn session(terms: &Terms, book: &mut Book, seen: &Seen, credential: &PaymentCredential) -> Reply {
    let payload: SessionCredentialPayload = credential.payload_as().expect("session payload");
    let management = seen.method == "POST";
    match payload {
        SessionCredentialPayload::Open {
            channel_id,
            transaction,
            descriptor,
            cumulative_amount,
            signature,
            ..
        } => {
            let descriptor = descriptor.expect("descriptor");
            let channel_id: B256 = channel_id.parse().expect("channel id");
            assert_eq!(
                compute_precompile_channel_id_from_descriptor(&descriptor, CHAIN_ID)
                    .expect("descriptor"),
                channel_id
            );
            let (tx, payer) = session_transaction(&transaction, terms.fee_payer);
            let expiring = if terms.fee_payer {
                compute_fee_payer_expiring_nonce_hash(&tx, payer)
            } else {
                compute_expiring_nonce_hash(&tx, payer)
            };
            assert_eq!(
                format!("{expiring:#x}"),
                descriptor.expiring_nonce_hash.to_lowercase()
            );
            assert_eq!(tx.calls.len(), 1);
            assert_eq!(tx.calls[0].to, TxKind::Call(TIP20_CHANNEL_RESERVE_ADDRESS));
            let open =
                ITIP20ChannelReserve::openCall::abi_decode(&tx.calls[0].input).expect("open");
            assert_eq!(
                open.payee,
                terms.recipient.parse::<Address>().expect("payee")
            );
            assert_eq!(open.authorizedSigner, payer);
            let deposit: u128 = open.deposit.to();
            let cumulative: u128 = cumulative_amount.parse().expect("cumulative");
            assert_eq!(cumulative, terms.amount);
            verify_voucher(channel_id, payer, cumulative, &signature);
            book.channels.insert(
                channel_id,
                Channel {
                    payer,
                    token: open.token,
                    deposit,
                    accepted: cumulative,
                    closed: false,
                },
            );
            book.log.push("open".into());
            paid_reply(terms, credential, channel_id, cumulative)
        }
        SessionCredentialPayload::Voucher {
            channel_id,
            cumulative_amount,
            signature,
            ..
        } => {
            let channel_id: B256 = channel_id.parse().expect("channel id");
            let Some(channel) = book.channels.get_mut(&channel_id) else {
                // A channel the merchant no longer knows.
                return Reply::new(410, "unknown channel");
            };
            let cumulative: u128 = cumulative_amount.parse().expect("cumulative");
            verify_voucher(channel_id, channel.payer, cumulative, &signature);
            assert!(cumulative > channel.accepted && cumulative <= channel.deposit);
            if !management {
                assert_eq!(
                    cumulative - channel.accepted,
                    terms.amount,
                    "one request's worth"
                );
            }
            channel.accepted = cumulative;
            book.log.push("voucher".into());
            if management {
                return Reply::new(200, "");
            }
            paid_reply(terms, credential, channel_id, cumulative)
        }
        SessionCredentialPayload::TopUp {
            channel_id,
            transaction,
            additional_deposit,
            ..
        } => {
            assert!(management, "top-ups are management requests");
            let channel_id: B256 = channel_id.parse().expect("channel id");
            let channel = book.channels.get_mut(&channel_id).expect("known channel");
            let (tx, payer) = session_transaction(&transaction, terms.fee_payer);
            assert_eq!(payer, channel.payer);
            let top_up =
                ITIP20ChannelReserve::topUpCall::abi_decode(&tx.calls[0].input).expect("topUp");
            let additional: u128 = top_up.additionalDeposit.to();
            assert_eq!(additional.to_string(), additional_deposit);
            channel.deposit += additional;
            book.log.push("top-up".into());
            Reply::new(200, "")
        }
        SessionCredentialPayload::Close {
            channel_id,
            cumulative_amount,
            signature,
            close_signature,
            ..
        } => {
            assert!(management, "closes are management requests");
            let channel_id: B256 = channel_id.parse().expect("channel id");
            let channel = book.channels.get_mut(&channel_id).expect("known channel");
            let cumulative: u128 = cumulative_amount.parse().expect("cumulative");
            verify_voucher(channel_id, channel.payer, cumulative, &signature);
            let digest = precompile_close_authorization_signing_hash_with_escrow(
                channel_id,
                cumulative,
                TIP20_CHANNEL_RESERVE_ADDRESS,
                CHAIN_ID,
            )
            .expect("digest");
            let close = hex::decode(
                close_signature
                    .expect("close authorization")
                    .trim_start_matches("0x"),
            )
            .expect("close hex");
            let close = TempoSignature::from_bytes(&close).expect("close signature");
            assert_eq!(
                close.recover_signer(&digest).expect("recover"),
                channel.payer
            );
            channel.closed = true;
            book.log.push("close".into());
            Reply::new(200, "").header(
                "Payment-Receipt",
                receipt(credential, channel_id, cumulative),
            )
        }
    }
}

/// The answer to a paid session request: JSON, or an event stream that
/// asks for one more request's worth.
fn paid_reply(
    terms: &Terms,
    credential: &PaymentCredential,
    channel_id: B256,
    accepted: u128,
) -> Reply {
    let header = receipt(credential, channel_id, accepted);
    if !terms.stream {
        return Reply::new(200, "{\"text\":\"Hi!\"}")
            .header("content-type", "application/json")
            .header("Payment-Receipt", header);
    }
    let required = accepted + terms.amount;
    let need = json!({
        "channelId": format!("{channel_id:#x}"),
        "requiredCumulative": required.to_string(),
        "acceptedCumulative": accepted.to_string(),
        "deposit": "0",
    });
    let final_receipt = json!({
        "method": "tempo", "intent": "session", "status": "success",
        "timestamp": "2026-11-05T12:00:01Z", "reference": format!("{channel_id:#x}"),
        "challengeId": credential.challenge.id, "channelId": format!("{channel_id:#x}"),
        "acceptedCumulative": required.to_string(), "spent": required.to_string(),
    });
    let body = format!(
        "event: message\ndata: hello\n\nevent: payment-need-voucher\ndata: {need}\n\n\
         event: message\ndata: world\n\nevent: payment-receipt\ndata: {final_receipt}\n\n"
    );
    Reply::new(200, body)
        .header("content-type", "text/event-stream")
        .header("Payment-Receipt", header)
}
