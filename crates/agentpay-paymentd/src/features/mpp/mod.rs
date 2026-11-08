//! `MppFetch`: fetch a URL and pay an MPP `402` with a Tempo charge or a
//! TIP-1034 session. The wire contract (selection, charges, sessions,
//! streams, approvals) is documented on `agentpay_api::payments::mpp`.
//!
//! `mpp` drives the HTTP payment flow ([`send_with_exchange`]): challenge
//! parsing, expiry and origin checks, `Accept-Payment` ranking, retries,
//! receipts, and commit/rollback. paymentd plugs in:
//!
//! - `provider`: `AgentPayProvider`, the `PaymentProvider` whose choices
//!   and signatures go through the signer daemon;
//! - `exchange`: the redirect-free HTTP exchange;
//! - `select`: challenge normalization and selection;
//! - `charge`, `session`, `tempo`: the payments and their checks;
//! - `management`, `sse`: management POSTs and paid event streams;
//! - `store`: persisted channels.

mod charge;
mod evm_charge;
mod evm_tx;
mod exchange;
mod funds;
mod management;
mod permit2;
mod provider;
mod select;
mod session;
mod solana_charge;
mod sse;
mod store;
mod tempo;

#[cfg(test)]
pub(crate) mod tests;

use agentpay_api::payments::ChainFamily;
use agentpay_api::payments::{
    MppCharge, MppFetchParams, MppFetchResult, MppPayment, MppSession, PaymentsConfig,
    PaymentsRpcRequest as Req, PaymentsRpcResponse as Res,
};
use mpp::client::{send_with_exchange, AcceptPaymentPolicy, ClientEvents, FlowError, HttpError};
use mpp::parse_receipt;
use reqwest::Url;
use serde_json::Value;

use super::http::{self, header_str};
use super::payer::Payer;
use crate::auth::AuthenticatedAgent;
use crate::error::PaymentsError;
use crate::state::AppState;
use exchange::MerchantExchange;
pub(crate) use provider::{AgentPayProvider, Settings};
use select::Intent;
pub(crate) use sse::EventParser;
pub(crate) use store::check_session_key;
pub use store::SessionLocks;

/// Payment retries `mpp` may make after the first `402`.
const MAX_PAYMENT_RETRIES: usize = 3;

/// Handles `MppFetch`.
pub async fn handle(
    state: &AppState,
    agent: &AuthenticatedAgent,
    request: Req,
) -> Result<Res, PaymentsError> {
    let Req::MppFetch(params) = request else {
        return Err(PaymentsError::Internal(format!(
            "the MPP feature cannot handle {}",
            request.method_name()
        )));
    };
    let payer = Payer::new(state, agent, params.approval_wait_secs).await?;
    fetch(&payer, params).await.map(Res::MppResponse)
}

async fn fetch(payer: &Payer, params: MppFetchParams) -> Result<MppFetchResult, PaymentsError> {
    if let Some(key) = &params.session_key {
        check_session_key(key)?;
    }
    let client = http::merchant_client()?;
    let request = http::build_request(&client, &params.request)?;
    let url = request.url().clone();
    let settings = Settings {
        amount: params.amount,
        max_amount: None,
        deposit: params.deposit,
        max_deposit: params.max_deposit,
        currency: params.currency.clone(),
        network: params.network.clone(),
        known_tokens: known_tokens(&payer.config),
        session_key: params.session_key.clone(),
        origin: url.origin().ascii_serialization(),
        url: url.as_str().to_ascii_lowercase(),
    };
    let lock = params
        .session_key
        .as_deref()
        .map(|key| payer.sessions.channel(payer.agent_key_id(), key));
    let _guard = match &lock {
        Some(lock) => Some(lock.lock().await),
        None => None,
    };
    let provider = AgentPayProvider::new(payer.clone(), settings)?;
    let response = pay(&provider, &client, request).await?;
    finish(&provider, &client, &url, response, params.close_session).await
}

/// Sends `request` through `mpp`'s payment flow with `provider`.
pub(crate) async fn pay(
    provider: &AgentPayProvider,
    client: &reqwest::Client,
    request: reqwest::Request,
) -> Result<reqwest::Response, PaymentsError> {
    let mut exchange = MerchantExchange::new(client.clone(), provider.clone());
    let result = send_with_exchange(
        &mut exchange,
        request,
        provider,
        &AcceptPaymentPolicy::Always,
        &ClientEvents::default(),
        MAX_PAYMENT_RETRIES,
    )
    .await;
    // A typed error from the provider's callbacks wins over `mpp`'s wrapper.
    if let Some(error) = provider.take_error() {
        return Err(error);
    }
    result.map_err(|error| match error {
        FlowError::Send(error) => error,
        FlowError::Payment(error) => flow_error(provider, error),
    })
}

fn flow_error(provider: &AgentPayProvider, error: HttpError) -> PaymentsError {
    match error {
        HttpError::NoSupportedChallenge(message) => {
            let reason = provider.state().selection_error.take().unwrap_or(message);
            PaymentsError::InvalidRequest(format!(
                "no MPP challenge can be paid ({reason}); nothing was signed"
            ))
        }
        HttpError::Request(error) => http::merchant_error(&error),
        HttpError::Payment(mpp::MppError::PaymentExpired(_)) => PaymentsError::Merchant(
            "every payable MPP challenge has expired; nothing was signed".into(),
        ),
        other => PaymentsError::Merchant(format!("the MPP payment flow failed: {other}")),
    }
}

/// Reads the paid response, answers a stream's payment events, closes the
/// channel when asked, and reports what was paid.
async fn finish(
    provider: &AgentPayProvider,
    client: &reqwest::Client,
    url: &Url,
    response: reqwest::Response,
    close_session: bool,
) -> Result<MppFetchResult, PaymentsError> {
    let paid = provider.state().paid.clone();
    let Some(paid) = paid else {
        return Ok(MppFetchResult {
            response: http::read_response(response).await?,
            payment: None,
        });
    };
    let header_receipt = header_str(response.headers(), "payment-receipt")
        .and_then(|header| parse_receipt(header).ok())
        .and_then(|receipt| serde_json::to_value(receipt).ok());
    if paid.offer.intent() == Intent::Session {
        if let Some(receipt) = &header_receipt {
            if let Some(channel) = receipt_channel(receipt) {
                sse::ensure_channel(provider, &channel)?;
            }
        }
    }
    let stream = header_str(response.headers(), "content-type")
        .is_some_and(|value| value.to_ascii_lowercase().starts_with("text/event-stream"));
    let (http_response, receipt) = if stream && paid.offer.intent() == Intent::Session {
        let (collected, stream_receipt) = sse::collect(provider, client, url, response).await?;
        (collected, stream_receipt.or(header_receipt))
    } else {
        (http::read_response(response).await?, header_receipt)
    };
    let session = match paid.offer.intent() {
        Intent::Charge => None,
        Intent::Session => Some(
            session_report(
                provider,
                client,
                url,
                &paid,
                close_session,
                receipt.as_ref(),
            )
            .await?,
        ),
    };
    let offer = &paid.offer;
    let network = match &paid.charge {
        Some(charged) => charged.network.clone(),
        None => network_key(&provider.payer().config, offer.chain_id()),
    };
    Ok(MppFetchResult {
        response: http_response,
        payment: Some(MppPayment {
            challenge_id: paid.challenge.id.clone(),
            realm: paid.challenge.realm.clone(),
            method: paid.challenge.method.to_string(),
            intent: paid.challenge.intent.to_string(),
            session_protocol: (offer.intent() == Intent::Session).then(|| "v2".to_string()),
            chain_id: offer.chain_id(),
            network,
            currency: offer.currency(),
            recipient: offer.recipient(),
            amount: offer.amount(),
            charge: paid.charge.as_ref().map(|charged| MppCharge {
                network: charged.network.clone(),
                credential_type: charged.credential_type.to_string(),
                tx_hash: charged.tx_hash.clone(),
                memo_hex: charged.memo_hex.clone(),
            }),
            session,
            receipt,
        }),
    })
}

/// Closes the channel when asked (or when it was opened for this call
/// only), and describes it.
async fn session_report(
    provider: &AgentPayProvider,
    client: &reqwest::Client,
    url: &Url,
    paid: &provider::Paid,
    close_session: bool,
    receipt: Option<&Value>,
) -> Result<MppSession, PaymentsError> {
    let active = provider.state().active.clone();
    let Some(active) = active else {
        return Err(PaymentsError::Merchant(
            "the merchant did not accept the session payment".into(),
        ));
    };
    let session_key = provider.settings().session_key.clone();
    let mut close_receipt = None;
    let closes = close_session || session_key.is_none();
    if closes {
        let amount = close_amount(active.record.cumulative, receipt);
        let payload = session::close(provider.payer(), &active.record, amount).await?;
        let source = provider.source(active.record.chain_id);
        let response =
            management::post(client, url, &paid.challenge, &source, &payload, "close").await?;
        close_receipt = header_str(response.headers(), "payment-receipt")
            .and_then(|header| parse_receipt(header).ok())
            .and_then(|receipt| serde_json::to_value(receipt).ok());
        provider.forget()?;
    }
    Ok(MppSession {
        session_key,
        channel_id: active.record.channel_id_hex.clone(),
        opened: active.opened,
        deposit: active.record.deposit,
        topped_up: active.topped_up,
        cumulative_amount: active.record.cumulative,
        vouchers: active.vouchers,
        closed: closes,
        close_receipt,
    })
}

/// Every token deployment in `config` as an MPP currency `(chain id, token)`, lower case: the
/// tokens the agent can hold limits and balances for, preferred when a merchant offers several.
pub(crate) fn known_tokens(config: &PaymentsConfig) -> Vec<(u64, String)> {
    let solana: Vec<u64> = config
        .chains
        .values()
        .filter(|chain| chain.family == ChainFamily::Solana)
        .map(|chain| chain.chain_id)
        .collect();
    config
        .tokens
        .values()
        .flat_map(|token| token.chains.values())
        .filter_map(|chain| match chain.address.as_deref() {
            Some(address) => Some((chain.chain_id, address.trim().to_ascii_lowercase())),
            // Native SOL is `"sol"` in MPP; native EVM coins are never MPP currencies.
            None if chain.is_native && solana.contains(&chain.chain_id) => {
                Some((chain.chain_id, "sol".to_string()))
            }
            None => None,
        })
        .collect()
}

/// Chains AgentPay can pay MPP charges on: configured networks with an RPC.
pub(crate) fn configured_chains(config: &PaymentsConfig) -> Vec<u64> {
    config
        .chains
        .values()
        .filter(|chain| chain.rpc_url.is_some())
        .map(|chain| chain.chain_id)
        .collect()
}

/// The configured network key with `chain_id` (empty when none).
fn network_key(config: &PaymentsConfig, chain_id: u64) -> String {
    config
        .chains
        .iter()
        .find(|(_, chain)| chain.chain_id == chain_id)
        .map(|(key, _)| key.clone())
        .unwrap_or_default()
}

/// Whether `provider`'s flow paid something.
pub(crate) fn paid(provider: &AgentPayProvider) -> bool {
    provider.state().paid.is_some()
}

/// Whether `provider`'s flow paid with a session channel that is in use.
pub(crate) fn paid_session(provider: &AgentPayProvider) -> bool {
    let state = provider.state();
    state.active.is_some()
        && state
            .paid
            .as_ref()
            .is_some_and(|paid| paid.offer.intent() == Intent::Session)
}

/// Answers one event of a paid session stream that passes through the
/// proxy: a `payment-need-voucher` gets a voucher (after a top-up when
/// needed) in the background; other events need nothing.
pub(crate) fn answer_event(
    provider: &AgentPayProvider,
    client: &reqwest::Client,
    url: &Url,
    name: &str,
    data: &str,
) {
    if name != "payment-need-voucher" {
        return;
    }
    let (provider, client, url, data) = (
        provider.clone(),
        client.clone(),
        url.clone(),
        data.to_string(),
    );
    tokio::spawn(async move {
        if let Err(error) = sse::need_voucher(&provider, &client, &url, &data).await {
            tracing::warn!(
                kind = error.kind(),
                "failed to answer a payment-need-voucher event"
            );
        }
    });
}

/// The channel a session receipt names (`channelId`, else `reference`).
fn receipt_channel(receipt: &Value) -> Option<String> {
    receipt
        .get("channelId")
        .or_else(|| receipt.get("reference"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// The amount to close at: the merchant's reported `spent`, else its
/// `acceptedCumulative`, when positive and not above what was signed;
/// otherwise everything signed.
fn close_amount(signed: u128, receipt: Option<&Value>) -> u128 {
    let field = |name: &str| {
        receipt
            .and_then(|receipt| receipt.get(name))
            .and_then(Value::as_str)
            .and_then(|value| value.trim().parse::<u128>().ok())
            .filter(|value| *value > 0 && *value <= signed)
    };
    field("spent")
        .or_else(|| field("acceptedCumulative"))
        .unwrap_or(signed)
}
