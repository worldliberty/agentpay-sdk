//! Forwarding one proxied request and paying its `402`.
//!
//! The request is sent upstream with the merchant client (no redirects, no
//! proxy). A `402` with an MPP (`WWW-Authenticate: Payment`) challenge is
//! paid through `mpp`'s flow (which asks again and pays the fresh
//! challenge), with the session persisted per origin; any other `402` is
//! tried as x402. A `402` neither can pay is passed through unchanged. A
//! payment that fails is answered with `402` and an
//! `x-agentpay-proxy-error` header naming the error kind.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HeaderValue, CONNECTION, HOST, WWW_AUTHENTICATE};
use hyper::{Request, Response, StatusCode, Version};
use reqwest::Url;
use sha2::{Digest, Sha256};

use super::server::{respond, Body};
use super::{Counters, Shared};
use crate::error::PaymentsError;
use crate::features::mpp::{self, check_session_key, AgentPayProvider, EventParser, Settings};
use crate::features::x402;

/// Largest request body the proxy forwards.
const MAX_REQUEST_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Headers that describe one connection rather than the request (RFC 9110
/// section 7.6.1), plus the legacy `Proxy-Connection`.
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Forwards `request` to `url`, paying a `402`.
pub(super) async fn forward(
    shared: &Arc<Shared>,
    request: Request<Incoming>,
    url: Url,
) -> Response<Body> {
    match forward_inner(shared, request, url).await {
        Ok(response) => response,
        Err((status, message)) => respond(status, &message),
    }
}

async fn forward_inner(
    shared: &Arc<Shared>,
    request: Request<Incoming>,
    url: Url,
) -> Result<Response<Body>, (StatusCode, String)> {
    let (mut parts, body) = request.into_parts();
    let body = Limited::new(body, MAX_REQUEST_BODY_BYTES)
        .collect()
        .await
        .map_err(|_| {
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                "the request body is too large or unreadable".to_string(),
            )
        })?
        .to_bytes();
    strip_hop_by_hop(&mut parts.headers);
    parts.headers.remove(HOST);
    let mut upstream = reqwest::Request::new(parts.method, url.clone());
    *upstream.headers_mut() = parts.headers;
    *upstream.body_mut() = Some(body.into());
    let retry = upstream.try_clone().ok_or((
        StatusCode::BAD_GATEWAY,
        "the request cannot be repeated".to_string(),
    ))?;
    let mut response = shared.client.execute(upstream).await.map_err(|_| {
        (
            StatusCode::BAD_GATEWAY,
            "the upstream request failed".to_string(),
        )
    })?;
    if response.status() != StatusCode::PAYMENT_REQUIRED {
        return Ok(passthrough(response, parts.version, None));
    }
    if has_mpp_challenge(response.headers()) {
        drop(response);
        return Ok(pay_mpp(shared, retry, url, parts.version).await);
    }
    let (body, _) =
        crate::features::http::read_body_bounded(&mut response, x402::MAX_CHALLENGE_BODY_BYTES)
            .await
            .map_err(|_| {
                (
                    StatusCode::BAD_GATEWAY,
                    "the upstream 402 is unreadable".to_string(),
                )
            })?;
    let Some(required) = x402::parse_payment_required(response.headers(), &body) else {
        return Ok(replay(&response, parts.version, body));
    };
    let limits = x402::Limits {
        expected_amount: None,
        max_amount: shared.max_amount,
    };
    match x402::pay(&shared.payer, &shared.client, retry, &required, &limits).await {
        Ok((paid, _)) => {
            Counters::bump(&shared.counters.payments);
            Ok(passthrough(paid, parts.version, None))
        }
        Err(error) => Ok(payment_failed(shared, &error)),
    }
}

/// Pays an MPP `402` for `retry` with the origin's persisted session.
async fn pay_mpp(
    shared: &Arc<Shared>,
    retry: reqwest::Request,
    url: Url,
    version: Version,
) -> Response<Body> {
    let payer = &shared.payer;
    let session_key = session_key(&url);
    if let Err(error) = check_session_key(&session_key) {
        return payment_failed(shared, &error);
    }
    let settings = Settings {
        max_amount: shared.max_amount,
        currency: shared.currency.clone(),
        network: shared.network.clone(),
        deposit: shared.deposit,
        max_deposit: shared.max_deposit,
        known_tokens: shared.known_tokens.clone(),
        session_key: Some(session_key.clone()),
        origin: url.origin().ascii_serialization(),
        url: url.as_str().to_ascii_lowercase(),
        ..Settings::default()
    };
    let lock = payer.sessions.channel(payer.agent_key_id(), &session_key);
    let guard = lock.lock().await;
    let provider = match AgentPayProvider::new(payer.clone(), settings) {
        Ok(provider) => provider,
        Err(error) => return payment_failed(shared, &error),
    };
    let result = mpp::pay(&provider, &shared.client, retry).await;
    drop(guard);
    match result {
        Ok(response) => {
            if mpp::paid(&provider) {
                Counters::bump(&shared.counters.payments);
            }
            let events =
                mpp::paid_session(&provider).then(|| (provider, shared.client.clone(), url));
            passthrough(response, version, events)
        }
        Err(error) => payment_failed(shared, &error),
    }
}

/// `proxy:<host>:<port>`, or a digest of the origin when that is not a
/// valid session key.
fn session_key(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    let port = url.port_or_known_default().unwrap_or_default();
    let key = format!("proxy:{host}:{port}");
    if check_session_key(&key).is_ok() {
        return key;
    }
    let digest = Sha256::digest(url.origin().ascii_serialization().as_bytes());
    format!("proxy:{}", alloy_primitives::hex::encode(&digest[..16]))
}

fn has_mpp_challenge(headers: &HeaderMap) -> bool {
    headers
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            value
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("payment")
        })
}

/// A `402` answering a payment the proxy could not make.
fn payment_failed(shared: &Shared, error: &PaymentsError) -> Response<Body> {
    Counters::bump(&shared.counters.failed_payments);
    tracing::warn!(kind = error.kind(), "paying proxy could not pay");
    let mut response = respond(
        StatusCode::PAYMENT_REQUIRED,
        &format!("agentpay proxy: payment failed ({}): {error}", error.kind()),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-agentpay-proxy-error"),
        HeaderValue::from_static(error.kind()),
    );
    response
}

/// The upstream response, streamed back. A paid session stream's payment
/// events are answered as they pass.
fn passthrough(
    response: reqwest::Response,
    version: Version,
    events: Option<(AgentPayProvider, reqwest::Client, Url)>,
) -> Response<Body> {
    let stream = response
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/event-stream"));
    let mut response = Response::<reqwest::Body>::from(response);
    strip_hop_by_hop(response.headers_mut());
    *response.version_mut() = version;
    match events.filter(|_| stream) {
        Some((provider, client, url)) => {
            let mut parser = EventParser::default();
            response.map(move |body| {
                body.map_frame(move |frame| {
                    if let Some(data) = frame.data_ref() {
                        for (name, data) in parser.push(data) {
                            mpp::answer_event(&provider, &client, &url, &name, &data);
                        }
                    }
                    frame
                })
                .map_err(Into::into)
                .boxed_unsync()
            })
        }
        None => response.map(|body| body.map_err(Into::into).boxed_unsync()),
    }
}

/// A `402` the proxy read but could not pay, sent back unchanged.
fn replay(response: &reqwest::Response, version: Version, body: Vec<u8>) -> Response<Body> {
    let mut replayed = Response::new(
        Full::new(Bytes::from(body))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *replayed.status_mut() = response.status();
    *replayed.version_mut() = version;
    *replayed.headers_mut() = response.headers().clone();
    strip_hop_by_hop(replayed.headers_mut());
    replayed.headers_mut().remove(hyper::header::CONTENT_LENGTH);
    replayed
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let nominated: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}
