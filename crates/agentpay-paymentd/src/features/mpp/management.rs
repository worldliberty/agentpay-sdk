//! Session management requests: a top-up, a mid-stream voucher, or a close
//! credential POSTed to the resource URL, as mppx clients do.
//!
//! The credential echoes the paid challenge unchanged and travels in the
//! header the challenge names. When the merchant answers `402` with a fresh
//! challenge (the first one expired, say), the credential is sent once more
//! against an equivalent challenge: same method, intent, chain, currency,
//! and recipient, and not a legacy session.

use mpp::protocol::core::{
    format_authorization, parse_www_authenticate_all, PaymentChallenge, PaymentCredential,
};
use mpp::protocol::methods::tempo::session::SessionCredentialPayload;
use reqwest::header::{HeaderName, HeaderValue, WWW_AUTHENTICATE};
use reqwest::{Method, StatusCode, Url};

use super::select::offer;
use crate::error::PaymentsError;
use crate::features::http::{self, read_body_bounded};

/// Longest error body quoted from a failed management request.
const MAX_QUOTED_BODY: usize = 200;

/// POSTs `payload` for `challenge` to `url`; `label` names it in errors.
pub(super) async fn post(
    client: &reqwest::Client,
    url: &Url,
    challenge: &PaymentChallenge,
    source: &str,
    payload: &SessionCredentialPayload,
    label: &str,
) -> Result<reqwest::Response, PaymentsError> {
    let mut url = url.clone();
    url.set_fragment(None);
    let mut response = send(client, &url, challenge, source, payload, label).await?;
    if response.status() == StatusCode::PAYMENT_REQUIRED {
        let fresh = response
            .headers()
            .get_all(WWW_AUTHENTICATE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| parse_www_authenticate_all([value]))
            .filter_map(Result::ok)
            .find(|candidate| equivalent(challenge, candidate));
        if let Some(fresh) = fresh {
            response = send(client, &url, &fresh, source, payload, label).await?;
        }
    }
    if !response.status().is_success() {
        let status = response.status();
        let (body, _) = read_body_bounded(&mut response, MAX_QUOTED_BODY)
            .await
            .unwrap_or_default();
        let body = String::from_utf8_lossy(&body);
        return Err(PaymentsError::Merchant(format!(
            "the session {label} request failed with status {status}{}{}; the {label} was signed",
            if body.trim().is_empty() { "" } else { ": " },
            body.trim()
        )));
    }
    Ok(response)
}

async fn send(
    client: &reqwest::Client,
    url: &Url,
    challenge: &PaymentChallenge,
    source: &str,
    payload: &SessionCredentialPayload,
    label: &str,
) -> Result<reqwest::Response, PaymentsError> {
    let credential = PaymentCredential::with_source(challenge.to_echo(), source, payload);
    let header = format_authorization(&credential)
        .ok()
        .and_then(|value| HeaderValue::from_str(&value).ok())
        .ok_or_else(|| {
            PaymentsError::Internal(format!("the session {label} credential is invalid"))
        })?;
    let name = HeaderName::from_bytes(challenge.credential_header().as_bytes())
        .unwrap_or(reqwest::header::AUTHORIZATION);
    let request = client
        .request(Method::POST, url.clone())
        .header(name, header)
        .build()
        .map_err(|_| PaymentsError::Internal(format!("the session {label} request is invalid")))?;
    http::send(client, request)
        .await
        .map_err(|error| match error {
            PaymentsError::Merchant(reason) => PaymentsError::Merchant(format!(
                "the session {label} request: {reason}; the {label} was signed"
            )),
            other => other,
        })
}

/// Whether `candidate` describes the same channel terms as `original`.
fn equivalent(original: &PaymentChallenge, candidate: &PaymentChallenge) -> bool {
    if candidate.method != original.method || candidate.intent != original.intent {
        return false;
    }
    match (offer(original), offer(candidate)) {
        (Ok(original), Ok(candidate)) => {
            original.chain_id == candidate.chain_id
                && original.currency == candidate.currency
                && original.recipient == candidate.recipient
        }
        _ => false,
    }
}
