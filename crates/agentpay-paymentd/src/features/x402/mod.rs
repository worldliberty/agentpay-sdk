//! `X402Fetch`: fetch a URL and pay an x402 `402` with an EIP-3009
//! authorization signed by the signer daemon. The wire contract and flow
//! are documented on `agentpay_api::payments::x402`.
//!
//! - `requirements`: decoding the `402` (v2 header, v1 body) with
//!   `x402-types` and normalizing its requirements;
//! - `scheme`: the exact EIP-3009 scheme on `x402-types`' client traits,
//!   signing through the signer daemon and checking the signature.
//!
//! `pay` is shared with the paying proxy.

mod requirements;
mod scheme;

#[cfg(test)]
mod tests;

use agentpay_api::payments::{
    PaymentsRpcRequest as Req, PaymentsRpcResponse as Res, X402FetchParams, X402FetchResult,
    X402Payment,
};
use base64::Engine;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;
use x402_types::proto;
use x402_types::scheme::client::{PaymentSelector, X402SchemeClient};

use super::http::{self, header_str};
use super::payer::Payer;
use crate::auth::AuthenticatedAgent;
use crate::error::PaymentsError;
use crate::state::AppState;
pub(crate) use requirements::parse_payment_required;
use scheme::{ExactEip3009, Outcome, WithinLimits};

/// Longest `402` body read while looking for v1 requirements.
pub(crate) const MAX_CHALLENGE_BODY_BYTES: usize = 64 * 1024;

/// Handles `X402Fetch`.
pub async fn handle(
    state: &AppState,
    agent: &AuthenticatedAgent,
    request: Req,
) -> Result<Res, PaymentsError> {
    let Req::X402Fetch(params) = request else {
        return Err(PaymentsError::Internal(format!(
            "the x402 feature cannot handle {}",
            request.method_name()
        )));
    };
    let payer = Payer::new(state, agent, params.approval_wait_secs).await?;
    fetch(&payer, params).await.map(Res::X402Response)
}

async fn fetch(payer: &Payer, params: X402FetchParams) -> Result<X402FetchResult, PaymentsError> {
    let client = http::merchant_client()?;
    let request = http::build_request(&client, &params.request)?;
    let retry = request
        .try_clone()
        .ok_or_else(|| PaymentsError::Internal("the request cannot be repeated".into()))?;
    let mut first = http::send(&client, request).await?;
    if first.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
        return Ok(X402FetchResult {
            response: http::read_response(first).await?,
            payment: None,
        });
    }
    let (body, _) = http::read_body_bounded(&mut first, MAX_CHALLENGE_BODY_BYTES).await?;
    let required = parse_payment_required(first.headers(), &body).ok_or_else(|| {
        PaymentsError::Merchant(
            "the merchant answered 402 with no x402 payment requirements; nothing was signed"
                .into(),
        )
    })?;
    let limits = Limits {
        expected_amount: params.expected_amount,
        max_amount: params.max_amount,
    };
    let (response, payment) = pay(payer, &client, retry, &required, &limits).await?;
    Ok(X402FetchResult {
        response: http::read_response(response).await?,
        payment: Some(payment),
    })
}

/// Caller limits on the amount of one payment.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Limits {
    /// The amount must equal this.
    pub(crate) expected_amount: Option<u128>,
    /// The amount must not exceed this.
    pub(crate) max_amount: Option<u128>,
}

/// Pays `required` and sends `retry` with the payment header. Returns the
/// merchant's (unread) answer and what was paid.
pub(crate) async fn pay(
    payer: &Payer,
    client: &reqwest::Client,
    mut retry: reqwest::Request,
    required: &proto::PaymentRequired,
    limits: &Limits,
) -> Result<(reqwest::Response, X402Payment), PaymentsError> {
    let (version, header) = match required {
        proto::PaymentRequired::V1(_) => (1, "x-payment"),
        proto::PaymentRequired::V2(_) => (2, "payment-signature"),
    };
    let outcome = Outcome::default();
    let candidates = ExactEip3009::new(version, payer.clone(), outcome.clone()).accept(required);
    if candidates.is_empty() {
        let (all, _) = requirements::requirements(required);
        let reasons: Vec<String> = all.into_iter().filter_map(Result::err).collect();
        return Err(PaymentsError::InvalidRequest(format!(
            "no x402 requirement can be paid with an EIP-3009 authorization ({}); nothing was signed",
            if reasons.is_empty() {
                "the merchant listed none".to_string()
            } else {
                reasons.join("; ")
            }
        )));
    }
    let selector = WithinLimits {
        expected_amount: limits.expected_amount,
        max_amount: limits.max_amount,
    };
    let Some(candidate) = selector.select(&candidates) else {
        let reasons: Vec<String> = candidates
            .iter()
            .filter_map(|candidate| selector.refusal(candidate.amount))
            .collect();
        return Err(PaymentsError::InvalidRequest(format!(
            "{}; nothing was signed",
            reasons.join("; ")
        )));
    };
    let value = match candidate.sign().await {
        Ok(value) => value,
        Err(error) => {
            return Err(outcome
                .error
                .take()
                .unwrap_or_else(|| PaymentsError::Internal(error.to_string())))
        }
    };
    let signed = outcome
        .take_signed()
        .ok_or_else(|| PaymentsError::Internal("the payment was not recorded".into()))?;
    let value = HeaderValue::from_str(&value)
        .map_err(|_| PaymentsError::Internal("the payment header is not ASCII".into()))?;
    retry
        .headers_mut()
        .insert(HeaderName::from_static(header), value);
    let response = http::send(client, retry)
        .await
        .map_err(|error| match error {
            PaymentsError::Merchant(reason) => PaymentsError::Merchant(format!(
                "{reason} after the payment was signed; the authorization may still be settled"
            )),
            other => other,
        })?;
    let requirement = &signed.requirement;
    let payment = X402Payment {
        x402_version: requirement.version,
        scheme: requirement.scheme.clone(),
        network: requirement.network.clone(),
        chain_id: requirement.chain_id,
        asset: requirement.asset.clone(),
        pay_to: requirement.pay_to.clone(),
        amount: requirement.amount,
        from: signed.from,
        valid_after: signed.valid_after,
        valid_before: signed.valid_before,
        nonce_hex: signed.nonce_hex,
        payment_response: payment_response(response.headers()),
    };
    Ok((response, payment))
}

/// The decoded `PAYMENT-RESPONSE` / `X-PAYMENT-RESPONSE` header.
fn payment_response(headers: &HeaderMap) -> Option<Value> {
    let header = header_str(headers, "payment-response")
        .or_else(|| header_str(headers, "x-payment-response"))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(header.trim())
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    Some(decoded.unwrap_or_else(|| Value::String(header.to_string())))
}
