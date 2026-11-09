//! Paid `text/event-stream` responses of a session: the stream is read to
//! its end (bounded), `payment-need-voucher` events are answered with a
//! voucher (after a top-up when the deposit is short), and
//! `payment-receipt` events are checked against the channel and kept.
//!
//! The body is returned after the stream ends, so the caller sees no event
//! while the stream is open. This is enough for request/response style
//! metered APIs; long-lived streams need the paying proxy instead, which
//! passes the stream through.

use agentpay_api::payments::http::MAX_RESPONSE_BODY_BYTES;
use agentpay_api::payments::HttpResponse;
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;

use super::management;
use super::provider::AgentPayProvider;
use super::session;
use crate::error::PaymentsError;
use crate::features::http::{merchant_error, response_with_body};

/// Most bytes read from one stream.
pub(super) const MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;
/// Longest single event kept while parsing.
const MAX_EVENT_BYTES: usize = 64 * 1024;

/// `payment-need-voucher` data (`mpp::server::sse::NeedVoucherEvent`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NeedVoucher {
    channel_id: String,
    required_cumulative: String,
}

/// Named events parsed from a stream as it arrives (the `mpp` forward
/// proxy's parser): `event:` names, `data:` lines joined by `\n`.
#[derive(Default)]
pub(crate) struct EventParser {
    buffer: Vec<u8>,
    name: Option<String>,
    data: Vec<String>,
}

impl EventParser {
    /// Feeds `chunk`; returns the events it completed as `(name, data)`.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Vec<(String, String)> {
        self.buffer.extend_from_slice(chunk);
        let mut events = Vec::new();
        while let Some(end) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.buffer.drain(..=end).collect();
            let line = String::from_utf8_lossy(&line);
            let line = line.trim_end_matches(['\n', '\r']);
            let field = |prefix: &str| {
                line.strip_prefix(prefix)
                    .map(|value| value.strip_prefix(' ').unwrap_or(value).to_owned())
            };
            if line.is_empty() {
                let data = std::mem::take(&mut self.data).join("\n");
                events.extend(self.name.take().map(|name| (name, data)));
            } else if let Some(name) = field("event:") {
                self.name = Some(name);
            } else if let Some(data) = field("data:") {
                if self.data.iter().map(String::len).sum::<usize>() < MAX_EVENT_BYTES {
                    self.data.push(data);
                }
            }
        }
        if self.buffer.len() > MAX_EVENT_BYTES {
            self.buffer.clear();
        }
        events
    }
}

/// Reads a paid session stream, answering its payment events. Returns the
/// collected response and the last `payment-receipt`.
pub(super) async fn collect(
    provider: &AgentPayProvider,
    client: &reqwest::Client,
    url: &Url,
    mut response: reqwest::Response,
) -> Result<(HttpResponse, Option<Value>), PaymentsError> {
    let mut parser = EventParser::default();
    let mut body = Vec::new();
    let mut truncated = false;
    let mut total = 0_usize;
    let mut receipt = None;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| merchant_error(&error))?
    {
        total += chunk.len();
        let room = MAX_RESPONSE_BODY_BYTES.saturating_sub(body.len());
        body.extend_from_slice(&chunk[..chunk.len().min(room)]);
        truncated |= chunk.len() > room;
        for (name, data) in parser.push(&chunk) {
            match name.as_str() {
                "payment-need-voucher" => need_voucher(provider, client, url, &data).await?,
                "payment-receipt" => receipt = Some(checked_receipt(provider, &data)?),
                _ => {}
            }
        }
        if total > MAX_STREAM_BYTES {
            truncated = true;
            break;
        }
    }
    Ok((response_with_body(&response, &body, truncated), receipt))
}

/// A `payment-receipt` event, refused when it names another channel.
fn checked_receipt(provider: &AgentPayProvider, data: &str) -> Result<Value, PaymentsError> {
    let receipt: Value = serde_json::from_str(data)
        .map_err(|_| PaymentsError::Merchant("a payment-receipt event is not JSON".into()))?;
    if let Some(channel) = receipt.get("channelId").and_then(Value::as_str) {
        ensure_channel(provider, channel)?;
    }
    Ok(receipt)
}

/// Fails unless `channel` is the active channel.
pub(super) fn ensure_channel(
    provider: &AgentPayProvider,
    channel: &str,
) -> Result<(), PaymentsError> {
    let state = provider.state();
    let active = state
        .active
        .as_ref()
        .map(|active| active.record.channel_id_hex.as_str());
    if active.is_some_and(|active| active.eq_ignore_ascii_case(channel.trim())) {
        Ok(())
    } else {
        Err(PaymentsError::Merchant(
            "the merchant named a different session channel than the one paid".into(),
        ))
    }
}

/// Answers `payment-need-voucher`: tops up if needed, then POSTs a voucher
/// for the required cumulative amount.
pub(super) async fn need_voucher(
    provider: &AgentPayProvider,
    client: &reqwest::Client,
    url: &Url,
    data: &str,
) -> Result<(), PaymentsError> {
    let event: NeedVoucher = serde_json::from_str(data)
        .map_err(|_| PaymentsError::Merchant("a payment-need-voucher event is malformed".into()))?;
    ensure_channel(provider, &event.channel_id)?;
    let required = event
        .required_cumulative
        .trim()
        .parse::<u128>()
        .map_err(|_| {
            PaymentsError::Merchant("a payment-need-voucher event has an invalid amount".into())
        })?;
    let (active, paid) = {
        let state = provider.state();
        (state.active.clone(), state.paid.clone())
    };
    let (Some(mut active), Some(paid)) = (active, paid) else {
        return Err(PaymentsError::Merchant(
            "the merchant asked for a voucher before a session was paid".into(),
        ));
    };
    if required <= active.record.cumulative {
        return Ok(());
    }
    let Some(offer) = paid.offer.tempo() else {
        return Err(PaymentsError::Merchant(
            "the merchant asked for a voucher for a payment that is not a session".into(),
        ));
    };
    let default_deposit = provider
        .settings()
        .deposit
        .or(offer.suggested_deposit)
        .unwrap_or(offer.amount);
    provider
        .ensure_deposit(
            client,
            url,
            &paid.challenge,
            &mut active,
            required,
            default_deposit,
        )
        .await?;
    let payload = session::voucher(provider.payer(), &active.record, required).await?;
    let source = provider.source(active.record.chain_id);
    management::post(client, url, &paid.challenge, &source, &payload, "voucher").await?;
    active.record.cumulative = required;
    active.vouchers += 1;
    provider.persist(&active.record)?;
    let mut state = provider.state();
    state.persisted = Some(active.record.clone());
    state.active = Some(active);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_are_parsed_across_chunks() {
        let mut parser = EventParser::default();
        assert!(parser.push(b"event: message\ndata: hel").is_empty());
        let events = parser.push(b"lo\ndata: world\n\nevent: payment-receipt\r\ndata: {}\r\n\r\n");
        assert_eq!(
            events,
            vec![
                ("message".to_string(), "hello\nworld".to_string()),
                ("payment-receipt".to_string(), "{}".to_string()),
            ]
        );
        // Unnamed events are ignored.
        assert!(parser.push(b"data: x\n\n").is_empty());
    }
}
