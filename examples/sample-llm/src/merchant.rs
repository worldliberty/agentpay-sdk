//! The merchant: OpenAI through MPP at `openai.mpp.tempo.xyz`, paid per
//! request with Tempo session vouchers.

use anyhow::{bail, Context, Result};
use base64::Engine;
use serde_json::{json, Value};

/// Where requests go.
pub const ORIGIN: &str = "https://openai.mpp.tempo.xyz";
/// The host the paying proxy may serve.
pub const HOST: &str = "openai.mpp.tempo.xyz";
/// The paid endpoint.
pub const CHAT: &str = "/v1/chat/completions";
/// Tempo mainnet, where the merchant takes payment.
pub const TEMPO_CHAIN_ID: u64 = 4217;

/// A chat-completion request body.
pub fn chat_body(model: &str, prompt: &str) -> Value {
    json!({
        "model": model,
        "stream": true,
        "messages": [{"role": "user", "content": prompt}],
    })
}

/// The Tempo tokens (lower case) the chat endpoint accepts for `model`.
///
/// Asked from the endpoint itself: an unpaid request is answered `402` with
/// one challenge per accepted token, and costs nothing. The discovery document
/// (`/.well-known/mpp`) lists tokens for the whole service, not per endpoint.
pub async fn accepted_tokens(client: &reqwest::Client, model: &str) -> Result<Vec<String>> {
    let response = client
        .post(format!("{ORIGIN}{CHAT}"))
        .json(&chat_body(model, "hi"))
        .send()
        .await
        .with_context(|| format!("could not reach {HOST}"))?;
    if response.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
        bail!(
            "{HOST} answered {} to an unpaid request instead of asking for payment",
            response.status()
        );
    }
    let header = response
        .headers()
        .get_all(reqwest::header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(", ");
    Ok(challenge_tokens(&header))
}

/// The currency of every Tempo mainnet challenge in a `WWW-Authenticate:
/// Payment` header (each challenge's `request` is base64url JSON).
fn challenge_tokens(header: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut rest = header;
    while let Some(start) = rest.find("request=\"") {
        rest = &rest[start + "request=\"".len()..];
        let Some(end) = rest.find('"') else { break };
        let encoded = rest[..end].trim_end_matches('=');
        rest = &rest[end..];
        let Some(request) = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        else {
            continue;
        };
        if request["methodDetails"]["chainId"].as_u64() != Some(TEMPO_CHAIN_ID) {
            continue;
        }
        if let Some(currency) = request["currency"].as_str() {
            let currency = currency.to_ascii_lowercase();
            if !tokens.contains(&currency) {
                tokens.push(currency);
            }
        }
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge(currency: &str, chain: u64) -> String {
        let request = json!({
            "amount": "616", "currency": currency, "recipient": "0xca4e835F803cB0b7C428222B3A3B98518d4779Fe",
            "methodDetails": {"chainId": chain, "sessionProtocol": "v2"}
        });
        let encoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(request.to_string().as_bytes());
        format!(
            r#"Payment id="x", realm="openai.mpp.tempo.xyz", method="tempo", intent="session", request="{encoded}""#
        )
    }

    #[test]
    fn accepted_tokens_come_from_the_endpoint_challenges() {
        let header = [
            challenge("0x20c0000000000000000000006a37DA5C996874BE", 4217),
            challenge("0x20c000000000000000000000b9537d11c60e8b50", 4217),
            challenge("0x20c000000000000000000000b9537d11c60e8b50", 4217),
            challenge("0x20c0000000000000000000000000000000000000", 42431),
        ]
        .join(", ");
        assert_eq!(
            challenge_tokens(&header),
            [
                "0x20c0000000000000000000006a37da5c996874be",
                "0x20c000000000000000000000b9537d11c60e8b50"
            ],
            "mainnet only, each once"
        );
        assert!(challenge_tokens("Bearer realm=\"x\"").is_empty());
    }
}
