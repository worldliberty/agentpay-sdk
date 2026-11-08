//! Parsing an x402 `402 Payment Required` answer into requirements the
//! exact EIP-3009 scheme can pay.
//!
//! v2 carries the `PaymentRequired` object as base64 JSON in the
//! `PAYMENT-REQUIRED` header; v1 carries it as the JSON body. Both are
//! decoded with `x402-types`; each requirement is then normalized into a
//! [`Requirement`] or skipped with a reason.

use std::str::FromStr;

use agentpay_domain::EvmAddress;
use reqwest::header::HeaderMap;
use serde_json::value::RawValue;
use serde_json::Value;
use x402_types::chain::ChainId;
use x402_types::proto::{self, v1, v2, OriginalJson};
use x402_types::util::Base64Bytes;

use crate::features::http::header_str;

/// The v2 header that carries the requirements.
pub(super) const PAYMENT_REQUIRED_HEADER: &str = "payment-required";

/// Parses a `402` answer: the v2 header first, then a v1 JSON body.
pub(crate) fn parse_payment_required(
    headers: &HeaderMap,
    body: &[u8],
) -> Option<proto::PaymentRequired> {
    let v2 = header_str(headers, PAYMENT_REQUIRED_HEADER)
        .and_then(|header| Base64Bytes::from(header.trim().as_bytes()).decode().ok())
        .and_then(|bytes| serde_json::from_slice::<v2::PaymentRequired<OriginalJson>>(&bytes).ok());
    if let Some(required) = v2 {
        return Some(proto::PaymentRequired::V2(required));
    }
    serde_json::from_slice::<v1::PaymentRequired<OriginalJson>>(body)
        .ok()
        .map(proto::PaymentRequired::V1)
}

/// A requirement the exact EIP-3009 scheme can pay.
#[derive(Debug, Clone)]
pub(super) struct Requirement {
    /// x402 version (1 or 2).
    pub(super) version: u8,
    /// `"exact"`.
    pub(super) scheme: String,
    /// The network as the merchant named it.
    pub(super) network: String,
    /// EVM chain id.
    pub(super) chain_id: u64,
    /// Token contract.
    pub(super) asset: EvmAddress,
    /// Recipient.
    pub(super) pay_to: EvmAddress,
    /// Amount in base units.
    pub(super) amount: u128,
    /// The merchant's validity window for the authorization.
    pub(super) max_timeout_seconds: u64,
    /// EIP-712 domain name of the token.
    pub(super) token_name: String,
    /// EIP-712 domain version of the token.
    pub(super) token_version: Option<String>,
    /// The requirement exactly as received (echoed as `accepted` in v2).
    pub(super) original: Box<RawValue>,
}

/// What a v2 payment payload echoes besides the requirement.
#[derive(Debug, Clone, Default)]
pub(super) struct Echo {
    /// `resource` of the v2 `PaymentRequired`.
    pub(super) resource: Option<Value>,
    /// `extensions` of the v2 `PaymentRequired`.
    pub(super) extensions: Option<Value>,
}

/// Every requirement of `required`, normalized or with the reason it was skipped.
pub(super) fn requirements(
    required: &proto::PaymentRequired,
) -> (Vec<Result<Requirement, String>>, Echo) {
    match required {
        proto::PaymentRequired::V1(required) => (
            required.accepts.iter().map(normalize_v1).collect(),
            Echo::default(),
        ),
        proto::PaymentRequired::V2(required) => {
            let echo = Echo {
                resource: required
                    .resource
                    .as_ref()
                    .and_then(|resource| serde_json::to_value(resource).ok()),
                extensions: serde_json::to_value(&required.extensions)
                    .ok()
                    .filter(|value| value.as_object().is_some_and(|map| !map.is_empty())),
            };
            (required.accepts.iter().map(normalize_v2).collect(), echo)
        }
    }
}

fn normalize_v1(original: &OriginalJson) -> Result<Requirement, String> {
    let parsed = v1::PaymentRequirements::<String, String, String, Value>::try_from(original)
        .map_err(|_| "a v1 requirement is malformed".to_string())?;
    let chain = ChainId::from_network_name(&parsed.network)
        .ok_or_else(|| format!("network '{}' is not a known EVM network", parsed.network))?;
    normalize(Fields {
        version: 1,
        scheme: parsed.scheme,
        network: parsed.network,
        chain,
        asset: parsed.asset,
        pay_to: parsed.pay_to,
        amount: parsed.max_amount_required,
        max_timeout_seconds: parsed.max_timeout_seconds,
        extra: parsed.extra,
        original: original.0.clone(),
    })
}

fn normalize_v2(original: &OriginalJson) -> Result<Requirement, String> {
    let parsed =
        v2::PaymentRequirements::<String, String, String, Option<Value>>::try_from(original)
            .map_err(|_| "a v2 requirement is malformed".to_string())?;
    normalize(Fields {
        version: 2,
        scheme: parsed.scheme,
        network: parsed.network.to_string(),
        chain: parsed.network,
        asset: parsed.asset,
        pay_to: parsed.pay_to,
        amount: parsed.amount,
        max_timeout_seconds: parsed.max_timeout_seconds,
        extra: parsed.extra,
        original: original.0.clone(),
    })
}

struct Fields {
    version: u8,
    scheme: String,
    network: String,
    chain: ChainId,
    asset: String,
    pay_to: String,
    amount: String,
    max_timeout_seconds: u64,
    extra: Option<Value>,
    original: Box<RawValue>,
}

fn normalize(fields: Fields) -> Result<Requirement, String> {
    let network = &fields.network;
    if fields.scheme != "exact" {
        return Err(format!(
            "scheme '{}' on {network} is not supported (only exact)",
            fields.scheme
        ));
    }
    if fields.chain.namespace() != "eip155" {
        return Err(format!("network {network} is not an EVM (eip155) network"));
    }
    let chain_id = fields
        .chain
        .reference()
        .parse::<u64>()
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| format!("network {network} has an invalid chain id"))?;
    let asset = EvmAddress::from_str(fields.asset.trim())
        .map_err(|_| format!("asset on {network} is not an EVM address"))?;
    let pay_to = EvmAddress::from_str(fields.pay_to.trim())
        .map_err(|_| format!("payTo on {network} is not an EVM address"))?;
    let amount = fields
        .amount
        .trim()
        .parse::<u128>()
        .ok()
        .filter(|amount| *amount > 0)
        .ok_or_else(|| format!("amount on {network} is not a positive integer"))?;
    let extra = fields.extra.unwrap_or(Value::Null);
    match extra.get("assetTransferMethod").and_then(Value::as_str) {
        None | Some("eip3009") => {}
        Some(other) => {
            return Err(format!(
                "asset transfer method '{other}' on {network} is not supported (only eip3009)"
            ))
        }
    }
    let token_name = extra
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            format!("the requirement on {network} has no EIP-712 token name (extra.name)")
        })?
        .to_string();
    let token_version = extra
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(Requirement {
        version: fields.version,
        scheme: fields.scheme,
        network: fields.network,
        chain_id,
        asset,
        pay_to,
        amount,
        max_timeout_seconds: fields.max_timeout_seconds,
        token_name,
        token_version,
        original: fields.original,
    })
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use reqwest::header::HeaderValue;
    use serde_json::json;

    use super::*;

    fn v2_header(value: &Value) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode(value.to_string());
        headers.insert(
            PAYMENT_REQUIRED_HEADER,
            HeaderValue::from_str(&encoded).expect("header"),
        );
        headers
    }

    #[test]
    fn v2_header_wins_and_requirements_are_normalized() {
        let required = json!({
            "x402Version": 2,
            "resource": {"url": "https://api.example.com/x"},
            "accepts": [
                {"scheme": "upto", "network": "eip155:8453", "amount": "1", "payTo": "0x209693bc6afc0c5328ba36faf03c514ef312287c", "maxTimeoutSeconds": 60, "asset": "0x036cbd53842c5426634e7929541ec2318f3dcf7e", "extra": null},
                {"scheme": "exact", "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "amount": "1", "payTo": "x", "maxTimeoutSeconds": 60, "asset": "y", "extra": null},
                {"scheme": "exact", "network": "eip155:84532", "amount": "1000", "payTo": "0x209693bc6afc0c5328ba36faf03c514ef312287c", "maxTimeoutSeconds": 60, "asset": "0x036cbd53842c5426634e7929541ec2318f3dcf7e", "extra": {"name": "USDC", "version": "2"}}
            ]
        });
        let parsed = parse_payment_required(&v2_header(&required), b"ignored").expect("v2");
        let (all, echo) = requirements(&parsed);
        assert!(echo.resource.is_some());
        assert!(all[0].as_ref().is_err_and(|reason| reason.contains("upto")));
        assert!(all[1]
            .as_ref()
            .is_err_and(|reason| reason.contains("eip155")));
        let paid = all[2].as_ref().expect("payable");
        assert_eq!((paid.version, paid.chain_id, paid.amount), (2, 84532, 1000));
        assert_eq!(paid.token_name, "USDC");
        assert_eq!(paid.token_version.as_deref(), Some("2"));
    }

    #[test]
    fn v1_bodies_parse_and_permit2_or_nameless_requirements_are_skipped() {
        let body = json!({
            "x402Version": 1,
            "accepts": [
                {"scheme": "exact", "network": "base-sepolia", "maxAmountRequired": "500", "resource": "https://api.example.com/x", "description": "", "mimeType": "application/json", "payTo": "0x209693bc6afc0c5328ba36faf03c514ef312287c", "maxTimeoutSeconds": 300, "asset": "0x036cbd53842c5426634e7929541ec2318f3dcf7e", "extra": {"name": "USDC", "version": "2", "assetTransferMethod": "permit2"}},
                {"scheme": "exact", "network": "base-sepolia", "maxAmountRequired": "500", "resource": "https://api.example.com/x", "description": "", "mimeType": "application/json", "payTo": "0x209693bc6afc0c5328ba36faf03c514ef312287c", "maxTimeoutSeconds": 300, "asset": "0x036cbd53842c5426634e7929541ec2318f3dcf7e"},
                {"scheme": "exact", "network": "base-sepolia", "maxAmountRequired": "500", "resource": "https://api.example.com/x", "description": "", "mimeType": "application/json", "payTo": "0x209693bc6afc0c5328ba36faf03c514ef312287c", "maxTimeoutSeconds": 300, "asset": "0x036cbd53842c5426634e7929541ec2318f3dcf7e", "extra": {"name": "USDC", "version": "2"}}
            ]
        });
        let parsed =
            parse_payment_required(&HeaderMap::new(), body.to_string().as_bytes()).expect("v1");
        let (all, _) = requirements(&parsed);
        assert!(all[0]
            .as_ref()
            .is_err_and(|reason| reason.contains("permit2")));
        assert!(all[1]
            .as_ref()
            .is_err_and(|reason| reason.contains("extra.name")));
        let paid = all[2].as_ref().expect("payable");
        assert_eq!(
            (paid.version, paid.chain_id, paid.network.as_str()),
            (1, 84532, "base-sepolia")
        );
    }

    #[test]
    fn other_402_bodies_are_not_x402() {
        assert!(parse_payment_required(&HeaderMap::new(), b"{\"error\":\"pay\"}").is_none());
        assert!(parse_payment_required(&HeaderMap::new(), b"not json").is_none());
    }
}
