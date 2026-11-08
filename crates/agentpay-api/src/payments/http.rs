//! HTTP request and response types shared by the paid-HTTP methods
//! (`X402Fetch`, `MppFetch`).
//!
//! The payments service makes the HTTP request itself, as its service
//! account, pays a `402 Payment Required` answer within the agent's
//! policies, and returns the final response. Rules:
//!
//! - `url` is an absolute `http` or `https` URL without credentials
//!   (`user:password@`).
//! - `method` defaults to `GET`, or `POST` when a `body` is given.
//! - `headers` are sent in order; repeated names are allowed. Connection
//!   headers (`Host`, `Connection`, `Content-Length`, `Transfer-Encoding`,
//!   `Proxy-*`, ...) are refused. At most [`MAX_REQUEST_HEADERS`] headers.
//! - Redirects are never followed: a `3xx` answer is returned as it is, so a
//!   payment credential never reaches another host.
//! - The request times out after [`HTTP_TIMEOUT_SECS`] seconds, the
//!   response included.
//!
//! The response body is returned up to [`MAX_RESPONSE_BODY_BYTES`]; longer
//! bodies are cut off and `body_truncated` is `true`. The response is
//! complete when the service returns it: streaming (`text/event-stream`)
//! responses are read to their end first (see `MppFetch`).
//!
//! Request headers and bodies may carry the caller's own credentials for the
//! merchant (API keys), so `Debug` redacts them and the service never logs
//! them.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use zeroize::Zeroize;

/// Most request headers a paid-HTTP call may set.
pub const MAX_REQUEST_HEADERS: usize = 64;

/// Longest response body returned, in bytes. Longer bodies are truncated so
/// the response fits one wire frame.
pub const MAX_RESPONSE_BODY_BYTES: usize = 48 * 1024;

/// Timeout of one merchant HTTP request (connect, send, and read), in seconds.
pub const HTTP_TIMEOUT_SECS: u64 = 60;

/// One HTTP header.
///
/// JSON: `{"name": "Accept", "value": "application/json"}`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct HttpHeader {
    /// Header name (case-insensitive on the wire).
    pub name: String,
    /// Header value.
    pub value: String,
}

impl fmt::Debug for HttpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpHeader")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// An HTTP body: UTF-8 text or base64-encoded bytes.
///
/// JSON: `{"type": "text", "data": "hello"}` or
/// `{"type": "base64", "data": "aGVsbG8="}` (standard alphabet, padded).
/// Response bodies are `text` when they are valid UTF-8 without control
/// characters other than tab, line feed, and carriage return; otherwise
/// `base64`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum HttpBody {
    /// UTF-8 text.
    Text(String),
    /// Base64-encoded bytes.
    Base64(String),
}

impl HttpBody {
    /// Wipes the body in place.
    pub fn zeroize_secrets(&mut self) {
        match self {
            Self::Text(data) | Self::Base64(data) => data.zeroize(),
        }
    }
}

impl fmt::Debug for HttpBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (encoding, len) = match self {
            Self::Text(data) => ("text", data.len()),
            Self::Base64(data) => ("base64", data.len()),
        };
        write!(f, "HttpBody::{encoding}(<{len} chars>)")
    }
}

/// The HTTP request a paid-HTTP method makes. Its fields appear directly in
/// the method's `params` (they are flattened).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct HttpRequest {
    /// Absolute `http` or `https` URL.
    pub url: String,
    /// HTTP method; default `GET`, or `POST` with a body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub method: Option<String>,
    /// Request headers, sent in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[ts(as = "Option<Vec<HttpHeader>>", optional)]
    pub headers: Vec<HttpHeader>,
    /// Request body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub body: Option<HttpBody>,
}

impl HttpRequest {
    /// Wipes header values and the body in place (they may hold the
    /// caller's merchant credentials).
    pub fn zeroize_secrets(&mut self) {
        for header in &mut self.headers {
            header.value.zeroize();
        }
        if let Some(body) = &mut self.body {
            body.zeroize_secrets();
        }
    }
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("url", &"<redacted>")
            .field("method", &self.method)
            .field("headers", &self.headers)
            .field("body", &self.body)
            .finish()
    }
}

/// The final HTTP response of a paid-HTTP method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct HttpResponse {
    /// The URL that answered.
    pub url: String,
    /// HTTP status code.
    pub status: u16,
    /// Response headers, in the order received.
    pub headers: Vec<HttpHeader>,
    /// The body, at most [`MAX_RESPONSE_BODY_BYTES`] bytes of it.
    pub body: HttpBody,
    /// Whether the body was longer than [`MAX_RESPONSE_BODY_BYTES`] and was cut off.
    pub body_truncated: bool,
}
