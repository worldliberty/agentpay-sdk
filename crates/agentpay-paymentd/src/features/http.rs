//! HTTP plumbing shared by `X402Fetch`, `MppFetch`, and the paying proxy:
//! the merchant HTTP client, request validation, and bounded response
//! reading.
//!
//! The client follows no redirects (a payment credential must never reach
//! another host), ignores the service account's proxy environment, and
//! times out after [`HTTP_TIMEOUT_SECS`]. Errors never quote the URL: it can
//! carry the caller's API keys.

use std::time::Duration;

use agentpay_api::payments::http::{
    HTTP_TIMEOUT_SECS, MAX_REQUEST_HEADERS, MAX_RESPONSE_BODY_BYTES,
};
use agentpay_api::payments::{HttpBody, HttpHeader, HttpRequest, HttpResponse};
use base64::Engine;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, Url};

use crate::error::PaymentsError;

/// Connection timeout of a merchant request.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Request headers callers may not set: they describe the connection, not
/// the request, or would let the caller steer the proxy.
const FORBIDDEN_HEADERS: &[&str] = &[
    "host",
    "connection",
    "proxy-connection",
    "keep-alive",
    "content-length",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
];

/// The HTTP client for merchant requests.
pub(crate) fn merchant_client() -> Result<reqwest::Client, PaymentsError> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .connect_timeout(CONNECT_TIMEOUT)
        .user_agent(concat!("agentpay-paymentd/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| PaymentsError::Internal("the merchant HTTP client is unavailable".into()))
}

/// Checks `url`: absolute `http`/`https`, a host, no embedded credentials.
pub(crate) fn parse_url(url: &str) -> Result<Url, PaymentsError> {
    let parsed = Url::parse(url)
        .map_err(|_| PaymentsError::InvalidRequest("url is not a valid absolute URL".into()))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(PaymentsError::InvalidRequest(
            "url must use http or https".into(),
        ));
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(PaymentsError::InvalidRequest("url must name a host".into()));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(PaymentsError::InvalidRequest(
            "url must not embed credentials".into(),
        ));
    }
    Ok(parsed)
}

/// Builds the merchant request described by `request`.
pub(crate) fn build_request(
    client: &reqwest::Client,
    request: &HttpRequest,
) -> Result<reqwest::Request, PaymentsError> {
    let url = parse_url(&request.url)?;
    let body = request.body.as_ref().map(decode_body).transpose()?;
    let method = match request.method.as_deref().map(str::trim) {
        Some(method) if !method.is_empty() => {
            Method::from_bytes(method.to_ascii_uppercase().as_bytes()).map_err(|_| {
                PaymentsError::InvalidRequest("method is not a valid HTTP method".into())
            })?
        }
        _ if body.is_some() => Method::POST,
        _ => Method::GET,
    };
    if method == Method::CONNECT {
        return Err(PaymentsError::InvalidRequest(
            "method CONNECT is not supported".into(),
        ));
    }
    let headers = request_headers(&request.headers)?;
    let mut builder = client.request(method, url).headers(headers);
    if let Some(body) = body {
        builder = builder.body(body);
    }
    builder
        .build()
        .map_err(|_| PaymentsError::InvalidRequest("the HTTP request is invalid".into()))
}

/// Validates and converts caller headers.
pub(crate) fn request_headers(headers: &[HttpHeader]) -> Result<HeaderMap, PaymentsError> {
    if headers.len() > MAX_REQUEST_HEADERS {
        return Err(PaymentsError::InvalidRequest(format!(
            "at most {MAX_REQUEST_HEADERS} headers are allowed"
        )));
    }
    let mut map = HeaderMap::new();
    for header in headers {
        let name = HeaderName::from_bytes(header.name.trim().as_bytes()).map_err(|_| {
            PaymentsError::InvalidRequest(format!("'{}' is not a valid header name", header.name))
        })?;
        if FORBIDDEN_HEADERS.contains(&name.as_str()) {
            return Err(PaymentsError::InvalidRequest(format!(
                "header '{name}' cannot be set"
            )));
        }
        let value = HeaderValue::from_str(&header.value).map_err(|_| {
            PaymentsError::InvalidRequest(format!("header '{name}' has an invalid value"))
        })?;
        map.append(name, value);
    }
    Ok(map)
}

fn decode_body(body: &HttpBody) -> Result<Vec<u8>, PaymentsError> {
    match body {
        HttpBody::Text(text) => Ok(text.as_bytes().to_vec()),
        HttpBody::Base64(data) => base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|_| PaymentsError::InvalidRequest("body is not valid base64".into())),
    }
}

/// Sends `request`; a failure is a `Merchant` error that never quotes the URL.
pub(crate) async fn send(
    client: &reqwest::Client,
    request: reqwest::Request,
) -> Result<reqwest::Response, PaymentsError> {
    client
        .execute(request)
        .await
        .map_err(|error| merchant_error(&error))
}

/// A `Merchant` error for a transport failure, without the URL.
pub(crate) fn merchant_error(error: &reqwest::Error) -> PaymentsError {
    let reason = if error.is_timeout() {
        "timed out"
    } else if error.is_connect() {
        "could not connect"
    } else if error.is_body() || error.is_decode() {
        "failed while reading the response"
    } else {
        "failed"
    };
    PaymentsError::Merchant(format!("the merchant request {reason}"))
}

/// Reads at most `limit` bytes of the body; returns the bytes and whether
/// more followed (the rest is not read).
pub(crate) async fn read_body_bounded(
    response: &mut reqwest::Response,
    limit: usize,
) -> Result<(Vec<u8>, bool), PaymentsError> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| merchant_error(&error))?
    {
        let room = limit.saturating_sub(body.len());
        if chunk.len() > room {
            body.extend_from_slice(&chunk[..room]);
            return Ok((body, true));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((body, false))
}

/// The response's status, URL, and headers, with `body`.
pub(crate) fn response_with_body(
    response: &reqwest::Response,
    body: &[u8],
    truncated: bool,
) -> HttpResponse {
    HttpResponse {
        url: response.url().to_string(),
        status: response.status().as_u16(),
        headers: response_headers(response.headers()),
        body: encode_body(body),
        body_truncated: truncated,
    }
}

/// Reads the whole response (body bounded by [`MAX_RESPONSE_BODY_BYTES`]).
pub(crate) async fn read_response(
    mut response: reqwest::Response,
) -> Result<HttpResponse, PaymentsError> {
    let (body, truncated) = read_body_bounded(&mut response, MAX_RESPONSE_BODY_BYTES).await?;
    Ok(response_with_body(&response, &body, truncated))
}

/// Headers in wire order; non-UTF-8 values are converted lossily.
pub(crate) fn response_headers(headers: &HeaderMap) -> Vec<HttpHeader> {
    headers
        .iter()
        .map(|(name, value)| HttpHeader {
            name: name.as_str().to_string(),
            value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect()
}

/// `Text` for printable UTF-8, otherwise `Base64`.
pub(crate) fn encode_body(bytes: &[u8]) -> HttpBody {
    match std::str::from_utf8(bytes) {
        Ok(text)
            if text
                .chars()
                .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t')) =>
        {
            HttpBody::Text(text.to_string())
        }
        _ => HttpBody::Base64(base64::engine::general_purpose::STANDARD.encode(bytes)),
    }
}

/// The value of header `name`, if present and UTF-8.
pub(crate) fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

#[cfg(test)]
pub(crate) mod merchant;

#[cfg(test)]
mod tests {
    use super::*;

    fn request(url: &str) -> HttpRequest {
        HttpRequest {
            url: url.into(),
            method: None,
            headers: Vec::new(),
            body: None,
        }
    }

    #[test]
    fn urls_must_be_absolute_http_without_credentials() {
        assert!(parse_url("https://api.example.com/x").is_ok());
        assert!(parse_url("http://127.0.0.1:8080/").is_ok());
        for bad in [
            "ftp://example.com/",
            "/relative",
            "https://user:pw@example.com/",
            "not a url",
        ] {
            assert!(
                matches!(parse_url(bad), Err(PaymentsError::InvalidRequest(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn methods_default_by_body_and_connection_headers_are_refused() {
        let client = merchant_client().expect("client");
        let get = build_request(&client, &request("https://example.com/")).expect("get");
        assert_eq!(get.method(), Method::GET);
        let mut with_body = request("https://example.com/");
        with_body.body = Some(HttpBody::Text("{}".into()));
        assert_eq!(
            build_request(&client, &with_body).expect("post").method(),
            Method::POST
        );
        let mut bad_body = request("https://example.com/");
        bad_body.body = Some(HttpBody::Base64("%%%".into()));
        assert!(build_request(&client, &bad_body).is_err());
        let mut host = request("https://example.com/");
        host.headers.push(HttpHeader {
            name: "Host".into(),
            value: "evil.example".into(),
        });
        assert!(matches!(
            build_request(&client, &host),
            Err(PaymentsError::InvalidRequest(_))
        ));
        let mut connect = request("https://example.com/");
        connect.method = Some("connect".into());
        assert!(build_request(&client, &connect).is_err());
    }

    #[test]
    fn bodies_are_text_when_printable() {
        assert_eq!(encode_body(b"hi\n"), HttpBody::Text("hi\n".into()));
        assert_eq!(encode_body(&[0, 159]), HttpBody::Base64("AJ8=".into()));
        assert_eq!(encode_body(b"a\x07"), HttpBody::Base64("YQc=".into()));
    }
}
