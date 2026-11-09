//! The proxy listener: authentication, absolute-form `http://` requests,
//! and `CONNECT` tunnels that are TLS-intercepted for paying.

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION};
use hyper::http::uri::Authority;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use reqwest::Url;
use subtle::ConstantTimeEq;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

use super::{forward, Counters, Shared};

/// The response body type.
pub(super) type Body = UnsyncBoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// Accepts connections until `stopped` turns true.
pub(super) async fn serve(
    listener: tokio::net::TcpListener,
    shared: Arc<Shared>,
    mut stopped: watch::Receiver<bool>,
) {
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = stopped.changed() => return,
        };
        let Ok((stream, _)) = accepted else {
            continue;
        };
        let shared = shared.clone();
        let mut stopped = stopped.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let shared = shared.clone();
                async move { Ok::<_, Infallible>(handle(shared, request).await) }
            });
            let connection = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades();
            tokio::select! {
                _ = connection => {}
                _ = stopped.changed() => {}
            }
        });
    }
}

/// Whether the request carries one of the proxy's credentials (constant
/// time per candidate).
fn authorized(shared: &Shared, value: Option<&HeaderValue>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let mut matched = false;
    for credential in &shared.credentials {
        matched |= bool::from(value.as_bytes().ct_eq(credential.as_bytes()));
    }
    matched
}

async fn handle(shared: Arc<Shared>, mut request: Request<Incoming>) -> Response<Body> {
    if !authorized(&shared, request.headers().get(PROXY_AUTHORIZATION)) {
        let mut response = respond(
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            "proxy authentication required",
        );
        response.headers_mut().insert(
            PROXY_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"agentpay\""),
        );
        return response;
    }
    Counters::bump(&shared.counters.requests);
    if request.method() != Method::CONNECT {
        let url = Url::parse(&request.uri().to_string());
        return match url {
            Ok(url) if url.scheme() == "http" => {
                let host = url.host_str().unwrap_or_default().to_string();
                if !shared.allows(&host) {
                    return respond(StatusCode::FORBIDDEN, "host not allowed by this proxy");
                }
                forward::forward(&shared, request, url).await
            }
            _ => respond(
                StatusCode::BAD_REQUEST,
                "expected CONNECT or an absolute http:// URL",
            ),
        };
    }
    let Some(authority) = request.uri().authority().cloned() else {
        return respond(StatusCode::BAD_REQUEST, "CONNECT needs host:port");
    };
    if !shared.allows(authority.host()) {
        return respond(StatusCode::FORBIDDEN, "host not allowed by this proxy");
    }
    let upgrade = hyper::upgrade::on(&mut request);
    tokio::spawn(async move {
        if let Ok(upgraded) = upgrade.await {
            intercept(shared, upgraded, authority).await;
        }
    });
    Response::new(empty())
}

/// Terminates TLS for `authority` with a certificate from the proxy's CA
/// and forwards each request inside the tunnel to `https://authority`.
async fn intercept(shared: Arc<Shared>, upgraded: Upgraded, authority: Authority) {
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let Ok(config) = shared.authority.server_config(&host) else {
        return;
    };
    let Ok(stream) = TlsAcceptor::from(config)
        .accept(TokioIo::new(upgraded))
        .await
    else {
        return;
    };
    let service = service_fn(move |request: Request<Incoming>| {
        let shared = shared.clone();
        let path = request
            .uri()
            .path_and_query()
            .map_or("/", |path| path.as_str())
            .to_owned();
        let url = Url::parse(&format!("https://{authority}{path}"));
        async move {
            Ok::<_, Infallible>(match url {
                Ok(url) => forward::forward(&shared, request, url).await,
                Err(_) => respond(StatusCode::BAD_REQUEST, "invalid request target"),
            })
        }
    });
    let _ = http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .await;
}

/// A plain-text response.
pub(super) fn respond(status: StatusCode, message: &str) -> Response<Body> {
    let mut response = Response::new(
        Full::new(Bytes::from(format!("{message}\n")))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = status;
    response
}

fn empty() -> Body {
    Empty::new().map_err(|never| match never {}).boxed_unsync()
}
