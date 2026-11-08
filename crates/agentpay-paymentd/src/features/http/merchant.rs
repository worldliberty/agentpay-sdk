//! A scripted merchant HTTP server on `127.0.0.1` for the paid-HTTP tests
//! (x402, MPP, the paying proxy). Every request is recorded and answered by
//! the test's handler, which can keep its own state.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use reqwest::header::HeaderMap;

/// A request the merchant received.
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    pub(crate) method: String,
    /// Path and query.
    pub(crate) path: String,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Vec<u8>,
}

impl Seen {
    /// Header `name` as a string.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

/// The merchant's answer.
#[derive(Debug, Clone)]
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl Reply {
    /// A reply with `status` and a text body.
    pub(crate) fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    /// Adds a header.
    pub(crate) fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_string(), value.into()));
        self
    }
}

/// The test's request handler.
pub(crate) type Handler = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

/// A running merchant; stops when dropped.
pub(crate) struct Merchant {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Merchant {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Merchant {
    /// Starts a merchant answering with `handler`.
    pub(crate) async fn start(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind merchant");
        let url = format!("http://{}", listener.local_addr().expect("address"));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let handler: Handler = Arc::new(handler);
        let recorded = seen.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (handler, recorded) = (handler.clone(), recorded.clone());
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                        let (handler, recorded) = (handler.clone(), recorded.clone());
                        async move {
                            let (parts, body) = request.into_parts();
                            let body = body
                                .collect()
                                .await
                                .map(|body| body.to_bytes().to_vec())
                                .unwrap_or_default();
                            let seen = Seen {
                                method: parts.method.to_string(),
                                path: parts
                                    .uri
                                    .path_and_query()
                                    .map_or("/".to_string(), |path| path.to_string()),
                                headers: parts.headers,
                                body,
                            };
                            recorded.lock().expect("seen lock").push(seen.clone());
                            let reply = handler(&seen);
                            let mut response = Response::new(Full::new(Bytes::from(reply.body)));
                            *response.status_mut() =
                                hyper::StatusCode::from_u16(reply.status).expect("status");
                            for (name, value) in reply.headers {
                                response.headers_mut().append(
                                    hyper::header::HeaderName::from_bytes(name.as_bytes())
                                        .expect("header name"),
                                    hyper::header::HeaderValue::from_str(&value)
                                        .expect("header value"),
                                );
                            }
                            Ok::<_, Infallible>(response)
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self { url, seen, task }
    }

    /// `http://127.0.0.1:<port>`.
    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    /// Every request received so far.
    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("seen lock").clone()
    }
}
