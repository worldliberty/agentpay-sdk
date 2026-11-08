//! The local paying proxy (`ProxyStart`, `ProxyStop`, `ProxyStatus`).
//!
//! An HTTP/1 forward proxy on `127.0.0.1` that pays `402` answers (MPP
//! first, then x402) as the agent that started it. It is modeled on `mpp`'s
//! `client::ForwardProxy` (token-authenticated loopback listener, TLS
//! interception with a per-run CA, hop-by-hop header stripping, payment
//! events answered while a stream passes through) and reuses `mpp`'s
//! payment flow through [`crate::features::mpp`] and the x402 scheme
//! through [`crate::features::x402`]. It does not use `ForwardProxy`
//! itself, which cannot be stopped, binds only ephemeral ports, writes its
//! CA bundle to a shared temporary directory, and pays MPP only.
//!
//! The security model is documented on `agentpay_api::payments::proxy`.
//!
//! - `server`: the listener, authentication, `CONNECT` handling;
//! - `forward`: forwarding one request upstream and paying its `402`;
//! - `tls`: the per-run certificate authority.

mod forward;
mod server;
mod tls;

#[cfg(test)]
mod tests;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use agentpay_api::payments::proxy::MAX_PROXY_ALLOWED_HOSTS;
use agentpay_api::payments::{ProxyStartParams, ProxyStartResult, ProxyStatusResult};
use alloy_primitives::hex;
use base64::Engine;
use tokio::sync::{watch, Mutex};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::PaymentsError;
use crate::features::payer::Payer;

/// Per-run counters.
#[derive(Debug, Default)]
pub(crate) struct Counters {
    pub(crate) requests: AtomicU64,
    pub(crate) payments: AtomicU64,
    pub(crate) failed_payments: AtomicU64,
}

impl Counters {
    pub(crate) fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// What a running proxy needs to serve requests.
pub(crate) struct Shared {
    /// Pays as this agent.
    pub(crate) payer: Payer,
    /// Hosts served (lower case); empty for all.
    pub(crate) allowed_hosts: Vec<String>,
    /// Per-payment cap (base units).
    pub(crate) max_amount: Option<u128>,
    /// MPP: only this token.
    pub(crate) currency: Option<String>,
    /// MPP: only this configured network.
    pub(crate) network: Option<String>,
    /// MPP: deposit for new channels (base units).
    pub(crate) deposit: Option<u128>,
    /// MPP: cap on a channel's deposit (base units).
    pub(crate) max_deposit: Option<u128>,
    /// MPP: tokens configured in AgentPay as of `ProxyStart`, preferred when several are offered.
    pub(crate) known_tokens: Vec<(u64, String)>,
    /// Accepted `Proxy-Authorization` values.
    pub(crate) credentials: Vec<Zeroizing<String>>,
    /// The per-run certificate authority.
    pub(crate) authority: tls::Authority,
    /// Upstream HTTP client.
    pub(crate) client: reqwest::Client,
    /// Counters.
    pub(crate) counters: Counters,
}

impl Shared {
    /// Whether `host` may be proxied.
    pub(crate) fn allows(&self, host: &str) -> bool {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        self.allowed_hosts.is_empty()
            || self
                .allowed_hosts
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(host))
    }
}

struct Running {
    agent_key_id: Uuid,
    address: SocketAddr,
    shared: Arc<Shared>,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    fn status(&self, running: bool) -> ProxyStatusResult {
        let counters = &self.shared.counters;
        ProxyStatusResult {
            running,
            address: running.then(|| self.address.to_string()),
            agent_key_id: running.then_some(self.agent_key_id),
            allowed_hosts: if running {
                self.shared.allowed_hosts.clone()
            } else {
                Vec::new()
            },
            max_amount: running.then_some(self.shared.max_amount).flatten(),
            currency: running.then(|| self.shared.currency.clone()).flatten(),
            network: running.then(|| self.shared.network.clone()).flatten(),
            deposit: running.then_some(self.shared.deposit).flatten(),
            max_deposit: running.then_some(self.shared.max_deposit).flatten(),
            requests: counters.requests.load(Ordering::Relaxed),
            payments: counters.payments.load(Ordering::Relaxed),
            failed_payments: counters.failed_payments.load(Ordering::Relaxed),
        }
    }
}

/// The service's single proxy slot.
#[derive(Default)]
pub struct ProxyManager {
    running: Mutex<Option<Running>>,
}

impl ProxyManager {
    /// Starts a proxy paying as `payer`.
    pub(crate) async fn start(
        &self,
        payer: Payer,
        params: &ProxyStartParams,
    ) -> Result<ProxyStartResult, PaymentsError> {
        let mut slot = self.running.lock().await;
        if slot
            .as_ref()
            .is_some_and(|running| !running.task.is_finished())
        {
            return Err(PaymentsError::InvalidRequest(
                "a paying proxy is already running; stop it first".into(),
            ));
        }
        let allowed_hosts = check_hosts(params.allowed_hosts.as_deref().unwrap_or_default())?;
        if let (Some(deposit), Some(max)) = (params.deposit, params.max_deposit) {
            if deposit > max {
                return Err(PaymentsError::InvalidRequest(format!(
                    "deposit {deposit} exceeds max_deposit {max}"
                )));
            }
        }
        let port = params.port.unwrap_or(0);
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::AddrInUse => {
                    PaymentsError::InvalidRequest(format!("port {port} is in use"))
                }
                _ => PaymentsError::Internal("failed to bind the proxy listener".into()),
            })?;
        let address = listener
            .local_addr()
            .map_err(|_| PaymentsError::Internal("the proxy listener has no address".into()))?;
        let token = Zeroizing::new(hex::encode(rand::random::<[u8; 32]>()));
        let basic =
            base64::engine::general_purpose::STANDARD.encode(format!("agentpay:{}", *token));
        let credentials = vec![
            Zeroizing::new(format!("Basic {basic}")),
            Zeroizing::new(format!("Bearer {}", *token)),
        ];
        let (authority, ca_certificate_pem) = tls::Authority::generate()?;
        let agent_key_id = payer.agent_key_id();
        let known_tokens = crate::features::mpp::known_tokens(&payer.config);
        let shared = Arc::new(Shared {
            payer,
            allowed_hosts,
            max_amount: params.max_amount,
            currency: params.currency.clone(),
            network: params.network.clone(),
            deposit: params.deposit,
            max_deposit: params.max_deposit,
            known_tokens,
            credentials,
            authority,
            client: crate::features::http::merchant_client()?,
            counters: Counters::default(),
        });
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(server::serve(listener, shared.clone(), stopped));
        let running = Running {
            agent_key_id,
            address,
            shared,
            stop,
            task,
        };
        let status = running.status(true);
        *slot = Some(running);
        tracing::info!(port = address.port(), "paying proxy started");
        Ok(ProxyStartResult {
            status,
            proxy_url: Zeroizing::new(format!("http://agentpay:{}@{address}", *token)),
            token,
            ca_certificate_pem,
        })
    }

    /// Stops the proxy started by `agent` and returns its final status.
    pub(crate) async fn stop(&self, agent: Uuid) -> Result<ProxyStatusResult, PaymentsError> {
        let mut slot = self.running.lock().await;
        let Some(running) = slot.as_ref() else {
            return Ok(ProxyStatusResult::default());
        };
        if running.agent_key_id != agent && !running.task.is_finished() {
            return Err(PaymentsError::InvalidRequest(
                "the paying proxy was started by another agent".into(),
            ));
        }
        let Some(running) = slot.take() else {
            return Ok(ProxyStatusResult::default());
        };
        let _ = running.stop.send(true);
        running.task.abort();
        tracing::info!("paying proxy stopped");
        Ok(running.status(false))
    }

    /// The proxy's status.
    pub(crate) async fn status(&self) -> ProxyStatusResult {
        match self.running.lock().await.as_ref() {
            Some(running) => running.status(!running.task.is_finished()),
            None => ProxyStatusResult::default(),
        }
    }
}

/// Normalizes `allowed_hosts`: host names or IP addresses, no scheme,
/// port, or path.
fn check_hosts(hosts: &[String]) -> Result<Vec<String>, PaymentsError> {
    if hosts.len() > MAX_PROXY_ALLOWED_HOSTS {
        return Err(PaymentsError::InvalidRequest(format!(
            "at most {MAX_PROXY_ALLOWED_HOSTS} allowed_hosts are allowed"
        )));
    }
    hosts
        .iter()
        .map(|host| {
            let host = host.trim().to_ascii_lowercase();
            let is_ip = host.parse::<std::net::IpAddr>().is_ok();
            let is_name = !host.is_empty()
                && host.len() <= 253
                && host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
            if is_ip || is_name {
                Ok(host)
            } else {
                Err(PaymentsError::InvalidRequest(format!(
                    "allowed host '{host}' must be a host name or IP address (no scheme or port)"
                )))
            }
        })
        .collect()
}
