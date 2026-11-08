//! The local paying proxy: `ProxyStart`, `ProxyStop`, `ProxyStatus`.
//!
//! The payments service can run one HTTP forward proxy on `127.0.0.1`. A
//! program that knows nothing about x402 or MPP (`curl`, an SDK, a browser
//! automation) sends its requests through it; when a merchant answers
//! `402 Payment Required`, the proxy pays the x402 or MPP challenge as the
//! agent that started it, under that agent's signer daemon policies, retries
//! the request, and returns the paid response. MPP sessions are persisted
//! per origin under the session key `proxy:<host>:<port>` and reused; they
//! stay open after the proxy stops (close one with `MppFetch` and that
//! `session_key` plus `close_session`).
//!
//! # Security model
//!
//! - **Loopback only.** The listener binds `127.0.0.1`; it is unreachable
//!   from other machines.
//! - **Bearer token.** Every proxied request must carry
//!   `Proxy-Authorization: Basic base64("agentpay:" + token)` (what HTTP
//!   clients send for a proxy URL `http://agentpay:<token>@127.0.0.1:<port>`)
//!   or `Proxy-Authorization: Bearer <token>`. The token is 32 random bytes
//!   (64 hex characters), new for every `ProxyStart`, compared in constant
//!   time, and returned only by `ProxyStart`. Other local processes and
//!   users cannot spend through the proxy without it; a request without it
//!   gets `407 Proxy Authentication Required` and is never forwarded.
//! - **Treat `token` and `proxy_url` as secrets**: anyone holding them can
//!   spend within the agent's policies until the proxy stops. Pass them to
//!   the child process through its environment or a private file, never on a
//!   command line.
//! - **Spending stays policy-checked.** The proxy holds the starting agent's
//!   token in memory only (never on disk) and sends every signature request
//!   through the signer daemon as that agent, so per-transaction, daily, and
//!   manual-approval policies apply to each proxied payment. `max_amount`
//!   adds a per-payment cap. Rotating or revoking the agent token makes
//!   every later proxied payment fail.
//! - **Allowed hosts.** With `allowed_hosts`, the proxy refuses (`403`) any
//!   other host, for plain requests and `CONNECT` tunnels alike, so a
//!   process cannot use it to reach other destinations. Without it, every
//!   host is proxied and paid.
//! - **HTTPS.** The proxy terminates TLS for proxied `https` hosts with
//!   certificates from a certificate authority generated for this proxy run
//!   and held only in memory (`ca_certificate_pem`); clients must trust that
//!   certificate (for example `SSL_CERT_FILE`, `CURL_CA_BUNDLE`,
//!   `NODE_EXTRA_CA_CERTS`). Upstream connections verify the merchant's
//!   real certificate against the system roots. The proxy follows no
//!   redirects.
//! - **Lifetime.** The proxy runs until `ProxyStop` or until the payments
//!   service exits; it is never restarted automatically. Only the agent that
//!   started it can stop it.
//! - **Configuration.** The proxy uses the configuration (chains, RPC URLs)
//!   as of `ProxyStart`; restart it after `SetConfig`.

use agentpay_domain::u128_as_decimal_string;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::auth::AgentAuth;
use crate::types::DecimalU128;

/// Most entries in `allowed_hosts`.
pub const MAX_PROXY_ALLOWED_HOSTS: usize = 64;

/// `ProxyStart`: start the local paying proxy for the calling agent.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`ProxyStarted`] |
/// | Side effects | a loopback listener that pays `402` answers as this agent until `ProxyStop` |
/// | Idempotent | no: fails with `InvalidRequest` while a proxy runs |
///
/// `port` 0 or omitted lets the system choose a free port. `allowed_hosts`
/// entries are host names or IP addresses (no scheme, no port), compared
/// case-insensitively. `currency`, `deposit`, and `max_deposit` apply to MPP
/// payments as in `MppFetch`: pick the token when a merchant accepts several,
/// and size session channels so a stream of requests does not top up on chain
/// each time. See the [module documentation](self) for the security model.
///
/// **Errors:** `AgentAuthenticationFailed`, `SignerUnavailable`,
/// `InvalidRequest` (a proxy already runs, the port is in use, bad host,
/// `deposit` above `max_deposit`), `Internal`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/proxy/ProxyStart.request.json")]
/// ```
///
/// Response (the token and URL are secrets):
///
/// ```json
#[doc = include_str!("../../fixtures/payments/proxy/ProxyStart.response.json")]
/// ```
///
/// [`ProxyStarted`]: crate::payments::PaymentsRpcResponse::ProxyStarted
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ProxyStartParams {
    /// Agent credentials; the proxy pays as this agent.
    pub auth: AgentAuth,
    /// Loopback port; 0 or omitted for any free port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub port: Option<u16>,
    /// Hosts the proxy serves and pays; omitted for every host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub allowed_hosts: Option<Vec<String>>,
    /// Refuse any single payment above this amount (the challenge's base
    /// units, any asset).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(optional, as = "Option<DecimalU128>")]
    pub max_amount: Option<u128>,
    /// MPP: only pay challenges in this token (for a merchant that accepts several): an EVM
    /// token address, a Solana mint, or `"sol"`. Without it, a token configured in AgentPay is
    /// preferred over one that is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub currency: Option<String>,
    /// MPP: only pay challenges on this configured network (a key of the configuration's
    /// `chains`, for example `"base"` or `"solana-mainnet"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub network: Option<String>,
    /// MPP: deposit of a new session channel, and the top-up target (base units).
    /// Default: the challenge's `suggestedDeposit`, else its amount, which makes every later
    /// request top the channel up on chain.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(optional, as = "Option<DecimalU128>")]
    pub deposit: Option<u128>,
    /// MPP: cap on a channel's total deposit (base units); at least `deposit`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(optional, as = "Option<DecimalU128>")]
    pub max_deposit: Option<u128>,
}

/// `ProxyStop` and `ProxyStatus` parameters.
///
/// `ProxyStop` stops the proxy and returns its final status
/// (`running: false`, with the counters of the run). It succeeds when no
/// proxy runs; a proxy started by another agent fails with
/// `InvalidRequest`. Requests in flight are dropped.
///
/// `ProxyStatus` reports whether a proxy runs, for which agent, and its
/// counters. It never returns the token.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`ProxyStatus`] |
/// | Side effects | `ProxyStop`: closes the listener; `ProxyStatus`: none |
/// | Idempotent | yes |
///
/// **Errors:** `AgentAuthenticationFailed`, `SignerUnavailable`,
/// `InvalidRequest` (`ProxyStop` of another agent's proxy).
///
/// `ProxyStop` request and response:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/proxy/ProxyStop.request.json")]
/// ```
///
/// ```json
#[doc = include_str!("../../fixtures/payments/proxy/ProxyStop.response.json")]
/// ```
///
/// `ProxyStatus` request and response:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/proxy/ProxyStatus.request.json")]
/// ```
///
/// ```json
#[doc = include_str!("../../fixtures/payments/proxy/ProxyStatus.response.json")]
/// ```
///
/// [`ProxyStatus`]: crate::payments::PaymentsRpcResponse::ProxyStatus
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ProxyParams {
    /// Agent credentials.
    pub auth: AgentAuth,
}

/// The proxy's state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ProxyStatusResult {
    /// Whether the proxy is running.
    pub running: bool,
    /// Listening address, `127.0.0.1:<port>`; `null` when stopped.
    pub address: Option<String>,
    /// The agent the proxy pays as; `null` when stopped.
    pub agent_key_id: Option<Uuid>,
    /// Allowed hosts; empty for every host.
    pub allowed_hosts: Vec<String>,
    /// Per-payment cap (base units), if any.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(optional, as = "Option<DecimalU128>")]
    pub max_amount: Option<u128>,
    /// MPP: the only token paid, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub currency: Option<String>,
    /// MPP: the only network paid on, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub network: Option<String>,
    /// MPP: deposit for new channels (base units), if set.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(optional, as = "Option<DecimalU128>")]
    pub deposit: Option<u128>,
    /// MPP: cap on a channel's deposit (base units), if set.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(optional, as = "Option<DecimalU128>")]
    pub max_deposit: Option<u128>,
    /// Authenticated requests served.
    pub requests: u64,
    /// `402` answers paid.
    pub payments: u64,
    /// `402` answers that could not be paid (refused, denied, failed).
    pub failed_payments: u64,
}

/// Result of `ProxyStart`. **Secret**: `token` and `proxy_url` let any
/// holder spend through the proxy.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ProxyStartResult {
    /// The new proxy's state.
    pub status: ProxyStatusResult,
    /// The bearer token: 64 hex characters.
    #[serde(with = "agentpay_domain::serde_helpers::zeroizing_string")]
    #[schemars(with = "String")]
    #[ts(as = "String")]
    pub token: Zeroizing<String>,
    /// `http://agentpay:<token>@127.0.0.1:<port>`, ready for `HTTP_PROXY`
    /// and `HTTPS_PROXY`.
    #[serde(with = "agentpay_domain::serde_helpers::zeroizing_string")]
    #[schemars(with = "String")]
    #[ts(as = "String")]
    pub proxy_url: Zeroizing<String>,
    /// PEM certificate of this run's certificate authority, which signs the
    /// certificates the proxy presents for `https` hosts. Public.
    pub ca_certificate_pem: String,
}

impl ProxyStartResult {
    /// Wipes the token and URL in place.
    pub fn zeroize_secrets(&mut self) {
        self.token.zeroize();
        self.proxy_url.zeroize();
    }
}

impl std::fmt::Debug for ProxyStartResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyStartResult")
            .field("status", &self.status)
            .field("token", &"<redacted>")
            .field("proxy_url", &"<redacted>")
            .finish_non_exhaustive()
    }
}
