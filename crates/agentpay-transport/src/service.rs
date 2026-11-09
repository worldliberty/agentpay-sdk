//! [`RpcService`]: what a socket server hosts.
//!
//! The server owns everything that is the same for every AgentPay service:
//! binding, the bounded accept loop, peer-euid allowlists, framing, size
//! limits, timeouts, and wiping request/response buffers. A service supplies
//! its request type, the allowlist each request needs, and the handler.
//!
//! [`SignerdService`] adapts the signer daemon ([`InMemoryDaemon`]); the
//! payments service (`agentpay-paymentd`) implements the trait for its own
//! request family.

use std::sync::Arc;

use agentpay_api::{AccessLevel, DaemonRpcRequest, WireDaemonError, WireResponse};
use agentpay_signer::VaultSignerBackend;
use agentpay_signerd::{InMemoryDaemon, RequestContext};
use async_trait::async_trait;
use serde::de::DeserializeOwned;

use crate::error::UnixTransportError;

/// A request/response service served over a Unix socket, one request per connection.
// `async_trait` marks each generated method `#[must_use]` on top of the boxed
// future it returns, which newer clippy reports as `double_must_use`.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait RpcService: Send + Sync + 'static {
    /// The decoded form of `WireRequest.body_json`.
    type Request: DeserializeOwned + Send + 'static;

    /// The peer allowlist that governs `request`.
    fn access_level(request: &Self::Request) -> AccessLevel;

    /// Wipes secrets in a request that is dropped without being handled.
    fn zeroize_request(request: &mut Self::Request);

    /// Handles one authorized request from the peer whose kernel-reported
    /// effective uid is `peer_euid`, and returns the response envelope.
    ///
    /// The transport wipes `body_json` after writing it. An `Err` closes the
    /// connection without a response.
    async fn handle(
        &self,
        peer_euid: u32,
        request: Self::Request,
    ) -> Result<WireResponse, UnixTransportError>;
}

/// [`RpcService`] for the signer daemon: [`DaemonRpcRequest`] dispatched to
/// [`InMemoryDaemon::handle_rpc`].
pub struct SignerdService<B>
where
    B: VaultSignerBackend,
{
    daemon: Arc<InMemoryDaemon<B>>,
}

impl<B> SignerdService<B>
where
    B: VaultSignerBackend,
{
    /// Wraps `daemon`.
    #[must_use]
    pub fn new(daemon: Arc<InMemoryDaemon<B>>) -> Self {
        Self { daemon }
    }
}

#[async_trait]
impl<B> RpcService for SignerdService<B>
where
    B: VaultSignerBackend + 'static,
{
    type Request = DaemonRpcRequest;

    fn access_level(request: &DaemonRpcRequest) -> AccessLevel {
        request.access_level()
    }

    fn zeroize_request(request: &mut DaemonRpcRequest) {
        request.zeroize_secrets();
    }

    async fn handle(
        &self,
        peer_euid: u32,
        request: DaemonRpcRequest,
    ) -> Result<WireResponse, UnixTransportError> {
        // The kernel-reported peer euid, never anything in the request body, decides
        // whether `AdminAuth::PeerCredentials` is honored.
        let context = RequestContext::peer(peer_euid);
        match self.daemon.handle_rpc(&context, request).await {
            Ok(mut success) => {
                let body_json = serde_json::to_string(&success)
                    .map_err(|err| UnixTransportError::Serialization(err.to_string()));
                success.zeroize_secrets();
                Ok(WireResponse {
                    ok: true,
                    body_json: body_json?,
                })
            }
            Err(err) => Ok(WireResponse {
                ok: false,
                body_json: serde_json::to_string(&WireDaemonError::from(err))
                    .map_err(|ser| UnixTransportError::Serialization(ser.to_string()))?,
            }),
        }
    }
}
