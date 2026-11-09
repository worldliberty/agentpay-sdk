//! Transport envelope: the length-prefixed JSON frames exchanged over the socket.
//!
//! # Framing
//!
//! Every frame is a 4-byte **big-endian** unsigned length `N` followed by `N`
//! bytes of UTF-8 JSON. `N` must not exceed [`MAX_WIRE_BODY_BYTES`] (256 KiB);
//! either side closes the connection on a larger frame.
//!
//! # Exchange
//!
//! One connection carries exactly one request and one response:
//!
//! 1. The client connects to the daemon's Unix socket and writes one frame
//!    holding a [`WireRequest`]. Its `body_json` is the
//!    [`DaemonRpcRequest`](crate::DaemonRpcRequest) serialized to a JSON
//!    **string** (the request is JSON-encoded twice).
//! 2. The daemon replies with one frame holding a [`WireResponse`]: on success
//!    `ok` is `true` and `body_json` is a serialized
//!    [`DaemonRpcResponse`](crate::DaemonRpcResponse); on failure `ok` is
//!    `false` and `body_json` is a serialized
//!    [`WireDaemonError`](crate::WireDaemonError).
//! 3. The daemon closes the connection.
//!
//! If the peer is not allowed to call the requested method, or the request
//! cannot be decoded, the daemon closes the connection **without** writing a
//! response frame. Clients should treat an EOF instead of a response as
//! "rejected by transport".
//!
//! The daemon applies a 10-second timeout to each frame read and write;
//! clients should use a comparable timeout (the bundled clients use 10 s).
//!
//! # Example
//!
//! The `Hello` request on the wire (the 4 length bytes shown as hex):
//!
//! ```text
//! 00 00 00 26  {"body_json":"{\"method\":\"Hello\"}"}
//! ```

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Maximum frame payload (and `body_json`) size accepted by either side: 256 KiB.
pub const MAX_WIRE_BODY_BYTES: usize = 256 * 1024;

/// Size of the big-endian `u32` length prefix that starts every frame.
pub const FRAME_LENGTH_PREFIX_BYTES: usize = 4;

/// Client-to-daemon envelope: the only JSON object a client ever sends.
///
/// JSON: `{"body_json": "{\"method\":\"Hello\"}"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct WireRequest {
    /// A [`DaemonRpcRequest`](crate::DaemonRpcRequest) serialized as a JSON
    /// string. May contain secrets (agent tokens, lease secrets): clients
    /// should wipe it after sending.
    pub body_json: String,
}

/// Daemon-to-client envelope: the only JSON object the daemon ever sends.
///
/// JSON (success): `{"ok": true, "body_json": "{\"type\":\"Unit\"}"}`.
/// JSON (failure): `{"ok": false, "body_json": "{\"kind\":\"UnknownLease\"}"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct WireResponse {
    /// `true` when `body_json` holds a `DaemonRpcResponse`, `false` when it
    /// holds a `WireDaemonError`.
    pub ok: bool,
    /// The serialized response or error, as a JSON string.
    pub body_json: String,
}

/// Prefixes `payload` with its big-endian `u32` length, or returns `None` when
/// it exceeds [`MAX_WIRE_BODY_BYTES`].
#[must_use]
pub fn encode_frame(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() > MAX_WIRE_BODY_BYTES {
        return None;
    }
    let len = u32::try_from(payload.len()).ok()?;
    let mut frame = Vec::with_capacity(FRAME_LENGTH_PREFIX_BYTES + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    Some(frame)
}

/// Decodes a frame length prefix, or returns `None` when the announced length
/// exceeds [`MAX_WIRE_BODY_BYTES`].
#[must_use]
pub fn decode_frame_len(prefix: [u8; FRAME_LENGTH_PREFIX_BYTES]) -> Option<usize> {
    let len = usize::try_from(u32::from_be_bytes(prefix)).ok()?;
    (len <= MAX_WIRE_BODY_BYTES).then_some(len)
}
