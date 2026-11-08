//! Frame I/O for the wire protocol defined in `agentpay_api::envelope`:
//! length-prefixed JSON frames exchanged over the socket.
//!
//! Every frame is a big-endian `u32` byte length followed by a JSON document of
//! at most [`MAX_WIRE_BODY_BYTES`]. Buffers that may contain secrets are
//! zeroized once they have been consumed.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use zeroize::Zeroize;

use crate::error::UnixTransportError;

pub(crate) use agentpay_api::envelope::{WireRequest, WireResponse, MAX_WIRE_BODY_BYTES};

/// Serializes `value` and writes it as a single length-prefixed frame.
pub(crate) async fn write_frame<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    timeout: Duration,
) -> Result<(), UnixTransportError> {
    let mut payload = serde_json::to_vec(value)
        .map_err(|err| UnixTransportError::Serialization(err.to_string()))?;
    if payload.len() > MAX_WIRE_BODY_BYTES {
        payload.zeroize();
        return Err(UnixTransportError::Protocol(format!(
            "wire body exceeds max bytes ({MAX_WIRE_BODY_BYTES})"
        )));
    }
    let len = payload.len() as u32;
    let result = async {
        tokio::time::timeout(timeout, stream.write_all(&len.to_be_bytes()))
            .await
            .map_err(|_| UnixTransportError::Timeout)?
            .map_err(|err| UnixTransportError::Io(err.to_string()))?;
        tokio::time::timeout(timeout, stream.write_all(&payload))
            .await
            .map_err(|_| UnixTransportError::Timeout)?
            .map_err(|err| UnixTransportError::Io(err.to_string()))?;
        Ok(())
    }
    .await;
    payload.zeroize();
    result
}

/// Reads a single length-prefixed frame and deserializes it into `T`.
pub(crate) async fn read_frame<T: for<'de> Deserialize<'de>>(
    stream: &mut UnixStream,
    timeout: Duration,
) -> Result<T, UnixTransportError> {
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(timeout, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| UnixTransportError::Timeout)?
        .map_err(|err| UnixTransportError::Io(err.to_string()))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_WIRE_BODY_BYTES {
        return Err(UnixTransportError::Protocol(format!(
            "wire frame exceeds max bytes ({MAX_WIRE_BODY_BYTES})"
        )));
    }

    let mut payload = vec![0u8; len];
    let result = async {
        tokio::time::timeout(timeout, stream.read_exact(&mut payload))
            .await
            .map_err(|_| UnixTransportError::Timeout)?
            .map_err(|err| UnixTransportError::Io(err.to_string()))?;
        serde_json::from_slice::<T>(&payload)
            .map_err(|err| UnixTransportError::Serialization(err.to_string()))
    }
    .await;
    payload.zeroize();
    result
}
