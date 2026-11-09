//! Envelope shapes and frame encoding.

use serde_json::json;

use crate::envelope::{decode_frame_len, encode_frame, FRAME_LENGTH_PREFIX_BYTES};
use crate::{DaemonRpcRequest, WireRequest, WireResponse, MAX_WIRE_BODY_BYTES};

#[test]
fn hello_frame_matches_the_documented_bytes() {
    let body_json = serde_json::to_string(&DaemonRpcRequest::Hello).expect("encode request");
    let envelope = serde_json::to_vec(&WireRequest { body_json }).expect("encode envelope");
    assert_eq!(envelope, br#"{"body_json":"{\"method\":\"Hello\"}"}"#);
    let frame = encode_frame(&envelope).expect("frame");
    assert_eq!(
        &frame[..FRAME_LENGTH_PREFIX_BYTES],
        &[0x00, 0x00, 0x00, 0x26]
    );
    assert_eq!(&frame[FRAME_LENGTH_PREFIX_BYTES..], envelope.as_slice());
}

#[test]
fn response_envelope_shapes_match_the_docs() {
    let ok: WireResponse =
        serde_json::from_value(json!({"ok": true, "body_json": "{\"type\":\"Unit\"}"}))
            .expect("success envelope");
    assert!(ok.ok);
    let failed: WireResponse =
        serde_json::from_value(json!({"ok": false, "body_json": "{\"kind\":\"UnknownLease\"}"}))
            .expect("failure envelope");
    assert!(!failed.ok);
    let error: crate::WireDaemonError =
        serde_json::from_str(&failed.body_json).expect("error body");
    assert_eq!(error, crate::WireDaemonError::UnknownLease);
}

#[test]
fn frames_are_bounded_by_the_maximum_body_size() {
    assert_eq!(MAX_WIRE_BODY_BYTES, 256 * 1024);
    assert!(encode_frame(&vec![b'x'; MAX_WIRE_BODY_BYTES]).is_some());
    assert!(encode_frame(&vec![b'x'; MAX_WIRE_BODY_BYTES + 1]).is_none());
    let max = u32::try_from(MAX_WIRE_BODY_BYTES).expect("fits");
    assert_eq!(
        decode_frame_len(max.to_be_bytes()),
        Some(MAX_WIRE_BODY_BYTES)
    );
    assert_eq!(decode_frame_len((max + 1).to_be_bytes()), None);
    assert_eq!(decode_frame_len([0, 0, 0, 0]), Some(0));
}
