//! The documented admin challenge example is a real, verifiable
//! `agentpay-admin-challenge-v1` message and signature.

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use uuid::Uuid;

use super::fixtures::load;
use crate::auth::{
    is_valid_admin_challenge_purpose, AdminChallenge, AdminCredential, ADMIN_CHALLENGE_DOMAIN_TAG,
    ADMIN_CHALLENGE_NONCE_BYTES, MAX_ADMIN_CHALLENGE_PURPOSE_BYTES,
};
use crate::rpc::{BeginAdminChallengeParams, CompleteAdminChallengeParams};
use crate::{DaemonRpcRequest, DaemonRpcResponse};

fn take<'a>(bytes: &mut &'a [u8], len: usize) -> &'a [u8] {
    let (head, tail) = bytes.split_at(len);
    *bytes = tail;
    head
}

fn example_challenge() -> (BeginAdminChallengeParams, AdminChallenge) {
    let DaemonRpcRequest::BeginAdminChallenge(params) =
        serde_json::from_value(load("BeginAdminChallenge", "request")).expect("request")
    else {
        panic!("wrong request example");
    };
    let DaemonRpcResponse::AdminChallenge(challenge) =
        serde_json::from_value(load("BeginAdminChallenge", "response")).expect("response")
    else {
        panic!("wrong response example");
    };
    (params, challenge)
}

#[test]
fn example_message_follows_the_documented_layout() {
    let (params, challenge) = example_challenge();
    let message = hex::decode(&challenge.message_hex).expect("hex message");
    let mut rest = message.as_slice();

    assert_eq!(
        take(&mut rest, ADMIN_CHALLENGE_DOMAIN_TAG.len()),
        ADMIN_CHALLENGE_DOMAIN_TAG
    );
    assert_eq!(take(&mut rest, 1), [0]);
    let _instance_id = Uuid::from_slice(take(&mut rest, 16)).expect("instance id");
    let credential_id = Uuid::from_slice(take(&mut rest, 16)).expect("credential id");
    assert_eq!(credential_id, params.credential_id);
    let challenge_id = Uuid::from_slice(take(&mut rest, 16)).expect("challenge id");
    assert_eq!(challenge_id, challenge.challenge_id);
    take(&mut rest, ADMIN_CHALLENGE_NONCE_BYTES);
    let purpose_len = u16::from_be_bytes(take(&mut rest, 2).try_into().expect("u16"));
    let purpose = take(&mut rest, usize::from(purpose_len));
    assert_eq!(purpose, params.purpose.as_bytes());
    let expiry = i64::from_be_bytes(take(&mut rest, 8).try_into().expect("i64"));
    assert_eq!(expiry, challenge.expires_at.unix_timestamp());
    assert!(rest.is_empty(), "no trailing bytes");
}

#[test]
fn example_signature_verifies_against_the_example_credential() {
    let (_, challenge) = example_challenge();
    let DaemonRpcResponse::AdminCredential(AdminCredential {
        public_key_sec1_hex,
        ..
    }) = serde_json::from_value(load("EnrollAdminCredential", "response")).expect("credential")
    else {
        panic!("wrong credential example");
    };
    let DaemonRpcRequest::CompleteAdminChallenge(CompleteAdminChallengeParams {
        challenge_id,
        signature_der_hex,
    }) = serde_json::from_value(load("CompleteAdminChallenge", "request")).expect("complete")
    else {
        panic!("wrong completion example");
    };
    assert_eq!(challenge_id, challenge.challenge_id);

    let key = VerifyingKey::from_sec1_bytes(&hex::decode(public_key_sec1_hex).expect("key hex"))
        .expect("P-256 key");
    let signature =
        Signature::from_der(&hex::decode(signature_der_hex).expect("sig hex")).expect("DER");
    let message = hex::decode(&challenge.message_hex).expect("message hex");
    key.verify(&message, &signature)
        .expect("the documented signature verifies (ECDSA P-256 over SHA-256)");
}

#[test]
fn purpose_validation_matches_the_documented_rules() {
    for purpose in [
        "admin-session",
        "approve:e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090",
        "a/b.c_d",
    ] {
        assert!(is_valid_admin_challenge_purpose(purpose), "{purpose}");
    }
    let too_long = "a".repeat(MAX_ADMIN_CHALLENGE_PURPOSE_BYTES + 1);
    for purpose in [
        "",
        "has space",
        "emoji-\u{1f600}",
        "semi;colon",
        too_long.as_str(),
    ] {
        assert!(!is_valid_admin_challenge_purpose(purpose), "{purpose}");
    }
    assert!(is_valid_admin_challenge_purpose(
        &"a".repeat(MAX_ADMIN_CHALLENGE_PURPOSE_BYTES)
    ));
}
