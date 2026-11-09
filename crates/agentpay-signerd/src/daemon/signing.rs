//! The `sign_for_agent` pipeline: payload authorization, policy evaluation, replay
//! and recovery handling, and EVM digest / typed-data / EIP-1559 signing.

use agentpay_domain::{AgentAction, AgentKey, SignRequest, Signature, SpendEvent, VaultKey};
use agentpay_policy::{PolicyDecision, PolicyError};
use agentpay_signer::{SignerError, VaultSignerBackend};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use super::manual_approval::{ensure_action_supports_manual_approval, ManualApprovalResolution};
use super::signed_nonces::SignedBroadcastRecord;
use crate::persistence::PersistedDaemonState;
use crate::{DaemonError, InMemoryDaemon};

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    pub(crate) async fn sign_for_agent_impl(
        &self,
        request: SignRequest,
    ) -> Result<Signature, DaemonError> {
        let mut request = request;
        let result = async {
            let _signing_guard = self.signing_guard.lock().await;
            let _state_guard = self.state_persist_guard.lock().await;
            let now = OffsetDateTime::now_utc();
            if let Some(signature) = self.recover_signature_if_available(&request, now)? {
                return Ok(signature);
            }

            let backup = self.backup_state_if_persistent()?;
            self.prune_spend_log(now)?;
            self.prune_manual_approval_requests(now)?;

            let (agent_key, payload_action, policy_explanation) =
                self.explain_authorized_request(&request, now)?;
            self.ensure_replay_id_available(request.request_id, now)?;
            let approved_manual_request_id = match policy_explanation.decision {
                PolicyDecision::Allow
                    if payload_action.requires_eip712_policy()
                        && policy_explanation.evaluated_policy_ids.is_empty() =>
                {
                    // EIP-712 defaults to manual approval when no explicit
                    // Eip712Signing policy was evaluated (even under AllPolicies).
                    let default_gate = PolicyError::Eip712ManualApprovalRequired {
                        policy_id: None,
                        policy_suffix: String::new(),
                    };
                    self.hold_for_approval(
                        &agent_key,
                        &payload_action,
                        &request.payload,
                        &[default_gate],
                        now,
                        backup,
                    )?
                }
                PolicyDecision::Allow => None,
                PolicyDecision::ManualApproval(outcomes) => {
                    ensure_action_supports_manual_approval(&payload_action)?;
                    self.hold_for_approval(
                        &agent_key,
                        &payload_action,
                        &request.payload,
                        &outcomes,
                        now,
                        backup,
                    )?
                }
                PolicyDecision::Deny(err) => return Err(DaemonError::Policy(err)),
            };
            let vault_key = self
                .vault_keys
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?
                .get(&agent_key.vault_key_id)
                .cloned()
                .ok_or(DaemonError::UnknownVaultKey(agent_key.vault_key_id))?;

            if let AgentAction::BroadcastTx { tx } = &payload_action {
                self.ensure_nonce_reservation(
                    request.agent_key_id,
                    agent_key.vault_key_id,
                    tx.chain_id,
                    tx.nonce,
                    now,
                )?;
            }

            let signature = match &payload_action {
                AgentAction::BroadcastTx { tx } => {
                    if vault_key.algorithm != agentpay_domain::KeyAlgorithm::Secp256k1 {
                        return Err(map_domain_to_signer_error(
                            agentpay_domain::DomainError::InvalidKeyAlgorithmForAction,
                        ));
                    }
                    if tx.tx_type != 0x02 {
                        return Err(DaemonError::Signer(SignerError::Unsupported(format!(
                            "broadcast transaction type 0x{:02x} is unsupported for signing",
                            tx.tx_type
                        ))));
                    }
                    self.sign_broadcast_eip1559(&vault_key, tx).await?
                }
                AgentAction::SolanaSplTransfer { transfer } => {
                    self.sign_solana_spl_transfer(&vault_key, transfer).await?
                }
                AgentAction::SolanaSolTransfer { transfer } => {
                    self.sign_solana_sol_transfer(&vault_key, transfer).await?
                }
                AgentAction::SolanaNonceAccountCreate { create } => {
                    self.sign_solana_nonce_account_create(&vault_key, create)
                        .await?
                }
                AgentAction::SolanaPaymentTransaction { payment } => {
                    self.sign_solana_payment_transaction(&vault_key, payment)
                        .await?
                }
                AgentAction::Eip3009TransferWithAuthorization { .. }
                | AgentAction::Eip3009ReceiveWithAuthorization { .. }
                | AgentAction::TempoSessionV2OpenTransaction { .. }
                | AgentAction::TempoSessionV2TopUpTransaction { .. }
                | AgentAction::TempoSessionV2Voucher { .. }
                | AgentAction::TempoSessionV2CloseAuthorization { .. }
                | AgentAction::Permit2WitnessTransfer { .. }
                | AgentAction::Eip712TypedData { .. } => {
                    if vault_key.algorithm != agentpay_domain::KeyAlgorithm::Secp256k1 {
                        return Err(map_domain_to_signer_error(
                            agentpay_domain::DomainError::InvalidKeyAlgorithmForAction,
                        ));
                    }
                    self.sign_typed_data_action(&vault_key, &payload_action)
                        .await?
                }
                AgentAction::Approve { .. }
                | AgentAction::Transfer { .. }
                | AgentAction::TransferNative { .. } => {
                    if vault_key.algorithm != agentpay_domain::KeyAlgorithm::Secp256k1 {
                        return Err(map_domain_to_signer_error(
                            agentpay_domain::DomainError::InvalidKeyAlgorithmForAction,
                        ));
                    }
                    self.signer_backend
                        .sign_payload(agent_key.vault_key_id, &request.payload)
                        .await?
                }
            };

            if let AgentAction::BroadcastTx { tx } = &payload_action {
                self.consume_nonce_reservation(
                    request.agent_key_id,
                    agent_key.vault_key_id,
                    tx.chain_id,
                    tx.nonce,
                    now,
                )?;
                if let Some(tx_hash_hex) = &signature.tx_hash_hex {
                    self.record_signed_broadcast(
                        tx_hash_hex,
                        SignedBroadcastRecord {
                            agent_key_id: request.agent_key_id,
                            vault_key_id: agent_key.vault_key_id,
                            chain_id: tx.chain_id,
                            nonce: tx.nonce,
                            request_id: request.request_id,
                            signed_at: now,
                        },
                        now,
                    )?;
                }
            }

            if let Some(approval_request_id) = approved_manual_request_id {
                self.complete_manual_approval_request(approval_request_id, now)?;
                self.prune_manual_approval_requests(now)?;
            }

            self.record_tempo_channel_deposit(request.agent_key_id, &payload_action, now)?;

            if payload_action.records_spend_event() {
                let event = SpendEvent {
                    agent_key_id: request.agent_key_id,
                    chain_id: payload_action.chain_id(),
                    asset: payload_action.asset(),
                    recipient: payload_action.recipient(),
                    amount_wei: payload_action.amount_wei(),
                    at: now,
                    approval_request_id: approved_manual_request_id,
                };
                self.spend_log
                    .write()
                    .map_err(|_| DaemonError::LockPoisoned)?
                    .push(event);
            }
            self.register_replay_id(request.request_id, request.expires_at, now)?;
            self.persist_signed_state_best_effort(&request, &signature, now);

            Ok(signature)
        }
        .await;
        request.zeroize_secrets();
        result
    }

    /// Resolves the manual approval request for a request with soft policy
    /// `outcomes`, keyed by the payload hash and the set of all their
    /// policies: approved -> its id (the caller signs and completes it),
    /// rejected -> `ManualApprovalRejected`, otherwise a pending request
    /// (created with one reason per outcome, persisted) ->
    /// `ManualApprovalRequired`.
    ///
    /// After an approval the request is evaluated again: when the same
    /// policies trigger it, the approval applies; when the set changed (a
    /// window rolled over, limits were edited), the approval no longer
    /// matches and the request is either allowed outright or needs a new
    /// approval.
    fn hold_for_approval(
        &self,
        agent_key: &AgentKey,
        payload_action: &AgentAction,
        payload: &[u8],
        outcomes: &[PolicyError],
        now: OffsetDateTime,
        backup: Option<PersistedDaemonState>,
    ) -> Result<Option<uuid::Uuid>, DaemonError> {
        let mut policy_ids: Vec<uuid::Uuid> = outcomes
            .iter()
            .filter_map(PolicyError::approval_policy_id)
            .collect();
        policy_ids.sort_unstable();
        policy_ids.dedup();
        let reasons = outcomes
            .iter()
            .filter_map(PolicyError::approval_reason)
            .collect();
        match self.resolve_manual_approval_request(
            agent_key,
            payload_action,
            &payload_hash_hex(payload),
            policy_ids,
            reasons,
            now,
        )? {
            ManualApprovalResolution::Approved(request_id) => Ok(request_id),
            ManualApprovalResolution::Rejected(approval_request_id) => {
                Err(DaemonError::ManualApprovalRejected {
                    approval_request_id,
                })
            }
            ManualApprovalResolution::Pending(approval_request_id) => {
                self.persist_or_revert(backup)?;
                Err(DaemonError::ManualApprovalRequired {
                    approval_request_id,
                })
            }
        }
    }

    pub(super) fn authorize_request_payload(
        &self,
        request: &SignRequest,
    ) -> Result<(AgentKey, AgentAction), DaemonError> {
        if request.payload.len() > self.config.max_sign_payload_bytes {
            return Err(DaemonError::PayloadTooLarge {
                max_bytes: self.config.max_sign_payload_bytes,
            });
        }

        let agent_key = self.authenticate_agent(request.agent_key_id, &request.agent_auth_token)?;

        let payload_action: AgentAction = serde_json::from_slice(&request.payload)
            .map_err(|_| DaemonError::PayloadActionMismatch)?;
        payload_action
            .validate()
            .map_err(|error| DaemonError::InvalidAction(error.to_string()))?;
        if payload_action != request.action {
            return Err(DaemonError::PayloadActionMismatch);
        }
        let canonical_payload =
            serde_json::to_vec(&request.action).map_err(|_| DaemonError::PayloadActionMismatch)?;
        if request.payload != canonical_payload {
            return Err(DaemonError::PayloadActionMismatch);
        }
        self.ensure_tempo_channel_authorized(&agent_key, &payload_action)?;

        Ok((agent_key, payload_action))
    }

    async fn sign_typed_data_action(
        &self,
        vault_key: &VaultKey,
        action: &AgentAction,
    ) -> Result<Signature, DaemonError> {
        let digest = action
            .signing_hash()
            .map_err(map_domain_to_signer_error)?
            .ok_or_else(|| {
                DaemonError::Signer(SignerError::Unsupported(
                    "action does not produce an eip-712 signing digest".to_string(),
                ))
            })?;
        self.sign_digest_with_recovery(vault_key, digest, "typed-data signing")
            .await
    }

    async fn sign_digest_with_recovery(
        &self,
        vault_key: &VaultKey,
        digest_bytes: [u8; 32],
        operation: &str,
    ) -> Result<Signature, DaemonError> {
        let der_signature = self
            .signer_backend
            .sign_digest(vault_key.id, digest_bytes)
            .await?;

        let parsed = K256Signature::from_der(&der_signature.bytes).map_err(|err| {
            DaemonError::Signer(SignerError::Internal(format!(
                "backend returned invalid DER signature for {operation}: {err}"
            )))
        })?;
        let parsed = parsed.normalize_s().unwrap_or(parsed);
        let verifying_key = parse_verifying_key(&vault_key.public_key_hex)?;
        let recovery_id =
            RecoveryId::trial_recovery_from_prehash(&verifying_key, &digest_bytes, &parsed)
                .map_err(|err| {
                    DaemonError::Signer(SignerError::Internal(format!(
                        "unable to derive signature recovery id for {operation}: {err}"
                    )))
                })?;

        let mut compact = [0u8; 64];
        compact.copy_from_slice(&parsed.to_bytes());
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&compact[..32]);
        s.copy_from_slice(&compact[32..]);
        let v = u8::from(recovery_id);

        Ok(Signature {
            bytes: parsed.to_der().as_bytes().to_vec(),
            signature_base58: None,
            r_hex: Some(format!("0x{}", hex::encode(r))),
            s_hex: Some(format!("0x{}", hex::encode(s))),
            v: Some(u64::from(v)),
            raw_tx_hex: None,
            tx_hash_hex: None,
            raw_tx_base64: None,
            tx_id: None,
        })
    }

    async fn sign_broadcast_eip1559(
        &self,
        vault_key: &VaultKey,
        tx: &agentpay_domain::BroadcastTx,
    ) -> Result<Signature, DaemonError> {
        let signing_message = tx
            .eip1559_signing_message()
            .map_err(map_domain_to_signer_error)?;
        let digest_bytes = alloy_primitives::keccak256(&signing_message).0;

        let mut signature = self
            .sign_digest_with_recovery(vault_key, digest_bytes, "tx signing")
            .await?;

        let r_hex = signature.r_hex.clone().ok_or_else(|| {
            DaemonError::Signer(SignerError::Internal("missing tx r value".to_string()))
        })?;
        let s_hex = signature.s_hex.clone().ok_or_else(|| {
            DaemonError::Signer(SignerError::Internal("missing tx s value".to_string()))
        })?;
        let v = signature.v.ok_or_else(|| {
            DaemonError::Signer(SignerError::Internal("missing tx recovery id".to_string()))
        })? as u8;

        let r_bytes = hex::decode(r_hex.trim_start_matches("0x")).map_err(|err| {
            DaemonError::Signer(SignerError::Internal(format!(
                "failed to decode tx r value: {err}"
            )))
        })?;
        let s_bytes = hex::decode(s_hex.trim_start_matches("0x")).map_err(|err| {
            DaemonError::Signer(SignerError::Internal(format!(
                "failed to decode tx s value: {err}"
            )))
        })?;
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&r_bytes);
        s.copy_from_slice(&s_bytes);

        let raw_tx = tx
            .eip1559_signed_raw_transaction(v, r, s)
            .map_err(map_domain_to_signer_error)?;
        let tx_hash = alloy_primitives::keccak256(&raw_tx);
        signature.raw_tx_hex = Some(format!("0x{}", hex::encode(raw_tx)));
        signature.tx_hash_hex = Some(format!("0x{}", hex::encode(tx_hash)));
        Ok(signature)
    }
}

pub(super) fn ethereum_address_from_public_key_hex(
    public_key_hex: &str,
) -> Result<String, DaemonError> {
    let verifying_key = parse_verifying_key(public_key_hex)?;
    let encoded = verifying_key.to_encoded_point(false);
    let public_key = encoded.as_bytes();
    if public_key.len() != 65 || public_key[0] != 0x04 {
        return Err(DaemonError::Signer(SignerError::Internal(
            "vault public key must be an uncompressed secp256k1 SEC1 point".to_string(),
        )));
    }
    let digest = alloy_primitives::keccak256(&public_key[1..]);
    let address = &digest.0[12..];
    Ok(format!("0x{}", hex::encode(address)))
}

pub(super) fn payload_hash_hex(payload: &[u8]) -> String {
    let digest = Sha256::digest(payload);
    hex::encode(digest)
}

pub(super) fn map_domain_to_signer_error(err: agentpay_domain::DomainError) -> DaemonError {
    DaemonError::Signer(SignerError::Unsupported(format!(
        "action cannot be signed: {err}"
    )))
}

pub(super) fn parse_verifying_key(public_key_hex: &str) -> Result<VerifyingKey, DaemonError> {
    let bytes =
        hex::decode(public_key_hex.strip_prefix("0x").unwrap_or(public_key_hex)).map_err(|_| {
            DaemonError::Signer(SignerError::Internal(
                "vault public key is not valid hex".to_string(),
            ))
        })?;
    VerifyingKey::from_sec1_bytes(&bytes).map_err(|err| {
        DaemonError::Signer(SignerError::Internal(format!(
            "vault public key is not valid secp256k1 SEC1 bytes: {err}"
        )))
    })
}
