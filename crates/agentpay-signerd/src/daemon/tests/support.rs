//! Shared fixtures for daemon tests: sample domain values, request builders, and
//! instrumented signer backends.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature as P256Signature, SigningKey};

use agentpay_domain::{
    AdminAuth, AdminChallenge, AdminCredential, AdminLease, AgentAction, AgentCredentials, AssetId,
    EntityScope, KeyAlgorithm, KeySource, ManualApprovalStatus, NonceReservation,
    NonceReservationRequest, PolicyAttachment, PolicyType, SignRequest, Signature,
    SolanaNonceAccountCreate, SolanaSolTransfer, SolanaSplTransfer, SpendingPolicy, VaultKey,
};
use agentpay_policy::{PolicyDecision, PolicyEvaluation, PolicyExplanation};
use agentpay_signer::{
    BackendKind, KeyCreateRequest, SignerError, SoftwareSignerBackend, VaultSignerBackend,
};
use serde_json::to_vec;
use solana_sdk::bs58;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::daemon::recovery::{
    RecoverableAgentRequest, RecoverableAgentResponse, RecoverableAgentResult,
};
use crate::{DaemonConfig, InMemoryDaemon, KeyManagerDaemonApi, StateSecret};

#[derive(Debug, Clone)]
pub(super) struct FlakySignerBackend {
    inner: SoftwareSignerBackend,
    remaining_payload_failures: Arc<AtomicUsize>,
    remaining_digest_failures: Arc<AtomicUsize>,
    error: SignerError,
}

impl FlakySignerBackend {
    pub(super) fn fail_first_payload(error: SignerError) -> Self {
        Self {
            inner: SoftwareSignerBackend::default(),
            remaining_payload_failures: Arc::new(AtomicUsize::new(1)),
            remaining_digest_failures: Arc::new(AtomicUsize::new(0)),
            error,
        }
    }

    pub(super) fn fail_first_digest(error: SignerError) -> Self {
        Self {
            inner: SoftwareSignerBackend::default(),
            remaining_payload_failures: Arc::new(AtomicUsize::new(0)),
            remaining_digest_failures: Arc::new(AtomicUsize::new(1)),
            error,
        }
    }

    fn consume_failure(counter: &AtomicUsize) -> bool {
        counter
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
    }
}

#[async_trait]
impl VaultSignerBackend for FlakySignerBackend {
    fn backend_kind(&self) -> BackendKind {
        self.inner.backend_kind()
    }

    async fn create_vault_key(&self, request: KeyCreateRequest) -> Result<VaultKey, SignerError> {
        self.inner.create_vault_key(request).await
    }

    async fn sign_payload(
        &self,
        vault_key_id: Uuid,
        payload: &[u8],
    ) -> Result<Signature, SignerError> {
        if Self::consume_failure(&self.remaining_payload_failures) {
            return Err(self.error.clone());
        }
        self.inner.sign_payload(vault_key_id, payload).await
    }

    async fn sign_digest(
        &self,
        vault_key_id: Uuid,
        digest: [u8; 32],
    ) -> Result<Signature, SignerError> {
        if Self::consume_failure(&self.remaining_digest_failures) {
            return Err(self.error.clone());
        }
        self.inner.sign_digest(vault_key_id, digest).await
    }

    fn export_persistable_key_material(
        &self,
        vault_key_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Zeroizing<String>>, SignerError> {
        self.inner.export_persistable_key_material(vault_key_ids)
    }

    fn restore_persistable_key_material(
        &self,
        persisted: &HashMap<Uuid, Zeroizing<String>>,
    ) -> Result<(), SignerError> {
        self.inner.restore_persistable_key_material(persisted)
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct CleanupTrackingSignerBackend {
    live_key_ids: Arc<Mutex<HashSet<Uuid>>>,
    deleted_key_ids: Arc<Mutex<Vec<Uuid>>>,
}

impl CleanupTrackingSignerBackend {
    pub(super) fn live_key_count(&self) -> usize {
        self.live_key_ids.lock().expect("live key lock").len()
    }

    pub(super) fn deleted_key_ids(&self) -> Vec<Uuid> {
        self.deleted_key_ids
            .lock()
            .expect("deleted key lock")
            .clone()
    }
}

#[async_trait]
impl VaultSignerBackend for CleanupTrackingSignerBackend {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::Tpm
    }

    async fn create_vault_key(&self, request: KeyCreateRequest) -> Result<VaultKey, SignerError> {
        let (source, algorithm, public_key_hex) = match request {
            KeyCreateRequest::Generate => (
                KeySource::Generated,
                KeyAlgorithm::Secp256k1,
                "11".repeat(33),
            ),
            KeyCreateRequest::GenerateWithAlgorithm { algorithm } => {
                let public_key_hex = match algorithm {
                    KeyAlgorithm::Secp256k1 => "11".repeat(33),
                    KeyAlgorithm::Ed25519 => "11".repeat(32),
                };
                (KeySource::Generated, algorithm, public_key_hex)
            }
            KeyCreateRequest::Import { .. } => (
                KeySource::Imported,
                KeyAlgorithm::Secp256k1,
                "11".repeat(33),
            ),
            KeyCreateRequest::ImportWithAlgorithm { algorithm, .. } => {
                let public_key_hex = match algorithm {
                    KeyAlgorithm::Secp256k1 => "11".repeat(33),
                    KeyAlgorithm::Ed25519 => "11".repeat(32),
                };
                (KeySource::Imported, algorithm, public_key_hex)
            }
        };
        let key_id = Uuid::new_v4();
        self.live_key_ids
            .lock()
            .expect("live key lock")
            .insert(key_id);
        Ok(VaultKey {
            id: key_id,
            source,
            algorithm,
            public_key_hex,
            created_at: time::OffsetDateTime::now_utc(),
            name: None,
        })
    }

    async fn sign_payload(
        &self,
        _vault_key_id: Uuid,
        _payload: &[u8],
    ) -> Result<Signature, SignerError> {
        Err(SignerError::Unsupported("not implemented".to_string()))
    }

    async fn sign_digest(
        &self,
        _vault_key_id: Uuid,
        _digest: [u8; 32],
    ) -> Result<Signature, SignerError> {
        Err(SignerError::Unsupported("not implemented".to_string()))
    }

    fn delete_vault_key_if_present(&self, vault_key_id: Uuid) -> Result<(), SignerError> {
        self.live_key_ids
            .lock()
            .expect("live key lock")
            .remove(&vault_key_id);
        self.deleted_key_ids
            .lock()
            .expect("deleted key lock")
            .push(vault_key_id);
        Ok(())
    }
}

#[derive(Clone, Default)]
pub(super) struct TrackingNonExportableSignerBackend {
    created_key_ids: Arc<RwLock<HashSet<Uuid>>>,
}

impl TrackingNonExportableSignerBackend {
    pub(super) fn created_key_count(&self) -> usize {
        self.created_key_ids.read().expect("created key ids").len()
    }
}

#[async_trait::async_trait]
impl VaultSignerBackend for TrackingNonExportableSignerBackend {
    fn backend_kind(&self) -> agentpay_signer::BackendKind {
        agentpay_signer::BackendKind::Tpm
    }

    async fn create_vault_key(&self, request: KeyCreateRequest) -> Result<VaultKey, SignerError> {
        match request {
            KeyCreateRequest::Generate
            | KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Secp256k1,
            } => {
                let key_id = Uuid::new_v4();
                self.created_key_ids
                    .write()
                    .map_err(|_| SignerError::Internal("poisoned lock".into()))?
                    .insert(key_id);
                Ok(VaultKey {
                    id: key_id,
                    source: KeySource::Generated,
                    algorithm: KeyAlgorithm::Secp256k1,
                    public_key_hex: "04".to_string() + &"11".repeat(64),
                    created_at: time::OffsetDateTime::now_utc(),
                    name: None,
                })
            }
            KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
            } => {
                let key_id = Uuid::new_v4();
                self.created_key_ids
                    .write()
                    .map_err(|_| SignerError::Internal("poisoned lock".into()))?
                    .insert(key_id);
                Ok(VaultKey {
                    id: key_id,
                    source: KeySource::Generated,
                    algorithm: KeyAlgorithm::Ed25519,
                    public_key_hex: "11".repeat(32),
                    created_at: time::OffsetDateTime::now_utc(),
                    name: None,
                })
            }
            KeyCreateRequest::Import { .. } | KeyCreateRequest::ImportWithAlgorithm { .. } => Err(
                SignerError::Unsupported("imports not supported in test backend".to_string()),
            ),
        }
    }

    async fn sign_payload(
        &self,
        _vault_key_id: Uuid,
        _payload: &[u8],
    ) -> Result<Signature, SignerError> {
        Err(SignerError::Unsupported(
            "signing not implemented in test backend".to_string(),
        ))
    }

    async fn sign_digest(
        &self,
        _vault_key_id: Uuid,
        _digest: [u8; 32],
    ) -> Result<Signature, SignerError> {
        Err(SignerError::Unsupported(
            "signing not implemented in test backend".to_string(),
        ))
    }

    fn delete_vault_key_if_present(&self, vault_key_id: Uuid) -> Result<(), SignerError> {
        self.created_key_ids
            .write()
            .map_err(|_| SignerError::Internal("poisoned lock".into()))?
            .remove(&vault_key_id);
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct ExportCountingSignerBackend {
    inner: SoftwareSignerBackend,
    export_calls: Arc<AtomicUsize>,
}

impl ExportCountingSignerBackend {
    pub(super) fn export_calls(&self) -> usize {
        self.export_calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl VaultSignerBackend for ExportCountingSignerBackend {
    fn backend_kind(&self) -> BackendKind {
        self.inner.backend_kind()
    }

    async fn create_vault_key(&self, request: KeyCreateRequest) -> Result<VaultKey, SignerError> {
        self.inner.create_vault_key(request).await
    }

    async fn sign_payload(
        &self,
        vault_key_id: Uuid,
        payload: &[u8],
    ) -> Result<Signature, SignerError> {
        self.inner.sign_payload(vault_key_id, payload).await
    }

    async fn sign_digest(
        &self,
        vault_key_id: Uuid,
        digest: [u8; 32],
    ) -> Result<Signature, SignerError> {
        self.inner.sign_digest(vault_key_id, digest).await
    }

    fn export_persistable_key_material(
        &self,
        vault_key_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Zeroizing<String>>, SignerError> {
        self.export_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.export_persistable_key_material(vault_key_ids)
    }

    fn restore_persistable_key_material(
        &self,
        persisted: &HashMap<Uuid, Zeroizing<String>>,
    ) -> Result<(), SignerError> {
        self.inner.restore_persistable_key_material(persisted)
    }
}

pub(super) fn policy_all_per_tx(max: u128) -> SpendingPolicy {
    SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        max,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy")
}

pub(super) fn policy_per_chain_gas(chain_id: u64, max_gas_wei: u128) -> SpendingPolicy {
    SpendingPolicy::new(
        2,
        PolicyType::PerChainMaxGasSpend,
        max_gas_wei,
        EntityScope::All,
        EntityScope::All,
        EntityScope::Set(BTreeSet::from([chain_id])),
    )
    .expect("policy")
}

pub(super) fn sign_request(credentials: &AgentCredentials, action: AgentAction) -> SignRequest {
    let now = time::OffsetDateTime::now_utc();
    SignRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: credentials.agent_key.id,
        agent_auth_token: credentials.auth_token.clone(),
        payload: to_vec(&action).expect("action payload"),
        action,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    }
}

pub(super) fn sample_solana_spl_transfer_action(fee_payer: &VaultKey) -> AgentAction {
    let fee_payer_bytes =
        hex::decode(&fee_payer.public_key_hex).expect("ed25519 public key hex must decode");
    let fee_payer = bs58::encode(fee_payer_bytes).into_string();
    let mint = bs58::encode([7u8; 32]).into_string();
    let recipient_owner = bs58::encode([9u8; 32]).into_string();
    AgentAction::SolanaSplTransfer {
        transfer: SolanaSplTransfer {
            chain_id: 900_000_002,
            recent_blockhash: bs58::encode([1u8; 32]).into_string(),
            durable_nonce_account: None,
            fee_payer: fee_payer.parse().expect("fee payer address"),
            mint: mint.parse().expect("mint address"),
            recipient_owner: recipient_owner.parse().expect("recipient owner address"),
            amount_wei: 1,
            decimals: 6,
            token_program: agentpay_domain::SolanaTokenProgram::Token,
            transfer_fee_wei: None,
            compute_unit_limit: None,
            compute_unit_price_micro_lamports: None,
        },
    }
}

pub(super) fn sample_solana_sol_transfer_action(fee_payer: &VaultKey) -> AgentAction {
    let fee_payer_bytes =
        hex::decode(&fee_payer.public_key_hex).expect("ed25519 public key hex must decode");
    let fee_payer = bs58::encode(fee_payer_bytes).into_string();
    let to = bs58::encode([8u8; 32]).into_string();
    AgentAction::SolanaSolTransfer {
        transfer: SolanaSolTransfer {
            chain_id: 900_000_002,
            recent_blockhash: bs58::encode([1u8; 32]).into_string(),
            durable_nonce_account: None,
            fee_payer: fee_payer.parse().expect("fee payer address"),
            to: to.parse().expect("recipient address"),
            amount_wei: 1,
            compute_unit_limit: None,
            compute_unit_price_micro_lamports: None,
        },
    }
}

pub(super) fn sample_solana_nonce_account_create_action(fee_payer: &VaultKey) -> AgentAction {
    let fee_payer_bytes =
        hex::decode(&fee_payer.public_key_hex).expect("ed25519 public key hex must decode");
    let fee_payer_pubkey = solana_sdk::pubkey::Pubkey::new_from_array(
        <[u8; 32]>::try_from(fee_payer_bytes.as_slice()).expect("ed25519 public key"),
    );
    let seed = "agentpay-900000002-nonce";
    let nonce_account = solana_sdk::pubkey::Pubkey::create_with_seed(
        &fee_payer_pubkey,
        seed,
        &"11111111111111111111111111111111"
            .parse()
            .expect("system program id"),
    )
    .expect("derive nonce account");
    AgentAction::SolanaNonceAccountCreate {
        create: SolanaNonceAccountCreate {
            chain_id: 900_000_002,
            recent_blockhash: bs58::encode([1u8; 32]).into_string(),
            fee_payer: fee_payer_pubkey.to_string().parse().expect("fee payer"),
            nonce_account: nonce_account.to_string().parse().expect("nonce account"),
            seed: seed.to_string(),
            rent_lamports: 1_500_000,
        },
    }
}

pub(super) async fn reserve_nonce_for_agent(
    daemon: &InMemoryDaemon<impl VaultSignerBackend>,
    credentials: &AgentCredentials,
    chain_id: u64,
    nonce: u64,
) {
    let now = time::OffsetDateTime::now_utc();
    daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: credentials.agent_key.id,
            agent_auth_token: credentials.auth_token.clone(),
            chain_id,
            min_nonce: nonce,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("nonce reservation");
}

pub(super) fn unique_state_path(test_name: &str) -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    // In a private (`0700`) directory: on Linux the temp directory is the shared `/tmp`
    // (mode `1777`), which the daemon rightly refuses as a state directory.
    let dir = std::env::temp_dir().join(format!("ap-{}-{unique}", std::process::id()));
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .expect("create private temp dir");
    }
    dir.join(format!("{test_name}.state"))
}

pub(super) fn poison_vault_keys_lock<B>(daemon: &InMemoryDaemon<B>)
where
    B: VaultSignerBackend,
{
    let vault_keys = daemon.vault_keys.clone();
    let _ = std::thread::spawn(move || {
        let _guard = vault_keys.write().expect("vault keys write lock");
        panic!("poison vault keys lock");
    })
    .join();
}

/// A fixed state secret so tests can reopen the same state file.
pub(super) fn test_state_secret() -> StateSecret {
    StateSecret::from_bytes([7u8; 32]).expect("test state secret")
}

pub(super) fn sample_admin_lease() -> AdminLease {
    let now = time::OffsetDateTime::now_utc();
    AdminLease {
        lease_id: Uuid::new_v4(),
        lease_secret: "ab".repeat(32).into(),
        issued_at: now,
        expires_at: now + time::Duration::minutes(1),
    }
}

/// A lease-based admin authorization (not issued by any daemon).
pub(super) fn sample_session() -> AdminAuth {
    sample_admin_lease().auth()
}

/// Generates a P-256 key standing in for a Secure Enclave admin key.
pub(super) fn test_admin_signing_key() -> SigningKey {
    SigningKey::from_slice(&rand::random::<[u8; 32]>()).expect("p256 signing key")
}

/// SEC1 (compressed) public key hex for `key`.
pub(super) fn admin_public_key_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_encoded_point(true).as_bytes())
}

/// Signs a challenge the way CryptoKit does: DER ECDSA over SHA-256(message).
pub(super) fn sign_admin_challenge(key: &SigningKey, challenge: &AdminChallenge) -> String {
    let message = hex::decode(&challenge.message_hex).expect("challenge hex");
    let signature: P256Signature = key.sign(&message);
    hex::encode(signature.to_der().as_bytes())
}

/// Enrolls a fresh credential in-process and returns it with its signing key.
pub(super) async fn enroll_admin_credential<B>(
    daemon: &InMemoryDaemon<B>,
) -> (SigningKey, AdminCredential)
where
    B: VaultSignerBackend,
{
    let key = test_admin_signing_key();
    let credential = daemon
        .enroll_admin_credential(admin_public_key_hex(&key), "Test Mac".to_string())
        .await
        .expect("enroll admin credential");
    (key, credential)
}

pub(super) fn sample_agent_credentials() -> AgentCredentials {
    AgentCredentials {
        agent_key: agentpay_domain::AgentKey {
            id: Uuid::new_v4(),
            vault_key_id: Uuid::new_v4(),
            policies: PolicyAttachment::AllPolicies,
            created_at: time::OffsetDateTime::now_utc(),
        },
        auth_token: "agent-secret-token".to_string().into(),
    }
}

pub(super) fn sample_vault_key() -> VaultKey {
    VaultKey {
        id: Uuid::new_v4(),
        source: KeySource::Generated,
        algorithm: KeyAlgorithm::Secp256k1,
        public_key_hex: "11".repeat(33),
        created_at: time::OffsetDateTime::now_utc(),
        name: None,
    }
}

pub(super) fn sample_manual_approval_request() -> agentpay_domain::ManualApprovalRequest {
    agentpay_domain::ManualApprovalRequest {
        id: Uuid::new_v4(),
        agent_key_id: Uuid::new_v4(),
        vault_key_id: Uuid::new_v4(),
        request_payload_hash_hex: "aa".repeat(32),
        action: AgentAction::TransferNative {
            chain_id: 1,
            to: "0x1111111111111111111111111111111111111111"
                .parse()
                .expect("recipient"),
            amount_wei: 42,
        },
        chain_id: 1,
        asset: AssetId::NativeEth,
        recipient: "0x1111111111111111111111111111111111111111"
            .parse()
            .expect("recipient"),
        amount_wei: 42,
        created_at: time::OffsetDateTime::now_utc(),
        updated_at: time::OffsetDateTime::now_utc(),
        status: ManualApprovalStatus::Pending,
        triggered_by_policy_ids: vec![Uuid::new_v4()],
        reasons: Vec::new(),
        completed_at: None,
        rejection_reason: None,
    }
}

pub(super) fn sample_nonce_reservation() -> NonceReservation {
    let now = time::OffsetDateTime::now_utc();
    NonceReservation {
        reservation_id: Uuid::new_v4(),
        agent_key_id: Uuid::new_v4(),
        vault_key_id: Uuid::new_v4(),
        chain_id: 1,
        nonce: 7,
        issued_at: now,
        expires_at: now + time::Duration::minutes(1),
    }
}

pub(super) fn sample_policy_evaluation() -> PolicyEvaluation {
    PolicyEvaluation {
        evaluated_policy_ids: vec![Uuid::new_v4()],
    }
}

pub(super) fn sample_policy_explanation() -> PolicyExplanation {
    let policy_id = Uuid::new_v4();
    PolicyExplanation {
        attached_policy_ids: vec![policy_id],
        applicable_policy_ids: vec![policy_id],
        evaluated_policy_ids: vec![policy_id],
        decision: PolicyDecision::Allow,
    }
}

pub(super) async fn daemon_with_agent(
    config: DaemonConfig,
) -> (
    InMemoryDaemon<SoftwareSignerBackend>,
    AdminAuth,
    AgentCredentials,
) {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), config).expect("daemon");
    let session = AdminAuth::PeerCredentials;
    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("vault key");
    let credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent key");
    (daemon, session, credentials)
}

pub(super) fn nonce_request(
    credentials: &AgentCredentials,
    request_id: Uuid,
    min_nonce: u64,
    exact_nonce: bool,
) -> NonceReservationRequest {
    let now = time::OffsetDateTime::now_utc();
    NonceReservationRequest {
        request_id,
        agent_key_id: credentials.agent_key.id,
        agent_auth_token: credentials.auth_token.clone(),
        chain_id: 1,
        min_nonce,
        exact_nonce,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    }
}

pub(super) fn recoverable_release(
    agent_key_id: Uuid,
    recover_until: time::OffsetDateTime,
) -> RecoverableAgentResult {
    RecoverableAgentResult {
        agent_key_id,
        request: RecoverableAgentRequest::ReleaseNonce {
            reservation_id: Uuid::new_v4(),
        },
        recover_until,
        response: RecoverableAgentResponse::Unit,
    }
}

pub(super) fn spend_event(
    agent_key_id: Uuid,
    amount_wei: u128,
    at: time::OffsetDateTime,
) -> agentpay_domain::SpendEvent {
    agentpay_domain::SpendEvent {
        agent_key_id,
        chain_id: 1,
        asset: AssetId::NativeEth,
        recipient: "0x7100000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei,
        at,
        approval_request_id: None,
    }
}

pub(super) fn tracked_nonce_head(
    daemon: &InMemoryDaemon<SoftwareSignerBackend>,
    credentials: &AgentCredentials,
) -> Option<u64> {
    daemon
        .nonce_heads
        .read()
        .expect("nonce heads")
        .get(&credentials.agent_key.vault_key_id)
        .and_then(|chains| chains.get(&1))
        .copied()
}

pub(super) fn tracked_nonce_gap_count(
    daemon: &InMemoryDaemon<SoftwareSignerBackend>,
    credentials: &AgentCredentials,
) -> usize {
    daemon
        .reusable_nonce_gaps
        .read()
        .expect("nonce gaps")
        .get(&credentials.agent_key.vault_key_id)
        .and_then(|chains| chains.get(&1))
        .map(|gaps| gaps.len())
        .unwrap_or_default()
}
