use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::keccak256;
use async_trait::async_trait;
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
use serde_json::to_vec;
use solana_sdk::bs58;
use uuid::Uuid;
use vault_domain::{
    AgentAction, AgentCredentials, AssetId, BroadcastTx, EntityScope, EvmAddress, KeyAlgorithm,
    KeySource, Lease, ManualApprovalDecision, ManualApprovalStatus, NonceReleaseRequest,
    NonceReservation, NonceReservationRequest, PolicyAttachment, PolicyType, RelayConfig,
    SignRequest, Signature, SolanaNonceAccountCreate, SolanaSolTransfer, SolanaSplTransfer,
    SpendingPolicy, VaultKey,
};
use vault_policy::{PolicyDecision, PolicyEvaluation, PolicyExplanation};
use vault_signer::{BackendKind, SignerError, SoftwareSignerBackend, VaultSignerBackend};
use zeroize::Zeroizing;

use super::{
    constant_time_eq, ensure_relay_identity, ethereum_address_from_public_key_hex,
    generate_agent_auth_token, hash_agent_auth_token, hash_password, manual_approval_frontend_url,
    map_domain_to_signer_error, normalize_optional_url, parse_verifying_key, payload_hash_hex,
    validate_admin_password, validate_config, validate_loaded_state, validate_policy, AdminSession,
    DaemonConfig, DaemonError, DaemonRpcRequest, DaemonRpcResponse, EncryptedStateStore,
    InMemoryDaemon, KeyCreateRequest, KeyManagerDaemonApi, PersistedDaemonState,
    PersistentStoreConfig, PolicyError, PolicySummary,
};

fn policy_all_per_tx(max: u128) -> SpendingPolicy {
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

fn policy_per_chain_gas(chain_id: u64, max_gas_wei: u128) -> SpendingPolicy {
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

fn sign_request(credentials: &AgentCredentials, action: AgentAction) -> SignRequest {
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

fn sample_solana_spl_transfer_action(fee_payer: &VaultKey) -> AgentAction {
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
            token_program: vault_domain::SolanaTokenProgram::Token,
            transfer_fee_wei: None,
            compute_unit_limit: None,
            compute_unit_price_micro_lamports: None,
        },
    }
}

fn sample_solana_sol_transfer_action(fee_payer: &VaultKey) -> AgentAction {
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

fn sample_solana_nonce_account_create_action(fee_payer: &VaultKey) -> AgentAction {
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

#[derive(Debug, Clone)]
struct FlakySignerBackend {
    inner: SoftwareSignerBackend,
    remaining_payload_failures: Arc<AtomicUsize>,
    remaining_digest_failures: Arc<AtomicUsize>,
    error: SignerError,
}

impl FlakySignerBackend {
    fn fail_first_payload(error: SignerError) -> Self {
        Self {
            inner: SoftwareSignerBackend::default(),
            remaining_payload_failures: Arc::new(AtomicUsize::new(1)),
            remaining_digest_failures: Arc::new(AtomicUsize::new(0)),
            error,
        }
    }

    fn fail_first_digest(error: SignerError) -> Self {
        Self {
            inner: SoftwareSignerBackend::default(),
            remaining_payload_failures: Arc::new(AtomicUsize::new(0)),
            remaining_digest_failures: Arc::new(AtomicUsize::new(1)),
            error,
        }
    }

    fn consume_failure(counter: &AtomicUsize) -> bool {
        counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
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

async fn reserve_nonce_for_agent(
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

fn unique_state_path(test_name: &str) -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "agentpay-daemon-{test_name}-{}-{}.state",
        std::process::id(),
        unique
    ))
}

#[derive(Debug, Clone, Default)]
struct CleanupTrackingSignerBackend {
    live_key_ids: Arc<Mutex<HashSet<Uuid>>>,
    deleted_key_ids: Arc<Mutex<Vec<Uuid>>>,
}

impl CleanupTrackingSignerBackend {
    fn live_key_count(&self) -> usize {
        self.live_key_ids.lock().expect("live key lock").len()
    }

    fn deleted_key_ids(&self) -> Vec<Uuid> {
        self.deleted_key_ids
            .lock()
            .expect("deleted key lock")
            .clone()
    }
}

#[async_trait]
impl VaultSignerBackend for CleanupTrackingSignerBackend {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::Tee
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
struct TrackingNonExportableSignerBackend {
    created_key_ids: Arc<RwLock<HashSet<Uuid>>>,
}

impl TrackingNonExportableSignerBackend {
    fn created_key_count(&self) -> usize {
        self.created_key_ids.read().expect("created key ids").len()
    }
}

#[async_trait::async_trait]
impl VaultSignerBackend for TrackingNonExportableSignerBackend {
    fn backend_kind(&self) -> vault_signer::BackendKind {
        vault_signer::BackendKind::Tee
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

fn poison_vault_keys_lock<B>(daemon: &InMemoryDaemon<B>)
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
fn sample_lease() -> Lease {
    let now = time::OffsetDateTime::now_utc();
    Lease {
        lease_id: Uuid::new_v4(),
        issued_at: now,
        expires_at: now + time::Duration::minutes(1),
    }
}

fn sample_session() -> AdminSession {
    AdminSession {
        vault_password: "vault-password".to_string(),
        lease: sample_lease(),
    }
}

fn sample_agent_credentials() -> AgentCredentials {
    AgentCredentials {
        agent_key: vault_domain::AgentKey {
            id: Uuid::new_v4(),
            vault_key_id: Uuid::new_v4(),
            policies: PolicyAttachment::AllPolicies,
            created_at: time::OffsetDateTime::now_utc(),
        },
        auth_token: "agent-secret-token".to_string().into(),
    }
}

fn sample_vault_key() -> VaultKey {
    VaultKey {
        id: Uuid::new_v4(),
        source: KeySource::Generated,
        algorithm: KeyAlgorithm::Secp256k1,
        public_key_hex: "11".repeat(33),
        created_at: time::OffsetDateTime::now_utc(),
    }
}

fn sample_manual_approval_request() -> vault_domain::ManualApprovalRequest {
    vault_domain::ManualApprovalRequest {
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
        completed_at: None,
        rejection_reason: None,
    }
}

fn sample_nonce_reservation() -> NonceReservation {
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

fn poison_rwlock<T>(lock: &Arc<std::sync::RwLock<T>>) {
    let lock = Arc::clone(lock);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _guard = lock.write().expect("lock write");
        panic!("poison lock");
    }));
}

fn sample_policy_evaluation() -> PolicyEvaluation {
    PolicyEvaluation {
        evaluated_policy_ids: vec![Uuid::new_v4()],
    }
}

fn sample_policy_explanation() -> PolicyExplanation {
    let policy_id = Uuid::new_v4();
    PolicyExplanation {
        attached_policy_ids: vec![policy_id],
        applicable_policy_ids: vec![policy_id],
        evaluated_policy_ids: vec![policy_id],
        decision: PolicyDecision::Allow,
    }
}

#[test]
fn daemon_rpc_request_debug_redacts_vault_password() {
    let rendered = format!(
        "{:?}",
        DaemonRpcRequest::IssueLease {
            vault_password: "super-secret-password".to_string(),
        }
    );

    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("super-secret-password"));
}

#[test]
fn daemon_rpc_response_debug_redacts_auth_token() {
    let rendered = format!(
        "{:?}",
        DaemonRpcResponse::AuthToken("super-secret-token".to_string())
    );

    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("super-secret-token"));
}

#[test]
fn daemon_rpc_request_zeroize_secrets_clears_nested_secret_material() {
    let now = time::OffsetDateTime::now_utc();
    let mut admin_request = DaemonRpcRequest::CreateAgentKey {
        session: AdminSession {
            vault_password: "super-secret-password".to_string(),
            lease: Lease {
                lease_id: Uuid::new_v4(),
                issued_at: now,
                expires_at: now + time::Duration::minutes(1),
            },
        },
        vault_key_id: Uuid::new_v4(),
        attachment: PolicyAttachment::AllPolicies,
    };
    admin_request.zeroize_secrets();
    match &admin_request {
        DaemonRpcRequest::CreateAgentKey { session, .. } => {
            assert!(session
                .vault_password
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0));
        }
        other => panic!("unexpected request variant: {other:?}"),
    }

    let mut sign_request = DaemonRpcRequest::SignForAgent {
        request: SignRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: Uuid::new_v4(),
            agent_auth_token: "agent-secret-token".to_string().into(),
            payload: vec![1, 2, 3, 4],
            action: AgentAction::Approve {
                token: "0x1111111111111111111111111111111111111111"
                    .parse()
                    .expect("token"),
                spender: "0x2222222222222222222222222222222222222222"
                    .parse()
                    .expect("spender"),
                amount_wei: 42,
                chain_id: 1,
            },
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        },
    };
    sign_request.zeroize_secrets();
    match &sign_request {
        DaemonRpcRequest::SignForAgent { request } => {
            assert!(request
                .agent_auth_token
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0));
            assert!(request.payload.iter().all(|byte| *byte == 0));
        }
        other => panic!("unexpected request variant: {other:?}"),
    }

    let mut reserve_nonce = DaemonRpcRequest::ReserveNonce {
        request: NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: Uuid::new_v4(),
            agent_auth_token: "nonce-secret".to_string().into(),
            chain_id: 1,
            min_nonce: 7,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        },
    };
    reserve_nonce.zeroize_secrets();
    match &reserve_nonce {
        DaemonRpcRequest::ReserveNonce { request } => {
            assert!(request
                .agent_auth_token
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0));
        }
        other => panic!("unexpected request variant: {other:?}"),
    }
}

#[test]
fn daemon_rpc_response_zeroize_secrets_clears_auth_tokens() {
    let now = time::OffsetDateTime::now_utc();
    let mut response = DaemonRpcResponse::AgentCredentials(AgentCredentials {
        agent_key: vault_domain::AgentKey {
            id: Uuid::new_v4(),
            vault_key_id: Uuid::new_v4(),
            policies: PolicyAttachment::AllPolicies,
            created_at: now,
        },
        auth_token: "agent-secret-token".to_string().into(),
    });
    response.zeroize_secrets();
    match &response {
        DaemonRpcResponse::AgentCredentials(credentials) => {
            assert!(credentials
                .auth_token
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0));
        }
        other => panic!("unexpected response variant: {other:?}"),
    }

    let mut rotated = DaemonRpcResponse::AuthToken("rotated-secret-token".to_string());
    rotated.zeroize_secrets();
    match &rotated {
        DaemonRpcResponse::AuthToken(token) => {
            assert!(token.as_bytes().iter().all(|byte| *byte == 0));
        }
        other => panic!("unexpected response variant: {other:?}"),
    }
}

#[test]
fn daemon_rpc_request_debug_covers_all_variants() {
    let session = sample_session();
    let credentials = sample_agent_credentials();
    let request = sign_request(
        &credentials,
        AgentAction::TransferNative {
            chain_id: 1,
            to: "0x1111111111111111111111111111111111111111"
                .parse()
                .expect("recipient"),
            amount_wei: 7,
        },
    );
    let nonce_request = NonceReservationRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: credentials.agent_key.id,
        agent_auth_token: credentials.auth_token.clone(),
        chain_id: 1,
        min_nonce: 9,
        exact_nonce: false,
        requested_at: time::OffsetDateTime::now_utc(),
        expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(1),
    };
    let release_request = NonceReleaseRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: credentials.agent_key.id,
        agent_auth_token: credentials.auth_token.clone(),
        reservation_id: Uuid::new_v4(),
        requested_at: time::OffsetDateTime::now_utc(),
        expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(1),
    };
    let requests = vec![
        DaemonRpcRequest::IssueLease {
            vault_password: "super-secret-password".to_string(),
        },
        DaemonRpcRequest::AddPolicy {
            session: session.clone(),
            policy: policy_all_per_tx(100),
        },
        DaemonRpcRequest::ListPolicies {
            session: session.clone(),
        },
        DaemonRpcRequest::ListPolicySummaries {
            session: session.clone(),
        },
        DaemonRpcRequest::DisablePolicy {
            session: session.clone(),
            policy_id: Uuid::new_v4(),
        },
        DaemonRpcRequest::CreateVaultKey {
            session: session.clone(),
            request: KeyCreateRequest::Generate,
        },
        DaemonRpcRequest::CreateAgentKey {
            session: session.clone(),
            vault_key_id: Uuid::new_v4(),
            attachment: PolicyAttachment::AllPolicies,
        },
        DaemonRpcRequest::ExportVaultPrivateKey {
            session: session.clone(),
            vault_key_id: Uuid::new_v4(),
        },
        DaemonRpcRequest::RotateAgentAuthToken {
            session: session.clone(),
            agent_key_id: Uuid::new_v4(),
        },
        DaemonRpcRequest::RevokeAgentKey {
            session: session.clone(),
            agent_key_id: Uuid::new_v4(),
        },
        DaemonRpcRequest::ListManualApprovalRequests {
            session: session.clone(),
        },
        DaemonRpcRequest::DecideManualApprovalRequest {
            session: session.clone(),
            approval_request_id: Uuid::new_v4(),
            decision: ManualApprovalDecision::Reject,
            rejection_reason: Some("denied".to_string()),
        },
        DaemonRpcRequest::SetRelayConfig {
            session: session.clone(),
            relay_url: Some("https://relay.example".to_string()),
            frontend_url: Some("https://frontend.example".to_string()),
        },
        DaemonRpcRequest::GetRelayConfig {
            session: session.clone(),
        },
        DaemonRpcRequest::EvaluateForAgent {
            request: request.clone(),
        },
        DaemonRpcRequest::ExplainForAgent {
            request: request.clone(),
        },
        DaemonRpcRequest::ReserveNonce {
            request: nonce_request,
        },
        DaemonRpcRequest::ReleaseNonce {
            request: release_request,
        },
        DaemonRpcRequest::SignForAgent { request },
    ];

    for request in requests {
        let rendered = format!("{request:?}");
        assert!(!rendered.is_empty());
    }
}

#[test]
fn daemon_rpc_request_zeroize_covers_remaining_admin_and_agent_variants() {
    let session = sample_session();
    let credentials = sample_agent_credentials();
    let request = sign_request(
        &credentials,
        AgentAction::TransferNative {
            chain_id: 1,
            to: "0x1111111111111111111111111111111111111111"
                .parse()
                .expect("recipient"),
            amount_wei: 7,
        },
    );

    let mut admin_variants = vec![
        DaemonRpcRequest::ExportVaultPrivateKey {
            session: session.clone(),
            vault_key_id: Uuid::new_v4(),
        },
        DaemonRpcRequest::ListManualApprovalRequests {
            session: session.clone(),
        },
        DaemonRpcRequest::DecideManualApprovalRequest {
            session: session.clone(),
            approval_request_id: Uuid::new_v4(),
            decision: ManualApprovalDecision::Approve,
            rejection_reason: None,
        },
        DaemonRpcRequest::SetRelayConfig {
            session: session.clone(),
            relay_url: Some("https://relay.example".to_string()),
            frontend_url: Some("https://frontend.example".to_string()),
        },
    ];
    for request in &mut admin_variants {
        request.zeroize_secrets();
        match request {
            DaemonRpcRequest::ExportVaultPrivateKey { session, .. }
            | DaemonRpcRequest::ListManualApprovalRequests { session }
            | DaemonRpcRequest::DecideManualApprovalRequest { session, .. }
            | DaemonRpcRequest::SetRelayConfig { session, .. } => {
                assert!(session
                    .vault_password
                    .as_bytes()
                    .iter()
                    .all(|byte| *byte == 0));
            }
            other => panic!("unexpected request variant: {other:?}"),
        }
    }

    let mut explain = DaemonRpcRequest::ExplainForAgent { request };
    explain.zeroize_secrets();
    match explain {
        DaemonRpcRequest::ExplainForAgent { request } => {
            assert!(request
                .agent_auth_token
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0));
        }
        other => panic!("unexpected request variant: {other:?}"),
    }
}

#[test]
fn daemon_rpc_response_debug_and_zeroize_cover_remaining_variants() {
    let lease = sample_lease();
    let manual_request = sample_manual_approval_request();
    let reservation = sample_nonce_reservation();
    let responses = vec![
        DaemonRpcResponse::Unit,
        DaemonRpcResponse::Lease(lease),
        DaemonRpcResponse::Policies(vec![policy_all_per_tx(100)]),
        DaemonRpcResponse::PolicySummaries(vec![PolicySummary {
            id: Uuid::new_v4(),
            enabled: true,
        }]),
        DaemonRpcResponse::PolicyEvaluation(sample_policy_evaluation()),
        DaemonRpcResponse::PolicyExplanation(sample_policy_explanation()),
        DaemonRpcResponse::VaultKey(sample_vault_key()),
        DaemonRpcResponse::PrivateKey(Some("super-secret-private-key".to_string())),
        DaemonRpcResponse::PrivateKey(None),
        DaemonRpcResponse::ManualApprovalRequests(vec![manual_request.clone()]),
        DaemonRpcResponse::ManualApprovalRequest(manual_request),
        DaemonRpcResponse::RelayConfig(vault_domain::RelayConfig {
            relay_url: Some("https://relay.example".to_string()),
            frontend_url: Some("https://frontend.example".to_string()),
            daemon_id_hex: "aa".repeat(32),
            daemon_public_key_hex: "bb".repeat(33),
        }),
        DaemonRpcResponse::NonceReservation(reservation),
        DaemonRpcResponse::Signature(Signature::from_der(vec![1, 2, 3])),
    ];

    for response in responses {
        let rendered = format!("{response:?}");
        assert!(!rendered.is_empty());
    }

    let rendered = format!(
        "{:?}",
        DaemonRpcResponse::AgentCredentials(sample_agent_credentials())
    );
    assert!(rendered.contains("AgentCredentials"));

    let mut private_key = DaemonRpcResponse::PrivateKey(Some("secret".to_string()));
    private_key.zeroize_secrets();
    match &private_key {
        DaemonRpcResponse::PrivateKey(Some(value)) => {
            assert!(value.as_bytes().iter().all(|byte| *byte == 0));
        }
        other => panic!("unexpected response variant: {other:?}"),
    }

    let mut none_private_key = DaemonRpcResponse::PrivateKey(None);
    none_private_key.zeroize_secrets();
    assert!(matches!(
        none_private_key,
        DaemonRpcResponse::PrivateKey(None)
    ));
}

#[test]
fn ensure_relay_identity_populates_missing_fields_and_preserves_existing_values() {
    let mut generated = PersistedDaemonState::default();
    ensure_relay_identity(&mut generated);
    assert_eq!(
        generated.relay_config.relay_url.as_deref(),
        Some("http://localhost:8787")
    );
    assert_eq!(generated.relay_private_key_hex.len(), 64);
    assert_eq!(generated.relay_config.daemon_id_hex.len(), 64);
    assert_eq!(generated.relay_config.daemon_public_key_hex.len(), 64);

    let mut preserved = PersistedDaemonState {
        relay_config: RelayConfig {
            relay_url: Some("https://relay.example".to_string()),
            frontend_url: Some("https://frontend.example".to_string()),
            daemon_id_hex: "11".repeat(32),
            daemon_public_key_hex: "22".repeat(32),
        },
        relay_private_key_hex: "33".repeat(32).into(),
        ..PersistedDaemonState::default()
    };
    ensure_relay_identity(&mut preserved);
    assert_eq!(preserved.relay_private_key_hex.as_str(), "33".repeat(32));
    assert_eq!(
        preserved.relay_config.relay_url.as_deref(),
        Some("https://relay.example")
    );
    assert_eq!(preserved.relay_config.daemon_id_hex, "11".repeat(32));
    assert_eq!(
        preserved.relay_config.daemon_public_key_hex,
        "22".repeat(32)
    );
}

#[test]
fn manual_approval_frontend_url_prefers_frontend_and_falls_back_to_relay() {
    let approval_request_id =
        Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("uuid");

    let preferred = manual_approval_frontend_url(
        &RelayConfig {
            relay_url: Some("https://relay.example".to_string()),
            frontend_url: Some("https://frontend.example/".to_string()),
            daemon_id_hex: "11".repeat(32),
            daemon_public_key_hex: "22".repeat(32),
        },
        approval_request_id,
        "capability-token",
    )
    .expect("frontend url");
    assert_eq!(
        preferred,
        format!(
            "https://frontend.example/approvals/{approval_request_id}?daemonId={}&approvalCapability=capability-token",
            "11".repeat(32)
        )
    );

    let fallback = manual_approval_frontend_url(
        &RelayConfig {
            relay_url: Some("https://relay.example".to_string()),
            frontend_url: None,
            daemon_id_hex: "   ".to_string(),
            daemon_public_key_hex: "22".repeat(32),
        },
        approval_request_id,
        "capability-token",
    )
    .expect("relay fallback");
    assert_eq!(
        fallback,
        format!(
            "https://relay.example/approvals/{approval_request_id}?approvalCapability=capability-token"
        )
    );
}

#[test]
fn payload_hash_hex_is_stable_and_input_sensitive() {
    let first = payload_hash_hex(b"hello world");
    let second = payload_hash_hex(b"hello world");
    let different = payload_hash_hex(b"hello world!");

    assert_eq!(first, second);
    assert_ne!(first, different);
    assert_eq!(first.len(), 64);
}

#[tokio::test]
async fn relay_registration_snapshot_and_address_helpers_use_latest_vault_key() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");
    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    let first = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("first key");
    let second = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("second key");

    let expected_address = {
        let public_bytes =
            hex::decode(second.public_key_hex.trim_start_matches("0x")).expect("decode public key");
        let digest = keccak256(&public_bytes[1..]);
        format!("0x{}", hex::encode(&digest.0[12..]))
    };

    assert_eq!(
        ethereum_address_from_public_key_hex(&second.public_key_hex).expect("address"),
        expected_address
    );
    assert!(
        matches!(
            ethereum_address_from_public_key_hex("zz"),
            Err(DaemonError::Signer(_))
        ),
        "invalid hex should be rejected"
    );

    let snapshot = daemon
        .relay_registration_snapshot()
        .expect("relay registration snapshot");
    assert_eq!(
        snapshot.vault_public_key_hex.as_deref(),
        Some(second.public_key_hex.as_str())
    );
    assert_eq!(
        snapshot.ethereum_address.as_deref(),
        Some(expected_address.as_str())
    );
    assert_ne!(
        snapshot.vault_public_key_hex.as_deref(),
        Some(first.public_key_hex.as_str())
    );
}

#[test]
fn decrypt_relay_envelope_round_trips_and_validates_inputs() {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305};

    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");
    let snapshot = daemon.snapshot_state().expect("snapshot");
    let daemon_public_bytes =
        hex::decode(snapshot.relay_config.daemon_public_key_hex).expect("daemon public key");
    let daemon_public = x25519_dalek::PublicKey::from(
        <[u8; 32]>::try_from(daemon_public_bytes.as_slice()).expect("public key bytes"),
    );
    let secret = x25519_dalek::StaticSecret::from([9u8; 32]);
    let shared_secret = secret.diffie_hellman(&daemon_public);
    let cipher = XChaCha20Poly1305::new(shared_secret.as_bytes().into());
    let nonce = [4u8; 24];
    let plaintext = br#"{"update":"payload"}"#;
    let ciphertext = cipher
        .encrypt((&nonce).into(), plaintext.as_slice())
        .expect("encrypt");
    let encapsulated_key_hex = hex::encode(x25519_dalek::PublicKey::from(&secret).as_bytes());

    let decrypted = daemon
        .decrypt_relay_envelope(
            "x25519-xchacha20poly1305-v1",
            &encapsulated_key_hex,
            &hex::encode(nonce),
            &hex::encode(ciphertext),
        )
        .expect("decrypt");
    assert_eq!(decrypted, plaintext);

    assert!(matches!(
        daemon.decrypt_relay_envelope("invalid", &encapsulated_key_hex, &hex::encode(nonce), "00"),
        Err(DaemonError::InvalidRelayConfig(message)) if message.contains("unsupported relay encryption algorithm")
    ));
    assert!(matches!(
        daemon.decrypt_relay_envelope("x25519-xchacha20poly1305-v1", "aa", &hex::encode(nonce), "00"),
        Err(DaemonError::InvalidRelayConfig(message)) if message.contains("encapsulated key must be 32 bytes")
    ));
    assert!(matches!(
        daemon.decrypt_relay_envelope("x25519-xchacha20poly1305-v1", &encapsulated_key_hex, "aa", "00"),
        Err(DaemonError::InvalidRelayConfig(message)) if message.contains("nonce must be 24 bytes")
    ));
    assert!(matches!(
        daemon.decrypt_relay_envelope(
            "x25519-xchacha20poly1305-v1",
            &encapsulated_key_hex,
            &hex::encode(nonce),
            "zz"
        ),
        Err(DaemonError::InvalidRelayConfig(message)) if message.contains("ciphertext is invalid hex")
    ));
}

#[tokio::test]
async fn snapshot_restore_and_non_persistent_helpers_cover_state_management_paths() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");
    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };
    daemon
        .add_policy(&session, policy_all_per_tx(77))
        .await
        .expect("add policy");
    let vault_key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("vault key");
    let agent_credentials = daemon
        .create_agent_key(&session, vault_key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent credentials");
    reserve_nonce_for_agent(&daemon, &agent_credentials, 1, 5).await;
    let snapshot = daemon.snapshot_state().expect("snapshot");

    daemon.policies.write().expect("policies").clear();
    daemon.vault_keys.write().expect("vault keys").clear();
    daemon.agent_keys.write().expect("agent keys").clear();
    daemon
        .agent_auth_tokens
        .write()
        .expect("auth tokens")
        .clear();
    daemon
        .reusable_nonce_gaps
        .write()
        .expect("reusable nonce gaps")
        .clear();
    daemon
        .nonce_reservations
        .write()
        .expect("reservations")
        .clear();
    daemon
        .restore_state(snapshot.clone())
        .expect("restore snapshot");

    assert_eq!(
        daemon.snapshot_state().expect("restored snapshot").policies,
        snapshot.policies
    );
    assert_eq!(
        daemon
            .snapshot_state()
            .expect("restored snapshot")
            .vault_keys,
        snapshot.vault_keys
    );
    assert_eq!(
        daemon
            .snapshot_state()
            .expect("restored snapshot")
            .agent_auth_tokens,
        snapshot.agent_auth_tokens
    );
    assert_eq!(
        daemon
            .snapshot_state()
            .expect("restored snapshot")
            .nonce_reservations,
        snapshot.nonce_reservations
    );

    assert!(daemon
        .backup_state_if_persistent()
        .expect("backup")
        .is_none());
    daemon.persist_state_if_enabled().expect("persist noop");
    daemon
        .persist_or_revert(None)
        .expect("persist or revert noop");
}

#[tokio::test]
async fn create_vault_key_cleans_up_backend_key_on_post_create_failure() {
    let signer_backend = TrackingNonExportableSignerBackend::default();
    let daemon = InMemoryDaemon::new(
        "vault-password",
        signer_backend.clone(),
        DaemonConfig::default(),
    )
    .expect("daemon");
    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    poison_vault_keys_lock(&daemon);

    let err = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect_err("poisoned vault key state must fail create");
    assert!(matches!(err, DaemonError::LockPoisoned));
    assert_eq!(
        signer_backend.created_key_count(),
        0,
        "backend key material must be cleaned up when daemon commit fails"
    );
    assert!(
        daemon.vault_keys.read().is_err(),
        "the test should fail after backend creation because the vault_keys lock is poisoned"
    );
}

#[test]
fn api_validation_helpers_cover_url_password_config_and_token_paths() {
    assert_eq!(
        normalize_optional_url("relay_url", None).expect("none"),
        None
    );
    assert_eq!(
        normalize_optional_url("relay_url", Some("   ".to_string())).expect("blank"),
        None
    );
    assert_eq!(
        normalize_optional_url("relay_url", Some("https://relay.example/path".to_string()))
            .expect("https"),
        Some("https://relay.example/path".to_string())
    );
    assert_eq!(
        normalize_optional_url("relay_url", Some("http://localhost:8787".to_string()))
            .expect("localhost http"),
        Some("http://localhost:8787".to_string())
    );
    assert_eq!(
        normalize_optional_url("relay_url", Some("http://127.0.0.1:8787".to_string()))
            .expect("loopback http"),
        Some("http://127.0.0.1:8787".to_string())
    );
    assert!(matches!(
        normalize_optional_url("relay_url", Some("ftp://relay.example".to_string())),
        Err(DaemonError::InvalidRelayConfig(message)) if message.contains("must use http or https")
    ));
    assert!(matches!(
        normalize_optional_url("relay_url", Some("https://user@example.com".to_string())),
        Err(DaemonError::InvalidRelayConfig(message)) if message.contains("embedded username or password")
    ));
    assert!(matches!(
        normalize_optional_url("relay_url", Some("https://relay.example?q=1".to_string())),
        Err(DaemonError::InvalidRelayConfig(message)) if message.contains("query string")
    ));
    assert!(matches!(
        normalize_optional_url("relay_url", Some("https://relay.example#frag".to_string())),
        Err(DaemonError::InvalidRelayConfig(message)) if message.contains("fragment")
    ));
    assert!(matches!(
        normalize_optional_url("relay_url", Some("http://relay.example".to_string())),
        Err(DaemonError::InvalidRelayConfig(message)) if message.contains("must use https unless it targets localhost or a loopback address")
    ));

    validate_admin_password("vault-password").expect("valid password");
    assert!(matches!(
        validate_admin_password("   "),
        Err(DaemonError::InvalidConfig(message)) if message.contains("must not be empty")
    ));
    assert!(matches!(
        validate_admin_password(&"x".repeat(16 * 1024 + 1)),
        Err(DaemonError::InvalidConfig(message)) if message.contains("must not exceed")
    ));

    validate_config(&DaemonConfig::default()).expect("valid config");
    assert!(matches!(
        validate_config(&DaemonConfig {
            lease_ttl: time::Duration::ZERO,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("lease_ttl")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_active_leases: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("max_active_leases")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_sign_payload_bytes: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("max_sign_payload_bytes")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_request_ttl: time::Duration::ZERO,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("max_request_ttl")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_request_clock_skew: time::Duration::seconds(-1),
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("max_request_clock_skew")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_tracked_replay_ids: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message))
            if message.contains("max_tracked_replay_ids")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            nonce_reservation_ttl: time::Duration::ZERO,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("nonce_reservation_ttl")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_active_nonce_reservations: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message))
            if message.contains("max_active_nonce_reservations")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            manual_approval_active_ttl: time::Duration::ZERO,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message))
            if message.contains("manual_approval_active_ttl")
    ));
    validate_config(&DaemonConfig {
        manual_approval_terminal_retention: time::Duration::ZERO,
        ..DaemonConfig::default()
    })
    .expect("zero manual approval retention must be allowed");
    assert!(matches!(
        validate_config(&DaemonConfig {
            manual_approval_terminal_retention: time::Duration::seconds(-1),
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message))
            if message.contains("manual_approval_terminal_retention")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_tracked_nonce_chains_per_vault: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message))
            if message.contains("max_tracked_nonce_chains_per_vault")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_failed_admin_auth_attempts: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("max_failed_admin_auth_attempts")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            admin_auth_lockout: time::Duration::ZERO,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("admin_auth_lockout")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            argon2_memory_kib: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("argon2_memory_kib")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            argon2_time_cost: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("argon2_time_cost")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            argon2_parallelism: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("argon2_parallelism")
    ));

    let token = generate_agent_auth_token();
    assert!(token.contains('.'));
    let left = hash_agent_auth_token(&token);
    let same = hash_agent_auth_token(&token);
    let right = hash_agent_auth_token("different-token");
    assert!(constant_time_eq(&left, &same));
    assert!(!constant_time_eq(&left, &right));
    assert!(!constant_time_eq(&left, &[1u8; 31]));
}

#[tokio::test]
async fn parsing_policy_and_loaded_state_helpers_cover_remaining_error_paths() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");
    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };
    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");

    let parsed_key = parse_verifying_key(&key.public_key_hex).expect("valid public key");
    assert_eq!(
        parsed_key.to_encoded_point(false).as_bytes(),
        &hex::decode(&key.public_key_hex).expect("hex")
    );
    assert!(matches!(
        parse_verifying_key("zz"),
        Err(DaemonError::Signer(_))
    ));
    assert!(matches!(
        parse_verifying_key(&hex::encode([0u8; 33])),
        Err(DaemonError::Signer(_))
    ));
    assert!(matches!(
        map_domain_to_signer_error(vault_domain::DomainError::UnsupportedTransactionType(0x03)),
        DaemonError::Signer(_)
    ));
    assert!(matches!(
        map_domain_to_signer_error(vault_domain::DomainError::Permit2FieldOutOfRange {
            field: "expiration"
        }),
        DaemonError::Signer(SignerError::Unsupported(message))
            if message.contains("permit2 expiration exceeds uint48 range")
    ));

    validate_policy(&policy_all_per_tx(1)).expect("valid policy");
    validate_policy(
        &SpendingPolicy::new_calldata_limit(
            0,
            1,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("valid calldata policy"),
    )
    .expect("calldata policy");
    validate_policy(
        &SpendingPolicy::new_tx_count_limit(
            0,
            1,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("valid tx-count policy"),
    )
    .expect("tx-count policy");
    validate_policy(
        &SpendingPolicy::new_fee_per_gas_limit(
            0,
            1,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("valid max-fee policy"),
    )
    .expect("max-fee policy");
    validate_policy(
        &SpendingPolicy::new_priority_fee_per_gas_limit(
            0,
            1,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("valid priority-fee policy"),
    )
    .expect("priority-fee policy");
    validate_policy(
        &SpendingPolicy::new_gas_spend_limit(
            0,
            1,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("valid gas-spend policy"),
    )
    .expect("gas-spend policy");
    let mut zero_policy = policy_all_per_tx(1);
    zero_policy.max_amount_wei = 0;
    assert!(matches!(
        validate_policy(&zero_policy),
        Err(DaemonError::InvalidPolicy(message)) if message.contains("max_amount_wei")
    ));
    let mut zero_calldata_policy = SpendingPolicy::new_calldata_limit(
        0,
        1,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("valid calldata policy");
    zero_calldata_policy.max_calldata_bytes = None;
    zero_calldata_policy.max_amount_wei = 0;
    assert!(matches!(
        validate_policy(&zero_calldata_policy),
        Err(DaemonError::InvalidPolicy(message)) if message.contains("max_calldata_bytes")
    ));
    let mut zero_tx_count_policy = SpendingPolicy::new_tx_count_limit(
        0,
        1,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("valid tx-count policy");
    zero_tx_count_policy.max_tx_count = None;
    assert!(matches!(
        validate_policy(&zero_tx_count_policy),
        Err(DaemonError::InvalidPolicy(message)) if message.contains("max_tx_count")
    ));
    let mut zero_max_fee_policy = SpendingPolicy::new_fee_per_gas_limit(
        0,
        1,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("valid max-fee policy");
    zero_max_fee_policy.max_fee_per_gas_wei = None;
    assert!(matches!(
        validate_policy(&zero_max_fee_policy),
        Err(DaemonError::InvalidPolicy(message)) if message.contains("max_fee_per_gas_wei")
    ));
    let mut zero_priority_fee_policy = SpendingPolicy::new_priority_fee_per_gas_limit(
        0,
        1,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("valid priority-fee policy");
    zero_priority_fee_policy.max_priority_fee_per_gas_wei = None;
    assert!(matches!(
        validate_policy(&zero_priority_fee_policy),
        Err(DaemonError::InvalidPolicy(message))
            if message.contains("max_priority_fee_per_gas_wei")
    ));
    let mut zero_gas_spend_policy = SpendingPolicy::new_gas_spend_limit(
        0,
        1,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("valid gas-spend policy");
    zero_gas_spend_policy.max_gas_spend_wei = None;
    assert!(matches!(
        validate_policy(&zero_gas_spend_policy),
        Err(DaemonError::InvalidPolicy(message)) if message.contains("max_gas_spend_wei")
    ));
    let mut bad_networks = policy_all_per_tx(1);
    bad_networks.networks = EntityScope::Set(BTreeSet::from([0]));
    assert!(matches!(
        validate_policy(&bad_networks),
        Err(DaemonError::InvalidPolicy(message)) if message.contains("network set scope")
    ));

    let valid_state = daemon.snapshot_state().expect("snapshot");
    validate_loaded_state(&valid_state).expect("valid loaded state");

    let mut state = valid_state.clone();
    let lease = sample_lease();
    state.leases.insert(Uuid::new_v4(), lease);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("lease entry keyed by")
    ));

    let mut state = valid_state.clone();
    let mut policy = policy_all_per_tx(1);
    let mismatched_policy_key = Uuid::new_v4();
    policy.id = Uuid::new_v4();
    state.policies.insert(mismatched_policy_key, policy);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("policy entry keyed by")
    ));

    let mut state = valid_state.clone();
    state
        .software_signer_private_keys
        .insert(Uuid::new_v4(), "11".repeat(32).into());
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("signer key material")
    ));

    let mut state = valid_state.clone();
    let agent_key = sample_agent_credentials().agent_key;
    state.agent_keys.insert(agent_key.id, agent_key.clone());
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("references unknown vault key")
    ));

    let mut state = valid_state.clone();
    let mut attached_agent = sample_agent_credentials().agent_key;
    attached_agent.vault_key_id = key.id;
    attached_agent.policies = PolicyAttachment::PolicySet(BTreeSet::new());
    state.agent_keys.insert(attached_agent.id, attached_agent);
    validate_loaded_state(&state).expect("empty policy set should be loadable");

    let mut state = valid_state.clone();
    let mut disabled_policy = policy_all_per_tx(100);
    disabled_policy.enabled = false;
    let disabled_policy_id = disabled_policy.id;
    state.policies.insert(disabled_policy.id, disabled_policy);
    let mut attached_agent = sample_agent_credentials().agent_key;
    attached_agent.vault_key_id = key.id;
    attached_agent.policies = PolicyAttachment::PolicySet(BTreeSet::from([disabled_policy_id]));
    state.agent_keys.insert(attached_agent.id, attached_agent);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("disabled policy")
    ));

    let mut state = valid_state.clone();
    state.agent_auth_tokens.insert(Uuid::new_v4(), [7u8; 32]);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("auth token for unknown agent")
    ));

    let mut state = valid_state.clone();
    state
        .nonce_heads
        .insert(Uuid::new_v4(), std::collections::HashMap::new());
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("nonce head for unknown vault key")
    ));

    let mut state = valid_state.clone();
    state.nonce_heads.entry(key.id).or_default().insert(0, 7);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("invalid chain_id 0")
    ));

    let mut state = valid_state.clone();
    let mut valid_agent = sample_agent_credentials().agent_key;
    valid_agent.vault_key_id = key.id;
    state.agent_keys.insert(valid_agent.id, valid_agent.clone());
    let mut reservation = sample_nonce_reservation();
    reservation.agent_key_id = valid_agent.id;
    reservation.vault_key_id = key.id;
    reservation.chain_id = 0;
    state
        .nonce_reservations
        .insert(reservation.reservation_id, reservation);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("invalid chain_id 0")
    ));

    let mut state = valid_state.clone();
    let manual_policy = SpendingPolicy::new_manual_approval(
        1,
        1,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy");
    let manual_policy_id = manual_policy.id;
    state.policies.insert(manual_policy.id, manual_policy);
    let mut request = sample_manual_approval_request();
    request.agent_key_id = Uuid::new_v4();
    request.triggered_by_policy_ids = vec![manual_policy_id];
    state.manual_approval_requests.insert(request.id, request);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("references unknown agent")
    ));

    let mut state = valid_state.clone();
    let mut valid_agent = sample_agent_credentials().agent_key;
    valid_agent.vault_key_id = key.id;
    state.agent_keys.insert(valid_agent.id, valid_agent.clone());
    let mut request = sample_manual_approval_request();
    request.agent_key_id = valid_agent.id;
    request.vault_key_id = Uuid::new_v4();
    state.manual_approval_requests.insert(request.id, request);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("vault key mismatch")
    ));

    let mut state = valid_state.clone();
    let mut valid_agent = sample_agent_credentials().agent_key;
    valid_agent.vault_key_id = key.id;
    state.agent_keys.insert(valid_agent.id, valid_agent.clone());
    let mut request = sample_manual_approval_request();
    request.agent_key_id = valid_agent.id;
    request.vault_key_id = key.id;
    request.chain_id = 0;
    state.manual_approval_requests.insert(request.id, request);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("invalid chain_id 0")
    ));

    let mut state = valid_state.clone();
    let mut valid_agent = sample_agent_credentials().agent_key;
    valid_agent.vault_key_id = key.id;
    state.agent_keys.insert(valid_agent.id, valid_agent.clone());
    let mut request = sample_manual_approval_request();
    request.agent_key_id = valid_agent.id;
    request.vault_key_id = key.id;
    request.request_payload_hash_hex = "   ".to_string();
    state.manual_approval_requests.insert(request.id, request);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("empty payload hash")
    ));

    let mut state = valid_state.clone();
    let mut valid_agent = sample_agent_credentials().agent_key;
    valid_agent.vault_key_id = key.id;
    state.agent_keys.insert(valid_agent.id, valid_agent.clone());
    let mut request = sample_manual_approval_request();
    request.agent_key_id = valid_agent.id;
    request.vault_key_id = key.id;
    request.updated_at = request.created_at - time::Duration::seconds(1);
    state.manual_approval_requests.insert(request.id, request);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("invalid timestamps")
    ));

    let mut state = valid_state.clone();
    let mut valid_agent = sample_agent_credentials().agent_key;
    valid_agent.vault_key_id = key.id;
    state.agent_keys.insert(valid_agent.id, valid_agent.clone());
    let mut request = sample_manual_approval_request();
    request.agent_key_id = valid_agent.id;
    request.vault_key_id = key.id;
    request.status = ManualApprovalStatus::Completed;
    request.completed_at = None;
    state.manual_approval_requests.insert(request.id, request);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("completed without completed_at")
    ));

    let mut state = valid_state.clone();
    let mut valid_agent = sample_agent_credentials().agent_key;
    valid_agent.vault_key_id = key.id;
    state.agent_keys.insert(valid_agent.id, valid_agent.clone());
    let mut request = sample_manual_approval_request();
    request.agent_key_id = valid_agent.id;
    request.vault_key_id = key.id;
    request.triggered_by_policy_ids = vec![Uuid::new_v4()];
    state.manual_approval_requests.insert(request.id, request);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("references unknown policy")
    ));

    let mut state = valid_state.clone();
    let mut valid_agent = sample_agent_credentials().agent_key;
    valid_agent.vault_key_id = key.id;
    state.agent_keys.insert(valid_agent.id, valid_agent.clone());
    let mut non_manual_policy = policy_all_per_tx(1);
    non_manual_policy.id = Uuid::new_v4();
    let non_manual_policy_id = non_manual_policy.id;
    state
        .policies
        .insert(non_manual_policy.id, non_manual_policy);
    let mut request = sample_manual_approval_request();
    request.agent_key_id = valid_agent.id;
    request.vault_key_id = key.id;
    request.triggered_by_policy_ids = vec![non_manual_policy_id];
    state.manual_approval_requests.insert(request.id, request);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("references non-manual policy")
    ));

    let mut state = valid_state.clone();
    state.relay_config.frontend_url = Some("http://frontend.example".to_string());
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::InvalidRelayConfig(message))
            | Err(DaemonError::Persistence(message))
            if message.contains("https unless it targets localhost or a loopback address")
    ));

    let mut state = valid_state.clone();
    state.relay_private_key_hex = "zz".to_string().into();
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("invalid hex")
    ));

    let mut state = valid_state.clone();
    state.relay_private_key_hex = "11".repeat(31).into();
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("must be 32 bytes")
    ));

    let mut state = valid_state.clone();
    state.relay_config.daemon_public_key_hex = "11".repeat(32);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("public key does not match")
    ));

    let mut state = valid_state.clone();
    state.relay_config.daemon_id_hex = "11".repeat(31);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("daemon id must be 32 bytes")
    ));
}

#[tokio::test]
async fn new_with_loaded_state_normalizes_disabled_policy_set_members() {
    let config = DaemonConfig::default();
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        config.clone(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    let policy = policy_all_per_tx(100);
    daemon
        .add_policy(&session, policy.clone())
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let credentials = daemon
        .create_agent_key(
            &session,
            key.id,
            PolicyAttachment::PolicySet(BTreeSet::from([policy.id])),
        )
        .await
        .expect("agent");

    let mut state = daemon.snapshot_state().expect("snapshot");
    state
        .policies
        .get_mut(&policy.id)
        .expect("policy in snapshot")
        .enabled = false;

    let loaded = InMemoryDaemon::new_with_loaded_state(
        SoftwareSignerBackend::default(),
        hash_password("vault-password", &config).expect("admin password hash"),
        config,
        state,
        None,
    )
    .expect("load normalized state");

    let normalized = loaded.snapshot_state().expect("normalized snapshot");
    let stored_agent = normalized
        .agent_keys
        .get(&credentials.agent_key.id)
        .expect("agent in normalized snapshot");
    assert_eq!(
        stored_agent.policies,
        PolicyAttachment::PolicySet(BTreeSet::new())
    );
    validate_loaded_state(&normalized).expect("normalized state remains valid");
}

include!("tests_parts/part1.rs");
include!("tests_parts/part2.rs");
include!("tests_parts/part3.rs");
include!("tests_parts/part4.rs");
