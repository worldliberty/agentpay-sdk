//! The in-memory daemon: state container, constructors, and the
//! [`KeyManagerDaemonApi`] implementation.
//!
//! Each trait method delegates to an inherent `*_impl` method that lives in the
//! submodule owning that concern (authentication, policies, keys, signing, nonces,
//! manual approvals, recovery, Tempo channels, and state persistence).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use agentpay_api::rpc::{
    SpendingLimit, SpendingLimitsReport, WalletBackupExport, WalletBackupSummary, WalletBootstrap,
    WalletBootstrapMode, WalletInfo,
};
use agentpay_api::{AgentAuth, AgentIdentity};
use agentpay_domain::{
    AdminAuth, AdminChallenge, AdminCredential, AdminLease, AgentCredentials, AgentKey,
    ManualApprovalDecision, ManualApprovalRequest, NonceReleaseRequest, NonceReservation,
    NonceReservationRequest, PolicyAttachment, SignRequest, Signature, SignedNonceReleaseRequest,
    SpendEvent, SpendingPolicy, VaultKey,
};
use agentpay_policy::{PolicyEngine, PolicyEvaluation, PolicyExplanation};
use agentpay_signer::{KeyCreateRequest, VaultSignerBackend};
use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use self::admin_auth::AdminAuthState;
use self::state::normalize_disabled_policy_set_attachments;
use crate::config::validate_config;
use crate::persistence::{EncryptedStateStore, PersistedDaemonState};
use crate::{
    DaemonConfig, DaemonError, KeyManagerDaemonApi, PersistentStoreConfig, PolicySummary,
    RequestContext, StateSecret,
};

mod activity;
mod admin_auth;
mod auth;
mod identity;
mod keys;
mod limits;
mod manual_approval;
mod nonces;
mod policies;
mod recovery;
mod signed_nonces;
mod signing;
mod solana;
mod solana_payment;
mod state;
mod tempo_channels;
#[cfg(test)]
mod tests;
mod wallet;

pub(crate) use self::nonces::ReusableNonceGaps;
pub use self::nonces::MAX_NONCE_SKIP;
pub(crate) use self::recovery::RecoverableAgentResult;
pub(crate) use self::signed_nonces::SignedBroadcastRecord;
pub(crate) use self::state::{prepare_loaded_state, validate_loaded_state};
pub(crate) use self::tempo_channels::TempoChannelRecord;

/// Context used by the in-process [`KeyManagerDaemonApi`] implementation.
const IN_PROCESS: RequestContext = RequestContext::in_process();

/// Key manager daemon that keeps keys, policies, and signing state in memory,
/// optionally mirrored to an encrypted state file.
pub struct InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    signer_backend: B,
    policy_engine: PolicyEngine,
    config: DaemonConfig,
    /// Random per-process id embedded in admin challenge messages.
    instance_id: Uuid,
    admin_credentials: Arc<RwLock<HashMap<Uuid, AdminCredential>>>,
    admin_auth: Mutex<AdminAuthState>,
    policies: Arc<RwLock<HashMap<Uuid, SpendingPolicy>>>,
    vault_keys: Arc<RwLock<HashMap<Uuid, VaultKey>>>,
    agent_keys: Arc<RwLock<HashMap<Uuid, AgentKey>>>,
    agent_auth_tokens: Arc<RwLock<HashMap<Uuid, [u8; 32]>>>,
    replay_ids: Arc<RwLock<HashMap<Uuid, OffsetDateTime>>>,
    nonce_heads: Arc<RwLock<HashMap<Uuid, HashMap<u64, u64>>>>,
    reusable_nonce_gaps: Arc<RwLock<ReusableNonceGaps>>,
    nonce_reservations: Arc<RwLock<HashMap<Uuid, NonceReservation>>>,
    spend_log: Arc<RwLock<Vec<SpendEvent>>>,
    manual_approval_requests: Arc<RwLock<HashMap<Uuid, ManualApprovalRequest>>>,
    recoverable_agent_results: Arc<RwLock<HashMap<Uuid, RecoverableAgentResult>>>,
    tempo_channels: Arc<RwLock<HashMap<String, TempoChannelRecord>>>,
    signed_broadcasts: Arc<RwLock<HashMap<String, SignedBroadcastRecord>>>,
    state_store: Option<EncryptedStateStore>,
    signing_guard: tokio::sync::Mutex<()>,
    state_persist_guard: tokio::sync::Mutex<()>,
    /// Serializes backup key derivations (scrypt needs 256 MiB to 1 GiB each).
    backup_kdf_guard: tokio::sync::Mutex<()>,
}

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    /// Builds a daemon with purely in-memory state.
    pub fn new(signer_backend: B, config: DaemonConfig) -> Result<Self, DaemonError> {
        validate_config(&config)?;
        let state = prepare_loaded_state(PersistedDaemonState::default())?;
        Self::new_with_loaded_state(signer_backend, config, state, None)
    }

    /// Builds a daemon whose state is mirrored to an encrypted file keyed by `state_secret`.
    ///
    /// A legacy v1 (vault password) state file is refused unless `store_config`
    /// requests a migration with
    /// [`PersistentStoreConfig::with_legacy_password_migration`].
    pub fn new_with_persistent_store(
        state_secret: &StateSecret,
        signer_backend: B,
        config: DaemonConfig,
        store_config: PersistentStoreConfig,
    ) -> Result<Self, DaemonError> {
        validate_config(&config)?;
        let (state_store, state) =
            EncryptedStateStore::open_or_initialize(state_secret, &config, store_config)
                .map_err(DaemonError::Persistence)?;
        Self::new_with_loaded_state(signer_backend, config, state, Some(state_store))
    }

    fn new_with_loaded_state(
        signer_backend: B,
        config: DaemonConfig,
        state: PersistedDaemonState,
        state_store: Option<EncryptedStateStore>,
    ) -> Result<Self, DaemonError> {
        let original_state = state.clone();
        let mut state = prepare_loaded_state(state)?;
        normalize_disabled_policy_set_attachments(&mut state);
        Self::scrub_persisted_ephemeral_state(&config, &mut state, OffsetDateTime::now_utc())?;
        validate_loaded_state(&state)?;
        signer_backend
            .restore_persistable_key_material(&state.software_signer_private_keys)
            .map_err(DaemonError::Signer)?;
        if state != original_state {
            if let Some(store) = &state_store {
                store.save(&state).map_err(DaemonError::Persistence)?;
            }
        }
        Ok(Self {
            signer_backend,
            policy_engine: PolicyEngine,
            config,
            instance_id: Uuid::new_v4(),
            admin_credentials: Arc::new(RwLock::new(state.admin_credentials)),
            admin_auth: Mutex::new(AdminAuthState::default()),
            policies: Arc::new(RwLock::new(state.policies)),
            vault_keys: Arc::new(RwLock::new(state.vault_keys)),
            agent_keys: Arc::new(RwLock::new(state.agent_keys)),
            agent_auth_tokens: Arc::new(RwLock::new(state.agent_auth_tokens)),
            replay_ids: Arc::new(RwLock::new(state.replay_ids)),
            nonce_heads: Arc::new(RwLock::new(state.nonce_heads)),
            reusable_nonce_gaps: Arc::new(RwLock::new(state.reusable_nonce_gaps)),
            nonce_reservations: Arc::new(RwLock::new(state.nonce_reservations)),
            spend_log: Arc::new(RwLock::new(state.spend_log)),
            manual_approval_requests: Arc::new(RwLock::new(state.manual_approval_requests)),
            recoverable_agent_results: Arc::new(RwLock::new(state.recoverable_agent_results)),
            tempo_channels: Arc::new(RwLock::new(state.tempo_channels)),
            signed_broadcasts: Arc::new(RwLock::new(state.signed_broadcasts)),
            state_store,
            signing_guard: tokio::sync::Mutex::new(()),
            state_persist_guard: tokio::sync::Mutex::new(()),
            backup_kdf_guard: tokio::sync::Mutex::new(()),
        })
    }
}

/// In-process callers use [`RequestContext::in_process`]; transports must go
/// through [`InMemoryDaemon::handle_rpc`] with the peer's context instead.
#[async_trait]
impl<B> KeyManagerDaemonApi for InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    async fn enroll_admin_credential(
        &self,
        public_key_sec1_hex: String,
        label: String,
    ) -> Result<AdminCredential, DaemonError> {
        self.enroll_admin_credential_impl(&IN_PROCESS, &public_key_sec1_hex, &label)
            .await
    }

    async fn list_admin_credentials(
        &self,
        auth: &AdminAuth,
    ) -> Result<Vec<AdminCredential>, DaemonError> {
        self.list_admin_credentials_impl(&IN_PROCESS, auth)
    }

    async fn revoke_admin_credential(
        &self,
        auth: &AdminAuth,
        credential_id: Uuid,
    ) -> Result<(), DaemonError> {
        self.revoke_admin_credential_impl(&IN_PROCESS, auth, credential_id)
            .await
    }

    async fn begin_admin_challenge(
        &self,
        credential_id: Uuid,
        purpose: String,
    ) -> Result<AdminChallenge, DaemonError> {
        self.begin_admin_challenge_impl(&IN_PROCESS, credential_id, &purpose)
    }

    async fn complete_admin_challenge(
        &self,
        challenge_id: Uuid,
        signature_der_hex: String,
    ) -> Result<AdminLease, DaemonError> {
        self.complete_admin_challenge_impl(&IN_PROCESS, challenge_id, &signature_der_hex)
    }

    async fn revoke_admin_lease(
        &self,
        auth: &AdminAuth,
        lease_id: Uuid,
    ) -> Result<(), DaemonError> {
        self.revoke_admin_lease_impl(&IN_PROCESS, auth, lease_id)
    }

    async fn add_policy(
        &self,
        auth: &AdminAuth,
        policy: SpendingPolicy,
    ) -> Result<(), DaemonError> {
        self.add_policy_impl(&IN_PROCESS, auth, policy).await
    }

    async fn list_policies(&self, auth: &AdminAuth) -> Result<Vec<SpendingPolicy>, DaemonError> {
        self.list_policies_impl(&IN_PROCESS, auth).await
    }

    async fn list_policy_summaries(
        &self,
        auth: &AdminAuth,
    ) -> Result<Vec<PolicySummary>, DaemonError> {
        self.list_policy_summaries_impl(&IN_PROCESS, auth).await
    }

    async fn disable_policy(&self, auth: &AdminAuth, policy_id: Uuid) -> Result<(), DaemonError> {
        self.disable_policy_impl(&IN_PROCESS, auth, policy_id).await
    }

    async fn create_vault_key(
        &self,
        auth: &AdminAuth,
        request: KeyCreateRequest,
    ) -> Result<VaultKey, DaemonError> {
        self.create_vault_key_impl(&IN_PROCESS, auth, request).await
    }

    async fn solana_public_key_hex(
        &self,
        auth: &AdminAuth,
        vault_key_id: Uuid,
    ) -> Result<String, DaemonError> {
        self.solana_public_key_hex_impl(&IN_PROCESS, auth, vault_key_id)
            .await
    }

    async fn create_agent_key(
        &self,
        auth: &AdminAuth,
        vault_key_id: Uuid,
        attachment: PolicyAttachment,
    ) -> Result<AgentCredentials, DaemonError> {
        self.create_agent_key_impl(&IN_PROCESS, auth, vault_key_id, attachment)
            .await
    }

    async fn refresh_agent_key(
        &self,
        auth: &AdminAuth,
        agent_key_id: Uuid,
        vault_key_id: Uuid,
        attachment: PolicyAttachment,
    ) -> Result<AgentCredentials, DaemonError> {
        self.refresh_agent_key_impl(&IN_PROCESS, auth, agent_key_id, vault_key_id, attachment)
            .await
    }

    async fn rotate_agent_auth_token(
        &self,
        auth: &AdminAuth,
        agent_key_id: Uuid,
    ) -> Result<String, DaemonError> {
        self.rotate_agent_auth_token_impl(&IN_PROCESS, auth, agent_key_id)
            .await
    }

    async fn revoke_agent_key(
        &self,
        auth: &AdminAuth,
        agent_key_id: Uuid,
    ) -> Result<(), DaemonError> {
        self.revoke_agent_key_impl(&IN_PROCESS, auth, agent_key_id)
            .await
    }

    async fn bootstrap_wallet(
        &self,
        auth: &AdminAuth,
        mode: WalletBootstrapMode,
        limits: Vec<SpendingLimit>,
    ) -> Result<WalletBootstrap, DaemonError> {
        self.bootstrap_wallet_impl(&IN_PROCESS, auth, mode, limits)
            .await
    }

    async fn list_wallets(&self, auth: &AdminAuth) -> Result<Vec<WalletInfo>, DaemonError> {
        self.list_wallets_impl(&IN_PROCESS, auth)
    }

    async fn rename_wallet(
        &self,
        auth: &AdminAuth,
        vault_key_id: Uuid,
        name: Option<String>,
    ) -> Result<WalletInfo, DaemonError> {
        self.rename_wallet_impl(&IN_PROCESS, auth, vault_key_id, name)
            .await
    }

    async fn export_wallet_backup(
        &self,
        auth: &AdminAuth,
        vault_key_id: Option<Uuid>,
        passphrase: Zeroizing<String>,
    ) -> Result<WalletBackupExport, DaemonError> {
        self.export_wallet_backup_impl(&IN_PROCESS, auth, vault_key_id, passphrase)
            .await
    }

    async fn verify_wallet_backup(
        &self,
        auth: &AdminAuth,
        backup_json: String,
        passphrase: Zeroizing<String>,
    ) -> Result<WalletBackupSummary, DaemonError> {
        self.verify_wallet_backup_impl(&IN_PROCESS, auth, backup_json, passphrase)
            .await
    }

    async fn list_spending_limits(
        &self,
        auth: &AdminAuth,
        agent_key_id: Uuid,
    ) -> Result<SpendingLimitsReport, DaemonError> {
        self.list_spending_limits_impl(&IN_PROCESS, auth, agent_key_id)
    }

    async fn set_spending_limits(
        &self,
        auth: &AdminAuth,
        agent_key_id: Uuid,
        limits: Vec<SpendingLimit>,
    ) -> Result<SpendingLimitsReport, DaemonError> {
        self.set_spending_limits_impl(&IN_PROCESS, auth, agent_key_id, limits)
            .await
    }

    async fn list_manual_approval_requests(
        &self,
        auth: &AdminAuth,
    ) -> Result<Vec<ManualApprovalRequest>, DaemonError> {
        self.list_manual_approval_requests_impl(&IN_PROCESS, auth)
            .await
    }

    async fn decide_manual_approval_request(
        &self,
        auth: &AdminAuth,
        approval_request_id: Uuid,
        decision: ManualApprovalDecision,
        rejection_reason: Option<String>,
    ) -> Result<ManualApprovalRequest, DaemonError> {
        self.decide_manual_approval_request_impl(
            &IN_PROCESS,
            auth,
            approval_request_id,
            decision,
            rejection_reason,
        )
        .await
    }

    async fn authenticate_agent(&self, auth: &AgentAuth) -> Result<AgentIdentity, DaemonError> {
        self.authenticate_agent_impl(auth)
    }

    async fn evaluate_for_agent(
        &self,
        request: SignRequest,
    ) -> Result<PolicyEvaluation, DaemonError> {
        self.evaluate_for_agent_impl(request).await
    }

    async fn explain_for_agent(
        &self,
        request: SignRequest,
    ) -> Result<PolicyExplanation, DaemonError> {
        self.explain_for_agent_impl(request).await
    }

    async fn reserve_nonce(
        &self,
        request: NonceReservationRequest,
    ) -> Result<NonceReservation, DaemonError> {
        self.reserve_nonce_impl(request).await
    }

    async fn release_nonce(&self, request: NonceReleaseRequest) -> Result<(), DaemonError> {
        self.release_nonce_impl(request).await
    }

    async fn release_signed_nonce(
        &self,
        request: SignedNonceReleaseRequest,
    ) -> Result<(), DaemonError> {
        self.release_signed_nonce_impl(request).await
    }

    async fn sign_for_agent(&self, request: SignRequest) -> Result<Signature, DaemonError> {
        self.sign_for_agent_impl(request).await
    }
}
