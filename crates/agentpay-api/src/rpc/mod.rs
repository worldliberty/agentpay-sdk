//! The RPC methods: [`DaemonRpcRequest`] and [`DaemonRpcResponse`].
//!
//! A request is an adjacently tagged JSON object, `{"method": "<Method>",
//! "params": {...}}` (`Hello` has no `params`). A successful response is
//! `{"type": "<Variant>", "data": ...}` (`Unit` has no `data`). Each method's
//! parameter struct documents who may call it, its authentication, side
//! effects, idempotency, errors, and a request/response example; the examples
//! are the fixtures under `crates/agentpay-api/fixtures/rpc/`, which the test
//! suite round-trips through these types.
//!
//! | Area | Methods |
//! |---|---|
//! | Handshake | `Hello` |
//! | [Admin auth](admin) | `EnrollAdminCredential`, `ListAdminCredentials`, `RevokeAdminCredential`, `BeginAdminChallenge`, `CompleteAdminChallenge`, `RevokeAdminLease` |
//! | [Policies](policies) | `AddPolicy`, `ListPolicies`, `ListPolicySummaries`, `DisablePolicy` |
//! | [Keys](keys) | `CreateVaultKey`, `CreateAgentKey`, `RefreshAgentKey`, `SolanaPublicKey`, `RotateAgentAuthToken`, `RevokeAgentKey` |
//! | [Wallet](wallet) | `BootstrapWallet`, `ListWallets`, `RenameWallet`, `ExportWalletBackup`, `VerifyWalletBackup` |
//! | [Spending limits](limits) | `ListSpendingLimits`, `SetSpendingLimits` |
//! | [Manual approvals](approvals) | `ListManualApprovalRequests`, `DecideManualApprovalRequest` |
//! | [Agent](agent) | `AuthenticateAgent`, `AgentPolicySummary`, `EvaluateForAgent`, `ExplainForAgent`, `ReserveNonce`, `ReleaseNonce`, `ReleaseSignedNonce`, `SignForAgent`, [`AgentActivity`](activity) |

pub mod activity;
pub mod admin;
pub mod agent;
pub mod approvals;
pub mod keys;
pub mod limits;
pub mod policies;
mod response;
pub mod wallet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub use activity::{AgentActivityParams, AgentActivityReport, AgentSpend};
pub use admin::{
    BeginAdminChallengeParams, CompleteAdminChallengeParams, EnrollAdminCredentialParams,
    ListAdminCredentialsParams, RevokeAdminCredentialParams, RevokeAdminLeaseParams,
};
pub use agent::{
    AgentPolicySummaryParams, AuthenticateAgentParams, EvaluateForAgentParams,
    ExplainForAgentParams, ReleaseNonceParams, ReleaseSignedNonceParams, ReserveNonceParams,
    SignForAgentParams,
};
pub use approvals::{DecideManualApprovalRequestParams, ListManualApprovalRequestsParams};
pub use keys::{
    CreateAgentKeyParams, CreateVaultKeyParams, RefreshAgentKeyParams, RevokeAgentKeyParams,
    RotateAgentAuthTokenParams, SolanaPublicKeyParams,
};
pub use limits::{
    ListSpendingLimitsParams, SetSpendingLimitsParams, SpendingLimit, SpendingLimitStatus,
    SpendingLimitsReport, SpendingUsage,
};
pub use policies::{
    AddPolicyParams, DisablePolicyParams, ListPoliciesParams, ListPolicySummariesParams,
};
pub use response::DaemonRpcResponse;
pub use wallet::{
    BootstrapWalletParams, ExportWalletBackupParams, ListWalletsParams, RenameWalletParams,
    VerifyWalletBackupParams, WalletBackupExport, WalletBackupSummary, WalletBootstrap,
    WalletBootstrapMode, WalletBootstrapOutcome, WalletInfo,
};

use crate::auth::AccessLevel;

/// One RPC call, as carried in [`WireRequest::body_json`](crate::WireRequest::body_json).
///
/// `Debug` is derived: every secret-bearing field type redacts itself.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "method", content = "params")]
pub enum DaemonRpcRequest {
    /// Handshake: returns the daemon's API version, release, and capabilities.
    ///
    /// | | |
    /// |---|---|
    /// | Access | any allowlisted peer ([`AccessLevel::Any`]) |
    /// | Auth | none |
    /// | Response | [`DaemonRpcResponse::Hello`] |
    /// | Side effects | none; idempotent |
    /// | Errors | none |
    ///
    /// Clients should call it first on a new daemon and refuse to continue when
    /// the major version differs from theirs
    /// ([`ApiVersion::is_compatible_with`](crate::ApiVersion::is_compatible_with)).
    /// Daemons from AgentPay releases before 1.0 predate this contract: they
    /// do not know this method and close the connection without a response.
    ///
    /// Request:
    ///
    /// ```json
    #[doc = include_str!("../../fixtures/rpc/Hello.request.json")]
    /// ```
    ///
    /// Response:
    ///
    /// ```json
    #[doc = include_str!("../../fixtures/rpc/Hello.response.json")]
    /// ```
    Hello,
    /// Enroll a P-256 admin credential. See [`EnrollAdminCredentialParams`].
    EnrollAdminCredential(EnrollAdminCredentialParams),
    /// List enrolled admin credentials. See [`ListAdminCredentialsParams`].
    ListAdminCredentials(ListAdminCredentialsParams),
    /// Revoke an admin credential. See [`RevokeAdminCredentialParams`].
    RevokeAdminCredential(RevokeAdminCredentialParams),
    /// Issue an admin challenge. See [`BeginAdminChallengeParams`].
    BeginAdminChallenge(BeginAdminChallengeParams),
    /// Exchange a signed challenge for a lease. See [`CompleteAdminChallengeParams`].
    CompleteAdminChallenge(CompleteAdminChallengeParams),
    /// Revoke an admin lease. See [`RevokeAdminLeaseParams`].
    RevokeAdminLease(RevokeAdminLeaseParams),
    /// Add a spending policy. See [`AddPolicyParams`].
    AddPolicy(AddPolicyParams),
    /// List policies. See [`ListPoliciesParams`].
    ListPolicies(ListPoliciesParams),
    /// List compact policy metadata. See [`ListPolicySummariesParams`].
    ListPolicySummaries(ListPolicySummariesParams),
    /// Disable a policy. See [`DisablePolicyParams`].
    DisablePolicy(DisablePolicyParams),
    /// Create a vault key. See [`CreateVaultKeyParams`].
    CreateVaultKey(CreateVaultKeyParams),
    /// Create an agent key. See [`CreateAgentKeyParams`].
    CreateAgentKey(CreateAgentKeyParams),
    /// Re-attach policies and rotate an agent key's token. See [`RefreshAgentKeyParams`].
    RefreshAgentKey(RefreshAgentKeyParams),
    /// Derive a vault key's Solana public key. See [`SolanaPublicKeyParams`].
    SolanaPublicKey(SolanaPublicKeyParams),
    /// Rotate an agent auth token. See [`RotateAgentAuthTokenParams`].
    RotateAgentAuthToken(RotateAgentAuthTokenParams),
    /// Revoke an agent key. See [`RevokeAgentKeyParams`].
    RevokeAgentKey(RevokeAgentKeyParams),
    /// Set up the wallet, its agent key, and its limits. See [`BootstrapWalletParams`].
    BootstrapWallet(BootstrapWalletParams),
    /// List the wallets on this machine. See [`ListWalletsParams`].
    ListWallets(ListWalletsParams),
    /// Export an encrypted wallet backup. See [`ExportWalletBackupParams`].
    ExportWalletBackup(ExportWalletBackupParams),
    /// Check an encrypted wallet backup. See [`VerifyWalletBackupParams`].
    VerifyWalletBackup(VerifyWalletBackupParams),
    /// List an agent's spending limits and usage. See [`ListSpendingLimitsParams`].
    ListSpendingLimits(ListSpendingLimitsParams),
    /// Replace an agent's spending limits. See [`SetSpendingLimitsParams`].
    SetSpendingLimits(SetSpendingLimitsParams),
    /// List manual approval requests. See [`ListManualApprovalRequestsParams`].
    ListManualApprovalRequests(ListManualApprovalRequestsParams),
    /// Approve or reject a manual approval request. See [`DecideManualApprovalRequestParams`].
    DecideManualApprovalRequest(DecideManualApprovalRequestParams),
    /// Verify an agent token and return the agent's identity. See [`AuthenticateAgentParams`].
    AuthenticateAgent(AuthenticateAgentParams),
    /// Summarize the policies that govern the agent. See [`AgentPolicySummaryParams`].
    AgentPolicySummary(AgentPolicySummaryParams),
    /// Evaluate policies without signing. See [`EvaluateForAgentParams`].
    EvaluateForAgent(EvaluateForAgentParams),
    /// Explain the policy decision without signing. See [`ExplainForAgentParams`].
    ExplainForAgent(ExplainForAgentParams),
    /// Reserve a broadcast nonce. See [`ReserveNonceParams`].
    ReserveNonce(ReserveNonceParams),
    /// Release a nonce reservation. See [`ReleaseNonceParams`].
    ReleaseNonce(ReleaseNonceParams),
    /// Return the nonce of a signed but never-sent transaction. See [`ReleaseSignedNonceParams`].
    ReleaseSignedNonce(ReleaseSignedNonceParams),
    /// Evaluate policies and sign. See [`SignForAgentParams`].
    SignForAgent(SignForAgentParams),
    /// Name or unname a wallet (API 1.1). See [`RenameWalletParams`].
    RenameWallet(RenameWalletParams),
    /// The agent's own recent spends and approval requests (API 1.1). See
    /// [`AgentActivityParams`].
    AgentActivity(AgentActivityParams),
}

impl DaemonRpcRequest {
    /// Every method name, in declaration order. Each is also a capability
    /// advertised by `Hello`.
    pub const METHOD_NAMES: &'static [&'static str] = &[
        "Hello",
        "EnrollAdminCredential",
        "ListAdminCredentials",
        "RevokeAdminCredential",
        "BeginAdminChallenge",
        "CompleteAdminChallenge",
        "RevokeAdminLease",
        "AddPolicy",
        "ListPolicies",
        "ListPolicySummaries",
        "DisablePolicy",
        "CreateVaultKey",
        "CreateAgentKey",
        "RefreshAgentKey",
        "SolanaPublicKey",
        "RotateAgentAuthToken",
        "RevokeAgentKey",
        "BootstrapWallet",
        "ListWallets",
        "ExportWalletBackup",
        "VerifyWalletBackup",
        "ListSpendingLimits",
        "SetSpendingLimits",
        "ListManualApprovalRequests",
        "DecideManualApprovalRequest",
        "AuthenticateAgent",
        "AgentPolicySummary",
        "EvaluateForAgent",
        "ExplainForAgent",
        "ReserveNonce",
        "ReleaseNonce",
        "ReleaseSignedNonce",
        "SignForAgent",
        "RenameWallet",
        "AgentActivity",
    ];

    /// Returns the wire name of this request's method (its `method` tag).
    #[must_use]
    pub fn method_name(&self) -> &'static str {
        match self {
            Self::Hello => "Hello",
            Self::EnrollAdminCredential(_) => "EnrollAdminCredential",
            Self::ListAdminCredentials(_) => "ListAdminCredentials",
            Self::RevokeAdminCredential(_) => "RevokeAdminCredential",
            Self::BeginAdminChallenge(_) => "BeginAdminChallenge",
            Self::CompleteAdminChallenge(_) => "CompleteAdminChallenge",
            Self::RevokeAdminLease(_) => "RevokeAdminLease",
            Self::AddPolicy(_) => "AddPolicy",
            Self::ListPolicies(_) => "ListPolicies",
            Self::ListPolicySummaries(_) => "ListPolicySummaries",
            Self::DisablePolicy(_) => "DisablePolicy",
            Self::CreateVaultKey(_) => "CreateVaultKey",
            Self::CreateAgentKey(_) => "CreateAgentKey",
            Self::RefreshAgentKey(_) => "RefreshAgentKey",
            Self::SolanaPublicKey(_) => "SolanaPublicKey",
            Self::RotateAgentAuthToken(_) => "RotateAgentAuthToken",
            Self::RevokeAgentKey(_) => "RevokeAgentKey",
            Self::BootstrapWallet(_) => "BootstrapWallet",
            Self::ListWallets(_) => "ListWallets",
            Self::ExportWalletBackup(_) => "ExportWalletBackup",
            Self::VerifyWalletBackup(_) => "VerifyWalletBackup",
            Self::ListSpendingLimits(_) => "ListSpendingLimits",
            Self::SetSpendingLimits(_) => "SetSpendingLimits",
            Self::ListManualApprovalRequests(_) => "ListManualApprovalRequests",
            Self::DecideManualApprovalRequest(_) => "DecideManualApprovalRequest",
            Self::AuthenticateAgent(_) => "AuthenticateAgent",
            Self::AgentPolicySummary(_) => "AgentPolicySummary",
            Self::EvaluateForAgent(_) => "EvaluateForAgent",
            Self::ExplainForAgent(_) => "ExplainForAgent",
            Self::ReserveNonce(_) => "ReserveNonce",
            Self::ReleaseNonce(_) => "ReleaseNonce",
            Self::ReleaseSignedNonce(_) => "ReleaseSignedNonce",
            Self::SignForAgent(_) => "SignForAgent",
            Self::RenameWallet(_) => "RenameWallet",
            Self::AgentActivity(_) => "AgentActivity",
        }
    }

    /// Returns the peer allowlist that governs this request.
    #[must_use]
    pub fn access_level(&self) -> AccessLevel {
        match self {
            Self::Hello => AccessLevel::Any,
            Self::EnrollAdminCredential(_)
            | Self::ListAdminCredentials(_)
            | Self::RevokeAdminCredential(_)
            | Self::BeginAdminChallenge(_)
            | Self::CompleteAdminChallenge(_)
            | Self::RevokeAdminLease(_)
            | Self::AddPolicy(_)
            | Self::ListPolicies(_)
            | Self::ListPolicySummaries(_)
            | Self::DisablePolicy(_)
            | Self::CreateVaultKey(_)
            | Self::CreateAgentKey(_)
            | Self::RefreshAgentKey(_)
            | Self::SolanaPublicKey(_)
            | Self::RotateAgentAuthToken(_)
            | Self::RevokeAgentKey(_)
            | Self::BootstrapWallet(_)
            | Self::ListWallets(_)
            | Self::ExportWalletBackup(_)
            | Self::VerifyWalletBackup(_)
            | Self::ListSpendingLimits(_)
            | Self::SetSpendingLimits(_)
            | Self::ListManualApprovalRequests(_)
            | Self::DecideManualApprovalRequest(_)
            | Self::RenameWallet(_) => AccessLevel::Admin,
            Self::AuthenticateAgent(_)
            | Self::AgentPolicySummary(_)
            | Self::EvaluateForAgent(_)
            | Self::ExplainForAgent(_)
            | Self::ReserveNonce(_)
            | Self::ReleaseNonce(_)
            | Self::ReleaseSignedNonce(_)
            | Self::SignForAgent(_)
            | Self::AgentActivity(_) => AccessLevel::Agent,
        }
    }

    /// Wipes secret material (lease secrets, agent tokens, imported keys) in place.
    pub fn zeroize_secrets(&mut self) {
        match self {
            Self::Hello
            | Self::EnrollAdminCredential(_)
            | Self::BeginAdminChallenge(_)
            | Self::CompleteAdminChallenge(_) => {}
            Self::CreateVaultKey(params) => params.zeroize_secrets(),
            Self::ExportWalletBackup(params) => params.zeroize_secrets(),
            Self::VerifyWalletBackup(params) => params.zeroize_secrets(),
            Self::BootstrapWallet(BootstrapWalletParams { auth, mode, .. }) => {
                auth.zeroize_secrets();
                mode.zeroize_secrets();
            }
            Self::ListAdminCredentials(ListAdminCredentialsParams { auth })
            | Self::RevokeAdminCredential(RevokeAdminCredentialParams { auth, .. })
            | Self::RevokeAdminLease(RevokeAdminLeaseParams { auth, .. })
            | Self::AddPolicy(AddPolicyParams { auth, .. })
            | Self::ListPolicies(ListPoliciesParams { auth })
            | Self::ListPolicySummaries(ListPolicySummariesParams { auth })
            | Self::DisablePolicy(DisablePolicyParams { auth, .. })
            | Self::CreateAgentKey(CreateAgentKeyParams { auth, .. })
            | Self::RefreshAgentKey(RefreshAgentKeyParams { auth, .. })
            | Self::SolanaPublicKey(SolanaPublicKeyParams { auth, .. })
            | Self::RotateAgentAuthToken(RotateAgentAuthTokenParams { auth, .. })
            | Self::RevokeAgentKey(RevokeAgentKeyParams { auth, .. })
            | Self::ListWallets(ListWalletsParams { auth })
            | Self::RenameWallet(RenameWalletParams { auth, .. })
            | Self::ListSpendingLimits(ListSpendingLimitsParams { auth, .. })
            | Self::SetSpendingLimits(SetSpendingLimitsParams { auth, .. })
            | Self::ListManualApprovalRequests(ListManualApprovalRequestsParams { auth })
            | Self::DecideManualApprovalRequest(DecideManualApprovalRequestParams {
                auth, ..
            }) => auth.zeroize_secrets(),
            Self::AuthenticateAgent(AuthenticateAgentParams { auth })
            | Self::AgentPolicySummary(AgentPolicySummaryParams { auth })
            | Self::AgentActivity(AgentActivityParams { auth, .. }) => auth.zeroize_secrets(),
            Self::EvaluateForAgent(EvaluateForAgentParams { request })
            | Self::ExplainForAgent(ExplainForAgentParams { request })
            | Self::SignForAgent(SignForAgentParams { request }) => request.zeroize_secrets(),
            Self::ReserveNonce(ReserveNonceParams { request }) => request.zeroize_secrets(),
            Self::ReleaseNonce(ReleaseNonceParams { request }) => request.zeroize_secrets(),
            Self::ReleaseSignedNonce(ReleaseSignedNonceParams { request }) => {
                request.zeroize_secrets();
            }
        }
    }
}
