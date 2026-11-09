//! [`DaemonRpcResponse`]: the success body of every method.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use zeroize::Zeroize;

use crate::auth::{AdminChallenge, AdminCredential, AdminLease, AgentCredentials};
use crate::rpc::activity::AgentActivityReport;
use crate::rpc::limits::SpendingLimitsReport;
use crate::rpc::wallet::{WalletBackupExport, WalletBackupSummary, WalletBootstrap, WalletInfo};
use crate::types::{
    AgentIdentity, AgentPolicySummary, ManualApprovalRequest, NonceReservation, PolicyEvaluation,
    PolicyExplanation, PolicySummary, Signature, SpendingPolicy, VaultKey,
};
use crate::HelloResponse;

/// Successful result of an RPC call, as carried in
/// [`WireResponse::body_json`](crate::WireResponse::body_json) when `ok` is `true`.
///
/// JSON: `{"type": "<Variant>", "data": <payload>}`; `Unit` is `{"type": "Unit"}`.
/// Each method documents which variant it returns; clients should reject any
/// other variant as a protocol error.
///
/// `Debug` redacts lease secrets and agent tokens.
#[derive(Clone, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "type", content = "data")]
pub enum DaemonRpcResponse {
    /// No return data (mutations such as `AddPolicy` or `RevokeAgentKey`).
    Unit,
    /// `Hello`: daemon version and capabilities.
    Hello(HelloResponse),
    /// `EnrollAdminCredential`: the enrolled credential.
    AdminCredential(AdminCredential),
    /// `ListAdminCredentials`: enrolled credentials, oldest first.
    AdminCredentials(Vec<AdminCredential>),
    /// `BeginAdminChallenge`: the challenge to sign.
    AdminChallenge(AdminChallenge),
    /// `CompleteAdminChallenge`: the issued lease (contains the lease secret).
    AdminLease(AdminLease),
    /// `ListPolicies`: every policy, ordered by priority.
    Policies(Vec<SpendingPolicy>),
    /// `ListPolicySummaries`: id and enabled state of every policy.
    PolicySummaries(Vec<PolicySummary>),
    /// `AuthenticateAgent`: the agent's identity and wallet addresses.
    AgentIdentity(Box<AgentIdentity>),
    /// `AgentPolicySummary`: the enabled policies that govern the agent.
    AgentPolicySummary(AgentPolicySummary),
    /// `EvaluateForAgent`: the policies that allowed the request.
    PolicyEvaluation(PolicyEvaluation),
    /// `ExplainForAgent`: the full allow/deny explanation.
    PolicyExplanation(PolicyExplanation),
    /// `CreateVaultKey`: public metadata of the new key.
    VaultKey(VaultKey),
    /// `CreateAgentKey` / `RefreshAgentKey`: agent metadata and its new bearer token.
    AgentCredentials(AgentCredentials),
    /// `SolanaPublicKey`: the Ed25519 public key, 64 lowercase hex chars without `0x`.
    PublicKey(String),
    /// `RotateAgentAuthToken`: the new bearer token.
    AuthToken(String),
    /// `BootstrapWallet`: the wallet, the agent key with its new token, and its limits.
    WalletBootstrap(Box<WalletBootstrap>),
    /// `ListWallets`: every wallet on the machine, oldest first.
    Wallets(Vec<WalletInfo>),
    /// `RenameWallet` (API 1.1): the renamed wallet.
    Wallet(WalletInfo),
    /// `AgentActivity` (API 1.1): the agent's recent spends and approvals.
    AgentActivity(AgentActivityReport),
    /// `ExportWalletBackup`: the encrypted backup document.
    WalletBackup(WalletBackupExport),
    /// `VerifyWalletBackup`: what the backup holds.
    WalletBackupSummary(WalletBackupSummary),
    /// `ListSpendingLimits` / `SetSpendingLimits`: the agent's limits with usage.
    SpendingLimits(SpendingLimitsReport),
    /// `ListManualApprovalRequests`: retained requests, newest first.
    ManualApprovalRequests(Vec<ManualApprovalRequest>),
    /// `DecideManualApprovalRequest`: the updated request.
    ManualApprovalRequest(Box<ManualApprovalRequest>),
    /// `ReserveNonce`: the reservation.
    NonceReservation(NonceReservation),
    /// `SignForAgent`: the signature (and signed transaction, when applicable).
    Signature(Signature),
}

impl DaemonRpcResponse {
    /// Wipes secret material (lease secrets, agent tokens) in place.
    pub fn zeroize_secrets(&mut self) {
        match self {
            Self::AdminLease(lease) => lease.zeroize_secrets(),
            Self::AgentCredentials(credentials) => credentials.zeroize_secrets(),
            Self::WalletBootstrap(bootstrap) => bootstrap.zeroize_secrets(),
            Self::AuthToken(token) => token.zeroize(),
            _ => {}
        }
    }
}

impl std::fmt::Debug for DaemonRpcResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unit => f.write_str("Unit"),
            Self::Hello(hello) => f.debug_tuple("Hello").field(hello).finish(),
            Self::AdminCredential(credential) => {
                f.debug_tuple("AdminCredential").field(credential).finish()
            }
            Self::AdminCredentials(credentials) => f
                .debug_tuple("AdminCredentials")
                .field(credentials)
                .finish(),
            Self::AdminChallenge(challenge) => {
                f.debug_tuple("AdminChallenge").field(challenge).finish()
            }
            Self::AdminLease(lease) => f.debug_tuple("AdminLease").field(lease).finish(),
            Self::Policies(policies) => f.debug_tuple("Policies").field(policies).finish(),
            Self::PolicySummaries(summaries) => {
                f.debug_tuple("PolicySummaries").field(summaries).finish()
            }
            Self::AgentIdentity(identity) => {
                f.debug_tuple("AgentIdentity").field(identity).finish()
            }
            Self::AgentPolicySummary(summary) => {
                f.debug_tuple("AgentPolicySummary").field(summary).finish()
            }
            Self::PolicyEvaluation(evaluation) => {
                f.debug_tuple("PolicyEvaluation").field(evaluation).finish()
            }
            Self::PolicyExplanation(explanation) => f
                .debug_tuple("PolicyExplanation")
                .field(explanation)
                .finish(),
            Self::VaultKey(key) => f.debug_tuple("VaultKey").field(key).finish(),
            Self::AgentCredentials(credentials) => f
                .debug_tuple("AgentCredentials")
                .field(credentials)
                .finish(),
            Self::PublicKey(public_key) => f.debug_tuple("PublicKey").field(public_key).finish(),
            Self::AuthToken(_) => f.debug_tuple("AuthToken").field(&"<redacted>").finish(),
            Self::WalletBootstrap(bootstrap) => {
                f.debug_tuple("WalletBootstrap").field(bootstrap).finish()
            }
            Self::Wallets(wallets) => f.debug_tuple("Wallets").field(wallets).finish(),
            Self::Wallet(wallet) => f.debug_tuple("Wallet").field(wallet).finish(),
            Self::AgentActivity(report) => f.debug_tuple("AgentActivity").field(report).finish(),
            Self::WalletBackup(backup) => f.debug_tuple("WalletBackup").field(backup).finish(),
            Self::WalletBackupSummary(summary) => {
                f.debug_tuple("WalletBackupSummary").field(summary).finish()
            }
            Self::SpendingLimits(report) => f.debug_tuple("SpendingLimits").field(report).finish(),
            Self::ManualApprovalRequests(requests) => f
                .debug_tuple("ManualApprovalRequests")
                .field(requests)
                .finish(),
            Self::ManualApprovalRequest(request) => f
                .debug_tuple("ManualApprovalRequest")
                .field(request)
                .finish(),
            Self::NonceReservation(reservation) => f
                .debug_tuple("NonceReservation")
                .field(reservation)
                .finish(),
            Self::Signature(signature) => f.debug_tuple("Signature").field(signature).finish(),
        }
    }
}
