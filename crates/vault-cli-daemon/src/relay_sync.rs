use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use ::time::format_description::well_known::Rfc3339;
use ::time::OffsetDateTime;
use anyhow::{Context, Result};
use reqwest::header::CONTENT_TYPE;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tokio::time::{self, MissedTickBehavior};
use uuid::Uuid;
use vault_daemon::{DaemonError, InMemoryDaemon, RelayRegistrationSnapshot};
use vault_domain::{
    manual_approval_capability_hash, manual_approval_capability_token, AgentAction, AssetId,
    EntityScope, ManualApprovalDecision, ManualApprovalStatus, PolicyType, SpendingPolicy,
};
use vault_signer::VaultSignerBackend;

const DEFAULT_RELAY_POLL_LIMIT: u32 = 25;
const DEFAULT_RELAY_LEASE_SECONDS: u32 = 30;
const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
const RELAY_DAEMON_TOKEN_ENV: &str = "AGENTPAY_RELAY_DAEMON_TOKEN";
const RELAY_DAEMON_TOKEN_FILE_ENV: &str = "AGENTPAY_RELAY_DAEMON_TOKEN_FILE";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RelayDaemonProfilePayload {
    daemon_id: String,
    daemon_public_key: String,
    ethereum_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    last_seen_at: String,
    registered_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_url: Option<String>,
    signer_backend: String,
    status: &'static str,
    updated_at: String,
    version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RelayPolicyPayload {
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount_max_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount_min_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tx_count: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_fee_per_gas_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_priority_fee_per_gas_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_calldata_bytes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_gas_spend_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_id: Option<u64>,
    destination: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<BTreeMap<String, String>>,
    policy_id: String,
    requires_manual_approval: bool,
    scope: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_address: Option<String>,
    updated_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RelayAgentKeyPayload {
    agent_key_id: String,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<BTreeMap<String, String>>,
    status: &'static str,
    updated_at: String,
}

#[derive(Debug, Default)]
struct RelayPolicyLimits {
    amount_max_wei: Option<String>,
    max_tx_count: Option<String>,
    max_fee_per_gas_wei: Option<String>,
    max_priority_fee_per_gas_wei: Option<String>,
    max_calldata_bytes: Option<String>,
    max_gas_spend_wei: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RelayApprovalRequestPayload {
    agent_key_id: String,
    amount_wei: String,
    approval_request_id: String,
    chain_id: u64,
    destination: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    requested_at: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_address: Option<String>,
    transaction_type: String,
    updated_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RelayRegisterRequest {
    daemon: RelayDaemonProfilePayload,
    policies: Vec<RelayPolicyPayload>,
    agent_keys: Vec<RelayAgentKeyPayload>,
    approval_requests: Vec<RelayApprovalRequestPayload>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RelayPollRequest<'a> {
    daemon_id: &'a str,
    lease_seconds: u32,
    limit: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelayEncryptedPayload {
    algorithm: String,
    ciphertext_base64: String,
    encapsulated_key_base64: String,
    nonce_base64: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelayEncryptedUpdateRecord {
    claim_token: Option<String>,
    daemon_id: String,
    payload: RelayEncryptedPayload,
    target_approval_request_id: Option<String>,
    r#type: String,
    update_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelayPollResponse {
    items: Vec<RelayEncryptedUpdateRecord>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RelayFeedbackRequest<'a> {
    claim_token: &'a str,
    daemon_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    status: &'a str,
    update_id: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelayManualApprovalUpdatePayload {
    approval_id: String,
    daemon_id: String,
    decision: RelayDecision,
    #[serde(default)]
    note: Option<String>,
    vault_password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RelayDecision {
    Approve,
    Reject,
}

struct ProcessedFeedback {
    details: Option<BTreeMap<String, String>>,
    message: Option<String>,
    status: &'static str,
}

fn manual_approval_feedback(
    approval_request_id: Uuid,
    status: ManualApprovalStatus,
    note: Option<&str>,
    message: String,
) -> ProcessedFeedback {
    let mut details = BTreeMap::new();
    details.insert(
        "approvalRequestId".to_string(),
        approval_request_id.to_string(),
    );
    details.insert(
        "manualApprovalStatus".to_string(),
        map_approval_status(status).to_string(),
    );
    if let Some(note) = note.filter(|value| !value.trim().is_empty()) {
        details.insert("note".to_string(), note.to_string());
    }

    ProcessedFeedback {
        details: Some(details),
        message: Some(message),
        status: "applied",
    }
}

fn manual_approval_error_feedback(
    approval_request_id: Uuid,
    decision: ManualApprovalDecision,
    note: Option<&str>,
    error: &DaemonError,
) -> ProcessedFeedback {
    if let DaemonError::ManualApprovalRequestNotPending { status, .. } = error {
        let same_decision_already_applied = matches!(
            (decision, status),
            (
                ManualApprovalDecision::Approve,
                ManualApprovalStatus::Approved | ManualApprovalStatus::Completed,
            ) | (
                ManualApprovalDecision::Reject,
                ManualApprovalStatus::Rejected
            )
        );

        if same_decision_already_applied {
            return manual_approval_feedback(
                approval_request_id,
                *status,
                note,
                format!(
                    "manual approval {} was already applied to {}",
                    match decision {
                        ManualApprovalDecision::Approve => "approve",
                        ManualApprovalDecision::Reject => "reject",
                    },
                    approval_request_id
                ),
            );
        }
    }

    ProcessedFeedback {
        details: None,
        message: Some(error.to_string()),
        status: if matches!(decision, ManualApprovalDecision::Reject) {
            "rejected"
        } else {
            "failed"
        },
    }
}

pub fn spawn_relay_sync_task<B>(
    daemon: Arc<InMemoryDaemon<B>>,
    signer_backend: &'static str,
) -> JoinHandle<()>
where
    B: VaultSignerBackend + Send + Sync + 'static,
{
    tokio::spawn(async move {
        if let Err(error) = run_relay_sync_loop(daemon, signer_backend).await {
            eprintln!("==> relay sync terminated: {error:#}");
        }
    })
}

async fn run_relay_sync_loop<B>(
    daemon: Arc<InMemoryDaemon<B>>,
    signer_backend: &'static str,
) -> Result<()>
where
    B: VaultSignerBackend + Send + Sync + 'static,
{
    let client = Client::builder()
        .user_agent(format!("agentpay-daemon/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to initialize relay sync HTTP client")?;
    let registered_at = format_time(OffsetDateTime::now_utc())?;
    let mut interval = time::interval(std::time::Duration::from_secs(1));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        interval.tick().await;
        if let Err(error) =
            sync_once(&client, daemon.as_ref(), signer_backend, &registered_at).await
        {
            eprintln!("==> relay sync warning: {error:#}");
        }
    }
}

async fn sync_once<B>(
    client: &Client,
    daemon: &InMemoryDaemon<B>,
    signer_backend: &'static str,
    registered_at: &str,
) -> Result<()>
where
    B: VaultSignerBackend + Send + Sync + 'static,
{
    let snapshot = daemon
        .relay_registration_snapshot()
        .context("failed to snapshot daemon relay registration state")?;
    let Some(relay_url) = snapshot.relay_config.relay_url.clone() else {
        return Ok(());
    };
    let Some(ethereum_address) = snapshot.ethereum_address.clone() else {
        return Ok(());
    };

    register_snapshot(
        client,
        &relay_url,
        signer_backend,
        registered_at,
        &snapshot,
        &ethereum_address,
    )
    .await
    .context("failed to register daemon snapshot with relay")?;

    let poll_response = poll_updates(client, &relay_url, &snapshot.relay_config.daemon_id_hex)
        .await
        .context("failed to poll relay for encrypted updates")?;

    for update in poll_response.items {
        let feedback = process_update(daemon, &snapshot.relay_config.daemon_id_hex, &update).await;
        let claim_token = update
            .claim_token
            .as_deref()
            .context("relay returned update without claim token")?;
        submit_feedback(
            client,
            &relay_url,
            claim_token,
            &snapshot.relay_config.daemon_id_hex,
            &update.update_id,
            feedback,
        )
        .await
        .with_context(|| {
            format!(
                "failed to submit feedback for relay update {}",
                update.update_id
            )
        })?;
    }

    Ok(())
}

async fn register_snapshot(
    client: &Client,
    relay_url: &str,
    signer_backend: &'static str,
    registered_at: &str,
    snapshot: &RelayRegistrationSnapshot,
    ethereum_address: &str,
) -> Result<()> {
    let now = format_time(OffsetDateTime::now_utc())?;
    let request = RelayRegisterRequest {
        daemon: RelayDaemonProfilePayload {
            daemon_id: snapshot.relay_config.daemon_id_hex.clone(),
            daemon_public_key: snapshot.relay_config.daemon_public_key_hex.clone(),
            ethereum_address: ethereum_address.to_string(),
            label: std::env::var("HOSTNAME")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            last_seen_at: now.clone(),
            registered_at: registered_at.to_string(),
            relay_url: snapshot.relay_config.relay_url.clone(),
            signer_backend: signer_backend.to_string(),
            status: "active",
            updated_at: now.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        policies: flatten_policy_records(&snapshot.policies, &now),
        agent_keys: snapshot
            .agent_keys
            .iter()
            .map(|agent_key| RelayAgentKeyPayload {
                agent_key_id: agent_key.id.to_string(),
                created_at: format_time(agent_key.created_at).unwrap_or_else(|_| now.clone()),
                label: None,
                metadata: None,
                status: "active",
                updated_at: now.clone(),
            })
            .collect(),
        approval_requests: snapshot
            .manual_approval_requests
            .iter()
            .map(|request| RelayApprovalRequestPayload {
                agent_key_id: request.agent_key_id.to_string(),
                amount_wei: request.amount_wei.to_string(),
                approval_request_id: request.id.to_string(),
                chain_id: request.chain_id,
                destination: request.recipient.to_string(),
                metadata: approval_metadata(request, &snapshot.relay_private_key_hex),
                network: Some(request.chain_id.to_string()),
                reason: request.rejection_reason.clone(),
                requested_at: format_time(request.created_at).unwrap_or_else(|_| now.clone()),
                status: map_approval_status(request.status),
                token_address: asset_token_address(&request.asset),
                transaction_type: action_name(&request.action).to_string(),
                updated_at: format_time(request.updated_at).unwrap_or_else(|_| now.clone()),
            })
            .collect(),
    };

    apply_daemon_auth(
        client
            .post(format!(
                "{}/v1/daemon/register",
                relay_url.trim_end_matches('/')
            ))
            .header(CONTENT_TYPE, "application/json")
            .json(&request),
    )
    .send()
    .await
    .context("relay register request failed")?
    .error_for_status()
    .context("relay register request was rejected")?;

    Ok(())
}

async fn poll_updates(
    client: &Client,
    relay_url: &str,
    daemon_id: &str,
) -> Result<RelayPollResponse> {
    let response = apply_daemon_auth(
        client
            .post(format!(
                "{}/v1/daemon/poll-updates",
                relay_url.trim_end_matches('/')
            ))
            .header(CONTENT_TYPE, "application/json")
            .json(&RelayPollRequest {
                daemon_id,
                lease_seconds: DEFAULT_RELAY_LEASE_SECONDS,
                limit: DEFAULT_RELAY_POLL_LIMIT,
            }),
    )
    .send()
    .await
    .context("relay poll request failed")?
    .error_for_status()
    .context("relay poll request was rejected")?;

    response
        .json::<RelayPollResponse>()
        .await
        .context("failed to deserialize relay poll response")
}

async fn submit_feedback(
    client: &Client,
    relay_url: &str,
    claim_token: &str,
    daemon_id: &str,
    update_id: &str,
    feedback: ProcessedFeedback,
) -> Result<()> {
    apply_daemon_auth(
        client
            .post(format!(
                "{}/v1/daemon/submit-feedback",
                relay_url.trim_end_matches('/')
            ))
            .header(CONTENT_TYPE, "application/json")
            .json(&RelayFeedbackRequest {
                claim_token,
                daemon_id,
                details: feedback.details,
                message: feedback.message,
                status: feedback.status,
                update_id,
            }),
    )
    .send()
    .await
    .context("relay feedback request failed")?
    .error_for_status()
    .context("relay feedback request was rejected")?;

    Ok(())
}

async fn process_update<B>(
    daemon: &InMemoryDaemon<B>,
    expected_daemon_id: &str,
    update: &RelayEncryptedUpdateRecord,
) -> ProcessedFeedback
where
    B: VaultSignerBackend + Send + Sync + 'static,
{
    if update.daemon_id != expected_daemon_id {
        return ProcessedFeedback {
            details: None,
            message: Some(format!(
                "relay update daemon_id '{}' does not match '{}'",
                update.daemon_id, expected_daemon_id
            )),
            status: "rejected",
        };
    }

    if update.r#type != "manual_approval_decision" {
        return ProcessedFeedback {
            details: None,
            message: Some(format!("unsupported relay update type '{}'", update.r#type)),
            status: "failed",
        };
    }

    let plaintext = match daemon.decrypt_relay_envelope(
        &update.payload.algorithm,
        &update.payload.encapsulated_key_base64,
        &update.payload.nonce_base64,
        &update.payload.ciphertext_base64,
    ) {
        Ok(value) => value,
        Err(error) => {
            return ProcessedFeedback {
                details: None,
                message: Some(error.to_string()),
                status: "failed",
            };
        }
    };

    let payload = match serde_json::from_slice::<RelayManualApprovalUpdatePayload>(&plaintext) {
        Ok(value) => value,
        Err(error) => {
            return ProcessedFeedback {
                details: None,
                message: Some(format!("invalid relay update payload: {error}")),
                status: "failed",
            };
        }
    };

    if payload.daemon_id != expected_daemon_id {
        return ProcessedFeedback {
            details: None,
            message: Some(format!(
                "payload daemon_id '{}' does not match '{}'",
                payload.daemon_id, expected_daemon_id
            )),
            status: "rejected",
        };
    }

    if let Some(target_approval_request_id) = &update.target_approval_request_id {
        if target_approval_request_id != &payload.approval_id {
            return ProcessedFeedback {
                details: None,
                message: Some(format!(
                    "payload approval_id '{}' does not match relay target '{}'",
                    payload.approval_id, target_approval_request_id
                )),
                status: "rejected",
            };
        }
    }

    let approval_request_id = match Uuid::parse_str(&payload.approval_id) {
        Ok(value) => value,
        Err(error) => {
            return ProcessedFeedback {
                details: None,
                message: Some(format!("approval_id is not a UUID: {error}")),
                status: "failed",
            };
        }
    };

    let decision = match payload.decision {
        RelayDecision::Approve => ManualApprovalDecision::Approve,
        RelayDecision::Reject => ManualApprovalDecision::Reject,
    };
    let rejection_reason = if matches!(decision, ManualApprovalDecision::Reject) {
        payload
            .note
            .clone()
            .filter(|value| !value.trim().is_empty())
    } else {
        None
    };

    match daemon
        .apply_relay_manual_approval_decision(
            &payload.vault_password,
            approval_request_id,
            decision,
            rejection_reason.clone(),
        )
        .await
    {
        Ok(request) => manual_approval_feedback(
            request.id,
            request.status,
            payload.note.as_deref(),
            format!(
                "manual approval {} applied to {}",
                match decision {
                    ManualApprovalDecision::Approve => "approve",
                    ManualApprovalDecision::Reject => "reject",
                },
                request.id
            ),
        ),
        Err(error) => manual_approval_error_feedback(
            approval_request_id,
            decision,
            payload.note.as_deref(),
            &error,
        ),
    }
}

fn apply_daemon_auth(request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    let token = resolve_relay_daemon_token();
    match token {
        Some(token) => request.header("x-relay-daemon-token", token),
        None => request,
    }
}

fn resolve_relay_daemon_token() -> Option<String> {
    resolve_relay_daemon_token_with(
        |name| std::env::var(name).ok(),
        |path| std::fs::read_to_string(path),
    )
}

fn resolve_relay_daemon_token_with<Env, ReadFile>(
    read_env: Env,
    read_file: ReadFile,
) -> Option<String>
where
    Env: Fn(&str) -> Option<String>,
    ReadFile: Fn(&Path) -> std::io::Result<String>,
{
    if let Some(token) = read_env(RELAY_DAEMON_TOKEN_ENV).and_then(|value| normalize_secret(&value))
    {
        return Some(token);
    }

    let token_path = read_env(RELAY_DAEMON_TOKEN_FILE_ENV)?;
    let trimmed_path = token_path.trim();
    if trimmed_path.is_empty() {
        return None;
    }

    read_file(Path::new(trimmed_path))
        .ok()
        .and_then(|value| normalize_secret(&value))
}

fn normalize_secret(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn flatten_policy_records(
    policies: &[SpendingPolicy],
    updated_at: &str,
) -> Vec<RelayPolicyPayload> {
    let mut records = Vec::new();

    for policy in policies.iter().filter(|policy| policy.enabled) {
        let recipients = match &policy.recipients {
            EntityScope::All => vec![(ZERO_ADDRESS.to_string(), "default")],
            EntityScope::Set(values) => values
                .iter()
                .cloned()
                .map(|value| (value.to_string(), "override"))
                .collect::<Vec<_>>(),
        };
        let assets = match &policy.assets {
            EntityScope::All => vec![None],
            EntityScope::Set(values) => values.iter().cloned().map(Some).collect::<Vec<_>>(),
        };
        let networks = match &policy.networks {
            EntityScope::All => vec![None],
            EntityScope::Set(values) => values.iter().copied().map(Some).collect::<Vec<_>>(),
        };

        for (destination, scope) in &recipients {
            for asset in &assets {
                for chain_id in &networks {
                    let limits = relay_policy_limits(policy);
                    records.push(RelayPolicyPayload {
                        action: policy_name(policy).to_string(),
                        amount_max_wei: limits.amount_max_wei,
                        amount_min_wei: policy.min_amount_wei.map(|value| value.to_string()),
                        max_tx_count: limits.max_tx_count,
                        max_fee_per_gas_wei: limits.max_fee_per_gas_wei,
                        max_priority_fee_per_gas_wei: limits.max_priority_fee_per_gas_wei,
                        max_calldata_bytes: limits.max_calldata_bytes,
                        max_gas_spend_wei: limits.max_gas_spend_wei,
                        chain_id: *chain_id,
                        destination: destination.clone(),
                        metadata: Some(policy_metadata(policy, asset.as_ref(), *chain_id, scope)),
                        policy_id: policy.id.to_string(),
                        requires_manual_approval: matches!(
                            policy.policy_type,
                            PolicyType::ManualApproval
                        ),
                        scope,
                        token_address: asset.as_ref().and_then(asset_token_address),
                        updated_at: updated_at.to_string(),
                    });
                }
            }
        }
    }

    records
}

fn relay_policy_limits(policy: &SpendingPolicy) -> RelayPolicyLimits {
    // Keep amount_max_wei as a legacy fallback so older relay deployments do
    // not silently drop specialized limits during rolling upgrades.
    match policy.policy_type {
        PolicyType::DailyMaxSpending
        | PolicyType::WeeklyMaxSpending
        | PolicyType::PerTxMaxSpending
        | PolicyType::ManualApproval => RelayPolicyLimits {
            amount_max_wei: Some(policy.max_amount_wei.to_string()),
            ..Default::default()
        },
        PolicyType::DailyMaxTxCount => {
            let max_tx_count = policy.tx_count_limit().map(|value| value.to_string());
            RelayPolicyLimits {
                amount_max_wei: max_tx_count.clone(),
                max_tx_count,
                ..Default::default()
            }
        }
        PolicyType::PerTxMaxFeePerGas => {
            let max_fee_per_gas_wei = policy.fee_per_gas_limit().map(|value| value.to_string());
            RelayPolicyLimits {
                amount_max_wei: max_fee_per_gas_wei.clone(),
                max_fee_per_gas_wei,
                ..Default::default()
            }
        }
        PolicyType::PerTxMaxPriorityFeePerGas => {
            let max_priority_fee_per_gas_wei = policy
                .priority_fee_per_gas_limit()
                .map(|value| value.to_string());
            RelayPolicyLimits {
                amount_max_wei: max_priority_fee_per_gas_wei.clone(),
                max_priority_fee_per_gas_wei,
                ..Default::default()
            }
        }
        PolicyType::PerTxMaxCalldataBytes => {
            let max_calldata_bytes = policy.calldata_bytes_limit().map(|value| value.to_string());
            RelayPolicyLimits {
                amount_max_wei: max_calldata_bytes.clone(),
                max_calldata_bytes,
                ..Default::default()
            }
        }
        PolicyType::PerChainMaxGasSpend => {
            let max_gas_spend_wei = policy.gas_spend_limit_wei().map(|value| value.to_string());
            RelayPolicyLimits {
                amount_max_wei: max_gas_spend_wei.clone(),
                max_gas_spend_wei,
                ..Default::default()
            }
        }
    }
}

fn policy_metadata(
    policy: &SpendingPolicy,
    asset: Option<&AssetId>,
    chain_id: Option<u64>,
    scope: &str,
) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert("policyType".to_string(), policy_name(policy).to_string());
    metadata.insert("scope".to_string(), scope.to_string());
    metadata.insert(
        "recipientScope".to_string(),
        match policy.recipients {
            EntityScope::All => "all".to_string(),
            EntityScope::Set(_) => "set".to_string(),
        },
    );
    metadata.insert(
        "assetScope".to_string(),
        match policy.assets {
            EntityScope::All => "all".to_string(),
            EntityScope::Set(_) => "set".to_string(),
        },
    );
    metadata.insert(
        "networkScope".to_string(),
        match policy.networks {
            EntityScope::All => "all".to_string(),
            EntityScope::Set(_) => "set".to_string(),
        },
    );
    if let Some(asset) = asset {
        metadata.insert("asset".to_string(), asset.to_string());
    }
    if let Some(chain_id) = chain_id {
        metadata.insert("chainId".to_string(), chain_id.to_string());
    }
    metadata
}

fn approval_metadata(
    request: &vault_domain::ManualApprovalRequest,
    relay_private_key_hex: &str,
) -> Option<BTreeMap<String, String>> {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "triggeredPolicyIds".to_string(),
        request
            .triggered_by_policy_ids
            .iter()
            .map(Uuid::to_string)
            .collect::<Vec<_>>()
            .join(","),
    );
    metadata.insert("asset".to_string(), request.asset.to_string());
    if matches!(request.status, ManualApprovalStatus::Pending) {
        if let Ok(token) = manual_approval_capability_token(relay_private_key_hex, request.id) {
            metadata.insert("approvalCapabilityToken".to_string(), token.clone());
            if let Ok(hash) = manual_approval_capability_hash(&token) {
                metadata.insert("approvalCapabilityHash".to_string(), hash);
            }
        }
    }
    Some(metadata)
}

fn policy_name(policy: &SpendingPolicy) -> &'static str {
    match policy.policy_type {
        PolicyType::DailyMaxSpending => "daily_max_spending",
        PolicyType::DailyMaxTxCount => "daily_max_tx_count",
        PolicyType::WeeklyMaxSpending => "weekly_max_spending",
        PolicyType::PerTxMaxSpending => "per_tx_max_spending",
        PolicyType::PerTxMaxFeePerGas => "per_tx_max_fee_per_gas",
        PolicyType::PerTxMaxPriorityFeePerGas => "per_tx_max_priority_fee_per_gas",
        PolicyType::PerTxMaxCalldataBytes => "per_tx_max_calldata_bytes",
        PolicyType::PerChainMaxGasSpend => "per_chain_max_gas_spend",
        PolicyType::ManualApproval => "manual_approval",
    }
}

fn action_name(action: &AgentAction) -> &'static str {
    match action {
        AgentAction::Approve { .. } => "approve",
        AgentAction::Transfer { .. } => "transfer",
        AgentAction::TransferNative { .. } => "transfer_native",
        AgentAction::Permit2Permit { .. } => "permit2_permit",
        AgentAction::Eip3009TransferWithAuthorization { .. } => {
            "eip3009_transfer_with_authorization"
        }
        AgentAction::Eip3009ReceiveWithAuthorization { .. } => "eip3009_receive_with_authorization",
        AgentAction::TempoSessionOpenTransaction { .. } => "tempo_session_open_transaction",
        AgentAction::TempoSessionTopUpTransaction { .. } => "tempo_session_top_up_transaction",
        AgentAction::TempoSessionVoucher { .. } => "tempo_session_voucher",
        AgentAction::BroadcastTx { .. } => "broadcast_tx",
    }
}

fn asset_token_address(asset: &AssetId) -> Option<String> {
    match asset {
        AssetId::NativeEth => None,
        AssetId::Erc20(token) => Some(token.to_string()),
    }
}

fn map_approval_status(status: ManualApprovalStatus) -> &'static str {
    match status {
        ManualApprovalStatus::Pending => "pending",
        ManualApprovalStatus::Approved => "approved",
        ManualApprovalStatus::Rejected => "rejected",
        ManualApprovalStatus::Completed => "completed",
    }
}

fn format_time(value: OffsetDateTime) -> Result<String> {
    value
        .format(&Rfc3339)
        .context("failed to format timestamp as RFC3339")
}

#[cfg(test)]
mod tests {
    use super::{
        action_name, apply_daemon_auth, approval_metadata, asset_token_address,
        flatten_policy_records, format_time, manual_approval_error_feedback,
        manual_approval_feedback, map_approval_status, normalize_secret, policy_metadata,
        policy_name, poll_updates, process_update, register_snapshot,
        resolve_relay_daemon_token_with, submit_feedback, ProcessedFeedback, RelayEncryptedPayload,
        RelayEncryptedUpdateRecord,
    };
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
    use reqwest::Client;
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};
    use time::OffsetDateTime;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use uuid::Uuid;
    use vault_daemon::{DaemonConfig, DaemonError, InMemoryDaemon, RelayRegistrationSnapshot};
    use vault_domain::{
        AgentAction, AgentKey, AssetId, BroadcastTx, Eip3009Transfer, EntityScope,
        ManualApprovalDecision, ManualApprovalRequest, ManualApprovalStatus, Permit2Permit,
        PolicyAttachment, PolicyType, RelayConfig, SpendingPolicy,
    };
    use vault_signer::SoftwareSignerBackend;

    fn env_lock() -> &'static Mutex<()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    #[derive(Debug)]
    struct CapturedHttpRequest {
        request_line: String,
        headers: BTreeMap<String, String>,
        body: String,
    }

    async fn spawn_single_response_server(
        status_line: &str,
        response_body: &str,
    ) -> (
        String,
        oneshot::Receiver<CapturedHttpRequest>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let status_line = status_line.to_string();
        let response_body = response_body.to_string();
        let (tx, rx) = oneshot::channel();

        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buffer = Vec::new();
            let header_end = loop {
                let mut chunk = [0u8; 1024];
                let read = stream.read(&mut chunk).await.expect("read request");
                if read == 0 {
                    panic!("connection closed before headers");
                }
                buffer.extend_from_slice(&chunk[..read]);
                if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                    break position + 4;
                }
            };

            let header_text = String::from_utf8_lossy(&buffer[..header_end]).to_string();
            let mut lines = header_text.split("\r\n");
            let request_line = lines.next().expect("request line").to_string();
            let mut headers = BTreeMap::new();
            let mut content_length = 0usize;
            for line in lines.filter(|line| !line.is_empty()) {
                let (name, value) = line.split_once(':').expect("header");
                let value = value.trim().to_string();
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.parse::<usize>().expect("content length");
                }
                headers.insert(name.to_ascii_lowercase(), value);
            }

            let mut body_bytes = buffer[header_end..].to_vec();
            while body_bytes.len() < content_length {
                let mut chunk = vec![0u8; content_length - body_bytes.len()];
                let read = stream.read(&mut chunk).await.expect("read body");
                if read == 0 {
                    break;
                }
                body_bytes.extend_from_slice(&chunk[..read]);
            }
            let body = String::from_utf8(body_bytes[..content_length].to_vec()).expect("utf8 body");

            let response = format!(
                "HTTP/1.1 {status_line}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");

            let _ = tx.send(CapturedHttpRequest {
                request_line,
                headers,
                body,
            });
        });

        (format!("http://{}", addr), rx, handle)
    }

    #[test]
    fn approval_metadata_includes_admin_reissue_token_and_public_hash_for_pending_requests() {
        let request = ManualApprovalRequest {
            id: Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("uuid"),
            agent_key_id: Uuid::nil(),
            vault_key_id: Uuid::nil(),
            request_payload_hash_hex: "11".repeat(32),
            action: AgentAction::TransferNative {
                chain_id: 56,
                to: "0x2222222222222222222222222222222222222222"
                    .parse()
                    .expect("address"),
                amount_wei: 1,
            },
            chain_id: 56,
            asset: AssetId::NativeEth,
            recipient: "0x2222222222222222222222222222222222222222"
                .parse()
                .expect("address"),
            amount_wei: 1,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            status: ManualApprovalStatus::Pending,
            triggered_by_policy_ids: vec![Uuid::nil()],
            completed_at: None,
            rejection_reason: None,
        };

        let metadata = approval_metadata(&request, &"11".repeat(32)).expect("metadata");
        let token = metadata
            .get("approvalCapabilityToken")
            .expect("capability token");
        let hash = metadata
            .get("approvalCapabilityHash")
            .expect("capability hash");

        assert_eq!(token.len(), 64);
        assert_eq!(hash.len(), 64);
    }

    fn temp_path(prefix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time before unix epoch")
                .as_nanos()
        ))
    }

    fn sample_address(value: &str) -> vault_domain::EvmAddress {
        value.parse().expect("address")
    }

    fn sample_policy(policy_type: PolicyType) -> SpendingPolicy {
        match policy_type {
            PolicyType::DailyMaxTxCount => {
                return SpendingPolicy::new_tx_count_limit(
                    1,
                    1_000,
                    EntityScope::All,
                    EntityScope::All,
                    EntityScope::All,
                )
                .expect("policy");
            }
            PolicyType::PerTxMaxFeePerGas => {
                return SpendingPolicy::new_fee_per_gas_limit(
                    1,
                    1_000,
                    EntityScope::All,
                    EntityScope::All,
                    EntityScope::All,
                )
                .expect("policy");
            }
            PolicyType::PerTxMaxPriorityFeePerGas => {
                return SpendingPolicy::new_priority_fee_per_gas_limit(
                    1,
                    1_000,
                    EntityScope::All,
                    EntityScope::All,
                    EntityScope::All,
                )
                .expect("policy");
            }
            PolicyType::PerTxMaxCalldataBytes => {
                return SpendingPolicy::new_calldata_limit(
                    1,
                    1_000,
                    EntityScope::All,
                    EntityScope::All,
                    EntityScope::All,
                )
                .expect("policy");
            }
            PolicyType::PerChainMaxGasSpend => {
                return SpendingPolicy::new_gas_spend_limit(
                    1,
                    1_000,
                    EntityScope::All,
                    EntityScope::All,
                    EntityScope::All,
                )
                .expect("policy");
            }
            _ => {}
        }

        SpendingPolicy::new(
            1,
            policy_type,
            1_000,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("policy")
    }

    fn sample_manual_request(status: ManualApprovalStatus) -> ManualApprovalRequest {
        ManualApprovalRequest {
            id: Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("uuid"),
            agent_key_id: Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("uuid"),
            vault_key_id: Uuid::parse_str("cccccccc-cccc-4ccc-8ccc-cccccccccccc").expect("uuid"),
            request_payload_hash_hex: "11".repeat(32),
            action: AgentAction::TransferNative {
                chain_id: 56,
                to: sample_address("0x2222222222222222222222222222222222222222"),
                amount_wei: 1,
            },
            chain_id: 56,
            asset: AssetId::NativeEth,
            recipient: sample_address("0x2222222222222222222222222222222222222222"),
            amount_wei: 1,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            status,
            triggered_by_policy_ids: vec![Uuid::nil()],
            completed_at: None,
            rejection_reason: None,
        }
    }

    fn sample_snapshot(relay_url: &str) -> RelayRegistrationSnapshot {
        RelayRegistrationSnapshot {
            relay_config: RelayConfig {
                relay_url: Some(relay_url.to_string()),
                frontend_url: Some("https://frontend.example".to_string()),
                daemon_id_hex: "aa".repeat(32),
                daemon_public_key_hex: "bb".repeat(32),
            },
            relay_private_key_hex: "11".repeat(32).into(),
            vault_public_key_hex: Some("04".repeat(33)),
            ethereum_address: Some("0x9999999999999999999999999999999999999999".to_string()),
            policies: vec![sample_policy(PolicyType::PerTxMaxSpending)],
            agent_keys: vec![AgentKey {
                id: Uuid::parse_str("dddddddd-dddd-4ddd-8ddd-dddddddddddd").expect("uuid"),
                vault_key_id: Uuid::parse_str("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
                    .expect("uuid"),
                policies: PolicyAttachment::AllPolicies,
                created_at: OffsetDateTime::UNIX_EPOCH,
            }],
            manual_approval_requests: vec![sample_manual_request(ManualApprovalStatus::Pending)],
        }
    }

    fn encrypt_payload(daemon_public_key_hex: &str, plaintext: &[u8]) -> RelayEncryptedPayload {
        let public_bytes = hex::decode(daemon_public_key_hex).expect("decode daemon public key");
        let peer_public = x25519_dalek::PublicKey::from(
            <[u8; 32]>::try_from(public_bytes.as_slice()).expect("public key bytes"),
        );
        let secret = x25519_dalek::StaticSecret::from([7u8; 32]);
        let shared_secret = secret.diffie_hellman(&peer_public);
        let cipher = XChaCha20Poly1305::new(shared_secret.as_bytes().into());
        let nonce = [9u8; 24];
        let ciphertext = cipher
            .encrypt(chacha20poly1305::XNonce::from_slice(&nonce), plaintext)
            .expect("encrypt payload");

        RelayEncryptedPayload {
            algorithm: "x25519-xchacha20poly1305-v1".to_string(),
            ciphertext_base64: hex::encode(ciphertext),
            encapsulated_key_base64: hex::encode(x25519_dalek::PublicKey::from(&secret).as_bytes()),
            nonce_base64: hex::encode(nonce),
        }
    }

    fn sample_update_record(
        daemon_id: &str,
        payload: RelayEncryptedPayload,
    ) -> RelayEncryptedUpdateRecord {
        RelayEncryptedUpdateRecord {
            claim_token: Some("claim-token".to_string()),
            daemon_id: daemon_id.to_string(),
            payload,
            target_approval_request_id: None,
            r#type: "manual_approval_decision".to_string(),
            update_id: "update-1".to_string(),
        }
    }

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    #[test]
    fn resolve_relay_daemon_token_prefers_explicit_env_value() {
        let env = BTreeMap::from([
            (
                "AGENTPAY_RELAY_DAEMON_TOKEN".to_string(),
                " env-token ".to_string(),
            ),
            (
                "AGENTPAY_RELAY_DAEMON_TOKEN_FILE".to_string(),
                "/should/not/be/read".to_string(),
            ),
        ]);

        let token = resolve_relay_daemon_token_with(
            |name| env.get(name).cloned(),
            |_path| -> std::io::Result<String> { panic!("file token should not be read") },
        );

        assert_eq!(token.as_deref(), Some("env-token"));
    }

    #[test]
    fn resolve_relay_daemon_token_reads_root_only_file_path_when_env_token_is_absent() {
        let token_path = temp_path("agentpay-relay-daemon-token");
        fs::write(&token_path, " file-token \n").expect("write relay token file");
        let env = BTreeMap::from([(
            "AGENTPAY_RELAY_DAEMON_TOKEN_FILE".to_string(),
            token_path.display().to_string(),
        )]);

        let token = resolve_relay_daemon_token_with(
            |name| env.get(name).cloned(),
            |path| fs::read_to_string(path),
        );

        assert_eq!(token.as_deref(), Some("file-token"));
        let _ = fs::remove_file(token_path);
    }

    #[test]
    fn resolve_relay_daemon_token_ignores_blank_or_unreadable_sources() {
        let env = BTreeMap::from([
            ("AGENTPAY_RELAY_DAEMON_TOKEN".to_string(), "   ".to_string()),
            (
                "AGENTPAY_RELAY_DAEMON_TOKEN_FILE".to_string(),
                "/missing/token-file".to_string(),
            ),
        ]);

        let token = resolve_relay_daemon_token_with(
            |name| env.get(name).cloned(),
            |_path: &Path| Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
        );

        assert_eq!(token, None);
    }

    #[test]
    fn manual_approval_error_feedback_marks_replayed_approve_updates_as_applied() {
        let approval_request_id =
            Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("uuid");

        let feedback = manual_approval_error_feedback(
            approval_request_id,
            ManualApprovalDecision::Approve,
            Some("approved earlier"),
            &DaemonError::ManualApprovalRequestNotPending {
                approval_request_id,
                status: ManualApprovalStatus::Completed,
            },
        );

        assert_eq!(feedback.status, "applied");
        assert_eq!(
            feedback
                .details
                .as_ref()
                .and_then(|details| details.get("manualApprovalStatus")),
            Some(&"completed".to_string())
        );
        assert_eq!(
            feedback
                .details
                .as_ref()
                .and_then(|details| details.get("note")),
            Some(&"approved earlier".to_string())
        );
        assert!(feedback
            .message
            .as_deref()
            .is_some_and(|message| message.contains("already applied")));
    }

    #[test]
    fn manual_approval_error_feedback_keeps_conflicting_approve_updates_failed() {
        let approval_request_id =
            Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("uuid");

        let feedback = manual_approval_error_feedback(
            approval_request_id,
            ManualApprovalDecision::Approve,
            None,
            &DaemonError::ManualApprovalRequestNotPending {
                approval_request_id,
                status: ManualApprovalStatus::Rejected,
            },
        );

        assert_eq!(feedback.status, "failed");
        assert!(feedback.details.is_none());
        assert!(feedback
            .message
            .as_deref()
            .is_some_and(|message| message.contains("already Rejected")));
    }

    #[test]
    fn manual_approval_feedback_and_reject_error_feedback_cover_remaining_paths() {
        let approval_request_id =
            Uuid::parse_str("dddddddd-dddd-4ddd-8ddd-dddddddddddd").expect("uuid");

        let feedback = manual_approval_feedback(
            approval_request_id,
            ManualApprovalStatus::Approved,
            Some("   "),
            "done".to_string(),
        );
        assert_eq!(feedback.status, "applied");
        assert_eq!(feedback.message.as_deref(), Some("done"));
        assert!(!feedback
            .details
            .as_ref()
            .expect("details")
            .contains_key("note"));

        let reject_feedback = manual_approval_error_feedback(
            approval_request_id,
            ManualApprovalDecision::Reject,
            Some("because"),
            &DaemonError::Transport("boom".to_string()),
        );
        assert_eq!(reject_feedback.status, "rejected");
        assert!(reject_feedback.details.is_none());
        assert_eq!(
            reject_feedback.message.as_deref(),
            Some("transport error: boom")
        );
    }

    #[test]
    fn normalize_secret_trims_and_rejects_blank_values() {
        assert_eq!(normalize_secret("  token  ").as_deref(), Some("token"));
        assert_eq!(normalize_secret("\n\t  "), None);
    }

    #[test]
    fn policy_name_covers_all_policy_types() {
        assert_eq!(
            policy_name(&sample_policy(PolicyType::DailyMaxSpending)),
            "daily_max_spending"
        );
        assert_eq!(
            policy_name(&sample_policy(PolicyType::DailyMaxTxCount)),
            "daily_max_tx_count"
        );
        assert_eq!(
            policy_name(&sample_policy(PolicyType::WeeklyMaxSpending)),
            "weekly_max_spending"
        );
        assert_eq!(
            policy_name(&sample_policy(PolicyType::PerTxMaxSpending)),
            "per_tx_max_spending"
        );
        assert_eq!(
            policy_name(&sample_policy(PolicyType::PerTxMaxFeePerGas)),
            "per_tx_max_fee_per_gas"
        );
        assert_eq!(
            policy_name(&sample_policy(PolicyType::PerTxMaxPriorityFeePerGas)),
            "per_tx_max_priority_fee_per_gas"
        );
        assert_eq!(
            policy_name(&sample_policy(PolicyType::PerTxMaxCalldataBytes)),
            "per_tx_max_calldata_bytes"
        );
        assert_eq!(
            policy_name(&sample_policy(PolicyType::PerChainMaxGasSpend)),
            "per_chain_max_gas_spend"
        );
        assert_eq!(
            policy_name(&sample_policy(PolicyType::ManualApproval)),
            "manual_approval"
        );
    }

    #[test]
    fn action_name_covers_all_agent_actions() {
        assert_eq!(
            action_name(&AgentAction::Approve {
                chain_id: 1,
                token: sample_address("0x1111111111111111111111111111111111111111"),
                spender: sample_address("0x2222222222222222222222222222222222222222"),
                amount_wei: 1,
            }),
            "approve"
        );
        assert_eq!(
            action_name(&AgentAction::Transfer {
                chain_id: 1,
                token: sample_address("0x1111111111111111111111111111111111111111"),
                to: sample_address("0x2222222222222222222222222222222222222222"),
                amount_wei: 1,
            }),
            "transfer"
        );
        assert_eq!(
            action_name(&AgentAction::TransferNative {
                chain_id: 1,
                to: sample_address("0x2222222222222222222222222222222222222222"),
                amount_wei: 1,
            }),
            "transfer_native"
        );
        assert_eq!(
            action_name(&AgentAction::Permit2Permit {
                permit: Permit2Permit {
                    chain_id: 1,
                    permit2_contract: sample_address("0x4444444444444444444444444444444444444444"),
                    token: sample_address("0x1111111111111111111111111111111111111111"),
                    spender: sample_address("0x2222222222222222222222222222222222222222"),
                    amount_wei: 1,
                    expiration: 1,
                    nonce: 1,
                    sig_deadline: 1,
                },
            }),
            "permit2_permit"
        );
        assert_eq!(
            action_name(&AgentAction::Eip3009TransferWithAuthorization {
                authorization: Eip3009Transfer {
                    chain_id: 1,
                    token: sample_address("0x1111111111111111111111111111111111111111"),
                    token_name: "USD Coin".to_string(),
                    token_version: Some("2".to_string()),
                    from: sample_address("0x2222222222222222222222222222222222222222"),
                    to: sample_address("0x3333333333333333333333333333333333333333"),
                    amount_wei: 1,
                    valid_after: 1,
                    valid_before: 2,
                    nonce_hex: format!("0x{}", "07".repeat(32)),
                },
            }),
            "eip3009_transfer_with_authorization"
        );
        assert_eq!(
            action_name(&AgentAction::Eip3009ReceiveWithAuthorization {
                authorization: Eip3009Transfer {
                    chain_id: 1,
                    token: sample_address("0x1111111111111111111111111111111111111111"),
                    token_name: "USD Coin".to_string(),
                    token_version: None,
                    from: sample_address("0x2222222222222222222222222222222222222222"),
                    to: sample_address("0x3333333333333333333333333333333333333333"),
                    amount_wei: 1,
                    valid_after: 1,
                    valid_before: 2,
                    nonce_hex: format!("0x{}", "09".repeat(32)),
                },
            }),
            "eip3009_receive_with_authorization"
        );
        assert_eq!(
            action_name(&AgentAction::BroadcastTx {
                tx: BroadcastTx {
                    chain_id: 1,
                    nonce: 1,
                    to: sample_address("0x2222222222222222222222222222222222222222"),
                    value_wei: 0,
                    data_hex: "0x".to_string(),
                    gas_limit: 21_000,
                    max_fee_per_gas_wei: 2,
                    max_priority_fee_per_gas_wei: 1,
                    tx_type: 0x02,
                    delegation_enabled: false,
                },
            }),
            "broadcast_tx"
        );
    }

    #[test]
    fn map_approval_status_covers_all_statuses() {
        assert_eq!(
            map_approval_status(ManualApprovalStatus::Pending),
            "pending"
        );
        assert_eq!(
            map_approval_status(ManualApprovalStatus::Approved),
            "approved"
        );
        assert_eq!(
            map_approval_status(ManualApprovalStatus::Rejected),
            "rejected"
        );
        assert_eq!(
            map_approval_status(ManualApprovalStatus::Completed),
            "completed"
        );
    }

    #[test]
    fn asset_token_address_covers_native_and_erc20_assets() {
        assert_eq!(asset_token_address(&AssetId::NativeEth), None);
        assert_eq!(
            asset_token_address(&AssetId::Erc20(sample_address(
                "0x1111111111111111111111111111111111111111"
            )))
            .as_deref(),
            Some("0x1111111111111111111111111111111111111111")
        );
    }

    #[test]
    fn flatten_policy_records_expands_scopes_and_skips_disabled_policies() {
        let mut policy = SpendingPolicy::new_manual_approval(
            5,
            10,
            100,
            EntityScope::Set(BTreeSet::from([
                sample_address("0x1111111111111111111111111111111111111111"),
                sample_address("0x2222222222222222222222222222222222222222"),
            ])),
            EntityScope::Set(BTreeSet::from([
                AssetId::NativeEth,
                AssetId::Erc20(sample_address("0x3333333333333333333333333333333333333333")),
            ])),
            EntityScope::Set(BTreeSet::from([1, 10])),
        )
        .expect("policy");
        let mut disabled = sample_policy(PolicyType::PerTxMaxSpending);
        disabled.enabled = false;
        policy.id = Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("uuid");

        let records = flatten_policy_records(&[policy.clone(), disabled], "2026-03-11T00:00:00Z");
        assert_eq!(records.len(), 8);
        assert!(records
            .iter()
            .all(|record| record.policy_id == policy.id.to_string()));
        assert!(records.iter().all(|record| record.requires_manual_approval));
        assert!(records.iter().all(|record| record.scope == "override"));
        assert!(records.iter().any(|record| record.token_address.is_none()));
        assert!(records.iter().any(|record| {
            record.token_address.as_deref() == Some("0x3333333333333333333333333333333333333333")
        }));
        assert!(records.iter().all(|record| record.metadata.is_some()));
    }

    #[test]
    fn flatten_policy_records_uses_dedicated_calldata_limit() {
        let policy = SpendingPolicy::new_calldata_limit(
            1,
            32,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("policy");

        let records = flatten_policy_records(&[policy], "2026-03-11T00:00:00Z");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].amount_max_wei.as_deref(), Some("32"));
        assert_eq!(records[0].max_calldata_bytes.as_deref(), Some("32"));
    }

    #[test]
    fn flatten_policy_records_uses_typed_specialized_limits() {
        let tx_count_policy = SpendingPolicy::new_tx_count_limit(
            1,
            5,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("policy");
        let fee_policy = SpendingPolicy::new_fee_per_gas_limit(
            1,
            7,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("policy");
        let priority_fee_policy = SpendingPolicy::new_priority_fee_per_gas_limit(
            1,
            11,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("policy");
        let gas_policy = SpendingPolicy::new_gas_spend_limit(
            1,
            13,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("policy");

        let records = flatten_policy_records(
            &[tx_count_policy, fee_policy, priority_fee_policy, gas_policy],
            "2026-03-11T00:00:00Z",
        );
        assert_eq!(records.len(), 4);
        assert_eq!(records[0].amount_max_wei.as_deref(), Some("5"));
        assert_eq!(records[1].amount_max_wei.as_deref(), Some("7"));
        assert_eq!(records[2].amount_max_wei.as_deref(), Some("11"));
        assert_eq!(records[3].amount_max_wei.as_deref(), Some("13"));
        assert_eq!(records[0].max_tx_count.as_deref(), Some("5"));
        assert_eq!(records[1].max_fee_per_gas_wei.as_deref(), Some("7"));
        assert_eq!(
            records[2].max_priority_fee_per_gas_wei.as_deref(),
            Some("11")
        );
        assert_eq!(records[3].max_gas_spend_wei.as_deref(), Some("13"));
    }

    #[test]
    fn policy_metadata_covers_scope_specific_fields() {
        let policy = SpendingPolicy::new_manual_approval(
            1,
            10,
            100,
            EntityScope::Set(BTreeSet::from([sample_address(
                "0x1111111111111111111111111111111111111111",
            )])),
            EntityScope::Set(BTreeSet::from([AssetId::Erc20(sample_address(
                "0x3333333333333333333333333333333333333333",
            ))])),
            EntityScope::Set(BTreeSet::from([1])),
        )
        .expect("policy");

        let metadata = policy_metadata(
            &policy,
            Some(&AssetId::Erc20(sample_address(
                "0x3333333333333333333333333333333333333333",
            ))),
            Some(1),
            "override",
        );
        assert_eq!(
            metadata.get("policyType").map(String::as_str),
            Some("manual_approval")
        );
        assert_eq!(metadata.get("scope").map(String::as_str), Some("override"));
        assert_eq!(
            metadata.get("recipientScope").map(String::as_str),
            Some("set")
        );
        assert_eq!(metadata.get("assetScope").map(String::as_str), Some("set"));
        assert_eq!(
            metadata.get("networkScope").map(String::as_str),
            Some("set")
        );
        assert_eq!(
            metadata.get("asset").map(String::as_str),
            Some("erc20:0x3333333333333333333333333333333333333333")
        );
        assert_eq!(metadata.get("chainId").map(String::as_str), Some("1"));
    }

    #[test]
    fn approval_metadata_omits_capability_for_non_pending_requests() {
        let mut request = ManualApprovalRequest {
            id: Uuid::parse_str("cccccccc-cccc-4ccc-8ccc-cccccccccccc").expect("uuid"),
            agent_key_id: Uuid::nil(),
            vault_key_id: Uuid::nil(),
            request_payload_hash_hex: "22".repeat(32),
            action: AgentAction::TransferNative {
                chain_id: 56,
                to: sample_address("0x2222222222222222222222222222222222222222"),
                amount_wei: 1,
            },
            chain_id: 56,
            asset: AssetId::NativeEth,
            recipient: sample_address("0x2222222222222222222222222222222222222222"),
            amount_wei: 1,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            status: ManualApprovalStatus::Completed,
            triggered_by_policy_ids: vec![Uuid::nil()],
            completed_at: Some(OffsetDateTime::UNIX_EPOCH),
            rejection_reason: None,
        };

        let metadata = approval_metadata(&request, &"11".repeat(32)).expect("metadata");
        assert_eq!(
            metadata.get("triggeredPolicyIds").map(String::as_str),
            Some("00000000-0000-0000-0000-000000000000")
        );
        assert_eq!(
            metadata.get("asset").map(String::as_str),
            Some("native_eth")
        );
        assert!(!metadata.contains_key("approvalCapabilityToken"));
        assert!(!metadata.contains_key("approvalCapabilityHash"));

        request.status = ManualApprovalStatus::Rejected;
        let metadata = approval_metadata(&request, " ").expect("metadata");
        assert!(!metadata.contains_key("approvalCapabilityToken"));
    }

    #[test]
    fn format_time_renders_rfc3339() {
        let rendered = format_time(OffsetDateTime::UNIX_EPOCH).expect("format time");
        assert_eq!(rendered, "1970-01-01T00:00:00Z");
    }

    #[test]
    fn apply_daemon_auth_adds_header_when_token_env_is_present() {
        let _guard = env_lock().lock().expect("env lock");
        std::env::set_var("AGENTPAY_RELAY_DAEMON_TOKEN", "relay-secret");
        std::env::remove_var("AGENTPAY_RELAY_DAEMON_TOKEN_FILE");

        let client = Client::new();
        let request = apply_daemon_auth(client.get("https://relay.example"))
            .build()
            .expect("build request");
        assert_eq!(
            request
                .headers()
                .get("x-relay-daemon-token")
                .and_then(|value| value.to_str().ok()),
            Some("relay-secret")
        );

        std::env::remove_var("AGENTPAY_RELAY_DAEMON_TOKEN");
    }

    #[tokio::test]
    async fn register_snapshot_posts_expected_payload_and_header() {
        let _guard = env_lock().lock().expect("env lock");
        std::env::set_var("AGENTPAY_RELAY_DAEMON_TOKEN", "relay-secret");
        std::env::set_var("HOSTNAME", "daemon-host");

        let (base_url, request_rx, handle) = spawn_single_response_server("200 OK", "{}").await;
        let snapshot = sample_snapshot(&base_url);
        let client = Client::new();

        register_snapshot(
            &client,
            &base_url,
            "software",
            "2026-03-11T00:00:00Z",
            &snapshot,
            snapshot.ethereum_address.as_deref().expect("eth address"),
        )
        .await
        .expect("register snapshot");

        let captured = request_rx.await.expect("captured request");
        handle.await.expect("server");
        assert_eq!(captured.request_line, "POST /v1/daemon/register HTTP/1.1");
        assert_eq!(
            captured
                .headers
                .get("x-relay-daemon-token")
                .map(String::as_str),
            Some("relay-secret")
        );
        assert!(captured.body.contains("\"daemonId\":\""));
        assert!(captured.body.contains("\"signerBackend\":\"software\""));
        assert!(captured.body.contains("\"label\":\"daemon-host\""));
        assert!(captured.body.contains("\"approvalRequests\""));

        std::env::remove_var("AGENTPAY_RELAY_DAEMON_TOKEN");
        std::env::remove_var("HOSTNAME");
    }

    #[tokio::test]
    async fn poll_updates_posts_expected_request_and_deserializes_response() {
        let response_body = r#"{"items":[{"claimToken":"claim-token","daemonId":"daemon-1","payload":{"algorithm":"x25519-xchacha20poly1305-v1","ciphertextBase64":"aa","encapsulatedKeyBase64":"bb","nonceBase64":"cc"},"type":"manual_approval_decision","updateId":"update-1"}]}"#;
        let (base_url, request_rx, handle) =
            spawn_single_response_server("200 OK", &response_body).await;
        let client = Client::new();

        let response = poll_updates(&client, &base_url, "daemon-1")
            .await
            .expect("poll response");
        let captured = request_rx.await.expect("captured request");
        handle.await.expect("server");

        assert_eq!(
            captured.request_line,
            "POST /v1/daemon/poll-updates HTTP/1.1"
        );
        assert!(captured.body.contains("\"daemonId\":\"daemon-1\""));
        assert!(captured.body.contains("\"leaseSeconds\":30"));
        assert!(captured.body.contains("\"limit\":25"));
        assert_eq!(response.items.len(), 1);
        assert_eq!(response.items[0].daemon_id, "daemon-1");
    }

    #[tokio::test]
    async fn submit_feedback_posts_expected_payload() {
        let (base_url, request_rx, handle) = spawn_single_response_server("200 OK", "{}").await;
        let client = Client::new();

        submit_feedback(
            &client,
            &base_url,
            "claim-token",
            "daemon-1",
            "update-1",
            ProcessedFeedback {
                details: Some(BTreeMap::from([(
                    "approvalRequestId".to_string(),
                    "approval-1".to_string(),
                )])),
                message: Some("done".to_string()),
                status: "applied",
            },
        )
        .await
        .expect("submit feedback");

        let captured = request_rx.await.expect("captured request");
        handle.await.expect("server");
        assert_eq!(
            captured.request_line,
            "POST /v1/daemon/submit-feedback HTTP/1.1"
        );
        assert!(captured.body.contains("\"claimToken\":\"claim-token\""));
        assert!(captured.body.contains("\"status\":\"applied\""));
        assert!(captured
            .body
            .contains("\"approvalRequestId\":\"approval-1\""));
    }

    #[tokio::test]
    async fn process_update_rejects_invalid_payload_variants() {
        let daemon = InMemoryDaemon::new(
            "vault-password",
            SoftwareSignerBackend::default(),
            DaemonConfig::default(),
        )
        .expect("daemon");
        let snapshot = daemon
            .relay_registration_snapshot()
            .expect("relay snapshot");
        let expected_daemon_id = snapshot.relay_config.daemon_id_hex.clone();

        let mismatch = process_update(
            &daemon,
            &expected_daemon_id,
            &RelayEncryptedUpdateRecord {
                daemon_id: "wrong-daemon".to_string(),
                ..sample_update_record(
                    &expected_daemon_id,
                    RelayEncryptedPayload {
                        algorithm: "x25519-xchacha20poly1305-v1".to_string(),
                        ciphertext_base64: String::new(),
                        encapsulated_key_base64: String::new(),
                        nonce_base64: String::new(),
                    },
                )
            },
        )
        .await;
        assert_eq!(mismatch.status, "rejected");
        assert!(mismatch
            .message
            .as_deref()
            .is_some_and(|value| value.contains("does not match")));

        let unsupported = process_update(
            &daemon,
            &expected_daemon_id,
            &RelayEncryptedUpdateRecord {
                r#type: "other".to_string(),
                ..sample_update_record(
                    &expected_daemon_id,
                    RelayEncryptedPayload {
                        algorithm: "x25519-xchacha20poly1305-v1".to_string(),
                        ciphertext_base64: String::new(),
                        encapsulated_key_base64: String::new(),
                        nonce_base64: String::new(),
                    },
                )
            },
        )
        .await;
        assert_eq!(unsupported.status, "failed");
        assert!(unsupported
            .message
            .as_deref()
            .is_some_and(|value| value.contains("unsupported relay update type")));

        let invalid_json_payload = encrypt_payload(
            &snapshot.relay_config.daemon_public_key_hex,
            br#"{"not":"a manual approval payload"}"#,
        );
        let invalid_json = process_update(
            &daemon,
            &expected_daemon_id,
            &sample_update_record(&expected_daemon_id, invalid_json_payload),
        )
        .await;
        assert_eq!(invalid_json.status, "failed");
        assert!(invalid_json
            .message
            .as_deref()
            .is_some_and(|value| value.contains("invalid relay update payload")));

        let wrong_payload_daemon = encrypt_payload(
            &snapshot.relay_config.daemon_public_key_hex,
            &serde_json::to_vec(&serde_json::json!({
                "approvalId": Uuid::nil().to_string(),
                "daemonId": "wrong-daemon",
                "decision": "approve",
                "vaultPassword": "vault-password"
            }))
            .expect("json"),
        );
        let wrong_payload_daemon = process_update(
            &daemon,
            &expected_daemon_id,
            &sample_update_record(&expected_daemon_id, wrong_payload_daemon),
        )
        .await;
        assert_eq!(wrong_payload_daemon.status, "rejected");

        let target_mismatch_payload = encrypt_payload(
            &snapshot.relay_config.daemon_public_key_hex,
            &serde_json::to_vec(&serde_json::json!({
                "approvalId": Uuid::nil().to_string(),
                "daemonId": expected_daemon_id,
                "decision": "approve",
                "vaultPassword": "vault-password"
            }))
            .expect("json"),
        );
        let target_mismatch = process_update(
            &daemon,
            &expected_daemon_id,
            &RelayEncryptedUpdateRecord {
                target_approval_request_id: Some(Uuid::new_v4().to_string()),
                ..sample_update_record(&expected_daemon_id, target_mismatch_payload)
            },
        )
        .await;
        assert_eq!(target_mismatch.status, "rejected");

        let invalid_approval_id_payload = encrypt_payload(
            &snapshot.relay_config.daemon_public_key_hex,
            &serde_json::to_vec(&serde_json::json!({
                "approvalId": "not-a-uuid",
                "daemonId": expected_daemon_id,
                "decision": "approve",
                "vaultPassword": "vault-password"
            }))
            .expect("json"),
        );
        let invalid_approval_id = process_update(
            &daemon,
            &expected_daemon_id,
            &sample_update_record(&expected_daemon_id, invalid_approval_id_payload),
        )
        .await;
        assert_eq!(invalid_approval_id.status, "failed");
        assert!(invalid_approval_id
            .message
            .as_deref()
            .is_some_and(|value| value.contains("approval_id is not a UUID")));
    }
}
