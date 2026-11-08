//! Tempo session channel registry: binds channels to the opening agent key and
//! caps vouchers at the deposited total.

use std::collections::HashMap;

use agentpay_domain::{AgentAction, AgentKey};
use agentpay_signer::VaultSignerBackend;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::signing::ethereum_address_from_public_key_hex;
use crate::{DaemonError, InMemoryDaemon};

/// Upper bound on Tempo session channels tracked in daemon state. The oldest
/// channels (by open time) are evicted first.
pub(super) const MAX_TRACKED_TEMPO_CHANNELS: usize = 1024;

/// Daemon-side record of a Tempo session channel opened through this daemon.
///
/// Vouchers skip spending-window limits because the channel deposit was already
/// charged when the open/top-up transaction was signed. This record ties every
/// voucher and top-up back to the agent key that opened the channel and caps
/// voucher amounts at what that agent actually deposited.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct TempoChannelRecord {
    pub(super) agent_key_id: Uuid,
    pub(super) deposited_total_wei: u128,
    pub(super) opened_at: OffsetDateTime,
}

/// How a signed action interacts with the Tempo session channel registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TempoChannelRole {
    /// Opens a channel and registers its initial deposit.
    Open { deposit_wei: u128 },
    /// Adds to the deposit of a channel the same agent key opened.
    TopUp { additional_deposit_wei: u128 },
    /// Redistributes the escrowed deposit (voucher or close authorization); the
    /// cumulative amount is capped at the deposit registered for the channel.
    Redistribute { cumulative_amount_wei: u128 },
}

/// A Tempo session action resolved to its channel id and registry role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TempoChannelAction {
    /// Lowercase `0x`-prefixed channel id.
    pub(super) channel_id_hex: String,
    pub(super) role: TempoChannelRole,
}

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    /// Tempo session actions name the channel payer explicitly; it must be the
    /// wallet that signs, so an agent cannot fund or vouch for someone else's channel.
    fn ensure_tempo_payer_is_wallet(
        &self,
        agent_key: &AgentKey,
        payer: &agentpay_domain::EvmAddress,
    ) -> Result<(), DaemonError> {
        let public_key_hex = self
            .vault_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .get(&agent_key.vault_key_id)
            .map(|vault_key| vault_key.public_key_hex.clone())
            .ok_or(DaemonError::UnknownVaultKey(agent_key.vault_key_id))?;
        let wallet = ethereum_address_from_public_key_hex(&public_key_hex)?;
        if !wallet.eq_ignore_ascii_case(payer.as_str()) {
            return Err(DaemonError::InvalidAction(
                "tempo session payer must be the signing wallet address".to_string(),
            ));
        }
        Ok(())
    }

    /// Ties Tempo session actions to the signing wallet and the channel registry.
    ///
    /// Every channel action must name the signing wallet as payer. Vouchers and
    /// close authorizations bypass spending-window limits, so they are only
    /// accepted for a channel this daemon opened for the same agent key, and
    /// only up to the total that agent deposited into it. Top-ups must target a
    /// channel the same agent opened, and an open may not take over a channel
    /// already registered to another agent key.
    ///
    /// Classification comes from [`tempo_channel_action`]; an action that
    /// claims to be an escrow redistribution, or names a Tempo payer, without
    /// resolving to the matching channel role is rejected instead of skipping
    /// the registry.
    pub(super) fn ensure_tempo_channel_authorized(
        &self,
        agent_key: &AgentKey,
        action: &AgentAction,
    ) -> Result<(), DaemonError> {
        let channel_action = tempo_channel_action(action)?;
        let payer = action.tempo_payer();
        let channel_action = match (channel_action, payer) {
            (None, None) if !action.is_escrow_redistribution() => return Ok(()),
            (Some(channel_action), Some(payer)) => {
                let is_redistribution =
                    matches!(channel_action.role, TempoChannelRole::Redistribute { .. });
                if is_redistribution != action.is_escrow_redistribution() {
                    return Err(DaemonError::InvalidAction(
                        "tempo session action has an inconsistent escrow classification"
                            .to_string(),
                    ));
                }
                self.ensure_tempo_payer_is_wallet(agent_key, payer)?;
                channel_action
            }
            _ => {
                return Err(DaemonError::InvalidAction(
                    "tempo session action is not bound to a tracked channel".to_string(),
                ))
            }
        };
        let TempoChannelAction {
            channel_id_hex,
            role,
        } = channel_action;
        let channels = self
            .tempo_channels
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?;
        let record = channels.get(&channel_id_hex);
        if let TempoChannelRole::Open { .. } = role {
            return match record {
                Some(record) if record.agent_key_id != agent_key.id => {
                    Err(DaemonError::InvalidAction(format!(
                        "tempo session channel {channel_id_hex} is already registered to a \
                         different agent key"
                    )))
                }
                _ => Ok(()),
            };
        }
        let Some(record) = record else {
            return Err(DaemonError::InvalidAction(format!(
                "tempo session channel {channel_id_hex} is unknown to this daemon; the channel \
                 must be opened through this daemon before it can be topped up or vouched for"
            )));
        };
        if record.agent_key_id != agent_key.id {
            return Err(DaemonError::InvalidAction(format!(
                "tempo session channel {channel_id_hex} was opened by a different agent key"
            )));
        }
        if let TempoChannelRole::Redistribute {
            cumulative_amount_wei,
        } = role
        {
            if cumulative_amount_wei > record.deposited_total_wei {
                return Err(DaemonError::InvalidAction(format!(
                    "tempo session voucher cumulative amount {} exceeds the {} deposited into \
                     channel {channel_id_hex} through this daemon",
                    cumulative_amount_wei, record.deposited_total_wei
                )));
            }
        }
        Ok(())
    }

    /// Records the deposit carried by a signed Tempo session open or top-up.
    pub(super) fn record_tempo_channel_deposit(
        &self,
        agent_key_id: Uuid,
        action: &AgentAction,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        let Some(TempoChannelAction {
            channel_id_hex,
            role,
        }) = tempo_channel_action(action)?
        else {
            return Ok(());
        };
        let mut channels = self
            .tempo_channels
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?;
        match role {
            TempoChannelRole::Open { deposit_wei } => match channels.get_mut(&channel_id_hex) {
                Some(record) if record.agent_key_id == agent_key_id => {
                    // Re-signing an open (e.g. a retried broadcast) replaces the same
                    // initial deposit instead of adding to it.
                    record.deposited_total_wei = record.deposited_total_wei.max(deposit_wei);
                }
                _ => {
                    Self::trim_tempo_channels(
                        &mut channels,
                        MAX_TRACKED_TEMPO_CHANNELS.saturating_sub(1),
                    );
                    channels.insert(
                        channel_id_hex,
                        TempoChannelRecord {
                            agent_key_id,
                            deposited_total_wei: deposit_wei,
                            opened_at: now,
                        },
                    );
                }
            },
            TempoChannelRole::TopUp {
                additional_deposit_wei,
            } => {
                if let Some(record) = channels
                    .get_mut(&channel_id_hex)
                    .filter(|record| record.agent_key_id == agent_key_id)
                {
                    record.deposited_total_wei = record
                        .deposited_total_wei
                        .saturating_add(additional_deposit_wei);
                }
            }
            TempoChannelRole::Redistribute { .. } => {}
        }
        Ok(())
    }

    /// Evicts the oldest tracked Tempo channels (by open time, then channel id
    /// for determinism) until at most `max_entries` remain.
    pub(super) fn trim_tempo_channels(
        channels: &mut HashMap<String, TempoChannelRecord>,
        max_entries: usize,
    ) {
        if channels.len() <= max_entries {
            return;
        }
        let excess = channels.len() - max_entries;
        let mut ordered = channels
            .iter()
            .map(|(channel_id, record)| (record.opened_at, channel_id.clone()))
            .collect::<Vec<_>>();
        ordered.sort_unstable();
        for (_, channel_id) in ordered.into_iter().take(excess) {
            channels.remove(&channel_id);
        }
    }
}

/// Resolves a Tempo session action to its channel id and registry role.
///
/// This is the single source of truth for how actions interact with the Tempo
/// channel registry. The match is exhaustive on purpose: a new action variant
/// must decide here whether it opens, tops up, or redistributes a channel, so
/// it can never silently skip the registry or the deposit cap.
pub(super) fn tempo_channel_action(
    action: &AgentAction,
) -> Result<Option<TempoChannelAction>, DaemonError> {
    let (channel_id, role) = match action {
        AgentAction::TempoSessionV2OpenTransaction { authorization } => (
            authorization.channel_id(),
            TempoChannelRole::Open {
                deposit_wei: authorization.deposit_wei,
            },
        ),
        AgentAction::TempoSessionV2TopUpTransaction { authorization } => (
            authorization.channel_id_bytes32(),
            TempoChannelRole::TopUp {
                additional_deposit_wei: authorization.additional_deposit_wei,
            },
        ),
        AgentAction::TempoSessionV2Voucher { authorization } => (
            authorization.channel_id_bytes32(),
            TempoChannelRole::Redistribute {
                cumulative_amount_wei: authorization.cumulative_amount_wei,
            },
        ),
        AgentAction::TempoSessionV2CloseAuthorization { authorization } => (
            authorization.voucher.channel_id_bytes32(),
            TempoChannelRole::Redistribute {
                cumulative_amount_wei: authorization.voucher.cumulative_amount_wei,
            },
        ),
        AgentAction::Approve { .. }
        | AgentAction::Transfer { .. }
        | AgentAction::TransferNative { .. }
        | AgentAction::Eip3009TransferWithAuthorization { .. }
        | AgentAction::Eip3009ReceiveWithAuthorization { .. }
        | AgentAction::Eip712TypedData { .. }
        | AgentAction::BroadcastTx { .. }
        | AgentAction::SolanaSolTransfer { .. }
        | AgentAction::SolanaSplTransfer { .. }
        | AgentAction::SolanaNonceAccountCreate { .. }
        | AgentAction::SolanaPaymentTransaction { .. }
        | AgentAction::Permit2WitnessTransfer { .. } => return Ok(None),
    };
    let channel_id = channel_id.map_err(|error| DaemonError::InvalidAction(error.to_string()))?;
    Ok(Some(TempoChannelAction {
        channel_id_hex: format!("0x{}", hex::encode(channel_id)),
        role,
    }))
}
