//! `AuthenticateAgent`: verifies an agent token and reports the agent's identity
//! and the wallet addresses its vault key signs for. `AgentPolicySummary`:
//! the enabled policies that govern the agent, without limits or recipients.

use agentpay_api::{AgentAuth, AgentIdentity, AgentPolicyInfo, AgentPolicySummary};
use agentpay_domain::{EvmAddress, KeyAlgorithm, PolicyType, SolanaAddress, VaultKey};
use agentpay_signer::{SignerError, VaultSignerBackend};

use super::signing::ethereum_address_from_public_key_hex;
use super::solana::decode_public_key_hex_32;
use crate::{DaemonError, InMemoryDaemon};

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    pub(crate) fn authenticate_agent_impl(
        &self,
        auth: &AgentAuth,
    ) -> Result<AgentIdentity, DaemonError> {
        let agent_key = self.authenticate_agent(auth.agent_key_id, &auth.agent_auth_token)?;
        let vault_key = self
            .vault_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .get(&agent_key.vault_key_id)
            .cloned()
            .ok_or(DaemonError::UnknownVaultKey(agent_key.vault_key_id))?;

        let (evm_address, solana_address) = self.wallet_addresses(&vault_key)?;

        Ok(AgentIdentity {
            agent_key,
            vault_key,
            evm_address,
            solana_address,
        })
    }

    /// The EVM address (secp256k1 keys) and Solana address (backends that
    /// can sign for Solana) of a vault key.
    pub(super) fn wallet_addresses(
        &self,
        vault_key: &VaultKey,
    ) -> Result<(Option<EvmAddress>, Option<SolanaAddress>), DaemonError> {
        let evm_address = match vault_key.algorithm {
            KeyAlgorithm::Secp256k1 => {
                let address = ethereum_address_from_public_key_hex(&vault_key.public_key_hex)?;
                Some(parse_internal::<EvmAddress>(&address, "EVM address")?)
            }
            KeyAlgorithm::Ed25519 => None,
        };
        let solana_address = match self.signer_backend.solana_public_key_hex(vault_key.id) {
            Ok(public_key_hex) => {
                let public_key = decode_public_key_hex_32(&public_key_hex)?;
                let address = solana_sdk::pubkey::Pubkey::new_from_array(public_key).to_string();
                Some(parse_internal::<SolanaAddress>(&address, "Solana address")?)
            }
            // Backends that cannot sign for Solana (the Linux TPM) have no Solana address.
            Err(SignerError::Unsupported(_)) => None,
            Err(err) => return Err(DaemonError::Signer(err)),
        };
        Ok((evm_address, solana_address))
    }

    /// The enabled policies attached to the agent, in evaluation order
    /// (priority, then id), exactly as the policy engine selects them.
    pub(crate) fn agent_policy_summary_impl(
        &self,
        auth: &AgentAuth,
    ) -> Result<AgentPolicySummary, DaemonError> {
        let agent_key = self.authenticate_agent(auth.agent_key_id, &auth.agent_auth_token)?;
        let mut policies: Vec<AgentPolicyInfo> = self
            .policies
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .values()
            .filter(|policy| policy.enabled && agent_key.policies.applies_to(policy.id))
            .map(|policy| AgentPolicyInfo {
                id: policy.id,
                priority: policy.priority,
                policy_type: policy.policy_type,
                assets: policy.assets.clone(),
                networks: policy.networks.clone(),
            })
            .collect();
        policies.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
        let spending = policies
            .iter()
            .filter(|policy| policy.policy_type != PolicyType::Eip712Signing)
            .count();
        Ok(AgentPolicySummary {
            attachment: agent_key.policies,
            policies,
            spending_policy_count: u32::try_from(spending).unwrap_or(u32::MAX),
        })
    }
}

/// Parses an address the daemon derived itself; a failure is an internal error.
fn parse_internal<T: std::str::FromStr>(value: &str, what: &str) -> Result<T, DaemonError> {
    value.parse().map_err(|_| {
        DaemonError::Signer(SignerError::Internal(format!(
            "derived {what} is not valid"
        )))
    })
}
