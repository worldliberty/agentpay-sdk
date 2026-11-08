//! [`AgentSdk`], the default [`AgentOperations`] implementation.
//!
//! Every operation builds an [`AgentAction`], validates it locally, and sends
//! it to the daemon as a short-lived [`SignRequest`] authenticated with the
//! agent's key id and bearer token. Broadcast transactions additionally
//! reserve their exact nonce first and release it if signing fails.

use std::sync::Arc;

use agentpay_domain::{
    action_from_erc20_calldata, AgentAction, AgentCredentials, BroadcastTx, Eip3009Transfer,
    Eip712TypedData, EvmAddress, NonceReleaseRequest, NonceReservation, NonceReservationRequest,
    SignRequest, Signature, SolanaAddress, SolanaNonceAccountCreate, SolanaSolTransfer,
    SolanaSplTransfer, SolanaTokenProgram, TempoSessionV2CloseAuthorization,
    TempoSessionV2OpenTransaction, TempoSessionV2TopUpTransaction, TempoSessionV2Voucher,
};
use agentpay_signerd::{DaemonError, KeyManagerDaemonApi};
use async_trait::async_trait;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{AgentOperations, AgentSdkError};

/// Default SDK implementation backed by a daemon API client.
pub struct AgentSdk<D>
where
    D: KeyManagerDaemonApi + ?Sized,
{
    daemon: Arc<D>,
    agent_key_id: Uuid,
    agent_auth_token: Zeroizing<String>,
}

impl<D> AgentSdk<D>
where
    D: KeyManagerDaemonApi + ?Sized,
{
    const REQUEST_TTL: Duration = Duration::minutes(2);

    /// Creates SDK bound to agent credentials.
    #[must_use]
    pub fn new(daemon: Arc<D>, agent_credentials: AgentCredentials) -> Self {
        Self {
            daemon,
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
        }
    }

    /// Creates SDK from raw agent key id and auth token.
    ///
    /// This constructor is useful for CLIs and integrations where only the
    /// stable key id + bearer token are persisted.
    #[must_use]
    pub fn new_with_key_id_and_token<T>(
        daemon: Arc<D>,
        agent_key_id: Uuid,
        agent_auth_token: T,
    ) -> Self
    where
        T: Into<Zeroizing<String>>,
    {
        Self {
            daemon,
            agent_key_id,
            agent_auth_token: agent_auth_token.into(),
        }
    }

    async fn sign_action(&self, action: AgentAction) -> Result<Signature, AgentSdkError> {
        action.validate()?;
        let now = OffsetDateTime::now_utc();
        let payload = serde_json::to_vec(&action)
            .map_err(|err| AgentSdkError::Serialization(err.to_string()))?;
        let request = SignRequest {
            request_id: uuid::Uuid::new_v4(),
            agent_key_id: self.agent_key_id,
            agent_auth_token: self.agent_auth_token.clone(),
            payload,
            action,
            requested_at: now,
            expires_at: now + Self::REQUEST_TTL,
        };

        Ok(self.daemon.sign_for_agent(request).await?)
    }
}

#[async_trait]
impl<D> AgentOperations for AgentSdk<D>
where
    D: KeyManagerDaemonApi + ?Sized,
{
    async fn approve(
        &self,
        chain_id: u64,
        token: EvmAddress,
        spender: EvmAddress,
        amount_wei: u128,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::Approve {
            chain_id,
            token,
            spender,
            amount_wei,
        })
        .await
    }

    async fn transfer(
        &self,
        chain_id: u64,
        token: EvmAddress,
        to: EvmAddress,
        amount_wei: u128,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::Transfer {
            chain_id,
            token,
            to,
            amount_wei,
        })
        .await
    }

    async fn transfer_native(
        &self,
        chain_id: u64,
        to: EvmAddress,
        amount_wei: u128,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::TransferNative {
            chain_id,
            to,
            amount_wei,
        })
        .await
    }

    async fn solana_spl_transfer(
        &self,
        chain_id: u64,
        recent_blockhash: String,
        durable_nonce_account: Option<SolanaAddress>,
        fee_payer: SolanaAddress,
        mint: SolanaAddress,
        recipient_owner: SolanaAddress,
        amount_wei: u128,
        decimals: u8,
        token_program: SolanaTokenProgram,
        transfer_fee_wei: Option<u128>,
        compute_unit_limit: Option<u32>,
        compute_unit_price_micro_lamports: Option<u64>,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::SolanaSplTransfer {
            transfer: SolanaSplTransfer {
                chain_id,
                recent_blockhash,
                durable_nonce_account,
                fee_payer,
                mint,
                recipient_owner,
                amount_wei,
                decimals,
                token_program,
                transfer_fee_wei,
                compute_unit_limit,
                compute_unit_price_micro_lamports,
            },
        })
        .await
    }

    async fn solana_sol_transfer(
        &self,
        chain_id: u64,
        recent_blockhash: String,
        durable_nonce_account: Option<SolanaAddress>,
        fee_payer: SolanaAddress,
        to: SolanaAddress,
        amount_wei: u128,
        compute_unit_limit: Option<u32>,
        compute_unit_price_micro_lamports: Option<u64>,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::SolanaSolTransfer {
            transfer: SolanaSolTransfer {
                chain_id,
                recent_blockhash,
                durable_nonce_account,
                fee_payer,
                to,
                amount_wei,
                compute_unit_limit,
                compute_unit_price_micro_lamports,
            },
        })
        .await
    }

    async fn solana_nonce_account_create(
        &self,
        chain_id: u64,
        recent_blockhash: String,
        fee_payer: SolanaAddress,
        nonce_account: SolanaAddress,
        seed: String,
        rent_lamports: u128,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::SolanaNonceAccountCreate {
            create: SolanaNonceAccountCreate {
                chain_id,
                recent_blockhash,
                fee_payer,
                nonce_account,
                seed,
                rent_lamports,
            },
        })
        .await
    }

    async fn eip3009_transfer_with_authorization(
        &self,
        authorization: Eip3009Transfer,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::Eip3009TransferWithAuthorization { authorization })
            .await
    }

    async fn eip3009_receive_with_authorization(
        &self,
        authorization: Eip3009Transfer,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::Eip3009ReceiveWithAuthorization { authorization })
            .await
    }

    async fn tempo_session_v2_open_transaction(
        &self,
        authorization: TempoSessionV2OpenTransaction,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::TempoSessionV2OpenTransaction { authorization })
            .await
    }

    async fn tempo_session_v2_top_up_transaction(
        &self,
        authorization: TempoSessionV2TopUpTransaction,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::TempoSessionV2TopUpTransaction { authorization })
            .await
    }

    async fn tempo_session_v2_voucher(
        &self,
        authorization: TempoSessionV2Voucher,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::TempoSessionV2Voucher { authorization })
            .await
    }

    async fn tempo_session_v2_close_authorization(
        &self,
        authorization: TempoSessionV2CloseAuthorization,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::TempoSessionV2CloseAuthorization { authorization })
            .await
    }

    async fn eip712_typed_data(
        &self,
        typed_data: Eip712TypedData,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::Eip712TypedData { typed_data })
            .await
    }

    async fn sign_erc20_calldata(
        &self,
        chain_id: u64,
        token: EvmAddress,
        calldata: Vec<u8>,
    ) -> Result<Signature, AgentSdkError> {
        let action = action_from_erc20_calldata(chain_id, token, &calldata)?;
        self.sign_action(action).await
    }

    async fn broadcast_tx(&self, mut tx: BroadcastTx) -> Result<Signature, AgentSdkError> {
        let requested_nonce = tx.nonce;
        let reservation = self
            .reserve_broadcast_nonce(tx.chain_id, requested_nonce)
            .await?;
        if reservation.nonce != requested_nonce {
            let _ = self
                .release_broadcast_nonce(reservation.reservation_id)
                .await;
            return Err(AgentSdkError::Daemon(DaemonError::InvalidNonceReservation(
                format!(
                    "requested exact nonce {requested_nonce} for chain_id {} but daemon reserved {}",
                    tx.chain_id, reservation.nonce
                ),
            )));
        }
        tx.nonce = reservation.nonce;

        match self.sign_action(AgentAction::BroadcastTx { tx }).await {
            Ok(signature) => Ok(signature),
            Err(err) => {
                let _ = self
                    .release_broadcast_nonce(reservation.reservation_id)
                    .await;
                Err(err)
            }
        }
    }

    async fn reserve_broadcast_nonce(
        &self,
        chain_id: u64,
        nonce: u64,
    ) -> Result<NonceReservation, AgentSdkError> {
        let now = OffsetDateTime::now_utc();
        let request = NonceReservationRequest {
            request_id: uuid::Uuid::new_v4(),
            agent_key_id: self.agent_key_id,
            agent_auth_token: self.agent_auth_token.clone(),
            chain_id,
            min_nonce: nonce,
            exact_nonce: true,
            requested_at: now,
            expires_at: now + Self::REQUEST_TTL,
        };
        Ok(self.daemon.reserve_nonce(request).await?)
    }

    async fn release_broadcast_nonce(
        &self,
        reservation_id: uuid::Uuid,
    ) -> Result<(), AgentSdkError> {
        let now = OffsetDateTime::now_utc();
        let request = NonceReleaseRequest {
            request_id: uuid::Uuid::new_v4(),
            agent_key_id: self.agent_key_id,
            agent_auth_token: self.agent_auth_token.clone(),
            reservation_id,
            requested_at: now,
            expires_at: now + Self::REQUEST_TTL,
        };
        Ok(self.daemon.release_nonce(request).await?)
    }
}
