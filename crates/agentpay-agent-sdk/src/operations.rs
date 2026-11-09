//! The [`AgentOperations`] trait: the high-level signing surface exposed to agents.

use agentpay_domain::{
    BroadcastTx, Eip3009Transfer, Eip712TypedData, EvmAddress, NonceReservation, Signature,
    SolanaAddress, SolanaTokenProgram, TempoSessionV2CloseAuthorization,
    TempoSessionV2OpenTransaction, TempoSessionV2TopUpTransaction, TempoSessionV2Voucher,
};
use async_trait::async_trait;

use crate::AgentSdkError;

/// High-level agent operations.
// `async_trait` marks each generated method `#[must_use]` on top of the boxed
// future it returns, which newer clippy reports as `double_must_use`. The
// Solana transfer methods mirror the full instruction field set.
#[allow(clippy::double_must_use, clippy::too_many_arguments)]
#[async_trait]
pub trait AgentOperations: Send + Sync {
    /// Requests an ERC-20 `approve` signature.
    async fn approve(
        &self,
        chain_id: u64,
        token: EvmAddress,
        spender: EvmAddress,
        amount_wei: u128,
    ) -> Result<Signature, AgentSdkError>;

    /// Requests an ERC-20 `transfer` signature.
    async fn transfer(
        &self,
        chain_id: u64,
        token: EvmAddress,
        to: EvmAddress,
        amount_wei: u128,
    ) -> Result<Signature, AgentSdkError>;

    /// Requests a native ETH transfer signature.
    async fn transfer_native(
        &self,
        chain_id: u64,
        to: EvmAddress,
        amount_wei: u128,
    ) -> Result<Signature, AgentSdkError>;

    /// Requests a signed native SOL transfer transaction.
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
    ) -> Result<Signature, AgentSdkError>;

    /// Requests a signed SPL/Token-2022 token transfer transaction.
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
    ) -> Result<Signature, AgentSdkError>;

    /// Requests a signed Solana durable nonce account creation transaction.
    async fn solana_nonce_account_create(
        &self,
        chain_id: u64,
        recent_blockhash: String,
        fee_payer: SolanaAddress,
        nonce_account: SolanaAddress,
        seed: String,
        rent_lamports: u128,
    ) -> Result<Signature, AgentSdkError>;

    /// Requests an EIP-3009 `transferWithAuthorization` signature.
    async fn eip3009_transfer_with_authorization(
        &self,
        authorization: Eip3009Transfer,
    ) -> Result<Signature, AgentSdkError>;

    /// Requests an EIP-3009 `receiveWithAuthorization` signature.
    async fn eip3009_receive_with_authorization(
        &self,
        authorization: Eip3009Transfer,
    ) -> Result<Signature, AgentSdkError>;

    /// Requests a Tempo sessions v2 (TIP-1034 reserve) open-transaction digest signature.
    async fn tempo_session_v2_open_transaction(
        &self,
        authorization: TempoSessionV2OpenTransaction,
    ) -> Result<Signature, AgentSdkError>;

    /// Requests a Tempo sessions v2 (TIP-1034 reserve) top-up transaction digest signature.
    async fn tempo_session_v2_top_up_transaction(
        &self,
        authorization: TempoSessionV2TopUpTransaction,
    ) -> Result<Signature, AgentSdkError>;

    /// Requests a Tempo sessions v2 (TIP-1034 reserve) voucher digest signature.
    async fn tempo_session_v2_voucher(
        &self,
        authorization: TempoSessionV2Voucher,
    ) -> Result<Signature, AgentSdkError>;

    /// Requests a Tempo sessions v2 (TIP-1034 reserve) close-authorization digest signature.
    async fn tempo_session_v2_close_authorization(
        &self,
        authorization: TempoSessionV2CloseAuthorization,
    ) -> Result<Signature, AgentSdkError>;

    /// Requests an arbitrary EIP-712 typed-data signature.
    async fn eip712_typed_data(
        &self,
        typed_data: Eip712TypedData,
    ) -> Result<Signature, AgentSdkError>;

    /// Parses ERC-20 calldata and signs derived action (`approve` / `transfer`).
    async fn sign_erc20_calldata(
        &self,
        chain_id: u64,
        token: EvmAddress,
        calldata: Vec<u8>,
    ) -> Result<Signature, AgentSdkError>;

    /// Requests signature authorization for a raw broadcast transaction.
    async fn broadcast_tx(&self, tx: BroadcastTx) -> Result<Signature, AgentSdkError>;

    /// Reserves a nonce lease for a future broadcast transaction.
    async fn reserve_broadcast_nonce(
        &self,
        chain_id: u64,
        nonce: u64,
    ) -> Result<NonceReservation, AgentSdkError>;

    /// Explicitly releases an unused nonce reservation.
    async fn release_broadcast_nonce(
        &self,
        reservation_id: uuid::Uuid,
    ) -> Result<(), AgentSdkError>;
}
