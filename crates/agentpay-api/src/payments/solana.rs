//! Solana transfers: `TransferSol` (native SOL) and `TransferSpl` (SPL Token
//! and Token-2022), with their shared options and result.
//!
//! # Flow
//!
//! For either method the payments service:
//!
//! 1. resolves `network` to a configured Solana chain (`family: "solana"`) and
//!    checks, once per RPC URL, that the endpoint serves that cluster (its
//!    genesis hash; skipped for loopback URLs, which run local validators);
//! 2. reads what the transfer needs from the chain: a recent blockhash or the
//!    durable nonce, the mint and both associated token accounts (SPL), the
//!    Token-2022 transfer fee, and a priority fee estimate;
//! 3. asks the signer daemon to sign a typed `SolanaSolTransfer` /
//!    `SolanaSplTransfer` action as the calling agent, so the agent's policies
//!    apply. The signer daemon builds the transaction itself from the action;
//! 4. decodes the signed transaction and **verifies** that it is exactly what
//!    was asked for (fee payer and single signer, blockhash or nonce, nonce
//!    advance, one transfer with the expected source, recipient, mint,
//!    amount, decimals, and fee, and priority fees within the caps); a
//!    mismatch fails with `SignedTransactionMismatch` and nothing is sent;
//! 5. with `broadcast`, sends it and, with `wait_for_confirmation`, polls its
//!    status for up to 30 seconds.
//!
//! The fee payer, signer, and source owner is always the agent's own Solana
//! wallet (`AgentIdentity.solana_address`).
//!
//! # Blockhash or durable nonce
//!
//! A transaction built on a recent blockhash expires after about a minute. A
//! **durable nonce** transaction instead uses the value stored in a nonce
//! account and stays valid until that account is advanced, which the
//! transaction itself does as its first instruction. See
//! [`SolanaNonceMode`]. The default (`auto`) uses the agent's **managed nonce
//! account** when broadcasting: an account derived from the wallet with the
//! seed `agentpay-<chain_id>-nonce`, created (wallet maintenance, about
//! 0.0015 SOL of rent, outside spending policies) through the signer daemon's
//! `SolanaNonceAccountCreate` action the first time it is needed.
//!
//! # Manual approval
//!
//! Only durable nonce transfers can wait for an operator: a blockhash would
//! expire first, so the signer daemon refuses manual approval for them. When
//! a policy holds a transfer, the call waits up to `approval_wait_secs` and
//! then returns
//! [`ManualApprovalPending`](crate::payments::PaymentsRpcResponse::ManualApprovalPending)
//! (the result shared with the EVM methods; `payment` is `null` and `action`
//! is the stored Solana action). The durable nonce is what makes resuming
//! possible: the transaction stays valid until the nonce account is
//! advanced. The service stores the exact signing action it sent, and
//! resends it when the same agent resends the same call (same network,
//! recipient, mint, amount, and options) or calls `ResumeApproved` with the
//! approval request id, so the approval applies even though a fresh priority
//! fee estimate would differ. If the nonce account was advanced in the
//! meantime, the stored action can never land: resending the call discards
//! it and creates a new approval request, and `ResumeApproved` fails with
//! `InvalidRequest`.
//!
//! # Associated token accounts
//!
//! `TransferSpl` moves tokens between the associated token accounts of the
//! wallet and of `to`. Both must already exist: the signed transaction never
//! creates accounts, so a missing one fails with `InvalidRequest` before
//! anything is signed. Token-2022 mints with a transfer hook are refused;
//! mints with a transfer fee use `transfer_checked_with_fee` with the fee for
//! the current epoch.

use agentpay_domain::schema::DecimalU128;
use agentpay_domain::{u128_as_decimal_string, SolanaAddress, SolanaTokenProgram};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::auth::AgentAuth;

/// Longest `approval_wait_secs` the service honors (10 minutes).
pub const SOLANA_MAX_APPROVAL_WAIT_SECS: u64 = 600;

/// `TransferSol`: send native SOL from the agent's wallet.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`SolanaTransfer`](crate::payments::PaymentsRpcResponse::SolanaTransfer), or [`ManualApprovalPending`](crate::payments::PaymentsRpcResponse::ManualApprovalPending) |
/// | Side effects | one policy-checked signature (counts toward the agent's limits); with `broadcast`, a transaction on chain; may create the managed nonce account (one more transaction) |
/// | Idempotent | no: every successful call signs a new transfer. While a manual approval is pending, resending the same call resumes it |
///
/// The amount is in lamports (`base_units`) or SOL (`decimal`, at most 9
/// fractional digits).
///
/// **Errors:** `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`
/// (policy denial, rejected approval, ...), `InvalidRequest`, `ChainRpc`,
/// `SignedTransactionMismatch`, `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/solana/TransferSol.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/solana/TransferSol.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct TransferSolParams {
    /// Agent credentials.
    pub auth: AgentAuth,
    /// Chain key of a configured Solana chain, for example `"solana"` or
    /// `"solana-devnet"`.
    pub network: String,
    /// Recipient wallet.
    pub to: SolanaAddress,
    /// Amount to send.
    pub amount: SolanaAmount,
    /// Signing, nonce, fee, and broadcast options; all optional.
    #[serde(default)]
    pub options: SolanaTransferOptions,
}

/// `TransferSpl`: send SPL Token or Token-2022 tokens from the agent's
/// associated token account to the recipient's.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`SolanaTransfer`](crate::payments::PaymentsRpcResponse::SolanaTransfer), or [`ManualApprovalPending`](crate::payments::PaymentsRpcResponse::ManualApprovalPending) |
/// | Side effects | one policy-checked signature (counts toward the agent's limits); with `broadcast`, a transaction on chain; may create the managed nonce account (one more transaction) |
/// | Idempotent | no: every successful call signs a new transfer. While a manual approval is pending, resending the same call resumes it |
///
/// The token program and decimals come from the mint account on chain. The
/// amount is in token base units (`base_units`) or whole tokens (`decimal`,
/// at most the mint's decimals of fractional digits). For a Token-2022 mint
/// with a transfer fee, the recipient receives the amount minus
/// `transfer_fee_wei`.
///
/// **Errors:** `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`
/// (policy denial, rejected approval, ...), `InvalidRequest` (unknown or non-Solana network, not a token mint,
/// transfer hook, missing associated token account, ...), `ChainRpc`,
/// `SignedTransactionMismatch`, `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/solana/TransferSpl.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/solana/TransferSpl.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct TransferSplParams {
    /// Agent credentials.
    pub auth: AgentAuth,
    /// Chain key of a configured Solana chain.
    pub network: String,
    /// Token mint, owned by the SPL Token or the Token-2022 program.
    pub mint: SolanaAddress,
    /// Recipient wallet (the owner of the destination associated token account).
    pub to: SolanaAddress,
    /// Amount to send.
    pub amount: SolanaAmount,
    /// Signing, nonce, fee, and broadcast options; all optional.
    #[serde(default)]
    pub options: SolanaTransferOptions,
}

/// A transfer amount. JSON: `{"base_units": "1500000"}` or `{"decimal": "1.5"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum SolanaAmount {
    /// In the asset's smallest unit (lamports, token base units), as a
    /// decimal string. Must be between 1 and 2^64 - 1.
    BaseUnits(
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        u128,
    ),
    /// In whole units (SOL, tokens) as a plain decimal string such as
    /// `"0.25"`: no sign, exponent, or more fractional digits than the asset
    /// has decimals.
    Decimal(String),
}

/// Options shared by `TransferSol` and `TransferSpl`. Every field may be
/// omitted; `{}` means sign only, with the defaults below.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SolanaTransferOptions {
    /// Send the signed transaction to the network. Default `false`: return
    /// the signed transaction (`raw_tx_base64`) without sending it.
    #[serde(default)]
    pub broadcast: bool,
    /// After broadcasting, poll the signature status for up to 30 seconds
    /// until it is `confirmed` or fails. Default `true`; ignored without
    /// `broadcast`.
    #[serde(default = "default_true")]
    pub wait_for_confirmation: bool,
    /// Recent blockhash or durable nonce. Default `"auto"`.
    #[serde(default)]
    pub nonce: SolanaNonceMode,
    /// Compute unit limit. Default: 5,000 (SOL) or 20,000 (SPL). Must be
    /// between 1 and 1,400,000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub compute_unit_limit: Option<u32>,
    /// Priority fee price in micro-lamports per compute unit. Default: the
    /// median of the cluster's recent non-zero prioritization fees, clamped
    /// to the caps, or none. An explicit price above the caps is refused.
    /// Caps: at most 10,000,000 micro-lamports per unit and 0.01 SOL of
    /// priority fee per transaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub compute_unit_price_micro_lamports: Option<u64>,
    /// How long to wait for an operator when a policy requires manual
    /// approval before returning `ManualApprovalPending`, in seconds (at
    /// most 600). Default: the service's configured wait (none unless
    /// configured). Use a response timeout longer than this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub approval_wait_secs: Option<u64>,
    /// Include `raw_tx_base64` in the result even when broadcasting. Without
    /// `broadcast` it is always included.
    #[serde(default)]
    pub reveal_raw_tx: bool,
}

impl Default for SolanaTransferOptions {
    fn default() -> Self {
        Self {
            broadcast: false,
            wait_for_confirmation: true,
            nonce: SolanaNonceMode::default(),
            compute_unit_limit: None,
            compute_unit_price_micro_lamports: None,
            approval_wait_secs: None,
            reveal_raw_tx: false,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Which value the transaction uses as its blockhash.
///
/// JSON: `"auto"`, `"recent_blockhash"`, `"managed"`, or
/// `{"account": "<nonce account>"}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum SolanaNonceMode {
    /// `managed` when broadcasting, `recent_blockhash` when only signing.
    #[default]
    Auto,
    /// A recent blockhash: valid for about a minute and never eligible for
    /// manual approval.
    RecentBlockhash,
    /// The agent's managed durable nonce account, created first if missing.
    Managed,
    /// An existing durable nonce account whose authority is the agent's
    /// wallet. It is never created.
    Account(SolanaAddress),
}

/// Result of `TransferSol` and `TransferSpl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SolanaTransferResult {
    /// The chain key the transfer used.
    pub network: String,
    /// Internal Solana network id of that chain (`900000001` to `900000003`).
    pub chain_id: u64,
    /// The agent's wallet: fee payer, only signer, and source owner.
    pub fee_payer: SolanaAddress,
    /// What the transaction transfers.
    pub transfer: SolanaTransferDetails,
    /// The transaction's blockhash: a recent blockhash, or the durable nonce
    /// value when `durable_nonce` is present.
    pub recent_blockhash: String,
    /// The durable nonce account the transaction advances, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub durable_nonce: Option<SolanaDurableNonce>,
    /// Compute unit limit set by the transaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub compute_unit_limit: Option<u32>,
    /// Priority fee price set by the transaction, in micro-lamports per unit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub compute_unit_price_micro_lamports: Option<u64>,
    /// The transaction signature (base58), which is also its id.
    pub signature: String,
    /// The signed transaction (bincode, base64). Present when not
    /// broadcasting, or with `reveal_raw_tx`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub raw_tx_base64: Option<String>,
    /// What happened on the network; absent when not broadcasting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub broadcast: Option<SolanaBroadcast>,
}

/// The transfer a signed transaction performs. JSON: internally tagged by
/// `kind` (`"sol"` or `"spl"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SolanaTransferDetails {
    /// A native SOL transfer (`TransferSol`).
    Sol {
        /// Recipient wallet.
        to: SolanaAddress,
        /// Amount in lamports.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        amount_wei: u128,
    },
    /// A token transfer (`TransferSpl`).
    Spl {
        /// Token mint.
        mint: SolanaAddress,
        /// Recipient wallet.
        recipient_owner: SolanaAddress,
        /// The agent's associated token account for the mint.
        source_token_account: SolanaAddress,
        /// The recipient's associated token account for the mint.
        destination_token_account: SolanaAddress,
        /// Program that owns the mint: `"token"` or `"token_2022"`.
        token_program: SolanaTokenProgram,
        /// Mint decimals, enforced by `transfer_checked`.
        decimals: u8,
        /// Amount debited from the source, in token base units.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        amount_wei: u128,
        /// Token-2022 transfer fee withheld from the amount, in base units;
        /// present exactly when the mint has a transfer fee configuration
        /// (the transaction then uses `transfer_checked_with_fee`).
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "agentpay_domain::u128_as_decimal_string::option"
        )]
        #[schemars(with = "Option<DecimalU128>")]
        #[ts(optional, as = "Option<DecimalU128>")]
        transfer_fee_wei: Option<u128>,
    },
}

/// The durable nonce account a transaction advances.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SolanaDurableNonce {
    /// The nonce account.
    pub account: SolanaAddress,
    /// Whether it is the agent's managed nonce account.
    pub managed: bool,
    /// Signature of the transaction that created the managed nonce account
    /// during this call; absent when it already existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub created_signature: Option<String>,
}

/// Network outcome of a broadcast transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SolanaBroadcast {
    /// Last known status.
    pub status: SolanaTxStatus,
    /// Slot the status was observed in, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub slot: Option<u64>,
    /// The transaction error reported by the cluster, when `status` is `"failed"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub error: Option<String>,
}

/// Status of a broadcast transaction. JSON: snake case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum SolanaTxStatus {
    /// Accepted by the RPC node; not waited for (`wait_for_confirmation: false`).
    Submitted,
    /// Confirmed by a supermajority of the cluster.
    Confirmed,
    /// Finalized (rooted).
    Finalized,
    /// Executed and failed; the fee was charged, nothing was transferred.
    Failed,
    /// Not confirmed within the wait. A durable nonce transaction may still
    /// land later; a blockhash transaction expires within about a minute.
    TimedOut,
}
