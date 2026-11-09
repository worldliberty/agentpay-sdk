//! Payments service configuration: chains, tokens, RPC endpoints, and the
//! default network and asset, plus the `GetConfig`, `SetConfig`, and
//! `AddToken` methods and the read-only `LookupToken`.
//!
//! The payments service owns this configuration and stores it in its own
//! state directory (`config.json`, readable only by the service account), so
//! clients never edit a file: they read it with `GetConfig`, replace it with
//! `SetConfig`, or add one token with `AddToken`. Until the first change, the
//! service serves the built-in defaults shown in the `GetConfig` example.
//!
//! # Validation (`SetConfig`, `AddToken`)
//!
//! - Chain and token keys are 1 to 64 characters of `[a-z0-9._-]`.
//! - `chain_id` is between 1 and 2^53 - 1. Solana chains (`family: "solana"`)
//!   use the internal ids `900000001` (mainnet), `900000002` (devnet), and
//!   `900000003` (testnet); every other chain is `"evm"`.
//! - `rpc_url` is an `https` URL, or `http` to a loopback host, without
//!   embedded credentials.
//! - `fallback_rpc_urls` holds at most 4 URLs, each valid like `rpc_url`,
//!   none repeated and none equal to `rpc_url`; it must be empty when
//!   `rpc_url` is `null`.
//! - Every entry of a token's `chains` names a configured chain key and repeats
//!   that chain's `chain_id`. A native entry has no `address`; any other entry
//!   has an EVM address (EVM chains) or a base58 mint (Solana chains).
//! - `decimals` is at most 36; `recommended_limits` are non-negative decimal
//!   strings in whole tokens.
//! - `default_network` names a configured chain, and `default_asset` names a
//!   token that has an entry for it.
//! - At most 256 chains and 256 tokens.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::auth::AgentAuth;

/// The complete payments service configuration.
///
/// Maps are keyed by lowercase keys and serialized in key order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct PaymentsConfig {
    /// Chain key used for payments that name no network (`"bsc"` by default).
    pub default_network: String,
    /// Token key used for payments that name no asset (`"usd1"` by default).
    pub default_asset: String,
    /// Configured chains by key, for example `"bsc"` or `"solana-mainnet"`.
    pub chains: BTreeMap<String, ChainProfile>,
    /// Configured tokens by key, for example `"usd1"` or `"usdc"`.
    pub tokens: BTreeMap<String, TokenProfile>,
}

/// Which signing and RPC stack a chain uses. JSON: `"evm"` or `"solana"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "lowercase")]
pub enum ChainFamily {
    /// An EVM chain, including Tempo. Addresses are `0x` + 40 hex characters.
    Evm,
    /// Solana. Addresses and mints are base58 public keys.
    Solana,
}

/// One chain the payments service can use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ChainProfile {
    /// EVM chain id, or the internal Solana network id (`900000001` to `900000003`).
    pub chain_id: u64,
    /// Display name, for example `"BSC"`.
    pub name: String,
    /// Signing and RPC stack.
    pub family: ChainFamily,
    /// JSON-RPC endpoint; `null` when none is configured, in which case the
    /// chain cannot be used for network calls until one is set. May embed a
    /// provider API key in its path or query, so the service never logs it.
    pub rpc_url: Option<String>,
    /// Backup JSON-RPC endpoints (API 1.1), tried in order when `rpc_url`
    /// cannot be reached or answers as another chain; at most 4. The
    /// endpoint that answered stays preferred for 10 minutes, after which
    /// `rpc_url` is tried first again. Each request still goes to exactly one
    /// endpoint. Like `rpc_url`, never logged or reported back. Optional in
    /// requests (default `[]`); always present in responses.
    #[serde(default)]
    pub fallback_rpc_urls: Vec<String>,
}

/// One token, with its deployment on each chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct TokenProfile {
    /// Display name, for example `"USD1"`.
    pub name: String,
    /// Ticker symbol, for example `"USD1"`.
    pub symbol: String,
    /// Suggested spending limits shown by onboarding. Informational only: the
    /// signer daemon's policies are what limits spending.
    pub recommended_limits: Option<TokenLimits>,
    /// Deployments by chain key; each key must be a configured chain.
    pub chains: BTreeMap<String, TokenChainProfile>,
}

/// A token's deployment on one chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct TokenChainProfile {
    /// Chain id of the chain this entry is keyed by (repeated for clarity).
    pub chain_id: u64,
    /// `true` for the chain's native coin (BNB, ETH, SOL, ...), which has no contract.
    pub is_native: bool,
    /// Contract address (EVM, `0x` + 40 hex, emitted lower case) or mint
    /// (Solana, base58); `null` exactly when `is_native` is `true`.
    pub address: Option<String>,
    /// Decimals of the token's smallest unit (18 for USD1 on BSC, 6 for USDC).
    pub decimals: u8,
}

/// Suggested spending limits in whole tokens, as decimal strings (for example `"10"` or `"0.05"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct TokenLimits {
    /// Per-transaction limit.
    pub per_tx: String,
    /// Rolling 24-hour limit.
    pub daily: String,
    /// Rolling 7-day limit.
    pub weekly: String,
}

/// `GetConfig`: returns the payments service configuration.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`PaymentsRpcResponse::Config`](crate::payments::PaymentsRpcResponse::Config) |
/// | Side effects | none |
/// | Idempotent | yes |
///
/// Before the first `SetConfig` this is the built-in default shown below.
///
/// **Errors:** `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/GetConfig.request.json")]
/// ```
///
/// Response (the built-in default):
///
/// ```json
#[doc = include_str!("../../fixtures/payments/GetConfig.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct GetConfigParams {
    /// Agent credentials.
    pub auth: AgentAuth,
}

/// `SetConfig`: validates and replaces the whole payments service configuration.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`PaymentsRpcResponse::Config`](crate::payments::PaymentsRpcResponse::Config) (the stored configuration) |
/// | Side effects | atomically rewrites the service's `config.json` |
/// | Idempotent | yes: storing the same configuration again changes nothing |
///
/// To change one entry, read the configuration with `GetConfig`, edit it, and
/// send it back. The configuration is validated as a whole (see the
/// [module documentation](self)); an invalid one is rejected and the stored
/// configuration is left unchanged. Changing an RPC URL changes where the
/// service reads balances and nonces and broadcasts transactions; it never
/// changes what the signer daemon's policies allow.
///
/// **Errors:** `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`,
/// `InvalidConfig`, `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/SetConfig.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/SetConfig.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SetConfigParams {
    /// Agent credentials.
    pub auth: AgentAuth,
    /// The new configuration.
    pub config: PaymentsConfig,
}

/// `AddToken` (API 1.1): adds one ERC-20 token or SPL mint to the
/// configuration, with its decimals (and, on EVM chains, its symbol) read
/// from the chain.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`PaymentsRpcResponse::TokenAdded`](crate::payments::PaymentsRpcResponse::TokenAdded) |
/// | Side effects | reads the chain; atomically rewrites the service's `config.json` unless the token is already configured |
/// | Idempotent | yes: adding the same contract or mint on the same network again changes nothing |
/// | Since | API 1.1.0 (capability `AddToken`) |
///
/// Lets a client add a token by network and address without doing chain I/O
/// or a `GetConfig` / edit / `SetConfig` round trip itself.
///
/// # Steps
///
/// 1. `network` must name a configured chain. `address` must be a contract
///    (EVM: `0x` + 40 hex characters, mixed case only with a valid checksum;
///    stored lower case) or a mint (Solana: a base58 public key). Native coins
///    are refused: the zero address, `0xeeee...eeee`, and the system program.
///    `symbol` is 1 to 32 characters without control characters, and
///    `decimals` is at most 36.
/// 2. If a token already has a deployment on `network` at `address`, the call
///    returns that token unchanged (`added: false`) without reading the chain;
///    `symbol` and `decimals` are ignored.
/// 3. The service reads the chain through the network's `rpc_url`. EVM: the
///    endpoint's chain id must match, the address must hold contract code,
///    and `decimals()` and `symbol()` are called. Solana: the endpoint must
///    serve the configured cluster, and the mint account must exist, belong to
///    the SPL Token or Token-2022 program, and have no transfer hook; its
///    decimals are read. SPL mints have no on-chain symbol, so `symbol` is
///    required on Solana chains (checked before any chain I/O).
/// 4. Decimals: the chain's value. A `decimals` that differs from it is
///    refused. If the chain cannot be read (no `rpc_url`, endpoint
///    unreachable or for another chain, `decimals()` failing), the given
///    `decimals` is used unverified (`verified_on_chain: false`); without one
///    the call fails with `ChainRpc`.
/// 5. Symbol: `symbol` when given, else the on-chain `symbol()` (EVM). The
///    token's display `name` is the symbol.
/// 6. Key: the symbol in lower case, with every run of characters outside
///    `[a-z0-9._-]` replaced by `-` (dropped at either end; `token` if
///    nothing is left). If that token exists without a deployment on
///    `network`, the deployment is added to it; if it exists with another deployment on `network`, the key gets
///    the suffix `-` + the first 6 characters of the address after `0x` (or
///    of the mint), in lower case; otherwise a new token is created with no
///    `recommended_limits`.
/// 7. The resulting configuration is validated as a whole, exactly like
///    `SetConfig`, and stored atomically.
///
/// Adding a token never changes what the signer daemon's policies allow.
///
/// **Errors:** `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`;
/// `InvalidRequest` (unknown network, malformed or native address, invalid
/// symbol or decimals, no symbol for a Solana mint or for an EVM token
/// without an on-chain `symbol()`, no contract at the address, a missing or
/// unsupported mint, `decimals` that differ from the chain's, both candidate
/// keys taken); `ChainRpc` (the chain could not be read and no `decimals` was
/// given; the message says how to set a working `rpc_url` or pass
/// `decimals`); `InvalidConfig` (the result fails validation, for example a
/// 257th token); `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/AddToken.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/AddToken.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AddTokenParams {
    /// Agent credentials.
    pub auth: AgentAuth,
    /// Chain key of a configured chain, for example `"bsc"` or
    /// `"solana-mainnet"` (case-insensitive).
    pub network: String,
    /// ERC-20 contract address (EVM chains, `0x` + 40 hex characters) or SPL
    /// mint (Solana chains, base58).
    pub address: String,
    /// Ticker symbol, for example `"USDC"`. Overrides the on-chain `symbol()`
    /// on EVM chains; required on Solana chains and for EVM tokens without a
    /// readable `symbol()`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub symbol: Option<String>,
    /// Decimals of the token's smallest unit. Optional: when the chain can be
    /// read it must equal the on-chain value; when it cannot, this value is
    /// stored unverified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub decimals: Option<u8>,
}

/// Result of `AddToken`: the token entry it added to (or found in) the
/// configuration, and the whole stored configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AddTokenResult {
    /// Token key in `config.tokens`, for example `"usdc"` or `"usdc-8ac76a"`.
    pub key: String,
    /// The token entry as stored, with all of its deployments.
    pub token: TokenProfile,
    /// Chain key the deployment was added on (lower case).
    pub network: String,
    /// The deployment on `network` as stored (EVM address in lower case).
    pub deployment: TokenChainProfile,
    /// `true` when this call read the token's decimals from the chain;
    /// `false` when they came from the request because the chain could not
    /// be read, or when the token was already configured (`added: false`).
    pub verified_on_chain: bool,
    /// `false` when a token already had this deployment and nothing changed.
    pub added: bool,
    /// The stored configuration after the call.
    pub config: PaymentsConfig,
}

/// `LookupToken` (API 1.1): reads an ERC-20 token's or SPL mint's metadata
/// from the chain without changing anything and without agent credentials.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist (the peer uid is checked by the socket) |
/// | Auth | none |
/// | Response | [`PaymentsRpcResponse::TokenInfo`](crate::payments::PaymentsRpcResponse::TokenInfo) |
/// | Side effects | none: reads the chain, never changes the configuration |
/// | Idempotent | yes |
/// | Since | API 1.1.0 (capability `LookupToken`) |
///
/// The read and validation half of [`AddToken`](AddTokenParams), with the
/// same rules for `network`, `address` (native coins refused), `symbol`,
/// `decimals`, the contract-code check, and an unreadable chain (steps 1,
/// 3, 4, and 5 there). It never answers from the configuration: the token
/// is read from the chain even when it is configured. A client can verify a
/// token before agent credentials exist, for example while setting up
/// spending limits.
///
/// **Why no credentials are needed:** it reads only public chain data,
/// only through the RPC endpoints the configuration already names (its
/// `rpc_url` and `fallback_rpc_urls`, never a URL from the request), stores
/// nothing, signs nothing, and asks the signer daemon nothing. The socket
/// still admits only allowlisted peers.
///
/// **Errors:** `InvalidRequest`, `ChainRpc` (as for `AddToken`).
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/LookupToken.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/LookupToken.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct LookupTokenParams {
    /// Chain key of a configured chain, for example `"bsc"` (case-insensitive).
    pub network: String,
    /// ERC-20 contract address (EVM chains) or SPL mint (Solana chains).
    pub address: String,
    /// Ticker symbol; overrides the on-chain `symbol()` on EVM chains and is
    /// required on Solana chains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub symbol: Option<String>,
    /// Expected decimals: must equal the on-chain value when the chain can
    /// be read, and is used unverified when it cannot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub decimals: Option<u8>,
}

/// Result of `LookupToken`: what `AddToken` would store for the token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct TokenInfo {
    /// Chain key (lower case).
    pub network: String,
    /// The chain's id (internal ids for Solana clusters).
    pub chain_id: u64,
    /// The contract (lower case) or mint, as the configuration would store it.
    pub address: String,
    /// The requested symbol, else the on-chain `symbol()`.
    pub symbol: String,
    /// Decimals of the token's smallest unit.
    pub decimals: u8,
    /// `true` when `decimals` were read from the chain; `false` when the
    /// chain could not be read and they came from the request.
    pub verified_on_chain: bool,
}
