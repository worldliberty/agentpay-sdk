//! Wallet and funding: `WalletSummary`, `WalletBalance`, and `FundingRequest`.
//!
//! The agent's wallet is the vault key behind its agent key: an EVM address
//! for a `secp256k1` key and a Solana address when the signer backend can
//! sign for Solana (both from the signer daemon's `AuthenticateAgent`). These
//! methods only read the chains; they sign nothing and change nothing.
//!
//! # Balances
//!
//! `WalletSummary` reads one balance per configured token deployment (every
//! `tokens.<key>.chains.<network>` entry) whose chain has an `rpc_url` and
//! whose family the wallet has an address for. The native coins of Tempo
//! chains (chain ids 4217 and 42431) are skipped: Tempo has no native gas
//! coin, so the number would be meaningless. The reads run in parallel, at
//! most 16 at a time, and every chain gets its own time budget (10 seconds
//! for connecting, including the chain id or cluster check, and 10 seconds
//! per balance). A chain that is down or slow never fails the call: its
//! entries carry an `error` instead of a balance, and every other entry is
//! still returned. Entries are sorted by `network`, then `asset`.
//!
//! | Kind | Read |
//! |---|---|
//! | `native` | `eth_getBalance` |
//! | `erc20` | `balanceOf(wallet)` |
//! | `sol` | the wallet account's lamports (`getAccountInfo`; a missing account is `0`) |
//! | `spl` | the amount in the wallet's associated token account for the mint, under the mint's owner program (SPL Token or Token-2022); a missing account is `0` |
//!
//! # Funding requests
//!
//! `FundingRequest` tells a person how to fund the wallet: the address, the
//! chain, the token contract, a payment URI their wallet app can open, and a
//! QR code of that URI.
//!
//! | Family | URI |
//! |---|---|
//! | EVM, native coin | [EIP-681](https://eips.ethereum.org/EIPS/eip-681) `ethereum:<wallet>@<chain_id>[?value=<wei>]` |
//! | EVM, ERC-20 | EIP-681 `ethereum:<token>@<chain_id>/transfer?address=<wallet>[&uint256=<base units>]` |
//! | Solana, SOL | [Solana Pay](https://docs.solanapay.com/spec) `solana:<wallet>[?amount=<SOL>]` |
//! | Solana, SPL | Solana Pay `solana:<wallet>?[amount=<tokens>&]spl-token=<mint>` |
//!
//! The QR code (error correction level M) comes in two renderings of the same
//! modules: an SVG document and a block of text for terminals, two module
//! rows per line drawn with the half-block characters `▀`, `▄`, `█`, and
//! space, including a 4-module quiet zone. The text is meant for dark
//! terminal backgrounds: light modules are drawn, dark modules are left blank.
//!
//! A token transfer also needs the chain's native coin for fees. For a
//! non-native asset on an EVM chain the result carries a `gas` hint naming
//! that coin (BNB on BSC for USD1, as in the TypeScript funding flow), and on
//! Solana SPL tokens need SOL for fees. Tempo chains get no hint: fees are paid
//! in the stablecoin itself.

use agentpay_domain::{EvmAddress, SolanaAddress};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

use super::{ChainFamily, WirePaymentsError};
use crate::auth::AgentAuth;

/// `WalletSummary`: the agent's addresses and every configured balance.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`WalletSummary`](crate::payments::PaymentsRpcResponse::WalletSummary) |
/// | Side effects | none |
/// | Idempotent | yes (balances follow the chains) |
///
/// Failed reads are reported per entry (see the [module docs](self)); the
/// call itself fails only when the caller cannot be authenticated.
///
/// **Errors:** `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/wallet/WalletSummary.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/wallet/WalletSummary.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct WalletSummaryParams {
    /// Agent credentials.
    pub auth: AgentAuth,
}

/// `WalletBalance`: one balance of the agent's wallet.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`WalletBalance`](crate::payments::PaymentsRpcResponse::WalletBalance) |
/// | Side effects | none |
/// | Idempotent | yes (the balance follows the chain) |
///
/// `network` defaults to `default_network` and `asset` to `default_asset`
/// (USD1 on BSC with the built-in configuration). `asset` is a token key, or
/// the contract address or mint of a configured deployment on `network`.
/// Unlike `WalletSummary`, a failed read fails the call, so `error` in the
/// result is always `null`.
///
/// **Errors:** `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`,
/// `InvalidRequest` (unknown network or asset, no deployment on the network,
/// no `rpc_url`, or no wallet address for the chain's family), `ChainRpc`
/// (endpoint unreachable, too slow, or serving another chain).
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/wallet/WalletBalance.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/wallet/WalletBalance.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct WalletBalanceParams {
    /// Agent credentials.
    pub auth: AgentAuth,
    /// Chain key; default `default_network`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub network: Option<String>,
    /// Token key, or a configured contract address or mint; default `default_asset`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub asset: Option<String>,
}

/// `FundingRequest`: everything a person needs to fund the agent's wallet.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`FundingRequest`](crate::payments::PaymentsRpcResponse::FundingRequest) |
/// | Side effects | none; no RPC call is made |
/// | Idempotent | yes |
///
/// `network` defaults to `default_network` and `asset` to `default_asset`;
/// `asset` resolves as for `WalletBalance`. `amount` is an optional suggested
/// amount in whole units (`"25"`, `"0.5"`), with at most as many fractional
/// digits as the asset has decimals; it is put into the URI. `qr` (default
/// `true`) renders the QR code; `false` leaves `qr` `null` in the result, as
/// in this example. See the [module docs](self) for the URI formats.
///
/// **Errors:** `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`,
/// `InvalidRequest` (unknown network or asset, no deployment, bad amount, or
/// no wallet address for the chain's family).
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/wallet/FundingRequest.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/wallet/FundingRequest.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct FundingRequestParams {
    /// Agent credentials.
    pub auth: AgentAuth,
    /// Chain key; default `default_network`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub network: Option<String>,
    /// Token key, or a configured contract address or mint; default `default_asset`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub asset: Option<String>,
    /// Suggested amount in whole units, for example `"25"`; none by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub amount: Option<String>,
    /// Whether to render the QR code; default `true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub qr: Option<bool>,
}

/// What kind of balance a [`WalletBalanceEntry`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "lowercase")]
pub enum WalletAssetKind {
    /// The native coin of an EVM chain (BNB, ETH, ...).
    Native,
    /// An ERC-20 (or TIP-20) token.
    Erc20,
    /// Native SOL.
    Sol,
    /// An SPL Token or Token-2022 mint.
    Spl,
}

/// The result of `WalletSummary`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct WalletSummaryResult {
    /// The calling agent key.
    pub agent_key_id: Uuid,
    /// The wallet's EVM address; `null` for an `ed25519` vault key.
    pub evm_address: Option<EvmAddress>,
    /// The wallet's Solana address; `null` when the signer backend cannot
    /// sign for Solana.
    pub solana_address: Option<SolanaAddress>,
    /// The configuration's `default_network`.
    pub default_network: String,
    /// The configuration's `default_asset`.
    pub default_asset: String,
    /// One entry per configured token deployment, sorted by `network`, then `asset`.
    pub balances: Vec<WalletBalanceEntry>,
}

/// One balance of the agent's wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct WalletBalanceEntry {
    /// Chain key.
    pub network: String,
    /// Chain id (internal ids for Solana clusters).
    pub chain_id: u64,
    /// The chain's display name.
    pub chain_name: String,
    /// The chain's family.
    pub family: ChainFamily,
    /// Token key.
    pub asset: String,
    /// Ticker symbol.
    pub symbol: String,
    /// What kind of balance this is.
    pub kind: WalletAssetKind,
    /// ERC-20 contract (lower case) or SPL mint; `null` for a native coin.
    pub token: Option<String>,
    /// Decimals of the smallest unit.
    pub decimals: u8,
    /// The wallet address whose balance this is.
    pub address: String,
    /// Balance in the smallest unit, as a decimal string (up to `uint256`);
    /// `null` when the read failed.
    pub balance_base_units: Option<String>,
    /// Balance in whole units without trailing zeros, for example `"12.5"`;
    /// `null` when the read failed.
    pub balance: Option<String>,
    /// Why the read failed (`ChainRpc` or `InvalidRequest`); `null` on success.
    pub error: Option<WirePaymentsError>,
}

/// The result of `FundingRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct FundingRequestResult {
    /// Chain key.
    pub network: String,
    /// Chain id (internal ids for Solana clusters).
    pub chain_id: u64,
    /// The chain's display name.
    pub chain_name: String,
    /// The chain's family.
    pub family: ChainFamily,
    /// Token key.
    pub asset: String,
    /// Ticker symbol.
    pub symbol: String,
    /// What kind of asset to send.
    pub kind: WalletAssetKind,
    /// ERC-20 contract (lower case) or SPL mint; `null` for a native coin.
    pub token: Option<String>,
    /// Decimals of the smallest unit.
    pub decimals: u8,
    /// The wallet address to fund (EVM or Solana, by family).
    pub address: String,
    /// The suggested amount in whole units, normalized; `null` when none was asked for.
    pub amount: Option<String>,
    /// The suggested amount in the smallest unit; `null` when none was asked for.
    pub amount_base_units: Option<String>,
    /// EIP-681 or Solana Pay URI.
    pub uri: String,
    /// QR code of `uri`; `null` when the request set `qr: false`.
    pub qr: Option<FundingQr>,
    /// The coin to send for fees as well; `null` when `asset` pays its own fees.
    pub gas: Option<FundingGasHint>,
    /// One sentence to show the person funding the wallet.
    pub instructions: String,
}

/// A QR code of a funding URI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct FundingQr {
    /// Modules per side, without the quiet zone.
    pub modules: u32,
    /// A standalone SVG document: black modules on white, 8 pixels per
    /// module, with a 4-module quiet zone.
    pub svg: String,
    /// The same code for a terminal: lines separated by `\n`, two module rows
    /// per line, for dark backgrounds (see the [module docs](self)).
    pub terminal: String,
}

/// The native coin a funder should send along for transaction fees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct FundingGasHint {
    /// Token key of the native coin; `null` when the configuration has no
    /// native deployment on the network (the symbol then comes from the chain id).
    pub asset: Option<String>,
    /// Its ticker symbol, for example `"BNB"`.
    pub symbol: String,
    /// Why it is needed.
    pub note: String,
}
