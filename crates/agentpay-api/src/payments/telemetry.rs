//! Anonymous telemetry: `TelemetryStatus` and `SetTelemetry`.
//!
//! The payments service reports anonymous usage analytics (Mixpanel) and
//! crash and error reports (Sentry), on by default with an opt-out, under the
//! same rules as the TypeScript CLI it replaces:
//!
//! - **Identity:** a random install id (UUID v4) stored in the service's
//!   state directory (`telemetry.json`, mode `0600`), nothing else. It is
//!   never derived from a wallet, key, or machine.
//! - **What is sent:** the method name, its outcome (`ok`, `approval_pending`,
//!   or the error kind), a duration bucket (`<100ms`, `100ms-1s`, `1-5s`,
//!   `5-30s`, `30s+`), a coarse amount bucket for payments (`0`, `<10`,
//!   `10-100`, `100-1k`, `1k-10k`, `10k+`, in whole units of the asset), the
//!   service version, OS, and CPU architecture; timestamps are truncated to
//!   the minute. Crash reports carry the scrubbed message and stack.
//! - **What is never sent:** addresses, keys, tokens, signatures,
//!   transaction hashes, exact amounts, RPC or merchant URLs (reduced to
//!   `scheme://host`), e-mail addresses, the host name, or the home
//!   directory. Every string passes a scrubber before it leaves the process,
//!   and every property name is checked against an allowlist.
//! - **Never in the way:** sending is asynchronous and best effort, bounded
//!   by short timeouts (2 seconds per request, 3 seconds at shutdown), and a
//!   failure never changes a payment's outcome. After a failed delivery the
//!   service stops sending for an hour.
//!
//! Telemetry is off when the service's environment sets
//! `AGENTPAY_TELEMETRY=0` (or `false`, `no`, `off`) or `DO_NOT_TRACK` (any
//! value but empty or `0`), when the stored consent is off (`SetTelemetry`),
//! or when the state file cannot be read (a damaged opt-out must not turn
//! collection back on; `SetTelemetry` rewrites it). Destinations can be
//! redirected or disabled with `AGENTPAY_SENTRY_DSN` and
//! `AGENTPAY_MIXPANEL_TOKEN` (empty disables), and
//! `AGENTPAY_TELEMETRY_ENVIRONMENT` labels the events (default `production`,
//! or `ci` when `CI` is set).
//!
//! The consent is per machine, not per agent: any authenticated client may
//! read or change it.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

use crate::auth::AgentAuth;

/// `TelemetryStatus`: whether telemetry is on, and why not.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`TelemetryStatus`](crate::payments::PaymentsRpcResponse::TelemetryStatus) |
/// | Side effects | creates `telemetry.json` with a new install id the first time, unless telemetry is off by environment |
/// | Idempotent | yes |
///
/// **Errors:** `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/telemetry/TelemetryStatus.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/telemetry/TelemetryStatus.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct TelemetryStatusParams {
    /// Agent credentials.
    pub auth: AgentAuth,
}

/// `SetTelemetry`: turn telemetry on or off for this machine.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`TelemetryStatus`](crate::payments::PaymentsRpcResponse::TelemetryStatus) |
/// | Side effects | writes the consent to `telemetry.json` (creating an install id if needed; a damaged file is replaced); turning it off drops queued events at once |
/// | Idempotent | yes |
///
/// The environment still wins: with `AGENTPAY_TELEMETRY=0` or `DO_NOT_TRACK`
/// set, `enabled: true` stores the consent but `enabled` in the result stays
/// `false`.
///
/// **Errors:** `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`,
/// `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/telemetry/SetTelemetry.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/telemetry/SetTelemetry.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SetTelemetryParams {
    /// Agent credentials.
    pub auth: AgentAuth,
    /// The new consent.
    pub enabled: bool,
}

/// The result of `TelemetryStatus` and `SetTelemetry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct TelemetryStatusResult {
    /// Whether events are being sent now.
    pub enabled: bool,
    /// The stored consent (`true` until someone opts out).
    pub consent: bool,
    /// Why telemetry is off; `null` when it is on.
    pub disabled_reason: Option<TelemetryDisabledReason>,
    /// The random install id events carry; `null` before it was created.
    pub install_id: Option<Uuid>,
    /// Whether crash reports have a destination (`AGENTPAY_SENTRY_DSN` not empty).
    pub crash_reports: bool,
    /// Whether usage analytics have a destination (`AGENTPAY_MIXPANEL_TOKEN` not empty).
    pub analytics: bool,
    /// The disclosure to show users before or when telemetry is on.
    pub notice: String,
}

/// Why telemetry is off, in order of precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryDisabledReason {
    /// `AGENTPAY_TELEMETRY` is `0`, `false`, `no`, `off`, or empty.
    EnvOptOut,
    /// `DO_NOT_TRACK` is set to something other than empty or `0`.
    DoNotTrack,
    /// Both destinations are disabled (empty DSN and token).
    MissingCredentials,
    /// `telemetry.json` cannot be read; `SetTelemetry` rewrites it.
    UnreadableState,
    /// Someone opted out with `SetTelemetry`.
    StoredOptOut,
    /// This service instance does not send telemetry (an embedded or test instance).
    Inactive,
}
