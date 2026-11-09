//! Anonymous, opt-out telemetry: usage analytics (Mixpanel) and crash and
//! error reports (Sentry), with the privacy rules of the TypeScript CLI. The
//! wire contract and the rules are documented on
//! `agentpay_api::payments::telemetry`.
//!
//! - [`settings`]: the environment (`AGENTPAY_TELEMETRY`, `DO_NOT_TRACK`, ...)
//!   and the baked-in destinations;
//! - [`consent`]: `telemetry.json` (opt-out and random install id);
//! - [`scrub`]: the scrubber every outgoing string passes;
//! - [`buckets`]: coarse amount and duration ranges;
//! - [`mixpanel`] and [`sentry`]: the two destinations.
//!
//! [`Telemetry::inactive`] (used by [`AppState::new`], so by every test)
//! never sends anything; only [`Telemetry::start`], called by the service
//! runtime, connects destinations. Recording is synchronous, non-blocking,
//! and infallible, so it can never slow down or fail a payment.
//!
//! [`AppState::new`]: crate::state::AppState::new

pub mod buckets;
pub mod consent;
pub mod mixpanel;
pub mod scrub;
pub mod sentry;
pub mod settings;

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentpay_api::payments::{
    PaymentsRpcRequest, PaymentsRpcResponse, TelemetryDisabledReason, TelemetryStatusResult,
};
use serde_json::{Map, Value};

use crate::error::PaymentsError;
use consent::{ConsentStore, Stored};
use scrub::{scrub_properties, Environment};
use settings::Settings;

/// Name of the analytics event recorded for every call.
pub const REQUEST_EVENT: &str = "paymentd_request";
/// Longest time shutdown waits for queued telemetry.
pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(3);

/// The disclosure clients show (same wording as the TypeScript CLI).
pub const NOTICE: &str = "AgentPay collects anonymous usage analytics and crash reports to \
understand adoption. It never collects private keys, passwords, wallet or recipient addresses, \
transaction hashes, or exact amounts; amounts and balances are reported only as coarse ranges. \
Opt out with `agentpay telemetry disable` or by setting AGENTPAY_TELEMETRY=0.";

/// Where events go. Production uses [`Destinations`]; tests use a recorder.
pub trait Sink: Send + Sync {
    /// An analytics event with scrubbed properties.
    fn track(&self, event: &str, properties: Map<String, Value>);
    /// An unexpected error (the message is scrubbed before sending).
    fn report_error(&self, method: &str, kind: &str, message: &str);
    /// Drops queued events (after an opt-out).
    fn discard(&self);
    /// Delivers what is queued, waiting at most `timeout`.
    fn flush(&self, timeout: Duration) -> FlushFuture;
}

/// The future [`Sink::flush`] returns: `true` when everything was delivered.
pub type FlushFuture = std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>;

/// What one call contributes to telemetry, captured before it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestUsage {
    method: &'static str,
    amount_bucket: Option<&'static str>,
}

impl RequestUsage {
    /// The method name and coarse amount of `request`.
    #[must_use]
    pub fn of(request: &PaymentsRpcRequest) -> Self {
        Self {
            method: request.method_name(),
            amount_bucket: buckets::request_amount_bucket(request),
        }
    }
}

/// The telemetry of this service instance.
pub struct Telemetry {
    settings: Settings,
    consent: ConsentStore,
    /// Destinations; `None` for an instance that never sends.
    sink: Option<Arc<dyn Sink>>,
    /// Whether events are sent now; shared with the Sentry `before_send`.
    enabled: Arc<AtomicBool>,
    /// Serializes consent changes.
    lock: Mutex<()>,
    env: Environment,
}

impl Telemetry {
    /// An instance that never sends anything (embedded and test services).
    /// Its status and consent still work.
    #[must_use]
    pub fn inactive(state_dir: &Path) -> Self {
        Self::with_sink(state_dir, Settings::from_env(), None)
    }

    /// An instance sending through `sink` when consent and `settings` allow.
    #[must_use]
    pub fn with_sink(state_dir: &Path, settings: Settings, sink: Option<Arc<dyn Sink>>) -> Self {
        let telemetry = Self {
            settings,
            consent: ConsentStore::new(state_dir),
            sink,
            enabled: Arc::new(AtomicBool::new(false)),
            lock: Mutex::new(()),
            env: Environment::current(),
        };
        let enabled = telemetry.status().enabled;
        telemetry.enabled.store(enabled, Ordering::Relaxed);
        telemetry
    }

    /// The production instance: connects Mixpanel and Sentry (unless the
    /// environment opts out or has no destinations) on the current Tokio
    /// runtime. Never fails; without a working HTTP client it sends nothing.
    #[must_use]
    pub fn start(state_dir: &Path, settings: Settings) -> Self {
        let mut telemetry = Self::with_sink(state_dir, settings.clone(), None);
        if settings.env_opt_out || settings.do_not_track {
            return telemetry;
        }
        let Some(consent) = telemetry.consent.ensure() else {
            return telemetry;
        };
        let install_id = consent.install_id.to_string();
        let destinations = Destinations::connect(&settings, &install_id, telemetry.enabled.clone());
        telemetry.sink = destinations.map(|d| Arc::new(d) as Arc<dyn Sink>);
        let enabled = telemetry.status().enabled;
        telemetry.enabled.store(enabled, Ordering::Relaxed);
        telemetry
    }

    /// Whether events are sent now.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// The current status. An active instance creates `telemetry.json` (on,
    /// with a new install id) when it is missing and the environment allows
    /// telemetry.
    #[must_use]
    pub fn status(&self) -> TelemetryStatusResult {
        let env_reason = if self.settings.env_opt_out {
            Some(TelemetryDisabledReason::EnvOptOut)
        } else if self.settings.do_not_track {
            Some(TelemetryDisabledReason::DoNotTrack)
        } else if !self.settings.crash_reports() && !self.settings.analytics() {
            Some(TelemetryDisabledReason::MissingCredentials)
        } else {
            None
        };
        // Only an instance that sends creates the install id.
        let stored = match (env_reason, self.consent.read()) {
            (None, Stored::Missing) if self.sink.is_some() => self
                .consent
                .ensure()
                .map_or(Stored::Unreadable, Stored::Present),
            (_, stored) => stored,
        };
        let (consent, install_id) = match stored {
            Stored::Present(consent) => (consent.enabled, Some(consent.install_id)),
            Stored::Missing => (true, None),
            Stored::Unreadable => (false, None),
        };
        let reason = env_reason.or(match stored {
            Stored::Unreadable => Some(TelemetryDisabledReason::UnreadableState),
            Stored::Present(consent) if !consent.enabled => {
                Some(TelemetryDisabledReason::StoredOptOut)
            }
            _ if self.sink.is_none() => Some(TelemetryDisabledReason::Inactive),
            _ => None,
        });
        TelemetryStatusResult {
            enabled: reason.is_none(),
            consent,
            disabled_reason: reason,
            install_id,
            crash_reports: self.settings.crash_reports(),
            analytics: self.settings.analytics(),
            notice: NOTICE.to_string(),
        }
    }

    /// Stores the consent and applies it at once; turning telemetry off drops
    /// queued events.
    pub fn set_enabled(&self, enabled: bool) -> Result<TelemetryStatusResult, PaymentsError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| PaymentsError::Internal("telemetry lock poisoned".into()))?;
        self.consent.set(enabled)?;
        let status = self.status();
        self.enabled.store(status.enabled, Ordering::Relaxed);
        if !status.enabled {
            if let Some(sink) = &self.sink {
                sink.discard();
            }
        }
        Ok(status)
    }

    /// Records one finished call: method, outcome, coarse duration and
    /// amount. Reports `Internal` and `SignedTransactionMismatch` errors to
    /// Sentry. Never blocks and never fails.
    pub fn record_request(
        &self,
        usage: RequestUsage,
        result: &Result<PaymentsRpcResponse, PaymentsError>,
        elapsed: Duration,
    ) {
        let Some(sink) = self.sink.as_ref().filter(|_| self.is_enabled()) else {
            return;
        };
        let outcome = match result {
            Ok(PaymentsRpcResponse::ManualApprovalPending(_))
            | Err(PaymentsError::ManualApprovalPending { .. }) => "approval_pending",
            Ok(_) => "ok",
            Err(_) => "error",
        };
        let mut properties = Map::new();
        properties.insert("method".into(), usage.method.into());
        properties.insert("outcome".into(), outcome.into());
        if let Err(error) = result {
            properties.insert("error_kind".into(), error.kind().into());
        }
        properties.insert(
            "duration_bucket".into(),
            buckets::duration_bucket(elapsed).into(),
        );
        if let Some(bucket) = usage.amount_bucket {
            properties.insert("amount_bucket".into(), bucket.into());
        }
        for (key, value) in base_properties(&self.settings) {
            properties.insert(key.into(), value.into());
        }
        sink.track(REQUEST_EVENT, scrub_properties(properties, &self.env));
        if let Err(
            error @ (PaymentsError::Internal(message)
            | PaymentsError::SignedTransactionMismatch(message)),
        ) = result
        {
            sink.report_error(usage.method, error.kind(), message);
        }
    }

    /// Delivers queued telemetry, waiting at most `deadline`.
    pub async fn shutdown(&self, deadline: Duration) {
        if let Some(sink) = &self.sink {
            let _ = tokio::time::timeout(deadline, sink.flush(deadline)).await;
        }
    }
}

/// Properties on every event: release, OS, architecture, environment.
fn base_properties(settings: &Settings) -> [(&'static str, String); 4] {
    [
        ("service_version", env!("CARGO_PKG_VERSION").to_string()),
        ("platform", std::env::consts::OS.to_string()),
        ("arch", std::env::consts::ARCH.to_string()),
        ("environment", settings.environment.clone()),
    ]
}

/// The production destinations.
struct Destinations {
    mixpanel: Option<mixpanel::Mixpanel>,
    sentry: Option<sentry::SentryReporter>,
}

impl Destinations {
    fn connect(settings: &Settings, install_id: &str, enabled: Arc<AtomicBool>) -> Option<Self> {
        let runtime = tokio::runtime::Handle::try_current().ok()?;
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .ok()?;
        let mixpanel = settings.analytics().then(|| {
            mixpanel::Mixpanel::start(
                http.clone(),
                settings.mixpanel_url.clone(),
                settings.mixpanel_token.clone(),
                install_id.to_string(),
            )
        });
        let sentry = settings
            .sentry_dsn
            .parse::<::sentry::types::Dsn>()
            .ok()
            .and_then(|dsn| {
                let transport = Arc::new(sentry::HttpTransport::new(http, &dsn, runtime));
                let tags: Vec<(&'static str, String)> = base_properties(settings).into();
                sentry::SentryReporter::install(
                    &settings.sentry_dsn,
                    &settings.environment,
                    install_id,
                    &tags,
                    enabled,
                    transport,
                )
            });
        Some(Self { mixpanel, sentry })
    }
}

impl Sink for Destinations {
    fn track(&self, event: &str, properties: Map<String, Value>) {
        if let Some(mixpanel) = &self.mixpanel {
            mixpanel.track(event, properties);
        }
    }

    fn report_error(&self, method: &str, kind: &str, message: &str) {
        if let Some(sentry) = &self.sentry {
            sentry.report_error(method, kind, message);
        }
    }

    fn discard(&self) {
        if let Some(mixpanel) = &self.mixpanel {
            mixpanel.discard();
        }
    }

    fn flush(&self, timeout: Duration) -> FlushFuture {
        let mixpanel = self.mixpanel.clone();
        let sentry_flush = self.sentry.as_ref().map(|reporter| {
            let client_flush = reporter.flusher();
            tokio::task::spawn_blocking(move || client_flush(timeout))
        });
        Box::pin(async move {
            let analytics = match mixpanel {
                Some(mixpanel) => mixpanel.flush().await,
                None => true,
            };
            let reports = match sentry_flush {
                Some(task) => task.await.unwrap_or(false),
                None => true,
            };
            analytics && reports
        })
    }
}

#[cfg(test)]
pub(crate) mod tests;
