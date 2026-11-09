//! [`Telemetry`]: consent precedence, gating, and what a recorded call sends,
//! against an in-memory sink (no network).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentpay_api::payments::{
    GetConfigParams, PaymentsRpcRequest, PaymentsRpcResponse, TelemetryDisabledReason,
    TransferParams,
};
use agentpay_api::AgentAuth;
use serde_json::{Map, Value};
use uuid::Uuid;

use super::*;
use crate::test_support::{set_mode, TempDir};

/// Records what it is given.
#[derive(Default)]
pub(crate) struct Recorder {
    pub(crate) events: Mutex<Vec<(String, Map<String, Value>)>>,
    pub(crate) errors: Mutex<Vec<(String, String, String)>>,
    pub(crate) discarded: Mutex<usize>,
}

impl Sink for Recorder {
    fn track(&self, event: &str, properties: Map<String, Value>) {
        self.events
            .lock()
            .expect("events")
            .push((event.to_string(), properties));
    }

    fn report_error(&self, method: &str, kind: &str, message: &str) {
        self.errors.lock().expect("errors").push((
            method.to_string(),
            kind.to_string(),
            message.to_string(),
        ));
    }

    fn discard(&self) {
        *self.discarded.lock().expect("discarded") += 1;
    }

    fn flush(&self, _timeout: Duration) -> FlushFuture {
        Box::pin(async { true })
    }
}

fn active(dir: &TempDir, settings: Settings) -> (Telemetry, Arc<Recorder>) {
    let recorder = Arc::new(Recorder::default());
    let telemetry = Telemetry::with_sink(dir.path(), settings, Some(recorder.clone()));
    (telemetry, recorder)
}

fn auth() -> AgentAuth {
    AgentAuth {
        agent_key_id: Uuid::nil(),
        agent_auth_token: "token".to_string().into(),
    }
}

fn transfer(amount: &str) -> PaymentsRpcRequest {
    PaymentsRpcRequest::Transfer(TransferParams {
        auth: auth(),
        network: None,
        asset: None,
        to: "0x5aeda56215b167893e80b4fe645ba6d5bab767de"
            .parse()
            .expect("address"),
        amount: amount.into(),
        options: Default::default(),
    })
}

#[test]
fn telemetry_is_on_by_default_with_a_random_install_id() {
    let dir = TempDir::new("telemetry");
    let (telemetry, _) = active(&dir, Settings::defaults());
    let status = telemetry.status();
    assert!(status.enabled && status.consent && telemetry.is_enabled());
    assert_eq!(status.disabled_reason, None);
    let install_id = status.install_id.expect("install id");
    assert!(!install_id.is_nil());
    assert_eq!(telemetry.status().install_id, Some(install_id));
    assert!(status.crash_reports && status.analytics);
    assert!(status.notice.contains("AGENTPAY_TELEMETRY=0"));
}

#[test]
fn the_environment_and_the_stored_consent_turn_it_off_in_order() {
    let dir = TempDir::new("telemetry");
    let env_off = Settings {
        env_opt_out: true,
        do_not_track: true,
        ..Settings::defaults()
    };
    let (telemetry, _) = active(&dir, env_off);
    let status = telemetry.status();
    assert_eq!(
        status.disabled_reason,
        Some(TelemetryDisabledReason::EnvOptOut)
    );
    assert_eq!(status.install_id, None, "an env opt-out creates no state");
    assert!(!dir.path().join(consent::TELEMETRY_FILE_NAME).exists());

    let dnt = Settings {
        do_not_track: true,
        ..Settings::defaults()
    };
    let (telemetry, _) = active(&dir, dnt);
    assert_eq!(
        telemetry.status().disabled_reason,
        Some(TelemetryDisabledReason::DoNotTrack)
    );

    let no_destinations = Settings {
        sentry_dsn: String::new(),
        mixpanel_token: String::new(),
        ..Settings::defaults()
    };
    let (telemetry, _) = active(&dir, no_destinations);
    assert_eq!(
        telemetry.status().disabled_reason,
        Some(TelemetryDisabledReason::MissingCredentials)
    );

    let (telemetry, recorder) = active(&dir, Settings::defaults());
    let off = telemetry.set_enabled(false).expect("opt out");
    assert!(!off.enabled && !off.consent);
    assert_eq!(
        off.disabled_reason,
        Some(TelemetryDisabledReason::StoredOptOut)
    );
    assert_eq!(*recorder.discarded.lock().expect("discarded"), 1);
    // A restarted service keeps the opt-out.
    let (restarted, _) = active(&dir, Settings::defaults());
    assert!(!restarted.is_enabled());
    let on = restarted.set_enabled(true).expect("opt in");
    assert!(on.enabled && restarted.is_enabled());
    assert_eq!(on.install_id, off.install_id);
}

#[test]
fn a_damaged_state_file_keeps_telemetry_off_until_set() {
    let dir = TempDir::new("telemetry");
    let path = dir.path().join(consent::TELEMETRY_FILE_NAME);
    std::fs::write(&path, b"garbage").expect("write");
    set_mode(&path, 0o600);
    let (telemetry, _) = active(&dir, Settings::defaults());
    let status = telemetry.status();
    assert_eq!(
        status.disabled_reason,
        Some(TelemetryDisabledReason::UnreadableState)
    );
    assert!(!status.consent);
    assert!(telemetry.set_enabled(true).expect("rewrite").enabled);
}

#[test]
fn an_inactive_instance_never_sends() {
    let dir = TempDir::new("telemetry");
    let telemetry = Telemetry::with_sink(dir.path(), Settings::defaults(), None);
    let status = telemetry.status();
    assert!(!status.enabled && status.consent);
    assert_eq!(
        status.disabled_reason,
        Some(TelemetryDisabledReason::Inactive)
    );
    telemetry.record_request(
        RequestUsage::of(&transfer("1")),
        &Err(PaymentsError::Internal("boom".into())),
        Duration::ZERO,
    );
}

#[test]
fn a_recorded_call_carries_only_coarse_scrubbed_properties() {
    let dir = TempDir::new("telemetry");
    let (telemetry, recorder) = active(&dir, Settings::defaults());
    let request = transfer("250.5");
    telemetry.record_request(
        RequestUsage::of(&request),
        &Err(PaymentsError::ChainRpc(
            "eth_call to 0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d failed".into(),
        )),
        Duration::from_millis(1_500),
    );
    let events = recorder.events.lock().expect("events").clone();
    let [(name, properties)] = events.as_slice() else {
        panic!("one event expected, got {events:?}");
    };
    assert_eq!(name, REQUEST_EVENT);
    let mut keys: Vec<&str> = properties.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "amount_bucket",
            "arch",
            "duration_bucket",
            "environment",
            "error_kind",
            "method",
            "outcome",
            "platform",
            "service_version"
        ]
    );
    assert_eq!(properties["method"], "Transfer");
    assert_eq!(properties["outcome"], "error");
    assert_eq!(properties["error_kind"], "ChainRpc");
    assert_eq!(properties["amount_bucket"], "100-1k");
    assert_eq!(properties["duration_bucket"], "1-5s");
    let rendered = Value::Object(properties.clone()).to_string();
    assert!(!rendered.contains("0x"), "no address may leave: {rendered}");
    assert!(
        !rendered.contains("250"),
        "no exact amount may leave: {rendered}"
    );
    // Ordinary errors are analytics only.
    assert!(recorder.errors.lock().expect("errors").is_empty());
}

#[test]
fn internal_errors_are_reported_and_outcomes_are_named() {
    let dir = TempDir::new("telemetry");
    let (telemetry, recorder) = active(&dir, Settings::defaults());
    let get = PaymentsRpcRequest::GetConfig(GetConfigParams { auth: auth() });
    telemetry.record_request(
        RequestUsage::of(&get),
        &Err(PaymentsError::Internal("lock poisoned".into())),
        Duration::ZERO,
    );
    telemetry.record_request(
        RequestUsage::of(&get),
        &Err(PaymentsError::ManualApprovalPending {
            approval_request_id: Uuid::nil(),
        }),
        Duration::ZERO,
    );
    telemetry.record_request(
        RequestUsage::of(&PaymentsRpcRequest::Hello),
        &Ok(PaymentsRpcResponse::Hello(
            agentpay_api::HelloResponse::for_payments_service("0"),
        )),
        Duration::ZERO,
    );
    let outcomes: Vec<Value> = recorder
        .events
        .lock()
        .expect("events")
        .iter()
        .map(|(_, properties)| properties["outcome"].clone())
        .collect();
    assert_eq!(outcomes, ["error", "approval_pending", "ok"]);
    assert_eq!(
        recorder.errors.lock().expect("errors").as_slice(),
        [(
            "GetConfig".to_string(),
            "Internal".to_string(),
            "lock poisoned".to_string()
        )]
    );

    telemetry.set_enabled(false).expect("opt out");
    telemetry.record_request(
        RequestUsage::of(&get),
        &Err(PaymentsError::Internal("after opt-out".into())),
        Duration::ZERO,
    );
    assert_eq!(recorder.events.lock().expect("events").len(), 3);
    assert_eq!(recorder.errors.lock().expect("errors").len(), 1);
}

#[tokio::test]
async fn start_without_destinations_sends_nothing_and_shuts_down_at_once() {
    let dir = TempDir::new("telemetry");
    let settings = Settings {
        env_opt_out: true,
        ..Settings::defaults()
    };
    let telemetry = Telemetry::start(dir.path(), settings);
    assert!(!telemetry.is_enabled());
    let started = std::time::Instant::now();
    telemetry.shutdown(SHUTDOWN_DEADLINE).await;
    assert!(started.elapsed() < Duration::from_secs(1));
}
