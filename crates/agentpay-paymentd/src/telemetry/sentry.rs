//! Sentry crash and error reports (ported from `telemetry-sentry`).
//!
//! The `sentry` crate builds events (panics through its panic integration,
//! internal errors through [`SentryReporter::report_error`]); paymentd sends
//! them itself through [`HttpTransport`] over its own reqwest client, so a
//! report is asynchronous, bounded (2 seconds per request, at most 8 in
//! flight), and never blocks a payment. Every event passes [`scrub_event`]
//! first, which keeps only the error type, the scrubbed message and stack,
//! and our own tags.

use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use sentry::protocol::{Event, Exception, Frame, Level, Stacktrace, User};
use sentry::types::Dsn;
use sentry::{ClientOptions, Envelope, Hub, Transport};

use super::scrub::{scrub_text, Environment};

/// Timeout of one delivery.
const SEND_TIMEOUT: Duration = Duration::from_secs(2);
/// Reports in flight before new ones are dropped.
const MAX_IN_FLIGHT: usize = 8;
/// Tags kept on an event; everything else is removed.
const ALLOWED_TAGS: &[&str] = &[
    "arch",
    "environment",
    "error_kind",
    "method",
    "platform",
    "service_version",
];

/// Removes everything about the machine and the person from `event`: keeps
/// the error type, the scrubbed message and stack (file paths scrubbed, no
/// source lines or variables), allowlisted tags, and the install id.
#[must_use]
pub fn scrub_event(mut event: Event<'static>, env: &Environment) -> Event<'static> {
    let scrub = |text: &mut String| *text = scrub_text(text, env);
    if let Some(message) = event.message.as_mut() {
        scrub(message);
    }
    if let Some(entry) = event.logentry.as_mut() {
        scrub(&mut entry.message);
        entry.params.clear();
    }
    for exception in &mut event.exception.values {
        scrub_exception(exception, env);
    }
    if let Some(stacktrace) = event.stacktrace.as_mut() {
        scrub_stacktrace(stacktrace, env);
    }
    for thread in &mut event.threads.values {
        thread.name = None;
        if let Some(stacktrace) = thread.stacktrace.as_mut() {
            scrub_stacktrace(stacktrace, env);
        }
    }
    if let Some(culprit) = event.culprit.as_mut() {
        scrub(culprit);
    }
    if let Some(transaction) = event.transaction.as_mut() {
        scrub(transaction);
    }
    event
        .tags
        .retain(|key, _| ALLOWED_TAGS.contains(&key.as_str()));
    for value in event.tags.values_mut() {
        scrub(value);
    }
    event.extra.clear();
    event.contexts.clear();
    event.user = event.user.take().and_then(|user| user.id).map(|id| User {
        id: Some(id),
        ..User::default()
    });
    event.server_name = None;
    event.breadcrumbs.values.clear();
    event.modules.clear();
    event.request = None;
    event.debug_meta = Cow::Owned(Default::default());
    event
}

fn scrub_exception(exception: &mut Exception, env: &Environment) {
    if let Some(value) = exception.value.as_mut() {
        *value = scrub_text(value, env);
    }
    if let Some(module) = exception.module.as_mut() {
        *module = scrub_text(module, env);
    }
    if let Some(stacktrace) = exception.stacktrace.as_mut() {
        scrub_stacktrace(stacktrace, env);
    }
    exception.raw_stacktrace = None;
    if let Some(mechanism) = exception.mechanism.as_mut() {
        mechanism.description = None;
        mechanism.data.clear();
    }
}

fn scrub_stacktrace(stacktrace: &mut Stacktrace, env: &Environment) {
    stacktrace
        .frames
        .iter_mut()
        .for_each(|frame| scrub_frame(frame, env));
    stacktrace.registers.clear();
}

fn scrub_frame(frame: &mut Frame, env: &Environment) {
    for field in [
        &mut frame.filename,
        &mut frame.abs_path,
        &mut frame.module,
        &mut frame.package,
    ] {
        if let Some(value) = field.as_mut() {
            *value = scrub_text(value, env);
        }
    }
    frame.pre_context.clear();
    frame.context_line = None;
    frame.post_context.clear();
    frame.vars.clear();
}

/// Sends envelopes over HTTP from Tokio tasks: never blocks the caller,
/// drops reports beyond [`MAX_IN_FLIGHT`], and lets `flush` wait (bounded)
/// for the ones in flight.
#[derive(Clone)]
pub struct HttpTransport {
    http: reqwest::Client,
    url: String,
    auth: String,
    runtime: tokio::runtime::Handle,
    in_flight: Arc<(Mutex<usize>, Condvar)>,
}

impl HttpTransport {
    /// A transport for `dsn` that spawns on `runtime`.
    #[must_use]
    pub fn new(http: reqwest::Client, dsn: &Dsn, runtime: tokio::runtime::Handle) -> Self {
        Self {
            http,
            url: dsn.envelope_api_url().to_string(),
            auth: dsn
                .to_auth(Some(concat!(
                    "agentpay-paymentd/",
                    env!("CARGO_PKG_VERSION")
                )))
                .to_string(),
            runtime,
            in_flight: Arc::new((Mutex::new(0), Condvar::new())),
        }
    }

    fn finish(in_flight: &(Mutex<usize>, Condvar)) {
        let (count, idle) = in_flight;
        if let Ok(mut count) = count.lock() {
            *count = count.saturating_sub(1);
        }
        idle.notify_all();
    }
}

impl Transport for HttpTransport {
    fn send_envelope(&self, envelope: Envelope) {
        let mut body = Vec::new();
        if envelope.to_writer(&mut body).is_err() {
            return;
        }
        {
            let Ok(mut count) = self.in_flight.0.lock() else {
                return;
            };
            if *count >= MAX_IN_FLIGHT {
                return;
            }
            *count += 1;
        }
        let request = self
            .http
            .post(&self.url)
            .timeout(SEND_TIMEOUT)
            .header("X-Sentry-Auth", &self.auth)
            .header("content-type", "application/x-sentry-envelope")
            .body(body);
        let in_flight = self.in_flight.clone();
        self.runtime.spawn(async move {
            let _ = request.send().await;
            Self::finish(&in_flight);
        });
    }

    fn flush(&self, timeout: Duration) -> bool {
        let (count, idle) = &*self.in_flight;
        let Ok(guard) = count.lock() else {
            return false;
        };
        idle.wait_timeout_while(guard, timeout, |count| *count > 0)
            .map(|(count, _)| *count == 0)
            .unwrap_or(false)
    }
}

/// Crash and error reporting through the process-wide Sentry hub.
pub struct SentryReporter {
    client: Arc<sentry::Client>,
}

impl SentryReporter {
    /// Builds the client and binds it to the main hub, so panics anywhere in
    /// the process are reported. `enabled` gates every event, so an opt-out
    /// takes effect at once. Returns `None` for an invalid DSN.
    #[must_use]
    pub fn install(
        dsn: &str,
        environment: &str,
        install_id: &str,
        tags: &[(&'static str, String)],
        enabled: Arc<AtomicBool>,
        transport: Arc<dyn Transport>,
    ) -> Option<Self> {
        let dsn: Dsn = dsn.parse().ok()?;
        let client = Arc::new(sentry::Client::from(options(
            dsn,
            environment,
            enabled,
            transport,
            true,
        )));
        let hub = Hub::main();
        hub.bind_client(Some(client.clone()));
        let install_id = install_id.to_string();
        let tags = tags.to_vec();
        hub.configure_scope(move |scope| {
            scope.set_user(Some(User {
                id: Some(install_id),
                ..User::default()
            }));
            for (key, value) in tags {
                scope.set_tag(key, value);
            }
        });
        Some(Self { client })
    }

    /// Reports an unexpected error from `method` (message scrubbed by `before_send`).
    pub fn report_error(&self, method: &str, kind: &str, message: &str) {
        let mut event = error_event(method, kind, message);
        event.level = Level::Error;
        Hub::main().capture_event(event);
    }

    /// A blocking function that waits up to its timeout for reports in
    /// flight; run it off the async runtime.
    pub fn flusher(&self) -> impl FnOnce(Duration) -> bool + Send + 'static {
        let client = self.client.clone();
        move |timeout| client.flush(Some(timeout))
    }
}

/// The client options: no default integrations, no PII, no breadcrumbs,
/// every event scrubbed and gated by `enabled`. `panics` adds the panic
/// integration (production only: it installs a process-wide hook).
pub(super) fn options(
    dsn: Dsn,
    environment: &str,
    enabled: Arc<AtomicBool>,
    transport: Arc<dyn Transport>,
    panics: bool,
) -> ClientOptions {
    let env = Environment::current();
    let mut integrations: Vec<Arc<dyn sentry::Integration>> = Vec::new();
    if panics {
        integrations.push(Arc::new(
            sentry::integrations::panic::PanicIntegration::default(),
        ));
    }
    ClientOptions {
        dsn: Some(dsn),
        release: Some(Cow::Owned(format!(
            "agentpay-paymentd@{}",
            env!("CARGO_PKG_VERSION")
        ))),
        environment: Some(Cow::Owned(environment.to_string())),
        default_integrations: false,
        integrations,
        send_default_pii: false,
        server_name: None,
        attach_stacktrace: false,
        max_breadcrumbs: 0,
        before_breadcrumb: Some(Arc::new(|_| None)),
        before_send: Some(Arc::new(move |event| {
            enabled
                .load(Ordering::Relaxed)
                .then(|| scrub_event(event, &env))
        })),
        transport: Some(Arc::new(move |_: &ClientOptions| transport.clone())),
        shutdown_timeout: SEND_TIMEOUT,
        ..ClientOptions::default()
    }
}

/// An error event for `method`; `before_send` scrubs the message.
pub(super) fn error_event(method: &str, kind: &str, message: &str) -> Event<'static> {
    let mut event = Event {
        message: Some(format!("{method}: {kind}: {message}")),
        level: Level::Error,
        ..Event::default()
    };
    event.tags.insert("method".into(), method.to_string());
    event.tags.insert("error_kind".into(), kind.to_string());
    event
}

#[cfg(test)]
mod tests {
    use sentry::protocol::{Breadcrumb, Context, Mechanism, Values};

    use super::*;

    /// Captures envelopes in memory instead of sending them.
    #[derive(Default)]
    struct Captured(Mutex<Vec<Envelope>>);

    impl Transport for Captured {
        fn send_envelope(&self, envelope: Envelope) {
            self.0.lock().expect("captured").push(envelope);
        }
    }

    fn env() -> Environment {
        Environment {
            hostname: Some("alices-mbp".into()),
            home: Some("/Users/alice".into()),
        }
    }

    #[test]
    fn events_keep_only_scrubbed_errors_and_allowed_tags() {
        let mut event = error_event(
            "Transfer",
            "Internal",
            "send to 0x5aeda56215b167893e80b4fe645ba6d5bab767de via https://k@rpc.example/v3/key on alices-mbp",
        );
        event.tags.insert("wallet".into(), "0xabc".into());
        event.extra.insert("recipient".into(), "x".into());
        event
            .contexts
            .insert("device".into(), Context::Other(Default::default()));
        event.server_name = Some("alices-mbp".into());
        event.user = Some(User {
            id: Some("install".into()),
            email: Some("alice@example.com".into()),
            ..User::default()
        });
        event.breadcrumbs = Values::from(vec![Breadcrumb::default()]);
        event.exception = Values::from(vec![Exception {
            ty: "panic".into(),
            value: Some(
                "token 4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318".into(),
            ),
            stacktrace: Some(Stacktrace {
                frames: vec![Frame {
                    abs_path: Some("/Users/alice/src/main.rs".into()),
                    context_line: Some("let key = ...".into()),
                    ..Frame::default()
                }],
                ..Stacktrace::default()
            }),
            mechanism: Some(Mechanism {
                description: Some("secret".into()),
                ..Mechanism::default()
            }),
            ..Exception::default()
        }]);

        let event = scrub_event(event, &env());
        assert_eq!(
            event.message.as_deref(),
            Some("Transfer: Internal: send to <redacted> via https://rpc.example on <redacted>")
        );
        assert_eq!(event.tags.len(), 2);
        assert_eq!(event.tags["method"], "Transfer");
        assert!(event.extra.is_empty() && event.contexts.is_empty());
        assert!(event.server_name.is_none() && event.breadcrumbs.values.is_empty());
        let user = event.user.expect("user");
        assert_eq!(user.id.as_deref(), Some("install"));
        assert!(user.email.is_none());
        let exception = &event.exception.values[0];
        assert_eq!(exception.value.as_deref(), Some("token <redacted>"));
        let frame = &exception.stacktrace.as_ref().expect("stack").frames[0];
        assert_eq!(frame.abs_path.as_deref(), Some("~/src/main.rs"));
        assert!(frame.context_line.is_none());
        assert!(exception
            .mechanism
            .as_ref()
            .expect("mechanism")
            .description
            .is_none());
    }

    #[test]
    fn the_client_scrubs_and_honors_the_opt_out() {
        let captured = Arc::new(Captured::default());
        let enabled = Arc::new(AtomicBool::new(true));
        let dsn: Dsn = "https://public@sentry.example/1".parse().expect("dsn");
        let client = Arc::new(sentry::Client::from(options(
            dsn,
            "test",
            enabled.clone(),
            captured.clone(),
            false,
        )));
        let hub = Hub::new(Some(client.clone()), Arc::new(sentry::Scope::default()));
        hub.capture_event(error_event(
            "Status",
            "Internal",
            "at 0x5aeda56215b167893e80b4fe645ba6d5bab767de",
        ));
        enabled.store(false, Ordering::Relaxed);
        hub.capture_event(error_event("Status", "Internal", "dropped"));
        client.flush(Some(Duration::from_secs(1)));

        let envelopes = captured.0.lock().expect("captured");
        assert_eq!(envelopes.len(), 1, "the opt-out drops the second event");
        let event = envelopes[0].event().expect("event");
        assert_eq!(
            event.message.as_deref(),
            Some("Status: Internal: at <redacted>")
        );
        assert_eq!(event.environment.as_deref(), Some("test"));
    }
}
