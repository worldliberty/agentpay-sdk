//! Mixpanel analytics: a bounded in-memory queue drained by one background
//! task that posts batches to `/track` (ported from `telemetry-mixpanel`).
//!
//! [`Mixpanel::track`] never blocks and never fails: when the queue is full
//! the event is dropped. Events are not sent as they happen: the first event
//! of a batch picks a random send time up to an hour ahead ([`MAX_DELAY`]),
//! and every event queued until then goes with it, in requests of 50 with a
//! 2-second timeout each. A flush (at shutdown) sends at once. After a failed
//! delivery the task drops everything for an hour, so an offline or
//! firewalled machine does not pay a timeout on every batch.

use std::time::Duration;

use serde_json::{Map, Value};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

/// Timeout of one delivery.
const SEND_TIMEOUT: Duration = Duration::from_secs(2);
/// Largest batch Mixpanel accepts per request.
const MAX_BATCH: usize = 50;
/// Events waiting in the channel before new ones are dropped.
const QUEUE_CAPACITY: usize = 256;
/// Longest random delay between a batch's first event and its delivery.
pub const MAX_DELAY: Duration = Duration::from_secs(60 * 60);
/// Events held for the next delivery before new ones are dropped.
const MAX_PENDING: usize = 2_000;
/// How long to stop sending after a failed delivery.
const OFFLINE_BACKOFF: Duration = Duration::from_secs(60 * 60);
/// Timestamps are truncated to this, so events cannot be matched to block times.
const TIME_GRANULARITY_MS: u128 = 60_000;

enum Command {
    Event(Map<String, Value>),
    Flush(oneshot::Sender<bool>),
    Discard,
}

/// Handle to the Mixpanel task.
#[derive(Debug, Clone)]
pub struct Mixpanel {
    sender: mpsc::Sender<Command>,
}

impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Event(_) => "Event",
            Self::Flush(_) => "Flush",
            Self::Discard => "Discard",
        })
    }
}

impl Mixpanel {
    /// Starts the task on the current Tokio runtime. `token` and `distinct_id`
    /// are added to every event, after scrubbing. Each batch is sent after a
    /// random delay of up to [`MAX_DELAY`].
    #[must_use]
    pub fn start(http: reqwest::Client, url: String, token: String, distinct_id: String) -> Self {
        Self::start_with_delay(http, url, token, distinct_id, random_delay)
    }

    /// [`Mixpanel::start`] with each batch's delay chosen by `delay`.
    #[must_use]
    pub fn start_with_delay(
        http: reqwest::Client,
        url: String,
        token: String,
        distinct_id: String,
        delay: fn() -> Duration,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        let worker = Worker {
            http,
            url,
            token,
            distinct_id,
            batch: Vec::new(),
            send_at: None,
            delay,
            offline_until: None,
        };
        tokio::spawn(worker.run(receiver));
        Self { sender }
    }

    /// Queues an event whose `properties` are already scrubbed.
    pub fn track(&self, event: &str, mut properties: Map<String, Value>) {
        properties.insert("event_name".into(), Value::String(event.to_string()));
        let _ = self.sender.try_send(Command::Event(properties));
    }

    /// Drops everything queued (after an opt-out).
    pub fn discard(&self) {
        let _ = self.sender.try_send(Command::Discard);
    }

    /// Sends what is queued; `true` when it was delivered (or nothing was
    /// queued). The caller bounds the wait.
    pub async fn flush(&self) -> bool {
        let (done, delivered) = oneshot::channel();
        if self.sender.send(Command::Flush(done)).await.is_err() {
            return false;
        }
        delivered.await.unwrap_or(false)
    }
}

/// A uniformly random delay between zero and [`MAX_DELAY`].
fn random_delay() -> Duration {
    Duration::from_millis(rand::random_range(0..=duration_millis(MAX_DELAY)))
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

struct Worker {
    http: reqwest::Client,
    url: String,
    token: String,
    distinct_id: String,
    batch: Vec<Value>,
    /// When the pending batch is sent; `None` while nothing is pending.
    send_at: Option<Instant>,
    delay: fn() -> Duration,
    offline_until: Option<Instant>,
}

impl Worker {
    async fn run(mut self, mut receiver: mpsc::Receiver<Command>) {
        loop {
            let due = async {
                match self.send_at {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                command = receiver.recv() => match command {
                    Some(Command::Event(properties)) => self.push(properties),
                    Some(Command::Flush(done)) => {
                        let delivered = self.send().await;
                        let _ = done.send(delivered);
                    }
                    Some(Command::Discard) => {
                        self.batch.clear();
                        self.send_at = None;
                    }
                    None => {
                        self.send().await;
                        return;
                    }
                },
                () = due => {
                    self.send().await;
                }
            }
        }
    }

    fn push(&mut self, mut properties: Map<String, Value>) {
        if self
            .offline_until
            .is_some_and(|until| Instant::now() < until)
            || self.batch.len() >= MAX_PENDING
        {
            return;
        }
        if self.send_at.is_none() {
            self.send_at = Some(Instant::now() + (self.delay)());
        }
        let event = properties
            .remove("event_name")
            .unwrap_or_else(|| Value::String("event".into()));
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis());
        let time = now_ms / TIME_GRANULARITY_MS * TIME_GRANULARITY_MS;
        properties.insert(
            "distinct_id".into(),
            Value::String(self.distinct_id.clone()),
        );
        properties.insert("token".into(), Value::String(self.token.clone()));
        // Mixpanel's standard app version property (shown as "App Version").
        properties.insert(
            "$app_version_string".into(),
            Value::String(env!("CARGO_PKG_VERSION").into()),
        );
        properties.insert(
            "$insert_id".into(),
            Value::String(uuid::Uuid::new_v4().simple().to_string()),
        );
        properties.insert("time".into(), Value::from(u64::try_from(time).unwrap_or(0)));
        self.batch.push(serde_json::json!({
            "event": event,
            "properties": Value::Object(properties),
        }));
    }

    /// Posts the pending events, [`MAX_BATCH`] per request; `true` when all
    /// were delivered (or none were pending). After a failed request the rest
    /// is dropped and the task goes offline.
    async fn send(&mut self) -> bool {
        self.send_at = None;
        let pending = std::mem::take(&mut self.batch);
        for chunk in pending.chunks(MAX_BATCH) {
            let delivered = matches!(
                self.http
                    .post(&self.url)
                    .timeout(SEND_TIMEOUT)
                    .json(&Value::Array(chunk.to_vec()))
                    .send()
                    .await,
                Ok(response) if response.status().is_success()
            );
            if !delivered {
                self.offline_until = Some(Instant::now() + OFFLINE_BACKOFF);
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// A loopback `/track` endpoint that records request bodies.
    async fn endpoint(status: u16) -> (String, Arc<Mutex<Vec<Value>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!("http://{}/track?ip=0", listener.local_addr().expect("addr"));
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let seen = bodies.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buffer = Vec::new();
                let mut chunk = [0_u8; 4096];
                let body = loop {
                    let Ok(read) = stream.read(&mut chunk).await else {
                        break None;
                    };
                    if read == 0 {
                        break None;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                    let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let head = String::from_utf8_lossy(&buffer[..end]).to_ascii_lowercase();
                    let length = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if buffer.len() >= end + 4 + length {
                        break Some(buffer[end + 4..end + 4 + length].to_vec());
                    }
                };
                if let Some(body) = body.and_then(|b| serde_json::from_slice(&b).ok()) {
                    seen.lock().expect("bodies").push(body);
                }
                let response = format!(
                    "HTTP/1.1 {status} X\r\ncontent-length: 1\r\nconnection: close\r\n\r\n1"
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        (url, bodies)
    }

    fn properties(method: &str) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("method".into(), Value::String(method.into()));
        map
    }

    #[tokio::test]
    async fn queued_events_are_posted_as_one_batch_with_identity_and_coarse_time() {
        let (url, bodies) = endpoint(200).await;
        let mixpanel = Mixpanel::start(reqwest::Client::new(), url, "tok".into(), "id-1".into());
        mixpanel.track("paymentd_request", properties("Transfer"));
        mixpanel.track("paymentd_request", properties("Status"));
        assert!(mixpanel.flush().await);
        let bodies = bodies.lock().expect("bodies").clone();
        assert_eq!(bodies.len(), 1);
        let events = bodies[0].as_array().expect("batch");
        assert_eq!(events.len(), 2);
        let first = &events[0];
        assert_eq!(first["event"], "paymentd_request");
        assert_eq!(first["properties"]["method"], "Transfer");
        assert_eq!(first["properties"]["distinct_id"], "id-1");
        assert_eq!(first["properties"]["token"], "tok");
        let time = first["properties"]["time"].as_u64().expect("time");
        assert_eq!(time % 60_000, 0);
        // Nothing queued: a flush sends nothing and succeeds.
        assert!(mixpanel.flush().await);
    }

    #[tokio::test]
    async fn a_failed_delivery_backs_off_and_discard_drops_the_queue() {
        let (url, bodies) = endpoint(500).await;
        let mixpanel = Mixpanel::start(reqwest::Client::new(), url, "tok".into(), "id".into());
        mixpanel.track("e", properties("A"));
        assert!(!mixpanel.flush().await);
        // Offline: new events are dropped instead of queued.
        mixpanel.track("e", properties("B"));
        assert!(mixpanel.flush().await);
        assert_eq!(bodies.lock().expect("bodies").len(), 1);

        let (url, bodies) = endpoint(200).await;
        let mixpanel = Mixpanel::start(reqwest::Client::new(), url, "tok".into(), "id".into());
        mixpanel.track("e", properties("C"));
        mixpanel.discard();
        assert!(mixpanel.flush().await);
        assert!(bodies.lock().expect("bodies").is_empty());
    }

    fn short() -> Duration {
        Duration::from_millis(300)
    }

    fn shorter() -> Duration {
        Duration::from_millis(100)
    }

    fn an_hour() -> Duration {
        MAX_DELAY
    }

    #[tokio::test]
    async fn events_wait_for_the_batch_delay_then_go_together_with_the_version() {
        let (url, bodies) = endpoint(200).await;
        let mixpanel = Mixpanel::start_with_delay(
            reqwest::Client::new(),
            url,
            "tok".into(),
            "id".into(),
            short,
        );
        mixpanel.track("paymentd_request", properties("Status"));
        mixpanel.track("paymentd_request", properties("MppFetch"));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            bodies.lock().expect("bodies").is_empty(),
            "nothing before the delay"
        );
        tokio::time::sleep(Duration::from_millis(600)).await;
        let sent = bodies.lock().expect("bodies").clone();
        assert_eq!(sent.len(), 1, "one delivery for the batch");
        let events = sent[0].as_array().expect("batch");
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0]["properties"]["$app_version_string"],
            env!("CARGO_PKG_VERSION")
        );
    }

    #[tokio::test]
    async fn a_large_batch_goes_in_requests_of_fifty() {
        let (url, bodies) = endpoint(200).await;
        let mixpanel = Mixpanel::start_with_delay(
            reqwest::Client::new(),
            url,
            "tok".into(),
            "id".into(),
            shorter,
        );
        for _ in 0..120 {
            mixpanel.track("paymentd_request", properties("Status"));
        }
        tokio::time::sleep(Duration::from_millis(800)).await;
        let sizes: Vec<usize> = bodies
            .lock()
            .expect("bodies")
            .iter()
            .map(|body| body.as_array().map_or(0, Vec::len))
            .collect();
        assert_eq!(sizes, [50, 50, 20]);
    }

    #[tokio::test]
    async fn a_flush_sends_at_once_whatever_the_delay() {
        let (url, bodies) = endpoint(200).await;
        let mixpanel = Mixpanel::start_with_delay(
            reqwest::Client::new(),
            url,
            "tok".into(),
            "id".into(),
            an_hour,
        );
        mixpanel.track("paymentd_request", properties("Status"));
        assert!(mixpanel.flush().await);
        assert_eq!(bodies.lock().expect("bodies").len(), 1);
    }

    #[test]
    fn the_random_delay_is_at_most_an_hour() {
        for _ in 0..1_000 {
            assert!(random_delay() <= MAX_DELAY);
        }
    }
}
