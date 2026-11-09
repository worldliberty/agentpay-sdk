//! Mixpanel analytics: a bounded in-memory queue drained by one background
//! task that posts batches to `/track` (ported from `telemetry-mixpanel`).
//!
//! [`Mixpanel::track`] never blocks and never fails: when the queue is full
//! the event is dropped. The task sends a batch when 50 events are queued or
//! every 30 seconds, with a 2-second timeout. After a failed delivery it
//! drops everything for an hour, so an offline or firewalled machine does not
//! pay a timeout on every batch.

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
/// How often a partial batch is sent.
const FLUSH_INTERVAL: Duration = Duration::from_secs(30);
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
    /// are added to every event, after scrubbing.
    #[must_use]
    pub fn start(http: reqwest::Client, url: String, token: String, distinct_id: String) -> Self {
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        let worker = Worker {
            http,
            url,
            token,
            distinct_id,
            batch: Vec::new(),
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

struct Worker {
    http: reqwest::Client,
    url: String,
    token: String,
    distinct_id: String,
    batch: Vec<Value>,
    offline_until: Option<Instant>,
}

impl Worker {
    async fn run(mut self, mut receiver: mpsc::Receiver<Command>) {
        let mut ticker = tokio::time::interval(FLUSH_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                command = receiver.recv() => match command {
                    Some(Command::Event(properties)) => {
                        self.push(properties);
                        if self.batch.len() >= MAX_BATCH {
                            self.send().await;
                        }
                    }
                    Some(Command::Flush(done)) => {
                        let delivered = self.send().await;
                        let _ = done.send(delivered);
                    }
                    Some(Command::Discard) => self.batch.clear(),
                    None => {
                        self.send().await;
                        return;
                    }
                },
                _ = ticker.tick() => {
                    self.send().await;
                }
            }
        }
    }

    fn push(&mut self, mut properties: Map<String, Value>) {
        if self
            .offline_until
            .is_some_and(|until| Instant::now() < until)
        {
            return;
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

    /// Posts the batch; `true` when delivered or empty.
    async fn send(&mut self) -> bool {
        if self.batch.is_empty() {
            return true;
        }
        let payload = Value::Array(std::mem::take(&mut self.batch));
        let delivered = matches!(
            self.http
                .post(&self.url)
                .timeout(SEND_TIMEOUT)
                .json(&payload)
                .send()
                .await,
            Ok(response) if response.status().is_success()
        );
        if !delivered {
            self.offline_until = Some(Instant::now() + OFFLINE_BACKOFF);
        }
        delivered
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
}
