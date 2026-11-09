//! Choosing among a chain's RPC endpoints at connect time: `rpc_url`, then
//! each of `fallback_rpc_urls` in order, with the endpoint that answered
//! kept preferred for [`PREFERENCE_TTL`].
//!
//! The provider's own check (EVM chain id, Solana cluster) decides whether
//! an endpoint works. Failover happens only while connecting: every request
//! made afterwards, including a transaction send, goes to the one endpoint
//! that was chosen, so a send is never raced or repeated across endpoints.
//!
//! **Timeouts.** Callers bound a whole connect with their own budget (10 s
//! for balances, 5 s for `Status`). With backups, each attempt is capped at
//! [`ATTEMPT_TIMEOUT`] so a hanging primary leaves time for the backups
//! (three endpoints fit in the 10-second budget). A dead endpoint usually
//! fails much faster (refused connection, DNS, HTTP error), and the
//! preference means it is skipped on the next calls. With a single endpoint
//! no cap is added.
//!
//! Errors never quote an endpoint: URLs may embed API keys.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::PaymentsError;

/// How long the endpoint that answered after a failover stays preferred.
pub const PREFERENCE_TTL: Duration = Duration::from_secs(600);
/// Longest one connection attempt may take when the chain has backups.
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);

/// The current time; injectable so tests can move it forward.
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// A connection and whether it uses a backup endpoint.
#[derive(Debug)]
pub struct Connected<T> {
    /// The connection.
    pub value: T,
    /// `true` when it is not the chain's `rpc_url`.
    pub backup: bool,
}

/// The preferred endpoint of each network, shared by a provider's connects.
pub struct Failover {
    preferred: Mutex<HashMap<(String, u64), Preference>>,
    clock: Clock,
}

/// A backup that answered while `rpc_url` did not.
struct Preference {
    /// The endpoint list it was chosen from; a changed configuration
    /// invalidates it.
    endpoints: Vec<String>,
    index: usize,
    until: Instant,
}

impl Default for Failover {
    fn default() -> Self {
        Self::with_clock(Arc::new(Instant::now))
    }
}

impl Failover {
    /// A failover whose preferences expire by `clock`.
    #[must_use]
    pub fn with_clock(clock: Clock) -> Self {
        Self {
            preferred: Mutex::new(HashMap::new()),
            clock,
        }
    }

    /// Connects through the first endpoint for which `attempt` succeeds:
    /// the preferred one if any, else `endpoints` in order. `attempt` gets an
    /// index into `endpoints`. When every endpoint fails, the error is the
    /// first endpoint's (`rpc_url`), with the number of backups that also
    /// failed appended; its kind is unchanged.
    pub async fn connect<T, F, Fut>(
        &self,
        network: &str,
        chain_id: u64,
        endpoints: &[String],
        mut attempt: F,
    ) -> Result<Connected<T>, PaymentsError>
    where
        F: FnMut(usize) -> Fut,
        Fut: Future<Output = Result<T, PaymentsError>>,
    {
        if endpoints.len() <= 1 {
            return attempt(0).await.map(|value| Connected {
                value,
                backup: false,
            });
        }
        let key = (network.to_string(), chain_id);
        let mut primary_error = None;
        for index in self.order(&key, endpoints) {
            let result = tokio::time::timeout(ATTEMPT_TIMEOUT, attempt(index))
                .await
                .unwrap_or_else(|_| {
                    Err(PaymentsError::ChainRpc(format!(
                        "the RPC endpoint of network '{network}' did not answer within {} ms",
                        ATTEMPT_TIMEOUT.as_millis()
                    )))
                });
            match result {
                Ok(value) => {
                    self.record(key, endpoints, index);
                    return Ok(Connected {
                        value,
                        backup: index != 0,
                    });
                }
                Err(error) if index == 0 => primary_error = Some(error),
                Err(_) => {}
            }
        }
        let error = primary_error
            .unwrap_or_else(|| PaymentsError::Internal("no RPC endpoint was tried".into()));
        Err(with_backups_failed(error, endpoints.len() - 1))
    }

    /// Endpoint indices to try: the preferred one first, then the others in order.
    fn order(&self, key: &(String, u64), endpoints: &[String]) -> Vec<usize> {
        let now = (self.clock)();
        let preferred = self.preferred.lock().ok().and_then(|mut preferred| {
            let valid = preferred
                .get(key)
                .filter(|p| p.endpoints == endpoints && now < p.until && p.index < endpoints.len())
                .map(|p| p.index);
            if valid.is_none() {
                preferred.remove(key);
            }
            valid
        });
        let mut order: Vec<usize> = preferred.into_iter().collect();
        order.extend((0..endpoints.len()).filter(|index| Some(*index) != preferred));
        order
    }

    /// Remembers that `index` answered: a backup becomes preferred for
    /// [`PREFERENCE_TTL`] (an existing preference for it is not extended);
    /// the primary clears any preference.
    fn record(&self, key: (String, u64), endpoints: &[String], index: usize) {
        let now = (self.clock)();
        let Ok(mut preferred) = self.preferred.lock() else {
            return;
        };
        if index == 0 {
            preferred.remove(&key);
            return;
        }
        let current = preferred
            .get(&key)
            .is_some_and(|p| p.endpoints == endpoints && p.index == index && now < p.until);
        if !current {
            preferred.insert(
                key,
                Preference {
                    endpoints: endpoints.to_vec(),
                    index,
                    until: now + PREFERENCE_TTL,
                },
            );
        }
    }
}

/// `error` with " (N backup RPCs also failed)" appended to its message.
fn with_backups_failed(error: PaymentsError, backups: usize) -> PaymentsError {
    let suffix = if backups == 1 {
        " (1 backup RPC also failed)".to_string()
    } else {
        format!(" ({backups} backup RPCs also failed)")
    };
    match error {
        PaymentsError::ChainRpc(message) => PaymentsError::ChainRpc(message + &suffix),
        PaymentsError::InvalidRequest(message) => PaymentsError::InvalidRequest(message + &suffix),
        PaymentsError::Internal(message) => PaymentsError::Internal(message + &suffix),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoints(count: usize) -> Vec<String> {
        (0..count)
            .map(|i| format!("https://rpc{i}.example"))
            .collect()
    }

    /// A clock tests can move forward.
    fn manual_clock() -> (Clock, Arc<Mutex<Instant>>) {
        let now = Arc::new(Mutex::new(Instant::now()));
        let shared = now.clone();
        let clock: Clock = Arc::new(move || *shared.lock().expect("clock"));
        (clock, now)
    }

    /// Connects with endpoints `0..count`, where those in `working` succeed;
    /// returns the chosen index and every index tried.
    async fn run(
        failover: &Failover,
        count: usize,
        working: &[usize],
    ) -> (Result<Connected<usize>, PaymentsError>, Vec<usize>) {
        let tried = Mutex::new(Vec::new());
        let result = failover
            .connect("bsc", 56, &endpoints(count), |index| {
                tried.lock().expect("tried").push(index);
                let ok = working.contains(&index);
                async move {
                    if ok {
                        Ok(index)
                    } else {
                        Err(PaymentsError::ChainRpc(format!("endpoint {index} failed")))
                    }
                }
            })
            .await;
        (result, tried.into_inner().expect("tried"))
    }

    #[tokio::test]
    async fn endpoints_are_tried_in_order_until_one_answers() {
        let failover = Failover::default();
        let (result, tried) = run(&failover, 3, &[2]).await;
        let connected = result.expect("connected");
        assert_eq!((connected.value, connected.backup), (2, true));
        assert_eq!(tried, [0, 1, 2]);

        let (result, tried) = run(&Failover::default(), 3, &[0, 1, 2]).await;
        assert!(!result.expect("primary").backup);
        assert_eq!(tried, [0]);
    }

    #[tokio::test]
    async fn a_working_backup_stays_preferred_until_the_preference_expires() {
        let (clock, now) = manual_clock();
        let failover = Failover::with_clock(clock);
        run(&failover, 3, &[1, 2]).await.0.expect("backup");

        // The primary recovered, but the backup is still preferred.
        let (result, tried) = run(&failover, 3, &[0, 1, 2]).await;
        assert_eq!(result.expect("preferred").value, 1);
        assert_eq!(tried, [1]);

        // The preferred backup failed: the others are tried in order.
        let (result, tried) = run(&failover, 3, &[2]).await;
        assert_eq!(result.expect("next").value, 2);
        assert_eq!(tried, [1, 0, 2]);

        // Not extended by use: after the TTL the primary comes first again.
        *now.lock().expect("clock") += PREFERENCE_TTL - Duration::from_secs(1);
        let (_, tried) = run(&failover, 3, &[0, 1, 2]).await;
        assert_eq!(tried, [2]);
        *now.lock().expect("clock") += Duration::from_secs(1);
        let (result, tried) = run(&failover, 3, &[0, 1, 2]).await;
        assert!(!result.expect("primary").backup);
        assert_eq!(tried, [0]);

        // A changed endpoint list drops the preference.
        run(&failover, 3, &[1]).await.0.expect("backup");
        let (_, tried) = run(&failover, 2, &[0, 1]).await;
        assert_eq!(tried, [0]);
    }

    #[tokio::test]
    async fn when_all_fail_the_primary_error_reports_the_backups() {
        let (result, tried) = run(&Failover::default(), 3, &[]).await;
        assert_eq!(tried, [0, 1, 2]);
        assert_eq!(
            result.expect_err("all fail"),
            PaymentsError::ChainRpc("endpoint 0 failed (2 backup RPCs also failed)".into())
        );
        let (result, _) = run(&Failover::default(), 2, &[]).await;
        assert_eq!(
            result.expect_err("all fail"),
            PaymentsError::ChainRpc("endpoint 0 failed (1 backup RPC also failed)".into())
        );
        // A single endpoint keeps its own error.
        let (result, _) = run(&Failover::default(), 1, &[]).await;
        assert_eq!(
            result.expect_err("fails"),
            PaymentsError::ChainRpc("endpoint 0 failed".into())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_hanging_endpoint_is_abandoned_after_the_attempt_timeout() {
        let failover = Failover::default();
        let result = failover
            .connect("bsc", 56, &endpoints(2), |index| async move {
                if index == 0 {
                    std::future::pending::<()>().await;
                }
                Ok(index)
            })
            .await;
        assert_eq!(result.expect("backup").value, 1);
    }
}
