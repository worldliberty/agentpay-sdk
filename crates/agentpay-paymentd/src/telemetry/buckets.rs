//! Coarse buckets: telemetry never carries an exact amount or duration.

use std::time::Duration;

use agentpay_api::payments::{PaymentsRpcRequest as Req, SolanaAmount};

/// Lamports per SOL.
const LAMPORTS_PER_SOL: f64 = 1_000_000_000.0;

/// The range an amount in whole units falls in (as in the TypeScript CLI).
#[must_use]
pub fn amount_bucket(amount: f64) -> Option<&'static str> {
    if !amount.is_finite() || amount < 0.0 {
        return None;
    }
    Some(match amount {
        0.0 => "0",
        a if a < 10.0 => "<10",
        a if a < 100.0 => "10-100",
        a if a < 1_000.0 => "100-1k",
        a if a < 10_000.0 => "1k-10k",
        _ => "10k+",
    })
}

/// The bucket of a decimal string in whole units, such as `"12.5"`.
#[must_use]
pub fn decimal_bucket(amount: &str) -> Option<&'static str> {
    let amount = amount.trim();
    if amount.is_empty() || !amount.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return None;
    }
    amount.parse::<f64>().ok().and_then(amount_bucket)
}

/// The range a call's duration falls in.
#[must_use]
pub fn duration_bucket(elapsed: Duration) -> &'static str {
    match elapsed.as_millis() {
        0..100 => "<100ms",
        100..1_000 => "100ms-1s",
        1_000..5_000 => "1-5s",
        5_000..30_000 => "5-30s",
        _ => "30s+",
    }
}

/// The amount bucket of a payment request, in whole units of its asset;
/// `None` for requests that move no amount, or whose amount's decimals are
/// unknown before the call (SPL base units).
#[must_use]
pub fn request_amount_bucket(request: &Req) -> Option<&'static str> {
    match request {
        Req::Transfer(params) => decimal_bucket(&params.amount),
        Req::TransferNative(params) => decimal_bucket(&params.amount),
        Req::Approve(params) => decimal_bucket(&params.amount),
        Req::TransferSol(params) => match &params.amount {
            SolanaAmount::Decimal(amount) => decimal_bucket(amount),
            // Exact for any realistic amount; only the bucket is kept.
            #[allow(clippy::cast_precision_loss)]
            SolanaAmount::BaseUnits(lamports) => amount_bucket(*lamports as f64 / LAMPORTS_PER_SOL),
        },
        Req::TransferSpl(params) => match &params.amount {
            SolanaAmount::Decimal(amount) => decimal_bucket(amount),
            SolanaAmount::BaseUnits(_) => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_fall_in_coarse_ranges() {
        assert_eq!(amount_bucket(0.0), Some("0"));
        assert_eq!(amount_bucket(9.99), Some("<10"));
        assert_eq!(amount_bucket(10.0), Some("10-100"));
        assert_eq!(amount_bucket(999.0), Some("100-1k"));
        assert_eq!(amount_bucket(1_000.0), Some("1k-10k"));
        assert_eq!(amount_bucket(10_000.0), Some("10k+"));
        assert_eq!(amount_bucket(-1.0), None);
        assert_eq!(amount_bucket(f64::NAN), None);
        assert_eq!(decimal_bucket(" 12.5 "), Some("10-100"));
        assert_eq!(decimal_bucket("1e9"), None);
        assert_eq!(decimal_bucket(""), None);
    }

    #[test]
    fn durations_fall_in_coarse_ranges() {
        assert_eq!(duration_bucket(Duration::from_millis(5)), "<100ms");
        assert_eq!(duration_bucket(Duration::from_millis(100)), "100ms-1s");
        assert_eq!(duration_bucket(Duration::from_secs(2)), "1-5s");
        assert_eq!(duration_bucket(Duration::from_secs(10)), "5-30s");
        assert_eq!(duration_bucket(Duration::from_secs(60)), "30s+");
    }

    #[test]
    fn payment_requests_report_their_amount_bucket() {
        let auth = serde_json::json!({"agent_key_id": uuid::Uuid::nil(), "agent_auth_token": "t"});
        let request =
            |value: serde_json::Value| -> Req { serde_json::from_value(value).expect("request") };
        let transfer = request(serde_json::json!({"method": "Transfer", "params": {
            "auth": auth, "to": "0x5aeda56215b167893e80b4fe645ba6d5bab767de", "amount": "250"}}));
        assert_eq!(request_amount_bucket(&transfer), Some("100-1k"));
        let sol = request(serde_json::json!({"method": "TransferSol", "params": {
            "auth": auth, "network": "solana", "to": "9fijMemJYwXS5QD85Qxsq7iKqvSebgb6LvpGftgkeigk",
            "amount": {"base_units": "1500000000"}}}));
        assert_eq!(request_amount_bucket(&sol), Some("<10"));
        let config = request(serde_json::json!({"method": "GetConfig", "params": {"auth": auth}}));
        assert_eq!(request_amount_bucket(&config), None);
    }
}
