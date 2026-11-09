//! Compute budget and priority fee caps for Solana transactions.
//!
//! Every transaction paymentd builds sets a compute unit limit, and may set
//! a compute unit price (the priority fee). The price comes from the caller,
//! or else from the cluster's recent prioritization fees, which an RPC
//! endpoint controls, so it is clamped to the caps here, and the signed
//! transaction is checked against the same caps before it is broadcast.

use crate::error::PaymentsError;

/// Largest compute unit limit the runtime grants a transaction.
pub const MAX_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;
/// Highest compute unit price accepted, in micro-lamports per unit.
pub const MAX_COMPUTE_UNIT_PRICE_MICRO_LAMPORTS: u64 = 10_000_000;
/// Highest priority fee accepted per transaction, in lamports (0.01 SOL).
pub const MAX_PRIORITY_FEE_LAMPORTS: u64 = 10_000_000;
/// Default compute unit limit of a SOL transfer.
pub const SOL_TRANSFER_COMPUTE_UNIT_LIMIT: u32 = 5_000;
/// Default compute unit limit of an SPL transfer.
pub const SPL_TRANSFER_COMPUTE_UNIT_LIMIT: u32 = 20_000;

const MICRO_LAMPORTS_PER_LAMPORT: u128 = 1_000_000;

/// A transaction's compute budget instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputeBudget {
    /// `SetComputeUnitLimit`.
    pub unit_limit: Option<u32>,
    /// `SetComputeUnitPrice`, in micro-lamports per unit.
    pub unit_price: Option<u64>,
}

impl ComputeBudget {
    /// Worst-case priority fee in lamports. Without a limit the runtime may
    /// grant up to [`MAX_COMPUTE_UNIT_LIMIT`] units, so that is assumed.
    #[must_use]
    pub fn priority_fee_lamports(&self) -> u128 {
        let Some(price) = self.unit_price.filter(|price| *price > 0) else {
            return 0;
        };
        let units = u128::from(self.unit_limit.unwrap_or(MAX_COMPUTE_UNIT_LIMIT));
        (units * u128::from(price)).div_ceil(MICRO_LAMPORTS_PER_LAMPORT)
    }

    /// Checks the price and the total priority fee against the caps.
    pub fn check_caps(&self) -> Result<(), String> {
        let price = self.unit_price.unwrap_or(0);
        if price > MAX_COMPUTE_UNIT_PRICE_MICRO_LAMPORTS {
            return Err(format!(
                "compute unit price {price} micro-lamports exceeds the maximum \
                 {MAX_COMPUTE_UNIT_PRICE_MICRO_LAMPORTS}"
            ));
        }
        let fee = self.priority_fee_lamports();
        if fee > u128::from(MAX_PRIORITY_FEE_LAMPORTS) {
            return Err(format!(
                "priority fee {fee} lamports exceeds the maximum {MAX_PRIORITY_FEE_LAMPORTS}"
            ));
        }
        Ok(())
    }
}

/// Resolves the compute budget for a transfer.
///
/// - `limit`: the caller's limit (1 to [`MAX_COMPUTE_UNIT_LIMIT`]), else `default_limit`.
/// - `price`: the caller's price, which must be within the caps, else the
///   median of `recent_fees` (non-zero entries only), clamped to the caps;
///   `None` when there is no estimate.
pub fn resolve(
    default_limit: u32,
    limit: Option<u32>,
    price: Option<u64>,
    recent_fees: Option<Vec<u64>>,
) -> Result<ComputeBudget, PaymentsError> {
    let unit_limit = limit.unwrap_or(default_limit);
    if unit_limit == 0 || unit_limit > MAX_COMPUTE_UNIT_LIMIT {
        return Err(PaymentsError::InvalidRequest(format!(
            "compute_unit_limit must be between 1 and {MAX_COMPUTE_UNIT_LIMIT}"
        )));
    }
    if let Some(price) = price {
        if price == 0 {
            return Err(PaymentsError::InvalidRequest(
                "compute_unit_price_micro_lamports must be greater than zero".into(),
            ));
        }
        let budget = ComputeBudget {
            unit_limit: Some(unit_limit),
            unit_price: Some(price),
        };
        budget.check_caps().map_err(PaymentsError::InvalidRequest)?;
        return Ok(budget);
    }
    let estimate = recent_fees
        .and_then(median_nonzero)
        .map(|fee| cap_price(fee, unit_limit))
        .filter(|price| *price > 0);
    Ok(ComputeBudget {
        unit_limit: Some(unit_limit),
        unit_price: estimate,
    })
}

/// The median (lower middle) of the non-zero fees.
fn median_nonzero(fees: Vec<u64>) -> Option<u64> {
    let mut fees: Vec<u64> = fees.into_iter().filter(|fee| *fee > 0).collect();
    if fees.is_empty() {
        return None;
    }
    fees.sort_unstable();
    fees.get((fees.len() - 1) / 2).copied()
}

/// Lowers `price` until both caps hold for `unit_limit` units.
fn cap_price(price: u64, unit_limit: u32) -> u64 {
    let for_max_fee = u128::from(MAX_PRIORITY_FEE_LAMPORTS) * MICRO_LAMPORTS_PER_LAMPORT
        / u128::from(unit_limit.max(1));
    let for_max_fee = u64::try_from(for_max_fee).unwrap_or(u64::MAX);
    price
        .min(MAX_COMPUTE_UNIT_PRICE_MICRO_LAMPORTS)
        .min(for_max_fee)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_fee_rounds_up_and_assumes_the_maximum_limit() {
        let budget = |limit, price| ComputeBudget {
            unit_limit: limit,
            unit_price: price,
        };
        assert_eq!(budget(Some(5_000), None).priority_fee_lamports(), 0);
        assert_eq!(budget(Some(5_000), Some(1)).priority_fee_lamports(), 1);
        assert_eq!(
            budget(Some(20_000), Some(1_000_000)).priority_fee_lamports(),
            20_000
        );
        assert_eq!(budget(None, Some(10)).priority_fee_lamports(), 14);
    }

    #[test]
    fn caps_reject_expensive_prices_and_fees() {
        let over_price = ComputeBudget {
            unit_limit: Some(1),
            unit_price: Some(MAX_COMPUTE_UNIT_PRICE_MICRO_LAMPORTS + 1),
        };
        assert!(over_price.check_caps().is_err());
        let over_fee = ComputeBudget {
            unit_limit: Some(MAX_COMPUTE_UNIT_LIMIT),
            unit_price: Some(MAX_COMPUTE_UNIT_PRICE_MICRO_LAMPORTS),
        };
        assert!(over_fee.check_caps().is_err());
        let fine = ComputeBudget {
            unit_limit: Some(20_000),
            unit_price: Some(MAX_COMPUTE_UNIT_PRICE_MICRO_LAMPORTS),
        };
        assert!(fine.check_caps().is_ok());
    }

    #[test]
    fn explicit_values_are_validated() {
        assert!(resolve(5_000, Some(0), None, None).is_err());
        assert!(resolve(5_000, Some(MAX_COMPUTE_UNIT_LIMIT + 1), None, None).is_err());
        assert!(resolve(5_000, None, Some(0), None).is_err());
        assert!(resolve(
            1_400_000,
            None,
            Some(MAX_COMPUTE_UNIT_PRICE_MICRO_LAMPORTS),
            None
        )
        .is_err());
        assert_eq!(
            resolve(5_000, Some(7_000), Some(42), Some(vec![1, 2, 3])).expect("explicit"),
            ComputeBudget {
                unit_limit: Some(7_000),
                unit_price: Some(42)
            }
        );
    }

    #[test]
    fn estimates_use_the_nonzero_median_and_are_clamped() {
        let estimate = |fees: Vec<u64>| resolve(20_000, None, None, Some(fees)).expect("ok");
        assert_eq!(estimate(vec![0, 0, 300, 100, 200]).unit_price, Some(200));
        assert_eq!(estimate(vec![0, 0]).unit_price, None);
        assert_eq!(
            resolve(20_000, None, None, None).expect("ok").unit_price,
            None
        );
        // A hostile RPC cannot push the price past either cap.
        let clamped = estimate(vec![u64::MAX]);
        assert_eq!(
            clamped.unit_price,
            Some(MAX_COMPUTE_UNIT_PRICE_MICRO_LAMPORTS)
        );
        assert!(clamped.check_caps().is_ok());
        let wide = resolve(MAX_COMPUTE_UNIT_LIMIT, None, None, Some(vec![u64::MAX])).expect("ok");
        assert!(wide.check_caps().is_ok());
        assert_eq!(wide.unit_limit, Some(MAX_COMPUTE_UNIT_LIMIT));
    }
}
