//! Converting a [`SolanaAmount`] to on-chain base units.

use agentpay_api::payments::SolanaAmount;

use crate::error::PaymentsError;

/// The amount in base units: between 1 and `u64::MAX`, the range a Solana
/// transfer instruction carries.
pub(super) fn base_units(amount: &SolanaAmount, decimals: u8) -> Result<u64, PaymentsError> {
    let units = match amount {
        SolanaAmount::BaseUnits(units) => *units,
        SolanaAmount::Decimal(text) => parse_decimal(text, decimals)?,
    };
    if units == 0 {
        return Err(invalid("amount must be greater than zero"));
    }
    u64::try_from(units).map_err(|_| invalid("amount exceeds the largest Solana amount"))
}

/// Parses `"12.345"` with `decimals` decimals into base units.
fn parse_decimal(text: &str, decimals: u8) -> Result<u128, PaymentsError> {
    let text = text.trim();
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    let digits = |part: &str| part.bytes().all(|byte| byte.is_ascii_digit());
    if (whole.is_empty() && fraction.is_empty()) || !digits(whole) || !digits(fraction) {
        return Err(invalid(
            "amount must be a plain decimal number such as \"1.5\"",
        ));
    }
    if fraction.len() > usize::from(decimals) {
        return Err(invalid(&format!(
            "amount has more than {decimals} decimal places"
        )));
    }
    let padded = format!("{whole}{fraction:0<width$}", width = usize::from(decimals));
    let padded = padded.trim_start_matches('0');
    if padded.is_empty() {
        return Ok(0);
    }
    padded
        .parse::<u128>()
        .map_err(|_| invalid("amount is too large"))
}

fn invalid(reason: &str) -> PaymentsError {
    PaymentsError::InvalidRequest(reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decimal(text: &str, decimals: u8) -> Result<u64, PaymentsError> {
        base_units(&SolanaAmount::Decimal(text.into()), decimals)
    }

    #[test]
    fn decimals_scale_to_base_units() {
        assert_eq!(decimal("1", 9), Ok(1_000_000_000));
        assert_eq!(decimal("0.0015", 9), Ok(1_500_000));
        assert_eq!(decimal(".5", 6), Ok(500_000));
        assert_eq!(decimal("2.", 6), Ok(2_000_000));
        assert_eq!(decimal("007", 0), Ok(7));
        assert_eq!(base_units(&SolanaAmount::BaseUnits(42), 9), Ok(42));
    }

    #[test]
    fn malformed_zero_and_oversized_amounts_are_refused() {
        for bad in ["", ".", "-1", "1e9", "1,5", "0x10", " 1 .5", "1.2.3"] {
            assert!(decimal(bad, 9).is_err(), "{bad:?}");
        }
        assert!(decimal("0.0000000001", 9).is_err(), "too many decimals");
        assert!(decimal("0", 9).is_err());
        assert!(decimal("0.000", 9).is_err());
        assert!(decimal("18446744073.709551616", 9).is_err(), "u64::MAX + 1");
        assert_eq!(decimal("18446744073.709551615", 9), Ok(u64::MAX));
        assert!(base_units(&SolanaAmount::BaseUnits(0), 9).is_err());
        assert!(base_units(&SolanaAmount::BaseUnits(u128::from(u64::MAX) + 1), 9).is_err());
        assert!(decimal(&"9".repeat(60), 9).is_err());
    }
}
