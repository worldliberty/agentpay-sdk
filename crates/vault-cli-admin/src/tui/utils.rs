use anyhow::{anyhow, bail, Result};
use vault_domain::EvmAddress;

use super::Field;

pub(super) fn parse_positive_u128(label: &str, value: &str) -> Result<u128> {
    let trimmed = value.trim();
    let parsed = trimmed
        .parse::<u128>()
        .map_err(|_| anyhow!("{label} must be a valid unsigned integer"))?;
    if parsed == 0 {
        bail!("{label} must be greater than zero");
    }
    Ok(parsed)
}

pub(super) fn parse_non_negative_u128(label: &str, value: &str) -> Result<u128> {
    value
        .trim()
        .parse::<u128>()
        .map_err(|_| anyhow!("{label} must be a valid unsigned integer"))
}

pub(super) fn parse_positive_u64(label: &str, value: &str) -> Result<u64> {
    let trimmed = value.trim();
    let parsed = trimmed
        .parse::<u64>()
        .map_err(|_| anyhow!("{label} must be a valid unsigned integer"))?;
    if parsed == 0 {
        bail!("{label} must be greater than zero");
    }
    Ok(parsed)
}

pub(super) fn parse_optional_rpc_url(label: &str, value: &str) -> Result<Option<String>> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Ok(None);
    }

    let parsed = reqwest::Url::parse(normalized)
        .map_err(|_| anyhow!("{label} must be a valid http(s) URL"))?;
    if parsed.scheme() != "https" && parsed.scheme() != "http" {
        bail!("{label} must use https or localhost http");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("{label} must not include embedded credentials");
    }

    let Some(hostname) = parsed.host_str() else {
        bail!("{label} must include a hostname");
    };
    if parsed.scheme() == "http" && !is_loopback_hostname(hostname) {
        bail!("{label} must use https unless it targets localhost or a loopback address");
    }

    Ok(Some(normalized.to_string()))
}

pub(super) fn parse_address(label: &str, value: &str) -> Result<EvmAddress> {
    value
        .trim()
        .parse::<EvmAddress>()
        .map_err(|err| anyhow!("invalid {label} address: {err}"))
}

fn is_loopback_hostname(hostname: &str) -> bool {
    let normalized = hostname
        .trim_matches(|ch| matches!(ch, '[' | ']'))
        .to_ascii_lowercase();
    normalized == "localhost"
        || normalized.ends_with(".localhost")
        || normalized == "::1"
        || is_ipv4_loopback(&normalized)
}

fn is_ipv4_loopback(hostname: &str) -> bool {
    let octets = hostname
        .split('.')
        .map(str::parse::<u8>)
        .collect::<std::result::Result<Vec<_>, _>>();
    matches!(octets, Ok(values) if values.len() == 4 && values[0] == 127)
}

pub(super) fn bool_label(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

pub(super) fn is_allowed_input_char(field: Field, ch: char) -> bool {
    match field {
        Field::TokenKey | Field::ChainConfigKey => {
            ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')
        }
        Field::PerTxLimit
        | Field::DailyLimit
        | Field::WeeklyLimit
        | Field::PerTxMaxFeePerGasGwei
        | Field::OverridePerTxLimit
        | Field::OverrideDailyLimit
        | Field::OverrideWeeklyLimit
        | Field::OverridePerTxMaxFeePerGasGwei
        | Field::ManualApprovalMinAmount
        | Field::ManualApprovalMaxAmount => ch.is_ascii_digit() || ch == '.',
        Field::MaxGasPerChainWei
        | Field::DailyMaxTxCount
        | Field::PerTxMaxPriorityFeePerGasWei
        | Field::PerTxMaxCalldataBytes
        | Field::OverrideMaxGasPerChainWei
        | Field::OverrideDailyMaxTxCount
        | Field::OverridePerTxMaxPriorityFeePerGasWei
        | Field::OverridePerTxMaxCalldataBytes
        | Field::ManualApprovalPriority
        | Field::ChainConfigId => ch.is_ascii_digit(),
        Field::NetworkAddress
        | Field::OverrideRecipientAddress
        | Field::ManualApprovalRecipientAddress => {
            // EVM hex addresses use 0-9, a-f, plus 'x' for the 0x prefix.
            // Solana base58 addresses use 1-9, A-H, J-N, P-Z, a-k, m-z (no 0/O/I/l).
            // Accept ASCII alphanumerics so both encodings can be typed; the
            // parser still rejects malformed values when the field is committed.
            ch.is_ascii_alphanumeric()
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        bool_label, is_allowed_input_char, parse_address, parse_non_negative_u128,
        parse_optional_rpc_url, parse_positive_u128, parse_positive_u64,
    };
    use crate::tui::Field;

    #[test]
    fn parsers_accept_trimmed_values_and_reject_invalid_or_zero_inputs() {
        assert_eq!(parse_positive_u128("amount", " 42 ").expect("u128"), 42);
        assert_eq!(
            parse_non_negative_u128("count", " 0 ").expect("non-negative"),
            0
        );
        assert_eq!(parse_positive_u64("chain", " 7 ").expect("u64"), 7);

        assert!(parse_positive_u128("amount", "0").is_err());
        assert!(parse_positive_u128("amount", "nope").is_err());
        assert!(parse_non_negative_u128("count", "nope").is_err());
        assert!(parse_positive_u64("chain", "0").is_err());
        assert!(parse_positive_u64("chain", "bad").is_err());
    }

    #[test]
    fn parse_address_and_bool_label_cover_happy_and_error_paths() {
        assert_eq!(bool_label(true), "yes");
        assert_eq!(bool_label(false), "no");

        let address = parse_address("recipient", " 0x1111111111111111111111111111111111111111 ")
            .expect("address");
        assert_eq!(
            address.as_str(),
            "0x1111111111111111111111111111111111111111"
        );
        assert!(parse_address("recipient", "not-an-address").is_err());
    }

    #[test]
    fn parse_optional_rpc_url_accepts_blank_and_safe_urls() {
        assert_eq!(
            parse_optional_rpc_url("rpc url", "   ").expect("blank"),
            None
        );
        assert_eq!(
            parse_optional_rpc_url("rpc url", " https://rpc.example ").expect("https"),
            Some("https://rpc.example".to_string())
        );
        assert_eq!(
            parse_optional_rpc_url("rpc url", "http://127.0.0.1:8545").expect("ipv4 loopback"),
            Some("http://127.0.0.1:8545".to_string())
        );
        assert_eq!(
            parse_optional_rpc_url("rpc url", "http://[::1]:8545").expect("ipv6 loopback"),
            Some("http://[::1]:8545".to_string())
        );
    }

    #[test]
    fn parse_optional_rpc_url_rejects_invalid_and_unsafe_urls() {
        assert!(parse_optional_rpc_url("rpc url", "not-a-url")
            .expect_err("invalid url")
            .to_string()
            .contains("rpc url must be a valid http(s) URL"));
        assert!(parse_optional_rpc_url("rpc url", "ftp://rpc.example")
            .expect_err("invalid scheme")
            .to_string()
            .contains("rpc url must use https or localhost http"));
        assert!(
            parse_optional_rpc_url("rpc url", "https://user:secret@rpc.example")
                .expect_err("embedded credentials")
                .to_string()
                .contains("rpc url must not include embedded credentials")
        );
        assert!(parse_optional_rpc_url("rpc url", "http://rpc.example")
            .expect_err("remote http")
            .to_string()
            .contains("rpc url must use https unless it targets localhost or a loopback address"));
    }

    #[test]
    fn allowed_input_characters_match_field_types() {
        assert!(is_allowed_input_char(Field::TokenKey, 'a'));
        assert!(is_allowed_input_char(Field::TokenKey, '-'));
        assert!(!is_allowed_input_char(Field::TokenKey, '!'));

        assert!(is_allowed_input_char(Field::PerTxLimit, '9'));
        assert!(is_allowed_input_char(Field::PerTxLimit, '.'));
        assert!(!is_allowed_input_char(Field::PerTxLimit, 'x'));

        assert!(is_allowed_input_char(Field::DailyMaxTxCount, '4'));
        assert!(!is_allowed_input_char(Field::DailyMaxTxCount, '.'));

        assert!(is_allowed_input_char(Field::NetworkAddress, 'a'));
        assert!(is_allowed_input_char(Field::NetworkAddress, 'X'));
        // Solana base58 mints use letters outside the EVM hex alphabet such
        // as 'g' and 'P'; the parser still rejects malformed values on commit.
        assert!(is_allowed_input_char(Field::NetworkAddress, 'g'));
        assert!(is_allowed_input_char(Field::NetworkAddress, 'P'));
        assert!(!is_allowed_input_char(Field::NetworkAddress, '!'));

        assert!(is_allowed_input_char(Field::TokenName, '!'));
    }
}
