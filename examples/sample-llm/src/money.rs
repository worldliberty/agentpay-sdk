//! Amounts, the token to pay with, and what each request was charged.

use std::collections::BTreeMap;
use std::path::PathBuf;

use agentpay_api::payments::WalletBalanceEntry;
use anyhow::{bail, Context, Result};

/// `units` base units as a decimal amount ("616" with 6 decimals: "0.000616").
pub fn format_units(units: u128, decimals: u8) -> String {
    let scale = 10u128.pow(u32::from(decimals));
    let fraction = format!("{:0width$}", units % scale, width = usize::from(decimals));
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        (units / scale).to_string()
    } else {
        format!("{}.{fraction}", units / scale)
    }
}

/// A decimal amount ("0.10") in base units.
pub fn parse_units(amount: &str, decimals: u8) -> Result<u128> {
    let (whole, fraction) = amount.trim().split_once('.').unwrap_or((amount.trim(), ""));
    let digits = |text: &str| text.chars().all(|c| c.is_ascii_digit());
    if whole.is_empty() && fraction.is_empty() || !digits(whole) || !digits(fraction) {
        bail!("{amount:?} is not an amount");
    }
    if fraction.len() > usize::from(decimals) {
        bail!("{amount:?} has more than {decimals} decimals");
    }
    let padded = format!("{fraction:0<width$}", width = usize::from(decimals));
    let units = format!("{whole}{padded}");
    match units.trim_start_matches('0') {
        "" => Ok(0),
        digits => digits
            .parse()
            .with_context(|| format!("{amount:?} is too large")),
    }
}

/// The wallet's Tempo balance to pay with: among the tokens the merchant
/// accepts (and `symbol`, when given), the one with the most whole units.
pub fn choose_token<'a>(
    balances: &'a [WalletBalanceEntry],
    accepted: &[String],
    symbol: Option<&str>,
) -> Option<&'a WalletBalanceEntry> {
    balances
        .iter()
        .filter(|entry| {
            entry.token.as_ref().is_some_and(|token| {
                accepted
                    .iter()
                    .any(|accepted| accepted.eq_ignore_ascii_case(token))
            })
        })
        .filter(|entry| symbol.is_none_or(|symbol| entry.symbol.eq_ignore_ascii_case(symbol)))
        .filter_map(|entry| Some((whole_units(entry)?, entry)))
        .filter(|(units, _)| *units > 0.0)
        .max_by(|a, b| a.0.total_cmp(&b.0))
        .map(|(_, entry)| entry)
}

fn whole_units(entry: &WalletBalanceEntry) -> Option<f64> {
    entry.balance.as_deref()?.parse().ok()
}

/// What this tool last saw each session channel charged, so a run can show
/// its own charge: `~/.sample-llm/channels.json` (`0600`, no secrets).
pub struct ChannelLog {
    path: PathBuf,
    spent: BTreeMap<String, String>,
}

impl ChannelLog {
    pub fn open() -> Self {
        let path = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default()
            .join(".sample-llm/channels.json");
        let spent = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self { path, spent }
    }

    /// Records `spent` for `channel` and returns what it was before, if known.
    pub fn record(&mut self, channel: &str, spent: u128) -> Option<u128> {
        let before = self.spent.get(channel).and_then(|text| text.parse().ok());
        self.spent.insert(channel.to_string(), spent.to_string());
        if let Err(error) = self.save() {
            eprintln!("(could not save {}: {error})", self.path.display());
        }
        before
    }

    fn save(&self) -> Result<()> {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        let dir = self.path.parent().context("no directory")?;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(dir)?;
        let temporary = self.path.with_extension("json.tmp");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
        file.write_all(&serde_json::to_vec_pretty(&self.spent)?)?;
        file.sync_all()?;
        std::fs::rename(&temporary, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(symbol: &str, token: &str, balance: &str) -> WalletBalanceEntry {
        serde_json::from_value(serde_json::json!({
            "network": "tempo", "chain_id": 4217, "chain_name": "Tempo", "family": "evm",
            "asset": symbol.to_lowercase(), "symbol": symbol, "kind": "erc20", "token": token,
            "decimals": 6, "address": "0x7df8772cb1534ac8a1a21e202f065847f363cf39",
            "balance_base_units": "0", "balance": balance, "error": null
        }))
        .expect("entry")
    }

    #[test]
    fn units_round_trip() {
        assert_eq!(format_units(616, 6), "0.000616");
        assert_eq!(format_units(2_000_000, 6), "2");
        assert_eq!(format_units(0, 6), "0");
        assert_eq!(parse_units("0.10", 6).expect("units"), 100_000);
        assert_eq!(parse_units("1", 6).expect("units"), 1_000_000);
        assert_eq!(parse_units(".5", 6).expect("units"), 500_000);
        assert_eq!(parse_units("0", 6).expect("units"), 0);
        assert!(parse_units("0.0000001", 6).is_err());
        assert!(parse_units("1e3", 6).is_err());
        assert!(parse_units(".", 6).is_err());
    }

    #[test]
    fn the_token_is_one_the_merchant_accepts_and_the_wallet_holds_most_of() {
        let path = "0x20c0000000000000000000000000000000000000";
        let usdc = "0x20c000000000000000000000b9537d11c60e8b50";
        let usd1 = "0x20c000000000000000000000111111111e910f0f";
        let balances = [
            entry("PATH/USD", path, "2"),
            entry("USDC.e", usdc, "0.5"),
            entry("USD1", usd1, "9"),
        ];
        let accepted = [path.to_uppercase().replace("0X", "0x"), usdc.to_string()];
        let chosen = choose_token(&balances, &accepted, None).expect("token");
        assert_eq!(chosen.symbol, "PATH/USD", "USD1 is not accepted");
        let chosen = choose_token(&balances, &accepted, Some("usdc.e")).expect("token");
        assert_eq!(chosen.symbol, "USDC.e");
        let empty = [entry("PATH/USD", path, "0")];
        assert!(choose_token(&empty, &accepted, None).is_none());
    }
}
