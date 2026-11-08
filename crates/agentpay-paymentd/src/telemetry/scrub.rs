//! The scrubber every telemetry string passes before it leaves the process
//! (ported from the TypeScript `telemetry-scrub`).
//!
//! [`scrub_text`] removes what could identify a user on chain, name their
//! machine, or leak a credential:
//!
//! - every URL collapses to `scheme://host[:port]` (paths and queries carry
//!   RPC API keys and payment endpoints; userinfo can carry a password);
//! - `0x`-prefixed hex of 16+ digits (addresses, hashes, calldata,
//!   signatures), bare hex of 32+ digits (keys, hashes, API keys), base58
//!   runs of 32+ characters (Solana addresses and signatures), and e-mail
//!   addresses become `<redacted>`;
//! - the host name (and its first label, when it is at least 4 characters)
//!   becomes `<redacted>`, and the home directory becomes `~`.
//!
//! [`scrub_properties`] drops every property whose name looks sensitive
//! unless it is on [`ALLOWED_KEYS`], so adding a property is a deliberate
//! decision, and scrubs every string value.

use serde_json::{Map, Value};

/// The replacement for redacted values.
pub const REDACTED: &str = "<redacted>";

/// Property names that may be sent even though some contain a sensitive word
/// (`amount_bucket` contains `amount`).
pub const ALLOWED_KEYS: &[&str] = &[
    "amount_bucket",
    "arch",
    "duration_bucket",
    "environment",
    "error_kind",
    "method",
    "outcome",
    "platform",
    "service_version",
];

/// Substrings that make a property name sensitive.
const SENSITIVE_KEY_PARTS: &[&str] = &[
    "password",
    "secret",
    "token",
    "mnemonic",
    "seed",
    "private",
    "signature",
    "rawtx",
    "raw_tx",
    "address",
    "recipient",
    "destination",
    "amount",
    "url",
    "hostname",
    "email",
    "hash",
    "key",
];

/// Characters that end a URL.
const URL_DELIMITERS: &[char] = &['"', '\'', '<', '>', '(', ')', '[', ']', '{', '}', ','];
/// Shortest host name label that is redacted on its own.
const MIN_HOSTNAME_LABEL_LENGTH: usize = 4;

/// What [`scrub_text`] removes besides patterns: the host name and home directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Environment {
    /// The machine's host name.
    pub hostname: Option<String>,
    /// The home directory of the service account.
    pub home: Option<String>,
}

impl Environment {
    /// This process's host name and `$HOME`.
    #[must_use]
    pub fn current() -> Self {
        Self {
            hostname: nix::unistd::gethostname()
                .ok()
                .and_then(|name| name.into_string().ok()),
            home: std::env::var("HOME").ok(),
        }
    }
}

/// Whether a property named `key` must be dropped.
#[must_use]
pub fn is_sensitive_key(key: &str) -> bool {
    if ALLOWED_KEYS.contains(&key) {
        return false;
    }
    let lower = key.to_ascii_lowercase();
    SENSITIVE_KEY_PARTS.iter().any(|part| lower.contains(part))
}

/// Drops sensitive and empty properties and scrubs every string, recursively.
#[must_use]
pub fn scrub_properties(input: Map<String, Value>, env: &Environment) -> Map<String, Value> {
    input
        .into_iter()
        .filter(|(key, value)| !value.is_null() && !is_sensitive_key(key))
        .map(|(key, value)| (key, scrub_value(value, env)))
        .collect()
}

fn scrub_value(value: Value, env: &Environment) -> Value {
    match value {
        Value::String(text) => Value::String(scrub_text(&text, env)),
        Value::Array(items) => {
            Value::Array(items.into_iter().map(|v| scrub_value(v, env)).collect())
        }
        Value::Object(map) => Value::Object(scrub_properties(map, env)),
        other => other,
    }
}

/// Removes URLs paths, identifiers, e-mail addresses, the host name, and the
/// home directory from `text`.
#[must_use]
pub fn scrub_text(text: &str, env: &Environment) -> String {
    let text = reduce_urls(text);
    let text = redact_emails(&text);
    let text = redact_identifiers(&text);
    let text = redact_hostname(&text, env.hostname.as_deref());
    match env.home.as_deref() {
        Some(home) if !home.is_empty() && home != "/" => text.replace(home, "~"),
        _ => text,
    }
}

/// `scheme://userinfo@host:port/path?query` becomes `scheme://host:port`.
fn reduce_urls(text: &str) -> String {
    let is_scheme = |c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-');
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find("://") {
        let (before, after) = rest.split_at(index);
        let target = &after[3..];
        out.push_str(before);
        out.push_str("://");
        let scheme_start = before.trim_end_matches(is_scheme).len();
        let scheme = &before[scheme_start..];
        let bounded = !before[..scheme_start].ends_with('_');
        if !bounded || !scheme.starts_with(|c: char| c.is_ascii_alphabetic()) {
            rest = target;
            continue;
        }
        let end = target
            .find(|c: char| c.is_whitespace() || URL_DELIMITERS.contains(&c))
            .unwrap_or(target.len());
        let url = &target[..end];
        let authority = &url[..url.find(['/', '?', '#']).unwrap_or(url.len())];
        out.push_str(
            authority
                .rsplit_once('@')
                .map_or(authority, |(_, host)| host),
        );
        rest = &target[end..];
    }
    out.push_str(rest);
    out
}

/// `local@domain.tld` becomes `<redacted>`.
fn redact_emails(text: &str) -> String {
    let is_local = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-');
    let is_domain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-');
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('@') {
        let (before, after) = rest.split_at(at);
        let local_start = before
            .char_indices()
            .rev()
            .take_while(|(_, c)| is_local(*c))
            .last()
            .map_or(before.len(), |(i, _)| i);
        let domain = &after[1..];
        let domain_len = domain.find(|c: char| !is_domain(c)).unwrap_or(domain.len());
        let candidate = domain[..domain_len].trim_end_matches(['.', '-']);
        let tld_ok = candidate.rsplit_once('.').is_some_and(|(name, tld)| {
            !name.is_empty() && tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
        });
        if local_start < before.len() && tld_ok {
            out.push_str(&before[..local_start]);
            out.push_str(REDACTED);
            rest = &domain[candidate.len()..];
        } else {
            out.push_str(before);
            out.push('@');
            rest = domain;
        }
    }
    out.push_str(rest);
    out
}

/// Long hex and base58 words become `<redacted>`.
fn redact_identifiers(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut word = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            word.push(c);
        } else {
            push_word(&mut out, &word);
            word.clear();
            out.push(c);
        }
    }
    push_word(&mut out, &word);
    out
}

fn push_word(out: &mut String, word: &str) {
    if is_identifier(word) {
        out.push_str(REDACTED);
    } else {
        out.push_str(word);
    }
}

fn is_identifier(word: &str) -> bool {
    let hex = |s: &str| s.chars().all(|c| c.is_ascii_hexdigit());
    let prefixed = word
        .strip_prefix("0x")
        .or_else(|| word.strip_prefix("0X"))
        .is_some_and(|digits| digits.len() >= 16 && hex(digits));
    let bare_hex = word.len() >= 32 && hex(word);
    let base58 = word.len() >= 32
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() && !matches!(c, '0' | 'O' | 'I' | 'l'));
    prefixed || bare_hex || base58
}

/// Removes the host name, and its first label when it is long enough to
/// matter, case-insensitively.
fn redact_hostname(text: &str, hostname: Option<&str>) -> String {
    let Some(hostname) = hostname.map(str::trim).filter(|h| !h.is_empty()) else {
        return text.to_string();
    };
    let mut scrubbed = replace_ignore_case(text, hostname, false);
    let label = hostname.split('.').next().unwrap_or_default();
    if label.len() >= MIN_HOSTNAME_LABEL_LENGTH && !label.eq_ignore_ascii_case("localhost") {
        scrubbed = replace_ignore_case(&scrubbed, label, true);
    }
    scrubbed
}

/// Replaces ASCII-case-insensitive occurrences of `needle`; with
/// `whole_word`, only where it is not part of a longer word.
fn replace_ignore_case(text: &str, needle: &str, whole_word: bool) -> String {
    let lower_text = text.to_ascii_lowercase();
    let lower_needle = needle.to_ascii_lowercase();
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = String::with_capacity(text.len());
    let mut position = 0;
    while let Some(found) = lower_text[position..].find(&lower_needle) {
        let start = position + found;
        let end = start + needle.len();
        let bounded =
            !whole_word || (!text[..start].ends_with(is_word) && !text[end..].starts_with(is_word));
        out.push_str(&text[position..start]);
        out.push_str(if bounded { REDACTED } else { &text[start..end] });
        position = end;
    }
    out.push_str(&text[position..]);
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn env() -> Environment {
        Environment {
            hostname: Some("Alices-MacBook.local".into()),
            home: Some("/Users/alice".into()),
        }
    }

    fn scrub(text: &str) -> String {
        scrub_text(text, &env())
    }

    #[test]
    fn urls_keep_only_scheme_and_host() {
        assert_eq!(
            scrub("rpc https://user:pass@bsc.example.com:8545/v3/abcdef?key=1 failed"),
            "rpc https://bsc.example.com:8545 failed"
        );
        assert_eq!(
            scrub("(see http://127.0.0.1:8899/path)"),
            "(see http://127.0.0.1:8899)"
        );
        assert_eq!(scrub("no scheme ://x"), "no scheme ://x");
    }

    #[test]
    fn addresses_hashes_and_keys_are_redacted() {
        assert_eq!(
            scrub("to 0x5aeda56215b167893e80b4fe645ba6d5bab767de done"),
            "to <redacted> done"
        );
        assert_eq!(
            scrub("key 4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"),
            "key <redacted>"
        );
        assert_eq!(
            scrub("sol 9fijMemJYwXS5QD85Qxsq7iKqvSebgb6LvpGftgkeigk."),
            "sol <redacted>."
        );
        // Short values and ordinary words survive.
        assert_eq!(
            scrub("chain 0x38 nonce 7 ChainRpc"),
            "chain 0x38 nonce 7 ChainRpc"
        );
    }

    #[test]
    fn emails_host_names_and_home_are_removed() {
        assert_eq!(scrub("mail alice@example.com now"), "mail <redacted> now");
        assert_eq!(scrub("not an email: a@b"), "not an email: a@b");
        assert_eq!(
            scrub("on alices-macbook.local and Alices-MacBook"),
            "on <redacted> and <redacted>"
        );
        assert_eq!(
            scrub("/Users/alice/.agentpay/config.json"),
            "~/.agentpay/config.json"
        );
    }

    #[test]
    fn short_host_labels_and_localhost_are_kept() {
        let env = Environment {
            hostname: Some("ci.example.org".into()),
            home: None,
        };
        assert_eq!(
            scrub_text("ci runner on ci.example.org", &env),
            "ci runner on <redacted>"
        );
        let env = Environment {
            hostname: Some("localhost".into()),
            home: None,
        };
        assert_eq!(scrub_text("localhost", &env), "<redacted>");
    }

    #[test]
    fn sensitive_properties_are_dropped_unless_allowed() {
        let input = json!({
            "method": "Transfer",
            "amount_bucket": "<10",
            "amount": "12.5",
            "recipient": "0x5aeda56215b167893e80b4fe645ba6d5bab767de",
            "agent_auth_token": "secret",
            "tx_hash": "0xabc",
            "rpc_url": "https://x",
            "nested": {"private_key": "k", "note": "see https://a.example/b"},
            "empty": null,
            "count": 3
        });
        let Value::Object(map) = input else {
            panic!("object");
        };
        let scrubbed = Value::Object(scrub_properties(map, &env()));
        assert_eq!(
            scrubbed,
            json!({
                "method": "Transfer",
                "amount_bucket": "<10",
                "nested": {"note": "see https://a.example"},
                "count": 3
            })
        );
    }

    #[test]
    fn every_allowed_key_would_otherwise_be_judged_on_its_own() {
        for key in ALLOWED_KEYS {
            assert!(!is_sensitive_key(key), "{key}");
        }
        assert!(is_sensitive_key("wallet_address"));
        assert!(is_sensitive_key("ApiKey"));
    }
}
