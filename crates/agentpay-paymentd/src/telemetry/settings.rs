//! Telemetry settings from the service's environment, and the baked-in
//! destinations (ported from the TypeScript `telemetry-credentials` and
//! `telemetry-consent`).
//!
//! Sentry DSNs and Mixpanel project tokens are write-only, client-side
//! identifiers, the same class of value every browser app ships, so they live
//! in source. Each can be overridden, and an empty value disables that
//! destination.

/// Default Sentry DSN (write-only).
pub const DEFAULT_SENTRY_DSN: &str =
    "https://7aa5990fd4aa55b52daf1439ff9dc460@o4507968571244544.ingest.us.sentry.io/4511977957490688";
/// Default Mixpanel project token (write-only).
pub const DEFAULT_MIXPANEL_TOKEN: &str = "0b777f1caa927f63e5f7e6b1648ff4f8";
/// `ip=0` keeps Mixpanel from deriving and storing a location from the caller's IP.
pub const DEFAULT_MIXPANEL_TRACK_URL: &str = "https://api.mixpanel.com/track?ip=0";

/// Values of `AGENTPAY_TELEMETRY` (and `DO_NOT_TRACK`) that mean "off" / "not set".
const FALSEY: &[&str] = &["", "0", "false", "no", "off"];

/// Everything telemetry reads from the environment, resolved once at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// `AGENTPAY_TELEMETRY` is falsy.
    pub env_opt_out: bool,
    /// `DO_NOT_TRACK` is set to anything but empty or `0`.
    pub do_not_track: bool,
    /// Sentry DSN; empty disables crash reports.
    pub sentry_dsn: String,
    /// Mixpanel token; empty disables analytics.
    pub mixpanel_token: String,
    /// Mixpanel `track` endpoint (overridable for local testing only).
    pub mixpanel_url: String,
    /// The `environment` label: `production`, `ci`, or an override.
    pub environment: String,
}

impl Settings {
    /// The settings of this process.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// The settings for an environment given by `get`.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let resolve = |name: &str, fallback: &str| {
            get(name).map_or_else(|| fallback.to_string(), |value| value.trim().to_string())
        };
        let falsey = |value: &str| FALSEY.contains(&value.trim().to_ascii_lowercase().as_str());
        let environment = get("AGENTPAY_TELEMETRY_ENVIRONMENT")
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| {
                let ci = get("CI").is_some_and(|value| !value.trim().is_empty());
                if ci { "ci" } else { "production" }.to_string()
            });
        Self {
            env_opt_out: get("AGENTPAY_TELEMETRY").is_some_and(|value| falsey(&value)),
            do_not_track: get("DO_NOT_TRACK").is_some_and(|value| !falsey(&value)),
            sentry_dsn: resolve("AGENTPAY_SENTRY_DSN", DEFAULT_SENTRY_DSN),
            mixpanel_token: resolve("AGENTPAY_MIXPANEL_TOKEN", DEFAULT_MIXPANEL_TOKEN),
            mixpanel_url: resolve("AGENTPAY_MIXPANEL_URL", DEFAULT_MIXPANEL_TRACK_URL),
            environment,
        }
    }

    /// Settings with nothing set: the baked-in destinations, `production`.
    #[must_use]
    pub fn defaults() -> Self {
        Self::from_lookup(|_| None)
    }

    /// Whether crash reports have a destination.
    #[must_use]
    pub fn crash_reports(&self) -> bool {
        !self.sentry_dsn.is_empty()
    }

    /// Whether analytics have a destination.
    #[must_use]
    pub fn analytics(&self) -> bool {
        !self.mixpanel_token.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn settings(vars: &[(&str, &str)]) -> Settings {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        Settings::from_lookup(|name| vars.get(name).cloned())
    }

    #[test]
    fn defaults_use_the_baked_in_destinations() {
        let defaults = settings(&[]);
        assert_eq!(defaults, Settings::defaults());
        assert!(!defaults.env_opt_out && !defaults.do_not_track);
        assert_eq!(defaults.sentry_dsn, DEFAULT_SENTRY_DSN);
        assert_eq!(defaults.mixpanel_token, DEFAULT_MIXPANEL_TOKEN);
        assert_eq!(defaults.mixpanel_url, DEFAULT_MIXPANEL_TRACK_URL);
        assert_eq!(defaults.environment, "production");
        assert!(defaults.crash_reports() && defaults.analytics());
    }

    #[test]
    fn opt_outs_follow_the_old_rules() {
        for value in ["0", "false", "NO", " off ", ""] {
            assert!(
                settings(&[("AGENTPAY_TELEMETRY", value)]).env_opt_out,
                "{value:?}"
            );
        }
        assert!(!settings(&[("AGENTPAY_TELEMETRY", "1")]).env_opt_out);
        for value in ["1", "true", "yes"] {
            assert!(
                settings(&[("DO_NOT_TRACK", value)]).do_not_track,
                "{value:?}"
            );
        }
        for value in ["0", ""] {
            assert!(
                !settings(&[("DO_NOT_TRACK", value)]).do_not_track,
                "{value:?}"
            );
        }
    }

    #[test]
    fn overrides_and_environment_labels() {
        let custom = settings(&[
            ("AGENTPAY_SENTRY_DSN", ""),
            ("AGENTPAY_MIXPANEL_TOKEN", " abc "),
            ("CI", "true"),
        ]);
        assert!(!custom.crash_reports());
        assert_eq!(custom.mixpanel_token, "abc");
        assert_eq!(custom.environment, "ci");
        let labelled = settings(&[("CI", "1"), ("AGENTPAY_TELEMETRY_ENVIRONMENT", "staging")]);
        assert_eq!(labelled.environment, "staging");
    }
}
