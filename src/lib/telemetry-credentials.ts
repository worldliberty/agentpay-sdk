/**
 * Sentry DSNs and Mixpanel project tokens are write-only, client-side identifiers — the same class
 * of value every browser app ships in plain JavaScript — so they live in source rather than being
 * injected at build time. Each can still be overridden at runtime, and setting one to an empty
 * string disables that destination.
 */

const DEFAULT_SENTRY_DSN =
  'https://7aa5990fd4aa55b52daf1439ff9dc460@o4507968571244544.ingest.us.sentry.io/4511977957490688';

const DEFAULT_MIXPANEL_TOKEN = '0b777f1caa927f63e5f7e6b1648ff4f8';

/** `ip=0` keeps Mixpanel from deriving and storing a location from the caller's IP address. */
const DEFAULT_MIXPANEL_TRACK_URL = 'https://api.mixpanel.com/track?ip=0';

function resolve(override: string | undefined, fallback: string): string {
  return override === undefined ? fallback : override.trim();
}

export function sentryDsn(): string {
  return resolve(process.env.AGENTPAY_SENTRY_DSN, DEFAULT_SENTRY_DSN);
}

export function mixpanelToken(): string {
  return resolve(process.env.AGENTPAY_MIXPANEL_TOKEN, DEFAULT_MIXPANEL_TOKEN);
}

/**
 * Exists so the test suite can point analytics at a local server; there is no reason for anyone
 * else to set it.
 */
export function mixpanelTrackUrl(): string {
  return resolve(process.env.AGENTPAY_MIXPANEL_URL, DEFAULT_MIXPANEL_TRACK_URL);
}

/**
 * Lets dashboards separate real usage from local development and CI builds, which now share the
 * same baked-in credentials as released builds.
 */
export function telemetryEnvironment(): string {
  const override = process.env.AGENTPAY_TELEMETRY_ENVIRONMENT?.trim();
  if (override) {
    return override;
  }

  return process.env.CI?.trim() ? 'ci' : 'production';
}
