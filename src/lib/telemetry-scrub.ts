import os from 'node:os';

const REDACTED = '<redacted>';

/**
 * Every URL collapses to `scheme://host[:port]`. Paths and query strings are where RPC API keys
 * (`/v3/<key>`), payment endpoints, and request ids live, and userinfo may carry credentials.
 */
const URL_PATTERN = /\b([a-z][a-z0-9+.-]*):\/\/([^\s/?#"'<>()[\]{},]+)([^\s"'<>()[\]{},]*)/giu;
/** `0x`-prefixed hex of 16+ nibbles: addresses, hashes, calldata, signatures, and long ids. */
const PREFIXED_HEX_PATTERN = /\b0[xX][0-9a-fA-F]{16,}\b/gu;
/** Bare hex runs of 32+ nibbles: private keys and hashes printed without a prefix, API keys. */
const BARE_HEX_PATTERN = /\b[0-9a-fA-F]{32,}\b/gu;
/** Railgun `0zk` shielded addresses. */
const RAILGUN_ADDRESS_PATTERN = /\b0zk1[a-z0-9]+/gu;
/** Base58 runs long enough to be a Solana address (32-44 chars) or signature (87-88 chars). */
const BASE58_PATTERN = /\b[1-9A-HJ-NP-Za-km-z]{32,}\b/gu;
const EMAIL_PATTERN = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/gu;
const MIN_HOSTNAME_LABEL_LENGTH = 4;

/**
 * Deliberately broad: it also catches keys that merely contain a banned substring, such as
 * `token_balance_bucket`, so every property the CLI intends to emit is allow-listed below and
 * adding a new one is a conscious decision rather than a silent match against this list.
 */
const SENSITIVE_KEY_PATTERN =
  /password|secret|token|mnemonic|seed|private|signature|rawtx|raw_tx|address|recipient|destination|amount|url|hostname|email/iu;

const ALLOWED_KEYS: ReadonlySet<string> = new Set([
  'action',
  'amount_bucket',
  'arch',
  'asset',
  'balance_bucket_after',
  'balance_bucket_before',
  'broadcast',
  'chain',
  'chain_id',
  'cli_version',
  'command',
  'duration_ms',
  'environment',
  'exit_code',
  'native_balance_bucket',
  'node_version',
  'os_release',
  'platform',
  'result',
  'subcommand',
  'token_balance_bucket',
]);

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}

function reduceUrl(_match: string, scheme: string, authority: string): string {
  // Anything before the last `@` is userinfo, which is the one part of a URL that can hold a
  // credential outright.
  const host = authority.slice(authority.lastIndexOf('@') + 1);
  return `${scheme}://${host}`;
}

/**
 * The machine name is not a secret, but it is frequently a person's name (`alices-macbook`), so
 * both the full name and its first label are removed wherever they appear.
 */
function scrubHostname(value: string): string {
  const hostname = os.hostname().trim();
  if (!hostname) {
    return value;
  }

  let scrubbed = value.replaceAll(new RegExp(escapeRegExp(hostname), 'giu'), REDACTED);
  const label = hostname.split('.')[0] ?? '';
  if (label.length >= MIN_HOSTNAME_LABEL_LENGTH && label.toLowerCase() !== 'localhost') {
    scrubbed = scrubbed.replaceAll(new RegExp(`\\b${escapeRegExp(label)}\\b`, 'giu'), REDACTED);
  }
  return scrubbed;
}

/**
 * Strips values that could identify a user on-chain, name their machine, or leak a credential.
 * Applied to every string that leaves the process, for both crash reports and analytics.
 */
export function scrubText(value: string): string {
  let scrubbed = value
    .replaceAll(URL_PATTERN, reduceUrl)
    .replaceAll(PREFIXED_HEX_PATTERN, REDACTED)
    .replaceAll(BARE_HEX_PATTERN, REDACTED)
    .replaceAll(RAILGUN_ADDRESS_PATTERN, REDACTED)
    .replaceAll(BASE58_PATTERN, REDACTED)
    .replaceAll(EMAIL_PATTERN, REDACTED);

  scrubbed = scrubHostname(scrubbed);

  const homeDir = os.homedir();
  if (homeDir && homeDir !== '/') {
    scrubbed = scrubbed.replaceAll(homeDir, '~');
  }

  return scrubbed;
}

export function isSensitiveKey(key: string): boolean {
  return !ALLOWED_KEYS.has(key) && SENSITIVE_KEY_PATTERN.test(key);
}

/**
 * Recursively scrubs an analytics/crash payload. Sensitive keys are dropped outright rather than
 * redacted so they never occupy a property slot in the destination schema.
 */
export function scrubProperties(input: Record<string, unknown>): Record<string, unknown> {
  const output: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(input)) {
    if (value === undefined || value === null || isSensitiveKey(key)) {
      continue;
    }
    output[key] = scrubValue(value);
  }

  return output;
}

function scrubValue(value: unknown): unknown {
  if (typeof value === 'string') {
    return scrubText(value);
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(scrubValue);
  }
  if (value && typeof value === 'object') {
    return scrubProperties(value as Record<string, unknown>);
  }

  return undefined;
}
