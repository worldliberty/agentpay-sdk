// Helpers shared by the AgentPay CLI Railgun subcommands (`shield`,
// `unshield`, `private-transfer`, `private-balance`).
//
// Track 5 wires the user-facing surface only. Outer transaction assembly and
// shielded UTXO scanning require the Track 4 railgun-prover sidecar and the
// Track 2 Phase B Baby Jubjub signer backend. The helpers here intentionally
// stay narrow: address shape validation, sidecar-pending messaging, and a
// default-resolution stub so the CLI matches the established patterns in
// `network-selection.ts` / `config-amounts.ts`.

import type { WlfiConfig } from '@worldlibertyfinancial/agent-config';

/// Minimum encoded length the daemon-layer `RailgunAddress::from_str` parser
/// accepts. Surfacing it here lets us reject obviously malformed CLI input
/// before the Rust subprocess spawns instead of waiting for `clap` to fail.
const RAILGUN_ADDRESS_MIN_LENGTH = 32;
const RAILGUN_ADDRESS_MAX_LENGTH = 256;
const RAILGUN_ADDRESS_PREFIX = '0zk1';

/**
 * Returns the input unchanged when it parses as a Railgun shielded address
 * (`0zk1...`) under the same shape constraints the Rust daemon enforces.
 * Throws otherwise. The CLI uses this to fail fast on bad `--to-railgun-address`
 * input before spawning the agent subprocess.
 */
export function assertRailgunAddress(value: string, label: string): string {
  if (typeof value !== 'string') {
    throw new Error(`${label} must be a Railgun shielded address (0zk1...)`);
  }
  const normalized = value.trim();
  if (!normalized.startsWith(RAILGUN_ADDRESS_PREFIX)) {
    throw new Error(`${label} must start with "${RAILGUN_ADDRESS_PREFIX}"`);
  }
  if (
    normalized.length < RAILGUN_ADDRESS_MIN_LENGTH ||
    normalized.length > RAILGUN_ADDRESS_MAX_LENGTH
  ) {
    throw new Error(
      `${label} length ${normalized.length} is outside the supported range (${RAILGUN_ADDRESS_MIN_LENGTH}-${RAILGUN_ADDRESS_MAX_LENGTH})`,
    );
  }
  if (!/^[A-Za-z0-9_]+$/u.test(normalized)) {
    throw new Error(`${label} contains characters outside the supported alphanumeric/_ set`);
  }
  return normalized;
}

/**
 * Returns the configured default Railgun shielded address for the wallet when
 * the user omits `--to-railgun-address` while shielding to self.
 *
 * Reserved for Track 2 Phase B: the daemon will own the derivation
 * (`railgun_master_public_key` -> bech32 `0zk1...`) and the CLI will surface
 * it through `agentpay config show`. Until that lands the helper returns
 * `null` so callers know to require an explicit recipient.
 */
export function resolveDefaultRailgunAddress(_config: WlfiConfig): string | null {
  return null;
}

/**
 * Standard message printed after the policy/authorization step of a Railgun
 * subcommand when the user passes `--broadcast`. Keeps the wording aligned
 * across `shield`, `unshield`, and `private-transfer` so callers can grep for
 * it from automation.
 */
export const RAILGUN_BROADCAST_PENDING_MESSAGE =
  'broadcast path requires the railgun-prover sidecar (Track 4 pending) and Phase B Rust crypto (Track 2 Phase B pending); only the authorization step is wired up today';

/**
 * Reason string emitted by `agentpay private-balance`. Kept in sync with the
 * Rust agent CLI so callers see identical messaging regardless of which
 * surface they hit first.
 */
export const RAILGUN_PRIVATE_BALANCE_UNAVAILABLE_REASON =
  'private balance scan requires the railgun-prover sidecar (Track 4 not yet implemented)';
