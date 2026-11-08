/**
 * The sudo relay used by the interactive screens when Touch ID is off (and always on Linux): the
 * client re-runs itself as `sudo agentpay admin privileged`, passes one admin call as JSON on
 * stdin, and reads the result from stdout.
 *
 * `sudo -n` is tried first, so a still-valid sudo timestamp means no prompt at all. Otherwise the
 * terminal UI asks for the password itself (sudo cannot prompt while Ink owns the terminal) and
 * hands it to `sudo -S -v` on stdin, never in arguments; the call is then retried with `sudo -n`.
 * Without a UI, sudo prompts on the terminal as usual.
 */
import { copy } from '../copy/index.js';
import { AuthError, SignerCallError } from '../errors.js';
import type { WireDaemonError } from '../generated/index.js';
import type { PasswordPrompter } from './password-prompt.js';
import type { CommandRunner } from './process.js';

/** Admin methods the relay forwards. Everything else is refused on the root side. */
export const RELAYED_METHODS = [
  'EnrollAdminCredential',
  'RevokeAdminCredential',
  'ListManualApprovalRequests',
  'DecideManualApprovalRequest',
  'BootstrapWallet',
  'ListWallets',
  'RenameWallet',
  'ExportWalletBackup',
  'VerifyWalletBackup',
  'ListSpendingLimits',
  'SetSpendingLimits',
] as const;

export type RelayedMethod = (typeof RELAYED_METHODS)[number];

export interface RelayRequest {
  method: RelayedMethod;
  /** Method params without `auth`; the root side adds `"peer_credentials"`. */
  params: Record<string, unknown>;
}

export type RelayResponse =
  | { ok: true; response: { type: string; data?: unknown } }
  | { ok: false; error: WireDaemonError };

export interface PrivilegedRunner {
  /** `reason` says what the password is for, if one is needed. */
  run(request: RelayRequest, reason?: string): Promise<{ type: string; data?: unknown }>;
}

const PASSWORD_REQUIRED = /password is required|a terminal is required/iu;
const RELAY_TIMEOUT_MS = 5 * 60_000;

/** Wrong passwords allowed before the action fails (sudo's own default is 3). */
const MAX_PASSWORD_ATTEMPTS = 3;

/** `self` is how to start this client, e.g. `[process.execPath, process.argv[1]]`. */
export function createSudoRelay(
  run: CommandRunner,
  self: readonly string[],
  prompter?: PasswordPrompter,
): PrivilegedRunner {
  const args = ['--', ...self, 'admin', 'privileged'];

  /**
   * Gets a sudo timestamp by asking for the password in the UI. `false` when no UI can ask;
   * throws when the user cancels or every attempt was wrong.
   */
  const authenticate = async (reason: string): Promise<boolean> => {
    for (let attempt = 1; attempt <= MAX_PASSWORD_ATTEMPTS; attempt += 1) {
      const password = await prompter?.ask(reason, attempt);
      if (password === undefined) {
        return false;
      }
      if (password === null) {
        throw new AuthError('sudo_cancelled', copy.errors.sudoCancelled);
      }
      // `-v` checks the password and saves sudo's timestamp for the `sudo -n` retry; `-p ''`
      // keeps sudo's own prompt out of the output. (Not `-k`: with it sudo checks the password
      // but does not save the timestamp, so the retry would still need one.)
      const result = await run('sudo', ['-S', '-p', '', '-v'], {
        input: `${password}\n`,
        timeoutMs: 30_000,
      });
      if (result.spawnError) {
        throw new AuthError('sudo_failed', copy.errors.sudoFailed(result.spawnError.message));
      }
      if (result.status === 0) {
        return true;
      }
    }
    throw new AuthError('sudo_failed', copy.errors.sudoWrongPassword);
  };

  return {
    async run(request, reason = copy.common.reasons.session) {
      const input = `${JSON.stringify(request)}\n`;
      let result = await run('sudo', ['-n', ...args], { input, timeoutMs: RELAY_TIMEOUT_MS });
      if (result.status !== 0 && PASSWORD_REQUIRED.test(result.stderr)) {
        result = (await authenticate(reason))
          ? await run('sudo', ['-n', ...args], { input, timeoutMs: RELAY_TIMEOUT_MS })
          : await run('sudo', args, { input, timeoutMs: RELAY_TIMEOUT_MS, inheritStderr: true });
      }
      if (result.spawnError) {
        throw new AuthError('sudo_failed', copy.errors.sudoFailed(result.spawnError.message));
      }
      let parsed: RelayResponse;
      try {
        parsed = JSON.parse(result.stdout.trim()) as RelayResponse;
      } catch {
        throw new AuthError(
          'sudo_failed',
          copy.errors.sudoFailed(result.stderr.trim() || `exit status ${result.status}`),
        );
      }
      if (!parsed.ok) {
        throw new SignerCallError(parsed.error);
      }
      return parsed.response;
    },
  };
}
