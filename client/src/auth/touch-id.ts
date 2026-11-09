/**
 * Wrapper for the macOS `agentpay-auth` helper (native/macos/AgentPayAuth.swift). Contract:
 * every command prints one JSON object on stdout and exits 0; failures print
 * `{"error":{"code":"<code>","message":"..."}}` and exit 1.
 *
 *   agentpay-auth status
 *   agentpay-auth create --key-file <path>
 *   agentpay-auth sign --key-file <path> --reason <text> --message-hex <hex>
 *   agentpay-auth delete --key-file <path>
 */
import { existsSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import type { CommandRunner } from './process.js';

/** Stable helper error codes, plus the client's own `helper_missing` / `malformed_output`. */
export type HelperErrorCode =
  | 'user_cancel'
  | 'authentication_failed'
  | 'biometry_lockout'
  | 'biometry_not_enrolled'
  | 'passcode_not_set'
  | 'interaction_not_allowed'
  | 'key_invalidated'
  | 'key_not_found'
  | 'invalid_input'
  | 'secure_enclave_unavailable'
  | 'other'
  | 'helper_missing'
  | 'malformed_output';

export class HelperError extends Error {
  readonly code: HelperErrorCode;

  constructor(code: HelperErrorCode, message: string) {
    super(message);
    this.code = code;
  }
}

export interface HelperStatus {
  secureEnclaveAvailable: boolean;
  biometry: { available: boolean; kind: string };
  userPresenceAvailable: boolean;
}

export interface TouchIdHelper {
  readonly path: string;
  status(): Promise<HelperStatus>;
  /** Creates the Secure Enclave key file; never prompts. */
  create(keyFile: string): Promise<{ publicKeySec1Hex: string }>;
  /** Signs after one Touch ID / password prompt that shows `reason`. */
  sign(keyFile: string, reason: string, messageHex: string): Promise<{ signatureDerHex: string }>;
  remove(keyFile: string): Promise<void>;
}

/** The longest prompt reason the helper accepts. */
export const MAX_REASON_LENGTH = 200;
const SIGN_TIMEOUT_MS = 5 * 60_000;
const HEX = /^[0-9a-f]+$/iu;

export const INSTALLED_HELPER_PATH = '/Library/AgentPay/bin/agentpay-auth';

/** `AGENTPAY_AUTH_HELPER`, the installed helper, or `agentpay-auth` on `PATH`. */
export function resolveHelperPath(
  env: NodeJS.ProcessEnv,
  exists: (path: string) => boolean = existsSync,
): string | null {
  const explicit = env.AGENTPAY_AUTH_HELPER?.trim();
  if (explicit) {
    return explicit;
  }
  if (exists(INSTALLED_HELPER_PATH)) {
    return INSTALLED_HELPER_PATH;
  }
  for (const dir of (env.PATH ?? '').split(delimiter).filter(Boolean)) {
    const candidate = join(dir, 'agentpay-auth');
    if (exists(candidate)) {
      return candidate;
    }
  }
  return null;
}

/** Makes `reason` acceptable to the helper: one line, at most 200 characters. */
export function sanitizeReason(reason: string): string {
  const flat = Array.from(
    reason
      .replace(/\p{C}|\p{Zl}|\p{Zp}/gu, ' ')
      .replace(/\s+/gu, ' ')
      .trim(),
  );
  return flat.length <= MAX_REASON_LENGTH
    ? flat.join('')
    : `${flat.slice(0, MAX_REASON_LENGTH - 1).join('')}…`;
}

function parseOutput(stdout: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(stdout.trim().split('\n').pop() ?? '');
    if (typeof value === 'object' && value !== null) {
      return value as Record<string, unknown>;
    }
  } catch {
    // fall through
  }
  throw new HelperError('malformed_output', 'the Touch ID helper printed something unexpected');
}

const KNOWN_CODES = new Set<string>([
  'user_cancel',
  'authentication_failed',
  'biometry_lockout',
  'biometry_not_enrolled',
  'passcode_not_set',
  'interaction_not_allowed',
  'key_invalidated',
  'key_not_found',
  'invalid_input',
  'secure_enclave_unavailable',
  'other',
]);

export function createTouchIdHelper(path: string, run: CommandRunner): TouchIdHelper {
  const invoke = async (args: string[], timeoutMs?: number) => {
    const result = await run(path, args, timeoutMs === undefined ? {} : { timeoutMs });
    if (result.spawnError) {
      throw new HelperError(
        'helper_missing',
        `cannot run ${path}: ${result.spawnError.code ?? ''}`,
      );
    }
    const output = parseOutput(result.stdout);
    const error = output.error as { code?: unknown; message?: unknown } | undefined;
    if (result.status !== 0 || error) {
      const code =
        typeof error?.code === 'string' && KNOWN_CODES.has(error.code) ? error.code : 'other';
      const message = typeof error?.message === 'string' ? error.message : result.stderr.trim();
      throw new HelperError(code as HelperErrorCode, message || 'the Touch ID helper failed');
    }
    return output;
  };

  return {
    path,
    async status() {
      const output = await invoke(['status']);
      const biometry = (output.biometry ?? {}) as { available?: unknown; kind?: unknown };
      return {
        secureEnclaveAvailable: output.secureEnclaveAvailable === true,
        biometry: {
          available: biometry.available === true,
          kind: typeof biometry.kind === 'string' ? biometry.kind : 'none',
        },
        userPresenceAvailable: output.userPresenceAvailable === true,
      };
    },
    async create(keyFile) {
      const output = await invoke(['create', '--key-file', keyFile]);
      const key = output.publicKeySec1Hex;
      if (typeof key !== 'string' || !HEX.test(key)) {
        throw new HelperError('malformed_output', 'the helper returned no public key');
      }
      return { publicKeySec1Hex: key.toLowerCase() };
    },
    async sign(keyFile, reason, messageHex) {
      const output = await invoke(
        [
          'sign',
          '--key-file',
          keyFile,
          '--reason',
          sanitizeReason(reason),
          '--message-hex',
          messageHex,
        ],
        SIGN_TIMEOUT_MS,
      );
      const signature = output.signatureDerHex;
      if (typeof signature !== 'string' || !HEX.test(signature)) {
        throw new HelperError('malformed_output', 'the helper returned no signature');
      }
      return { signatureDerHex: signature.toLowerCase() };
    },
    async remove(keyFile) {
      try {
        await invoke(['delete', '--key-file', keyFile]);
      } catch (error) {
        if (!(error instanceof HelperError && error.code === 'key_not_found')) {
          throw error;
        }
      }
    },
  };
}
