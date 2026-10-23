import { spawnSync } from 'node:child_process';
import { constants as osConstants } from 'node:os';
import { assertValidAgentAuthToken } from './agent-auth-token.js';

export const AGENT_AUTH_TOKEN_KEYCHAIN_SERVICE = 'agentpay-agent-auth-token';
export const DAEMON_PASSWORD_KEYCHAIN_SERVICE = 'agentpay-daemon-password';
const SECURITY_NOT_FOUND_EXIT_CODE = 44;
const AGENT_KEY_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const MAX_KEYCHAIN_SECRET_BYTES = 16 * 1024;

export interface SecurityCommandInvocation {
  args: string[];
  input?: string;
}

export type SecurityCommandRunner = (command: SecurityCommandInvocation) => string;

export function assertValidAgentKeyId(agentKeyId: string): string {
  const normalized = agentKeyId.trim();
  if (!AGENT_KEY_ID_PATTERN.test(normalized)) {
    throw new Error('agentKeyId must be a valid UUID');
  }
  return normalized;
}

function signalExitCode(signal: NodeJS.Signals | null): number {
  if (!signal) {
    return 1;
  }

  const signalNumber = osConstants.signals[signal];
  return typeof signalNumber === 'number' ? 128 + signalNumber : 128;
}

function hasControlCharacters(value: string): boolean {
  return Array.from(value).some((character) => {
    const code = character.codePointAt(0);
    return code !== undefined && ((code >= 0 && code <= 0x1f) || code === 0x7f);
  });
}

function defaultSecurityRunner(command: SecurityCommandInvocation): string {
  const result = spawnSync('security', command.args, {
    encoding: 'utf8',
    input: command.input,
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  if (result.error) {
    throw result.error;
  }
  const exitCode = result.status ?? signalExitCode(result.signal);
  if (exitCode !== 0) {
    // `security -i` reads its command from stdin; name that subcommand (never its arguments,
    // which can carry the hex-encoded secret) instead of the generic `-i` flag.
    const commandLabel =
      command.args[0] === '-i' && command.input
        ? (command.input.trimStart().split(/\s/u)[0] ?? '-i')
        : command.args[0];
    const error = new Error(
      result.stderr.trim() ||
        result.stdout.trim() ||
        (result.signal
          ? `security ${commandLabel} exited with code ${exitCode}`
          : `security ${commandLabel} failed`),
    );
    Object.assign(error, {
      status: exitCode,
      signal: result.signal,
      stdout: result.stdout,
      stderr: result.stderr,
    });
    throw error;
  }

  return result.stdout.trim();
}

function renderSecurityError(error: unknown): string | null {
  if (!(error instanceof Error)) {
    return null;
  }

  const stderr = 'stderr' in error && typeof error.stderr === 'string' ? error.stderr.trim() : '';
  const stdout = 'stdout' in error && typeof error.stdout === 'string' ? error.stdout.trim() : '';
  return stderr || stdout || error.message || null;
}

function isMissingSecurityItem(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }

  const status = 'status' in error && typeof error.status === 'number' ? error.status : null;
  const message = renderSecurityError(error)?.toLowerCase() ?? '';
  return status === SECURITY_NOT_FOUND_EXIT_CODE || message.includes('could not be found');
}

function assertMacOsKeychainAvailable(): void {
  if (process.platform !== 'darwin') {
    throw new Error('macOS Keychain integration is available only on macOS');
  }
}

function withDefaultRunner(runner: SecurityCommandRunner): boolean {
  return runner === defaultSecurityRunner;
}

function assertValidKeychainAccount(account: string): string {
  const normalized = account.trim();
  if (!normalized) {
    throw new Error('keychain account is required');
  }
  if (hasControlCharacters(normalized)) {
    throw new Error('keychain account must not contain control characters');
  }
  return normalized;
}

function assertValidKeychainService(service: string): string {
  const normalized = service.trim();
  /* c8 ignore next 6 -- public APIs use fixed non-empty service identifiers, so these guards are unreachable through exported entry points */
  if (!normalized) {
    throw new Error('keychain service is required');
  }
  if (hasControlCharacters(normalized)) {
    throw new Error('keychain service must not contain control characters');
  }
  return normalized;
}

function assertValidKeychainSecret(secret: string, label: string): string {
  if (Buffer.byteLength(secret, 'utf8') > MAX_KEYCHAIN_SECRET_BYTES) {
    throw new Error(`${label} must not exceed ${MAX_KEYCHAIN_SECRET_BYTES} bytes`);
  }
  if (!secret.trim()) {
    throw new Error(`${label} must not be empty or whitespace`);
  }
  return secret;
}

/**
 * Quotes one token for `security -i` interactive mode, which splits each stdin line into argv
 * with shell-like rules: double quotes group whitespace and backslash escapes `"` and `\`.
 * Callers validate that the value has no control characters (newlines would end the command).
 */
export function quoteSecurityInteractiveArg(value: string): string {
  if (hasControlCharacters(value)) {
    throw new Error('security interactive arguments must not contain control characters');
  }
  return `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
}

/**
 * Builds the `security -i` invocation that stores a generic password. The secret is written to
 * the tool's stdin as a hex-encoded `-X` argument instead of being placed on the process argv,
 * where any local user could read it with `ps` while the command runs.
 */
export function buildStoreGenericPasswordInvocation(
  service: string,
  account: string,
  secret: string,
): SecurityCommandInvocation {
  const commandLine = [
    'add-generic-password',
    '-U',
    '-s',
    quoteSecurityInteractiveArg(service),
    '-a',
    quoteSecurityInteractiveArg(account),
    '-X',
    Buffer.from(secret, 'utf8').toString('hex'),
  ].join(' ');

  return {
    args: ['-i'],
    input: `${commandLine}\n`,
  };
}

function storeGenericPasswordInKeychain(
  service: string,
  account: string,
  secret: string,
  runner: SecurityCommandRunner = defaultSecurityRunner,
): void {
  if (withDefaultRunner(runner)) {
    assertMacOsKeychainAvailable();
  }

  const normalizedService = assertValidKeychainService(service);
  const normalizedAccount = assertValidKeychainAccount(account);
  const normalizedSecret = assertValidKeychainSecret(secret, 'keychain secret');

  runner(
    buildStoreGenericPasswordInvocation(normalizedService, normalizedAccount, normalizedSecret),
  );
}

export function storeAgentAuthTokenInKeychain(
  agentKeyId: string,
  token: string,
  runner: SecurityCommandRunner = defaultSecurityRunner,
): void {
  const normalizedAgentKeyId = assertValidAgentKeyId(agentKeyId);
  const normalizedToken = assertValidAgentAuthToken(token, 'agentAuthToken');
  storeGenericPasswordInKeychain(
    AGENT_AUTH_TOKEN_KEYCHAIN_SERVICE,
    normalizedAgentKeyId,
    normalizedToken,
    runner,
  );
}

export function storeDaemonPasswordInKeychain(
  account: string,
  password: string,
  runner: SecurityCommandRunner = defaultSecurityRunner,
): void {
  storeGenericPasswordInKeychain(DAEMON_PASSWORD_KEYCHAIN_SERVICE, account, password, runner);
}

export function readAgentAuthTokenFromKeychain(
  agentKeyId: string,
  runner: SecurityCommandRunner = defaultSecurityRunner,
): string | null {
  if (process.platform !== 'darwin' && withDefaultRunner(runner)) {
    return null;
  }

  const normalizedAgentKeyId = assertValidAgentKeyId(agentKeyId);

  try {
    return runner({
      args: [
        'find-generic-password',
        '-w',
        '-s',
        AGENT_AUTH_TOKEN_KEYCHAIN_SERVICE,
        '-a',
        normalizedAgentKeyId,
      ],
    });
  } catch (error) {
    if (isMissingSecurityItem(error)) {
      return null;
    }
    throw new Error(renderSecurityError(error) ?? 'failed to read agent auth token from Keychain');
  }
}

export function deleteAgentAuthTokenFromKeychain(
  agentKeyId: string,
  runner: SecurityCommandRunner = defaultSecurityRunner,
): boolean {
  if (process.platform !== 'darwin' && withDefaultRunner(runner)) {
    return false;
  }

  const normalizedAgentKeyId = assertValidAgentKeyId(agentKeyId);

  try {
    runner({
      args: [
        'delete-generic-password',
        '-s',
        AGENT_AUTH_TOKEN_KEYCHAIN_SERVICE,
        '-a',
        normalizedAgentKeyId,
      ],
    });
    return true;
  } catch (error) {
    if (isMissingSecurityItem(error)) {
      return false;
    }
    throw new Error(
      renderSecurityError(error) ?? 'failed to delete agent auth token from Keychain',
    );
  }
}

export function hasAgentAuthTokenInKeychain(
  agentKeyId: string,
  runner: SecurityCommandRunner = defaultSecurityRunner,
): boolean {
  return readAgentAuthTokenFromKeychain(agentKeyId, runner) !== null;
}
