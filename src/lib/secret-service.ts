import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { constants as osConstants } from 'node:os';
import { assertValidAgentAuthToken } from './agent-auth-token.js';
import { assertValidAgentKeyId } from './keychain.js';

export const AGENT_AUTH_TOKEN_SECRET_SERVICE = 'agentpay-agent-auth-token';
const MAX_SECRET_SERVICE_SECRET_BYTES = 16 * 1024;

export interface SecretToolCommandInvocation {
  args: string[];
  input?: string;
}

export type SecretToolRunner = (command: SecretToolCommandInvocation) => string;

function signalExitCode(signal: NodeJS.Signals | null): number {
  if (!signal) {
    return 1;
  }

  const signalNumber = osConstants.signals[signal];
  return typeof signalNumber === 'number' ? 128 + signalNumber : 128;
}

function renderRunnerError(error: unknown): string | null {
  if (!(error instanceof Error)) {
    return null;
  }

  const stderr = 'stderr' in error && typeof error.stderr === 'string' ? error.stderr.trim() : '';
  const stdout = 'stdout' in error && typeof error.stdout === 'string' ? error.stdout.trim() : '';
  return stderr || stdout || error.message || null;
}

export function isSecretToolUnavailableError(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }

  const code = 'code' in error && typeof error.code === 'string' ? error.code : null;
  const message = renderRunnerError(error)?.toLowerCase() ?? '';
  return (
    code === 'ENOENT' ||
    message.includes('spawnsync secret-tool enoent') ||
    message.includes('spawn secret-tool enoent')
  );
}

export function isSecretToolAvailable(searchPath = process.env.PATH): boolean {
  for (const entry of (searchPath ?? '').split(path.delimiter).filter(Boolean)) {
    const candidate = path.join(entry, 'secret-tool');
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return true;
    } catch {}
  }

  return false;
}

function defaultSecretToolRunner(command: SecretToolCommandInvocation): string {
  const result = spawnSync('secret-tool', command.args, {
    encoding: 'utf8',
    input: command.input,
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  if (result.error) {
    throw result.error;
  }
  const exitCode = result.status ?? signalExitCode(result.signal);
  if (exitCode !== 0) {
    const error = new Error(
      result.stderr.trim() ||
        result.stdout.trim() ||
        (result.signal
          ? `secret-tool ${command.args[0]} exited with code ${exitCode}`
          : `secret-tool ${command.args[0]} failed`),
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

function assertLinuxSecretServiceAvailable(): void {
  if (process.platform !== 'linux') {
    throw new Error('Linux Secret Service integration is available only on Linux');
  }
}

function withDefaultRunner(runner: SecretToolRunner): boolean {
  return runner === defaultSecretToolRunner;
}

function assertValidSecretServiceSecret(secret: string, label: string): string {
  if (Buffer.byteLength(secret, 'utf8') > MAX_SECRET_SERVICE_SECRET_BYTES) {
    throw new Error(`${label} must not exceed ${MAX_SECRET_SERVICE_SECRET_BYTES} bytes`);
  }
  if (!secret.trim()) {
    throw new Error(`${label} must not be empty or whitespace`);
  }
  return secret;
}

function isMissingSecret(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }

  const status = 'status' in error && typeof error.status === 'number' ? error.status : null;
  const message = renderRunnerError(error)?.toLowerCase() ?? '';
  return (
    status === 1 &&
    (message === '' ||
      message.includes('no such secret collection') ||
      message.includes('no such secret') ||
      message.includes('not found'))
  );
}

export function storeAgentAuthTokenInSecretService(
  agentKeyId: string,
  token: string,
  runner: SecretToolRunner = defaultSecretToolRunner,
): void {
  if (withDefaultRunner(runner)) {
    assertLinuxSecretServiceAvailable();
  }

  const normalizedAgentKeyId = assertValidAgentKeyId(agentKeyId);
  const normalizedToken = assertValidAgentAuthToken(token, 'agentAuthToken');
  runner({
    args: [
      'store',
      '--label=AgentPay agent auth token',
      'service',
      AGENT_AUTH_TOKEN_SECRET_SERVICE,
      'account',
      normalizedAgentKeyId,
    ],
    input: `${normalizedToken}\n`,
  });
}

export function readAgentAuthTokenFromSecretService(
  agentKeyId: string,
  runner: SecretToolRunner = defaultSecretToolRunner,
): string | null {
  if (process.platform !== 'linux' && withDefaultRunner(runner)) {
    return null;
  }

  const normalizedAgentKeyId = assertValidAgentKeyId(agentKeyId);
  try {
    const value = runner({
      args: [
        'lookup',
        'service',
        AGENT_AUTH_TOKEN_SECRET_SERVICE,
        'account',
        normalizedAgentKeyId,
      ],
    });
    return assertValidSecretServiceSecret(value, 'agentAuthToken');
  } catch (error) {
    if (isMissingSecret(error)) {
      return null;
    }
    throw new Error(
      renderRunnerError(error) ?? 'failed to read agent auth token from Linux Secret Service',
    );
  }
}

export function deleteAgentAuthTokenFromSecretService(
  agentKeyId: string,
  runner: SecretToolRunner = defaultSecretToolRunner,
): boolean {
  if (process.platform !== 'linux' && withDefaultRunner(runner)) {
    return false;
  }

  const normalizedAgentKeyId = assertValidAgentKeyId(agentKeyId);
  const current = readAgentAuthTokenFromSecretService(normalizedAgentKeyId, runner);
  if (current === null) {
    return false;
  }

  try {
    runner({
      args: [
        'clear',
        'service',
        AGENT_AUTH_TOKEN_SECRET_SERVICE,
        'account',
        normalizedAgentKeyId,
      ],
    });
    return true;
  } catch (error) {
    if (isMissingSecret(error)) {
      return false;
    }
    throw new Error(
      renderRunnerError(error) ?? 'failed to delete agent auth token from Linux Secret Service',
    );
  }
}

export function hasAgentAuthTokenInSecretService(
  agentKeyId: string,
  runner: SecretToolRunner = defaultSecretToolRunner,
): boolean {
  return readAgentAuthTokenFromSecretService(agentKeyId, runner) !== null;
}
