import { mkdtempSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { resolveAgentAuth } from '../src/auth/agent-credentials.js';
import { memoryClientStateStore } from '../src/auth/client-state.js';
import type { CommandRunner, RunOptions } from '../src/auth/process.js';
import {
  AGENT_TOKEN_SERVICE,
  fileSecretStore,
  macosKeychainStore,
  memorySecretStore,
  quoteSecurityArg,
  secretToolStore,
  withFallback,
} from '../src/auth/secret-store.js';
import { AuthError, UsageError } from '../src/errors.js';

interface Invocation {
  command: string;
  args: readonly string[];
  options: RunOptions | undefined;
}

function recorder(results: { status: number; stdout?: string; stderr?: string }[]) {
  const calls: Invocation[] = [];
  const run: CommandRunner = async (command, args, options) => {
    calls.push({ command, args, options });
    const next = results.shift() ?? { status: 0 };
    return { status: next.status, stdout: next.stdout ?? '', stderr: next.stderr ?? '' };
  };
  return { calls, run };
}

const ID = '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d';
const TOKEN = '8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7';

describe('macOS keychain store', () => {
  it('writes through `security -i` with the token hex-encoded on stdin, never in argv', async () => {
    const { calls, run } = recorder([{ status: 0 }]);
    await macosKeychainStore(run).write(ID, TOKEN);
    expect(calls[0]?.command).toBe('security');
    expect(calls[0]?.args).toEqual(['-i']);
    expect(calls[0]?.args.join(' ')).not.toContain(TOKEN);
    expect(calls[0]?.options?.input).toBe(
      `add-generic-password -U -s "${AGENT_TOKEN_SERVICE}" -a "${ID}" -X ${Buffer.from(TOKEN).toString('hex')}\n`,
    );
  });

  it('reads a token and treats exit 44 as not found', async () => {
    const { calls, run } = recorder([{ status: 0, stdout: `${TOKEN}\n` }, { status: 44 }]);
    const store = macosKeychainStore(run);
    expect(await store.read(ID)).toBe(TOKEN);
    expect(calls[0]?.args).toEqual([
      'find-generic-password',
      '-w',
      '-s',
      AGENT_TOKEN_SERVICE,
      '-a',
      ID,
    ]);
    expect(await store.read(ID)).toBeNull();
  });

  it('quotes interactive arguments and rejects control characters', () => {
    expect(quoteSecurityArg('a "b" \\c')).toBe('"a \\"b\\" \\\\c"');
    expect(() => quoteSecurityArg('a\nb')).toThrow();
  });
});

describe('Linux stores', () => {
  it('stores through secret-tool with the token on stdin', async () => {
    const { calls, run } = recorder([{ status: 0 }, { status: 1 }]);
    const store = secretToolStore(run);
    await store.write(ID, TOKEN);
    expect(calls[0]?.args).toEqual([
      'store',
      '--label=AgentPay agent auth token',
      'service',
      AGENT_TOKEN_SERVICE,
      'account',
      ID,
    ]);
    expect(calls[0]?.options?.input).toBe(`${TOKEN}\n`);
    expect(await store.read(ID)).toBeNull();
  });

  it('falls back to a 0600 file when the Secret Service fails', async () => {
    const dir = join(mkdtempSync(join(tmpdir(), 'ap-')), 'agent-auth');
    const { run } = recorder([
      { status: 1, stderr: 'Cannot autolaunch D-Bus' },
      { status: 1, stderr: 'Cannot autolaunch D-Bus' },
    ]);
    const store = withFallback(secretToolStore(run), fileSecretStore(dir));
    await store.write(ID, TOKEN);
    expect(statSync(join(dir, `${ID}.token`)).mode & 0o777).toBe(0o600);
    expect(statSync(dir).mode & 0o777).toBe(0o700);
    expect(await store.read(ID)).toBe(TOKEN);
  });
});

describe('agent credentials', () => {
  const sources = (overrides: {
    state?: string | null;
    token?: string;
    stdin?: string;
    env?: NodeJS.ProcessEnv;
  }) => ({
    env: overrides.env ?? {},
    state: memoryClientStateStore(overrides.state ? { agentKeyId: overrides.state } : {}),
    store: memorySecretStore(overrides.token ? { [ID]: overrides.token } : {}),
    readStdin: async () => overrides.stdin ?? '',
  });

  it('uses the saved key id and the stored token', async () => {
    await expect(resolveAgentAuth({}, sources({ state: ID, token: TOKEN }))).resolves.toEqual({
      agent_key_id: ID,
      agent_auth_token: TOKEN,
    });
  });

  it('prefers --agent-key-id and reads the token from stdin when asked', async () => {
    const auth = await resolveAgentAuth(
      { agentKeyId: ID.toUpperCase(), agentAuthTokenStdin: true },
      sources({ stdin: `${TOKEN}\n` }),
    );
    expect(auth).toEqual({ agent_key_id: ID, agent_auth_token: TOKEN });
  });

  it('explains what to do when nothing is set up', async () => {
    const error = await resolveAgentAuth({}, sources({})).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AuthError);
    expect((error as AuthError).exitCode).toBe(4);
    expect((error as AuthError).guidance.next).toContain('agentpay setup');
    await expect(resolveAgentAuth({}, sources({ state: ID }))).rejects.toMatchObject({
      code: 'token_missing',
    });
    await expect(resolveAgentAuth({ agentKeyId: 'nope' }, sources({}))).rejects.toBeInstanceOf(
      UsageError,
    );
  });
});
