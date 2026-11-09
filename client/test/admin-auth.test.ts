import { chmodSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createAdminAuthorizer, parseChallengeMessage } from '../src/auth/admin-auth.js';
import { memoryClientStateStore } from '../src/auth/client-state.js';
import { runCommand } from '../src/auth/process.js';
import {
  createTouchIdHelper,
  HelperError,
  sanitizeReason,
  type TouchIdHelper,
} from '../src/auth/touch-id.js';
import { SignerClient } from '../src/daemon/signer.js';
import { AuthError } from '../src/errors.js';
import { body, type FakeDaemon, ok, startFakeDaemon, withHello } from './helpers/fake-daemon.js';
import { fixture, fixtureData } from './helpers/fixtures.js';

const CREDENTIAL = '6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b';
const challenge = fixtureData<{ challenge_id: string; message_hex: string }>(
  'rpc/BeginAdminChallenge.response.json',
);
const SIGNATURE = (
  fixture('rpc/CompleteAdminChallenge.request.json') as unknown as {
    params: { signature_der_hex: string };
  }
).params.signature_der_hex;

describe('challenge message', () => {
  it('parses the documented example', () => {
    const message = parseChallengeMessage(challenge.message_hex);
    expect(message.credentialId).toBe(CREDENTIAL);
    expect(message.purpose).toBe('admin-session');
    expect(message.expiresAt.toISOString()).toBe('2026-11-05T12:02:00.000Z');
  });

  it('rejects other messages', () => {
    expect(() => parseChallengeMessage('00ff')).toThrow();
  });
});

function fakeHelper(sign: TouchIdHelper['sign']): TouchIdHelper & { reasons: string[] } {
  const reasons: string[] = [];
  return {
    path: '/fake/agentpay-auth',
    reasons,
    status: async () => ({
      secureEnclaveAvailable: true,
      biometry: { available: true, kind: 'touch_id' },
      userPresenceAvailable: true,
    }),
    create: async () => ({ publicKeySec1Hex: '04ab' }),
    sign: async (keyFile, reason, messageHex) => {
      reasons.push(reason);
      return sign(keyFile, reason, messageHex);
    },
    remove: async () => {},
  };
}

let daemon: FakeDaemon | null = null;
afterEach(async () => {
  await daemon?.close();
  daemon = null;
});

async function setup(options: {
  euid?: number;
  credential?: boolean;
  helper?: TouchIdHelper | null;
  platform?: NodeJS.Platform;
}) {
  daemon = await startFakeDaemon(
    withHello((call) => {
      switch (call.method) {
        case 'BeginAdminChallenge':
          return body(fixture('rpc/BeginAdminChallenge.response.json'));
        case 'CompleteAdminChallenge':
          return body(fixture('rpc/CompleteAdminChallenge.response.json'));
        case 'RevokeAdminLease':
          return ok('Unit');
        default:
          return { close: true };
      }
    }),
  );
  const signer = new SignerClient({
    endpoint: {
      service: 'signer',
      path: daemon.path,
      trust: () => ({ kind: 'user', uid: process.getuid?.() ?? 0 }),
    },
  });
  return createAdminAuthorizer({
    euid: options.euid ?? 501,
    platform: options.platform ?? 'darwin',
    state: memoryClientStateStore(
      options.credential === false ? {} : { adminCredentialId: CREDENTIAL },
    ),
    helper:
      options.helper === undefined
        ? fakeHelper(async () => ({ signatureDerHex: SIGNATURE }))
        : options.helper,
    keyFile: '/home/me/.agentpay/admin-key.json',
    keyFileExists: () => true,
    signer,
    now: () => new Date('2026-11-05T12:00:30Z'),
  });
}

const OPERATION = {
  purpose: 'admin-session',
  reason: 'approve sending 1 USD1',
  command: 'agentpay admin approve x',
};

describe('admin authorization', () => {
  it('uses the root peer under sudo', async () => {
    const authorizer = await setup({ euid: 0 });
    expect(authorizer.method()).toBe('root');
    expect((await authorizer.authorize(OPERATION)).auth).toBe('peer_credentials');
    expect(daemon?.calls).toEqual([]);
  });

  it('runs the Touch ID challenge flow and revokes the lease afterwards', async () => {
    const helper = fakeHelper(async () => ({ signatureDerHex: SIGNATURE }));
    const authorizer = await setup({ helper });
    expect(authorizer.method()).toBe('touch_id');
    const grant = await authorizer.authorize(OPERATION);
    expect(grant.auth).toEqual({
      lease: {
        lease_id: 'c3d2e1f0-5a6b-4c7d-8e9f-0a1b2c3d4e5f',
        lease_secret: '3f9a6c1e8b2d47f0a5c3e9b1d7f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8',
      },
    });
    expect(helper.reasons).toEqual(['approve sending 1 USD1']);
    await grant.release();
    expect(daemon?.calls.map((c) => c.method)).toEqual([
      'Hello',
      'BeginAdminChallenge',
      'CompleteAdminChallenge',
      'RevokeAdminLease',
    ]);
    expect(daemon?.calls[1]?.params).toEqual({
      credential_id: CREDENTIAL,
      purpose: 'admin-session',
    });
    expect(daemon?.calls[2]?.params).toEqual({
      challenge_id: challenge.challenge_id,
      signature_der_hex: SIGNATURE,
    });
  });

  it('refuses to sign a challenge issued for another purpose', async () => {
    const authorizer = await setup({});
    await expect(
      authorizer.authorize({ ...OPERATION, purpose: 'approve:e7d6c5b4' }),
    ).rejects.toMatchObject({
      code: 'touch_id_failed',
    });
  });

  it('reuses one session lease for setup-style operations', async () => {
    const helper = fakeHelper(async () => ({ signatureDerHex: SIGNATURE }));
    const authorizer = await setup({ helper });
    await authorizer.authorize({ ...OPERATION, reusable: true });
    await authorizer.authorize({ ...OPERATION, purpose: 'limits:set', reusable: true });
    expect(helper.reasons).toHaveLength(1);
    await authorizer.dispose();
    expect(daemon?.calls.filter((c) => c.method === 'RevokeAdminLease')).toHaveLength(1);
  });

  it('maps helper failures to one clear next action', async () => {
    const cancel = await setup({
      helper: fakeHelper(async () => {
        throw new HelperError('user_cancel', 'cancelled');
      }),
    });
    await expect(cancel.authorize(OPERATION)).rejects.toMatchObject({ code: 'touch_id_cancelled' });
    await daemon?.close();
    const ssh = await setup({
      helper: fakeHelper(async () => {
        throw new HelperError('interaction_not_allowed', 'no GUI');
      }),
    });
    const error = await ssh.authorize(OPERATION).catch((e: unknown) => e);
    expect((error as AuthError).guidance.next).toBe(
      'Run it with sudo instead: `sudo agentpay admin approve x`.',
    );
  });

  it('tells the user to use sudo without Touch ID (Linux, or not enrolled)', async () => {
    const linux = await setup({ platform: 'linux' });
    expect(linux.method()).toBe('sudo');
    const error = await linux.authorize(OPERATION).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AuthError);
    expect((error as AuthError).guidance.next).toContain('sudo agentpay admin approve x');
    await daemon?.close();
    const notEnrolled = await setup({ credential: false });
    expect(notEnrolled.method()).toBe('sudo');
  });
});

describe('agentpay-auth helper contract', () => {
  function script(body: string): string {
    const dir = mkdtempSync(join(tmpdir(), 'aph-'));
    const path = join(dir, 'agentpay-auth');
    writeFileSync(path, `#!/bin/sh\n${body}\n`);
    chmodSync(path, 0o755);
    return path;
  }

  it('passes the documented arguments and parses JSON output', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'aph-'));
    const log = join(dir, 'args');
    const path = script(
      `printf '%s\\n' "$@" > ${log}\ncase "$1" in\n  status) echo '{"biometry":{"available":true,"kind":"touch_id"},"secureEnclaveAvailable":true,"userPresenceAvailable":true}';;\n  create) echo '{"publicKeySec1Hex":"04AB"}';;\n  sign) echo '{"signatureDerHex":"3045"}';;\n  delete) echo '{"deleted":true}';;\nesac`,
    );
    const helper = createTouchIdHelper(path, runCommand);
    expect(await helper.status()).toEqual({
      secureEnclaveAvailable: true,
      biometry: { available: true, kind: 'touch_id' },
      userPresenceAvailable: true,
    });
    expect(await helper.create('/k.json')).toEqual({ publicKeySec1Hex: '04ab' });
    expect(await helper.sign('/k.json', 'approve sending 1 USD1', 'abcd')).toEqual({
      signatureDerHex: '3045',
    });
    const { readFileSync } = await import('node:fs');
    expect(readFileSync(log, 'utf8').trim().split('\n')).toEqual([
      'sign',
      '--key-file',
      '/k.json',
      '--reason',
      'approve sending 1 USD1',
      '--message-hex',
      'abcd',
    ]);
  });

  it('turns `{"error":{"code":...}}` with exit 1 into a typed error', async () => {
    const path = script(
      `echo '{"error":{"code":"user_cancel","message":"Canceled by user"}}'\nexit 1`,
    );
    const error = await createTouchIdHelper(path, runCommand)
      .sign('/k.json', 'x', 'ab')
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(HelperError);
    expect((error as HelperError).code).toBe('user_cancel');
  });

  it('reports a missing helper', async () => {
    const error = await createTouchIdHelper('/nonexistent/agentpay-auth', runCommand)
      .status()
      .catch((e: unknown) => e);
    expect((error as HelperError).code).toBe('helper_missing');
  });

  it('keeps prompt reasons to one line of at most 200 characters', () => {
    expect(sanitizeReason('approve\nthis‮ now')).toBe('approve this now');
    expect(Array.from(sanitizeReason('x'.repeat(300)))).toHaveLength(200);
  });
});
