import { chmodSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  assertTrustedSocket,
  checkSocketTrust,
  type StatLike,
  type TrustFs,
} from '../src/daemon/socket-trust.js';
import { TransportError } from '../src/errors.js';
import { startFakeDaemon } from './helpers/fake-daemon.js';

function stat(uid: number, mode: number, kind: 'socket' | 'dir' | 'link' | 'file'): StatLike {
  return {
    uid,
    mode,
    isSocket: () => kind === 'socket',
    isDirectory: () => kind === 'dir',
    isSymbolicLink: () => kind === 'link',
  };
}

function fakeFs(entries: Record<string, StatLike>): TrustFs {
  const get = (path: string) => {
    const entry = entries[path];
    if (!entry) {
      throw Object.assign(new Error('missing'), { code: 'ENOENT' });
    }
    return entry;
  };
  return { lstat: get, stat: get, realpath: (path) => path };
}

const ROOT_CHAIN = {
  '/': stat(0, 0o755, 'dir'),
  '/Library': stat(0, 0o755, 'dir'),
  '/Library/AgentPay': stat(0, 0o755, 'dir'),
  '/Library/AgentPay/run': stat(0, 0o755, 'dir'),
};

describe('socket trust', () => {
  const signer = '/Library/AgentPay/run/daemon.sock';

  it('accepts a root-owned socket in a root-owned chain', () => {
    const fs = fakeFs({ ...ROOT_CHAIN, [signer]: stat(0, 0o140666, 'socket') });
    expect(checkSocketTrust(signer, { kind: 'root' }, fs)).toBeNull();
  });

  it('rejects a socket a user could have planted', () => {
    const fs = fakeFs({ ...ROOT_CHAIN, [signer]: stat(501, 0o140666, 'socket') });
    expect(checkSocketTrust(signer, { kind: 'root' }, fs)).toMatch(/unexpected user/u);
  });

  it('rejects a writable directory anywhere in the chain', () => {
    const fs = fakeFs({
      ...ROOT_CHAIN,
      '/Library/AgentPay': stat(0, 0o777, 'dir'),
      [signer]: stat(0, 0o140666, 'socket'),
    });
    expect(checkSocketTrust(signer, { kind: 'root' }, fs)).toMatch(/writable by other users/u);
  });

  it('rejects symlinks and non-sockets', () => {
    expect(
      checkSocketTrust(
        signer,
        { kind: 'root' },
        fakeFs({ ...ROOT_CHAIN, [signer]: stat(0, 0, 'link') }),
      ),
    ).toMatch(/symlink/u);
    expect(
      checkSocketTrust(
        signer,
        { kind: 'root' },
        fakeFs({ ...ROOT_CHAIN, [signer]: stat(0, 0, 'file') }),
      ),
    ).toMatch(/not a socket/u);
  });

  it('pins the payments socket to the service account', () => {
    const path = '/Library/AgentPay/run/paymentd/paymentd.sock';
    const fs = fakeFs({
      ...ROOT_CHAIN,
      '/Library/AgentPay/run/paymentd': stat(250, 0o750, 'dir'),
      [path]: stat(250, 0o140660, 'socket'),
    });
    expect(checkSocketTrust(path, { kind: 'service', uid: 250 }, fs)).toBeNull();
    expect(checkSocketTrust(path, { kind: 'service', uid: 251 }, fs)).toMatch(/unexpected user/u);
  });

  it('reports a missing socket as socket_missing', () => {
    expect(() =>
      assertTrustedSocket('/nope/x.sock', { kind: 'root' }, 'signer', fakeFs({})),
    ).toThrow(TransportError);
    try {
      assertTrustedSocket('/nope/x.sock', { kind: 'root' }, 'signer', fakeFs({}));
    } catch (error) {
      expect((error as TransportError).code).toBe('socket_missing');
    }
  });

  it('checks a real development socket owned by this user', async () => {
    const daemon = await startFakeDaemon(() => ({ close: true }));
    const uid = process.getuid?.() ?? 0;
    expect(checkSocketTrust(daemon.path, { kind: 'user', uid })).toBeNull();
    const dir = daemon.path.replace(/\/s\.sock$/u, '');
    chmodSync(dir, 0o777);
    expect(checkSocketTrust(daemon.path, { kind: 'user', uid })).toMatch(/writable/u);
    chmodSync(dir, 0o700);
    await daemon.close();
    const other = join(mkdtempSync(join(tmpdir(), 'apd-')), 'none.sock');
    expect(checkSocketTrust(other, { kind: 'user', uid })).toBe('missing');
  });
});
