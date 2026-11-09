import { describe, expect, it } from 'vitest';
import { readServiceUid, resolveEndpoints } from '../src/daemon/endpoints.js';
import type { StatLike, TrustFs } from '../src/daemon/socket-trust.js';
import { AuthError } from '../src/errors.js';

const file = (uid: number, mode = 0o644): StatLike => ({
  uid,
  mode,
  isSocket: () => false,
  isDirectory: () => false,
  isSymbolicLink: () => false,
});
const fsWith = (entries: Record<string, StatLike>): TrustFs => ({
  lstat: (path) => {
    const entry = entries[path];
    if (!entry) {
      throw Object.assign(new Error('missing'), { code: 'ENOENT' });
    }
    return entry;
  },
  stat: (path) => entries[path] ?? file(0),
  realpath: (path) => path,
});

describe('endpoints', () => {
  it('uses the documented production sockets per OS', () => {
    const mac = resolveEndpoints({ env: {}, platform: 'darwin', uid: 501 });
    expect(mac.signer.path).toBe('/Library/AgentPay/run/daemon.sock');
    expect(mac.payments.path).toBe('/Library/AgentPay/run/paymentd/paymentd.sock');
    expect(mac.signer.trust()).toEqual({ kind: 'root' });
    const linux = resolveEndpoints({ env: {}, platform: 'linux', uid: 1000 });
    expect(linux.signer.path).toBe('/run/agentpay/daemon.sock');
    expect(linux.payments.path).toBe('/run/agentpay-paymentd/paymentd.sock');
  });

  it('pins the payments socket to the service uid from the root-owned install record', () => {
    const endpoints = resolveEndpoints({
      env: {},
      platform: 'linux',
      uid: 1000,
      fs: fsWith({ '/opt/agentpay/install.json': file(0) }),
      readFile: () => JSON.stringify({ service_uid: 997, uid: 1000 }),
    });
    expect(endpoints.payments.trust()).toEqual({ kind: 'service', uid: 997 });
  });

  it('treats a missing or user-writable install record as not installed', () => {
    expect(() => readServiceUid('/opt/agentpay/install.json', fsWith({}))).toThrow(AuthError);
    expect(() =>
      readServiceUid(
        '/opt/agentpay/install.json',
        fsWith({ '/opt/agentpay/install.json': file(1000) }),
        () => '{}',
      ),
    ).toThrow(AuthError);
  });

  it('ignores $AGENTPAY_HOME (left over from the previous installer) for sockets', () => {
    const endpoints = resolveEndpoints({
      env: { AGENTPAY_HOME: '/Users/alice/.agentpay' },
      platform: 'darwin',
      uid: 501,
    });
    expect(endpoints.signer.path).toBe('/Library/AgentPay/run/daemon.sock');
    expect(endpoints.signer.trust()).toEqual({ kind: 'root' });
    expect(endpoints.payments.path).toBe('/Library/AgentPay/run/paymentd/paymentd.sock');
  });

  it('uses explicit development sockets', () => {
    const explicit = resolveEndpoints({
      env: { AGENTPAY_HOME: '/tmp/ap', AGENTPAY_PAYMENTS_SOCKET: '/tmp/p.sock' },
      platform: 'darwin',
      uid: 501,
      overrides: { daemonSocket: '/tmp/d.sock' },
    });
    expect(explicit.signer.path).toBe('/tmp/d.sock');
    expect(explicit.payments.path).toBe('/tmp/p.sock');
    expect(explicit.payments.trust()).toEqual({ kind: 'user', uid: 501 });
  });
});
