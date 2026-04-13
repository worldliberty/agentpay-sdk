import test from 'node:test';
import assert from 'node:assert/strict';

const modulePath = new URL('../src/lib/admin-daemon-socket.ts', import.meta.url);
const expectedDefaultManagedSocket =
  process.platform === 'linux' ? '/run/agentpay/daemon.sock' : '/Library/AgentPay/run/daemon.sock';

function loadModule(caseId) {
  return import(modulePath.href + `?case=${caseId}`);
}

test('resolveAdminDaemonSocketSelection prioritizes explicit, env, config, then managed default', async () => {
  const adminDaemonSocket = await loadModule(`${Date.now()}-selection-order`);

  assert.deepEqual(
    adminDaemonSocket.resolveAdminDaemonSocketSelection(
      '/explicit.sock',
      { daemonSocket: '/config.sock' },
      { AGENTPAY_DAEMON_SOCKET: '/env.sock' },
    ),
    { value: '/explicit.sock', source: 'explicit' },
  );
  assert.deepEqual(
    adminDaemonSocket.resolveAdminDaemonSocketSelection(
      undefined,
      { daemonSocket: '/config.sock' },
      { AGENTPAY_DAEMON_SOCKET: '/env.sock' },
    ),
    { value: '/env.sock', source: 'env-daemon-socket' },
  );
  assert.deepEqual(
    adminDaemonSocket.resolveAdminDaemonSocketSelection(undefined, { daemonSocket: '/config.sock' }, {}),
    { value: '/config.sock', source: 'config-daemon-socket' },
  );
  assert.deepEqual(adminDaemonSocket.resolveAdminDaemonSocketSelection(undefined, {}, {}), {
    value: expectedDefaultManagedSocket,
    source: 'default',
  });
});

test('resolveValidatedAdminDaemonSocket rejects empty explicit daemon socket paths', async () => {
  const adminDaemonSocket = await loadModule(`${Date.now()}-empty-explicit`);

  assert.throws(
    () =>
      adminDaemonSocket.resolveValidatedAdminDaemonSocket('   ', {}, {
        env: {},
        assertTrustedAdminDaemonSocketPath: (targetPath) => targetPath,
      }),
    /--daemon-socket requires a path/,
  );
});

test('resolveValidatedAdminDaemonSocket adds recovery commands for stale config overrides', async () => {
  const adminDaemonSocket = await loadModule(`${Date.now()}-config-recovery`);

  assert.throws(
    () =>
      adminDaemonSocket.resolveValidatedAdminDaemonSocket(undefined, {
        daemonSocket: '/Users/example/agentpay-home/daemon.sock',
      }, {
        env: {},
        assertTrustedAdminDaemonSocketPath: () => {
          throw new Error("Daemon socket directory '/Users/example/agentpay-home' must be owned by root");
        },
      }),
    /agentpay config unset daemonSocket/,
  );
  assert.throws(
    () =>
      adminDaemonSocket.resolveValidatedAdminDaemonSocket(undefined, {
        daemonSocket: '/Users/example/agentpay-home/daemon.sock',
      }, {
        env: {},
        assertTrustedAdminDaemonSocketPath: () => {
          throw new Error("Daemon socket directory '/Users/example/agentpay-home' must be owned by root");
        },
      }),
    /agentpay status --strict/,
  );
});

test('resolveValidatedAdminDaemonSocket adds AGENTPAY_HOME recovery guidance for managed defaults', async () => {
  const adminDaemonSocket = await loadModule(`${Date.now()}-default-recovery`);

  assert.throws(
    () =>
      adminDaemonSocket.resolveValidatedAdminDaemonSocket(undefined, {}, {
        env: { AGENTPAY_HOME: '/Users/example/agentpay-home' },
        assertTrustedAdminDaemonSocketPath: () => {
          throw new Error("Daemon socket '/Library/AgentPay/run/daemon.sock' does not exist");
        },
      }),
    /unset `AGENTPAY_HOME`/,
  );
  assert.throws(
    () =>
      adminDaemonSocket.resolveValidatedAdminDaemonSocket(undefined, {}, {
        env: { AGENTPAY_HOME: '/Users/example/agentpay-home' },
        assertTrustedAdminDaemonSocketPath: () => {
          throw new Error("Daemon socket '/Library/AgentPay/run/daemon.sock' does not exist");
        },
      }),
    /agentpay admin setup --reuse-existing-wallet/,
  );
});

test('resolveValidatedAdminDaemonSocket uses the managed Linux default when no override is configured', async () => {
  const adminDaemonSocket = await loadModule(`${Date.now()}-linux-default-supported`);

  const resolved = adminDaemonSocket.resolveValidatedAdminDaemonSocket(undefined, {}, {
    env: {},
    platform: 'linux',
    assertTrustedAdminDaemonSocketPath: (targetPath) => {
      assert.equal(targetPath, '/run/agentpay/daemon.sock');
      return targetPath;
    },
  });

  assert.equal(resolved, '/run/agentpay/daemon.sock');
});

test('wrapAdminDaemonSocketTrustError gives Linux-specific recovery guidance', async () => {
  const adminDaemonSocket = await loadModule(`${Date.now()}-linux-trust-guidance`);

  const error = adminDaemonSocket.wrapAdminDaemonSocketTrustError(
    "Daemon socket '/tmp/agentpay.sock' must be owned by root",
    'explicit',
    {},
    'linux',
  );

  assert.match(error.message, /managed root-owned socket `\/run\/agentpay\/daemon\.sock`/u);
  assert.match(error.message, /agentpay admin setup --reuse-existing-wallet/u);
  assert.doesNotMatch(error.message, /point the command at your existing daemon socket with/u);
});
