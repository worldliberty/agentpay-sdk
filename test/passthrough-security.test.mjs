import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

const modulePath = new URL('../src/lib/passthrough-security.ts', import.meta.url);
const expectedDefaultManagedSocket =
  process.platform === 'linux' ? '/run/agentpay/daemon.sock' : '/Library/AgentPay/run/daemon.sock';

function loadModule(caseId) {
  return import(modulePath.href + `?case=${caseId}`);
}

function withMockedEuid(euid, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(process, 'geteuid');
  Object.defineProperty(process, 'geteuid', {
    configurable: true,
    value: () => euid,
  });

  try {
    return fn();
  } finally {
    if (descriptor) {
      Object.defineProperty(process, 'geteuid', descriptor);
    } else {
      delete process.geteuid;
    }
  }
}

async function listenOnUnixSocket(socketPath) {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      server.off('error', reject);
      resolve();
    });
  });
  return server;
}

async function closeUnixSocket(server, socketPath) {
  await new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
  fs.rmSync(socketPath, { force: true });
}

test('forwardedArgsSkipDaemonSocketValidation skips help and version passthroughs', async () => {
  const passthrough = await loadModule(`${Date.now()}-skip`);

  assert.equal(passthrough.forwardedArgsSkipDaemonSocketValidation(['help']), true);
  assert.equal(passthrough.forwardedArgsSkipDaemonSocketValidation(['--help']), true);
  assert.equal(passthrough.forwardedArgsSkipDaemonSocketValidation(['transfer', '-h']), true);
  assert.equal(passthrough.forwardedArgsSkipDaemonSocketValidation(['--version']), true);
  assert.equal(passthrough.forwardedArgsSkipDaemonSocketValidation(['transfer']), false);
  assert.equal(passthrough.forwardedArgsSkipDaemonSocketValidation(['transfer', 'help']), false);
  assert.equal(passthrough.forwardedArgsSkipDaemonSocketValidation(['transfer', '--', '--help']), false);
  assert.equal(passthrough.forwardedArgsSkipDaemonSocketValidation(['transfer', '--', '-h']), false);
});

test('resolveValidatedPassthroughDaemonSocket prefers explicit forwarded daemon sockets', async () => {
  const passthrough = await loadModule(`${Date.now()}-explicit`);
  const seen = [];

  const resolved = passthrough.resolveValidatedPassthroughDaemonSocket(
    'agentpay-agent',
    ['--daemon-socket', '/trusted/run/custom.sock', 'transfer'],
    { daemonSocket: '/trusted/run/config.sock' },
    {
      env: { AGENTPAY_DAEMON_SOCKET: '/trusted/run/env.sock' },
      assertTrustedDaemonSocketPath: (targetPath) => {
        seen.push(targetPath);
        return targetPath;
      }
    }
  );

  assert.equal(resolved, '/trusted/run/custom.sock');
  assert.deepEqual(seen, ['/trusted/run/custom.sock']);
});

test('resolveValidatedPassthroughDaemonSocket falls back to env and config values', async () => {
  const passthrough = await loadModule(`${Date.now()}-fallback`);

  const envResolved = passthrough.resolveValidatedPassthroughDaemonSocket(
    'agentpay-admin',
    ['bootstrap'],
    { daemonSocket: '/trusted/run/config.sock' },
    {
      env: { AGENTPAY_DAEMON_SOCKET: '/trusted/run/env.sock' },
      assertTrustedDaemonSocketPath: (targetPath) => targetPath
    }
  );
  const configResolved = passthrough.resolveValidatedPassthroughDaemonSocket(
    'agentpay-admin',
    ['bootstrap'],
    { daemonSocket: '/trusted/run/config.sock' },
    {
      env: {},
      assertTrustedDaemonSocketPath: (targetPath) => targetPath
    }
  );

  assert.equal(envResolved, '/trusted/run/env.sock');
  assert.equal(configResolved, '/trusted/run/config.sock');
});

test('resolveValidatedPassthroughDaemonSocket falls back to the default daemon socket path', async () => {
  const passthrough = await loadModule(`${Date.now()}-default-daemon-socket`);
  const originalAgentPayHome = process.env.AGENTPAY_HOME;

  try {
    process.env.AGENTPAY_HOME = '/trusted/default-home';
    const resolved = passthrough.resolveValidatedPassthroughDaemonSocket(
      'agentpay-agent',
      ['transfer'],
      {},
      {
        env: {},
        assertTrustedDaemonSocketPath: (targetPath) => targetPath,
      },
    );

    assert.equal(resolved, '/trusted/default-home/daemon.sock');
  } finally {
    if (originalAgentPayHome === undefined) {
      delete process.env.AGENTPAY_HOME;
    } else {
      process.env.AGENTPAY_HOME = originalAgentPayHome;
    }
  }
});

test('resolveValidatedPassthroughDaemonSocket defaults admin passthroughs to the managed root socket', async () => {
  const passthrough = await loadModule(`${Date.now()}-default-admin-daemon-socket`);
  const originalAgentPayHome = process.env.AGENTPAY_HOME;

  try {
    process.env.AGENTPAY_HOME = '/trusted/default-home';
    const resolved = passthrough.resolveValidatedPassthroughDaemonSocket(
      'agentpay-admin',
      ['bootstrap'],
      {},
      {
        env: {},
        assertTrustedDaemonSocketPath: (targetPath) => targetPath,
      },
    );

    assert.equal(resolved, expectedDefaultManagedSocket);
  } finally {
    if (originalAgentPayHome === undefined) {
      delete process.env.AGENTPAY_HOME;
    } else {
      process.env.AGENTPAY_HOME = originalAgentPayHome;
    }
  }
});

test('resolveValidatedPassthroughDaemonSocket rejects empty daemon socket values', async () => {
  const passthrough = await loadModule(`${Date.now()}-empty`);

  assert.throws(
    () =>
      passthrough.resolveValidatedPassthroughDaemonSocket(
        'agentpay-agent',
        ['--daemon-socket=   ', 'transfer'],
        {},
        {
          env: {},
          assertTrustedDaemonSocketPath: (targetPath) => targetPath
        }
      ),
    /--daemon-socket requires a path/
  );
});

test('resolveValidatedPassthroughDaemonSocket rejects duplicate daemon socket values', async () => {
  const passthrough = await loadModule(`${Date.now()}-duplicate`);

  assert.throws(
    () =>
      passthrough.resolveValidatedPassthroughDaemonSocket(
        'agentpay-agent',
        ['--daemon-socket', '/trusted/one.sock', '--daemon-socket=/trusted/two.sock', 'transfer'],
        {},
        {
          env: {},
          assertTrustedDaemonSocketPath: (targetPath) => targetPath
        }
      ),
    /--daemon-socket may only be provided once/
  );
});

test('readForwardedLongOptionValue ignores tokens after option terminator', async () => {
  const passthrough = await loadModule(`${Date.now()}-terminator`);

  assert.deepEqual(
    passthrough.readForwardedLongOptionValue(
      ['transfer', '--', '--daemon-socket', '/unparsed.sock'],
      '--daemon-socket'
    ),
    {
      present: false,
      value: undefined
    }
  );
});

test('resolveValidatedPassthroughDaemonSocket skips validation for daemon passthroughs', async () => {
  const passthrough = await loadModule(`${Date.now()}-daemon`);
  let called = false;

  const resolved = passthrough.resolveValidatedPassthroughDaemonSocket(
    'agentpay-daemon',
    ['start'],
    {},
    {
      env: {},
      assertTrustedDaemonSocketPath: () => {
        called = true;
        return '/trusted/run/daemon.sock';
      }
    }
  );

  assert.equal(resolved, null);
  assert.equal(called, false);
});

test('resolveValidatedPassthroughDaemonSocket requires root-owned sockets for admin passthroughs by default', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const passthrough = await loadModule(`${Date.now()}-admin-root-owned`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-passthrough-'));
  const socketDir = path.join(tempRoot, 'run');
  const socketPath = path.join(socketDir, 'daemon.sock');
  fs.mkdirSync(socketDir, { mode: 0o755 });

  const server = await listenOnUnixSocket(socketPath);

  assert.throws(
    () => passthrough.resolveValidatedPassthroughDaemonSocket('agentpay-admin', ['bootstrap'], {
      daemonSocket: socketPath
    }),
    /must be owned by root/
  );

  await closeUnixSocket(server, socketPath);
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('resolveValidatedPassthroughDaemonSocket adds recovery commands for stale admin config overrides', async () => {
  const passthrough = await loadModule(`${Date.now()}-admin-config-recovery`);

  assert.throws(
    () =>
      passthrough.resolveValidatedPassthroughDaemonSocket(
        'agentpay-admin',
        ['bootstrap'],
        { daemonSocket: '/Users/example/agentpay-home/daemon.sock' },
        {
          env: {},
          assertTrustedDaemonSocketPath: () => {
            throw new Error(
              "Daemon socket directory '/Users/example/agentpay-home' must be owned by root",
            );
          },
        },
      ),
    /agentpay config unset daemonSocket/,
  );
  assert.throws(
    () =>
      passthrough.resolveValidatedPassthroughDaemonSocket(
        'agentpay-admin',
        ['bootstrap'],
        { daemonSocket: '/Users/example/agentpay-home/daemon.sock' },
        {
          env: {},
          assertTrustedDaemonSocketPath: () => {
            throw new Error(
              "Daemon socket directory '/Users/example/agentpay-home' must be owned by root",
            );
          },
        },
      ),
    /agentpay status --strict/,
  );
  assert.throws(
    () =>
      passthrough.resolveValidatedPassthroughDaemonSocket(
        'agentpay-admin',
        ['bootstrap'],
        { daemonSocket: '/Users/example/agentpay-home/daemon.sock' },
        {
          env: {},
          assertTrustedDaemonSocketPath: () => {
            throw new Error(
              "Daemon socket directory '/Users/example/agentpay-home' must be owned by root",
            );
          },
        },
      ),
    /agentpay admin setup --reuse-existing-wallet/,
  );
});

test('resolveValidatedPassthroughDaemonSocket still accepts same-user sockets for agent passthroughs', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const passthrough = await loadModule(`${Date.now()}-agent-same-user`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-passthrough-'));
  const socketDir = path.join(tempRoot, 'run');
  const socketPath = path.join(socketDir, 'daemon.sock');
  fs.mkdirSync(socketDir, { mode: 0o755 });

  const server = await listenOnUnixSocket(socketPath);

  assert.equal(
    passthrough.resolveValidatedPassthroughDaemonSocket('agentpay-agent', ['transfer'], {
      daemonSocket: socketPath
    }),
    path.resolve(socketPath)
  );

  await closeUnixSocket(server, socketPath);
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('resolveValidatedPassthroughDaemonSocket rejects same-user sockets for agent passthroughs when the wrapper runs as root', async () => {
  if (process.platform === 'win32' || typeof process.getuid !== 'function') {
    return;
  }

  const passthrough = await loadModule(`${Date.now()}-agent-root-wrapper`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-passthrough-'));
  const socketDir = path.join(tempRoot, 'run');
  const socketPath = path.join(socketDir, 'daemon.sock');
  fs.mkdirSync(socketDir, { mode: 0o755 });

  const server = await listenOnUnixSocket(socketPath);
  const originalSudoUid = process.env.SUDO_UID;
  process.env.SUDO_UID = String(process.getuid());

  try {
    assert.throws(
      () =>
        withMockedEuid(0, () =>
          passthrough.resolveValidatedPassthroughDaemonSocket(
            'agentpay-agent',
            ['transfer'],
            { daemonSocket: socketPath }
          )
        ),
      /must be owned by root/
    );
  } finally {
    if (originalSudoUid === undefined) {
      delete process.env.SUDO_UID;
    } else {
      process.env.SUDO_UID = originalSudoUid;
    }
    await closeUnixSocket(server, socketPath);
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('resolveValidatedPassthroughDaemonSocket rejects split daemon socket values that look like flags', async () => {
  const passthrough = await loadModule(`${Date.now()}-flag-like-split-daemon-socket`);

  assert.throws(
    () =>
      passthrough.resolveValidatedPassthroughDaemonSocket(
        'agentpay-agent',
        ['--daemon-socket', '--non-interactive', 'transfer'],
        {},
        {
          env: {},
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /use --daemon-socket=<path> if the path starts with -/,
  );
});
