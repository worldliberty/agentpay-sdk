import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import test from 'node:test';

const modulePath = new URL('../src/lib/rust-spawn-options.ts', import.meta.url);

test('prepareSpawnOptions accepts pre-supplied agent auth stdin without re-running the relay', async () => {
  const rust = await import(modulePath.href + `?case=${Date.now()}-pre-supplied-agent-auth`);
  const originalAgentEnv = process.env.AGENTPAY_AGENT_AUTH_TOKEN;
  process.env.AGENTPAY_AGENT_AUTH_TOKEN = 'env-secret';

  const prepared = await rust.prepareSpawnOptions(
    'agentpay-agent',
    ['--agent-auth-token-stdin', 'broadcast'],
    {
      stdin: 'agent-secret\n',
      preSuppliedSecretStdin: 'agentAuthToken',
      scrubSensitiveEnv: true,
    },
  );

  assert.deepEqual(prepared.args, ['--agent-auth-token-stdin', 'broadcast']);
  assert.equal(prepared.stdin, 'agent-secret\n');
  assert.equal(prepared.env.AGENTPAY_AGENT_AUTH_TOKEN, undefined);

  if (originalAgentEnv === undefined) {
    delete process.env.AGENTPAY_AGENT_AUTH_TOKEN;
  } else {
    process.env.AGENTPAY_AGENT_AUTH_TOKEN = originalAgentEnv;
  }
});

test('prepareSpawnOptions rejects pre-supplied agent auth stdin when args do not request stdin relay', async () => {
  const rust = await import(modulePath.href + `?case=${Date.now()}-missing-agent-auth-flag`);

  await assert.rejects(
    () =>
      rust.prepareSpawnOptions('agentpay-agent', ['--help'], {
        stdin: 'agent-secret\n',
        preSuppliedSecretStdin: 'agentAuthToken',
        scrubSensitiveEnv: true,
      }),
    /requires --agent-auth-token-stdin in args/,
  );
});

test('prepareSpawnOptions skips vault-password env relay for help invocations and scrubs the child env', async () => {
  const rust = await import(modulePath.href + `?case=${Date.now()}-help-vault-password-env`);
  const originalVaultEnv = process.env.AGENTPAY_VAULT_PASSWORD;
  process.env.AGENTPAY_VAULT_PASSWORD = 'env-secret';

  try {
    const prepared = await rust.prepareSpawnOptions('agentpay-admin', ['--help'], {});
    assert.deepEqual(prepared.args, ['--help']);
    assert.equal(prepared.stdin, undefined);
    assert.equal(prepared.env.AGENTPAY_VAULT_PASSWORD, undefined);
  } finally {
    if (originalVaultEnv === undefined) {
      delete process.env.AGENTPAY_VAULT_PASSWORD;
    } else {
      process.env.AGENTPAY_VAULT_PASSWORD = originalVaultEnv;
    }
  }
});

test('prepareSpawnOptions skips agent-auth env relay for version invocations and scrubs the child env', async () => {
  const rust = await import(modulePath.href + `?case=${Date.now()}-version-agent-auth-env`);
  const originalAgentEnv = process.env.AGENTPAY_AGENT_AUTH_TOKEN;
  process.env.AGENTPAY_AGENT_AUTH_TOKEN = 'env-secret';

  try {
    const prepared = await rust.prepareSpawnOptions('agentpay-agent', ['--version'], {});
    assert.deepEqual(prepared.args, ['--version']);
    assert.equal(prepared.stdin, undefined);
    assert.equal(prepared.env.AGENTPAY_AGENT_AUTH_TOKEN, undefined);
  } finally {
    if (originalAgentEnv === undefined) {
      delete process.env.AGENTPAY_AGENT_AUTH_TOKEN;
    } else {
      process.env.AGENTPAY_AGENT_AUTH_TOKEN = originalAgentEnv;
    }
  }
});

function withEnv(overrides, fn) {
  const saved = new Map();
  for (const [key, value] of Object.entries(overrides)) {
    saved.set(key, process.env[key]);
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      for (const [key, value] of saved) {
        if (value === undefined) {
          delete process.env[key];
        } else {
          process.env[key] = value;
        }
      }
    });
}

test('prepareSpawnOptions builds the child env from an allowlist even when scrubbing is disabled', async () => {
  const rust = await import(modulePath.href + `?case=${Date.now()}-allowlist-env`);

  await withEnv(
    {
      AGENTPAY_VAULT_PASSWORD: 'vault-secret',
      AGENTPAY_AGENT_AUTH_TOKEN: 'agent-secret',
      AGENTPAY_DAEMON_SOCKET: '/tmp/agentpay-test.sock',
      DYLD_INSERT_LIBRARIES: '/tmp/evil.dylib',
      LD_PRELOAD: '/tmp/evil.so',
      NODE_OPTIONS: '--require /tmp/evil.js',
      LC_ALL: 'C.UTF-8',
      XDG_RUNTIME_DIR: '/run/user/501',
      SUDO_UID: '501',
      HTTPS_PROXY: 'http://proxy.test:3128',
      no_proxy: 'localhost',
      RUST_LOG: 'debug',
      SSL_CERT_FILE: '/etc/ssl/cert.pem',
      GITHUB_TOKEN: 'ghp_secret',
      AWS_SECRET_ACCESS_KEY: 'aws-secret',
    },
    async () => {
      const prepared = await rust.prepareSpawnOptions('agentpay-unknown', ['--help'], {
        scrubSensitiveEnv: false,
      });

      assert.equal(prepared.stdin, undefined);
      assert.notStrictEqual(prepared.env, process.env);
      assert.equal(prepared.env.PATH, process.env.PATH);
      assert.equal(prepared.env.HOME, process.env.HOME);
      assert.equal(prepared.env.AGENTPAY_DAEMON_SOCKET, '/tmp/agentpay-test.sock');
      assert.equal(prepared.env.LC_ALL, 'C.UTF-8');
      assert.equal(prepared.env.XDG_RUNTIME_DIR, '/run/user/501');
      assert.equal(prepared.env.SUDO_UID, '501');
      assert.equal(prepared.env.HTTPS_PROXY, 'http://proxy.test:3128');
      assert.equal(prepared.env.no_proxy, 'localhost');
      assert.equal(prepared.env.RUST_LOG, 'debug');
      assert.equal(prepared.env.SSL_CERT_FILE, '/etc/ssl/cert.pem');

      assert.equal(prepared.env.AGENTPAY_VAULT_PASSWORD, undefined);
      assert.equal(prepared.env.AGENTPAY_AGENT_AUTH_TOKEN, undefined);
      assert.equal(prepared.env.DYLD_INSERT_LIBRARIES, undefined);
      assert.equal(prepared.env.LD_PRELOAD, undefined);
      assert.equal(prepared.env.NODE_OPTIONS, undefined);
      assert.equal(prepared.env.GITHUB_TOKEN, undefined);
      assert.equal(prepared.env.AWS_SECRET_ACCESS_KEY, undefined);
    },
  );
});

test('buildAllowlistedChildEnv can exclude every AGENTPAY_* variable for third-party children', async () => {
  const rust = await import(modulePath.href + `?case=${Date.now()}-allowlist-no-agentpay`);
  const source = {
    PATH: '/usr/bin',
    HOME: '/Users/tester',
    TERM: 'xterm-256color',
    TZ: 'UTC',
    AGENTPAY_HOME: '/Users/tester/.agentpay',
    AGENTPAY_TELEMETRY: '0',
    AGENTPAY_VAULT_PASSWORD: 'vault-secret',
    DYLD_LIBRARY_PATH: '/tmp',
    LD_AUDIT: '/tmp/audit.so',
    NODE_OPTIONS: '--inspect',
    UNRELATED: 'value',
    EMPTY: undefined,
  };

  assert.deepEqual(rust.buildAllowlistedChildEnv(source, { includeAgentPayVars: false }), {
    PATH: '/usr/bin',
    HOME: '/Users/tester',
    TERM: 'xterm-256color',
    TZ: 'UTC',
  });
  assert.deepEqual(rust.buildAllowlistedChildEnv(source), {
    PATH: '/usr/bin',
    HOME: '/Users/tester',
    TERM: 'xterm-256color',
    TZ: 'UTC',
    AGENTPAY_HOME: '/Users/tester/.agentpay',
    AGENTPAY_TELEMETRY: '0',
  });
});

test('prepareSpawnOptions refuses to relay AGENTPAY_AGENT_AUTH_TOKEN from the environment', async () => {
  const rust = await import(modulePath.href + `?case=${Date.now()}-env-agent-token-refused`);

  await withEnv({ AGENTPAY_AGENT_AUTH_TOKEN: 'env-secret' }, async () => {
    await assert.rejects(
      () => rust.prepareSpawnOptions('agentpay-agent', ['broadcast'], {}),
      /AGENTPAY_AGENT_AUTH_TOKEN is disabled by default for security/,
    );
  });
});

test('prepareSpawnOptions validates pre-supplied secret stdin invariants', async () => {
  const rust = await import(modulePath.href + `?case=${Date.now()}-pre-supplied-invariants`);

  await assert.rejects(
    () =>
      rust.prepareSpawnOptions('agentpay-admin', ['--vault-password-stdin', 'bootstrap'], {
        preSuppliedSecretStdin: 'vaultPassword',
      }),
    /requires an explicit stdin payload/,
  );

  await assert.rejects(
    () =>
      rust.prepareSpawnOptions('agentpay-admin', ['bootstrap'], {
        stdin: 'vault-secret\n',
        preSuppliedSecretStdin: 'vaultPassword',
      }),
    /requires --vault-password-stdin in args/,
  );
});

test('prepareSpawnOptions rejects relay conflicts with explicit stdin payloads', async () => {
  const rust = await import(modulePath.href + `?case=${Date.now()}-relay-stdin-conflicts`);
  const originalStdinDescriptor = Object.getOwnPropertyDescriptor(process, 'stdin');
  const installMockedStdin = (chunks) => {
    const mockedStdin = Readable.from(chunks);
    mockedStdin.setEncoding('utf8');
    Object.defineProperty(process, 'stdin', {
      value: mockedStdin,
      configurable: true,
    });
  };

  try {
    installMockedStdin(['vault-secret\n']);
    await assert.rejects(
      () =>
        rust.prepareSpawnOptions('agentpay-admin', ['--vault-password-stdin', 'bootstrap'], {
          stdin: 'already-present\n',
        }),
      /vault password relay conflicts with explicit stdin payload/,
    );

    installMockedStdin(['agent-secret\n']);
    await assert.rejects(
      () =>
        rust.prepareSpawnOptions('agentpay-agent', ['--agent-auth-token-stdin', 'broadcast'], {
          stdin: 'already-present\n',
        }),
      /agent auth token relay conflicts with explicit stdin payload/,
    );
  } finally {
    if (originalStdinDescriptor) {
      Object.defineProperty(process, 'stdin', originalStdinDescriptor);
    }
  }
});
