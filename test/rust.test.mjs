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

test('prepareSpawnOptions returns process env directly when scrubbing is disabled', async () => {
  const rust = await import(modulePath.href + `?case=${Date.now()}-no-scrub-env`);

  const prepared = await rust.prepareSpawnOptions('agentpay-unknown', ['--help'], {
    scrubSensitiveEnv: false,
  });

  assert.equal(prepared.stdin, undefined);
  assert.strictEqual(prepared.env, process.env);
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
  const originalAgentEnv = process.env.AGENTPAY_AGENT_AUTH_TOKEN;
  process.env.AGENTPAY_AGENT_AUTH_TOKEN = 'agent-from-env';
  const originalStdinDescriptor = Object.getOwnPropertyDescriptor(process, 'stdin');

  try {
    const mockedStdin = Readable.from(['vault-secret\n']);
    mockedStdin.setEncoding('utf8');
    Object.defineProperty(process, 'stdin', {
      value: mockedStdin,
      configurable: true,
    });

    await assert.rejects(
      () =>
        rust.prepareSpawnOptions('agentpay-admin', ['--vault-password-stdin', 'bootstrap'], {
          stdin: 'already-present\n',
        }),
      /vault password relay conflicts with explicit stdin payload/,
    );

    await assert.rejects(
      () =>
        rust.prepareSpawnOptions('agentpay-agent', ['broadcast'], {
          stdin: 'already-present\n',
        }),
      /agent auth token relay conflicts with explicit stdin payload/,
    );
  } finally {
    if (originalStdinDescriptor) {
      Object.defineProperty(process, 'stdin', originalStdinDescriptor);
    }
    if (originalAgentEnv === undefined) {
      delete process.env.AGENTPAY_AGENT_AUTH_TOKEN;
    } else {
      process.env.AGENTPAY_AGENT_AUTH_TOKEN = originalAgentEnv;
    }
  }
});
