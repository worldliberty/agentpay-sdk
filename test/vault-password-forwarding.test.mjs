import assert from 'node:assert/strict';
import test from 'node:test';

const modulePath = new URL('../src/lib/vault-password-forwarding.ts', import.meta.url);

function loadModule(caseId) {
  return import(modulePath.href + `?case=${caseId}`);
}

async function withMockedProcessStdin(chunks, fn) {
  const originalDescriptor = Object.getOwnPropertyDescriptor(process, 'stdin');
  const mockStdin = {
    isTTY: false,
    setEncoding() {},
    async *[Symbol.asyncIterator]() {
      for (const chunk of chunks) {
        yield chunk;
      }
    },
  };

  Object.defineProperty(process, 'stdin', {
    configurable: true,
    value: mockStdin,
  });

  try {
    await fn();
  } finally {
    if (originalDescriptor) {
      Object.defineProperty(process, 'stdin', originalDescriptor);
    }
  }
}

test('prepareVaultPasswordRelay rejects split argv passwords', async () => {
  const relay = await loadModule(`${Date.now()}-split`);

  await assert.rejects(
    relay.prepareVaultPasswordRelay([
      '--json',
      '--vault-password',
      'vault-secret',
      'rotate-agent-auth-token',
    ]),
    /insecure --vault-password is disabled/,
  );
});

test('prepareVaultPasswordRelay rejects inline argv passwords', async () => {
  const relay = await loadModule(`${Date.now()}-inline`);

  await assert.rejects(
    relay.prepareVaultPasswordRelay(['--json', '--vault-password=vault-secret', 'bootstrap']),
    /insecure --vault-password is disabled/,
  );
});

test('prepareVaultPasswordRelay reads vault passwords from stdin when requested', async () => {
  const relay = await loadModule(`${Date.now()}-stdin`);
  let requestedLabel = null;

  const prepared = await relay.prepareVaultPasswordRelay(['--vault-password-stdin', 'bootstrap'], {
    readFromStdin: async (label) => {
      requestedLabel = label;
      return 'stdin-secret';
    },
  });

  assert.equal(requestedLabel, 'vaultPassword');
  assert.deepEqual(prepared.args, ['--vault-password-stdin', 'bootstrap']);
  assert.equal(prepared.stdin, 'stdin-secret\n');
});

test('prepareVaultPasswordRelay rejects oversized input from the default stdin reader', async () => {
  const relay = await loadModule(`${Date.now()}-default-stdin-oversized`);

  await withMockedProcessStdin(['a'.repeat(16 * 1024 + 1)], async () => {
    await assert.rejects(
      relay.prepareVaultPasswordRelay(['--vault-password-stdin', 'bootstrap']),
      /vaultPassword must not exceed 16384 bytes/,
    );
  });
});

test('prepareVaultPasswordRelay uses the default stdin reader when requested', async () => {
  const relay = await loadModule(`${Date.now()}-default-stdin-success`);

  await withMockedProcessStdin(['vault-secret\n'], async () => {
    const prepared = await relay.prepareVaultPasswordRelay(['--vault-password-stdin', 'bootstrap']);
    assert.deepEqual(prepared.args, ['--vault-password-stdin', 'bootstrap']);
    assert.equal(prepared.stdin, 'vault-secret\n');
    assert.equal(prepared.scrubSensitiveEnv, true);
  });
});

test('prepareVaultPasswordRelay rejects AGENTPAY_VAULT_PASSWORD for non-help invocations', async () => {
  const relay = await loadModule(`${Date.now()}-env`);

  await assert.rejects(
    relay.prepareVaultPasswordRelay(['bootstrap'], {
      env: {
        AGENTPAY_VAULT_PASSWORD: 'env-secret',
      },
    }),
    /AGENTPAY_VAULT_PASSWORD is disabled for security/,
  );
});

test('prepareVaultPasswordRelay rejects conflicting vault password sources', async () => {
  const relay = await loadModule(`${Date.now()}-conflict`);

  await assert.rejects(
    relay.prepareVaultPasswordRelay(['--vault-password', 'secret', '--vault-password-stdin']),
    /--vault-password conflicts with --vault-password-stdin/,
  );
});

test('prepareVaultPasswordRelay rejects duplicate argv vault passwords', async () => {
  const relay = await loadModule(`${Date.now()}-duplicate-inline`);

  await assert.rejects(
    relay.prepareVaultPasswordRelay([
      '--vault-password',
      'secret-one',
      '--vault-password=secret-two',
      'bootstrap',
    ]),
    /--vault-password may only be provided once/,
  );
});

test('prepareVaultPasswordRelay rejects duplicate stdin flags', async () => {
  const relay = await loadModule(`${Date.now()}-duplicate-stdin-flag`);

  await assert.rejects(
    relay.prepareVaultPasswordRelay([
      '--vault-password-stdin',
      '--vault-password-stdin',
      'bootstrap',
    ]),
    /--vault-password-stdin may only be provided once/,
  );
});

test('prepareVaultPasswordRelay rejects oversized inline passwords', async () => {
  const relay = await loadModule(`${Date.now()}-oversized-inline`);

  await assert.rejects(
    relay.prepareVaultPasswordRelay(['--vault-password', 'a'.repeat(16 * 1024 + 1), 'bootstrap']),
    /vaultPassword must not exceed 16384 bytes/,
  );
});

test('prepareVaultPasswordRelay rejects empty environment passwords', async () => {
  const relay = await loadModule(`${Date.now()}-empty-env`);

  await assert.rejects(
    relay.prepareVaultPasswordRelay(['bootstrap'], {
      env: {
        AGENTPAY_VAULT_PASSWORD: '   \n',
      },
    }),
    /vaultPassword is required/,
  );
});

test('prepareVaultPasswordRelay rejects undefined environment passwords when the variable is present', async () => {
  const relay = await loadModule(`${Date.now()}-undefined-env`);

  await assert.rejects(
    relay.prepareVaultPasswordRelay(['bootstrap'], {
      env: {
        AGENTPAY_VAULT_PASSWORD: undefined,
      },
    }),
    /vaultPassword is required/,
  );
});

test('prepareVaultPasswordRelay ignores flags after -- terminator', async () => {
  const relay = await loadModule(`${Date.now()}-terminator`);

  const prepared = await relay.prepareVaultPasswordRelay([
    'bootstrap',
    '--',
    '--vault-password',
    'vault-secret',
  ]);

  assert.deepEqual(prepared.args, ['bootstrap', '--', '--vault-password', 'vault-secret']);
  assert.equal(prepared.stdin, undefined);
});

test('prepareVaultPasswordRelay rejects AGENTPAY_VAULT_PASSWORD when help appears only after --', async () => {
  const relay = await loadModule(`${Date.now()}-env-terminator-help`);

  await assert.rejects(
    relay.prepareVaultPasswordRelay(['bootstrap', '--', '--help'], {
      env: {
        AGENTPAY_VAULT_PASSWORD: 'env-secret',
      },
    }),
    /AGENTPAY_VAULT_PASSWORD is disabled for security/,
  );
});

test('prepareVaultPasswordRelay skips env relay for help and version invocations', async () => {
  const relay = await loadModule(`${Date.now()}-env-help-skip`);

  const helpPrepared = await relay.prepareVaultPasswordRelay(['help'], {
    env: {
      AGENTPAY_VAULT_PASSWORD: 'env-secret',
    },
  });
  assert.deepEqual(helpPrepared.args, ['help']);
  assert.equal(helpPrepared.stdin, undefined);
  assert.equal(helpPrepared.scrubSensitiveEnv, true);

  const versionPrepared = await relay.prepareVaultPasswordRelay(['bootstrap', '--help'], {
    env: {
      AGENTPAY_VAULT_PASSWORD: 'env-secret',
    },
  });
  assert.deepEqual(versionPrepared.args, ['bootstrap', '--help']);
  assert.equal(versionPrepared.stdin, undefined);
  assert.equal(versionPrepared.scrubSensitiveEnv, true);
});

test('prepareVaultPasswordRelay rejects split vault passwords that look like flags', async () => {
  const relay = await loadModule(`${Date.now()}-flag-like-split-password`);

  await assert.rejects(
    relay.prepareVaultPasswordRelay(['--vault-password', '--non-interactive', 'bootstrap']),
    /use --vault-password=<value> if the value starts with -/,
  );
});

test('prepareVaultPasswordRelay rejects inline vault passwords that start with dashes', async () => {
  const relay = await loadModule(`${Date.now()}-flag-like-inline-password`);

  await assert.rejects(
    relay.prepareVaultPasswordRelay(['--vault-password=--still-a-secret', 'bootstrap']),
    /insecure --vault-password is disabled/,
  );
});
