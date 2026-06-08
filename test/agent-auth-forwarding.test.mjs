import assert from 'node:assert/strict';
import test from 'node:test';

const modulePath = new URL('../src/lib/agent-auth-forwarding.ts', import.meta.url);

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

test('prepareAgentAuthRelay rejects split argv tokens', async () => {
  const relay = await loadModule(`${Date.now()}-split`);

  await assert.rejects(
    relay.prepareAgentAuthRelay([
      '--agent-key-id',
      '00000000-0000-0000-0000-000000000001',
      '--agent-auth-token',
      'agent-secret',
      'transfer',
    ]),
    /--agent-auth-token is disabled for security/,
  );
});

test('prepareAgentAuthRelay rejects inline argv tokens', async () => {
  const relay = await loadModule(`${Date.now()}-inline`);

  await assert.rejects(
    relay.prepareAgentAuthRelay(['--agent-auth-token=agent-secret', 'broadcast']),
    /--agent-auth-token is disabled for security/,
  );
});

test('prepareAgentAuthRelay rejects split argv tokens without a value', async () => {
  const relay = await loadModule(`${Date.now()}-missing-inline-value`);

  await assert.rejects(
    relay.prepareAgentAuthRelay(['--agent-auth-token']),
    /--agent-auth-token requires a value/,
  );
});

test('prepareAgentAuthRelay reads agent auth tokens from stdin when requested', async () => {
  const relay = await loadModule(`${Date.now()}-stdin`);
  let requestedLabel = null;

  const prepared = await relay.prepareAgentAuthRelay(['--agent-auth-token-stdin', 'transfer'], {
    readFromStdin: async (label) => {
      requestedLabel = label;
      return 'stdin-secret';
    },
  });

  assert.equal(requestedLabel, 'agentAuthToken');
  assert.deepEqual(prepared.args, ['--agent-auth-token-stdin', 'transfer']);
  assert.equal(prepared.stdin, 'stdin-secret\n');
});

test('prepareAgentAuthRelay relays AGENTPAY_AGENT_AUTH_TOKEN through stdin and scrubs env', async () => {
  const relay = await loadModule(`${Date.now()}-env`);

  const prepared = await relay.prepareAgentAuthRelay(['transfer'], {
    env: {
      AGENTPAY_AGENT_AUTH_TOKEN: 'env-secret',
    },
  });

  assert.deepEqual(prepared.args, ['--agent-auth-token-stdin', 'transfer']);
  assert.equal(prepared.stdin, 'env-secret\n');
  assert.equal(prepared.scrubSensitiveEnv, true);
});

test('prepareAgentAuthRelay rejects conflicting agent auth sources', async () => {
  const relay = await loadModule(`${Date.now()}-conflict`);

  await assert.rejects(
    relay.prepareAgentAuthRelay(['--agent-auth-token', 'secret', '--agent-auth-token-stdin']),
    /--agent-auth-token conflicts with --agent-auth-token-stdin/,
  );
});

test('prepareAgentAuthRelay rejects duplicate argv agent auth tokens', async () => {
  const relay = await loadModule(`${Date.now()}-duplicate-inline`);

  await assert.rejects(
    relay.prepareAgentAuthRelay([
      '--agent-auth-token',
      'secret-one',
      '--agent-auth-token=secret-two',
      'transfer',
    ]),
    /--agent-auth-token may only be provided once/,
  );
});

test('prepareAgentAuthRelay rejects duplicate stdin flags', async () => {
  const relay = await loadModule(`${Date.now()}-duplicate-stdin-flag`);

  await assert.rejects(
    relay.prepareAgentAuthRelay([
      '--agent-auth-token-stdin',
      '--agent-auth-token-stdin',
      'transfer',
    ]),
    /--agent-auth-token-stdin may only be provided once/,
  );
});

test('prepareAgentAuthRelay rejects oversized stdin tokens', async () => {
  const relay = await loadModule(`${Date.now()}-oversized`);

  await assert.rejects(
    relay.prepareAgentAuthRelay(['--agent-auth-token-stdin'], {
      readFromStdin: async () => 'a'.repeat(16 * 1024 + 1),
    }),
    /agentAuthToken must not exceed 16384 bytes/,
  );
});

test('prepareAgentAuthRelay uses the default stdin reader when requested', async () => {
  const relay = await loadModule(`${Date.now()}-default-stdin-reader`);

  await withMockedProcessStdin(['stdin-secret\n'], async () => {
    const prepared = await relay.prepareAgentAuthRelay(['--agent-auth-token-stdin', 'transfer']);
    assert.deepEqual(prepared.args, ['--agent-auth-token-stdin', 'transfer']);
    assert.equal(prepared.stdin, 'stdin-secret\n');
    assert.equal(prepared.scrubSensitiveEnv, true);
  });
});

test('prepareAgentAuthRelay rejects oversized input from the default stdin reader', async () => {
  const relay = await loadModule(`${Date.now()}-default-stdin-reader-oversized`);

  await withMockedProcessStdin(['a'.repeat(16 * 1024 + 1)], async () => {
    await assert.rejects(
      relay.prepareAgentAuthRelay(['--agent-auth-token-stdin', 'transfer']),
      /agentAuthToken must not exceed 16384 bytes/,
    );
  });
});

test('prepareAgentAuthRelay ignores flags after -- terminator', async () => {
  const relay = await loadModule(`${Date.now()}-terminator`);

  const prepared = await relay.prepareAgentAuthRelay([
    'transfer',
    '--',
    '--agent-auth-token',
    'agent-secret',
  ]);

  assert.deepEqual(prepared.args, ['transfer', '--', '--agent-auth-token', 'agent-secret']);
  assert.equal(prepared.stdin, undefined);
});

test('prepareAgentAuthRelay still relays env secrets when help flags appear after --', async () => {
  const relay = await loadModule(`${Date.now()}-env-terminator-help`);

  const prepared = await relay.prepareAgentAuthRelay(['transfer', '--', '--help'], {
    env: {
      AGENTPAY_AGENT_AUTH_TOKEN: 'env-secret',
    },
  });

  assert.deepEqual(prepared.args, ['--agent-auth-token-stdin', 'transfer', '--', '--help']);
  assert.equal(prepared.stdin, 'env-secret\n');
});

test('prepareAgentAuthRelay skips env relay for direct help and version invocations', async () => {
  const relay = await loadModule(`${Date.now()}-env-help-skip`);

  const helpPrepared = await relay.prepareAgentAuthRelay(['help'], {
    env: {
      AGENTPAY_AGENT_AUTH_TOKEN: 'env-secret',
    },
  });
  assert.deepEqual(helpPrepared.args, ['help']);
  assert.equal(helpPrepared.stdin, undefined);
  assert.equal(helpPrepared.scrubSensitiveEnv, true);

  const versionPrepared = await relay.prepareAgentAuthRelay(['transfer', '--help'], {
    env: {
      AGENTPAY_AGENT_AUTH_TOKEN: 'env-secret',
    },
  });
  assert.deepEqual(versionPrepared.args, ['transfer', '--help']);
  assert.equal(versionPrepared.stdin, undefined);
  assert.equal(versionPrepared.scrubSensitiveEnv, true);
});

test('prepareAgentAuthRelay rejects blank env tokens when the variable is present but unset', async () => {
  const relay = await loadModule(`${Date.now()}-env-undefined`);

  await assert.rejects(
    relay.prepareAgentAuthRelay(['transfer'], {
      env: {
        AGENTPAY_AGENT_AUTH_TOKEN: undefined,
      },
    }),
    /agentAuthToken is required/,
  );
});
