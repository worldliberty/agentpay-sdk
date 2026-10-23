import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const modulePath = new URL('../src/lib/keychain.ts', import.meta.url);
const TEST_AGENT_KEY_ID = '00000000-0000-0000-0000-000000000001';

async function withMockSecurityOnPath(scriptBody, fn) {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-keychain-security-'));
  const securityPath = path.join(tempRoot, 'security');
  const originalPath = process.env.PATH;
  const platformDescriptor = Object.getOwnPropertyDescriptor(process, 'platform');

  fs.writeFileSync(securityPath, `#!/bin/sh\n${scriptBody}\n`, { mode: 0o755 });
  Object.defineProperty(process, 'platform', { value: 'darwin', configurable: true });
  process.env.PATH = `${tempRoot}${path.delimiter}${originalPath ?? ''}`;

  try {
    await fn();
  } finally {
    if (platformDescriptor) {
      Object.defineProperty(process, 'platform', platformDescriptor);
    }
    if (originalPath === undefined) {
      delete process.env.PATH;
    } else {
      process.env.PATH = originalPath;
    }
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

test('readAgentAuthTokenFromKeychain returns null for missing entries', async () => {
  const keychain = await import(`${modulePath.href}?case=${Date.now()}-1`);
  const token = keychain.readAgentAuthTokenFromKeychain(TEST_AGENT_KEY_ID, () => {
    const error = new Error('The specified item could not be found in the keychain.');
    error.status = 44;
    throw error;
  });

  assert.equal(token, null);
});

test('storeAgentAuthTokenInKeychain uses a stable service and keeps the secret off argv', async () => {
  const keychain = await import(`${modulePath.href}?case=${Date.now()}-2`);
  const calls = [];
  keychain.storeAgentAuthTokenInKeychain(TEST_AGENT_KEY_ID, 'secret-token', (command) => {
    calls.push(command);
    return '';
  });

  const secretHex = Buffer.from('secret-token', 'utf8').toString('hex');
  assert.deepEqual(calls, [
    {
      args: ['-i'],
      input: `add-generic-password -U -s "${keychain.AGENT_AUTH_TOKEN_KEYCHAIN_SERVICE}" -a "${TEST_AGENT_KEY_ID}" -X ${secretHex}\n`,
    },
  ]);
  assert.equal(
    calls[0].args.some((arg) => arg.includes(secretHex)),
    false,
  );
});

test('deleteAgentAuthTokenFromKeychain reports false when entry is absent', async () => {
  const keychain = await import(`${modulePath.href}?case=${Date.now()}-3`);
  const removed = keychain.deleteAgentAuthTokenFromKeychain(TEST_AGENT_KEY_ID, () => {
    const error = new Error('item missing');
    error.status = 44;
    throw error;
  });

  assert.equal(removed, false);
});

test('keychain helpers reject agent key ids that are not UUIDs', async () => {
  const keychain = await import(`${modulePath.href}?case=${Date.now()}-4`);

  assert.throws(() => keychain.assertValidAgentKeyId('not-a-uuid'), /valid UUID/);
  assert.throws(
    () => keychain.storeAgentAuthTokenInKeychain('bad\naccount', 'secret-token', () => ''),
    /valid UUID/,
  );
});

test('storeDaemonPasswordInKeychain preserves spaces and rejects control characters', async () => {
  const keychain = await import(`${modulePath.href}?case=${Date.now()}-daemon-account`);
  const calls = [];

  keychain.storeDaemonPasswordInKeychain('Jane Doe', 'vault-secret', (command) => {
    calls.push(command);
    return '';
  });

  assert.deepEqual(calls, [
    {
      args: ['-i'],
      input: `add-generic-password -U -s "${keychain.DAEMON_PASSWORD_KEYCHAIN_SERVICE}" -a "Jane Doe" -X ${Buffer.from('vault-secret', 'utf8').toString('hex')}\n`,
    },
  ]);

  assert.throws(
    () => keychain.storeDaemonPasswordInKeychain('bad\naccount', 'vault-secret', () => ''),
    /keychain account must not contain control characters/,
  );
});

test('storeAgentAuthTokenInKeychain rejects malformed agent auth tokens', async () => {
  const keychain = await import(`${modulePath.href}?case=${Date.now()}-5`);

  assert.throws(
    () => keychain.storeAgentAuthTokenInKeychain(TEST_AGENT_KEY_ID, '   \n', () => ''),
    /agentAuthToken is required/,
  );
  assert.throws(
    () =>
      keychain.storeAgentAuthTokenInKeychain(
        TEST_AGENT_KEY_ID,
        'a'.repeat(16 * 1024 + 1),
        () => '',
      ),
    /agentAuthToken must not exceed 16384 bytes/,
  );
});

test('keychain defaults are no-ops on non-macOS for read/delete and fail closed for writes', async () => {
  const keychain = await import(`${modulePath.href}?case=${Date.now()}-non-darwin-defaults`);
  const platformDescriptor = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { value: 'linux', configurable: true });

  try {
    assert.equal(keychain.readAgentAuthTokenFromKeychain(TEST_AGENT_KEY_ID), null);
    assert.equal(keychain.deleteAgentAuthTokenFromKeychain(TEST_AGENT_KEY_ID), false);
    assert.throws(
      () => keychain.storeDaemonPasswordInKeychain('Jane Doe', 'vault-secret'),
      /available only on macOS/,
    );
  } finally {
    if (platformDescriptor) {
      Object.defineProperty(process, 'platform', platformDescriptor);
    }
  }
});

test('read/delete keychain helpers surface non-missing errors and handle non-Error throws', async () => {
  const keychain = await import(`${modulePath.href}?case=${Date.now()}-error-rendering`);

  assert.throws(
    () =>
      keychain.readAgentAuthTokenFromKeychain(TEST_AGENT_KEY_ID, () => {
        const error = new Error('fallback-message');
        error.stdout = 'from-stdout';
        error.stderr = '';
        throw error;
      }),
    /from-stdout/,
  );

  assert.throws(
    () =>
      keychain.readAgentAuthTokenFromKeychain(TEST_AGENT_KEY_ID, () => {
        throw 'boom';
      }),
    /failed to read agent auth token from Keychain/,
  );

  assert.throws(
    () =>
      keychain.deleteAgentAuthTokenFromKeychain(TEST_AGENT_KEY_ID, () => {
        throw 'boom';
      }),
    /failed to delete agent auth token from Keychain/,
  );

  const missingWithBlankMessage = keychain.readAgentAuthTokenFromKeychain(TEST_AGENT_KEY_ID, () => {
    const error = new Error('');
    error.status = 44;
    throw error;
  });
  assert.equal(missingWithBlankMessage, null);
});

test('storeDaemonPasswordInKeychain validates keychain account and secret fields', async () => {
  const keychain = await import(`${modulePath.href}?case=${Date.now()}-daemon-validation`);

  assert.throws(
    () => keychain.storeDaemonPasswordInKeychain('   ', 'vault-secret', () => ''),
    /keychain account is required/,
  );
  assert.throws(
    () => keychain.storeDaemonPasswordInKeychain('Jane Doe', '   ', () => ''),
    /keychain secret must not be empty or whitespace/,
  );
  assert.throws(
    () => keychain.storeDaemonPasswordInKeychain('Jane Doe', 'a'.repeat(16 * 1024 + 1), () => ''),
    /keychain secret must not exceed 16384 bytes/,
  );
});

test('default security runner surfaces spawn errors when security binary is unavailable', async () => {
  const keychain = await import(`${modulePath.href}?case=${Date.now()}-default-runner-spawn-error`);
  const platformDescriptor = Object.getOwnPropertyDescriptor(process, 'platform');
  const originalPath = process.env.PATH;
  Object.defineProperty(process, 'platform', { value: 'darwin', configurable: true });
  process.env.PATH = '';

  try {
    assert.throws(
      () => keychain.storeDaemonPasswordInKeychain('Jane Doe', 'vault-secret'),
      /ENOENT/,
    );
  } finally {
    if (platformDescriptor) {
      Object.defineProperty(process, 'platform', platformDescriptor);
    }
    process.env.PATH = originalPath;
  }
});

test('default security runner reads trimmed keychain output and powers hasAgentAuthTokenInKeychain', async () => {
  const keychain = await import(`${modulePath.href}?case=${Date.now()}-default-runner-success`);

  await withMockSecurityOnPath(
    [
      'if [ "$1" = "find-generic-password" ]; then',
      '  printf "stored-token\\n"',
      '  exit 0',
      'fi',
      'exit 0',
    ].join('\n'),
    async () => {
      assert.equal(keychain.readAgentAuthTokenFromKeychain(TEST_AGENT_KEY_ID), 'stored-token');
      assert.equal(keychain.hasAgentAuthTokenInKeychain(TEST_AGENT_KEY_ID), true);
    },
  );
});

test('default security runner surfaces non-zero security command output', async () => {
  const keychain = await import(`${modulePath.href}?case=${Date.now()}-default-runner-nonzero`);

  await withMockSecurityOnPath(
    ['printf "security command failed\\n" 1>&2', 'exit 9'].join('\n'),
    async () => {
      assert.throws(
        () => keychain.storeDaemonPasswordInKeychain('Jane Doe', 'vault-secret'),
        /security command failed/,
      );
    },
  );
});

test('default security runner falls back to stdout and generic command messages on failure', async () => {
  const keychain = await import(`${modulePath.href}?case=${Date.now()}-default-runner-fallbacks`);

  await withMockSecurityOnPath(['printf "stdout failure\\n"', 'exit 9'].join('\n'), async () => {
    assert.throws(
      () => keychain.storeDaemonPasswordInKeychain('Jane Doe', 'vault-secret'),
      /stdout failure/,
    );
  });

  await withMockSecurityOnPath('exit 9', async () => {
    assert.throws(
      () => keychain.storeDaemonPasswordInKeychain('Jane Doe', 'vault-secret'),
      /security add-generic-password failed/,
    );
  });
});

test('default security runner maps signaled security exits to shell-style exit codes', async () => {
  const keychain = await import(`${modulePath.href}?case=${Date.now()}-default-runner-signal`);

  await withMockSecurityOnPath('kill -INT $$', async () => {
    assert.throws(
      () => keychain.storeDaemonPasswordInKeychain('Jane Doe', 'vault-secret'),
      (error) => {
        assert.equal(error.status, 130);
        assert.equal(error.signal, 'SIGINT');
        assert.match(error.message, /security add-generic-password exited with code 130/u);
        return true;
      },
    );
  });
});

test('quoteSecurityInteractiveArg escapes quotes and backslashes and rejects control characters', async () => {
  const keychain = await import(`${modulePath.href}?case=${Date.now()}-quote-interactive`);

  assert.equal(keychain.quoteSecurityInteractiveArg('Jane Doe'), '"Jane Doe"');
  assert.equal(keychain.quoteSecurityInteractiveArg('a"b\\c'), '"a\\"b\\\\c"');
  assert.throws(
    () => keychain.quoteSecurityInteractiveArg('line\nbreak'),
    /must not contain control characters/u,
  );
});

test('default security runner feeds add-generic-password through security -i stdin', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-keychain-capture-'));
  const argvCapture = path.join(tempRoot, 'argv.txt');
  const stdinCapture = path.join(tempRoot, 'stdin.txt');
  try {
    await withMockSecurityOnPath(
      `printf '%s\\n' "$@" > '${argvCapture}'\ncat > '${stdinCapture}'\nexit 0`,
      async () => {
        const keychain = await import(`${modulePath.href}?case=${Date.now()}-interactive-stdin`);
        keychain.storeDaemonPasswordInKeychain('Jane Doe', 'vault-secret');
      },
    );
    const secretHex = Buffer.from('vault-secret', 'utf8').toString('hex');
    assert.equal(fs.readFileSync(argvCapture, 'utf8'), '-i\n');
    assert.equal(
      fs.readFileSync(stdinCapture, 'utf8'),
      `add-generic-password -U -s "agentpay-daemon-password" -a "Jane Doe" -X ${secretHex}\n`,
    );
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
