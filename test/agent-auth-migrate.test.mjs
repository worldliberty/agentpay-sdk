import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const modulePath = new URL('../src/lib/agent-auth-migrate.ts', import.meta.url);
const configModulePath = new URL('../packages/config/src/index.ts', import.meta.url);

const TEST_AGENT_KEY_ID = '00000000-0000-0000-0000-000000000001';

async function withMockSecurityOnPath(scriptBody, fn) {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-auth-migrate-security-'));
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

test('migrateLegacyAgentAuthToken stores the legacy config secret in Keychain and scrubs config.json', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-auth-migrate-'));
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  const migrate = await import(modulePath.href + `?case=${Date.now()}-1`);
  const config = await import(configModulePath.href + `?case=${Date.now()}-cfg-1`);

  config.writeConfig({
    agentKeyId: TEST_AGENT_KEY_ID,
    agentAuthToken: 'legacy-token'
  });

  let storedCredentials = null;
  const result = migrate.migrateLegacyAgentAuthToken(
    {},
    {
      platform: 'darwin',
      storeAgentAuthToken: (agentKeyId, token) => {
        storedCredentials = { agentKeyId, token };
      },
      readAgentAuthToken: () => null
    }
  );

  assert.deepEqual(storedCredentials, {
    agentKeyId: TEST_AGENT_KEY_ID,
    token: 'legacy-token'
  });
  assert.equal(result.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(result.source, 'config');
  assert.equal(result.keychain.stored, true);
  assert.equal(result.keychain.overwritten, false);
  assert.equal(result.keychain.alreadyPresent, false);
  assert.equal(result.keychain.matchedExisting, false);

  const updatedConfig = config.readConfig();
  assert.equal(updatedConfig.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(updatedConfig.agentAuthToken, undefined);

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('migrateLegacyAgentAuthToken refuses to overwrite a different existing Keychain secret by default', async () => {
  const migrate = await import(modulePath.href + `?case=${Date.now()}-2`);

  assert.throws(
    () =>
      migrate.migrateLegacyAgentAuthToken(
        {},
        {
          platform: 'darwin',
          readConfig: () => ({
            agentKeyId: TEST_AGENT_KEY_ID,
            agentAuthToken: 'legacy-token'
          }),
          readAgentAuthToken: () => 'newer-keychain-token',
          storeAgentAuthToken: () => {
            throw new Error('storeAgentAuthToken should not be called');
          }
        }
      ),
    /already contains a different agent auth token/
  );
});

test('migrateLegacyAgentAuthToken can explicitly overwrite a different Keychain secret', async () => {
  const migrate = await import(modulePath.href + `?case=${Date.now()}-3`);

  let storedCredentials = null;
  let configState = {
    agentKeyId: TEST_AGENT_KEY_ID,
    agentAuthToken: 'legacy-token',
    chains: {}
  };

  const result = migrate.migrateLegacyAgentAuthToken(
    {
      overwriteKeychain: true
    },
    {
      platform: 'darwin',
      readConfig: () => configState,
      writeConfig: (nextConfig) => {
        configState = { ...configState, ...nextConfig };
        return configState;
      },
      deleteConfigKey: (key) => {
        const nextConfig = { ...configState };
        delete nextConfig[key];
        configState = nextConfig;
        return configState;
      },
      readAgentAuthToken: () => 'different-keychain-token',
      storeAgentAuthToken: (agentKeyId, token) => {
        storedCredentials = { agentKeyId, token };
      }
    }
  );

  assert.deepEqual(storedCredentials, {
    agentKeyId: TEST_AGENT_KEY_ID,
    token: 'legacy-token'
  });
  assert.equal(result.keychain.stored, true);
  assert.equal(result.keychain.overwritten, true);
  assert.equal(result.keychain.alreadyPresent, true);
  assert.equal(result.keychain.matchedExisting, false);
  assert.equal(configState.agentAuthToken, undefined);
});

test('migrateLegacyAgentAuthToken allows an explicit agent key id when config.json only contains the legacy token', async () => {
  const migrate = await import(modulePath.href + `?case=${Date.now()}-4`);

  let configState = {
    agentAuthToken: 'legacy-token',
    chains: {}
  };

  const result = migrate.migrateLegacyAgentAuthToken(
    {
      agentKeyId: TEST_AGENT_KEY_ID
    },
    {
      platform: 'darwin',
      readConfig: () => configState,
      writeConfig: (nextConfig) => {
        configState = { ...configState, ...nextConfig };
        return configState;
      },
      deleteConfigKey: (key) => {
        const nextConfig = { ...configState };
        delete nextConfig[key];
        configState = nextConfig;
        return configState;
      },
      readAgentAuthToken: () => null,
      storeAgentAuthToken: () => {}
    }
  );

  assert.equal(result.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(configState.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(configState.agentAuthToken, undefined);
});

test('migrateLegacyAgentAuthToken supports Linux Secret Service-backed migration', async () => {
  const migrate = await import(modulePath.href + `?case=${Date.now()}-5`);
  let configState = {
    agentKeyId: TEST_AGENT_KEY_ID,
    agentAuthToken: 'legacy-token',
    chains: {},
  };
  let storedCredentials = null;

  const result = migrate.migrateLegacyAgentAuthToken(
    {},
    {
      platform: 'linux',
      readConfig: () => configState,
      writeConfig: (nextConfig) => {
        configState = { ...configState, ...nextConfig };
        return configState;
      },
      deleteConfigKey: (key) => {
        const nextConfig = { ...configState };
        delete nextConfig[key];
        configState = nextConfig;
        return configState;
      },
      readAgentAuthToken: () => null,
      storeAgentAuthToken: (agentKeyId, token) => {
        storedCredentials = { agentKeyId, token };
      },
    },
  );

  assert.deepEqual(storedCredentials, {
    agentKeyId: TEST_AGENT_KEY_ID,
    token: 'legacy-token',
  });
  assert.equal(result.keychain.service, 'agentpay-agent-auth-token');
  assert.equal(result.keychain.stored, true);
  assert.equal(configState.agentAuthToken, undefined);
});

test('migrateLegacyAgentAuthToken validates configured agentKeyId and explicit overrides', async () => {
  const migrate = await import(modulePath.href + `?case=${Date.now()}-configured-agent-key-validation`);

  assert.throws(
    () =>
      migrate.migrateLegacyAgentAuthToken(
        {},
        {
          platform: 'darwin',
          readConfig: () => ({
            agentKeyId: 'not-a-uuid',
            agentAuthToken: 'legacy-token',
            chains: {},
          }),
          readAgentAuthToken: () => null,
          storeAgentAuthToken: () => {},
        },
      ),
    /pass --agent-key-id to migrate the legacy config secret explicitly/,
  );

  let state = {
    agentKeyId: 'not-a-uuid',
    agentAuthToken: 'legacy-token',
    chains: {},
  };

  const explicitResult = migrate.migrateLegacyAgentAuthToken(
    {
      agentKeyId: TEST_AGENT_KEY_ID,
    },
    {
      platform: 'darwin',
      readConfig: () => state,
      writeConfig: (next) => {
        state = { ...state, ...next };
        return state;
      },
      deleteConfigKey: (key) => {
        const next = { ...state };
        delete next[key];
        state = next;
        return state;
      },
      readAgentAuthToken: () => null,
      storeAgentAuthToken: () => {},
    },
  );

  assert.equal(explicitResult.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(state.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(state.agentAuthToken, undefined);
});

test('migrateLegacyAgentAuthToken rejects mismatched explicit ids and missing migration inputs', async () => {
  const migrate = await import(modulePath.href + `?case=${Date.now()}-mismatch-and-missing`);

  assert.throws(
    () =>
      migrate.migrateLegacyAgentAuthToken(
        {
          agentKeyId: '00000000-0000-0000-0000-000000000099',
        },
        {
          platform: 'darwin',
          readConfig: () => ({
            agentKeyId: TEST_AGENT_KEY_ID,
            agentAuthToken: 'legacy-token',
            chains: {},
          }),
          readAgentAuthToken: () => null,
          storeAgentAuthToken: () => {},
        },
      ),
    /does not match the configured agentKeyId/,
  );

  assert.throws(
    () =>
      migrate.migrateLegacyAgentAuthToken(
        {},
        {
          platform: 'darwin',
          readConfig: () => ({
            chains: {},
            agentAuthToken: 'legacy-token',
          }),
          readAgentAuthToken: () => null,
          storeAgentAuthToken: () => {},
        },
      ),
    /agentKeyId is required/,
  );

  assert.throws(
    () =>
      migrate.migrateLegacyAgentAuthToken(
        {},
        {
          platform: 'darwin',
          readConfig: () => ({
            agentKeyId: TEST_AGENT_KEY_ID,
            agentAuthToken: '   ',
            chains: {},
          }),
          readAgentAuthToken: () => null,
          storeAgentAuthToken: () => {},
        },
      ),
    /does not contain a legacy agentAuthToken/,
  );
});

test('migrateLegacyAgentAuthToken recognizes matching existing keychain values', async () => {
  const migrate = await import(modulePath.href + `?case=${Date.now()}-matched-existing`);

  let storeCalled = false;
  const result = migrate.migrateLegacyAgentAuthToken(
    {},
    {
      platform: 'darwin',
      readConfig: () => ({
        agentKeyId: TEST_AGENT_KEY_ID,
        agentAuthToken: 'legacy-token',
        chains: {},
      }),
      readAgentAuthToken: () => 'legacy-token',
      storeAgentAuthToken: () => {
        storeCalled = true;
      },
      deleteConfigKey: () => ({
        agentKeyId: TEST_AGENT_KEY_ID,
        chains: {},
      }),
    },
  );

  assert.equal(storeCalled, false);
  assert.equal(result.keychain.alreadyPresent, true);
  assert.equal(result.keychain.matchedExisting, true);
  assert.equal(result.keychain.stored, false);
});

test('migrateLegacyAgentAuthToken rejects non-string legacy config tokens as missing', async () => {
  const migrate = await import(modulePath.href + `?case=${Date.now()}-non-string-legacy-token`);

  assert.throws(
    () =>
      migrate.migrateLegacyAgentAuthToken(
        {},
        {
          platform: 'darwin',
          readConfig: () => ({
            agentKeyId: TEST_AGENT_KEY_ID,
            agentAuthToken: 12345,
            chains: {},
          }),
          readAgentAuthToken: () => null,
          storeAgentAuthToken: () => {},
        },
      ),
    /config\.json does not contain a legacy agentAuthToken to migrate/,
  );
});

test('migrateLegacyAgentAuthToken uses the default platform and Keychain runners when they are omitted', async () => {
  const migrate = await import(modulePath.href + `?case=${Date.now()}-default-keychain-runners`);
  let configState = {
    agentKeyId: TEST_AGENT_KEY_ID,
    agentAuthToken: 'legacy-token',
    chains: {},
  };

  await withMockSecurityOnPath(
    [
      'if [ "$1" = "find-generic-password" ]; then',
      '  echo "The specified item could not be found in the keychain." 1>&2',
      '  exit 44',
      'fi',
      'exit 0',
    ].join('\n'),
    async () => {
      const result = migrate.migrateLegacyAgentAuthToken(
        {},
        {
          readConfig: () => configState,
          writeConfig: (next) => {
            configState = { ...configState, ...next };
            return configState;
          },
          deleteConfigKey: (key) => {
            const next = { ...configState };
            delete next[key];
            configState = next;
            return configState;
          },
        },
      );

      assert.equal(result.agentKeyId, TEST_AGENT_KEY_ID);
      assert.equal(result.keychain.stored, true);
      assert.equal(configState.agentAuthToken, undefined);
    },
  );
});
