import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const modulePath = new URL('../src/lib/agent-auth-rotate.ts', import.meta.url);
const configModulePath = new URL('../packages/config/src/index.ts', import.meta.url);

const TEST_AGENT_KEY_ID = '00000000-0000-0000-0000-000000000001';
const TEST_AGENT_AUTH_TOKEN = 'rotated-agent-token';

async function withMockSecurityOnPath(scriptBody, fn) {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-auth-rotate-security-'));
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

test('buildRotateAgentAuthTokenAdminArgs forwards secure admin flags', async () => {
  const rotation = await import(modulePath.href + `?case=${Date.now()}-1`);

  const args = rotation.buildRotateAgentAuthTokenAdminArgs({
    agentKeyId: TEST_AGENT_KEY_ID,
    vaultPasswordStdin: true,
    nonInteractive: true,
    daemonSocket: '/tmp/agentpay.sock',
  });

  assert.deepEqual(args, [
    '--json',
    '--quiet',
    '--vault-password-stdin',
    '--non-interactive',
    '--daemon-socket',
    '/tmp/agentpay.sock',
    'rotate-agent-auth-token',
    '--agent-key-id',
    TEST_AGENT_KEY_ID,
    '--print-agent-auth-token',
  ]);
});

test('buildRotateAgentAuthTokenAdminArgs rejects insecure inline vault passwords', async () => {
  const rotation = await import(modulePath.href + `?case=${Date.now()}-inline-reject`);

  assert.throws(
    () =>
      rotation.buildRotateAgentAuthTokenAdminArgs({
        agentKeyId: TEST_AGENT_KEY_ID,
        vaultPassword: 'vault-secret',
      }),
    /insecure vaultPassword is disabled/,
  );
});

test('completeAgentAuthRotation stores the rotated token and updates config', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-auth-rotate-'));
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  const rotation = await import(modulePath.href + `?case=${Date.now()}-2`);
  const config = await import(configModulePath.href + `?case=${Date.now()}-cfg-2`);

  config.writeConfig({ agentAuthToken: 'legacy-token' });

  let storedCredentials = null;
  const result = rotation.completeAgentAuthRotation(
    {
      agent_key_id: TEST_AGENT_KEY_ID,
      agent_auth_token: TEST_AGENT_AUTH_TOKEN,
      agent_auth_token_redacted: false,
    },
    {
      storeAgentAuthToken: (agentKeyId, token) => {
        storedCredentials = { agentKeyId, token };
      },
    },
  );

  assert.deepEqual(storedCredentials, {
    agentKeyId: TEST_AGENT_KEY_ID,
    token: TEST_AGENT_AUTH_TOKEN,
  });
  assert.equal(result.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(result.keychain.service, 'agentpay-agent-auth-token');

  const updatedConfig = config.readConfig();
  assert.equal(updatedConfig.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(updatedConfig.agentAuthToken, undefined);

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('completeAgentAuthRotation rejects redacted Rust output', async () => {
  const rotation = await import(modulePath.href + `?case=${Date.now()}-3`);

  assert.throws(
    () =>
      rotation.completeAgentAuthRotation({
        agent_key_id: TEST_AGENT_KEY_ID,
        agent_auth_token: '<redacted>',
        agent_auth_token_redacted: true,
      }),
    /returned a redacted agent auth token/,
  );
});

test('completeAgentAuthRotation rejects empty rotated tokens', async () => {
  const rotation = await import(modulePath.href + `?case=${Date.now()}-empty-token`);

  assert.throws(
    () =>
      rotation.completeAgentAuthRotation({
        agent_key_id: TEST_AGENT_KEY_ID,
        agent_auth_token: '   ',
        agent_auth_token_redacted: false,
      }),
    /returned an empty agent auth token/,
  );
});

test('completeAgentAuthRotation uses the default Keychain writer when storeAgentAuthToken is omitted', async () => {
  const rotation = await import(modulePath.href + `?case=${Date.now()}-default-keychain-store`);
  let configState = {
    agentAuthToken: 'legacy-token',
    chains: {},
  };

  await withMockSecurityOnPath('exit 0', async () => {
    const result = rotation.completeAgentAuthRotation(
      {
        agent_key_id: TEST_AGENT_KEY_ID,
        agent_auth_token: TEST_AGENT_AUTH_TOKEN,
        agent_auth_token_redacted: false,
      },
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
  });
});
