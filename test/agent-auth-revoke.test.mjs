import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const modulePath = new URL('../src/lib/agent-auth-revoke.ts', import.meta.url);
const configModulePath = new URL('../packages/config/src/index.ts', import.meta.url);

const TEST_AGENT_KEY_ID = '00000000-0000-0000-0000-000000000001';
const OTHER_AGENT_KEY_ID = '00000000-0000-0000-0000-000000000002';

test('buildRevokeAgentKeyAdminArgs forwards secure admin flags', async () => {
  const revoke = await import(modulePath.href + `?case=${Date.now()}-1`);

  const args = revoke.buildRevokeAgentKeyAdminArgs({
    agentKeyId: TEST_AGENT_KEY_ID,
    vaultPasswordStdin: true,
    nonInteractive: true,
    daemonSocket: '/tmp/agentpay.sock'
  });

  assert.deepEqual(args, [
    '--json',
    '--quiet',
    '--vault-password-stdin',
    '--non-interactive',
    '--daemon-socket',
    '/tmp/agentpay.sock',
    'revoke-agent-key',
    '--agent-key-id',
    TEST_AGENT_KEY_ID
  ]);
});

test('buildRevokeAgentKeyAdminArgs rejects insecure inline vault passwords', async () => {
  const revoke = await import(modulePath.href + `?case=${Date.now()}-inline-reject`);

  assert.throws(
    () =>
      revoke.buildRevokeAgentKeyAdminArgs({
        agentKeyId: TEST_AGENT_KEY_ID,
        vaultPassword: 'vault-secret'
      }),
    /insecure vaultPassword is disabled/
  );
});

test('completeAgentKeyRevocation removes local credentials for the configured agent', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-auth-revoke-'));
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  const revoke = await import(modulePath.href + `?case=${Date.now()}-2`);
  const config = await import(configModulePath.href + `?case=${Date.now()}-cfg-2`);

  config.writeConfig({
    agentKeyId: TEST_AGENT_KEY_ID,
    agentAuthToken: 'legacy-token'
  });

  let removedAgentKeyId = null;
  const result = revoke.completeAgentKeyRevocation(
    {
      agent_key_id: TEST_AGENT_KEY_ID,
      revoked: true
    },
    {
      platform: 'darwin',
      deleteAgentAuthToken: (agentKeyId) => {
        removedAgentKeyId = agentKeyId;
        return true;
      }
    }
  );

  assert.equal(removedAgentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(result.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(result.revoked, true);
  assert.equal(result.keychain.removed, true);
  assert.equal(result.keychain.service, 'agentpay-agent-auth-token');

  const updatedConfig = config.readConfig();
  assert.equal(updatedConfig.agentKeyId, undefined);
  assert.equal(updatedConfig.agentAuthToken, undefined);

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('completeAgentKeyRevocation leaves unrelated configured agent metadata intact', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-auth-revoke-'));
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  const revoke = await import(modulePath.href + `?case=${Date.now()}-3`);
  const config = await import(configModulePath.href + `?case=${Date.now()}-cfg-3`);

  config.writeConfig({
    agentKeyId: OTHER_AGENT_KEY_ID,
    agentAuthToken: 'legacy-token'
  });

  const result = revoke.completeAgentKeyRevocation(
    {
      agent_key_id: TEST_AGENT_KEY_ID,
      revoked: true
    },
    {
      platform: 'darwin',
      deleteAgentAuthToken: () => false
    }
  );

  assert.equal(result.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(result.keychain.removed, false);

  const updatedConfig = config.readConfig();
  assert.equal(updatedConfig.agentKeyId, OTHER_AGENT_KEY_ID);
  assert.equal(updatedConfig.agentAuthToken, 'legacy-token');

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('completeAgentKeyRevocation rejects unconfirmed Rust output', async () => {
  const revoke = await import(modulePath.href + `?case=${Date.now()}-4`);

  assert.throws(
    () => revoke.completeAgentKeyRevocation({
      agent_key_id: TEST_AGENT_KEY_ID,
      revoked: false
    }),
    /did not confirm revocation/
  );
});

test('completeAgentKeyRevocation reports the local credential service on Linux', async () => {
  const revoke = await import(modulePath.href + `?case=${Date.now()}-linux-service-null`);
  let configState = {
    agentKeyId: TEST_AGENT_KEY_ID,
    chains: {},
  };

  const result = revoke.completeAgentKeyRevocation(
    {
      agent_key_id: TEST_AGENT_KEY_ID,
      revoked: true,
    },
    {
      platform: 'linux',
      deleteAgentAuthToken: () => false,
      readConfig: () => ({ ...configState }),
      writeConfig: (nextConfig) => {
        configState = { ...configState, ...nextConfig };
        return { ...configState };
      },
      deleteConfigKey: (key) => {
        const next = { ...configState };
        delete next[key];
        configState = next;
        return { ...configState };
      },
    },
  );

  assert.equal(result.keychain.removed, false);
  assert.equal(result.keychain.service, 'agentpay-agent-auth-token');
});
