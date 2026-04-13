import test from 'node:test';
import assert from 'node:assert/strict';

const modulePath = new URL('../src/lib/agent-auth-clear.ts', import.meta.url);

const TEST_AGENT_KEY_ID = '00000000-0000-0000-0000-000000000001';
const OTHER_AGENT_KEY_ID = '00000000-0000-0000-0000-000000000002';

test('clearAgentAuthToken removes matching configured agentKeyId and legacy config token', async () => {
  const clear = await import(modulePath.href + `?case=${Date.now()}-matching`);
  let configState = {
    agentKeyId: TEST_AGENT_KEY_ID,
    agentAuthToken: 'legacy-config-token',
    daemonSocket: '/trusted/run/daemon.sock',
    stateFile: '/trusted/state.enc',
    rustBinDir: '/trusted/bin',
    chains: {}
  };
  const clearedKeys = [];

  const result = clear.clearAgentAuthToken(TEST_AGENT_KEY_ID, {
    platform: 'darwin',
    deleteAgentAuthToken: (agentKeyId) => {
      assert.equal(agentKeyId, TEST_AGENT_KEY_ID);
      return true;
    },
    readConfig: () => ({ ...configState }),
    deleteConfigKey: (key) => {
      clearedKeys.push(key);
      const next = { ...configState };
      delete next[key];
      configState = next;
      return { ...configState };
    }
  });

  assert.equal(result.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(result.keychain.removed, true);
  assert.equal(result.keychain.service, 'agentpay-agent-auth-token');
  assert.deepEqual(clearedKeys, ['agentKeyId', 'agentAuthToken']);
  assert.equal(result.config.agentKeyId, undefined);
  assert.equal(result.config.agentAuthToken, undefined);
});

test('clearAgentAuthToken preserves other configured agentKeyIds but still scrubs legacy config tokens', async () => {
  const clear = await import(modulePath.href + `?case=${Date.now()}-different-key`);
  let configState = {
    agentKeyId: OTHER_AGENT_KEY_ID,
    agentAuthToken: 'legacy-config-token',
    daemonSocket: '/trusted/run/daemon.sock',
    stateFile: '/trusted/state.enc',
    rustBinDir: '/trusted/bin',
    chains: {}
  };
  const clearedKeys = [];

  const result = clear.clearAgentAuthToken(TEST_AGENT_KEY_ID, {
    platform: 'darwin',
    deleteAgentAuthToken: () => false,
    readConfig: () => ({ ...configState }),
    deleteConfigKey: (key) => {
      clearedKeys.push(key);
      const next = { ...configState };
      delete next[key];
      configState = next;
      return { ...configState };
    }
  });

  assert.equal(result.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(result.keychain.removed, false);
  assert.deepEqual(clearedKeys, ['agentAuthToken']);
  assert.equal(result.config.agentKeyId, OTHER_AGENT_KEY_ID);
  assert.equal(result.config.agentAuthToken, undefined);
});

test('clearAgentAuthToken reports the local credential service on Linux', async () => {
  const clear = await import(modulePath.href + `?case=${Date.now()}-linux-service-null`);
  let configState = {
    agentKeyId: TEST_AGENT_KEY_ID,
    daemonSocket: '/trusted/run/daemon.sock',
    stateFile: '/trusted/state.enc',
    rustBinDir: '/trusted/bin',
    chains: {},
  };

  const result = clear.clearAgentAuthToken(TEST_AGENT_KEY_ID, {
    platform: 'linux',
    deleteAgentAuthToken: () => true,
    readConfig: () => ({ ...configState }),
    deleteConfigKey: (key) => {
      const next = { ...configState };
      delete next[key];
      configState = next;
      return { ...configState };
    },
  });

  assert.equal(result.keychain.removed, true);
  assert.equal(result.keychain.service, 'agentpay-agent-auth-token');
});
