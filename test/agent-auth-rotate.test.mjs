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

  // `security -i` reads its command from stdin; drain it so the write cannot race the exit.
  const securityScript = ['if [ "$1" = "-i" ]; then', '  cat >/dev/null', 'fi', 'exit 0'];

  await withMockSecurityOnPath(securityScript.join('\n'), async () => {
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

const bootstrapModulePath = new URL('../src/lib/bootstrap-credentials.ts', import.meta.url);

test('completeAgentAuthRotation parks the rotated token in a 0600 recovery file when storage fails', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-auth-rotate-recovery-'));
  const originalHome = process.env.AGENTPAY_HOME;
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  try {
    const rotation = await import(modulePath.href + `?case=${Date.now()}-recovery`);
    const config = await import(configModulePath.href + `?case=${Date.now()}-cfg-recovery`);
    const bootstrap = await import(
      bootstrapModulePath.href + `?case=${Date.now()}-bootstrap-recovery`
    );

    config.writeConfig({
      wallet: {
        vaultKeyId: 'vault-key-test',
        vaultPublicKey: '03abcdef',
        algorithm: 'secp256k1',
        policyAttachment: 'policy_set',
        attachedPolicyIds: ['policy-per-tx'],
        policyNote: 'test policy note',
      },
    });

    const recoveryPath = path.join(
      process.env.AGENTPAY_HOME,
      'agent-auth',
      `${TEST_AGENT_KEY_ID}.recovery.json`,
    );

    let thrown = null;
    try {
      rotation.completeAgentAuthRotation(
        {
          agent_key_id: TEST_AGENT_KEY_ID,
          agent_auth_token: TEST_AGENT_AUTH_TOKEN,
          agent_auth_token_redacted: false,
        },
        {
          storeAgentAuthToken: () => {
            throw new Error('keychain is locked');
          },
        },
      );
    } catch (error) {
      thrown = error;
    }

    assert.ok(thrown, 'rotation must fail loudly when the token cannot be stored');
    assert.match(thrown.message, /could not be stored locally: keychain is locked/u);
    assert.match(thrown.message, /previous token is no longer valid/u);
    assert.ok(
      thrown.message.includes(`agentpay config agent-auth import ${recoveryPath}`),
      thrown.message,
    );

    const stats = fs.statSync(recoveryPath);
    assert.equal(stats.mode & 0o777, 0o600);
    assert.deepEqual(
      fs.readdirSync(path.dirname(recoveryPath)).filter((name) => name.endsWith('.tmp')),
      [],
      'temp file must be renamed away',
    );

    const payload = JSON.parse(fs.readFileSync(recoveryPath, 'utf8'));
    assert.equal(payload.agent_key_id, TEST_AGENT_KEY_ID);
    assert.equal(payload.agent_auth_token, TEST_AGENT_AUTH_TOKEN);
    assert.equal(payload.agent_auth_token_redacted, false);
    assert.equal(payload.vault_key_id, 'vault-key-test');
    assert.equal(payload.vault_public_key, '03abcdef');

    // The file is consumable by the same reader `agentpay config agent-auth import` uses.
    const imported = bootstrap.readBootstrapSetupFile(recoveryPath);
    assert.equal(imported.credentials.agentKeyId, TEST_AGENT_KEY_ID);
    assert.equal(imported.credentials.agentAuthToken, TEST_AGENT_AUTH_TOKEN);
    assert.equal(imported.summary.vaultKeyId, 'vault-key-test');
    assert.deepEqual(imported.summary.attachedPolicyIds, ['policy-per-tx']);
    bootstrap.assertBootstrapSetupSummaryLeaseIsActive(imported.summary);

    // Config is left untouched: the rotation did not complete.
    assert.equal(config.readConfig().agentKeyId, undefined);
  } finally {
    if (originalHome === undefined) {
      delete process.env.AGENTPAY_HOME;
    } else {
      process.env.AGENTPAY_HOME = originalHome;
    }
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('completeAgentAuthRotation still writes the credential-only recovery file without wallet metadata', async () => {
  const rotation = await import(modulePath.href + `?case=${Date.now()}-recovery-no-wallet`);
  let written = null;

  assert.throws(
    () =>
      rotation.completeAgentAuthRotation(
        {
          agent_key_id: TEST_AGENT_KEY_ID,
          agent_auth_token: TEST_AGENT_AUTH_TOKEN,
          agent_auth_token_redacted: false,
        },
        {
          readConfig: () => ({}),
          storeAgentAuthToken: () => {
            throw new Error('secret-tool unavailable');
          },
          writeRecoveryFile: (agentKeyId, payload) => {
            written = { agentKeyId, payload };
            return '/tmp/agentpay-test/agent-auth/recovery.json';
          },
        },
      ),
    (error) => {
      assert.match(error.message, /secret-tool unavailable/u);
      assert.match(
        error.message,
        /agentpay config agent-auth import \/tmp\/agentpay-test\/agent-auth\/recovery\.json/u,
      );
      assert.match(
        error.message,
        new RegExp(
          `agent-auth set --agent-key-id ${TEST_AGENT_KEY_ID} --agent-auth-token-stdin`,
          'u',
        ),
      );
      return true;
    },
  );

  assert.equal(written.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(written.payload.agent_auth_token, TEST_AGENT_AUTH_TOKEN);
  assert.equal(written.payload.agent_key_id, TEST_AGENT_KEY_ID);
  assert.equal(written.payload.vault_key_id, undefined);
  assert.ok(Date.parse(written.payload.lease_expires_at) > Date.now());
});
