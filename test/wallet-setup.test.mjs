import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const walletSetupModulePath = new URL('../src/lib/wallet-setup.ts', import.meta.url);
const configModulePath = new URL('../packages/config/src/index.ts', import.meta.url);

const TEST_AGENT_KEY_ID = '00000000-0000-0000-0000-000000000001';
const TEST_AGENT_AUTH_TOKEN = 'secret-agent-token';
const TEST_VAULT_PRIVATE_KEY = '11'.repeat(32);

function writePrivateJsonFile(targetPath, payload) {
  fs.mkdirSync(path.dirname(targetPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(targetPath, JSON.stringify(payload, null, 2) + '\n', {
    encoding: 'utf8',
    mode: 0o600,
  });
  fs.chmodSync(targetPath, 0o600);
}

function withMockedFs(overrides, fn) {
  const originals = new Map();
  for (const [key, value] of Object.entries(overrides)) {
    originals.set(key, fs[key]);
    fs[key] = value;
  }

  try {
    return fn();
  } finally {
    for (const [key, value] of originals.entries()) {
      fs[key] = value;
    }
  }
}

function mockStats({
  uid = 0,
  mode = 0o700,
  directory = false,
  file = false,
  symlink = false,
} = {}) {
  return {
    uid,
    mode,
    isDirectory: () => directory,
    isFile: () => file,
    isSocket: () => false,
    isSymbolicLink: () => symlink,
  };
}

function bootstrapPayload(overrides = {}) {
  const payload = {
    state_file: 'daemon_socket:/tmp/agentpay.sock',
    lease_id: 'lease-123',
    lease_expires_at: '2099-01-01T00:00:00Z',
    per_tx_policy_id: 'policy-per-tx',
    daily_policy_id: 'policy-daily',
    weekly_policy_id: 'policy-weekly',
    gas_policy_id: 'policy-gas',
    per_tx_max_wei: '1000000000000000000',
    daily_max_wei: '5000000000000000000',
    weekly_max_wei: '20000000000000000000',
    max_gas_per_chain_wei: '1000000000000000',
    daily_max_tx_count: undefined,
    daily_tx_count_policy_id: undefined,
    per_tx_max_fee_per_gas_wei: undefined,
    per_tx_max_fee_per_gas_policy_id: undefined,
    per_tx_max_priority_fee_per_gas_wei: undefined,
    per_tx_max_priority_fee_per_gas_policy_id: undefined,
    per_tx_max_calldata_bytes: undefined,
    per_tx_max_calldata_bytes_policy_id: undefined,
    vault_key_id: 'vault-key-123',
    vault_public_key: '03abcdef',
    vault_private_key: TEST_VAULT_PRIVATE_KEY,
    agent_key_id: TEST_AGENT_KEY_ID,
    agent_auth_token: TEST_AGENT_AUTH_TOKEN,
    agent_auth_token_redacted: false,
    network_scope: 'all networks',
    asset_scope: 'all assets',
    recipient_scope: 'all recipients',
    policy_attachment: 'policy_set',
    attached_policy_ids: undefined,
    policy_note: 'bootstrap note',
    ...overrides,
  };

  if (!('attached_policy_ids' in overrides)) {
    payload.attached_policy_ids = [
      payload.per_tx_policy_id,
      payload.daily_policy_id,
      payload.weekly_policy_id,
      payload.gas_policy_id,
      payload.daily_tx_count_policy_id,
      payload.per_tx_max_fee_per_gas_policy_id,
      payload.per_tx_max_priority_fee_per_gas_policy_id,
      payload.per_tx_max_calldata_bytes_policy_id,
    ].filter((value) => typeof value === 'string');
  }

  return payload;
}

test('buildWalletSetupAdminArgs adds secure bootstrap flags and forwarded options', async () => {
  const walletSetup = await import(walletSetupModulePath.href + `?case=${Date.now()}-1`);

  const args = walletSetup.buildWalletSetupAdminArgs({
    vaultPasswordStdin: true,
    daemonSocket: '/tmp/agentpay.sock',
    perTxMaxWei: '1',
    network: '1',
    token: ['0x0000000000000000000000000000000000000001'],
    allowNativeEth: true,
    attachPolicyId: ['00000000-0000-0000-0000-000000000002'],
    attachBootstrapPolicies: true,
    bootstrapOutputPath: '/tmp/bootstrap.json',
  });

  assert.deepEqual(args, [
    '--json',
    '--quiet',
    '--output',
    '/tmp/bootstrap.json',
    '--vault-password-stdin',
    '--daemon-socket',
    '/tmp/agentpay.sock',
    'bootstrap',
    '--print-agent-auth-token',
    '--per-tx-max-wei',
    '1',
    '--network',
    '1',
    '--token',
    '0x0000000000000000000000000000000000000001',
    '--allow-native-eth',
    '--attach-policy-id',
    '00000000-0000-0000-0000-000000000002',
    '--attach-bootstrap-policies',
  ]);
});

test('buildWalletSetupAdminArgs forwards existing wallet reuse metadata', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-reuse-existing-wallet`
  );

  const args = walletSetup.buildWalletSetupAdminArgs({
    bootstrapOutputPath: '/tmp/bootstrap.json',
    fromSharedConfig: true,
    existingVaultKeyId: '00000000-0000-0000-0000-000000000003',
    existingVaultPublicKey: '03abcdef',
  });

  assert.deepEqual(args, [
    '--json',
    '--quiet',
    '--output',
    '/tmp/bootstrap.json',
    'bootstrap',
    '--print-agent-auth-token',
    '--from-shared-config',
    '--existing-vault-key-id',
    '00000000-0000-0000-0000-000000000003',
    '--existing-vault-public-key',
    '03abcdef',
  ]);
});

test('buildWalletSetupAdminArgs forwards wallet restore import file', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-import-wallet-private-key-file`
  );

  const args = walletSetup.buildWalletSetupAdminArgs({
    bootstrapOutputPath: '/tmp/bootstrap.json',
    importVaultPrivateKeyFile: '/tmp/restored-wallet.key',
  });

  assert.deepEqual(args, [
    '--json',
    '--quiet',
    '--output',
    '/tmp/bootstrap.json',
    'bootstrap',
    '--print-agent-auth-token',
    '--from-shared-config',
    '--import-vault-private-key-file',
    '/tmp/restored-wallet.key',
  ]);
});

test('buildWalletSetupAdminArgs rejects partial existing wallet reuse metadata', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-reuse-existing-wallet-partial`
  );

  assert.throws(
    () =>
      walletSetup.buildWalletSetupAdminArgs({
        bootstrapOutputPath: '/tmp/bootstrap.json',
        existingVaultKeyId: '00000000-0000-0000-0000-000000000003',
      }),
    /must be provided together to reuse an existing wallet/,
  );
});

test('buildWalletSetupAdminArgs rejects conflicting wallet reuse and import metadata', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-reuse-existing-wallet-import-conflict`
  );

  assert.throws(
    () =>
      walletSetup.buildWalletSetupAdminArgs({
        bootstrapOutputPath: '/tmp/bootstrap.json',
        existingVaultKeyId: '00000000-0000-0000-0000-000000000003',
        existingVaultPublicKey: '03abcdef',
        importVaultPrivateKeyFile: '/tmp/restored-wallet.key',
      }),
    /importVaultPrivateKeyFile conflicts with existingVaultKeyId/,
  );
});

test('buildWalletSetupAdminArgs rejects insecure inline vault passwords', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-inline-reject`
  );

  assert.throws(
    () =>
      walletSetup.buildWalletSetupAdminArgs({
        vaultPassword: 'vault-secret',
        bootstrapOutputPath: '/tmp/bootstrap.json',
      }),
    /insecure vaultPassword is disabled/,
  );
});

test('buildWalletSetupAdminArgs loads saved per-token config by default', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-shared-config-default`
  );

  const args = walletSetup.buildWalletSetupAdminArgs({
    daemonSocket: '/tmp/agentpay.sock',
    bootstrapOutputPath: '/tmp/bootstrap.json',
  });

  assert.deepEqual(args, [
    '--json',
    '--quiet',
    '--output',
    '/tmp/bootstrap.json',
    '--daemon-socket',
    '/tmp/agentpay.sock',
    'bootstrap',
    '--print-agent-auth-token',
    '--from-shared-config',
  ]);
});

test('wallet setup helpers canonicalize duplicate token and policy inputs', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-dedupe-inputs`
  );
  const args = walletSetup.buildWalletSetupAdminArgs({
    bootstrapOutputPath: '/tmp/bootstrap.json',
    token: [
      '0x0000000000000000000000000000000000000001',
      '0x0000000000000000000000000000000000000001',
    ],
    attachPolicyId: [
      '00000000-0000-0000-0000-000000000002',
      '00000000-0000-0000-0000-000000000002'.toUpperCase(),
    ],
  });

  assert.deepEqual(args, [
    '--json',
    '--quiet',
    '--output',
    '/tmp/bootstrap.json',
    'bootstrap',
    '--print-agent-auth-token',
    '--token',
    '0x0000000000000000000000000000000000000001',
    '--attach-policy-id',
    '00000000-0000-0000-0000-000000000002',
  ]);

  const plan = walletSetup.createWalletSetupPlan(
    {
      token: [
        '0x0000000000000000000000000000000000000001',
        '0x0000000000000000000000000000000000000001',
      ],
      attachPolicyId: [
        '00000000-0000-0000-0000-000000000002',
        '00000000-0000-0000-0000-000000000002'.toUpperCase(),
      ],
    },
    {
      readConfig: () => ({ chains: {} }),
      assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    },
  );

  assert.deepEqual(plan.policyScope.assets.erc20Tokens, [
    '0x0000000000000000000000000000000000000001',
  ]);
  assert.deepEqual(plan.policyAttachment.explicitPolicyIds, [
    '00000000-0000-0000-0000-000000000002',
  ]);
});

test('completeWalletSetup accepts per-token bootstrap summaries from shared config', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-per-token-summary`
  );
  const config = await import(configModulePath.href + `?case=${Date.now()}-per-token-summary`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const bootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  writePrivateJsonFile(
    bootstrapPath,
    bootstrapPayload({
      per_tx_policy_id: undefined,
      daily_policy_id: undefined,
      weekly_policy_id: undefined,
      gas_policy_id: undefined,
      per_tx_max_wei: undefined,
      daily_max_wei: undefined,
      weekly_max_wei: undefined,
      max_gas_per_chain_wei: undefined,
      network_scope: undefined,
      asset_scope: undefined,
      recipient_scope: undefined,
      attached_policy_ids: ['token-per-tx', 'token-daily', 'token-weekly', 'token-manual'],
      token_policies: [
        {
          token_key: 'usd1',
          symbol: 'USD1',
          chain_key: 'bsc',
          chain_id: 56,
          asset_scope: 'erc20:0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
          recipient_scope: 'all recipients',
          per_tx_policy_id: 'token-per-tx',
          daily_policy_id: 'token-daily',
          weekly_policy_id: 'token-weekly',
          per_tx_max_wei: '10000000000000000000',
          daily_max_wei: '100000000000000000000',
          weekly_max_wei: '700000000000000000000',
        },
      ],
      token_manual_approval_policies: [
        {
          token_key: 'usd1',
          symbol: 'USD1',
          chain_key: 'bsc',
          chain_id: 56,
          priority: 100,
          min_amount_wei: '5000000000000000000',
          max_amount_wei: '700000000000000000000',
          asset_scope: 'erc20:0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
          recipient_scope: 'all recipients',
          policy_id: 'token-manual',
        },
      ],
    }),
  );

  const result = walletSetup.completeWalletSetup(
    {
      bootstrapOutputPath: bootstrapPath,
      cleanupAction: 'redacted',
      daemonSocket: path.join(tempRoot, 'daemon.sock'),
      network: 1,
      rpcUrl: 'https://eth.example',
      chainName: 'eth',
    },
    {
      platform: 'darwin',
      storeAgentAuthToken: () => {},
      readConfig: () => ({}),
      writeConfig: (nextConfig) => nextConfig,
      deleteConfigKey: () => ({}),
      assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    },
  );

  assert.equal(result.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(result.policyAttachment, 'policy_set');

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('completeWalletSetup accepts unrestricted shared-config bootstrap summaries', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-shared-config-unrestricted`
  );
  const config = await import(
    configModulePath.href + `?case=${Date.now()}-shared-config-unrestricted`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const bootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  writePrivateJsonFile(
    bootstrapPath,
    bootstrapPayload({
      per_tx_policy_id: undefined,
      daily_policy_id: undefined,
      weekly_policy_id: undefined,
      gas_policy_id: undefined,
      per_tx_max_wei: undefined,
      daily_max_wei: undefined,
      weekly_max_wei: undefined,
      max_gas_per_chain_wei: undefined,
      network_scope: undefined,
      asset_scope: undefined,
      recipient_scope: undefined,
      policy_attachment: 'all_policies',
      attached_policy_ids: [],
      policy_note: 'agent key is attached to all policies',
    }),
  );

  const result = walletSetup.completeWalletSetup(
    {
      bootstrapOutputPath: bootstrapPath,
      cleanupAction: 'redacted',
      daemonSocket: path.join(tempRoot, 'daemon.sock'),
      network: 1,
      rpcUrl: 'https://eth.example',
      chainName: 'eth',
    },
    {
      platform: 'darwin',
      storeAgentAuthToken: () => {},
      assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    },
  );

  assert.equal(result.policyAttachment, 'all_policies');
  assert.deepEqual(result.attachedPolicyIds, []);
  assert.match(result.policyNote ?? '', /attached to all policies/);

  const updatedConfig = config.readConfig();
  assert.equal(updatedConfig.wallet?.policyAttachment, 'all_policies');
  assert.deepEqual(updatedConfig.wallet?.attachedPolicyIds ?? [], []);

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('buildWalletSetupAdminArgs rejects invalid token and recipient values before Rust is invoked', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-invalid-addresses`
  );

  assert.throws(
    () =>
      walletSetup.buildWalletSetupAdminArgs({
        bootstrapOutputPath: '/tmp/bootstrap.json',
        token: ['not-an-address'],
      }),
    /token must be a valid EVM address/,
  );

  assert.throws(
    () =>
      walletSetup.buildWalletSetupAdminArgs({
        bootstrapOutputPath: '/tmp/bootstrap.json',
        recipient: 'not-an-address',
      }),
    /recipient must be a valid EVM address/,
  );
});

test('wallet setup helpers reject invalid attach-policy-id values before privileged execution', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-invalid-policy-id`
  );

  assert.throws(
    () =>
      walletSetup.buildWalletSetupAdminArgs({
        bootstrapOutputPath: '/tmp/bootstrap.json',
        attachPolicyId: ['not-a-uuid'],
      }),
    /attachPolicyId must be a valid UUID/,
  );

  assert.throws(
    () =>
      walletSetup.createWalletSetupPlan(
        {
          attachPolicyId: ['not-a-uuid'],
        },
        {
          readConfig: () => ({ chains: {} }),
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /attachPolicyId must be a valid UUID/,
  );
});

test('createWalletSetupPlan previews sanitized rust args and resulting config changes', async () => {
  const walletSetup = await import(walletSetupModulePath.href + `?case=${Date.now()}-plan`);
  const config = await import(configModulePath.href + `?case=${Date.now()}-plan`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-plan-'));
  const explicitBootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  const daemonSocket = path.join(tempRoot, 'daemon.sock');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  config.writeConfig({
    chainId: 56,
    chainName: 'bsc',
    rpcUrl: 'https://rpc.bsc.example',
    daemonSocket: path.join(tempRoot, 'configured.sock'),
  });

  const plan = walletSetup.createWalletSetupPlan(
    {
      vaultPasswordStdin: true,
      daemonSocket,
      perTxMaxWei: '1',
      dailyMaxWei: '2',
      weeklyMaxWei: '3',
      maxGasPerChainWei: '4',
      dailyMaxTxCount: '5',
      perTxMaxFeePerGasWei: '6',
      perTxMaxPriorityFeePerGasWei: '7',
      perTxMaxCalldataBytes: '8',
      token: ['0x0000000000000000000000000000000000000001'],
      allowNativeEth: true,
      network: '1',
      rpcUrl: 'https://rpc.example',
      chainName: 'eth',
      recipient: '0x0000000000000000000000000000000000000002',
      attachPolicyId: ['00000000-0000-0000-0000-000000000002'],
      attachBootstrapPolicies: true,
      bootstrapOutputPath: explicitBootstrapPath,
      deleteBootstrapOutput: true,
    },
    {
      assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    },
  );

  assert.equal(plan.adminAccess.permitted, true);
  assert.equal(plan.adminAccess.mode, 'vault-password-stdin');
  assert.equal(plan.bootstrapOutput.path, explicitBootstrapPath);
  assert.equal(plan.bootstrapOutput.autoGenerated, false);
  assert.equal(plan.bootstrapOutput.cleanupAction, 'deleted');
  assert.equal(plan.daemonSocket, path.resolve(daemonSocket));
  assert.equal(plan.rustCommand.binary, 'agentpay-admin');
  assert.deepEqual(plan.rustCommand.args, [
    '--json',
    '--quiet',
    '--output',
    explicitBootstrapPath,
    '--vault-password-stdin',
    '--daemon-socket',
    daemonSocket,
    'bootstrap',
    '--print-agent-auth-token',
    '--per-tx-max-wei',
    '1',
    '--daily-max-wei',
    '2',
    '--weekly-max-wei',
    '3',
    '--max-gas-per-chain-wei',
    '4',
    '--daily-max-tx-count',
    '5',
    '--per-tx-max-fee-per-gas-wei',
    '6',
    '--per-tx-max-priority-fee-per-gas-wei',
    '7',
    '--per-tx-max-calldata-bytes',
    '8',
    '--network',
    '1',
    '--recipient',
    '0x0000000000000000000000000000000000000002',
    '--token',
    '0x0000000000000000000000000000000000000001',
    '--allow-native-eth',
    '--attach-policy-id',
    '00000000-0000-0000-0000-000000000002',
    '--attach-bootstrap-policies',
  ]);
  assert.equal(plan.policyLimits.perTxMaxWei, '1');
  assert.equal(plan.policyScope.network, 1);
  assert.equal(plan.policyScope.chainName, 'eth');
  assert.equal(plan.policyScope.assets.mode, 'mixed');
  assert.deepEqual(plan.policyScope.assets.erc20Tokens, [
    '0x0000000000000000000000000000000000000001',
  ]);
  assert.equal(plan.policyAttachment.mode, 'bootstrap-and-explicit');
  assert.equal(plan.configAfterSetup.agentKeyId, '<issued during bootstrap>');
  assert.equal(plan.configAfterSetup.daemonSocket, path.resolve(daemonSocket));
  assert.equal(plan.configAfterSetup.chainId, 1);
  assert.equal(plan.configAfterSetup.chainName, 'eth');
  assert.equal(plan.configAfterSetup.rpcUrl, 'https://rpc.example');
  assert.equal(plan.preflight.daemonSocketTrusted, true);
  assert.equal(plan.preflight.daemonSocketError, null);
  assert.equal(plan.preflight.rpcUrlTrusted, true);
  assert.equal(plan.preflight.rpcUrlError, null);
  assert.equal(plan.preflight.bootstrapOutputReady, true);
  assert.equal(plan.preflight.bootstrapOutputError, null);
  assert.equal(plan.security.rustPasswordTransport, 'stdin-relay');
  assert.equal(plan.security.childArgvContainsVaultPassword, false);
  assert.equal(plan.security.childEnvContainsVaultPassword, false);
  assert.match(plan.security.notes.join('\n'), /vault password is passed to Rust through stdin/i);

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('formatWalletSetupPlanText renders the sanitized preview for humans', async () => {
  const walletSetup = await import(walletSetupModulePath.href + `?case=${Date.now()}-plan-text`);

  const plan = walletSetup.createWalletSetupPlan(
    {
      vaultPasswordStdin: true,
      nonInteractive: true,
      daemonSocket: '/Library/AgentPay/run/daemon.sock',
      perTxMaxWei: '1',
      dailyMaxWei: '2',
      weeklyMaxWei: '3',
      maxGasPerChainWei: '4',
      token: ['0x0000000000000000000000000000000000000001'],
      allowNativeEth: true,
      network: '1',
      rpcUrl: 'https://rpc.example',
      chainName: 'eth',
      recipient: '0x0000000000000000000000000000000000000002',
      attachPolicyId: ['00000000-0000-0000-0000-000000000099'],
      attachBootstrapPolicies: true,
      bootstrapOutputPath: '/tmp/bootstrap-preview.json',
      deleteBootstrapOutput: true,
    },
    {
      readConfig: () => ({ chains: {} }),
      assertTrustedDaemonSocketPath: (targetPath) => targetPath,
      stdinIsTty: false,
      stderrIsTty: false,
      getEffectiveUid: () => 501,
      env: {},
    },
  );

  const rendered = walletSetup.formatWalletSetupPlanText(plan);

  assert.match(rendered, /^Wallet Setup Preview/m);
  assert.match(rendered, /Admin Access: allowed \(vault-password-stdin\)/);
  assert.match(rendered, /Rust Command: agentpay-admin .*--vault-password-stdin/);
  assert.match(rendered, /Policy Scope/);
  assert.match(rendered, /ERC20 Tokens: 0x0000000000000000000000000000000000000001/);
  assert.match(rendered, /Policy Attachment/);
  assert.match(rendered, /Explicit Policy IDs: 00000000-0000-0000-0000-000000000099/);
  assert.match(rendered, /Preflight/);
  assert.match(rendered, /Security/);
  assert.match(rendered, /Notes:\n- /);
});

test('formatWalletSetupPlanText includes preflight error details and interactive prompt notes', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-plan-text-preflight-errors`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-plan-'));
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  const plan = walletSetup.createWalletSetupPlan(
    {
      network: '1',
      rpcUrl: 'http://rpc.example',
      bootstrapOutputPath: path.join(tempRoot, 'exports', 'bootstrap.json'),
    },
    {
      readConfig: () => ({ chains: {} }),
      assertTrustedDaemonSocketPath: () => {
        throw new Error('daemon unreachable');
      },
      env: {},
      stdinIsTty: true,
      stderrIsTty: true,
      getEffectiveUid: () => 501,
    },
  );

  assert.equal(plan.adminAccess.mode, 'interactive-prompt');
  assert.equal(plan.security.rustPasswordTransport, 'interactive-prompt');
  assert.match(
    plan.security.notes.join('\n'),
    /local tty is expected so a human can enter the vault password securely/i,
  );

  const rendered = walletSetup.formatWalletSetupPlanText(plan);
  assert.match(rendered, /daemon unreachable/);
  assert.match(rendered, /rpcUrl must use https unless it targets localhost or a loopback address/);

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('formatWalletSetupPlanText covers blocked access and daemon-default summary branches', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-plan-text-blocked-defaults`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-plan-'));
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  const plan = walletSetup.createWalletSetupPlan(
    {
      nonInteractive: true,
    },
    {
      readConfig: () => ({ chains: {} }),
      assertTrustedDaemonSocketPath: (targetPath) => targetPath,
      env: {},
      stdinIsTty: true,
      stderrIsTty: true,
      getEffectiveUid: () => 501,
    },
  );

  const rendered = walletSetup.formatWalletSetupPlanText(plan);
  assert.match(rendered, /Admin Access: blocked \(blocked\)/);
  assert.match(rendered, /Bootstrap Output: .*auto-generated, deleted after import/);
  assert.match(rendered, /- Network: daemon default/);
  assert.match(rendered, /- Chain Name: daemon default/);
  assert.match(rendered, /- RPC URL Trusted: not applicable/);
  assert.match(rendered, /- Chain ID: unchanged/);
  assert.match(rendered, /- Chain Name: unchanged/);
  assert.match(rendered, /- RPC URL: unchanged/);

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('createWalletSetupPlan surfaces blocked non-interactive execution without a password source', async () => {
  const walletSetup = await import(walletSetupModulePath.href + `?case=${Date.now()}-blocked-plan`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-plan-'));
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  const plan = walletSetup.createWalletSetupPlan(
    {
      nonInteractive: true,
    },
    {
      env: {},
      getEffectiveUid: () => 501,
      stdinIsTty: true,
      stderrIsTty: true,
    },
  );

  assert.equal(plan.adminAccess.permitted, false);
  assert.equal(plan.adminAccess.mode, 'blocked');
  assert.equal(plan.adminAccess.nonInteractive, true);
  assert.match(plan.adminAccess.reason, /vault password is required in non-interactive mode/);
  assert.equal(plan.bootstrapOutput.autoGenerated, true);
  assert.match(plan.bootstrapOutput.path, /bootstrap-<pid>-<timestamp>\.json$/);
  assert.equal(plan.bootstrapOutput.cleanupAction, 'deleted');
  assert.equal(plan.security.rustPasswordTransport, 'not-available');

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('createWalletSetupPlan reports daemon-socket and inherited rpc preflight failures', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-preflight-failures`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-plan-'));
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  const plan = walletSetup.createWalletSetupPlan(
    {
      network: '1',
    },
    {
      readConfig: () => ({
        daemonSocket: '/tmp/untrusted.sock',
        chainId: 1,
        rpcUrl: 'http://rpc.example',
      }),
      assertTrustedDaemonSocketPath: () => {
        throw new Error('Daemon socket is not trusted');
      },
    },
  );

  assert.equal(plan.preflight.daemonSocketTrusted, false);
  assert.match(plan.preflight.daemonSocketError ?? '', /Daemon socket is not trusted/);
  assert.equal(plan.preflight.rpcUrlTrusted, false);
  assert.match(
    plan.preflight.rpcUrlError ?? '',
    /rpcUrl must use https unless it targets localhost or a loopback address/,
  );
  assert.equal(plan.preflight.bootstrapOutputReady, true);
  assert.equal(plan.preflight.bootstrapOutputError, null);
  assert.match(
    plan.security.notes.join('\n'),
    /daemon socket is not currently trusted or reachable/i,
  );
  assert.match(plan.security.notes.join('\n'), /rpcUrl that would be persisted .* is not trusted/i);

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('createWalletSetupPlan falls back to chain-id labels and stringifies non-Error daemon failures', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-string-render-and-chain-fallback`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-plan-'));
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  const plan = walletSetup.createWalletSetupPlan(
    {
      network: '424242',
      bootstrapOutputPath: path.join(tempRoot, 'exports', 'bootstrap.json'),
    },
    {
      readConfig: () => ({}),
      assertTrustedDaemonSocketPath: () => {
        throw 'daemon exploded';
      },
    },
  );

  assert.equal(plan.policyScope.network, 424242);
  assert.equal(plan.policyScope.chainName, 'chain-424242');
  assert.equal(plan.configAfterSetup.chainName, 'chain-424242');
  assert.equal(plan.configAfterSetup.rpcUrl, null);
  assert.equal(plan.preflight.daemonSocketTrusted, false);
  assert.equal(plan.preflight.daemonSocketError, 'daemon exploded');

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('createWalletSetupPlan warns when the configured admin daemon socket is not root-owned', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-preflight-root-owned-socket`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-plan-'));
  const socketDir = path.join(tempRoot, 'run');
  const socketPath = path.join(socketDir, 'daemon.sock');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  fs.mkdirSync(socketDir, { recursive: true, mode: 0o755 });

  const net = await import('node:net');
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      server.off('error', reject);
      resolve();
    });
  });

  const plan = walletSetup.createWalletSetupPlan({
    daemonSocket: socketPath,
  });

  assert.equal(plan.preflight.daemonSocketTrusted, false);
  assert.match(plan.preflight.daemonSocketError ?? '', /must be owned by root/);
  assert.match(
    plan.security.notes.join('\n'),
    /daemon socket is not currently trusted or reachable/i,
  );

  await new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
  fs.rmSync(socketPath, { force: true });
  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('createWalletSetupPlan reports bootstrap-output preflight failures', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-bootstrap-output-preflight`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-plan-'));
  const bootstrapDir = path.join(tempRoot, 'exports');
  const bootstrapPath = path.join(bootstrapDir, 'bootstrap.json');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  fs.mkdirSync(bootstrapDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(bootstrapPath, '{}', {
    encoding: 'utf8',
    mode: 0o400,
  });
  fs.chmodSync(bootstrapDir, 0o700);
  fs.chmodSync(bootstrapPath, 0o400);

  const plan = walletSetup.createWalletSetupPlan(
    {
      bootstrapOutputPath: bootstrapPath,
    },
    {
      readConfig: () => ({
        daemonSocket: '/trusted/run/daemon.sock',
      }),
      assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    },
  );

  assert.equal(plan.preflight.daemonSocketTrusted, true);
  assert.equal(plan.preflight.bootstrapOutputReady, false);
  assert.match(
    plan.preflight.bootstrapOutputError ?? '',
    /must be writable by the current process/,
  );
  assert.match(
    plan.security.notes.join('\n'),
    /bootstrap output path is not currently safe or writable/i,
  );

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('createWalletSetupPlan rejects bootstrap-output paths that traverse symlinked ancestor directories', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-bootstrap-output-ancestor-link`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-plan-'));
  const realRoot = path.join(tempRoot, 'real-root');
  const linkedRoot = path.join(tempRoot, 'linked-root');
  const bootstrapDir = path.join(realRoot, 'exports');
  const bootstrapPath = path.join(linkedRoot, 'exports', 'bootstrap.json');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  fs.mkdirSync(bootstrapDir, { recursive: true, mode: 0o700 });
  fs.symlinkSync(realRoot, linkedRoot);

  const plan = walletSetup.createWalletSetupPlan(
    {
      bootstrapOutputPath: bootstrapPath,
    },
    {
      readConfig: () => ({
        daemonSocket: '/trusted/run/daemon.sock',
      }),
      assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    },
  );

  assert.equal(plan.preflight.daemonSocketTrusted, true);
  assert.equal(plan.preflight.bootstrapOutputReady, false);
  assert.match(
    plan.preflight.bootstrapOutputError ?? '',
    /must not traverse symlinked ancestor directories/,
  );
  assert.match(
    plan.security.notes.join('\n'),
    /bootstrap output path is not currently safe or writable/i,
  );

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('resolveWalletSetupBootstrapOutputPath creates private explicit parent directories', async () => {
  const walletSetup = await import(walletSetupModulePath.href + `?case=${Date.now()}-2`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const explicitPath = path.join(tempRoot, 'nested', 'bootstrap.json');

  const resolved = walletSetup.resolveWalletSetupBootstrapOutputPath(explicitPath);

  assert.equal(resolved.autoGenerated, false);
  assert.equal(resolved.path, explicitPath);
  assert.equal(fs.statSync(path.dirname(explicitPath)).isDirectory(), true);
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(path.dirname(explicitPath)).mode & 0o777, 0o700);
  }

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('resolveWalletSetupBootstrapOutputPath tolerates chmod failures on existing directories', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-chmod-failure-ignored`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const explicitPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  fs.mkdirSync(path.dirname(explicitPath), { recursive: true, mode: 0o700 });

  const originalChmodSync = fs.chmodSync;
  withMockedFs(
    {
      chmodSync: (targetPath, mode) => {
        if (path.resolve(String(targetPath)) === path.resolve(path.dirname(explicitPath))) {
          const error = new Error('chmod denied');
          error.code = 'EPERM';
          throw error;
        }
        return originalChmodSync(targetPath, mode);
      },
    },
    () => {
      const resolved = walletSetup.resolveWalletSetupBootstrapOutputPath(explicitPath);
      assert.equal(resolved.path, explicitPath);
      assert.equal(resolved.autoGenerated, false);
    },
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('resolveWalletSetupBootstrapOutputPath rejects existing bootstrap files that are not writable', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-bootstrap-output-runtime`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const bootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');

  fs.mkdirSync(path.dirname(bootstrapPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(bootstrapPath, '{}', {
    encoding: 'utf8',
    mode: 0o400,
  });
  fs.chmodSync(path.dirname(bootstrapPath), 0o700);
  fs.chmodSync(bootstrapPath, 0o400);

  assert.throws(
    () => walletSetup.resolveWalletSetupBootstrapOutputPath(bootstrapPath),
    /must be writable by the current process/,
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('completeWalletSetup imports credentials, updates config, and redacts explicit bootstrap output', async () => {
  const walletSetup = await import(walletSetupModulePath.href + `?case=${Date.now()}-3`);
  const config = await import(configModulePath.href + `?case=${Date.now()}-3`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const agentpayHome = path.join(tempRoot, 'home');
  const bootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  process.env.AGENTPAY_HOME = agentpayHome;

  writePrivateJsonFile(bootstrapPath, bootstrapPayload({ network_scope: '1' }));
  config.writeConfig({
    agentAuthToken: 'legacy-config-token',
    chainId: 56,
    chainName: 'bsc',
    rpcUrl: 'https://old-rpc.example',
  });

  let storedCredentials = null;
  const result = walletSetup.completeWalletSetup(
    {
      bootstrapOutputPath: bootstrapPath,
      cleanupAction: 'redacted',
      daemonSocket: path.join(tempRoot, 'daemon.sock'),
      network: 1,
      rpcUrl: 'https://rpc.example',
      chainName: 'eth',
    },
    {
      platform: 'darwin',
      storeAgentAuthToken: (agentKeyId, token) => {
        storedCredentials = { agentKeyId, token };
      },
      assertTrustedDaemonSocketPath: (targetPath) => path.resolve(targetPath),
    },
  );

  assert.deepEqual(storedCredentials, {
    agentKeyId: TEST_AGENT_KEY_ID,
    token: TEST_AGENT_AUTH_TOKEN,
  });
  assert.equal(result.sourceCleanup, 'redacted');
  assert.equal(result.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(result.agentAuthToken, TEST_AGENT_AUTH_TOKEN);
  assert.equal(result.vaultPrivateKey, TEST_VAULT_PRIVATE_KEY);
  assert.equal(result.keychain.service, 'agentpay-agent-auth-token');

  const updatedConfig = config.readConfig();
  assert.equal(updatedConfig.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(updatedConfig.agentAuthToken, undefined);
  assert.equal(updatedConfig.chainId, 1);
  assert.equal(updatedConfig.chainName, 'eth');
  assert.equal(updatedConfig.rpcUrl, 'https://rpc.example');
  assert.equal(updatedConfig.daemonSocket, path.resolve(tempRoot, 'daemon.sock'));
  assert.equal(updatedConfig.wallet?.vaultPublicKey, '03abcdef');
  assert.equal(updatedConfig.wallet?.policyAttachment, 'policy_set');
  assert.equal(updatedConfig.wallet?.policyNote, 'bootstrap note');
  assert.deepEqual(updatedConfig.wallet?.attachedPolicyIds, [
    'policy-per-tx',
    'policy-daily',
    'policy-weekly',
    'policy-gas',
  ]);

  const redactedPayload = JSON.parse(fs.readFileSync(bootstrapPath, 'utf8'));
  assert.equal(redactedPayload.agent_auth_token, '<redacted>');
  assert.equal(redactedPayload.agent_auth_token_redacted, true);
  assert.equal(redactedPayload.vault_private_key, '<redacted>');
  assert.equal(redactedPayload.vault_private_key_redacted, true);

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('completeWalletSetup returns a cleanup warning when redaction and fallback delete both fail', async () => {
  const walletSetup = await import(walletSetupModulePath.href + `?case=${Date.now()}-cleanup-warning`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const bootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  writePrivateJsonFile(bootstrapPath, bootstrapPayload({ network_scope: '1' }));

  const originalRenameSync = fs.renameSync;
  const originalRmSync = fs.rmSync;
  fs.renameSync = (sourcePath, destinationPath, ...args) => {
    if (path.resolve(String(destinationPath)) === bootstrapPath) {
      throw new Error('rename failed');
    }
    return originalRenameSync.call(fs, sourcePath, destinationPath, ...args);
  };
  fs.rmSync = (targetPath, ...args) => {
    if (path.resolve(String(targetPath)) === bootstrapPath) {
      throw new Error('delete failed');
    }
    return originalRmSync.call(fs, targetPath, ...args);
  };

  let result;
  try {
    result = walletSetup.completeWalletSetup(
      {
        bootstrapOutputPath: bootstrapPath,
        cleanupAction: 'redacted',
        daemonSocket: path.join(tempRoot, 'daemon.sock'),
        network: 1,
        rpcUrl: 'https://rpc.example',
        chainName: 'eth',
      },
      {
        platform: 'darwin',
        storeAgentAuthToken: () => {},
        assertTrustedDaemonSocketPath: (targetPath) => path.resolve(targetPath),
      },
    );
  } finally {
    fs.renameSync = originalRenameSync;
    fs.rmSync = originalRmSync;
  }

  assert.equal(result.sourceCleanup, 'redacted');
  assert.match(result.sourceCleanupWarning ?? '', /rename failed/);
  assert.match(result.sourceCleanupWarning ?? '', /fallback delete also failed: delete failed/);

  const retainedPayload = JSON.parse(fs.readFileSync(bootstrapPath, 'utf8'));
  assert.equal(retainedPayload.agent_auth_token, TEST_AGENT_AUTH_TOKEN);
  assert.equal(retainedPayload.vault_private_key, TEST_VAULT_PRIVATE_KEY);

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('completeWalletSetup uses configured chain metadata and matching explicit limits', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-configured-chain-fallbacks`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const bootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  writePrivateJsonFile(bootstrapPath, bootstrapPayload({ network_scope: '56' }));

  let persistedConfig = null;
  const result = walletSetup.completeWalletSetup(
    {
      bootstrapOutputPath: bootstrapPath,
      cleanupAction: 'deleted',
      network: 56,
      perTxMaxWei: '1000000000000000000',
      dailyMaxWei: '5000000000000000000',
      weeklyMaxWei: '20000000000000000000',
      maxGasPerChainWei: '1000000000000000',
      dailyMaxTxCount: '0',
    },
    {
      platform: 'darwin',
      storeAgentAuthToken: () => {},
      readConfig: () => ({
        chains: {
          bsc: {
            chainId: 56,
            name: 'bsc',
            rpcUrl: 'https://bsc.example',
          },
        },
      }),
      writeConfig: (nextConfig) => {
        persistedConfig = nextConfig;
        return nextConfig;
      },
      deleteConfigKey: () => persistedConfig ?? {},
      assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    },
  );

  assert.equal(result.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(persistedConfig.chainId, 56);
  assert.equal(persistedConfig.chainName, 'bsc');
  assert.equal(persistedConfig.rpcUrl, 'https://bsc.example');

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('completeWalletSetup works when bootstrap output omits the vault private key', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-bootstrap-without-private-key`
  );
  const config = await import(
    configModulePath.href + `?case=${Date.now()}-bootstrap-without-private-key`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const bootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  const daemonSocket = path.join(tempRoot, 'home', 'run', 'daemon.sock');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');
  fs.mkdirSync(path.dirname(daemonSocket), { recursive: true, mode: 0o700 });

  writePrivateJsonFile(
    bootstrapPath,
    bootstrapPayload({
      network_scope: '1',
      vault_private_key: undefined,
    }),
  );

  let storedCredentials = null;
  const result = walletSetup.completeWalletSetup(
    {
      bootstrapOutputPath: bootstrapPath,
      cleanupAction: 'redacted',
      daemonSocket: path.join(tempRoot, 'daemon.sock'),
      network: 1,
      rpcUrl: 'https://rpc.example',
      chainName: 'eth',
    },
    {
      platform: 'darwin',
      storeAgentAuthToken: (agentKeyId, token) => {
        storedCredentials = { agentKeyId, token };
      },
      assertTrustedDaemonSocketPath: (targetPath) => path.resolve(targetPath),
    },
  );

  assert.deepEqual(storedCredentials, {
    agentKeyId: TEST_AGENT_KEY_ID,
    token: TEST_AGENT_AUTH_TOKEN,
  });
  assert.equal(result.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(result.agentAuthToken, TEST_AGENT_AUTH_TOKEN);
  assert.equal(result.vaultPrivateKey, null);

  const redactedPayload = JSON.parse(fs.readFileSync(bootstrapPath, 'utf8'));
  assert.equal(redactedPayload.agent_auth_token, '<redacted>');
  assert.equal(redactedPayload.agent_auth_token_redacted, true);
  assert.equal('vault_private_key' in redactedPayload, false);

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('completeWalletSetup rejects bootstrap asset scope mismatches before importing credentials', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-asset-scope-mismatch`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const bootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  const daemonSocket = path.join(tempRoot, 'home', 'run', 'daemon.sock');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');
  fs.mkdirSync(path.dirname(daemonSocket), { recursive: true, mode: 0o700 });

  writePrivateJsonFile(bootstrapPath, bootstrapPayload());

  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: bootstrapPath,
          cleanupAction: 'redacted',
          allowNativeEth: true,
        },
        {
          platform: 'darwin',
          storeAgentAuthToken: () => {
            throw new Error('should not import token');
          },
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /asset_scope does not match/,
  );

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('completeWalletSetup accepts duplicate token inputs after canonicalization', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-asset-scope-dedupe`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const bootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  const daemonSocket = path.join(tempRoot, 'home', 'run', 'daemon.sock');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');
  fs.mkdirSync(path.dirname(daemonSocket), { recursive: true, mode: 0o700 });

  writePrivateJsonFile(
    bootstrapPath,
    bootstrapPayload({
      asset_scope: 'erc20:0x0000000000000000000000000000000000000001',
    }),
  );

  const result = walletSetup.completeWalletSetup(
    {
      bootstrapOutputPath: bootstrapPath,
      cleanupAction: 'deleted',
      token: [
        '0x0000000000000000000000000000000000000001',
        '0x0000000000000000000000000000000000000001',
      ],
    },
    {
      platform: 'darwin',
      storeAgentAuthToken: () => {},
      readConfig: () => ({}),
      writeConfig: (nextConfig) => nextConfig,
      deleteConfigKey: () => ({}),
      assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    },
  );

  assert.equal(result.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(fs.existsSync(bootstrapPath), false);

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('completeWalletSetup rejects bootstrap recipient scope mismatches before importing credentials', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-recipient-scope-mismatch`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const bootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  writePrivateJsonFile(bootstrapPath, bootstrapPayload());

  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: bootstrapPath,
          cleanupAction: 'redacted',
          recipient: '0x0000000000000000000000000000000000000001',
        },
        {
          platform: 'darwin',
          storeAgentAuthToken: () => {
            throw new Error('should not import token');
          },
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /recipient_scope does not match/,
  );

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('completeWalletSetup rejects bootstrap attachment mismatches before importing credentials', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-attachment-mismatch`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const bootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  writePrivateJsonFile(
    bootstrapPath,
    bootstrapPayload({
      policy_attachment: 'policy_set',
      attached_policy_ids: ['00000000-0000-0000-0000-000000000099'],
    }),
  );

  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: bootstrapPath,
          cleanupAction: 'redacted',
        },
        {
          platform: 'darwin',
          storeAgentAuthToken: () => {
            throw new Error('should not import token');
          },
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /policy_attachment does not match|attached_policy_ids/,
  );

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('completeWalletSetup deletes autogenerated bootstrap output after import', async () => {
  const walletSetup = await import(walletSetupModulePath.href + `?case=${Date.now()}-4`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  const output = walletSetup.resolveWalletSetupBootstrapOutputPath();
  writePrivateJsonFile(output.path, bootstrapPayload());

  walletSetup.completeWalletSetup(
    {
      bootstrapOutputPath: output.path,
      cleanupAction: walletSetup.resolveWalletSetupCleanupAction(output.autoGenerated, false),
    },
    {
      platform: 'darwin',
      storeAgentAuthToken: () => {},
      assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    },
  );

  assert.equal(fs.existsSync(output.path), false);

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('completeWalletSetup redacts bootstrap output even when Keychain import fails', async () => {
  const walletSetup = await import(walletSetupModulePath.href + `?case=${Date.now()}-5`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const bootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  writePrivateJsonFile(bootstrapPath, bootstrapPayload());

  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: bootstrapPath,
          cleanupAction: 'redacted',
        },
        {
          platform: 'darwin',
          storeAgentAuthToken: () => {
            throw new Error('keychain unavailable');
          },
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /keychain unavailable/,
  );

  const redactedPayload = JSON.parse(fs.readFileSync(bootstrapPath, 'utf8'));
  assert.equal(redactedPayload.agent_auth_token, '<redacted>');
  assert.equal(redactedPayload.agent_auth_token_redacted, true);
  assert.equal(redactedPayload.vault_private_key, '<redacted>');
  assert.equal(redactedPayload.vault_private_key_redacted, true);

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('completeWalletSetup rejects expired bootstrap leases before importing credentials', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-expired-lease`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const bootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  writePrivateJsonFile(
    bootstrapPath,
    bootstrapPayload({
      lease_expires_at: '2020-01-01T00:00:00Z',
    }),
  );

  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: bootstrapPath,
          cleanupAction: 'redacted',
        },
        {
          platform: 'darwin',
          storeAgentAuthToken: () => {
            throw new Error('should not import token');
          },
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /bootstrap summary lease has expired/,
  );

  const redactedPayload = JSON.parse(fs.readFileSync(bootstrapPath, 'utf8'));
  assert.equal(redactedPayload.agent_auth_token, '<redacted>');
  assert.equal(redactedPayload.agent_auth_token_redacted, true);
  assert.equal(redactedPayload.vault_private_key, '<redacted>');
  assert.equal(redactedPayload.vault_private_key_redacted, true);

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('completeWalletSetup rejects rpcUrl without network before reading files', async () => {
  const walletSetup = await import(walletSetupModulePath.href + `?case=${Date.now()}-6`);

  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: '/tmp/ignored-bootstrap.json',
          cleanupAction: 'deleted',
          rpcUrl: 'https://rpc.example',
        },
        {
          platform: 'darwin',
          storeAgentAuthToken: () => {},
        },
      ),
    /--rpc-url requires --network/,
  );
});

test('completeWalletSetup rejects insecure remote rpcUrl values', async () => {
  const walletSetup = await import(walletSetupModulePath.href + `?case=${Date.now()}-unsafe-rpc`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const bootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  writePrivateJsonFile(bootstrapPath, bootstrapPayload({ network_scope: '1' }));

  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: bootstrapPath,
          cleanupAction: 'deleted',
          network: 1,
          rpcUrl: 'http://rpc.example',
        },
        {
          platform: 'darwin',
          storeAgentAuthToken: () => {},
        },
      ),
    /rpcUrl must use https unless it targets localhost or a loopback address/,
  );

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('completeWalletSetup rejects inherited insecure rpcUrl values before importing credentials', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-unsafe-inherited-rpc`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const bootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  writePrivateJsonFile(bootstrapPath, bootstrapPayload({ network_scope: '1' }));

  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: bootstrapPath,
          cleanupAction: 'deleted',
          network: 1,
        },
        {
          platform: 'darwin',
          readConfig: () => ({
            chainId: 1,
            rpcUrl: 'http://rpc.example',
          }),
          storeAgentAuthToken: () => {
            throw new Error('should not import token');
          },
        },
      ),
    /rpcUrl must use https unless it targets localhost or a loopback address/,
  );

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('completeWalletSetup validates daemon socket trust for library callers', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-daemon-socket-trust`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const bootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  writePrivateJsonFile(bootstrapPath, bootstrapPayload());

  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: bootstrapPath,
          cleanupAction: 'deleted',
          daemonSocket: '/tmp/untrusted.sock',
        },
        {
          platform: 'darwin',
          storeAgentAuthToken: () => {},
          assertTrustedDaemonSocketPath: () => {
            throw new Error('Daemon socket is not trusted');
          },
        },
      ),
    /Daemon socket is not trusted/,
  );

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('completeWalletSetup rejects untrusted daemon sockets before reading bootstrap files', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-daemon-socket-first`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: path.join(tempRoot, 'missing-bootstrap.json'),
          cleanupAction: 'deleted',
          daemonSocket: '/tmp/untrusted.sock',
        },
        {
          platform: 'darwin',
          storeAgentAuthToken: () => {
            throw new Error('should not import token');
          },
          assertTrustedDaemonSocketPath: () => {
            throw new Error('Daemon socket is not trusted');
          },
        },
      ),
    /Daemon socket is not trusted/,
  );

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('assertWalletSetupExecutionPreconditions tolerates no-op callers without explicit deps', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-preconditions-default-deps`
  );

  assert.doesNotThrow(() => {
    walletSetup.assertWalletSetupExecutionPreconditions({}, {});
  });
});

test('completeWalletSetup rejects invalid network ids for library callers', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-invalid-network`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const bootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');

  writePrivateJsonFile(bootstrapPath, bootstrapPayload());

  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: bootstrapPath,
          cleanupAction: 'deleted',
          network: 0,
        },
        {
          platform: 'darwin',
          storeAgentAuthToken: () => {},
        },
      ),
    /network must be a positive safe integer/,
  );

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('createWalletSetupPlan validates network input and models native-only scope', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-plan-network-and-native-mode`
  );

  assert.throws(
    () =>
      walletSetup.createWalletSetupPlan(
        {
          network: '0',
        },
        {
          readConfig: () => ({ chains: {} }),
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /network must be a positive safe integer/,
  );

  const plan = walletSetup.createWalletSetupPlan(
    {
      network: '56',
      allowNativeEth: true,
    },
    {
      readConfig: () => ({
        chains: {
          bsc: {
            chainId: 56,
            name: 'bsc',
            rpcUrl: 'https://bsc.drpc.org',
          },
        },
      }),
      assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    },
  );

  assert.equal(plan.policyScope.assets.mode, 'native-only');
});

test('buildWalletSetupAdminArgs honors explicit fromSharedConfig overrides', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-explicit-shared-config-toggle`
  );

  const forcedSharedConfig = walletSetup.buildWalletSetupAdminArgs({
    bootstrapOutputPath: '/tmp/bootstrap.json',
    fromSharedConfig: true,
    token: ['0x0000000000000000000000000000000000000001'],
    allowNativeEth: true,
    recipient: '0x1111111111111111111111111111111111111111',
  });
  assert.equal(forcedSharedConfig.includes('--from-shared-config'), true);
  assert.equal(forcedSharedConfig.includes('--token'), false);
  assert.equal(forcedSharedConfig.includes('--allow-native-eth'), false);

  const forcedLegacyArgs = walletSetup.buildWalletSetupAdminArgs({
    bootstrapOutputPath: '/tmp/bootstrap.json',
    fromSharedConfig: false,
  });
  assert.equal(forcedLegacyArgs.includes('--from-shared-config'), false);
});

test('completeWalletSetup enforces supported-platform and integer-limit validation', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-platform-and-limit-validation`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const bootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  const daemonSocket = path.join(tempRoot, 'home', 'run', 'daemon.sock');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');
  fs.mkdirSync(path.dirname(daemonSocket), { recursive: true, mode: 0o700 });
  writePrivateJsonFile(bootstrapPath, bootstrapPayload());

  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: bootstrapPath,
          cleanupAction: 'deleted',
          daemonSocket,
        },
        {
          platform: 'win32',
          storeAgentAuthToken: () => {},
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /wallet setup requires macOS or Linux local credential storage support/,
  );
  writePrivateJsonFile(bootstrapPath, bootstrapPayload());

  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: bootstrapPath,
          cleanupAction: 'deleted',
          chainName: 'mainnet',
          daemonSocket,
        },
        {
          platform: 'darwin',
          storeAgentAuthToken: () => {},
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /--chain-name requires --network/,
  );
  writePrivateJsonFile(bootstrapPath, bootstrapPayload());

  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: bootstrapPath,
          cleanupAction: 'deleted',
          perTxMaxWei: 'not-an-integer',
          daemonSocket,
        },
        {
          platform: 'darwin',
          storeAgentAuthToken: () => {},
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /perTxMaxWei must be a positive integer string/,
  );
  writePrivateJsonFile(bootstrapPath, bootstrapPayload());

  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: bootstrapPath,
          cleanupAction: 'deleted',
          dailyMaxTxCount: '-1',
          daemonSocket,
        },
        {
          platform: 'darwin',
          storeAgentAuthToken: () => {},
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /dailyMaxTxCount must be a non-negative integer string/,
  );

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('completeWalletSetup rejects attachment and optional-policy mismatches and accepts rich per-token summaries', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-attachment-and-rich-summary`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-'));
  const bootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  const daemonSocket = path.join(tempRoot, 'home', 'run', 'daemon.sock');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');
  fs.mkdirSync(path.dirname(daemonSocket), { recursive: true, mode: 0o700 });

  writePrivateJsonFile(
    bootstrapPath,
    bootstrapPayload({
      policy_attachment: 'legacy',
    }),
  );
  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: bootstrapPath,
          cleanupAction: 'deleted',
          daemonSocket,
        },
        {
          platform: 'darwin',
          storeAgentAuthToken: () => {},
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /policy_attachment does not match/,
  );

  writePrivateJsonFile(
    bootstrapPath,
    bootstrapPayload({
      daily_max_tx_count: '5',
      daily_tx_count_policy_id: null,
    }),
  );
  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: bootstrapPath,
          cleanupAction: 'deleted',
          dailyMaxTxCount: '5',
          daemonSocket,
        },
        {
          platform: 'darwin',
          storeAgentAuthToken: () => {},
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /dailyMaxTxCount is missing its policy id/,
  );

  writePrivateJsonFile(
    bootstrapPath,
    bootstrapPayload({
      daily_max_tx_count: '5',
      daily_tx_count_policy_id: 'policy-daily-count',
    }),
  );
  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: bootstrapPath,
          cleanupAction: 'deleted',
          daemonSocket,
        },
        {
          platform: 'darwin',
          storeAgentAuthToken: () => {},
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /dailyMaxTxCount was enabled unexpectedly/,
  );

  writePrivateJsonFile(
    bootstrapPath,
    bootstrapPayload({
      attached_policy_ids: [
        'policy-per-tx',
        'policy-daily',
        'policy-weekly',
        'policy-gas',
        'wrong-policy',
      ],
    }),
  );
  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: bootstrapPath,
          cleanupAction: 'deleted',
          attachPolicyId: ['00000000-0000-0000-0000-000000000002'],
          daemonSocket,
        },
        {
          platform: 'darwin',
          storeAgentAuthToken: () => {},
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /attached_policy_ids do not match/,
  );

  writePrivateJsonFile(
    bootstrapPath,
    bootstrapPayload({
      attached_policy_ids: [
        'policy-per-tx',
        'policy-daily',
        'policy-weekly',
        'policy-gas',
        'manual-approval-extra',
      ],
    }),
  );
  assert.doesNotThrow(() =>
    walletSetup.completeWalletSetup(
      {
        bootstrapOutputPath: bootstrapPath,
        cleanupAction: 'deleted',
        attachBootstrapPolicies: true,
        daemonSocket,
      },
      {
        platform: 'darwin',
        storeAgentAuthToken: () => {},
        assertTrustedDaemonSocketPath: (targetPath) => targetPath,
      },
    ),
  );

  const richSummaryAttachedPolicyIds = [
    'dest-per-tx',
    'dest-daily',
    'dest-weekly',
    'dest-gas',
    'dest-daily-count',
    'dest-fee',
    'dest-priority',
    'dest-calldata',
    'token-per-tx',
    'token-daily',
    'token-weekly',
    'token-gas',
    'token-daily-count',
    'token-fee',
    'token-priority',
    'token-calldata',
    'override-per-tx',
    'override-daily',
    'override-weekly',
    'override-gas',
    'override-daily-count',
    'override-fee',
    'override-priority',
    'override-calldata',
    'manual-approval',
    '00000000-0000-0000-0000-000000000002',
  ];
  writePrivateJsonFile(
    bootstrapPath,
    bootstrapPayload({
      per_tx_policy_id: null,
      daily_policy_id: null,
      weekly_policy_id: null,
      gas_policy_id: null,
      per_tx_max_wei: null,
      daily_max_wei: null,
      weekly_max_wei: null,
      max_gas_per_chain_wei: null,
      network_scope: null,
      asset_scope: null,
      recipient_scope: null,
      attached_policy_ids: richSummaryAttachedPolicyIds,
      destination_overrides: [
        {
          recipient: '0x1111111111111111111111111111111111111111',
          per_tx_policy_id: 'dest-per-tx',
          daily_policy_id: 'dest-daily',
          weekly_policy_id: 'dest-weekly',
          gas_policy_id: 'dest-gas',
          per_tx_max_wei: '1',
          daily_max_wei: '2',
          weekly_max_wei: '3',
          max_gas_per_chain_wei: '4',
          daily_max_tx_count: '5',
          daily_tx_count_policy_id: 'dest-daily-count',
          per_tx_max_fee_per_gas_wei: '6',
          per_tx_max_fee_per_gas_policy_id: 'dest-fee',
          per_tx_max_priority_fee_per_gas_wei: '7',
          per_tx_max_priority_fee_per_gas_policy_id: 'dest-priority',
          per_tx_max_calldata_bytes: '8',
          per_tx_max_calldata_bytes_policy_id: 'dest-calldata',
        },
      ],
      token_policies: [
        {
          token_key: 'usd1',
          symbol: 'USD1',
          chain_key: 'eth',
          chain_id: 1,
          asset_scope: 'erc20:0x0000000000000000000000000000000000000001',
          recipient_scope: 'all recipients',
          per_tx_policy_id: 'token-per-tx',
          daily_policy_id: 'token-daily',
          weekly_policy_id: 'token-weekly',
          gas_policy_id: 'token-gas',
          per_tx_max_wei: '11',
          daily_max_wei: '22',
          weekly_max_wei: '33',
          max_gas_per_chain_wei: '44',
          daily_max_tx_count: '9',
          daily_tx_count_policy_id: 'token-daily-count',
          per_tx_max_fee_per_gas_wei: '12',
          per_tx_max_fee_per_gas_policy_id: 'token-fee',
          per_tx_max_priority_fee_per_gas_wei: '13',
          per_tx_max_priority_fee_per_gas_policy_id: 'token-priority',
          per_tx_max_calldata_bytes: '14',
          per_tx_max_calldata_bytes_policy_id: 'token-calldata',
        },
      ],
      token_destination_overrides: [
        {
          token_key: 'usd1',
          symbol: 'USD1',
          chain_key: 'eth',
          chain_id: 1,
          recipient: '0x2222222222222222222222222222222222222222',
          asset_scope: 'erc20:0x0000000000000000000000000000000000000001',
          per_tx_policy_id: 'override-per-tx',
          daily_policy_id: 'override-daily',
          weekly_policy_id: 'override-weekly',
          gas_policy_id: 'override-gas',
          per_tx_max_wei: '101',
          daily_max_wei: '202',
          weekly_max_wei: '303',
          max_gas_per_chain_wei: '404',
          daily_max_tx_count: '4',
          daily_tx_count_policy_id: 'override-daily-count',
          per_tx_max_fee_per_gas_wei: '15',
          per_tx_max_fee_per_gas_policy_id: 'override-fee',
          per_tx_max_priority_fee_per_gas_wei: '16',
          per_tx_max_priority_fee_per_gas_policy_id: 'override-priority',
          per_tx_max_calldata_bytes: '17',
          per_tx_max_calldata_bytes_policy_id: 'override-calldata',
        },
      ],
      token_manual_approval_policies: [
        {
          token_key: 'usd1',
          symbol: 'USD1',
          chain_key: 'eth',
          chain_id: 1,
          priority: 100,
          min_amount_wei: '1',
          max_amount_wei: '1000',
          asset_scope: 'erc20:0x0000000000000000000000000000000000000001',
          recipient_scope: 'all recipients',
          policy_id: 'manual-approval',
        },
      ],
    }),
  );

  const result = walletSetup.completeWalletSetup(
    {
      bootstrapOutputPath: bootstrapPath,
      cleanupAction: 'deleted',
      attachPolicyId: ['00000000-0000-0000-0000-000000000002'],
      daemonSocket,
    },
    {
      platform: 'darwin',
      storeAgentAuthToken: () => {},
      assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    },
  );
  assert.equal(result.keychain.stored, true);

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('resolveWalletSetupBootstrapOutputPath enforces writable and file-type guards', async () => {
  const walletSetup = await import(walletSetupModulePath.href + `?case=${Date.now()}-bootstrap-output-guard-edges`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-guard-'));

  const nonWritableParent = path.join(tempRoot, 'non-writable');
  fs.mkdirSync(nonWritableParent, { recursive: true, mode: 0o700 });
  const originalAccessSync = fs.accessSync;
  withMockedFs(
    {
      accessSync: (targetPath, mode) => {
        if (path.resolve(String(targetPath)) === path.resolve(nonWritableParent)) {
          const error = new Error('permission denied');
          error.code = 'EACCES';
          throw error;
        }
        return originalAccessSync(targetPath, mode);
      },
    },
    () => {
      assert.throws(
        () =>
          walletSetup.resolveWalletSetupBootstrapOutputPath(
            path.join(nonWritableParent, 'bootstrap.json'),
          ),
        /must be writable by the current process/,
      );
    },
  );

  const realDir = path.join(tempRoot, 'real-dir');
  const linkedDir = path.join(tempRoot, 'linked-dir');
  fs.mkdirSync(realDir, { recursive: true, mode: 0o700 });
  fs.symlinkSync(realDir, linkedDir);
  assert.throws(
    () => walletSetup.resolveWalletSetupBootstrapOutputPath(path.join(linkedDir, 'bootstrap.json')),
    /must not be a symlink/,
  );

  const parentFile = path.join(tempRoot, 'parent-file');
  fs.writeFileSync(parentFile, 'not-a-directory', { mode: 0o600 });
  assert.throws(
    () => walletSetup.resolveWalletSetupBootstrapOutputPath(path.join(parentFile, 'bootstrap.json')),
    /must be a directory/,
  );

  const realBootstrapFile = path.join(tempRoot, 'real-bootstrap.json');
  const symlinkBootstrapFile = path.join(tempRoot, 'symlink-bootstrap.json');
  fs.writeFileSync(realBootstrapFile, '{}', { mode: 0o600 });
  fs.symlinkSync(realBootstrapFile, symlinkBootstrapFile);
  assert.throws(
    () => walletSetup.resolveWalletSetupBootstrapOutputPath(symlinkBootstrapFile),
    /bootstrap output file .* must not be a symlink/,
  );

  const bootstrapDirTarget = path.join(tempRoot, 'bootstrap-dir-target');
  fs.mkdirSync(bootstrapDirTarget, { recursive: true, mode: 0o700 });
  assert.throws(
    () => walletSetup.resolveWalletSetupBootstrapOutputPath(bootstrapDirTarget),
    /bootstrap output file .* must be a regular file/,
  );

  assert.throws(
    () => walletSetup.resolveWalletSetupBootstrapOutputPath('/'),
    /bootstrap output directory '\/' must be writable by the current process|bootstrap output file .* must be a regular file/,
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('createWalletSetupPlan preflight covers root, missing-ancestor, and mocked preview directory branches', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-preflight-root-and-preview-branches`
  );

  const rootPlan = walletSetup.createWalletSetupPlan(
    {
      bootstrapOutputPath: '/',
    },
    {
      readConfig: () => ({ chains: {} }),
      assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    },
  );
  assert.equal(rootPlan.preflight.bootstrapOutputReady, false);

  withMockedFs(
    {
      lstatSync: () => {
        const error = new Error('missing');
        error.code = 'ENOENT';
        throw error;
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      const plan = walletSetup.createWalletSetupPlan(
        {
          bootstrapOutputPath: '/virtual/bootstrap.json',
        },
        {
          readConfig: () => ({ chains: {} }),
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      );
      assert.equal(plan.preflight.bootstrapOutputReady, false);
      assert.match(plan.preflight.bootstrapOutputError ?? '', /missing/);
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === '/virtual') {
          const error = new Error('lstat boom');
          error.code = 'EIO';
          throw error;
        }
        const missing = new Error('missing');
        missing.code = 'ENOENT';
        throw missing;
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      const plan = walletSetup.createWalletSetupPlan(
        {
          bootstrapOutputPath: '/virtual/preview/bootstrap.json',
        },
        {
          readConfig: () => ({ chains: {} }),
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      );
      assert.equal(plan.preflight.bootstrapOutputReady, false);
      assert.match(plan.preflight.bootstrapOutputError ?? '', /lstat boom/);
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === '/virtual/preview') {
          return mockStats({ uid: 0, mode: 0o777, directory: true });
        }
        if (resolved === '/virtual' || resolved === '/') {
          return mockStats({ uid: 0, mode: 0o700, directory: true });
        }
        const error = new Error('missing');
        error.code = 'ENOENT';
        throw error;
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
      accessSync: () => {},
    },
    () => {
      const plan = walletSetup.createWalletSetupPlan(
        {
          bootstrapOutputPath: '/virtual/preview/bootstrap.json',
        },
        {
          readConfig: () => ({ chains: {} }),
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
          getEffectiveUid: () => 501,
        },
      );
      assert.equal(plan.preflight.bootstrapOutputReady, false);
      assert.match(plan.preflight.bootstrapOutputError ?? '', /must not be writable by group\/other/);
    },
  );
});

test('createWalletSetupPlan preview guards cover non-writable directories and unsafe ancestors', async () => {
  const walletSetup = await import(
    walletSetupModulePath.href + `?case=${Date.now()}-preview-guard-branches`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-plan-'));
  const nonWritableDir = path.join(tempRoot, 'locked');
  fs.mkdirSync(nonWritableDir, { recursive: true, mode: 0o500 });
  fs.chmodSync(nonWritableDir, 0o500);

  const nonWritablePlan = walletSetup.createWalletSetupPlan(
    {
      bootstrapOutputPath: path.join(nonWritableDir, 'bootstrap.json'),
    },
    {
      readConfig: () => ({ chains: {} }),
      assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    },
  );
  assert.equal(nonWritablePlan.preflight.bootstrapOutputReady, false);
  assert.match(
    nonWritablePlan.preflight.bootstrapOutputError ?? '',
    /must be writable by the current process/,
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === '/virtual/preview') {
          return mockStats({ uid: 0, mode: 0o700, file: true });
        }
        if (resolved === '/virtual' || resolved === '/') {
          return mockStats({ uid: 0, mode: 0o700, directory: true });
        }
        const error = new Error('missing');
        error.code = 'ENOENT';
        throw error;
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
      accessSync: () => {},
    },
    () => {
      const plan = walletSetup.createWalletSetupPlan(
        {
          bootstrapOutputPath: '/virtual/preview/bootstrap.json',
        },
        {
          readConfig: () => ({ chains: {} }),
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      );
      assert.equal(plan.preflight.bootstrapOutputReady, false);
      assert.match(plan.preflight.bootstrapOutputError ?? '', /must be a directory/);
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === '/virtual/preview') {
          return mockStats({ uid: 0, mode: 0o700, directory: true });
        }
        if (resolved === '/virtual') {
          return mockStats({ uid: 0, mode: 0o600, file: true });
        }
        if (resolved === '/') {
          return mockStats({ uid: 0, mode: 0o700, directory: true });
        }
        const error = new Error('missing');
        error.code = 'ENOENT';
        throw error;
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
      accessSync: () => {},
    },
    () => {
      const plan = walletSetup.createWalletSetupPlan(
        {
          bootstrapOutputPath: '/virtual/preview/bootstrap.json',
        },
        {
          readConfig: () => ({ chains: {} }),
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      );
      assert.equal(plan.preflight.bootstrapOutputReady, false);
      assert.match(plan.preflight.bootstrapOutputError ?? '', /must be a directory/);
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === '/virtual/preview') {
          return mockStats({ uid: 0, mode: 0o700, directory: true });
        }
        if (resolved === '/virtual') {
          return mockStats({ uid: 0, mode: 0o777, directory: true });
        }
        if (resolved === '/') {
          return mockStats({ uid: 0, mode: 0o700, directory: true });
        }
        const error = new Error('missing');
        error.code = 'ENOENT';
        throw error;
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
      accessSync: () => {},
    },
    () => {
      const plan = walletSetup.createWalletSetupPlan(
        {
          bootstrapOutputPath: '/virtual/preview/bootstrap.json',
        },
        {
          readConfig: () => ({ chains: {} }),
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      );
      assert.equal(plan.preflight.bootstrapOutputReady, false);
      assert.match(plan.preflight.bootstrapOutputError ?? '', /must not be writable by group\/other/);
    },
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('createWalletSetupPlan preflight covers mocked fs edge branches and interactive note rendering', async () => {
  const walletSetup = await import(walletSetupModulePath.href + `?case=${Date.now()}-plan-preflight-edges`);
  const virtualBootstrapPath = '/virtual/preview/bootstrap.json';

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === '/virtual') {
          const error = new Error('lstat boom');
          error.code = 'EIO';
          throw error;
        }
        const error = new Error('missing');
        error.code = 'ENOENT';
        throw error;
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      const plan = walletSetup.createWalletSetupPlan(
        {
          bootstrapOutputPath: virtualBootstrapPath,
        },
        {
          readConfig: () => ({ chains: {} }),
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      );
      assert.equal(plan.preflight.bootstrapOutputReady, false);
      assert.match(plan.preflight.bootstrapOutputError ?? '', /lstat boom/);
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === '/virtual/preview') {
          return {
            uid: 0,
            mode: 0o777,
            isDirectory: () => true,
            isFile: () => false,
            isSocket: () => false,
            isSymbolicLink: () => false,
          };
        }
        if (resolved === '/virtual' || resolved === '/') {
          return {
            uid: 0,
            mode: 0o700,
            isDirectory: () => true,
            isFile: () => false,
            isSocket: () => false,
            isSymbolicLink: () => false,
          };
        }
        const error = new Error('missing');
        error.code = 'ENOENT';
        throw error;
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
      accessSync: () => {},
    },
    () => {
      const plan = walletSetup.createWalletSetupPlan(
        {
          bootstrapOutputPath: virtualBootstrapPath,
        },
        {
          readConfig: () => ({ chains: {} }),
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
          getEffectiveUid: () => 501,
        },
      );
      assert.equal(plan.preflight.bootstrapOutputReady, false);
      assert.match(plan.preflight.bootstrapOutputError ?? '', /must not be writable by group\/other/);
    },
  );

  assert.throws(
    () =>
      walletSetup.createWalletSetupPlan(
        {
          rpcUrl: 'https://rpc.example',
        },
        {
          readConfig: () => ({ chains: {} }),
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /--rpc-url requires --network/,
  );
  assert.throws(
    () =>
      walletSetup.createWalletSetupPlan(
        {
          chainName: 'mainnet',
        },
        {
          readConfig: () => ({ chains: {} }),
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /--chain-name requires --network/,
  );

  const interactivePlan = walletSetup.createWalletSetupPlan(
    {},
    {
      readConfig: () => ({ chains: {} }),
      assertTrustedDaemonSocketPath: (targetPath) => targetPath,
      env: {},
      stdinIsTty: true,
      stderrIsTty: true,
      getEffectiveUid: () => 501,
    },
  );
  assert.equal(interactivePlan.adminAccess.mode, 'interactive-prompt');
  assert.match(
    interactivePlan.security.notes.join('\n'),
    /local tty is expected so a human can enter the vault password securely/i,
  );
});

test('completeWalletSetup mismatch validation covers required/optional/network-scope branches', async () => {
  const walletSetup = await import(walletSetupModulePath.href + `?case=${Date.now()}-mismatch-branches`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-setup-mismatch-'));
  const bootstrapPath = path.join(tempRoot, 'exports', 'bootstrap.json');
  const daemonSocket = path.join(tempRoot, 'home', 'run', 'daemon.sock');
  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');
  fs.mkdirSync(path.dirname(daemonSocket), { recursive: true, mode: 0o700 });

  writePrivateJsonFile(bootstrapPath, bootstrapPayload());
  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: bootstrapPath,
          cleanupAction: 'deleted',
          perTxMaxWei: '1',
          daemonSocket,
        },
        {
          platform: 'darwin',
          storeAgentAuthToken: () => {},
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /perTxMaxWei does not match the requested wallet setup limit/,
  );

  writePrivateJsonFile(
    bootstrapPath,
    bootstrapPayload({
      daily_max_tx_count: '9',
      daily_tx_count_policy_id: 'daily-count-policy',
    }),
  );
  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: bootstrapPath,
          cleanupAction: 'deleted',
          dailyMaxTxCount: '5',
          daemonSocket,
        },
        {
          platform: 'darwin',
          storeAgentAuthToken: () => {},
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /dailyMaxTxCount does not match the requested wallet setup limit/,
  );

  writePrivateJsonFile(bootstrapPath, bootstrapPayload({ network_scope: 'all networks' }));
  assert.throws(
    () =>
      walletSetup.completeWalletSetup(
        {
          bootstrapOutputPath: bootstrapPath,
          cleanupAction: 'deleted',
          network: 1,
          daemonSocket,
        },
        {
          platform: 'darwin',
          storeAgentAuthToken: () => {},
          assertTrustedDaemonSocketPath: (targetPath) => targetPath,
        },
      ),
    /network_scope does not match the requested wallet setup scope/,
  );

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});
