import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';

const modulePath = new URL('../src/lib/admin-reset.ts', import.meta.url);
const walletProfileModulePath = new URL('../src/lib/wallet-profile.ts', import.meta.url);

const TEST_AGENT_KEY_ID = '00000000-0000-0000-0000-000000000001';
const PATH_SHIM_MARKER = '# agentpay-sdk one-click PATH shim';

function writeExecutable(targetPath, body) {
  fs.writeFileSync(targetPath, `#!/bin/sh\n${body}\n`, { mode: 0o755 });
}

async function withIsolatedHome(fn) {
  const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-admin-reset-cli-'));
  const agentpayHome = path.join(homeDir, '.agentpay');
  const rustBinDir = path.join(agentpayHome, 'bin');
  const toolDir = path.join(homeDir, 'tools');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(agentpayHome, { recursive: true, mode: 0o700 });
  fs.mkdirSync(toolDir, { recursive: true, mode: 0o700 });
  try {
    return await fn({ homeDir, agentpayHome, rustBinDir, toolDir });
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
}

async function withMockedPrompt(answer, fn, options = {}) {
  const originalCreateInterface = readline.createInterface;
  const stdinDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
  const stdoutDescriptor = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
  const stderrDescriptor = Object.getOwnPropertyDescriptor(process.stderr, 'isTTY');
  const rawModeDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'setRawMode');
  const isRawDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'isRaw');
  Object.defineProperty(process.stdin, 'isTTY', { value: true, configurable: true });
  Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });
  Object.defineProperty(process.stderr, 'isTTY', { value: true, configurable: true });
  Object.defineProperty(process.stdin, 'isRaw', {
    value: false,
    writable: true,
    configurable: true,
  });
  Object.defineProperty(process.stdin, 'setRawMode', {
    value: (mode) => {
      process.stdin.isRaw = mode;
      if (mode) {
        process.nextTick(() => {
          process.stdin.emit('data', Buffer.from(answer, 'utf8'));
          process.stdin.emit('data', Buffer.from('\r', 'utf8'));
        });
      }
      return process.stdin;
    },
    configurable: true,
  });
  readline.createInterface = (() => ({
    output: {
      write() {
        return true;
      },
    },
    question(_query, callback) {
      callback(answer);
    },
    close() {},
  }));
  try {
    await fn([]);
  } finally {
    readline.createInterface = originalCreateInterface;
    if (stdinDescriptor) {
      Object.defineProperty(process.stdin, 'isTTY', stdinDescriptor);
    } else {
      delete process.stdin.isTTY;
    }
    if (stdoutDescriptor) {
      Object.defineProperty(process.stdout, 'isTTY', stdoutDescriptor);
    } else {
      delete process.stdout.isTTY;
    }
    if (stderrDescriptor) {
      Object.defineProperty(process.stderr, 'isTTY', stderrDescriptor);
    } else {
      delete process.stderr.isTTY;
    }
    if (rawModeDescriptor) {
      Object.defineProperty(process.stdin, 'setRawMode', rawModeDescriptor);
    } else {
      delete process.stdin.setRawMode;
    }
    if (isRawDescriptor) {
      Object.defineProperty(process.stdin, 'isRaw', isRawDescriptor);
    } else {
      delete process.stdin.isRaw;
    }
  }
}

async function withStderrTty(fn) {
  const stderrDescriptor = Object.getOwnPropertyDescriptor(process.stderr, 'isTTY');
  Object.defineProperty(process.stderr, 'isTTY', { value: true, configurable: true });
  try {
    await fn();
  } finally {
    if (stderrDescriptor) {
      Object.defineProperty(process.stderr, 'isTTY', stderrDescriptor);
    } else {
      delete process.stderr.isTTY;
    }
  }
}

test('cleanupLocalAdminResetState clears wallet credentials but preserves non-secret config by default', async () => {
  const reset = await import(modulePath.href + `?case=${Date.now()}-preserve`);
  let configState = {
    agentKeyId: TEST_AGENT_KEY_ID,
    agentAuthToken: 'legacy-config-token',
    chainId: 1,
    chainName: 'eth',
    rpcUrl: 'https://rpc.ethereum.example',
    daemonSocket: '/Library/AgentPay/run/daemon.sock',
    stateFile: '/var/db/agentpay/daemon-state.enc',
    rustBinDir: '/trusted/bin',
    wallet: {
      vaultKeyId: 'vault-key-id',
      vaultPublicKey: '03abcdef',
      address: '0x0000000000000000000000000000000000000001',
      agentKeyId: TEST_AGENT_KEY_ID,
      policyAttachment: 'policy_set',
      attachedPolicyIds: ['policy-1'],
    },
    chains: {},
  };
  const clearedKeys = [];
  let deletedConfigPath = null;

  const result = reset.cleanupLocalAdminResetState({ deleteConfig: false }, {
    platform: 'darwin',
    existsSync: (targetPath) => targetPath === '/tmp/config.json' || targetPath === '/tmp/home',
    resolveConfigPath: () => '/tmp/config.json',
    resolveAgentPayHome: () => '/tmp/home',
    readConfig: () => ({ ...configState }),
    deleteConfigKey: (key) => {
      clearedKeys.push(key);
      const next = { ...configState };
      delete next[key];
      configState = next;
      return { ...configState };
    },
    deleteAgentAuthToken: (agentKeyId) => {
      assert.equal(agentKeyId, TEST_AGENT_KEY_ID);
      return true;
    },
    unlinkSync: (targetPath) => {
      deletedConfigPath = targetPath;
    },
    cleanupBootstrapArtifacts: () => ({
      agentpayHome: '/tmp/home',
      action: 'deleted',
      files: [
        { path: '/tmp/home/bootstrap-1-1.json', status: 'plaintext', agentKeyId: TEST_AGENT_KEY_ID, leaseExpiresAt: null, error: null, cleanup: 'deleted' },
        { path: '/tmp/home/bootstrap-1-2.json', status: 'invalid', agentKeyId: null, leaseExpiresAt: null, error: 'bad file', cleanup: 'skipped' },
      ],
    }),
  });

  assert.equal(result.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(result.keychain.removed, true);
  assert.equal(result.keychain.service, 'agentpay-agent-auth-token');
  assert.deepEqual(clearedKeys, ['agentKeyId', 'agentAuthToken', 'wallet']);
  assert.equal(deletedConfigPath, null);
  assert.equal(result.config.existed, true);
  assert.equal(result.config.deleted, false);
  assert.equal(result.config.clearedAgentKeyId, true);
  assert.equal(result.config.clearedLegacyAgentAuthToken, true);
  assert.equal(result.config.clearedWalletMetadata, true);
  assert.equal(result.config.value.chainId, 1);
  assert.equal(result.config.value.agentKeyId, undefined);
  assert.equal(result.config.value.agentAuthToken, undefined);
  assert.equal(result.config.value.wallet, undefined);
  assert.equal(result.bootstrapArtifacts.attempted, true);
  assert.equal(result.bootstrapArtifacts.fileCount, 2);
  assert.equal(result.bootstrapArtifacts.cleanedCount, 1);
  assert.equal(result.bootstrapArtifacts.skippedCount, 1);
});

test('cleanupLocalAdminResetState can delete the whole config file', async () => {
  const reset = await import(modulePath.href + `?case=${Date.now()}-delete-config`);
  const configState = {
    agentKeyId: TEST_AGENT_KEY_ID,
    agentAuthToken: 'legacy-config-token',
    chainId: 1,
    daemonSocket: '/Library/AgentPay/run/daemon.sock',
    stateFile: '/var/db/agentpay/daemon-state.enc',
    rustBinDir: '/trusted/bin',
    chains: {},
  };
  const clearedKeys = [];
  const deletedPaths = [];

  const result = reset.cleanupLocalAdminResetState({ deleteConfig: true }, {
    platform: 'darwin',
    existsSync: (targetPath) => targetPath === '/tmp/config.json' || targetPath === '/tmp/home',
    resolveConfigPath: () => '/tmp/config.json',
    resolveAgentPayHome: () => '/tmp/home',
    readConfig: () => ({ ...configState }),
    deleteConfigKey: (key) => {
      clearedKeys.push(key);
      return { ...configState };
    },
    deleteAgentAuthToken: () => true,
    unlinkSync: (targetPath) => {
      deletedPaths.push(targetPath);
    },
    cleanupBootstrapArtifacts: () => ({
      agentpayHome: '/tmp/home',
      action: 'deleted',
      files: [],
    }),
  });

  assert.equal(result.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(result.keychain.removed, true);
  assert.deepEqual(clearedKeys, []);
  assert.deepEqual(deletedPaths, ['/tmp/config.json']);
  assert.equal(result.config.deleted, true);
  assert.equal(result.config.value, null);
});

test('cleanupLocalAdminResetState falls back to wallet.agentKeyId when top-level agentKeyId is absent', async () => {
  const reset = await import(modulePath.href + `?case=${Date.now()}-wallet-agent-key-id`);
  let removedAgentKeyId = null;
  let configState = {
    chainId: 1,
    chains: {},
    wallet: {
      vaultKeyId: 'vault-key-id',
      vaultPublicKey: '03abcdef',
      address: '0x0000000000000000000000000000000000000001',
      agentKeyId: TEST_AGENT_KEY_ID,
      policyAttachment: 'policy_set',
    },
  };

  const result = reset.cleanupLocalAdminResetState({ deleteConfig: false }, {
    platform: 'darwin',
    existsSync: (targetPath) => targetPath === '/tmp/config.json' || targetPath === '/tmp/home',
    resolveConfigPath: () => '/tmp/config.json',
    resolveAgentPayHome: () => '/tmp/home',
    readConfig: () => ({ ...configState }),
    deleteConfigKey: (key) => {
      assert.equal(key, 'wallet');
      const next = { ...configState };
      delete next[key];
      configState = next;
      return { ...configState };
    },
    deleteAgentAuthToken: (agentKeyId) => {
      removedAgentKeyId = agentKeyId;
      return true;
    },
    cleanupBootstrapArtifacts: () => ({
      agentpayHome: '/tmp/home',
      action: 'deleted',
      files: [],
    }),
  });

  assert.equal(result.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(removedAgentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(result.keychain.removed, true);
  assert.equal(result.config.clearedAgentKeyId, false);
  assert.equal(result.config.clearedWalletMetadata, true);
  assert.equal(result.config.value.wallet, undefined);
});

test('cleanupLocalAdminUninstallState removes the entire AgentPay home and clears the stored token', async () => {
  const reset = await import(modulePath.href + `?case=${Date.now()}-uninstall-home`);
  const removedPaths = [];

  const result = reset.cleanupLocalAdminUninstallState({
    platform: 'darwin',
    existsSync: (targetPath) => targetPath === '/tmp/home/config.json' || targetPath === '/tmp/home',
    resolveConfigPath: () => '/tmp/home/config.json',
    resolveAgentPayHome: () => '/tmp/home',
    readConfig: () => ({
      agentKeyId: TEST_AGENT_KEY_ID,
      chainId: 56,
      chains: {},
    }),
    deleteAgentAuthToken: (agentKeyId) => {
      assert.equal(agentKeyId, TEST_AGENT_KEY_ID);
      return true;
    },
    rmSync: (targetPath, options) => {
      removedPaths.push([targetPath, options]);
    },
  });

  assert.equal(result.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(result.keychain.removed, true);
  assert.equal(result.keychain.service, 'agentpay-agent-auth-token');
  assert.equal(result.config.existed, true);
  assert.equal(result.config.deleted, true);
  assert.equal(result.agentpayHome.existed, true);
  assert.equal(result.agentpayHome.deleted, true);
  assert.deepEqual(removedPaths, [
    ['/tmp/home', { recursive: true, force: true }],
  ]);
});

test('cleanupLocalAdminUninstallState removes config separately when it lives outside AgentPay home', async () => {
  const reset = await import(modulePath.href + `?case=${Date.now()}-uninstall-external-config`);
  const removedPaths = [];

  const result = reset.cleanupLocalAdminUninstallState({
    platform: 'darwin',
    existsSync: (targetPath) =>
      targetPath === '/tmp/config.json' || targetPath === '/tmp/home',
    resolveConfigPath: () => '/tmp/config.json',
    resolveAgentPayHome: () => '/tmp/home',
    readConfig: () => ({
      agentKeyId: TEST_AGENT_KEY_ID,
      chains: {},
    }),
    deleteAgentAuthToken: () => true,
    rmSync: (targetPath, options) => {
      removedPaths.push([targetPath, options]);
    },
  });

  assert.equal(result.config.deleted, true);
  assert.equal(result.agentpayHome.deleted, true);
  assert.deepEqual(removedPaths, [
    ['/tmp/config.json', { recursive: true, force: true }],
    ['/tmp/home', { recursive: true, force: true }],
  ]);
});

test('cleanupLocalAdminUninstallState reverses one-click shell exports, AI skills, cursor adapters, and empty install roots', async () => {
  const reset = await import(modulePath.href + `?case=${Date.now()}-uninstall-one-click-cleanup`);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-one-click-uninstall-'));
  const homeDir = path.join(root, 'home');
  const installRoot = path.join(root, 'install-root');
  const agentpayHome = path.join(installRoot, 'agentpay-home');
  const shimDir = path.join(root, 'path-bin');
  const shimPath = path.join(shimDir, 'agentpay');
  const cursorWorkspace = path.join(root, 'workspace');
  const zshrcPath = path.join(homeDir, '.zshrc');
  const configPath = path.join(agentpayHome, 'config.json');
  const manifestPath = path.join(agentpayHome, 'one-click-install-manifest.json');
  const codexSkillPath = path.join(homeDir, '.codex', 'skills', 'agentpay-sdk');
  const genericSkillPath = path.join(homeDir, '.agents', 'skills', 'agentpay-sdk');
  const claudeSkillPath = path.join(homeDir, '.claude', 'skills', 'agentpay-sdk');
  const cursorRulePath = path.join(cursorWorkspace, '.cursor', 'rules', 'agentpay-sdk.mdc');
  const cursorAgentsPath = path.join(cursorWorkspace, 'AGENTS.md');

  try {
    fs.mkdirSync(path.dirname(configPath), { recursive: true, mode: 0o700 });
    fs.mkdirSync(codexSkillPath, { recursive: true, mode: 0o700 });
    fs.mkdirSync(genericSkillPath, { recursive: true, mode: 0o700 });
    fs.mkdirSync(claudeSkillPath, { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.dirname(cursorRulePath), { recursive: true, mode: 0o700 });
    fs.mkdirSync(homeDir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(shimDir, { recursive: true, mode: 0o700 });

    fs.writeFileSync(
      zshrcPath,
      [
        'export FOO=bar',
        '# >>> agentpay-sdk >>>',
        `export AGENTPAY_HOME="${agentpayHome}"`,
        'export PATH="$AGENTPAY_HOME/bin:$PATH"',
        '# <<< agentpay-sdk <<<',
        'export BAR=baz',
        '',
      ].join('\n'),
      'utf8',
    );
    fs.writeFileSync(configPath, `${JSON.stringify({ agentKeyId: TEST_AGENT_KEY_ID, chains: {} }, null, 2)}\n`, 'utf8');
    fs.writeFileSync(
      manifestPath,
      `${JSON.stringify(
        {
          version: 1,
          installRoot,
          agentpayHome,
          shellRcPath: zshrcPath,
          skillTargets: [codexSkillPath, genericSkillPath, claudeSkillPath],
          cursorArtifactPaths: [cursorRulePath, cursorAgentsPath],
          pathShimPaths: [shimPath],
        },
        null,
        2,
      )}\n`,
      'utf8',
    );
    fs.writeFileSync(path.join(codexSkillPath, 'SKILL.md'), '# codex\n', 'utf8');
    fs.writeFileSync(path.join(genericSkillPath, 'SKILL.md'), '# agents\n', 'utf8');
    fs.writeFileSync(path.join(claudeSkillPath, 'SKILL.md'), '# claude\n', 'utf8');
    fs.writeFileSync(cursorRulePath, '# cursor rule\n', 'utf8');
    fs.writeFileSync(cursorAgentsPath, '# generated agents file\n', 'utf8');
    fs.writeFileSync(
      shimPath,
      `#!/bin/sh\n${PATH_SHIM_MARKER}\nset -eu\nexec "${agentpayHome}/bin/agentpay" "$@"\n`,
      'utf8',
    );

    const result = reset.cleanupLocalAdminUninstallState({
      platform: 'darwin',
      resolveConfigPath: () => configPath,
      resolveAgentPayHome: () => agentpayHome,
      readConfig: () => ({
        agentKeyId: TEST_AGENT_KEY_ID,
        chains: {},
      }),
      deleteAgentAuthToken: (agentKeyId) => {
        assert.equal(agentKeyId, TEST_AGENT_KEY_ID);
        return true;
      },
      homedir: () => homeDir,
    });

    assert.equal(result.agentpayHome.deleted, true);
    assert.equal(result.oneClickInstaller.manifest.existed, true);
    assert.equal(result.oneClickInstaller.manifest.removedWithAgentPayHome, true);
    assert.deepEqual(result.oneClickInstaller.shellRcFilesUpdated, [zshrcPath]);
    assert.deepEqual(result.oneClickInstaller.skillTargetsRemoved.sort(), [
      genericSkillPath,
      claudeSkillPath,
      codexSkillPath,
    ]);
    assert.deepEqual(result.oneClickInstaller.cursorArtifactsRemoved.sort(), [
      cursorRulePath,
      cursorAgentsPath,
    ]);
    assert.deepEqual(result.oneClickInstaller.pathShimsRemoved, [shimPath]);
    assert.equal(result.oneClickInstaller.installRoot.path, installRoot);
    assert.equal(result.oneClickInstaller.installRoot.removed, true);

    assert.equal(fs.existsSync(agentpayHome), false);
    assert.equal(fs.existsSync(installRoot), false);
    assert.equal(fs.existsSync(codexSkillPath), false);
    assert.equal(fs.existsSync(genericSkillPath), false);
    assert.equal(fs.existsSync(claudeSkillPath), false);
    assert.equal(fs.existsSync(shimPath), false);
    assert.equal(fs.existsSync(cursorRulePath), false);
    assert.equal(fs.existsSync(cursorAgentsPath), false);
    assert.equal(fs.existsSync(path.join(cursorWorkspace, '.cursor')), false);
    const zshrc = fs.readFileSync(zshrcPath, 'utf8');
    assert.match(zshrc, /export FOO=bar/u);
    assert.match(zshrc, /export BAR=baz/u);
    assert.doesNotMatch(zshrc, /# >>> agentpay-sdk >>>/u);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('cleanupLocalAdminUninstallState treats installRoot equal to AgentPay home as removed with the same delete', async () => {
  const reset = await import(modulePath.href + `?case=${Date.now()}-uninstall-same-root`);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-one-click-same-root-'));
  const agentpayHome = path.join(root, '.agentpay');
  const configPath = path.join(agentpayHome, 'config.json');
  const manifestPath = path.join(agentpayHome, 'one-click-install-manifest.json');

  try {
    fs.mkdirSync(agentpayHome, { recursive: true, mode: 0o700 });
    fs.writeFileSync(configPath, `${JSON.stringify({ agentKeyId: TEST_AGENT_KEY_ID, chains: {} }, null, 2)}\n`, 'utf8');
    fs.writeFileSync(
      manifestPath,
      `${JSON.stringify(
        {
          version: 1,
          installRoot: agentpayHome,
          agentpayHome,
          shellRcPath: null,
          skillTargets: [],
          cursorArtifactPaths: [],
          pathShimPaths: [],
        },
        null,
        2,
      )}\n`,
      'utf8',
    );

    const result = reset.cleanupLocalAdminUninstallState({
      platform: 'darwin',
      resolveConfigPath: () => configPath,
      resolveAgentPayHome: () => agentpayHome,
      deleteAgentAuthToken: () => true,
      homedir: () => root,
    });

    assert.equal(result.agentpayHome.deleted, true);
    assert.equal(result.oneClickInstaller.installRoot.path, agentpayHome);
    assert.equal(result.oneClickInstaller.installRoot.removed, true);
    assert.equal(result.oneClickInstaller.installRoot.skippedReason, null);
    assert.equal(fs.existsSync(agentpayHome), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('cleanupLocalAdminResetState reports no bootstrap cleanup when AgentPay home is missing', async () => {
  const reset = await import(modulePath.href + `?case=${Date.now()}-reset-no-agentpay-home`);

  const result = reset.cleanupLocalAdminResetState({}, {
    platform: 'darwin',
    existsSync: (targetPath) => targetPath === '/tmp/config.json',
    resolveConfigPath: () => '/tmp/config.json',
    resolveAgentPayHome: () => '/tmp/home',
    readConfig: () => ({
      chainId: 1,
      chains: {},
    }),
    deleteConfigKey: () => ({}),
    deleteAgentAuthToken: () => false,
    unlinkSync: () => {},
    cleanupBootstrapArtifacts: () => {
      throw new Error('should not run when agentpayHome is missing');
    },
  });

  assert.equal(result.bootstrapArtifacts.attempted, false);
  assert.equal(result.bootstrapArtifacts.fileCount, 0);
  assert.equal(result.bootstrapArtifacts.error, null);
});

test('cleanupLocalAdminResetState tolerates missing config and non-macOS keychain helpers', async () => {
  const reset = await import(modulePath.href + `?case=${Date.now()}-reset-missing-config-linux`);

  const result = reset.cleanupLocalAdminResetState({}, {
    platform: 'linux',
    existsSync: (targetPath) => targetPath === '/tmp/home',
    resolveConfigPath: () => '/tmp/config.json',
    resolveAgentPayHome: () => '/tmp/home',
    readConfig: () => {
      throw new Error('readConfig should not run when config is missing');
    },
    deleteConfigKey: () => {
      throw new Error('deleteConfigKey should not run when config is missing');
    },
    deleteAgentAuthToken: () => {
      throw new Error('deleteAgentAuthToken should not run when config is missing');
    },
    unlinkSync: () => {
      throw new Error('unlinkSync should not run when config is missing');
    },
    cleanupBootstrapArtifacts: () => ({
      agentpayHome: '/tmp/home',
      action: 'deleted',
      files: [],
    }),
  });

  assert.equal(result.agentKeyId, null);
  assert.equal(result.keychain.removed, false);
  assert.equal(result.keychain.service, null);
  assert.equal(result.config.existed, false);
  assert.equal(result.config.deleted, false);
  assert.equal(result.config.value, null);
});

test('cleanupLocalAdminResetState captures bootstrap cleanup errors as warnings', async () => {
  const reset = await import(modulePath.href + `?case=${Date.now()}-reset-bootstrap-cleanup-error`);

  const result = reset.cleanupLocalAdminResetState({}, {
    platform: 'darwin',
    existsSync: () => true,
    resolveConfigPath: () => '/tmp/config.json',
    resolveAgentPayHome: () => '/tmp/home',
    readConfig: () => ({
      chainId: 1,
      chains: {},
    }),
    deleteConfigKey: () => ({}),
    deleteAgentAuthToken: () => false,
    unlinkSync: () => {},
    cleanupBootstrapArtifacts: () => {
      throw 'mock bootstrap cleanup failure';
    },
  });

  assert.equal(result.bootstrapArtifacts.attempted, true);
  assert.equal(result.bootstrapArtifacts.error, 'mock bootstrap cleanup failure');
});

test('cleanupLocalAdminUninstallState reports non-macOS service fallback', async () => {
  const reset = await import(modulePath.href + `?case=${Date.now()}-uninstall-linux-service-null`);

  const result = reset.cleanupLocalAdminUninstallState({
    platform: 'linux',
    existsSync: () => false,
    resolveConfigPath: () => '/tmp/config.json',
    resolveAgentPayHome: () => '/tmp/home',
    readConfig: () => {
      throw new Error('readConfig should not run when config is missing');
    },
    deleteAgentAuthToken: () => {
      throw new Error('deleteAgentAuthToken should not run when config is missing');
    },
    rmSync: () => {
      throw new Error('rmSync should not run when files are missing');
    },
  });

  assert.equal(result.agentKeyId, null);
  assert.equal(result.keychain.removed, false);
  assert.equal(result.keychain.service, null);
  assert.equal(result.config.existed, false);
  assert.equal(result.agentpayHome.existed, false);
});

test('managedDaemonResetArtifactPaths includes the relay daemon token file', async () => {
  const reset = await import(modulePath.href + `?case=${Date.now()}-reset-artifacts`);

  assert.deepEqual(reset.managedDaemonResetArtifactPaths(), [
    '/var/db/agentpay/daemon-state.enc',
    '/Library/AgentPay/run/daemon.sock',
    '/var/db/agentpay/relay-daemon-token',
  ]);
});

test('runAdminResetCli enforces confirmation in non-interactive and prompt-abort paths', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome }) => {
    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    fs.writeFileSync(path.join(agentpayHome, 'config.json'), `${JSON.stringify({ chains: {} }, null, 2)}\n`, {
      mode: 0o600,
    });

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-reset-confirmation-guards`);
      await assert.rejects(
        () => reset.runAdminResetCli(['--non-interactive']),
        /requires --yes in non-interactive mode/,
      );
      await assert.rejects(
        () => reset.runAdminResetCli([]),
        /requires --yes in non-interactive environments/,
      );

      await withMockedPrompt('NOPE', async () => {
        await assert.rejects(
          () => reset.runAdminResetCli([]),
          /admin reset aborted/,
        );
      });
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
    }
  });
});

test('runAdminResetCli requires a local tty before prompting for the hidden root password', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-n" ]; then',
        '  exit 1',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    fs.writeFileSync(
      path.join(agentpayHome, 'config.json'),
      `${JSON.stringify({ rustBinDir, chains: {} }, null, 2)}\n`,
      { mode: 0o600 },
    );

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = `${toolDir}:${originalPath ?? ''}`;

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-reset-hidden-password-no-tty`);
      await assert.rejects(
        () => reset.runAdminResetCli(['--yes']),
        /macOS admin password for sudo is required; rerun on a local TTY/u,
      );
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
    }
  });
});

test('runAdminResetCli validates prompted hidden root passwords before sudo prime succeeds', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-n" ]; then',
        '  exit 1',
        'fi',
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  exit 0',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    fs.writeFileSync(
      path.join(agentpayHome, 'config.json'),
      `${JSON.stringify({ rustBinDir, chains: {} }, null, 2)}\n`,
      { mode: 0o600 },
    );

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = toolDir;

    try {
      const blankReset = await import(`${modulePath.href}?case=${Date.now()}-reset-blank-hidden-password`);
      await withMockedPrompt('   ', async () => {
        await assert.rejects(
          () => blankReset.runAdminResetCli(['--yes']),
          /macOS admin password for sudo must not be empty or whitespace/u,
        );
      });

      const oversizedReset = await import(
        `${modulePath.href}?case=${Date.now()}-reset-oversized-hidden-password`
      );
      await withMockedPrompt('x'.repeat(17_000), async () => {
        await assert.rejects(
          () => oversizedReset.runAdminResetCli(['--yes']),
          /macOS admin password for sudo must not exceed 16384 bytes/u,
        );
      });
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
    }
  });
});

test('runAdminResetCli does not echo the hidden sudo password to stdout', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-n" ]; then',
        '  exit 1',
        'fi',
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  exit 0',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    fs.writeFileSync(
      path.join(agentpayHome, 'config.json'),
      `${JSON.stringify({ rustBinDir, chains: {} }, null, 2)}\n`,
      { mode: 0o600 },
    );

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = `${toolDir}:${originalPath ?? ''}`;

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-reset-hidden-password-unmuted-echo`);
      let rendered = '';
      const originalStderrWrite = process.stderr.write.bind(process.stderr);
      try {
        process.stderr.write = ((chunk, ...args) => {
          rendered += String(chunk);
          return originalStderrWrite(chunk, ...args);
        });
        await withMockedPrompt(
          'root-password',
          async () => {
            await assert.rejects(
              () => reset.runAdminResetCli(['--yes', '--non-interactive']),
              /failed to uninstall managed daemon \(exit code 1\)/u,
            );
          },
        );
      } finally {
        process.stderr.write = originalStderrWrite;
      }
      assert.doesNotMatch(rendered, /root-password/u);
      assert.match(
        rendered,
        /macOS admin password for sudo \(input hidden; required to uninstall the root daemon and delete its state\): /u,
      );
      assert.match(rendered, /\n/u);
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
    }
  });
});

test('runAdminResetCli executes the reset workflow with staged launchd helper scripts', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const configPath = path.join(agentpayHome, 'config.json');
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  exit 0',
        'fi',
        'if [ "$1" = "-n" ] && [ "$2" = "/bin/test" ]; then',
        '  exit 1',
        'fi',
        'if [ "$1" = "-n" ]; then',
          '  exit 0',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    fs.writeFileSync(
      configPath,
      `${JSON.stringify(
        {
          rustBinDir,
          chains: {},
        },
        null,
        2,
      )}\n`,
      { mode: 0o600 },
    );

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    const stderrChunks = [];
    const stdoutChunks = [];
    const originalStderrWrite = process.stderr.write.bind(process.stderr);
    const originalStdoutWrite = process.stdout.write.bind(process.stdout);

    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = `${toolDir}:${originalPath ?? ''}`;
    process.stderr.write = ((chunk, ...args) => {
      stderrChunks.push(String(chunk));
      return originalStderrWrite(chunk, ...args);
    });
    process.stdout.write = ((chunk, ...args) => {
      stdoutChunks.push(String(chunk));
      return originalStdoutWrite(chunk, ...args);
    });

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-run-cli-reset`);
      await withMockedPrompt('root-password', async () => {
        await reset.runAdminResetCli(['--yes', '--non-interactive']);
      });
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
      process.stderr.write = originalStderrWrite;
      process.stdout.write = originalStdoutWrite;
    }

    assert.match(stderrChunks.join(''), /Managed daemon uninstalled/u);
    assert.match(stderrChunks.join(''), /Root-managed daemon state deleted/u);
    assert.match(stdoutChunks.join(''), /reset complete/u);
    assert.equal(fs.existsSync(configPath), true);
  });
});

test('runAdminResetCli removes persisted wallet metadata from a kept config file', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const configPath = path.join(agentpayHome, 'config.json');
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  exit 0',
        'fi',
        'if [ "$1" = "-n" ] && [ "$2" = "/bin/test" ]; then',
        '  exit 1',
        'fi',
        'if [ "$1" = "-n" ]; then',
        '  exit 0',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    fs.writeFileSync(
      configPath,
      `${JSON.stringify(
        {
          rustBinDir,
          agentKeyId: TEST_AGENT_KEY_ID,
          chains: {},
          wallet: {
            vaultKeyId: 'vault-key-id',
            vaultPublicKey: '03abcdef',
            address: '0x0000000000000000000000000000000000000001',
            agentKeyId: TEST_AGENT_KEY_ID,
            policyAttachment: 'policy_set',
            attachedPolicyIds: ['policy-1'],
          },
        },
        null,
        2,
      )}\n`,
      { mode: 0o600 },
    );

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = `${toolDir}:${originalPath ?? ''}`;

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-run-cli-reset-clears-wallet`);
      await withMockedPrompt('root-password', async () => {
        await reset.runAdminResetCli(['--yes', '--non-interactive']);
      });
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
    }

    const persisted = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    const walletProfile = await import(
      `${walletProfileModulePath.href}?case=${Date.now()}-reset-clears-wallet-profile`
    );
    assert.equal(persisted.agentKeyId, undefined);
    assert.equal(persisted.wallet, undefined);
    assert.equal(persisted.rustBinDir, rustBinDir);
    assert.throws(
      () => walletProfile.resolveWalletProfile(persisted),
      /wallet metadata is unavailable; rerun `agentpay admin setup` or import a bootstrap file first/u,
    );
  });
});

test('runAdminResetCli non-json summary reports missing config and bootstrap cleanup warnings', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  exit 0',
        'fi',
        'if [ "$1" = "-n" ] && [ "$2" = "/bin/test" ]; then',
        '  exit 1',
        'fi',
        'if [ "$1" = "-n" ]; then',
        '  exit 0',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    fs.chmodSync(agentpayHome, 0o777);
    const stdoutChunks = [];
    const originalStdoutWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((chunk, ...args) => {
      stdoutChunks.push(String(chunk));
      return originalStdoutWrite(chunk, ...args);
    });

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = `${toolDir}:${originalPath ?? ''}`;

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-run-cli-reset-summary-warning`);
      await withMockedPrompt('root-password', async () => {
        await reset.runAdminResetCli(['--yes', '--non-interactive']);
      });
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
      process.stdout.write = originalStdoutWrite;
      fs.chmodSync(agentpayHome, 0o700);
    }

    const output = stdoutChunks.join('');
    assert.match(output, /config not found:/u);
    assert.match(output, /bootstrap artifact cleanup warning:/u);
  });
});

test('runAdminResetCli emits machine-readable output on successful json reset runs', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const configPath = path.join(agentpayHome, 'config.json');
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  exit 0',
        'fi',
        'if [ "$1" = "-n" ] && [ "$2" = "/bin/test" ]; then',
        '  exit 1',
        'fi',
        'if [ "$1" = "-n" ]; then',
        '  exit 0',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    fs.writeFileSync(
      configPath,
      `${JSON.stringify({ rustBinDir, chains: {} }, null, 2)}\n`,
      { mode: 0o600 },
    );

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    const stdoutChunks = [];
    const originalStdoutWrite = process.stdout.write.bind(process.stdout);
    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = `${toolDir}:${originalPath ?? ''}`;
    process.stdout.write = ((chunk, ...args) => {
      stdoutChunks.push(
        typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'),
      );
      return originalStdoutWrite(chunk, ...args);
    });

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-run-cli-reset-json-success`);
      await withMockedPrompt('root-password', async () => {
        await reset.runAdminResetCli(['--yes', '--non-interactive', '--json']);
      });
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
      process.stdout.write = originalStdoutWrite;
    }

    const output = stdoutChunks.join('');
    assert.match(output, /"command": "reset"/u);
    assert.match(output, /"label": "com\.agentpay\.daemon"/u);
    assert.match(output, /"deleted": false/u);
  });
});

test('runAdminResetCli prefers stdout when managed state deletion fails without stderr', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  exit 0',
        'fi',
        'if [ "$1" = "-n" ] && [ "$2" = "/bin/rm" ]; then',
        "  echo 'mock rm stdout failure'",
        '  exit 7',
        'fi',
        'if [ "$1" = "-n" ]; then',
        '  exit 0',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    fs.writeFileSync(
      path.join(agentpayHome, 'config.json'),
      `${JSON.stringify({ rustBinDir, chains: {} }, null, 2)}\n`,
      { mode: 0o600 },
    );

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = `${toolDir}:${originalPath ?? ''}`;

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-run-cli-reset-rm-stdout-fail`);
      await withMockedPrompt('root-password', async () => {
        await assert.rejects(
          () => reset.runAdminResetCli(['--yes', '--non-interactive', '--json']),
          /mock rm stdout failure/u,
        );
      });
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
    }
  });
});

test('runAdminResetCli falls back to the default managed state deletion message when sudo returns no output', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  exit 0',
        'fi',
        'if [ "$1" = "-n" ] && [ "$2" = "/bin/rm" ]; then',
        '  exit 7',
        'fi',
        'if [ "$1" = "-n" ]; then',
        '  exit 0',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    fs.writeFileSync(
      path.join(agentpayHome, 'config.json'),
      `${JSON.stringify({ rustBinDir, chains: {} }, null, 2)}\n`,
      { mode: 0o600 },
    );

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = `${toolDir}:${originalPath ?? ''}`;

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-run-cli-reset-rm-default-fail`);
      await withMockedPrompt('root-password', async () => {
        await assert.rejects(
          () => reset.runAdminResetCli(['--yes', '--non-interactive', '--json']),
          /failed to delete managed daemon state \(exit code 7\)/u,
        );
      });
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
    }
  });
});

test('runAdminResetCli can delete config and print spinner progress when stderr is a tty', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const configPath = path.join(agentpayHome, 'config.json');
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  exit 0',
        'fi',
        'if [ "$1" = "-n" ] && [ "$2" = "/bin/test" ]; then',
        '  exit 1',
        'fi',
        'if [ "$1" = "-n" ]; then',
        '  exit 0',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    fs.writeFileSync(
      configPath,
      `${JSON.stringify(
        {
          rustBinDir,
          agentKeyId: TEST_AGENT_KEY_ID,
          chains: {},
        },
        null,
        2,
      )}\n`,
      { mode: 0o600 },
    );

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    const stderrChunks = [];
    const stdoutChunks = [];
    const originalStderrWrite = process.stderr.write.bind(process.stderr);
    const originalStdoutWrite = process.stdout.write.bind(process.stdout);

    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = `${toolDir}:${originalPath ?? ''}`;
    process.stderr.write = ((chunk, ...args) => {
      stderrChunks.push(String(chunk));
      return originalStderrWrite(chunk, ...args);
    });
    process.stdout.write = ((chunk, ...args) => {
      stdoutChunks.push(String(chunk));
      return originalStdoutWrite(chunk, ...args);
    });

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-run-cli-reset-delete-config`);
      await withStderrTty(async () => {
        await withMockedPrompt('root-password', async () => {
          await reset.runAdminResetCli(['--yes', '--delete-config']);
        });
      });
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
      process.stderr.write = originalStderrWrite;
      process.stdout.write = originalStdoutWrite;
    }

    assert.match(stderrChunks.join(''), /\u001b\[2K/u);
    assert.match(stdoutChunks.join(''), /config deleted:/u);
    assert.match(stdoutChunks.join(''), new RegExp(`old agent key cleared: ${TEST_AGENT_KEY_ID}`, 'u'));
    assert.equal(fs.existsSync(configPath), false);
  });
});

test('runAdminUninstallCli removes the local AgentPay home with --json output', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const configPath = path.join(agentpayHome, 'config.json');
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  exit 0',
        'fi',
        'if [ "$1" = "-n" ] && [ "$2" = "/bin/test" ]; then',
        '  exit 1',
        'fi',
        'if [ "$1" = "-n" ]; then',
        '  exit 0',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    fs.writeFileSync(
      configPath,
      `${JSON.stringify(
        {
          rustBinDir,
          chains: {},
        },
        null,
        2,
      )}\n`,
      { mode: 0o600 },
    );

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    const stdoutChunks = [];
    const originalStdoutWrite = process.stdout.write.bind(process.stdout);

    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = `${toolDir}:${originalPath ?? ''}`;
    process.stdout.write = ((chunk, ...args) => {
      stdoutChunks.push(String(chunk));
      return originalStdoutWrite(chunk, ...args);
    });

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-run-cli-uninstall`);
      await withMockedPrompt('root-password', async () => {
        await reset.runAdminUninstallCli(['--yes', '--non-interactive', '--json']);
      });
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
      process.stdout.write = originalStdoutWrite;
    }

    assert.equal(fs.existsSync(agentpayHome), false);
    assert.match(stdoutChunks.join(''), /"command": "uninstall"/u);
  });
});

test('runAdminResetCli surfaces managed state deletion failures from sudo commands', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  exit 0',
        'fi',
        'if [ "$1" = "-n" ] && [ "$2" = "/bin/rm" ]; then',
        "  echo 'mock rm failure' >&2",
        '  exit 7',
        'fi',
        'if [ "$1" = "-n" ]; then',
        '  exit 0',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    fs.writeFileSync(
      path.join(agentpayHome, 'config.json'),
      `${JSON.stringify({ rustBinDir, chains: {} }, null, 2)}\n`,
      { mode: 0o600 },
    );

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = `${toolDir}:${originalPath ?? ''}`;

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-run-cli-reset-rm-fail`);
      await withMockedPrompt('root-password', async () => {
        await assert.rejects(
          () => reset.runAdminResetCli(['--yes', '--non-interactive', '--json']),
          /mock rm failure/,
        );
      });
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
    }
  });
});

test('runAdminUninstallCli surfaces launchd uninstall failures from sudo commands', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  exit 0',
        'fi',
        'if [ "$1" = "-n" ] && [ "$2" = "' + uninstallScriptPath + '" ]; then',
        "  echo 'mock uninstall failure' >&2",
        '  exit 9',
        'fi',
        'if [ "$1" = "-n" ]; then',
        '  exit 0',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    fs.writeFileSync(
      path.join(agentpayHome, 'config.json'),
      `${JSON.stringify({ rustBinDir, chains: {} }, null, 2)}\n`,
      { mode: 0o600 },
    );

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = `${toolDir}:${originalPath ?? ''}`;

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-run-cli-uninstall-fail`);
      await withMockedPrompt('root-password', async () => {
        await assert.rejects(
          () => reset.runAdminUninstallCli(['--yes', '--non-interactive']),
          /mock uninstall failure/,
        );
      });
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
    }
  });
});

test('runAdminUninstallCli enforces explicit confirmation in non-interactive and prompt-abort flows', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  exit 0',
        'fi',
        'if [ "$1" = "-n" ] && [ "$2" = "/bin/test" ]; then',
        '  exit 1',
        'fi',
        'if [ "$1" = "-n" ]; then',
        '  exit 0',
        'fi',
        'exit 0',
      ].join('\n'),
    );

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = `${toolDir}:${originalPath ?? ''}`;

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-run-cli-uninstall-confirmation`);
      await assert.rejects(
        () => reset.runAdminUninstallCli(['--non-interactive']),
        /requires --yes in non-interactive mode/u,
      );
      await withMockedPrompt('NOPE', async () => {
        await assert.rejects(
          () => reset.runAdminUninstallCli([]),
          /admin uninstall aborted/u,
        );
      });
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
    }
  });
});

test('runAdminResetCli surfaces launchd uninstall failures before local cleanup', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  exit 0',
        'fi',
        'if [ "$1" = "-n" ] && [ "$2" = "' + uninstallScriptPath + '" ]; then',
        "  echo 'mock reset uninstall failure' >&2",
        '  exit 8',
        'fi',
        'if [ "$1" = "-n" ]; then',
        '  exit 0',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    fs.writeFileSync(
      path.join(agentpayHome, 'config.json'),
      `${JSON.stringify({ rustBinDir, chains: {} }, null, 2)}\n`,
      { mode: 0o600 },
    );

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = `${toolDir}:${originalPath ?? ''}`;

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-run-cli-reset-uninstall-fail`);
      await withMockedPrompt('root-password', async () => {
        await assert.rejects(
          () => reset.runAdminResetCli(['--yes', '--non-interactive']),
          /mock reset uninstall failure/,
        );
      });
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
    }
  });
});

test('runAdminResetCli and runAdminUninstallCli exercise tty spinner fail paths on immediate sudo execution failures', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  rm -rf "$(dirname "$(command -v "$0")")"',
        '  exit 0',
        'fi',
        'if [ "$1" = "-n" ]; then',
        '  exit 1',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    fs.writeFileSync(
      path.join(agentpayHome, 'config.json'),
      `${JSON.stringify({ rustBinDir, chains: {} }, null, 2)}\n`,
      { mode: 0o600 },
    );

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    const originalSetInterval = global.setInterval;
    const originalClearInterval = global.clearInterval;
    global.setInterval = ((callback) => {
      callback();
      return 1;
    });
    global.clearInterval = (() => {});
    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = toolDir;

    try {
      const resetCli = await import(`${modulePath.href}?case=${Date.now()}-run-cli-reset-sudo-throw`);
      await withStderrTty(async () => {
        await withMockedPrompt('root-password', async () => {
          await assert.rejects(
            () => resetCli.runAdminResetCli(['--yes']),
            /failed to uninstall managed daemon \(exit code 1\)/u,
          );
        });
      });

      writeExecutable(
        sudoScriptPath,
        [
          'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
          '  cat >/dev/null',
          '  rm -rf "$(dirname "$(command -v "$0")")"',
          '  exit 0',
          'fi',
          'if [ "$1" = "-n" ]; then',
          '  exit 1',
          'fi',
          'exit 0',
        ].join('\n'),
      );
      const uninstallCli = await import(
        `${modulePath.href}?case=${Date.now()}-run-cli-uninstall-sudo-throw`
      );
      await withStderrTty(async () => {
        await withMockedPrompt('root-password', async () => {
          await assert.rejects(
            () => uninstallCli.runAdminUninstallCli(['--yes']),
            /failed to uninstall managed daemon \(exit code 1\)/u,
          );
        });
      });
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
      global.setInterval = originalSetInterval;
      global.clearInterval = originalClearInterval;
    }
  });
});

test('runAdminUninstallCli fails when root-managed file removal returns non-zero', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  exit 0',
        'fi',
        'if [ "$1" = "-n" ] && [ "$2" = "/bin/rm" ]; then',
        "  echo 'mock root rm failure' >&2",
        '  exit 11',
        'fi',
        'if [ "$1" = "-n" ]; then',
        '  exit 0',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    fs.writeFileSync(
      path.join(agentpayHome, 'config.json'),
      `${JSON.stringify({ rustBinDir, chains: {} }, null, 2)}\n`,
      { mode: 0o600 },
    );

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = `${toolDir}:${originalPath ?? ''}`;

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-run-cli-uninstall-rm-fail`);
      await withMockedPrompt('root-password', async () => {
        await assert.rejects(
          () => reset.runAdminUninstallCli(['--yes', '--non-interactive']),
          /mock root rm failure/,
        );
      });
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
    }
  });
});

test('runAdminUninstallCli falls back to the default root artifact failure message when sudo returns no output', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  exit 0',
        'fi',
        'if [ "$1" = "-n" ] && [ "$2" = "/bin/rm" ]; then',
        '  exit 11',
        'fi',
        'if [ "$1" = "-n" ]; then',
        '  exit 0',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    fs.writeFileSync(
      path.join(agentpayHome, 'config.json'),
      `${JSON.stringify({ rustBinDir, chains: {} }, null, 2)}\n`,
      { mode: 0o600 },
    );

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = `${toolDir}:${originalPath ?? ''}`;

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-run-cli-uninstall-rm-default-fail`);
      await withMockedPrompt('root-password', async () => {
        await assert.rejects(
          () => reset.runAdminUninstallCli(['--yes', '--non-interactive']),
          /failed to delete managed root-owned files \(exit code 11\)/u,
        );
      });
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
    }
  });
});

test('runAdminUninstallCli fails when managed root-owned files still exist after uninstall cleanup', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  exit 0',
        'fi',
        'if [ "$1" = "-n" ] && [ "$2" = "/bin/test" ]; then',
        '  if [ "$4" = "/var/db/agentpay" ]; then',
        '    exit 0',
        '  fi',
        '  exit 1',
        'fi',
        'if [ "$1" = "-n" ]; then',
        '  exit 0',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    const configPath = path.join(agentpayHome, 'config.json');
    fs.writeFileSync(
      configPath,
      `${JSON.stringify({ rustBinDir, agentKeyId: TEST_AGENT_KEY_ID, chains: {} }, null, 2)}\n`,
      { mode: 0o600 },
    );

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = `${toolDir}:${originalPath ?? ''}`;

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-run-cli-uninstall-root-remnant`);
      await withMockedPrompt('root-password', async () => {
        await assert.rejects(
          () => reset.runAdminUninstallCli(['--yes', '--non-interactive']),
          /admin uninstall left managed root-owned files behind: \/var\/db\/agentpay/u,
        );
      });
      assert.equal(fs.existsSync(configPath), true);
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
    }
  });
});

test('runAdminUninstallCli fails when the local AgentPay home still exists after cleanup', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  exit 0',
        'fi',
        'if [ "$1" = "-n" ] && [ "$2" = "/bin/test" ]; then',
        '  exit 1',
        'fi',
        'if [ "$1" = "-n" ]; then',
        '  exit 0',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    const configPath = path.join(agentpayHome, 'config.json');
    fs.writeFileSync(
      configPath,
      `${JSON.stringify({ rustBinDir, agentKeyId: TEST_AGENT_KEY_ID, chains: {} }, null, 2)}\n`,
      { mode: 0o600 },
    );

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    const originalRmSync = fs.rmSync;
    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = `${toolDir}:${originalPath ?? ''}`;
    fs.rmSync = ((targetPath, options) => {
      if (path.resolve(String(targetPath)) === path.resolve(agentpayHome)) {
        return;
      }
      return originalRmSync(targetPath, options);
    });

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-run-cli-uninstall-local-remnant`);
      await withMockedPrompt('root-password', async () => {
        await assert.rejects(
          () => reset.runAdminUninstallCli(['--yes', '--non-interactive']),
          (error) => {
            assert.match(String(error?.message), /admin uninstall left local AgentPay files behind:/u);
            assert.match(String(error?.message), new RegExp(agentpayHome.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&'), 'u'));
            return true;
          },
        );
      });
      assert.equal(fs.existsSync(configPath), true);
    } finally {
      fs.rmSync = originalRmSync;
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
    }
  });
});

test('runAdminUninstallCli non-json summary reports configured agent keys and removed config paths', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  exit 0',
        'fi',
        'if [ "$1" = "-n" ] && [ "$2" = "/bin/test" ]; then',
        '  exit 1',
        'fi',
        'if [ "$1" = "-n" ]; then',
        '  exit 0',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    fs.writeFileSync(
      path.join(agentpayHome, 'config.json'),
      `${JSON.stringify({ rustBinDir, agentKeyId: TEST_AGENT_KEY_ID, chains: {} }, null, 2)}\n`,
      { mode: 0o600 },
    );
    const stdoutChunks = [];
    const originalStdoutWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((chunk, ...args) => {
      stdoutChunks.push(String(chunk));
      return originalStdoutWrite(chunk, ...args);
    });

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = `${toolDir}:${originalPath ?? ''}`;

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-run-cli-uninstall-summary-config-present`);
      await withMockedPrompt('UNINSTALL', async () => {
        await reset.runAdminUninstallCli([]);
      });
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
      process.stdout.write = originalStdoutWrite;
    }

    const output = stdoutChunks.join('');
    assert.match(output, new RegExp(`old agent key cleared: ${TEST_AGENT_KEY_ID}`, 'u'));
    assert.match(output, /local AgentPay home removed:/u);
    assert.match(output, /config removed:/u);
    assert.match(
      output,
      /legacy global npm AgentPay SDK CLI not removed: current command is not running from a legacy global npm install/u,
    );
    assert.match(output, /next: run `agentpay admin setup` only if you want a fresh managed wallet again/u);
  });
});

test('runAdminUninstallCli non-json summary reports missing config and confirms prompt', async () => {
  await withIsolatedHome(async ({ homeDir, agentpayHome, rustBinDir, toolDir }) => {
    const uninstallScriptPath = path.join(rustBinDir, 'uninstall-user-daemon.sh');
    const sudoScriptPath = path.join(toolDir, 'sudo');
    writeExecutable(uninstallScriptPath, 'exit 0');
    writeExecutable(
      sudoScriptPath,
      [
        'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
        '  cat >/dev/null',
        '  exit 0',
        'fi',
        'if [ "$1" = "-n" ] && [ "$2" = "/bin/test" ]; then',
        '  exit 1',
        'fi',
        'if [ "$1" = "-n" ]; then',
        '  exit 0',
        'fi',
        'exit 0',
      ].join('\n'),
    );
    const stdoutChunks = [];
    const originalStdoutWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((chunk, ...args) => {
      stdoutChunks.push(String(chunk));
      return originalStdoutWrite(chunk, ...args);
    });

    const originalHome = process.env.HOME;
    const originalAgentPayHome = process.env.AGENTPAY_HOME;
    const originalPath = process.env.PATH;
    process.env.HOME = homeDir;
    process.env.AGENTPAY_HOME = agentpayHome;
    process.env.PATH = `${toolDir}:${originalPath ?? ''}`;

    try {
      const reset = await import(`${modulePath.href}?case=${Date.now()}-run-cli-uninstall-summary-missing-config`);
      await withMockedPrompt('UNINSTALL', async () => {
        await reset.runAdminUninstallCli([]);
      });
    } finally {
      process.env.HOME = originalHome;
      process.env.AGENTPAY_HOME = originalAgentPayHome;
      process.env.PATH = originalPath;
      process.stdout.write = originalStdoutWrite;
    }

    const output = stdoutChunks.join('');
    assert.match(output, /uninstall complete/u);
    assert.match(output, /old agent key cleared: no configured agent key was found/u);
    assert.match(output, /config not found:/u);
    assert.match(
      output,
      /legacy global npm AgentPay SDK CLI not removed: current command is not running from a legacy global npm install/u,
    );
  });
});