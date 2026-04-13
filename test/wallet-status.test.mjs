import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const modulePath = new URL('../src/lib/wallet-status.ts', import.meta.url);
const configModulePath = new URL('../packages/config/src/index.ts', import.meta.url);
const TEST_AGENT_KEY_ID = '00000000-0000-0000-0000-000000000001';

function loadWalletStatusModule(caseId) {
  return import(`${modulePath.href}?case=${caseId}`);
}

function withMockedEuid(euid, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(process, 'geteuid');
  Object.defineProperty(process, 'geteuid', {
    configurable: true,
    value: () => euid,
  });

  try {
    return fn();
  } finally {
    if (descriptor) {
      Object.defineProperty(process, 'geteuid', descriptor);
    } else {
      delete process.geteuid;
    }
  }
}

async function listenOnUnixSocket(socketPath) {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      server.off('error', reject);
      resolve();
    });
  });
  return server;
}

async function closeUnixSocket(server, socketPath) {
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
}

function createWalletStatusResult(overrides = {}) {
  return {
    platform: 'darwin',
    config: {
      readable: true,
      error: null,
      values: {},
    },
    agent: {
      agentKeyId: TEST_AGENT_KEY_ID,
      agentKeyIdValid: true,
      keychain: {
        supported: true,
        service: 'agentpay-agent-auth-token',
        tokenStored: true,
        error: null,
      },
      legacyConfigToken: {
        present: false,
        keychainMatch: null,
        error: null,
      },
    },
    chain: {
      chainId: 1,
      chainName: 'eth',
      rpcUrlConfigured: true,
      rpcUrlTrusted: true,
      error: null,
    },
    chainProfiles: [],
    bootstrapFiles: [],
    daemonSocket: {
      path: '/trusted/run/daemon.sock',
      trusted: true,
      error: null,
    },
    stateFile: {
      path: '/trusted/run/daemon-state.enc',
      present: true,
      trusted: true,
      error: null,
    },
    binaries: [
      {
        name: 'agentpay-daemon',
        path: '/trusted/bin/agentpay-daemon',
        installed: true,
        trusted: true,
        error: null,
      },
      {
        name: 'agentpay-admin',
        path: '/trusted/bin/agentpay-admin',
        installed: true,
        trusted: true,
        error: null,
      },
      {
        name: 'agentpay-agent',
        path: '/trusted/bin/agentpay-agent',
        installed: true,
        trusted: true,
        error: null,
      },
    ],
    security: {
      ready: true,
      warnings: [],
    },
    ...overrides,
  };
}

test('getWalletStatus reports a ready wallet when config, socket, state file, keychain, and binaries are trusted', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-ready`);
  const binaryPaths = {
    'agentpay-daemon': '/trusted/bin/agentpay-daemon',
    'agentpay-admin': '/trusted/bin/agentpay-admin',
    'agentpay-agent': '/trusted/bin/agentpay-agent',
  };

  const result = walletStatus.getWalletStatus({
    platform: 'darwin',
    readConfig: () => ({
      agentKeyId: TEST_AGENT_KEY_ID,
      chainId: 1,
      chainName: 'eth',
      rpcUrl: 'https://rpc.example',
      daemonSocket: '/trusted/run/daemon.sock',
      stateFile: '/trusted/run/daemon-state.enc',
      rustBinDir: '/trusted/bin',
      chains: {},
    }),
    hasAgentAuthToken: (agentKeyId) => agentKeyId === TEST_AGENT_KEY_ID,
    readAgentAuthToken: () => null,
    assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    assertTrustedStateFilePath: (targetPath) => targetPath,
    resolveRustBinaryPath: (binaryName) => binaryPaths[binaryName],
    existsSync: () => true,
    assertTrustedExecutablePath: () => {},
  });

  assert.equal(result.security.ready, true);
  assert.deepEqual(result.security.warnings, []);
  assert.equal(result.agent.agentKeyId, TEST_AGENT_KEY_ID);
  assert.equal(result.agent.keychain.tokenStored, true);
  assert.equal(result.agent.legacyConfigToken.present, false);
  assert.equal(result.daemonSocket.trusted, true);
  assert.equal(result.stateFile.trusted, true);
  assert.equal(result.stateFile.present, true);
  assert.equal(
    result.binaries.every((binary) => binary.trusted),
    true,
  );
});

test('getWalletStatus warns about legacy config secrets and invalid configured agent ids', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-legacy`);

  const result = walletStatus.getWalletStatus({
    platform: 'darwin',
    readConfig: () => ({
      agentKeyId: 'not-a-uuid',
      agentAuthToken: 'legacy-token',
      daemonSocket: '/trusted/run/daemon.sock',
      stateFile: '/trusted/run/daemon-state.enc',
      rustBinDir: '/trusted/bin',
      chains: {},
    }),
    hasAgentAuthToken: () => {
      throw new Error('should not read keychain for invalid UUIDs');
    },
    readAgentAuthToken: () => {
      throw new Error('should not compare keychain for invalid UUIDs');
    },
    assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    assertTrustedStateFilePath: (targetPath) => targetPath,
    resolveRustBinaryPath: (binaryName) => `/trusted/bin/${binaryName}`,
    existsSync: () => true,
    assertTrustedExecutablePath: () => {},
  });

  assert.equal(result.security.ready, false);
  assert.equal(result.agent.agentKeyIdValid, false);
  assert.equal(result.agent.legacyConfigToken.present, true);
  assert.match(result.agent.keychain.error ?? '', /valid UUID/);
  assert.equal(
    result.security.warnings.includes(
      'legacy agentAuthToken is still present in config.json; migrate it to macOS Keychain',
    ),
    true,
  );
  assert.equal(
    result.security.warnings.includes('configured agentKeyId is not a valid UUID'),
    true,
  );
});

test('getWalletStatus distinguishes duplicated and mismatched legacy config tokens', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-migrate-state`);

  const duplicated = walletStatus.getWalletStatus({
    platform: 'darwin',
    readConfig: () => ({
      agentKeyId: TEST_AGENT_KEY_ID,
      agentAuthToken: 'legacy-token',
      daemonSocket: '/trusted/run/daemon.sock',
      stateFile: '/trusted/run/daemon-state.enc',
      rustBinDir: '/trusted/bin',
      chains: {},
    }),
    hasAgentAuthToken: () => true,
    readAgentAuthToken: () => 'legacy-token',
    assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    assertTrustedStateFilePath: (targetPath) => targetPath,
    resolveRustBinaryPath: (binaryName) => `/trusted/bin/${binaryName}`,
    existsSync: () => true,
    assertTrustedExecutablePath: () => {},
  });
  const mismatched = walletStatus.getWalletStatus({
    platform: 'darwin',
    readConfig: () => ({
      agentKeyId: TEST_AGENT_KEY_ID,
      agentAuthToken: 'legacy-token',
      daemonSocket: '/trusted/run/daemon.sock',
      stateFile: '/trusted/run/daemon-state.enc',
      rustBinDir: '/trusted/bin',
      chains: {},
    }),
    hasAgentAuthToken: () => true,
    readAgentAuthToken: () => 'rotated-token',
    assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    assertTrustedStateFilePath: (targetPath) => targetPath,
    resolveRustBinaryPath: (binaryName) => `/trusted/bin/${binaryName}`,
    existsSync: () => true,
    assertTrustedExecutablePath: () => {},
  });

  assert.equal(duplicated.agent.legacyConfigToken.present, true);
  assert.equal(duplicated.agent.legacyConfigToken.keychainMatch, true);
  assert.equal(
    duplicated.security.warnings.includes(
      'legacy agentAuthToken is duplicated in config.json and macOS Keychain; run `agentpay config agent-auth migrate` to scrub plaintext config storage',
    ),
    true,
  );

  assert.equal(mismatched.agent.legacyConfigToken.present, true);
  assert.equal(mismatched.agent.legacyConfigToken.keychainMatch, false);
  assert.equal(
    mismatched.security.warnings.includes(
      'legacy agentAuthToken in config.json differs from the macOS Keychain token for the configured agentKeyId; avoid `--allow-legacy-agent-auth-source` until migrated',
    ),
    true,
  );
});

test('getWalletStatus reports keychain status failures without crashing', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-keychain-error`);

  const result = walletStatus.getWalletStatus({
    platform: 'darwin',
    readConfig: () => ({
      agentKeyId: TEST_AGENT_KEY_ID,
      daemonSocket: '/trusted/run/daemon.sock',
      stateFile: '/trusted/run/daemon-state.enc',
      rustBinDir: '/trusted/bin',
      chains: {},
    }),
    hasAgentAuthToken: () => {
      throw new Error('keychain is locked');
    },
    readAgentAuthToken: () => null,
    assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    assertTrustedStateFilePath: (targetPath) => targetPath,
    resolveRustBinaryPath: (binaryName) => `/trusted/bin/${binaryName}`,
    existsSync: () => true,
    assertTrustedExecutablePath: () => {},
  });

  assert.equal(result.security.ready, false);
  assert.equal(result.agent.keychain.tokenStored, false);
  assert.match(result.agent.keychain.error ?? '', /keychain is locked/);
  assert.equal(
    result.security.warnings.includes('macOS Keychain status check failed: keychain is locked'),
    true,
  );
  assert.equal(
    result.security.warnings.includes(
      'macOS Keychain does not contain an agent auth token for the configured agentKeyId',
    ),
    false,
  );
});

test('getWalletStatus handles missing agent ids, empty legacy secrets, and partial chain profiles', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-missing-agent-and-partial-chains`);

  const result = walletStatus.getWalletStatus({
    platform: 'linux',
    readConfig: () => ({
      agentKeyId: '   ',
      agentAuthToken: '',
      chainName: 'mainnet',
      rpcUrl: 'https://rpc.example',
      daemonSocket: '/trusted/run/daemon.sock',
      stateFile: '/trusted/run/daemon-state.enc',
      rustBinDir: '/trusted/bin',
      chains: {
        partial: {
          rpcUrl: 'https://partial.example',
        },
        typed: {
          chainId: '56',
          name: 123,
          rpcUrl: 'https://typed.example',
        },
      },
    }),
    hasAgentAuthToken: () => {
      throw new Error('should not query keychain without an agent key id');
    },
    readAgentAuthToken: () => {
      throw new Error('should not compare keychain without an agent key id');
    },
    assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    assertTrustedStateFilePath: (targetPath) => targetPath,
    resolveRustBinaryPath: (binaryName) => `/trusted/bin/${binaryName}`,
    existsSync: () => true,
    assertTrustedExecutablePath: () => {},
  });

  assert.equal(result.agent.agentKeyId, null);
  assert.equal(result.agent.keychain.supported, true);
  assert.equal(result.agent.keychain.service, 'agentpay-agent-auth-token');
  assert.equal(result.agent.legacyConfigToken.present, false);
  assert.equal(result.chain.chainId, null);
  assert.equal(result.chain.rpcUrlTrusted, true);
  assert.equal(result.chainProfiles.length, 2);
  assert.equal(result.chainProfiles[0].chainId, null);
  assert.equal(result.chainProfiles[0].chainName, null);
  assert.equal(result.chainProfiles[0].rpcUrlTrusted, true);
  assert.equal(result.chainProfiles[1].chainId, null);
  assert.equal(result.chainProfiles[1].chainName, null);
  assert.equal(
    result.security.warnings.includes('agentKeyId is not configured'),
    true,
  );
});

test('getWalletStatus warns when the macOS Keychain token is absent and the legacy token cannot be compared', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-missing-keychain-token`);

  const result = walletStatus.getWalletStatus({
    platform: 'darwin',
    readConfig: () => ({
      agentKeyId: TEST_AGENT_KEY_ID,
      agentAuthToken: 'legacy-token',
      chainName: 'mainnet',
      rpcUrl: 'http://rpc.example',
      daemonSocket: '/trusted/run/daemon.sock',
      stateFile: '/trusted/run/daemon-state.enc',
      rustBinDir: '/trusted/bin',
    }),
    hasAgentAuthToken: () => false,
    readAgentAuthToken: () => null,
    assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    assertTrustedStateFilePath: (targetPath) => targetPath,
    resolveRustBinaryPath: (binaryName) => `/trusted/bin/${binaryName}`,
    existsSync: () => true,
    assertTrustedExecutablePath: () => {},
  });

  assert.equal(result.chain.chainId, null);
  assert.equal(result.chain.rpcUrlTrusted, false);
  assert.equal(result.agent.keychain.tokenStored, false);
  assert.equal(result.agent.legacyConfigToken.keychainMatch, null);
  assert.equal(
    result.security.warnings.includes(
      'macOS Keychain does not contain an agent auth token for the configured agentKeyId',
    ),
    true,
  );
  assert.equal(
    result.security.warnings.includes(
      'legacy agentAuthToken is still present in config.json; migrate it to macOS Keychain',
    ),
    true,
  );
});

test('getWalletStatus reports unreadable config, untrusted sockets, untrusted state files, and missing binaries', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-degraded`);

  const result = walletStatus.getWalletStatus({
    readConfig: () => {
      throw new Error('config file must not be a symlink');
    },
    hasAgentAuthToken: () => false,
    readAgentAuthToken: () => null,
    assertTrustedDaemonSocketPath: () => {
      throw new Error("Daemon socket '/tmp/agentpay.sock' does not exist");
    },
    assertTrustedStateFilePath: () => {
      throw new Error("State file directory '/tmp' must not be writable by group/other");
    },
    resolveRustBinaryPath: (binaryName) => `/missing/bin/${binaryName}`,
    existsSync: () => false,
    assertTrustedExecutablePath: () => {},
  });

  assert.equal(result.config.readable, false);
  assert.equal(result.security.ready, false);
  assert.match(result.config.error ?? '', /must not be a symlink/);
  assert.match(result.daemonSocket.error ?? '', /does not exist/);
  assert.match(result.stateFile.error ?? '', /must not be writable by group\/other/);
  assert.equal(result.stateFile.trusted, false);
  assert.equal(
    result.binaries.every((binary) => binary.installed === false),
    true,
  );
  assert.equal(
    result.security.warnings.some((warning) => warning.startsWith('config is unreadable:')),
    true,
  );
  assert.equal(
    result.security.warnings.some((warning) => warning.startsWith('daemon socket is not trusted:')),
    true,
  );
  assert.equal(
    result.security.warnings.some((warning) => warning.startsWith('state file is not trusted:')),
    true,
  );
});

test('getWalletStatus renders string failures without crashing', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-string-failures`);

  const result = walletStatus.getWalletStatus({
    readConfig: () => {
      throw 'config unreadable';
    },
    hasAgentAuthToken: () => false,
    readAgentAuthToken: () => null,
    assertTrustedDaemonSocketPath: () => {
      throw 'daemon exploded';
    },
    assertTrustedStateFilePath: () => {
      throw 'state exploded';
    },
    resolveRustBinaryPath: (binaryName) => `/missing/bin/${binaryName}`,
    existsSync: () => false,
    assertTrustedExecutablePath: () => {},
  });

  assert.equal(result.config.error, 'config unreadable');
  assert.equal(result.daemonSocket.error, 'daemon exploded');
  assert.equal(result.stateFile.error, 'state exploded');
});

test('getWalletStatus rejects same-user daemon sockets when the wrapper runs as root', async () => {
  if (process.platform === 'win32' || typeof process.getuid !== 'function') {
    return;
  }

  const walletStatus = await loadWalletStatusModule(`${Date.now()}-root-socket-owner`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-status-'));
  const socketDir = path.join(tempRoot, 'run');
  const socketPath = path.join(socketDir, 'daemon.sock');
  fs.mkdirSync(socketDir, { mode: 0o755 });

  const server = await listenOnUnixSocket(socketPath);
  const originalSudoUid = process.env.SUDO_UID;
  process.env.SUDO_UID = String(process.getuid());

  try {
    const result = withMockedEuid(0, () =>
      walletStatus.getWalletStatus({
        platform: 'darwin',
        readConfig: () => ({
          agentKeyId: TEST_AGENT_KEY_ID,
          daemonSocket: socketPath,
          stateFile: '/trusted/run/daemon-state.enc',
          rustBinDir: '/trusted/bin',
          chains: {},
        }),
        hasAgentAuthToken: () => true,
        readAgentAuthToken: () => null,
        assertTrustedStateFilePath: (targetPath) => targetPath,
        resolveRustBinaryPath: (binaryName) => `/trusted/bin/${binaryName}`,
        existsSync: (targetPath) => targetPath === socketPath,
        assertTrustedExecutablePath: () => {},
      }),
    );

    assert.equal(result.daemonSocket.trusted, false);
    assert.match(result.daemonSocket.error ?? '', /must be owned by root/);
    assert.equal(
      result.security.warnings.some((warning) =>
        warning.startsWith('daemon socket is not trusted:'),
      ),
      true,
    );
  } finally {
    if (originalSudoUid === undefined) {
      delete process.env.SUDO_UID;
    } else {
      process.env.SUDO_UID = originalSudoUid;
    }
    await closeUnixSocket(server, socketPath);
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('getWalletStatus covers default dependency fallbacks with a real temp config', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-default-fallbacks`);
  const configModule = await import(`${configModulePath.href}?case=${Date.now()}-default-fallbacks`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-status-defaults-'));
  process.env.AGENTPAY_HOME = tempRoot;

  try {
    configModule.writeConfig({
      agentKeyId: 'not-a-uuid',
      chainName: 'mainnet',
      rpcUrl: 'https://rpc.example',
    });

    const result = walletStatus.getWalletStatus({
      platform: 'linux',
    });

    assert.equal(result.config.readable, true);
    assert.equal(result.agent.agentKeyIdValid, false);
    assert.equal(result.agent.keychain.supported, true);
    assert.equal(result.agent.keychain.service, 'agentpay-agent-auth-token');
    assert.equal(result.daemonSocket.path.length > 0, true);
    assert.equal(result.stateFile.path.length > 0, true);
    assert.equal(result.chainProfiles.length > 0, true);
    assert.equal(
      result.chainProfiles.every((profile) => typeof profile.key === 'string'),
      true,
    );
    assert.equal(result.bootstrapFiles.length, 0);
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('getWalletStatus falls back to default daemon and state file paths when config omits them', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-default-paths`);
  const configModule = await import(`${configModulePath.href}?case=${Date.now()}-default-paths`);
  let seenDaemonPath = null;
  let seenStatePath = null;

  const result = walletStatus.getWalletStatus({
    platform: 'darwin',
    readConfig: () => ({
      agentKeyId: TEST_AGENT_KEY_ID,
      rustBinDir: '/trusted/bin',
      chains: {},
    }),
    hasAgentAuthToken: () => true,
    readAgentAuthToken: () => null,
    assertTrustedDaemonSocketPath: (targetPath) => {
      seenDaemonPath = targetPath;
      return targetPath;
    },
    assertTrustedStateFilePath: (targetPath) => {
      seenStatePath = targetPath;
      return targetPath;
    },
    resolveRustBinaryPath: (binaryName) => `/trusted/bin/${binaryName}`,
    existsSync: () => false,
    assertTrustedExecutablePath: () => {},
  });

  assert.equal(seenDaemonPath, configModule.defaultDaemonSocketPath());
  assert.equal(seenStatePath, configModule.defaultStateFilePath());
  assert.equal(result.daemonSocket.path, configModule.defaultDaemonSocketPath());
  assert.equal(result.stateFile.path, configModule.defaultStateFilePath());
});

test('resolveWalletStatusExitCode keeps non-strict status informational', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-exit-nonstrict`);

  assert.equal(
    walletStatus.resolveWalletStatusExitCode(
      {
        security: {
          ready: false,
          warnings: ['daemon socket is not trusted'],
        },
      },
      {
        strict: false,
      },
    ),
    0,
  );
});

test('resolveWalletStatusExitCode fails strict status when wallet is not ready', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-exit-strict`);

  assert.equal(
    walletStatus.resolveWalletStatusExitCode(
      {
        security: {
          ready: false,
          warnings: ['macOS Keychain does not contain an agent auth token'],
        },
      },
      {
        strict: true,
      },
    ),
    1,
  );
  assert.equal(
    walletStatus.resolveWalletStatusExitCode(
      {
        security: {
          ready: true,
          warnings: [],
        },
      },
      {
        strict: true,
      },
    ),
    0,
  );
});

test('formatWalletStatusText renders a concise ready summary', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-format-ready`);

  const rendered = walletStatus.formatWalletStatusText(createWalletStatusResult());

  assert.match(rendered, /^wallet status: ready/m);
  assert.match(rendered, /agent auth token: stored in macOS Keychain/);
  assert.match(rendered, /active chain: eth \(1\)/);
  assert.match(rendered, /bootstrap artifacts: none detected/);
  assert.match(rendered, /warnings: none/);
});

test('formatWalletStatusText includes warning details for degraded wallets', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-format-warn`);

  const rendered = walletStatus.formatWalletStatusText(
    createWalletStatusResult({
      agent: {
        agentKeyId: TEST_AGENT_KEY_ID,
        agentKeyIdValid: true,
        keychain: {
          supported: true,
          service: 'agentpay-agent-auth-token',
          tokenStored: false,
          error: null,
        },
        legacyConfigToken: {
          present: false,
          keychainMatch: null,
          error: null,
        },
      },
      daemonSocket: {
        path: '/tmp/agentpay.sock',
        trusted: false,
        error: 'socket owner is not trusted',
      },
      stateFile: {
        path: '/tmp/daemon-state.enc',
        present: false,
        trusted: false,
        error: 'state file directory is writable by group',
      },
      bootstrapFiles: [{ path: '/tmp/bootstrap.json', status: 'plaintext', error: null }],
      security: {
        ready: false,
        warnings: [
          'macOS Keychain does not contain an agent auth token for the configured agentKeyId',
          'daemon socket is not trusted: socket owner is not trusted',
        ],
      },
    }),
  );

  assert.match(rendered, /^wallet status: attention required/m);
  assert.match(
    rendered,
    /daemon socket: \/tmp\/agentpay\.sock \(untrusted: socket owner is not trusted\)/,
  );
  assert.match(
    rendered,
    /state file: \/tmp\/daemon-state\.enc \(missing, untrusted: state file directory is writable by group\)/,
  );
  assert.match(rendered, /bootstrap artifacts: 1 detected/);
  assert.match(rendered, /warnings \(2\):/);
  assert.match(rendered, /- daemon socket is not trusted: socket owner is not trusted/);
});

test('getWalletStatus warns when the configured rpcUrl is unsafe', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-unsafe-rpc`);
  const binaryPaths = {
    'agentpay-daemon': '/trusted/bin/agentpay-daemon',
    'agentpay-admin': '/trusted/bin/agentpay-admin',
    'agentpay-agent': '/trusted/bin/agentpay-agent',
  };

  const result = walletStatus.getWalletStatus({
    platform: 'darwin',
    readConfig: () => ({
      agentKeyId: TEST_AGENT_KEY_ID,
      chainId: 1,
      chainName: 'mainnet',
      rpcUrl: 'http://rpc.example',
      daemonSocket: '/trusted/run/daemon.sock',
      stateFile: '/trusted/run/daemon-state.enc',
      rustBinDir: '/trusted/bin',
      chains: {},
    }),
    hasAgentAuthToken: (agentKeyId) => agentKeyId === TEST_AGENT_KEY_ID,
    readAgentAuthToken: () => null,
    assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    assertTrustedStateFilePath: (targetPath) => targetPath,
    resolveRustBinaryPath: (binaryName) => binaryPaths[binaryName],
    existsSync: () => true,
    assertTrustedExecutablePath: () => {},
  });

  assert.equal(result.chain.rpcUrlConfigured, true);
  assert.equal(result.chain.rpcUrlTrusted, false);
  assert.match(
    result.chain.error ?? '',
    /configured rpcUrl must use https unless it targets localhost or a loopback address/,
  );
  assert.equal(result.security.ready, false);
  assert.equal(
    result.security.warnings.includes(
      'configured rpcUrl is not trusted: configured rpcUrl must use https unless it targets localhost or a loopback address',
    ),
    true,
  );
});

test('getWalletStatus warns when a stored chain profile rpcUrl is unsafe', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-unsafe-profile-rpc`);
  const binaryPaths = {
    'agentpay-daemon': '/trusted/bin/agentpay-daemon',
    'agentpay-admin': '/trusted/bin/agentpay-admin',
    'agentpay-agent': '/trusted/bin/agentpay-agent',
  };

  const result = walletStatus.getWalletStatus({
    platform: 'darwin',
    readConfig: () => ({
      agentKeyId: TEST_AGENT_KEY_ID,
      chainId: 1,
      chainName: 'eth',
      rpcUrl: 'https://rpc.example',
      daemonSocket: '/trusted/run/daemon.sock',
      stateFile: '/trusted/run/daemon-state.enc',
      rustBinDir: '/trusted/bin',
      chains: {
        unsafe: {
          chainId: 1,
          name: 'mainnet',
          rpcUrl: 'http://rpc.example',
        },
        safe: {
          chainId: 56,
          name: 'bsc',
          rpcUrl: 'https://bsc.example',
        },
      },
    }),
    hasAgentAuthToken: (agentKeyId) => agentKeyId === TEST_AGENT_KEY_ID,
    readAgentAuthToken: () => null,
    assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    assertTrustedStateFilePath: (targetPath) => targetPath,
    resolveRustBinaryPath: (binaryName) => binaryPaths[binaryName],
    existsSync: () => true,
    assertTrustedExecutablePath: () => {},
  });

  assert.equal(result.chainProfiles.length, 2);
  assert.equal(
    result.chainProfiles.find((profile) => profile.key === 'unsafe')?.rpcUrlTrusted,
    false,
  );
  assert.equal(result.security.ready, false);
  assert.equal(
    result.security.warnings.includes(
      "chain profile 'unsafe' rpcUrl is not trusted: chain profile 'unsafe' rpcUrl must use https unless it targets localhost or a loopback address",
    ),
    true,
  );
});

test('getWalletStatus warns when lingering bootstrap files still expose secrets', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-bootstrap-files`);
  const binaryPaths = {
    'agentpay-daemon': '/trusted/bin/agentpay-daemon',
    'agentpay-admin': '/trusted/bin/agentpay-admin',
    'agentpay-agent': '/trusted/bin/agentpay-agent',
  };

  const result = walletStatus.getWalletStatus({
    platform: 'darwin',
    readConfig: () => ({
      agentKeyId: TEST_AGENT_KEY_ID,
      chainId: 1,
      chainName: 'eth',
      rpcUrl: 'https://rpc.example',
      daemonSocket: '/trusted/run/daemon.sock',
      stateFile: '/trusted/run/daemon-state.enc',
      rustBinDir: '/trusted/bin',
      chains: {},
    }),
    hasAgentAuthToken: (agentKeyId) => agentKeyId === TEST_AGENT_KEY_ID,
    readAgentAuthToken: () => null,
    assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    assertTrustedStateFilePath: (targetPath) => targetPath,
    resolveRustBinaryPath: (binaryName) => binaryPaths[binaryName],
    existsSync: () => true,
    assertTrustedExecutablePath: () => {},
    listBootstrapFiles: () => [
      {
        path: '/trusted/home/bootstrap-100-200.json',
        status: 'plaintext',
        agentKeyId: TEST_AGENT_KEY_ID,
        leaseExpiresAt: '2099-01-01T00:00:00Z',
        leaseExpired: false,
        error: null,
      },
      {
        path: '/trusted/home/bootstrap-300-400.json',
        status: 'redacted',
        agentKeyId: TEST_AGENT_KEY_ID,
        leaseExpiresAt: '2099-01-01T00:00:00Z',
        leaseExpired: false,
        error: null,
      },
      {
        path: '/trusted/home/bootstrap-500-600.json',
        status: 'invalid',
        agentKeyId: null,
        leaseExpiresAt: null,
        leaseExpired: false,
        error: 'lease_id is required in bootstrap credentials file',
      },
    ],
  });

  assert.equal(result.bootstrapFiles.length, 3);
  assert.equal(result.security.ready, false);
  assert.equal(
    result.security.warnings.includes(
      "bootstrap file '/trusted/home/bootstrap-100-200.json' still contains plaintext bootstrap secrets; delete or redact it securely",
    ),
    true,
  );
  assert.equal(
    result.security.warnings.includes(
      "bootstrap file '/trusted/home/bootstrap-500-600.json' is malformed or incomplete: lease_id is required in bootstrap credentials file",
    ),
    true,
  );
  assert.equal(
    result.security.warnings.some((warning) => warning.includes('bootstrap-300-400.json')),
    false,
  );
});

test('getWalletStatus warns when a bootstrap file still contains a plaintext vault private key', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-plaintext-bootstrap-private-key`);
  const binaryPaths = {
    'agentpay-daemon': '/trusted/bin/agentpay-daemon',
    'agentpay-admin': '/trusted/bin/agentpay-admin',
    'agentpay-agent': '/trusted/bin/agentpay-agent',
  };

  const result = walletStatus.getWalletStatus({
    platform: 'darwin',
    readConfig: () => ({
      agentKeyId: TEST_AGENT_KEY_ID,
      daemonSocket: '/trusted/run/daemon.sock',
      stateFile: '/trusted/run/daemon-state.enc',
      rustBinDir: '/trusted/bin',
      chains: {},
    }),
    hasAgentAuthToken: (agentKeyId) => agentKeyId === TEST_AGENT_KEY_ID,
    readAgentAuthToken: () => null,
    assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    assertTrustedStateFilePath: (targetPath) => targetPath,
    resolveRustBinaryPath: (binaryName) => binaryPaths[binaryName],
    existsSync: () => true,
    assertTrustedExecutablePath: () => {},
    listBootstrapFiles: () => [
      {
        path: '/trusted/home/bootstrap-100-200.json',
        status: 'plaintext',
        agentKeyId: TEST_AGENT_KEY_ID,
        leaseExpiresAt: '2099-01-01T00:00:00Z',
        leaseExpired: false,
        error: null,
      },
    ],
  });

  assert.equal(
    result.security.warnings.includes(
      "bootstrap file '/trusted/home/bootstrap-100-200.json' still contains plaintext bootstrap secrets; delete or redact it securely",
    ),
    true,
  );
});

test('getWalletStatus warns when a bootstrap file lease has expired', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-expired-bootstrap-lease`);
  const binaryPaths = {
    'agentpay-daemon': '/trusted/bin/agentpay-daemon',
    'agentpay-admin': '/trusted/bin/agentpay-admin',
    'agentpay-agent': '/trusted/bin/agentpay-agent',
  };

  const result = walletStatus.getWalletStatus({
    platform: 'darwin',
    readConfig: () => ({
      agentKeyId: TEST_AGENT_KEY_ID,
      daemonSocket: '/trusted/run/daemon.sock',
      stateFile: '/trusted/run/daemon-state.enc',
      rustBinDir: '/trusted/bin',
      chains: {},
    }),
    hasAgentAuthToken: (agentKeyId) => agentKeyId === TEST_AGENT_KEY_ID,
    readAgentAuthToken: () => null,
    assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    assertTrustedStateFilePath: (targetPath) => targetPath,
    resolveRustBinaryPath: (binaryName) => binaryPaths[binaryName],
    existsSync: () => true,
    assertTrustedExecutablePath: () => {},
    listBootstrapFiles: () => [
      {
        path: '/trusted/home/bootstrap-100-200.json',
        status: 'redacted',
        agentKeyId: TEST_AGENT_KEY_ID,
        leaseExpiresAt: '2000-01-01T00:00:00Z',
        leaseExpired: true,
        error: null,
      },
    ],
  });

  assert.equal(
    result.security.warnings.includes(
      "bootstrap file '/trusted/home/bootstrap-100-200.json' has an expired setup lease; do not rely on it for wallet recovery or metadata backfill",
    ),
    true,
  );
});

test('getWalletStatus marks inaccessible state files as untrusted', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-state-inaccessible`);

  const result = walletStatus.getWalletStatus({
    platform: 'darwin',
    readConfig: () => ({
      agentKeyId: TEST_AGENT_KEY_ID,
      daemonSocket: '/trusted/run/daemon.sock',
      stateFile: '/trusted/run/daemon-state.enc',
      rustBinDir: '/trusted/bin',
      chains: {},
    }),
    hasAgentAuthToken: () => true,
    readAgentAuthToken: () => null,
    assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    assertTrustedStateFilePath: () => {
      throw new Error(
        "State file '/trusted/run/daemon-state.enc' is not accessible to the current process",
      );
    },
    resolveRustBinaryPath: (binaryName) => `/trusted/bin/${binaryName}`,
    existsSync: () => true,
    assertTrustedExecutablePath: () => {},
  });

  assert.equal(result.stateFile.trusted, false);
  assert.match(result.stateFile.error ?? '', /is not accessible to the current process/);
  assert.equal(
    result.security.warnings.some((warning) => warning.startsWith('state file is not trusted:')),
    true,
  );
});

test('getWalletStatus reports Linux credential-storage state, untrusted binaries, untrusted bootstrap files, and missing active rpcUrl', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-linux-untrusted-and-missing-rpc`);

  const result = walletStatus.getWalletStatus({
    platform: 'linux',
    readConfig: () => ({
      agentKeyId: TEST_AGENT_KEY_ID,
      chainId: 1,
      chainName: null,
      daemonSocket: '/trusted/run/daemon.sock',
      stateFile: '/trusted/run/daemon-state.enc',
      rustBinDir: '/trusted/bin',
      chains: {
        noRpc: {
          chainId: 56,
          name: 'bsc',
        },
      },
    }),
    hasAgentAuthToken: () => true,
    readAgentAuthToken: () => null,
    assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    assertTrustedStateFilePath: (targetPath) => targetPath,
    resolveRustBinaryPath: (binaryName) => `/trusted/bin/${binaryName}`,
    existsSync: () => true,
    assertTrustedExecutablePath: (targetPath) => {
      if (String(targetPath).endsWith('agentpay-admin')) {
        throw new Error('binary path owner is not trusted');
      }
    },
    listBootstrapFiles: () => [
      {
        path: '/trusted/home/bootstrap-100-200.json',
        status: 'untrusted',
        agentKeyId: TEST_AGENT_KEY_ID,
        leaseExpiresAt: '2099-01-01T00:00:00Z',
        leaseExpired: false,
        error: 'file owner mismatch',
      },
    ],
  });

  assert.equal(result.chainProfiles.length, 1);
  assert.equal(result.chainProfiles[0].rpcUrlConfigured, false);
  assert.equal(
    result.security.warnings.includes('active chain is configured without an rpcUrl'),
    true,
  );
  assert.equal(
    result.security.warnings.includes('local credential storage is unavailable on this platform'),
    false,
  );
  assert.equal(
    result.security.warnings.some((warning) =>
      warning.includes('agentpay-admin is not trusted: binary path owner is not trusted'),
    ),
    true,
  );
  assert.equal(
    result.security.warnings.includes(
      "bootstrap file '/trusted/home/bootstrap-100-200.json' is not trusted: file owner mismatch",
    ),
    true,
  );
});

test('getWalletStatus captures legacy keychain comparison errors and formatWalletStatusText covers summary edge cases', async () => {
  const walletStatus = await loadWalletStatusModule(`${Date.now()}-legacy-compare-error-and-format-edges`);

  const status = walletStatus.getWalletStatus({
    platform: 'darwin',
    readConfig: () => ({
      agentKeyId: TEST_AGENT_KEY_ID,
      agentAuthToken: 'legacy-token',
      chainId: 1,
      chainName: 'mainnet',
      rpcUrl: 'https://rpc.example',
      daemonSocket: '/trusted/run/daemon.sock',
      stateFile: '/trusted/run/daemon-state.enc',
      rustBinDir: '/trusted/bin',
      chains: {},
    }),
    hasAgentAuthToken: () => true,
    readAgentAuthToken: () => {
      throw new Error('keychain compare blocked');
    },
    assertTrustedDaemonSocketPath: (targetPath) => targetPath,
    assertTrustedStateFilePath: (targetPath) => targetPath,
    resolveRustBinaryPath: (binaryName) => `/trusted/bin/${binaryName}`,
    existsSync: () => true,
    assertTrustedExecutablePath: () => {},
  });

  assert.equal(
    status.security.warnings.includes(
      'legacy agentAuthToken could not be compared with macOS Keychain: keychain compare blocked',
    ),
    true,
  );

  const notConfigured = walletStatus.formatWalletStatusText(
    createWalletStatusResult({
      agent: {
        agentKeyId: null,
        agentKeyIdValid: false,
        keychain: {
          supported: true,
          service: 'agentpay-agent-auth-token',
          tokenStored: false,
          error: null,
        },
        legacyConfigToken: {
          present: false,
          keychainMatch: null,
          error: null,
        },
      },
      chain: {
        chainId: null,
        chainName: null,
        rpcUrlConfigured: false,
        rpcUrlTrusted: null,
        error: null,
      },
    }),
  );
  assert.match(notConfigured, /agent auth token: not configured/);
  assert.match(notConfigured, /active chain: unconfigured/);
  assert.match(notConfigured, /rpc url: not configured/);

  const invalidAgent = walletStatus.formatWalletStatusText(
    createWalletStatusResult({
      agent: {
        agentKeyId: TEST_AGENT_KEY_ID,
        agentKeyIdValid: false,
        keychain: {
          supported: true,
          service: 'agentpay-agent-auth-token',
          tokenStored: false,
          error: null,
        },
        legacyConfigToken: {
          present: false,
          keychainMatch: null,
          error: null,
        },
      },
      chain: {
        chainId: 1,
        chainName: null,
        rpcUrlConfigured: true,
        rpcUrlTrusted: false,
        error: 'rpc is insecure',
      },
    }),
  );
  assert.match(invalidAgent, /agent auth token: configured agentKeyId is invalid/);
  assert.match(invalidAgent, /active chain: chainId 1/);
  assert.match(invalidAgent, /rpc url: untrusted: rpc is insecure/);

  const unsupportedKeychain = walletStatus.formatWalletStatusText(
    createWalletStatusResult({
      agent: {
        agentKeyId: TEST_AGENT_KEY_ID,
        agentKeyIdValid: true,
        keychain: {
          supported: false,
          service: null,
          tokenStored: false,
          error: null,
        },
        legacyConfigToken: {
          present: false,
          keychainMatch: null,
          error: null,
        },
      },
      chain: {
        chainId: null,
        chainName: 'mainnet',
        rpcUrlConfigured: true,
        rpcUrlTrusted: true,
        error: null,
      },
    }),
  );
  assert.match(
    unsupportedKeychain,
    /agent auth token: local credential storage unavailable on this platform/,
  );
  assert.match(unsupportedKeychain, /active chain: mainnet/);

  const keychainError = walletStatus.formatWalletStatusText(
    createWalletStatusResult({
      agent: {
        agentKeyId: TEST_AGENT_KEY_ID,
        agentKeyIdValid: true,
        keychain: {
          supported: true,
          service: 'agentpay-agent-auth-token',
          tokenStored: false,
          error: 'exec failed',
        },
        legacyConfigToken: {
          present: false,
          keychainMatch: null,
          error: null,
        },
      },
    }),
  );
  assert.match(keychainError, /agent auth token: macOS Keychain check failed: exec failed/);
});
