import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import test from 'node:test';

const modulePath = new URL('../src/lib/admin-setup.ts', import.meta.url);
const walletBackupModulePath = new URL('../src/lib/wallet-backup.ts', import.meta.url);
const HOST_MANAGED = process.platform === 'linux'
  ? {
      label: 'agentpay-daemon',
      daemonSocket: '/run/agentpay/daemon.sock',
      stateFile: '/var/lib/agentpay/daemon-state.enc',
      serviceFile: '/etc/systemd/system/agentpay-daemon.service',
      managedBinDir: '/opt/agentpay/bin',
      installScriptName: 'install-system-daemon.sh',
      uninstallScriptName: 'uninstall-system-daemon.sh',
      runnerScriptName: 'run-agentpay-daemon.sh',
      credentialHelperName: 'agentpay-daemon-password-helper.sh',
    }
  : {
      label: 'com.agentpay.daemon',
      daemonSocket: '/Library/AgentPay/run/daemon.sock',
      stateFile: '/var/db/agentpay/daemon-state.enc',
      serviceFile: '/Library/LaunchDaemons/com.agentpay.daemon.plist',
      managedBinDir: '/Library/AgentPay/bin',
      installScriptName: 'install-user-daemon.sh',
      uninstallScriptName: 'uninstall-user-daemon.sh',
      runnerScriptName: 'run-agentpay-daemon.sh',
      credentialHelperName: 'agentpay-system-keychain',
    };
const HOST_AGENT_AUTH_STORAGE = process.platform === 'linux'
  ? 'Linux Secret Service'
  : 'macOS Keychain';

function loadModule(caseId) {
  return import(`${modulePath.href}?case=${caseId}`);
}

function writeManagedSetupHelpers(rustBinDir) {
  const helpers = new Map([
    [path.join(rustBinDir, 'run-agentpay-daemon.sh'), 'exit 0'],
    [path.join(rustBinDir, 'install-user-daemon.sh'), 'exit 0'],
    [path.join(rustBinDir, 'install-system-daemon.sh'), 'exit 0'],
    [path.join(rustBinDir, 'uninstall-user-daemon.sh'), 'exit 0'],
    [path.join(rustBinDir, 'uninstall-system-daemon.sh'), 'exit 0'],
    [path.join(rustBinDir, 'agentpay-system-keychain'), 'exit 0'],
    [path.join(rustBinDir, 'agentpay-daemon-password-helper.sh'), 'exit 0'],
    [path.join(rustBinDir, 'agentpay-daemon'), 'exit 0'],
  ]);
  for (const [targetPath, body] of helpers) {
    writeExecutable(targetPath, body);
  }
}

async function withMockPlatform(platform, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { value: platform, configurable: true });
  try {
    await fn();
  } finally {
    if (descriptor) {
      Object.defineProperty(process, 'platform', descriptor);
    } else {
      delete process.platform;
    }
  }
}

async function withTrustedRootDaemonSocket(fn) {
  const tmpBase = fs.realpathSync.native('/tmp');
  const tempRoot = fs.mkdtempSync(path.join(tmpBase, 'agentpay-admin-setup-root-socket-'));
  const socketPath = path.join(tempRoot, 'daemon.sock');
  const rootOwnedPaths = new Set([path.resolve(tempRoot), path.resolve(socketPath)]);
  const originalLstatSync = fs.lstatSync;
  const server = net.createServer((socket) => {
    socket.end();
  });

  fs.lstatSync = ((targetPath, ...args) => {
    const stats = originalLstatSync(targetPath, ...args);
    const resolvedPath = path.resolve(String(targetPath));
    if (!rootOwnedPaths.has(resolvedPath)) {
      return stats;
    }
    return new Proxy(stats, {
      get(target, key, receiver) {
        if (key === 'uid') {
          return 0;
        }
        return Reflect.get(target, key, receiver);
      },
    });
  });

  try {
    await new Promise((resolve, reject) => {
      const onError = (error) => {
        server.off('listening', onListening);
        reject(error);
      };
      const onListening = () => {
        server.off('error', onError);
        resolve();
      };
      server.once('error', onError);
      server.once('listening', onListening);
      server.listen(socketPath);
    });
    await fn(socketPath);
  } finally {
    fs.lstatSync = originalLstatSync;
    await new Promise((resolve) => {
      server.close(() => resolve());
    });
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

async function withMockedManagedLaunchDaemonMetadata(input, fn) {
  const configPath = path.join(input.agentpayHome, 'config.json');
  const currentConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  const rustBinDir = currentConfig.rustBinDir;
  const sourcePaths = {
    runnerPath: path.join(rustBinDir, 'run-agentpay-daemon.sh'),
    daemonBin: path.join(rustBinDir, 'agentpay-daemon'),
    keychainHelperBin: path.join(rustBinDir, 'agentpay-system-keychain'),
  };
  const plistPath = '/Library/LaunchDaemons/com.agentpay.daemon.plist';
  const currentUid = String(process.getuid?.() ?? process.geteuid?.() ?? 0);
  const keychainAccount = os.userInfo().username;
  const plistContents = [
    '<plist><dict>',
    `<string>${sourcePaths.runnerPath}</string>`,
    `<string>${sourcePaths.daemonBin}</string>`,
    `<string>${sourcePaths.keychainHelperBin}</string>`,
    `<string>com.agentpay.daemon</string>`,
    `<string>${input.daemonSocket}</string>`,
    `<string>${input.stateFile}</string>`,
    '<string>agentpay-daemon-password</string>',
    `<string>${keychainAccount}</string>`,
    '<string>software</string>',
    '<key>AGENTPAY_ALLOW_ADMIN_EUID</key>',
    `<string>${currentUid}</string>`,
    '<key>AGENTPAY_ALLOW_AGENT_EUID</key>',
    `<string>${currentUid}</string>`,
    '</dict></plist>',
  ].join('\n');

  const originalExistsSync = fs.existsSync;
  const originalReadFileSync = fs.readFileSync;
  fs.existsSync = ((targetPath, ...args) => {
    if (path.resolve(String(targetPath)) === plistPath) {
      return true;
    }
    return originalExistsSync(targetPath, ...args);
  });
  fs.readFileSync = ((targetPath, ...args) => {
    if (path.resolve(String(targetPath)) === plistPath) {
      if (args[0] === 'utf8' || (args[0] && typeof args[0] === 'object' && args[0].encoding === 'utf8')) {
        return plistContents;
      }
      return Buffer.from(plistContents, 'utf8');
    }
    return originalReadFileSync(targetPath, ...args);
  });

  try {
    await fn();
  } finally {
    fs.existsSync = originalExistsSync;
    fs.readFileSync = originalReadFileSync;
  }
}

async function withInstallMarkerConnectionGate(markerPath, fn) {
  const originalCreateConnection = net.createConnection;
  net.createConnection = ((...args) => {
    if (fs.existsSync(markerPath)) {
      return originalCreateConnection(...args);
    }

    const socket = new EventEmitter();
    socket.destroy = () => {};
    socket.setTimeout = () => socket;
    process.nextTick(() => {
      const error = new Error('simulated not-ready socket');
      error.code = 'ENOENT';
      socket.emit('error', error);
    });
    return socket;
  });

  try {
    await fn();
  } finally {
    net.createConnection = originalCreateConnection;
  }
}

test('assertManagedDaemonInstallPreconditions validates staged root-daemon inputs before sudo setup', async () => {
  const adminSetup = await loadModule(`${Date.now()}-install-preconditions`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-admin-setup-'));
  const rustBinDir = path.join(tempRoot, 'bin');
  const runnerPath = path.join(rustBinDir, 'run-agentpay-daemon.sh');
  const daemonBin = path.join(rustBinDir, 'agentpay-daemon');
  const keychainHelperBin = path.join(rustBinDir, HOST_MANAGED.credentialHelperName);
  const installScript = path.join(tempRoot, HOST_MANAGED.installScriptName);
  const daemonSocket = HOST_MANAGED.daemonSocket;
  const stateFile = HOST_MANAGED.stateFile;

  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(runnerPath, '#!/bin/sh\n', { mode: 0o755 });
  fs.writeFileSync(daemonBin, 'daemon-bin\n', { mode: 0o755 });
  fs.writeFileSync(keychainHelperBin, 'helper-bin\n', { mode: 0o755 });
  fs.writeFileSync(installScript, '#!/bin/sh\n', { mode: 0o755 });

  const calls = [];
  const result = adminSetup.assertManagedDaemonInstallPreconditions(
    {
      rustBinDir,
      chains: {},
    },
    daemonSocket,
    stateFile,
    {
      assertTrustedExecutablePath: (targetPath) => {
        calls.push(['exec', path.resolve(targetPath)]);
      },
      assertTrustedRootPlannedDaemonSocketPath: (targetPath, label) => {
        calls.push(['socket', label, path.resolve(targetPath)]);
        return path.resolve(targetPath);
      },
      assertTrustedRootPlannedPrivateFilePath: (targetPath, label) => {
        calls.push(['state', label, path.resolve(targetPath)]);
        return path.resolve(targetPath);
      },
      resolveInstallScriptPath: () => installScript,
    },
  );

  const managedPaths = adminSetup.resolveManagedLaunchDaemonPaths();
  assert.equal(result.runnerPath, path.resolve(runnerPath));
  assert.equal(result.daemonBin, path.resolve(daemonBin));
  assert.equal(result.keychainHelperBin, path.resolve(keychainHelperBin));
  assert.equal(result.installScript, path.resolve(installScript));
  assert.equal(result.managedRunnerPath, managedPaths.runnerPath);
  assert.equal(result.managedDaemonBin, managedPaths.daemonBin);
  assert.equal(result.managedKeychainHelperBin, managedPaths.keychainHelperBin);
  assert.deepEqual(calls, [
    ['exec', path.resolve(runnerPath)],
    ['exec', path.resolve(daemonBin)],
    ['exec', path.resolve(keychainHelperBin)],
    ['exec', path.resolve(installScript)],
    ['socket', 'Managed daemon socket', path.resolve(daemonSocket)],
    ['state', 'Managed daemon state file', path.resolve(stateFile)],
  ]);

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('runAdminSetupCli supports Linux managed setup planning', async () => {
  await withMockPlatform('linux', async () => {
    await withMockedAdminSetupEnv(async () => {
      const stdoutChunks = [];
      const originalStdoutWrite = process.stdout.write.bind(process.stdout);
      process.stdout.write = ((chunk, ...args) => {
        stdoutChunks.push(String(chunk));
        return originalStdoutWrite(chunk, ...args);
      });
      try {
        const adminSetup = await loadModule(`${Date.now()}-linux-setup-supported`);
        await adminSetup.runAdminSetupCli(['--plan', '--json']);
      } finally {
        process.stdout.write = originalStdoutWrite;
      }
      assert.match(stdoutChunks.join(''), /"command": "setup"/u);
      assert.match(stdoutChunks.join(''), /"mode": "plan"/u);
    });
  });
});

test('runAdminTuiCli supports Linux managed TUI passthrough when the daemon socket is trusted', async () => {
  await withMockPlatform('linux', async () => {
    await withTrustedRootDaemonSocket(async (trustedSocket) => {
      await withMockedAdminSetupEnv(async ({ agentpayHome }) => {
        const configPath = path.join(agentpayHome, 'config.json');
        const currentConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        fs.writeFileSync(
          configPath,
          `${JSON.stringify({ ...currentConfig, daemonSocket: trustedSocket }, null, 2)}\n`,
          { mode: 0o600 },
        );

        process.env.AGENTPAY_MOCK_SKIP_TUI_OUTPUT = '1';
        const stdoutChunks = [];
        const originalStdoutWrite = process.stdout.write.bind(process.stdout);
        process.stdout.write = ((chunk, ...args) => {
          stdoutChunks.push(String(chunk));
          return originalStdoutWrite(chunk, ...args);
        });
        try {
          const adminSetup = await loadModule(`${Date.now()}-linux-tui-supported`);
          await withMockedPrompt('vault-password', async () => {
            await adminSetup.runAdminTuiCli(['--json']);
          });
        } finally {
          process.stdout.write = originalStdoutWrite;
        }
        assert.match(stdoutChunks.join(''), /"command": "tui"/u);
        assert.match(stdoutChunks.join(''), /"canceled": true/u);
      });
    });
  });
});

test('assertManagedDaemonInstallPreconditions prefers staged launchd helpers from rustBinDir', async () => {
  const adminSetup = await loadModule(`${Date.now()}-install-preconditions-staged-helper`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-admin-setup-'));
  const rustBinDir = path.join(tempRoot, 'bin');
  const runnerPath = path.join(rustBinDir, 'run-agentpay-daemon.sh');
  const daemonBin = path.join(rustBinDir, 'agentpay-daemon');
  const keychainHelperBin = path.join(rustBinDir, HOST_MANAGED.credentialHelperName);
  const installScript = path.join(rustBinDir, HOST_MANAGED.installScriptName);

  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(runnerPath, '#!/bin/sh\n', { mode: 0o755 });
  fs.writeFileSync(daemonBin, 'daemon-bin\n', { mode: 0o755 });
  fs.writeFileSync(keychainHelperBin, 'helper-bin\n', { mode: 0o755 });
  fs.writeFileSync(installScript, '#!/bin/sh\n', { mode: 0o755 });

  const result = adminSetup.assertManagedDaemonInstallPreconditions(
    {
      rustBinDir,
      chains: {},
    },
    HOST_MANAGED.daemonSocket,
    HOST_MANAGED.stateFile,
    {
      assertTrustedExecutablePath: () => {},
      assertTrustedRootPlannedDaemonSocketPath: (targetPath) => path.resolve(targetPath),
      assertTrustedRootPlannedPrivateFilePath: (targetPath) => path.resolve(targetPath),
    },
  );

  assert.equal(result.installScript, path.resolve(installScript));

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('assertManagedDaemonInstallPreconditions fails closed when root-managed paths are untrusted', async () => {
  const adminSetup = await loadModule(`${Date.now()}-install-preconditions-untrusted`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-admin-setup-'));
  const rustBinDir = path.join(tempRoot, 'bin');
  const runnerPath = path.join(rustBinDir, 'run-agentpay-daemon.sh');
  const daemonBin = path.join(rustBinDir, 'agentpay-daemon');
  const keychainHelperBin = path.join(rustBinDir, HOST_MANAGED.credentialHelperName);
  const installScript = path.join(tempRoot, HOST_MANAGED.installScriptName);

  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(runnerPath, '#!/bin/sh\n', { mode: 0o755 });
  fs.writeFileSync(daemonBin, 'daemon-bin\n', { mode: 0o755 });
  fs.writeFileSync(keychainHelperBin, 'helper-bin\n', { mode: 0o755 });
  fs.writeFileSync(installScript, '#!/bin/sh\n', { mode: 0o755 });

  assert.throws(
    () =>
      adminSetup.assertManagedDaemonInstallPreconditions(
        {
          rustBinDir,
          chains: {},
        },
        '/Users/example/agentpay/run/daemon.sock',
        HOST_MANAGED.stateFile,
        {
          assertTrustedExecutablePath: () => {},
          assertTrustedRootPlannedDaemonSocketPath: () => {
            throw new Error('Managed daemon socket directory must be owned by root');
          },
          assertTrustedRootPlannedPrivateFilePath: (targetPath) => path.resolve(targetPath),
          resolveInstallScriptPath: () => installScript,
        },
      ),
    /must be owned by root/,
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('managedLaunchDaemonAssetsMatchSource compares staged root copies against current source assets', async () => {
  const adminSetup = await loadModule(`${Date.now()}-managed-assets-match`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-admin-setup-'));
  const sourceBinDir = path.join(tempRoot, 'source-bin');
  const managedBinDir = path.join(tempRoot, 'managed-bin');
  const sourceRunner = path.join(sourceBinDir, 'run-agentpay-daemon.sh');
  const sourceDaemon = path.join(sourceBinDir, 'agentpay-daemon');
  const sourceKeychainHelper = path.join(sourceBinDir, HOST_MANAGED.credentialHelperName);
  const managedRunner = path.join(managedBinDir, 'run-agentpay-daemon.sh');
  const managedDaemon = path.join(managedBinDir, 'agentpay-daemon');
  const managedKeychainHelper = path.join(managedBinDir, HOST_MANAGED.credentialHelperName);

  fs.mkdirSync(sourceBinDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(managedBinDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(sourceRunner, '#!/bin/sh\necho source\n', { mode: 0o755 });
  fs.writeFileSync(sourceDaemon, 'daemon-v1\n', { mode: 0o755 });
  fs.writeFileSync(sourceKeychainHelper, 'helper-v1\n', { mode: 0o755 });
  fs.writeFileSync(managedRunner, '#!/bin/sh\necho source\n', { mode: 0o755 });
  fs.writeFileSync(managedDaemon, 'daemon-v1\n', { mode: 0o755 });
  fs.writeFileSync(managedKeychainHelper, 'helper-v1\n', { mode: 0o755 });

  assert.equal(
    adminSetup.managedLaunchDaemonAssetsMatchSource(
      {
        rustBinDir: sourceBinDir,
        chains: {},
      },
      {
        resolveManagedPaths: () => ({
          runnerPath: managedRunner,
          daemonBin: managedDaemon,
          keychainHelperBin: managedKeychainHelper,
        }),
      },
    ),
    true,
  );

  fs.writeFileSync(managedDaemon, 'daemon-v2\n', { mode: 0o755 });
  assert.equal(
    adminSetup.managedLaunchDaemonAssetsMatchSource(
      {
        rustBinDir: sourceBinDir,
        chains: {},
      },
      {
        resolveManagedPaths: () => ({
          runnerPath: managedRunner,
          daemonBin: managedDaemon,
          keychainHelperBin: managedKeychainHelper,
        }),
      },
    ),
    false,
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('managedLaunchDaemonAssetsMatchSource fails closed for size mismatches and missing files', async () => {
  const adminSetup = await loadModule(`${Date.now()}-managed-assets-size-and-missing`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-admin-setup-'));
  const sourceBinDir = path.join(tempRoot, 'source-bin');
  const managedBinDir = path.join(tempRoot, 'managed-bin');
  const sourceRunner = path.join(sourceBinDir, 'run-agentpay-daemon.sh');
  const sourceDaemon = path.join(sourceBinDir, 'agentpay-daemon');
  const sourceKeychainHelper = path.join(sourceBinDir, HOST_MANAGED.credentialHelperName);
  const managedRunner = path.join(managedBinDir, 'run-agentpay-daemon.sh');
  const managedDaemon = path.join(managedBinDir, 'agentpay-daemon');
  const managedKeychainHelper = path.join(managedBinDir, HOST_MANAGED.credentialHelperName);

  fs.mkdirSync(sourceBinDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(managedBinDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(sourceRunner, '#!/bin/sh\necho source\n', { mode: 0o755 });
  fs.writeFileSync(sourceDaemon, 'daemon-v1\n', { mode: 0o755 });
  fs.writeFileSync(sourceKeychainHelper, 'helper-v1\n', { mode: 0o755 });
  fs.writeFileSync(managedRunner, '#!/bin/sh\necho source\n', { mode: 0o755 });
  fs.writeFileSync(managedDaemon, 'daemon-v1 with extra bytes\n', { mode: 0o755 });
  fs.writeFileSync(managedKeychainHelper, 'helper-v1\n', { mode: 0o755 });

  assert.equal(
    adminSetup.managedLaunchDaemonAssetsMatchSource(
      {
        rustBinDir: sourceBinDir,
        chains: {},
      },
      {
        resolveManagedPaths: () => ({
          runnerPath: managedRunner,
          daemonBin: managedDaemon,
          keychainHelperBin: managedKeychainHelper,
        }),
      },
    ),
    false,
  );

  fs.rmSync(managedDaemon, { force: true });
  assert.equal(
    adminSetup.managedLaunchDaemonAssetsMatchSource(
      {
        rustBinDir: sourceBinDir,
        chains: {},
      },
      {
        resolveManagedPaths: () => ({
          runnerPath: managedRunner,
          daemonBin: managedDaemon,
          keychainHelperBin: managedKeychainHelper,
        }),
      },
    ),
    false,
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('assertManagedDaemonInstallPreconditions fails closed when staged assets are missing', async () => {
  const adminSetup = await loadModule(`${Date.now()}-install-preconditions-missing-assets`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-admin-setup-'));
  const rustBinDir = path.join(tempRoot, 'bin');
  const runnerPath = path.join(rustBinDir, 'run-agentpay-daemon.sh');
  const daemonBin = path.join(rustBinDir, 'agentpay-daemon');
  const keychainHelperBin = path.join(rustBinDir, HOST_MANAGED.credentialHelperName);
  const installScript = path.join(tempRoot, HOST_MANAGED.installScriptName);

  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(runnerPath, '#!/bin/sh\n', { mode: 0o755 });
  fs.writeFileSync(daemonBin, 'daemon-bin\n', { mode: 0o755 });
  fs.writeFileSync(keychainHelperBin, 'helper-bin\n', { mode: 0o755 });
  fs.writeFileSync(installScript, '#!/bin/sh\n', { mode: 0o755 });

  fs.rmSync(daemonBin, { force: true });
  assert.throws(
    () =>
      adminSetup.assertManagedDaemonInstallPreconditions(
        { rustBinDir, chains: {} },
        HOST_MANAGED.daemonSocket,
        HOST_MANAGED.stateFile,
        {
          assertTrustedExecutablePath: () => {},
          assertTrustedRootPlannedDaemonSocketPath: () => {},
          assertTrustedRootPlannedPrivateFilePath: () => {},
          resolveInstallScriptPath: () => installScript,
        },
      ),
    /daemon binary is not installed/u,
  );

  fs.writeFileSync(daemonBin, 'daemon-bin\n', { mode: 0o755 });
  fs.rmSync(keychainHelperBin, { force: true });
  assert.throws(
    () =>
      adminSetup.assertManagedDaemonInstallPreconditions(
        { rustBinDir, chains: {} },
        HOST_MANAGED.daemonSocket,
        HOST_MANAGED.stateFile,
        {
          assertTrustedExecutablePath: () => {},
          assertTrustedRootPlannedDaemonSocketPath: () => {},
          assertTrustedRootPlannedPrivateFilePath: () => {},
          resolveInstallScriptPath: () => installScript,
        },
      ),
    /daemon credential helper is not installed/u,
  );

  fs.writeFileSync(keychainHelperBin, 'helper-bin\n', { mode: 0o755 });
  fs.rmSync(installScript, { force: true });
  assert.throws(
    () =>
      adminSetup.assertManagedDaemonInstallPreconditions(
        { rustBinDir, chains: {} },
        HOST_MANAGED.daemonSocket,
        HOST_MANAGED.stateFile,
        {
          assertTrustedExecutablePath: () => {},
          assertTrustedRootPlannedDaemonSocketPath: () => {},
          assertTrustedRootPlannedPrivateFilePath: () => {},
          resolveInstallScriptPath: () => installScript,
        },
      ),
    /managed daemon install helper is not installed/u,
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('assertManagedDaemonInstallPreconditions fails closed when the daemon runner is missing', async () => {
  const adminSetup = await loadModule(`${Date.now()}-install-preconditions-missing-runner`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-admin-setup-'));
  const rustBinDir = path.join(tempRoot, 'bin');
  const daemonBin = path.join(rustBinDir, 'agentpay-daemon');
  const keychainHelperBin = path.join(rustBinDir, HOST_MANAGED.credentialHelperName);
  const installScript = path.join(tempRoot, HOST_MANAGED.installScriptName);

  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(daemonBin, 'daemon-bin\n', { mode: 0o755 });
  fs.writeFileSync(keychainHelperBin, 'helper-bin\n', { mode: 0o755 });
  fs.writeFileSync(installScript, '#!/bin/sh\n', { mode: 0o755 });

  assert.throws(
    () =>
      adminSetup.assertManagedDaemonInstallPreconditions(
        { rustBinDir, chains: {} },
        HOST_MANAGED.daemonSocket,
        HOST_MANAGED.stateFile,
        {
          assertTrustedExecutablePath: () => {},
          assertTrustedRootPlannedDaemonSocketPath: () => {},
          assertTrustedRootPlannedPrivateFilePath: () => {},
          resolveInstallScriptPath: () => installScript,
        },
      ),
    /daemon runner is not installed/u,
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('launchDaemonPlistValue reads keyed launchd environment values without conflating duplicate strings', async () => {
  const adminSetup = await loadModule(`${Date.now()}-plist-env-values`);
  const plistContents = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
  <dict>
    <key>EnvironmentVariables</key>
    <dict>
      <key>AGENTPAY_ALLOW_ADMIN_EUID</key>
      <string>501</string>
      <key>AGENTPAY_ALLOW_AGENT_EUID</key>
      <string>777</string>
      <key>AGENTPAY_KEYCHAIN_ACCOUNT</key>
      <string>501</string>
    </dict>
  </dict>
</plist>`;

  assert.equal(adminSetup.launchDaemonPlistValue(plistContents, 'AGENTPAY_ALLOW_ADMIN_EUID'), '501');
  assert.equal(adminSetup.launchDaemonPlistValue(plistContents, 'AGENTPAY_ALLOW_AGENT_EUID'), '777');
  assert.equal(adminSetup.launchDaemonPlistValue(plistContents, 'AGENTPAY_MISSING_KEY'), null);
});

test('resolveExistingWalletSetupTarget returns null when no wallet is configured', async () => {
  const adminSetup = await loadModule(`${Date.now()}-no-existing-wallet`);
  assert.equal(
    adminSetup.resolveExistingWalletSetupTarget({
      chains: {},
    }),
    null,
  );
});

test('resolveExistingWalletSetupTarget derives address and agent key details', async () => {
  const adminSetup = await loadModule(`${Date.now()}-existing-wallet`);
  const existing = adminSetup.resolveExistingWalletSetupTarget({
    agentKeyId: '00000000-0000-0000-0000-000000000001',
    agentAuthToken: 'legacy-token',
    wallet: {
      vaultPublicKey: '03abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd',
      policyAttachment: 'policy_set',
    },
    chains: {},
  });

  assert.equal(existing.agentKeyId, '00000000-0000-0000-0000-000000000001');
  assert.equal(existing.hasLegacyAgentAuthToken, true);
  assert.match(existing.address ?? '', /^0x[0-9a-fA-F]{40}$/);
});

test('resolveExistingWalletSetupTarget still derives an address from non-standard vault key input', async () => {
  const adminSetup = await loadModule(`${Date.now()}-existing-wallet-nonstandard-vault-pubkey`);
  const existing = adminSetup.resolveExistingWalletSetupTarget({
    wallet: {
      vaultPublicKey: '0xzzzz',
      policyAttachment: 'policy_set',
    },
    agentKeyId: '00000000-0000-0000-0000-000000000001',
    chains: {},
  });

  assert.match(existing.address ?? '', /^0x[0-9a-fA-F]{40}$/);
  assert.equal(existing.agentKeyId, '00000000-0000-0000-0000-000000000001');
});

test('resolveExistingWalletSetupTarget reports configured agent identity without wallet metadata', async () => {
  const adminSetup = await loadModule(`${Date.now()}-existing-wallet-agent-only`);
  const existing = adminSetup.resolveExistingWalletSetupTarget({
    agentKeyId: '00000000-0000-0000-0000-000000000001',
    chains: {},
  });

  assert.equal(existing?.address, undefined);
  assert.equal(existing?.agentKeyId, '00000000-0000-0000-0000-000000000001');
  assert.equal(existing?.hasLegacyAgentAuthToken, false);
});

test('createAdminSetupPlan rejects reuse when no local wallet exists', async () => {
  const adminSetup = await loadModule(`${Date.now()}-reuse-missing-wallet`);

  assert.throws(
    () =>
      adminSetup.createAdminSetupPlan(
        {
          reuseExistingWallet: true,
        },
        {
          readConfig: () => ({
            rustBinDir: '/trusted/bin',
            chains: {},
          }),
          assertManagedDaemonInstallPreconditions: () => {
            throw new Error('mock install preflight failure');
          },
        },
      ),
    /requires a local wallet to reuse/u,
  );
});

test('createAdminSetupPlan rejects attach-bootstrap-policies when no local wallet exists', async () => {
  const adminSetup = await loadModule(`${Date.now()}-attach-bootstrap-policies-missing-wallet`);

  assert.throws(
    () =>
      adminSetup.createAdminSetupPlan(
        {
          attachBootstrapPolicies: true,
        },
        {
          readConfig: () => ({
            rustBinDir: '/trusted/bin',
            chains: {},
          }),
          assertManagedDaemonInstallPreconditions: () => {
            throw new Error('mock install preflight failure');
          },
        },
      ),
    /--attach-bootstrap-policies requires a local wallet to reuse/u,
  );
});

test('createAdminSetupPlan rejects restoring from backup while reusing existing wallet', async () => {
  const adminSetup = await loadModule(`${Date.now()}-admin-plan-restore-reuse-conflict`);

  assert.throws(
    () =>
      adminSetup.createAdminSetupPlan({
        reuseExistingWallet: true,
        restoreWalletFrom: '/tmp/recovery.json',
        token: [],
        attachPolicyId: [],
      }),
    /--restore-wallet-from conflicts with --reuse-existing-wallet/,
  );
});

test('createAdminSetupPlan rejects reuse when persisted wallet metadata is incomplete', async () => {
  const adminSetup = await loadModule(`${Date.now()}-reuse-missing-wallet-fields`);

  assert.throws(
    () =>
      adminSetup.createAdminSetupPlan(
        {
          reuseExistingWallet: true,
        },
        {
          readConfig: () => ({
            rustBinDir: '/trusted/bin',
            wallet: {
              vaultPublicKey: '03abcdef',
              policyAttachment: 'policy_set',
            },
            chains: {},
          }),
          assertManagedDaemonInstallPreconditions: () => {
            throw new Error('mock install preflight failure');
          },
        },
      ),
    /requires wallet\.vaultKeyId and wallet\.vaultPublicKey/u,
  );
});

test('createAdminSetupPlan derives the reusable wallet address when it is not persisted explicitly', async () => {
  const adminSetup = await loadModule(`${Date.now()}-reuse-derived-address`);

  const plan = adminSetup.createAdminSetupPlan(
    {
      reuseExistingWallet: true,
      daemonSocket: '/Library/AgentPay/run/daemon.sock',
    },
    {
      readConfig: () => ({
        rustBinDir: '/tmp/agentpay-rust-bin',
        wallet: {
          vaultKeyId: '00000000-0000-0000-0000-000000000003',
          vaultPublicKey: '03abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd',
          policyAttachment: 'policy_set',
        },
        chains: {},
      }),
      assertManagedDaemonInstallPreconditions: () => ({
        runnerPath: '/tmp/agentpay-rust-bin/run-agentpay-daemon.sh',
        daemonBin: '/tmp/agentpay-rust-bin/agentpay-daemon',
        keychainHelperBin: '/tmp/agentpay-rust-bin/agentpay-system-keychain',
        installScript: '/tmp/install-user-daemon.sh',
        managedRunnerPath: '/Library/AgentPay/bin/run-agentpay-daemon.sh',
        managedDaemonBin: '/Library/AgentPay/bin/agentpay-daemon',
        managedKeychainHelperBin: '/Library/AgentPay/bin/agentpay-system-keychain',
      }),
    },
  );

  const addressIndex = plan.walletSetup.rustCommand.args.indexOf('--existing-vault-public-key');
  assert.notEqual(addressIndex, -1);
  assert.match(plan.existingWallet?.address ?? '', /^0x[0-9a-fA-F]{40}$/u);
});

test('confirmAdminSetupOverwrite rejects non-interactive overwrite without --yes', async () => {
  const adminSetup = await loadModule(`${Date.now()}-overwrite-non-interactive`);

  await assert.rejects(
    () =>
      adminSetup.confirmAdminSetupOverwrite(
        {
          nonInteractive: true,
        },
        {
          agentKeyId: '00000000-0000-0000-0000-000000000001',
          chains: {},
        },
      ),
    /rerun with --yes in non-interactive mode/,
  );
});

test('confirmAdminSetupOverwrite rejects non-interactive wallet reuse without --yes', async () => {
  const adminSetup = await loadModule(`${Date.now()}-overwrite-reuse-non-interactive`);

  await assert.rejects(
    () =>
      adminSetup.confirmAdminSetupOverwrite(
        {
          nonInteractive: true,
          reuseExistingWallet: true,
        },
        {
          wallet: {
            vaultPublicKey: '03abcdef',
            policyAttachment: 'policy_set',
          },
          chains: {},
        },
      ),
    /refresh the existing local wallet metadata and agent credentials/u,
  );
});

test('confirmAdminSetupOverwrite accepts explicit --yes without prompting', async () => {
  const adminSetup = await loadModule(`${Date.now()}-overwrite-yes`);
  let prompted = false;

  await adminSetup.confirmAdminSetupOverwrite(
    {
      yes: true,
    },
    {
      agentKeyId: '00000000-0000-0000-0000-000000000001',
      chains: {},
    },
    {
      prompt: async () => {
        prompted = true;
        return 'OVERWRITE';
      },
    },
  );

  assert.equal(prompted, false);
});

test('confirmAdminSetupOverwrite prompts and aborts on wrong confirmation', async () => {
  const adminSetup = await loadModule(`${Date.now()}-overwrite-abort`);
  let warning = '';

  await assert.rejects(
    () =>
      adminSetup.confirmAdminSetupOverwrite(
        {},
        {
          wallet: {
            address: '0x1111111111111111111111111111111111111111',
            vaultPublicKey: '03abcdef',
            policyAttachment: 'policy_set',
          },
          agentKeyId: '00000000-0000-0000-0000-000000000001',
          chains: {},
        },
        {
          prompt: async () => 'nope',
          stderr: {
            write: (value) => {
              warning += String(value);
              return true;
            },
          },
        },
      ),
    /admin setup aborted/,
  );

  assert.match(warning, /overwrite the current local wallet metadata and agent credentials/);
  assert.match(warning, /current address:/);
  assert.match(warning, /current agent key id:/);
});

test('buildAdminTuiPassthroughArgs forces importable bootstrap output', async () => {
  const adminSetup = await loadModule(`${Date.now()}-tui-passthrough-args`);
  assert.deepEqual(
    adminSetup.buildAdminTuiPassthroughArgs({
      daemonSocket: '/Library/AgentPay/run/daemon.sock',
      bootstrapOutputPath: '/tmp/bootstrap.json',
    }),
    [
      '--json',
      '--quiet',
      '--output',
      '/tmp/bootstrap.json',
      '--daemon-socket',
      '/Library/AgentPay/run/daemon.sock',
      'tui',
      '--print-agent-auth-token',
    ],
  );
});

test('buildAdminTuiPassthroughArgs omits daemon socket when not provided', async () => {
  const adminSetup = await loadModule(`${Date.now()}-tui-passthrough-args-no-socket`);
  assert.deepEqual(
    adminSetup.buildAdminTuiPassthroughArgs({
      bootstrapOutputPath: '/tmp/bootstrap.json',
    }),
    ['--json', '--quiet', '--output', '/tmp/bootstrap.json', 'tui', '--print-agent-auth-token'],
  );
});

test('buildAdminSetupBootstrapInvocation relays the vault password over stdin', async () => {
  const adminSetup = await loadModule(`${Date.now()}-setup-bootstrap-invocation`);

  const invocation = adminSetup.buildAdminSetupBootstrapInvocation({
    vaultPassword: 'vault-secret',
    daemonSocket: '/Library/AgentPay/run/daemon.sock',
    perTxMaxWei: '1',
    network: '1',
    token: ['0x0000000000000000000000000000000000000001'],
    allowNativeEth: true,
    attachPolicyId: ['00000000-0000-0000-0000-000000000002'],
    attachBootstrapPolicies: true,
    bootstrapOutputPath: '/tmp/bootstrap.json',
  });

  assert.deepEqual(invocation, {
    args: [
      '--json',
      '--quiet',
      '--output',
      '/tmp/bootstrap.json',
      '--vault-password-stdin',
      '--non-interactive',
      '--daemon-socket',
      '/Library/AgentPay/run/daemon.sock',
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
    ],
    stdin: 'vault-secret\n',
  });
});

test('buildAdminSetupBootstrapInvocation forwards existing wallet reuse metadata', async () => {
  const adminSetup = await loadModule(`${Date.now()}-setup-bootstrap-invocation-reuse-wallet`);

  const invocation = adminSetup.buildAdminSetupBootstrapInvocation({
    vaultPassword: 'vault-secret',
    daemonSocket: '/Library/AgentPay/run/daemon.sock',
    existingVaultKeyId: '00000000-0000-0000-0000-000000000003',
    existingVaultPublicKey: '03abcdef',
    bootstrapOutputPath: '/tmp/bootstrap.json',
  });

  assert.deepEqual(invocation, {
    args: [
      '--json',
      '--quiet',
      '--output',
      '/tmp/bootstrap.json',
      '--vault-password-stdin',
      '--non-interactive',
      '--daemon-socket',
      '/Library/AgentPay/run/daemon.sock',
      'bootstrap',
      '--print-agent-auth-token',
      '--from-shared-config',
      '--existing-vault-key-id',
      '00000000-0000-0000-0000-000000000003',
      '--existing-vault-public-key',
      '03abcdef',
    ],
    stdin: 'vault-secret\n',
  });
});

test('buildAdminSetupBootstrapInvocation forwards wallet restore import file', async () => {
  const adminSetup = await loadModule(`${Date.now()}-setup-bootstrap-invocation-wallet-restore`);

  const invocation = adminSetup.buildAdminSetupBootstrapInvocation({
    vaultPassword: 'vault-secret',
    daemonSocket: '/Library/AgentPay/run/daemon.sock',
    importVaultPrivateKeyFile: '/tmp/restored-wallet.key',
    bootstrapOutputPath: '/tmp/bootstrap.json',
  });

  assert.deepEqual(invocation, {
    args: [
      '--json',
      '--quiet',
      '--output',
      '/tmp/bootstrap.json',
      '--vault-password-stdin',
      '--non-interactive',
      '--daemon-socket',
      '/Library/AgentPay/run/daemon.sock',
      'bootstrap',
      '--print-agent-auth-token',
      '--from-shared-config',
      '--import-vault-private-key-file',
      '/tmp/restored-wallet.key',
    ],
    stdin: 'vault-secret\n',
  });
});

test('prepareAdminCommandOutputPayload redacts setup secrets by default', async () => {
  const adminSetup = await loadModule(`${Date.now()}-prepare-admin-output`);
  const payload = {
    command: 'setup',
    vaultKeyId: 'vault-key-123',
    agentKeyId: '00000000-0000-0000-0000-000000000001',
    agentAuthToken: 'secret-agent-token',
    vaultPrivateKey: '11'.repeat(32),
    keychain: {
      stored: true,
      service: 'agentpay-agent-auth-token',
    },
    config: {
      chainName: 'eth',
      daemonSocket: '/Library/AgentPay/run/daemon.sock',
      stateFile: '/var/db/agentpay/daemon-state.enc',
    },
  };

  const prepared = adminSetup.prepareAdminCommandOutputPayload(payload);

  assert.notEqual(prepared, payload);
  assert.equal(prepared.agentAuthToken, '<redacted>');
  assert.equal(prepared.agentAuthTokenRedacted, true);
  assert.equal(prepared.vaultPrivateKey, '<redacted>');
  assert.equal(prepared.vaultPrivateKeyRedacted, true);
  assert.equal(payload.agentAuthToken, 'secret-agent-token');
  assert.equal(payload.vaultPrivateKey, '11'.repeat(32));

  const explicit = adminSetup.prepareAdminCommandOutputPayload(payload, true);
  assert.equal(explicit.agentAuthToken, 'secret-agent-token');
  assert.equal(explicit.vaultPrivateKey, '<redacted>');
  assert.equal(explicit.vaultPrivateKeyRedacted, true);
});

test('formatAdminCommandOutput keeps setup output keychain-first unless secrets are explicitly requested', async () => {
  const adminSetup = await loadModule(`${Date.now()}-format-admin-output`);
  const payload = {
    command: 'setup',
    vaultKeyId: 'vault-key-123',
    vaultPublicKey: '03abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd',
    agentKeyId: '00000000-0000-0000-0000-000000000001',
    agentAuthToken: 'secret-agent-token',
    vaultPrivateKey: '11'.repeat(32),
    keychain: {
      stored: true,
      service: 'agentpay-agent-auth-token',
    },
    daemon: {
      daemonSocket: '/Library/AgentPay/run/daemon.sock',
      stateFile: '/var/db/agentpay/daemon-state.enc',
    },
    config: {
      chainName: 'eth',
    },
  };

  const rendered = adminSetup.formatAdminCommandOutput(payload);
  assert.match(rendered, /setup complete/);
  assert.match(rendered, /vault key id: vault-key-123/);
  assert.match(rendered, /agent key id: 00000000-0000-0000-0000-000000000001/);
  assert.match(rendered, /daemon socket: \/Library\/AgentPay\/run\/daemon\.sock/);
  assert.match(rendered, /state file: \/var\/db\/agentpay\/daemon-state\.enc/);
  assert.match(rendered, /chain: eth/);
  assert.match(
    rendered,
    new RegExp(`agent auth token: stored in ${HOST_AGENT_AUTH_STORAGE}`, 'u'),
  );
  assert.match(rendered, /credential service: agentpay-agent-auth-token/);
  assert.doesNotMatch(rendered, /secret-agent-token/);
  assert.doesNotMatch(rendered, /vault private key:/);

  const renderedWithSecrets = adminSetup.formatAdminCommandOutput(payload, {
    includeSecrets: true,
  });
  assert.match(renderedWithSecrets, /agent auth token: secret-agent-token/);
  assert.doesNotMatch(renderedWithSecrets, /vault private key:/);
  assert.match(renderedWithSecrets, /warning: keep the agent auth token carefully/);
});

test('resolveAdminSetupVaultPassword rejects inline vault password input', async () => {
  const adminSetup = await loadModule(`${Date.now()}-resolve-inline-password`);

  await assert.rejects(
    () =>
      adminSetup.resolveAdminSetupVaultPassword({
        vaultPassword: 'vault-secret',
      }),
    /insecure --vault-password is disabled/,
  );
});

test('resolveAdminSetupVaultPassword rejects AGENTPAY_VAULT_PASSWORD for setup flows', async () => {
  const adminSetup = await loadModule(`${Date.now()}-resolve-env-password`);

  await assert.rejects(
    () =>
      adminSetup.resolveAdminSetupVaultPassword(
        {},
        {
          env: {
            AGENTPAY_VAULT_PASSWORD: 'vault-secret',
          },
        },
      ),
    /AGENTPAY_VAULT_PASSWORD is disabled for security/,
  );
});

test('resolveAdminSetupVaultPassword requires stdin in non-interactive mode', async () => {
  const adminSetup = await loadModule(`${Date.now()}-resolve-non-interactive-password`);

  await assert.rejects(
    () =>
      adminSetup.resolveAdminSetupVaultPassword({
        nonInteractive: true,
      }),
    /use --vault-password-stdin/,
  );
});

test('resolveAdminSetupVaultPassword still accepts stdin relays', async () => {
  const adminSetup = await loadModule(`${Date.now()}-resolve-stdin-password`);
  let requestedLabel = null;

  const password = await adminSetup.resolveAdminSetupVaultPassword(
    {
      vaultPasswordStdin: true,
    },
    {
      readTrimmedStdin: async (label) => {
        requestedLabel = label;
        return 'vault-secret';
      },
    },
  );

  assert.equal(password, 'vault-secret');
  assert.equal(requestedLabel, 'vault password');
});

test('resolveAdminSetupVaultPassword uses the default stdin reader and validates streamed input', async () => {
  const adminSetup = await loadModule(`${Date.now()}-resolve-default-stdin-password`);

  await withMockedProcessStdin(['vault-secret\n'], async () => {
    const password = await adminSetup.resolveAdminSetupVaultPassword({
      vaultPasswordStdin: true,
    });
    assert.equal(password, 'vault-secret');
  });

  await withMockedProcessStdin(['   \n'], async () => {
    await assert.rejects(
      () =>
        adminSetup.resolveAdminSetupVaultPassword({
          vaultPasswordStdin: true,
        }),
      /vault password must not be empty or whitespace/u,
    );
  });

  await withMockedProcessStdin(['a'.repeat(16 * 1024 + 1)], async () => {
    await assert.rejects(
      () =>
        adminSetup.resolveAdminSetupVaultPassword({
          vaultPasswordStdin: true,
        }),
      /vault password must not exceed/u,
    );
  });
});

test('createAdminSetupPlan summarizes install readiness, overwrite risk, and wallet preview', async () => {
  const adminSetup = await loadModule(`${Date.now()}-admin-plan`);

  const plan = adminSetup.createAdminSetupPlan(
    {
      nonInteractive: true,
      daemonSocket: '/Library/AgentPay/run/daemon.sock',
      network: '1',
      rpcUrl: 'https://rpc.example',
      chainName: 'eth',
      perTxMaxWei: '1',
      dailyMaxWei: '2',
      weeklyMaxWei: '3',
      maxGasPerChainWei: '4',
      token: ['0x0000000000000000000000000000000000000001'],
      allowNativeEth: true,
      attachPolicyId: ['00000000-0000-0000-0000-000000000099'],
      attachBootstrapPolicies: true,
    },
    {
      readConfig: () => ({
        rustBinDir: '/tmp/agentpay-rust-bin',
        agentKeyId: '00000000-0000-0000-0000-000000000001',
        wallet: {
          address: '0x1111111111111111111111111111111111111111',
          vaultKeyId: '00000000-0000-0000-0000-000000000003',
          vaultPublicKey: '03abcdef',
          policyAttachment: 'policy_set',
        },
        agentAuthToken: 'legacy-token',
        chains: {},
      }),
      assertManagedDaemonInstallPreconditions: () => ({
        runnerPath: '/tmp/agentpay-rust-bin/run-agentpay-daemon.sh',
        daemonBin: '/tmp/agentpay-rust-bin/agentpay-daemon',
        keychainHelperBin: '/tmp/agentpay-rust-bin/agentpay-system-keychain',
        installScript: '/tmp/install-user-daemon.sh',
        managedRunnerPath: '/Library/AgentPay/bin/run-agentpay-daemon.sh',
        managedDaemonBin: '/Library/AgentPay/bin/agentpay-daemon',
        managedKeychainHelperBin: '/Library/AgentPay/bin/agentpay-system-keychain',
      }),
    },
  );

  assert.equal(plan.command, 'setup');
  assert.equal(plan.mode, 'plan');
  assert.equal(plan.daemon.installReady, true);
  assert.equal(plan.daemon.installError, null);
  assert.equal(plan.overwrite.required, true);
  assert.equal(plan.overwrite.requiresYesInNonInteractive, true);
  assert.equal(plan.walletSetup.policyScope.network, 1);
  assert.equal(plan.walletSetup.configAfterSetup.rpcUrl, 'https://rpc.example');
  assert.equal(plan.existingWallet?.address, '0x1111111111111111111111111111111111111111');
  assert.equal(plan.existingWallet?.hasLegacyAgentAuthToken, true);
});

test('createAdminSetupPlan forwards existing wallet reuse metadata into the bootstrap preview', async () => {
  const adminSetup = await loadModule(`${Date.now()}-admin-plan-reuse-wallet`);

  const plan = adminSetup.createAdminSetupPlan(
    {
      reuseExistingWallet: true,
      daemonSocket: '/Library/AgentPay/run/daemon.sock',
    },
    {
      readConfig: () => ({
        rustBinDir: '/tmp/agentpay-rust-bin',
        wallet: {
          address: '0x1111111111111111111111111111111111111111',
          vaultKeyId: '00000000-0000-0000-0000-000000000003',
          vaultPublicKey: '03abcdef',
          policyAttachment: 'policy_set',
        },
        chains: {},
      }),
      assertManagedDaemonInstallPreconditions: () => ({
        runnerPath: '/tmp/agentpay-rust-bin/run-agentpay-daemon.sh',
        daemonBin: '/tmp/agentpay-rust-bin/agentpay-daemon',
        keychainHelperBin: '/tmp/agentpay-rust-bin/agentpay-system-keychain',
        installScript: '/tmp/install-user-daemon.sh',
        managedRunnerPath: '/Library/AgentPay/bin/run-agentpay-daemon.sh',
        managedDaemonBin: '/Library/AgentPay/bin/agentpay-daemon',
        managedKeychainHelperBin: '/Library/AgentPay/bin/agentpay-system-keychain',
      }),
    },
  );

  assert.equal(plan.walletSetup.rustCommand.args.includes('--existing-vault-key-id'), true);
  assert.equal(plan.walletSetup.rustCommand.args.includes('--existing-vault-public-key'), true);
});

test('createAdminSetupPlan treats attach-bootstrap-policies as wallet reuse for existing wallets', async () => {
  const adminSetup = await loadModule(`${Date.now()}-admin-plan-attach-bootstrap-policies`);

  const plan = adminSetup.createAdminSetupPlan(
    {
      attachBootstrapPolicies: true,
      daemonSocket: '/Library/AgentPay/run/daemon.sock',
    },
    {
      readConfig: () => ({
        rustBinDir: '/tmp/agentpay-rust-bin',
        wallet: {
          address: '0x1111111111111111111111111111111111111111',
          vaultKeyId: '00000000-0000-0000-0000-000000000003',
          vaultPublicKey: '03abcdef',
          policyAttachment: 'policy_set',
        },
        chains: {},
      }),
      assertManagedDaemonInstallPreconditions: () => ({
        runnerPath: '/tmp/agentpay-rust-bin/run-agentpay-daemon.sh',
        daemonBin: '/tmp/agentpay-rust-bin/agentpay-daemon',
        keychainHelperBin: '/tmp/agentpay-rust-bin/agentpay-system-keychain',
        installScript: '/tmp/install-user-daemon.sh',
        managedRunnerPath: '/Library/AgentPay/bin/run-agentpay-daemon.sh',
        managedDaemonBin: '/Library/AgentPay/bin/agentpay-daemon',
        managedKeychainHelperBin: '/Library/AgentPay/bin/agentpay-system-keychain',
      }),
    },
  );

  assert.equal(plan.walletSetup.rustCommand.args.includes('--existing-vault-key-id'), true);
  assert.equal(plan.walletSetup.rustCommand.args.includes('--existing-vault-public-key'), true);
});

test('formatAdminSetupPlanText includes install failures and the nested wallet preview', async () => {
  const adminSetup = await loadModule(`${Date.now()}-admin-plan-text`);

  const plan = adminSetup.createAdminSetupPlan(
    {
      token: [],
      attachPolicyId: [],
    },
    {
      readConfig: () => ({
        rustBinDir: '/tmp/agentpay-rust-bin',
        chains: {},
      }),
      assertManagedDaemonInstallPreconditions: () => {
        throw new Error('daemon binary is not installed at /tmp/agentpay-rust-bin/agentpay-daemon');
      },
    },
  );

  const rendered = adminSetup.formatAdminSetupPlanText(plan);

  assert.match(rendered, /^Admin Setup Preview/m);
  assert.match(rendered, /Managed Service Install: blocked/);
  assert.match(rendered, /daemon binary is not installed/);
  assert.match(rendered, /Existing Wallet\n- none/);
  assert.match(rendered, /Wallet Setup Preview/);
  assert.match(rendered, /Managed Socket:/);
});

test('formatAdminSetupPlanText includes existing wallet detail rows when present', async () => {
  const adminSetup = await loadModule(`${Date.now()}-admin-plan-text-existing-wallet`);

  const plan = adminSetup.createAdminSetupPlan(
    {
      token: [],
      attachPolicyId: [],
    },
    {
      readConfig: () => ({
        agentKeyId: '00000000-0000-0000-0000-000000000111',
        agentAuthToken: 'legacy-token',
        wallet: {
          address: '0x1111111111111111111111111111111111111111',
          vaultPublicKey: '03abcdef',
          policyAttachment: 'policy_set',
        },
        chains: {},
      }),
      assertManagedDaemonInstallPreconditions: () => ({
        runnerPath: '/tmp/runner.sh',
        daemonBin: '/tmp/daemon',
        keychainHelperBin: '/tmp/helper',
        installScript: '/tmp/install.sh',
        managedRunnerPath: '/Library/AgentPay/bin/run-agentpay-daemon.sh',
        managedDaemonBin: '/Library/AgentPay/bin/agentpay-daemon',
        managedKeychainHelperBin: '/Library/AgentPay/bin/agentpay-system-keychain',
      }),
    },
  );

  const rendered = adminSetup.formatAdminSetupPlanText(plan);
  assert.match(rendered, /Existing Wallet/u);
  assert.match(rendered, /Address: 0x1111111111111111111111111111111111111111/u);
  assert.match(rendered, /Agent Key ID: 00000000-0000-0000-0000-000000000111/u);
  assert.match(rendered, /Legacy Config Token Present: yes/u);
});

test('formatAdminSetupPlanText shows unknown existing wallet fields when only legacy config state remains', async () => {
  const adminSetup = await loadModule(`${Date.now()}-admin-plan-text-existing-wallet-unknown`);

  const plan = adminSetup.createAdminSetupPlan(
    {
      token: [],
      attachPolicyId: [],
    },
    {
      readConfig: () => ({
        agentAuthToken: 'legacy-token',
        chains: {},
      }),
      assertManagedDaemonInstallPreconditions: () => ({
        runnerPath: '/tmp/runner.sh',
        daemonBin: '/tmp/daemon',
        keychainHelperBin: '/tmp/helper',
        installScript: '/tmp/install.sh',
        managedRunnerPath: '/Library/AgentPay/bin/run-agentpay-daemon.sh',
        managedDaemonBin: '/Library/AgentPay/bin/agentpay-daemon',
        managedKeychainHelperBin: '/Library/AgentPay/bin/agentpay-system-keychain',
      }),
    },
  );

  const rendered = adminSetup.formatAdminSetupPlanText(plan);
  assert.match(rendered, /Address: unknown/u);
  assert.match(rendered, /Agent Key ID: unknown/u);
  assert.match(rendered, /Legacy Config Token Present: yes/u);
});

test('confirmAdminSetupOverwrite uses default prompt path and fails closed without a tty', async () => {
  const adminSetup = await loadModule(`${Date.now()}-overwrite-default-prompt-no-tty`);
  const stdinDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
  const stdoutDescriptor = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
  Object.defineProperty(process.stdin, 'isTTY', { value: false, configurable: true });
  Object.defineProperty(process.stdout, 'isTTY', { value: false, configurable: true });

  try {
    await assert.rejects(
      () =>
        adminSetup.confirmAdminSetupOverwrite(
          {},
          {
            agentKeyId: '00000000-0000-0000-0000-000000000001',
            chains: {},
          },
        ),
      /requires --yes in non-interactive environments/,
    );
  } finally {
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
  }
});

test('confirmAdminSetupOverwrite default prompt accepts OVERWRITE and warns about legacy tokens', async () => {
  const adminSetup = await loadModule(`${Date.now()}-overwrite-default-prompt-success`);
  let warning = '';

  await withMockedPrompt('OVERWRITE', async () => {
    await adminSetup.confirmAdminSetupOverwrite(
      {},
      {
        wallet: {
          address: '0x1111111111111111111111111111111111111111',
          vaultPublicKey: '03abcdef',
          policyAttachment: 'policy_set',
        },
        agentKeyId: '00000000-0000-0000-0000-000000000001',
        agentAuthToken: 'legacy-config-token',
        chains: {},
      },
      {
        stderr: {
          write: (value) => {
            warning += String(value);
            return true;
          },
        },
      },
    );
  });

  assert.match(warning, /legacy agent auth token is still present in config\.json/u);
});

test('confirmAdminSetupOverwrite reuse mode requires REUSE and updates the warning text', async () => {
  const adminSetup = await loadModule(`${Date.now()}-overwrite-reuse-prompt-success`);
  let warning = '';
  let prompt = '';

  await adminSetup.confirmAdminSetupOverwrite(
    {
      reuseExistingWallet: true,
    },
    {
      wallet: {
        address: '0x1111111111111111111111111111111111111111',
        vaultPublicKey: '03abcdef',
        policyAttachment: 'policy_set',
      },
      agentKeyId: '00000000-0000-0000-0000-000000000001',
      chains: {},
    },
    {
      prompt: async (query) => {
        prompt = query;
        return 'REUSE';
      },
      stderr: {
        write: (value) => {
          warning += String(value);
          return true;
        },
      },
    },
  );

  assert.match(warning, /reuse the current vault and refresh the local wallet metadata and agent credentials/u);
  assert.equal(prompt, 'Type REUSE to reattach the current local vault: ');
});

test('resolveAdminSetupVaultPassword rejects conflicting flags and default prompt without tty', async () => {
  const adminSetup = await loadModule(`${Date.now()}-resolve-password-conflict-default-prompt`);

  await assert.rejects(
    () =>
      adminSetup.resolveAdminSetupVaultPassword({
        vaultPassword: 'vault-secret',
        vaultPasswordStdin: true,
      }),
    /--vault-password conflicts with --vault-password-stdin/,
  );

  await assert.rejects(
    () => adminSetup.resolveAdminSetupVaultPassword({}),
    /vault password is required; use --vault-password-stdin or a local TTY prompt/,
  );
});

test('buildAdminSetupBootstrapInvocation validates vault password secrecy constraints', async () => {
  const adminSetup = await loadModule(`${Date.now()}-setup-bootstrap-password-validation`);

  assert.throws(
    () =>
      adminSetup.buildAdminSetupBootstrapInvocation({
        vaultPassword: ' ',
        daemonSocket: '/Library/AgentPay/run/daemon.sock',
        bootstrapOutputPath: '/tmp/bootstrap.json',
      }),
    /vault password must not be empty or whitespace/,
  );

  assert.throws(
    () =>
      adminSetup.buildAdminSetupBootstrapInvocation({
        vaultPassword: 'a'.repeat(16 * 1024 + 1),
        daemonSocket: '/Library/AgentPay/run/daemon.sock',
        bootstrapOutputPath: '/tmp/bootstrap.json',
      }),
    /vault password must not exceed 16384 bytes/,
  );
});

test('createAdminSetupPlan rejects rpc and chain metadata without a selected network', async () => {
  const adminSetup = await loadModule(`${Date.now()}-create-plan-network-validation`);

  assert.throws(
    () =>
      adminSetup.createAdminSetupPlan({
        rpcUrl: 'https://rpc.example',
      }),
    /--rpc-url requires --network/,
  );

  assert.throws(
    () =>
      adminSetup.createAdminSetupPlan({
        chainName: 'eth',
      }),
    /--chain-name requires --network/,
  );
});

test('formatAdminCommandOutput handles scalar values and tui cancellation summaries', async () => {
  const adminSetup = await loadModule(`${Date.now()}-format-admin-output-scalars`);

  assert.equal(adminSetup.formatAdminCommandOutput('plain output'), 'plain output');
  assert.equal(adminSetup.formatAdminCommandOutput(123), '123');
  assert.equal(
    adminSetup.formatAdminCommandOutput({
      command: 'tui',
      canceled: true,
    }),
    'tui canceled',
  );
});

test('formatAdminCommandOutput falls back to unconfigured defaults when optional fields are absent', async () => {
  const adminSetup = await loadModule(`${Date.now()}-format-admin-output-minimal`);

  const rendered = adminSetup.formatAdminCommandOutput({
    command: 'setup',
    config: {},
    daemon: {},
    keychain: {},
  });

  assert.match(rendered, /setup complete/u);
  assert.match(rendered, /chain: unconfigured/u);
  assert.match(
    rendered,
    new RegExp(`agent auth token: stored in ${HOST_AGENT_AUTH_STORAGE}`, 'u'),
  );
  assert.doesNotMatch(rendered, /daemon socket:/u);
  assert.doesNotMatch(rendered, /state file:/u);
  assert.doesNotMatch(rendered, /credential service:/u);
});

test('formatAdminCommandOutput renders direct file-storage notes when setup falls back from secret-tool', async () => {
  const adminSetup = await loadModule(`${Date.now()}-format-admin-output-linux-file-note`);

  const rendered = adminSetup.formatAdminCommandOutput({
    command: 'setup',
    agentKeyId: bootstrapPayload().agent_key_id,
    config: {
      chainName: 'bsc',
    },
    keychain: {
      service: '/tmp/agent-auth/00000000-0000-0000-0000-000000000001.token',
      label: 'Linux local credential file',
      locationType: 'file',
      note: 'secret-tool is unavailable, so the agent auth token is stored in a local file and is directly accessible to this user',
    },
  });

  assert.match(rendered, /agent auth token: stored in Linux local credential file/u);
  assert.match(rendered, /credential file: \/tmp\/agent-auth\/00000000-0000-0000-0000-000000000001\.token/u);
  assert.match(rendered, /note: secret-tool is unavailable/u);
});

function writeExecutable(targetPath, body) {
  fs.writeFileSync(targetPath, `#!/bin/sh\n${body}\n`, { mode: 0o755 });
}

function writeNodeExecutable(targetPath, body) {
  fs.writeFileSync(targetPath, `#!/usr/bin/env node\n${body}\n`, { mode: 0o755 });
}

function writeMockSecretTool(targetPath) {
  writeNodeExecutable(
    targetPath,
    [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      "const root = process.env.AGENTPAY_MOCK_SECRET_TOOL_ROOT;",
      "if (!root) { process.stderr.write('missing AGENTPAY_MOCK_SECRET_TOOL_ROOT\\n'); process.exit(2); }",
      'const args = process.argv.slice(2);',
      'const command = args[0];',
      'const attrs = new Map();',
      'for (let i = 1; i < args.length; i += 2) {',
      '  attrs.set(String(args[i]), String(args[i + 1] ?? ""));',
      '}',
      'const service = attrs.get("service") || "default-service";',
      'const account = attrs.get("account") || "default-account";',
      'const targetPath = path.join(root, encodeURIComponent(service), encodeURIComponent(account));',
      'if (command === "store") {',
      '  const input = fs.readFileSync(0, "utf8").replace(/[\\r\\n]+$/u, "");',
      '  fs.mkdirSync(path.dirname(targetPath), { recursive: true, mode: 0o700 });',
      '  fs.writeFileSync(targetPath, input, { encoding: "utf8", mode: 0o600 });',
      '  process.exit(0);',
      '}',
      'if (command === "lookup") {',
      '  if (!fs.existsSync(targetPath)) { process.exit(1); }',
      '  process.stdout.write(fs.readFileSync(targetPath, "utf8"));',
      '  process.exit(0);',
      '}',
      'if (command === "clear") {',
      '  if (!fs.existsSync(targetPath)) { process.exit(1); }',
      '  fs.rmSync(targetPath, { force: true });',
      '  process.exit(0);',
      '}',
      'process.stderr.write(`unsupported secret-tool command: ${command}\\n`);',
      'process.exit(2);',
    ].join('\n'),
  );
}

function writePrivateJsonFile(targetPath, payload) {
  fs.mkdirSync(path.dirname(targetPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(targetPath, `${JSON.stringify(payload, null, 2)}\n`, {
    encoding: 'utf8',
    mode: 0o600,
  });
  fs.chmodSync(targetPath, 0o600);
}

function bootstrapPayload() {
  return {
    state_file: 'daemon_socket:/Library/AgentPay/run/daemon.sock',
    lease_id: 'lease-admin-setup-test',
    lease_expires_at: '2099-01-01T00:00:00Z',
    per_tx_policy_id: 'policy-per-tx',
    daily_policy_id: 'policy-daily',
    weekly_policy_id: 'policy-weekly',
    gas_policy_id: 'policy-gas',
    per_tx_max_wei: '1000000000000000000',
    daily_max_wei: '5000000000000000000',
    weekly_max_wei: '20000000000000000000',
    max_gas_per_chain_wei: '1000000000000000',
    daily_max_tx_count: null,
    daily_tx_count_policy_id: null,
    per_tx_max_fee_per_gas_wei: null,
    per_tx_max_fee_per_gas_policy_id: null,
    per_tx_max_priority_fee_per_gas_wei: null,
    per_tx_max_priority_fee_per_gas_policy_id: null,
    per_tx_max_calldata_bytes: null,
    per_tx_max_calldata_bytes_policy_id: null,
    vault_key_id: 'vault-key-admin-setup',
    vault_public_key: '03abcdef',
    vault_private_key: '11'.repeat(32),
    agent_key_id: '00000000-0000-0000-0000-000000000001',
    agent_auth_token: 'admin-setup-token',
    agent_auth_token_redacted: false,
    network_scope: 'all networks',
    asset_scope: 'all assets',
    recipient_scope: 'all recipients',
    destination_override_count: 0,
    destination_overrides: [],
    token_policies: [],
    token_destination_overrides: [],
    token_manual_approval_policies: [],
    policy_attachment: 'policy_set',
    attached_policy_ids: ['policy-per-tx', 'policy-daily', 'policy-weekly', 'policy-gas'],
    policy_note: 'bootstrap note',
  };
}

async function withMockedPrompt(answer, fn, options = {}) {
  const resolveAnswer = (query = '') => {
    if (
      typeof answer === 'string' &&
      /wallet backup/iu.test(query) &&
      !/^(|y|yes|n|no|skip)$/iu.test(answer.trim())
    ) {
      return 'skip';
    }
    return typeof answer === 'function' ? answer(query) : answer;
  };
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
          process.stdin.emit('data', Buffer.from(String(resolveAnswer()), 'utf8'));
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
    question(query, callback) {
      callback(resolveAnswer(query));
    },
    close() {},
  }));
  try {
    await fn();
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

function writeMockAdminBinary(targetPath) {
  writeNodeExecutable(
    targetPath,
    [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      'const args = process.argv.slice(2);',
      "const outputIndex = args.indexOf('--output');",
      'const outputPath = outputIndex >= 0 ? args[outputIndex + 1] : null;',
      "const relayCounterPath = process.env.AGENTPAY_MOCK_RELAY_COUNTER || null;",
      `const payload = ${JSON.stringify(bootstrapPayload(), null, 2)};`,
      'const writeBootstrap = () => {',
      '  if (!outputPath) return;',
      "  fs.mkdirSync(path.dirname(outputPath), { recursive: true, mode: 0o700 });",
      "  fs.writeFileSync(outputPath, `${JSON.stringify(payload, null, 2)}\\n`, { mode: 0o600 });",
      '  fs.chmodSync(outputPath, 0o600);',
      '};',
      'const relayExitCode = () => {',
      "  const sequence = (process.env.AGENTPAY_MOCK_RELAY_SEQUENCE || '')",
      "    .split(',')",
      '    .map((value) => value.trim())',
      '    .filter(Boolean);',
      '  if (sequence.length > 0) {',
      '    let index = 0;',
      '    if (relayCounterPath) {',
      '      try {',
      "        index = Number.parseInt(fs.readFileSync(relayCounterPath, 'utf8').trim(), 10) || 0;",
      '      } catch {}',
      "      fs.writeFileSync(relayCounterPath, String(index + 1), 'utf8');",
      '    }',
      '    const raw = sequence[Math.min(index, sequence.length - 1)];',
      '    return Number(raw);',
      '  }',
      "  if (process.env.AGENTPAY_MOCK_RELAY_EXIT) {",
      '    return Number(process.env.AGENTPAY_MOCK_RELAY_EXIT);',
      '  }',
      "  if (process.env.AGENTPAY_MOCK_RELAY_AUTH_FAIL === '1') {",
      '    return 9;',
      '  }',
      '  return 0;',
      '};',
      "if (args.includes('list-policies')) {",
      '  const code = relayExitCode();',
      '  if (code !== 0) {',
      "    const message = process.env.AGENTPAY_MOCK_RELAY_ERROR_MESSAGE || (code === 9 ? 'authentication failed' : 'mock relay failure');",
      "    process.stderr.write(`${message}\\n`);",
      '    process.exit(code);',
      '  }',
      "  process.stdout.write('[]\\n');",
      '  process.exit(0);',
      '}',
      "if (args.includes('bootstrap')) {",
      '  writeBootstrap();',
      "  if (process.env.AGENTPAY_MOCK_BOOTSTRAP_SYMLINK_OUTPUT === '1' && outputPath) {",
      "    const realPath = `${outputPath}.real`;",
      '    fs.renameSync(outputPath, realPath);',
      '    fs.symlinkSync(realPath, outputPath);',
      '  }',
      "  const code = Number(process.env.AGENTPAY_MOCK_BOOTSTRAP_EXIT || '0');",
      '  if (code !== 0) {',
      "    process.stderr.write('mock bootstrap failure\\n');",
      '    process.exit(code);',
      '  }',
      "  process.stdout.write('{\"ok\":true}\\n');",
      '  process.exit(0);',
      '}',
      "if (args.includes('tui')) {",
      "  if (process.env.AGENTPAY_MOCK_SKIP_TUI_OUTPUT !== '1') {",
      '    writeBootstrap();',
      '  }',
      "  if (process.env.AGENTPAY_MOCK_TUI_SYMLINK_OUTPUT === '1' && outputPath) {",
      "    const realPath = `${outputPath}.real`;",
      '    fs.renameSync(outputPath, realPath);',
      '    fs.symlinkSync(realPath, outputPath);',
      '  }',
      "  const code = Number(process.env.AGENTPAY_MOCK_TUI_EXIT || '0');",
      '  process.exit(code);',
      '}',
      "process.stdout.write('{}\\n');",
      'process.exit(0);',
    ].join('\n'),
  );
}

function writeDefaultMockSudo(targetPath) {
  writeExecutable(
    targetPath,
    [
      'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
      '  cat >/dev/null',
      '  exit 0',
      'fi',
      'if [ "$1" = "-n" ]; then',
      '  exit 0',
      'fi',
      'exit 0',
    ].join('\n'),
  );
}

async function withMockedAdminSetupEnv(fn) {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-admin-setup-cli-'));
  const homeDir = path.join(tempRoot, 'home');
  const agentpayHome = path.join(homeDir, '.agentpay');
  const rustBinDir = path.join(agentpayHome, 'bin');
  const toolDir = path.join(tempRoot, 'tools');
  const secretToolRoot = path.join(tempRoot, 'secret-tool');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(toolDir, { recursive: true, mode: 0o700 });

  writeExecutable(path.join(toolDir, 'security'), 'exit 0');
  writeDefaultMockSudo(path.join(toolDir, 'sudo'));
  writeMockSecretTool(path.join(toolDir, 'secret-tool'));
  writeManagedSetupHelpers(rustBinDir);
  writeMockAdminBinary(path.join(rustBinDir, 'agentpay-admin'));

  fs.writeFileSync(
    path.join(agentpayHome, 'config.json'),
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
  process.env.HOME = homeDir;
  process.env.AGENTPAY_HOME = agentpayHome;
  process.env.PATH = `${toolDir}:${originalPath ?? ''}`;
  process.env.AGENTPAY_MOCK_SECRET_TOOL_ROOT = secretToolRoot;

  try {
    await fn({ tempRoot, homeDir, agentpayHome, rustBinDir, toolDir });
  } finally {
    process.env.HOME = originalHome;
    process.env.AGENTPAY_HOME = originalAgentPayHome;
    process.env.PATH = originalPath;
    delete process.env.AGENTPAY_MOCK_BOOTSTRAP_EXIT;
    delete process.env.AGENTPAY_MOCK_BOOTSTRAP_SYMLINK_OUTPUT;
    delete process.env.AGENTPAY_MOCK_TUI_EXIT;
    delete process.env.AGENTPAY_MOCK_TUI_SYMLINK_OUTPUT;
    delete process.env.AGENTPAY_MOCK_SKIP_TUI_OUTPUT;
    delete process.env.AGENTPAY_MOCK_RELAY_AUTH_FAIL;
    delete process.env.AGENTPAY_MOCK_RELAY_EXIT;
    delete process.env.AGENTPAY_MOCK_RELAY_SEQUENCE;
    delete process.env.AGENTPAY_MOCK_RELAY_ERROR_MESSAGE;
    delete process.env.AGENTPAY_MOCK_RELAY_COUNTER;
    delete process.env.AGENTPAY_MOCK_SECRET_TOOL_ROOT;
    process.exitCode = undefined;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

test('runAdminSetupCli plan mode parses repeated token and attach-policy-id flags', async () => {
  await withMockedAdminSetupEnv(async () => {
    const stdoutChunks = [];
    const originalStdoutWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((chunk, ...args) => {
      if (typeof chunk === 'string' && chunk.trimStart().startsWith('{')) {
        stdoutChunks.push(chunk);
      }
      return true;
    });

    try {
      const adminSetup = await loadModule(`${Date.now()}-run-setup-plan-repeated-options`);
      await adminSetup.runAdminSetupCli([
        '--plan',
        '--json',
        '--network',
        '1',
        '--token',
        '0x0000000000000000000000000000000000000001',
        '--token',
        '0x0000000000000000000000000000000000000002',
        '--attach-policy-id',
        '00000000-0000-0000-0000-000000000001',
        '--attach-policy-id',
        '00000000-0000-0000-0000-000000000002',
      ]);
    } finally {
      process.stdout.write = originalStdoutWrite;
    }

    const payload = JSON.parse(stdoutChunks.join('').trim());
    const rustArgs = payload?.walletSetup?.rustCommand?.args ?? [];
    assert.equal(rustArgs.filter((value) => value === '--token').length, 2);
    assert.equal(rustArgs.filter((value) => value === '--attach-policy-id').length, 2);
  });
});

test('runAdminSetupCli plan mode forwards restore and backup flags', async () => {
  await withMockedAdminSetupEnv(async () => {
    const stdoutChunks = [];
    const originalStdoutWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((chunk, ...args) => {
      if (typeof chunk === 'string' && chunk.trimStart().startsWith('{')) {
        stdoutChunks.push(chunk);
      }
      return true;
    });

    try {
      const adminSetup = await loadModule(`${Date.now()}-run-setup-plan-restore-wallet`);
      await adminSetup.runAdminSetupCli([
        '--plan',
        '--json',
        '--restore-wallet-from',
        '/tmp/recovery.json',
        '--backup-output',
        '/tmp/recovery-out.json',
      ]);
    } finally {
      process.stdout.write = originalStdoutWrite;
    }

    const payload = JSON.parse(stdoutChunks.join('').trim());
    const rustArgs = payload?.walletSetup?.rustCommand?.args ?? [];
    const importFlagIndex = rustArgs.indexOf('--import-vault-private-key-file');
    assert.ok(importFlagIndex >= 0);
    assert.equal(rustArgs[importFlagIndex + 1], '<decrypted from backup at runtime>');
  });
});

test('runAdminSetupCli plan mode reuses the current wallet for attach-bootstrap-policies', async () => {
  await withMockedAdminSetupEnv(async ({ agentpayHome, rustBinDir }) => {
    fs.writeFileSync(
      path.join(agentpayHome, 'config.json'),
      `${JSON.stringify(
        {
          rustBinDir,
          wallet: {
            address: '0x1111111111111111111111111111111111111111',
            vaultKeyId: '00000000-0000-0000-0000-000000000003',
            vaultPublicKey: '03abcdef',
            policyAttachment: 'policy_set',
          },
          chains: {},
        },
        null,
        2,
      )}\n`,
      { mode: 0o600 },
    );

    const stdoutChunks = [];
    const originalStdoutWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((chunk, ...args) => {
      if (typeof chunk === 'string' && chunk.trimStart().startsWith('{')) {
        stdoutChunks.push(chunk);
      }
      return true;
    });

    try {
      const adminSetup = await loadModule(`${Date.now()}-run-setup-plan-attach-bootstrap-policies`);
      await adminSetup.runAdminSetupCli([
        '--plan',
        '--json',
        '--attach-bootstrap-policies',
      ]);
    } finally {
      process.stdout.write = originalStdoutWrite;
    }

    const payload = JSON.parse(stdoutChunks.join('').trim());
    const rustArgs = payload?.walletSetup?.rustCommand?.args ?? [];
    assert.ok(rustArgs.includes('--existing-vault-key-id'));
    assert.ok(rustArgs.includes('--existing-vault-public-key'));
  });
});

test('runAdminSetupCli non-json mode renders progress and human summary output', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome }) => {
      const stdoutChunks = [];
      const stderrChunks = [];
      const originalStdoutWrite = process.stdout.write.bind(process.stdout);
      const originalStderrWrite = process.stderr.write.bind(process.stderr);
      process.stdout.write = ((chunk, ...args) => {
        stdoutChunks.push(String(chunk));
        return originalStdoutWrite(chunk, ...args);
      });
      process.stderr.write = ((chunk, ...args) => {
        stderrChunks.push(String(chunk));
        return originalStderrWrite(chunk, ...args);
      });

      try {
        const adminSetup = await loadModule(`${Date.now()}-run-setup-success-non-json`);
        await withMockedPrompt('vault-secret', async () => {
          await adminSetup.runAdminSetupCli([
            '--yes',
            '--daemon-socket',
            trustedSocket,
            '--bootstrap-output',
            path.join(agentpayHome, 'bootstrap-human.txt'),
          ]);
        });
      } finally {
        process.stdout.write = originalStdoutWrite;
        process.stderr.write = originalStderrWrite;
      }

      assert.match(stdoutChunks.join(''), /setup complete/u);
      assert.match(stdoutChunks.join(''), /chain: bsc/u);
      assert.match(
        stdoutChunks.join(''),
        new RegExp(`agent auth token: stored in ${HOST_AGENT_AUTH_STORAGE}`, 'u'),
      );
      assert.match(stderrChunks.join(''), /Setting up wallet access|Daemon is ready/u);
    });
  });
});

test('runAdminSetupCli falls back to a local credential file when secret-tool is unavailable on Linux', async () => {
  if (process.platform !== 'linux') {
    return;
  }

  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome, toolDir }) => {
      const stdoutChunks = [];
      const originalStdoutWrite = process.stdout.write.bind(process.stdout);
      const originalPath = process.env.PATH;
      const expectedAgentKeyId = bootstrapPayload().agent_key_id;
      const expectedToken = bootstrapPayload().agent_auth_token;
      const expectedCredentialPath = path.join(
        agentpayHome,
        'agent-auth',
        `${expectedAgentKeyId}.token`,
      );

      process.stdout.write = ((chunk, ...args) => {
        stdoutChunks.push(String(chunk));
        return originalStdoutWrite(chunk, ...args);
      });
      process.env.PATH = `${toolDir}:${path.dirname(process.execPath)}`;
      fs.rmSync(path.join(toolDir, 'secret-tool'), { force: true });

      try {
        const adminSetup = await loadModule(`${Date.now()}-run-setup-linux-file-fallback`);
        await withMockedPrompt('vault-secret', async () => {
          await adminSetup.runAdminSetupCli([
            '--yes',
            '--daemon-socket',
            trustedSocket,
            '--bootstrap-output',
            path.join(agentpayHome, 'bootstrap-linux-file-fallback.json'),
          ]);
        });
      } finally {
        process.stdout.write = originalStdoutWrite;
        process.env.PATH = originalPath;
      }

      const output = stdoutChunks.join('');
      assert.match(output, /agent auth token: stored in Linux local credential file/u);
      assert.match(output, /note: secret-tool is unavailable/u);
      assert.match(
        output,
        new RegExp(expectedCredentialPath.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&'), 'u'),
      );
      assert.equal(fs.readFileSync(expectedCredentialPath, 'utf8'), expectedToken);
      assert.equal(fs.statSync(expectedCredentialPath).mode & 0o777, 0o600);
    });
  });
});

test('runAdminSetupCli skips wallet backup prompts by default on fresh setup', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome }) => {
      const stdoutChunks = [];
      const originalStdoutWrite = process.stdout.write.bind(process.stdout);
      let promptCount = 0;
      process.stdout.write = ((chunk, ...args) => {
        stdoutChunks.push(String(chunk));
        return originalStdoutWrite(chunk, ...args);
      });

      try {
        const adminSetup = await loadModule(`${Date.now()}-run-setup-skip-default-backup`);
        await withMockedPrompt((query) => {
          promptCount += 1;
          assert.doesNotMatch(query, /wallet backup/iu);
          return 'vault-secret';
        }, async () => {
          await adminSetup.runAdminSetupCli([
            '--yes',
            '--daemon-socket',
            trustedSocket,
            '--bootstrap-output',
            path.join(agentpayHome, 'bootstrap-skip-default-backup.json'),
          ]);
        });
      } finally {
        process.stdout.write = originalStdoutWrite;
      }

      const output = stdoutChunks.join('');
      assert.equal(promptCount, 2);
      assert.match(output, /wallet backup: skipped by default/u);
      assert.match(output, /wallet backup command: agentpay admin wallet-backup export --output/u);
      assert.doesNotMatch(output, /wallet backup path:/u);
    });
  });
});

test('runAdminSetupCli falls back to plain text progress when stderr is not a tty', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async () => {
      const stderrChunks = [];
      const originalStderrWrite = process.stderr.write.bind(process.stderr);
      process.stderr.write = ((chunk, ...args) => {
        stderrChunks.push(String(chunk));
        return originalStderrWrite(chunk, ...args);
      });

      try {
        const adminSetup = await loadModule(`${Date.now()}-run-setup-non-tty-progress`);
        await withMockedProcessStdin(['vault-secret\n'], async () => {
          await adminSetup.runAdminSetupCli([
            '--vault-password-stdin',
            '--non-interactive',
            '--daemon-socket',
            trustedSocket,
          ]);
        });
      } finally {
        process.stderr.write = originalStderrWrite;
      }

      const rendered = stderrChunks.join('');
      assert.match(rendered, /==> Checking existing daemon/u);
      assert.match(rendered, /✓ Bootstrap completed/u);
    });
  });
});

test('runAdminSetupCli warns when bootstrap cleanup cannot scrub a failed explicit output path', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome }) => {
      process.env.AGENTPAY_MOCK_BOOTSTRAP_EXIT = '9';
      process.env.AGENTPAY_MOCK_BOOTSTRAP_SYMLINK_OUTPUT = '1';
      const bootstrapOutputPath = path.join(agentpayHome, 'bootstrap-cleanup-warning.json');

      const stderrChunks = [];
      const originalStderrWrite = process.stderr.write.bind(process.stderr);
      process.stderr.write = ((chunk, ...args) => {
        stderrChunks.push(String(chunk));
        return originalStderrWrite(chunk, ...args);
      });

      try {
        const adminSetup = await loadModule(`${Date.now()}-run-setup-bootstrap-cleanup-warning`);
        await withMockedPrompt('vault-secret', async () => {
          await adminSetup.runAdminSetupCli([
            '--yes',
            '--daemon-socket',
            trustedSocket,
            '--bootstrap-output',
            bootstrapOutputPath,
            '--json',
          ]);
        });
      } finally {
        process.stderr.write = originalStderrWrite;
      }

      assert.equal(process.exitCode, 9);
      assert.match(
        stderrChunks.join(''),
        /warning: failed to scrub bootstrap output after setup failure/u,
      );
    });
  });
});

test('runAdminSetupCli warns when temporary wallet import key cleanup fails after restore', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome }) => {
      const walletBackup = await import(
        walletBackupModulePath.href + `?case=${Date.now()}-restore-cleanup-warning`
      );
      const backupPath = path.join(agentpayHome, 'restore-wallet.json');
      const backup = walletBackup.createEncryptedWalletBackup({
        privateKeyHex: '11'.repeat(32),
        sourceVaultKeyId: '00000000-0000-0000-0000-000000000001',
        password: 'backup-secret',
      });
      walletBackup.writeEncryptedWalletBackupFile(backupPath, backup);

      const stderrChunks = [];
      const originalStderrWrite = process.stderr.write.bind(process.stderr);
      const originalRmSync = fs.rmSync;
      process.stderr.write = ((chunk, ...args) => {
        stderrChunks.push(String(chunk));
        return originalStderrWrite(chunk, ...args);
      });
      fs.rmSync = (targetPath, ...args) => {
        if (path.basename(path.resolve(String(targetPath))).startsWith('wallet-import-key-')) {
          throw new Error('delete failed');
        }
        return originalRmSync.call(fs, targetPath, ...args);
      };

      try {
        const adminSetup = await loadModule(
          `${Date.now()}-run-setup-restore-import-key-cleanup-warning`
        );
        let promptCount = 0;
        await withMockedPrompt(() => {
          promptCount += 1;
          if (promptCount <= 2) {
            return 'vault-secret';
          }
          return 'backup-secret';
        }, async () => {
          await adminSetup.runAdminSetupCli([
            '--yes',
            '--daemon-socket',
            trustedSocket,
            '--restore-wallet-from',
            backupPath,
            '--bootstrap-output',
            path.join(agentpayHome, 'bootstrap-restore-cleanup-warning.json'),
            '--json',
          ]);
        });
      } finally {
        process.stderr.write = originalStderrWrite;
        fs.rmSync = originalRmSync;
      }

      assert.match(
        stderrChunks.join(''),
        /warning: failed to delete temporary wallet import key file:/u,
      );
    });
  });
});

test('runAdminTuiCli reports canceled json output when passthrough exits cleanly without bootstrap output', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome }) => {
      process.env.AGENTPAY_MOCK_SKIP_TUI_OUTPUT = '1';
      const stdoutChunks = [];
      const originalStdoutWrite = process.stdout.write.bind(process.stdout);
      process.stdout.write = ((chunk, ...args) => {
        stdoutChunks.push(String(chunk));
        return originalStdoutWrite(chunk, ...args);
      });

      try {
        const adminSetup = await loadModule(`${Date.now()}-run-tui-canceled`);
        await withMockedPrompt('vault-secret', async () => {
          await adminSetup.runAdminTuiCli([
            '--daemon-socket',
            trustedSocket,
            '--bootstrap-output',
            path.join(agentpayHome, 'bootstrap-tui-canceled.json'),
            '--json',
          ]);
        });
      } finally {
        process.stdout.write = originalStdoutWrite;
      }

      const output = stdoutChunks.join('');
      assert.match(output, /"command": "tui"/u);
      assert.match(output, /"canceled": true/u);
    });
  });
});

test('runAdminTuiCli still opens when a saved chain profile rpcUrl is malformed', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome }) => {
      const configPath = path.join(agentpayHome, 'config.json');
      const currentConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      currentConfig.chains = {
        sol: {
          chainId: 101,
          name: 'sol',
          rpcUrl: 'not-a-url',
        },
      };
      fs.writeFileSync(configPath, `${JSON.stringify(currentConfig, null, 2)}\n`, {
        encoding: 'utf8',
        mode: 0o600,
      });
      fs.chmodSync(configPath, 0o600);

      process.env.AGENTPAY_MOCK_SKIP_TUI_OUTPUT = '1';
      const adminSetup = await loadModule(`${Date.now()}-run-tui-invalid-rpc-url`);
      await withMockedPrompt('vault-secret', async () => {
        await adminSetup.runAdminTuiCli([
          '--daemon-socket',
          trustedSocket,
          '--bootstrap-output',
          path.join(agentpayHome, 'bootstrap-tui-invalid-rpc-url.json'),
          '--json',
        ]);
      });

      assert.equal(process.exitCode, undefined);
    });
  });
});

test('runAdminSetupCli completes setup with mocked rust binaries and keychain', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome }) => {
      const bootstrapPath = path.join(agentpayHome, 'bootstrap-explicit.json');
      const stdoutChunks = [];
      const originalStdoutWrite = process.stdout.write.bind(process.stdout);
      process.stdout.write = ((chunk, ...args) => {
        stdoutChunks.push(String(chunk));
        return originalStdoutWrite(chunk, ...args);
      });

      try {
        const adminSetup = await loadModule(`${Date.now()}-run-setup-success`);
        await withMockedPrompt('vault-secret', async () => {
          await adminSetup.runAdminSetupCli([
            '--yes',
            '--daemon-socket',
            trustedSocket,
            '--bootstrap-output',
            bootstrapPath,
            '--json',
          ]);
        });
      } finally {
        process.stdout.write = originalStdoutWrite;
      }

      const updatedConfig = JSON.parse(fs.readFileSync(path.join(agentpayHome, 'config.json'), 'utf8'));
      assert.equal(updatedConfig.agentKeyId, '00000000-0000-0000-0000-000000000001');
      assert.equal(updatedConfig.daemonSocket, trustedSocket);
      assert.equal(updatedConfig.chainId, 56);
      assert.equal(updatedConfig.chainName, 'bsc');
      assert.equal(updatedConfig.rpcUrl, 'https://bsc.drpc.org');
      assert.match(stdoutChunks.join(''), /"command": "setup"/u);

      const redactedBootstrap = JSON.parse(fs.readFileSync(bootstrapPath, 'utf8'));
      assert.equal(redactedBootstrap.agent_auth_token, '<redacted>');
      assert.equal(redactedBootstrap.agent_auth_token_redacted, true);
    });
  });
});

test('runAdminSetupCli returns non-zero exitCode when bootstrap command fails', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome }) => {
      process.env.AGENTPAY_MOCK_BOOTSTRAP_EXIT = '9';
      const bootstrapPath = path.join(agentpayHome, 'bootstrap-explicit.json');
      const stderrChunks = [];
      const originalStderrWrite = process.stderr.write.bind(process.stderr);
      process.stderr.write = ((chunk, ...args) => {
        stderrChunks.push(String(chunk));
        return originalStderrWrite(chunk, ...args);
      });

      try {
        const adminSetup = await loadModule(`${Date.now()}-run-setup-bootstrap-fail`);
        await withMockedPrompt('vault-secret', async () => {
          await adminSetup.runAdminSetupCli([
            '--yes',
            '--daemon-socket',
            trustedSocket,
            '--bootstrap-output',
            bootstrapPath,
            '--json',
          ]);
        });
      } finally {
        process.stderr.write = originalStderrWrite;
      }

      assert.equal(process.exitCode, 9);
      assert.match(stderrChunks.join(''), /mock bootstrap failure/u);
    });
  });
});

test('runAdminTuiCli imports bootstrap output and reports cancellation when passthrough exits non-zero', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome }) => {
      const bootstrapPath = path.join(agentpayHome, 'bootstrap-tui.json');
      const adminSetup = await loadModule(`${Date.now()}-run-tui-success`);
      await withMockedPrompt('vault-secret', async () => {
        await adminSetup.runAdminTuiCli([
          '--daemon-socket',
        trustedSocket,
        '--bootstrap-output',
        bootstrapPath,
        '--json',
      ]);
    });
    assert.equal(process.exitCode, undefined);

    process.env.AGENTPAY_MOCK_TUI_EXIT = '7';
    const failingBootstrap = path.join(agentpayHome, 'bootstrap-tui-fail.json');
      await withMockedPrompt('vault-secret', async () => {
        await adminSetup.runAdminTuiCli([
          '--daemon-socket',
          trustedSocket,
          '--bootstrap-output',
          failingBootstrap,
          '--json',
        ]);
      });
      assert.equal(process.exitCode, 7);
    });
  });
});

test('runAdminSetupCli rejects rpc/chain metadata without a network selector', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome }) => {
      const adminSetup = await loadModule(`${Date.now()}-run-setup-validate`);
      const bootstrapPath = path.join(agentpayHome, 'bootstrap-validate.json');

      await assert.rejects(
        () =>
          adminSetup.runAdminSetupCli([
            '--yes',
            '--daemon-socket',
            trustedSocket,
            '--bootstrap-output',
            bootstrapPath,
            '--rpc-url',
            'https://rpc.example',
          ]),
        /--rpc-url requires --network/,
      );

      await assert.rejects(
        () =>
          adminSetup.runAdminSetupCli([
            '--yes',
            '--daemon-socket',
            trustedSocket,
            '--bootstrap-output',
            bootstrapPath,
            '--chain-name',
            'eth',
          ]),
        /--chain-name requires --network/,
      );
    });
  });
});

test('runAdminSetupCli fails closed before reinstall when daemon password does not match existing managed state', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome, toolDir }) => {
      const installMarkerPath = path.join(agentpayHome, 'install-marker-password-mismatch.txt');
      process.env.AGENTPAY_MOCK_INSTALL_MARKER = installMarkerPath;
      writeNodeExecutable(
        path.join(toolDir, 'sudo'),
        [
          "const fs = require('node:fs');",
          'const args = process.argv.slice(2);',
          "const marker = process.env.AGENTPAY_MOCK_INSTALL_MARKER;",
          "if (args[0] === '-S' && args[3] === '-v') {",
          '  process.stdin.resume();',
          "  process.stdin.on('end', () => process.exit(0));",
          '  return;',
          '}',
          "if (args[0] === '-n' && args[1] === '/bin/test') {",
          '  process.exit(0);',
          '}',
          "if (args[0] === '-n' && args[1] === '/bin/bash') {",
          "  process.stderr.write('failed to initialize daemon\\nCaused by: failed to decrypt state (wrong password or tampered file)\\n');",
          '  process.exit(1);',
          '}',
          "if (args[0] === '-n') {",
          `  if (marker && args.some((value) => String(value).includes(${JSON.stringify(HOST_MANAGED.installScriptName)}))) {`,
          "    fs.writeFileSync(marker, 'installed\\n', 'utf8');",
          '  }',
          '  process.exit(0);',
          '}',
          'process.exit(0);',
        ].join('\n'),
      );

      process.env.AGENTPAY_MOCK_RELAY_AUTH_FAIL = '1';
      try {
        const adminSetup = await loadModule(`${Date.now()}-run-setup-password-mismatch`);
        let renderedStderr = '';
        const originalStderrWrite = process.stderr.write.bind(process.stderr);
        process.stderr.write = ((chunk, ...args) => {
          renderedStderr += String(chunk);
          return originalStderrWrite(chunk, ...args);
        });
        await withMockedPrompt('vault-secret', async () => {
          try {
            await assert.rejects(
              () =>
                adminSetup.runAdminSetupCli([
                  '--yes',
                  '--daemon-socket',
                  trustedSocket,
                  '--bootstrap-output',
                  path.join(agentpayHome, 'bootstrap-mismatch.json'),
                ]),
              /managed daemon state already exists .* encrypted with a different vault password/u,
            );
          } finally {
            process.stderr.write = originalStderrWrite;
          }
        });
        const promptIndex = renderedStderr.indexOf(
          'System admin password for sudo (input hidden; required to install or recover the root-managed daemon): ',
        );
        const inspectIndex = renderedStderr.indexOf('Inspecting managed daemon state before install');
        assert.notEqual(promptIndex, -1);
        assert.notEqual(inspectIndex, -1);
        assert.ok(
          promptIndex < inspectIndex,
          `expected sudo prompt before managed-state inspection output:\n${renderedStderr}`,
        );
      } finally {
        delete process.env.AGENTPAY_MOCK_INSTALL_MARKER;
      }

      assert.equal(fs.existsSync(installMarkerPath), false);
    });
  });
});

test('runAdminSetupCli fails closed when a recovered daemon still has existing managed state', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome, toolDir }) => {
      writeExecutable(
        path.join(toolDir, 'sudo'),
        [
          'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
          '  cat >/dev/null',
          '  exit 0',
          'fi',
          'if [ "$1" = "-n" ] && [ "$2" = "/bin/test" ]; then',
          '  exit 0',
          'fi',
          'if [ "$1" = "-n" ]; then',
          '  exit 0',
          'fi',
          'exit 0',
        ].join('\n'),
      );

      process.env.AGENTPAY_MOCK_RELAY_SEQUENCE = '0,9';
      process.env.AGENTPAY_MOCK_RELAY_COUNTER = path.join(agentpayHome, 'relay-call-count-existing-state.txt');

      const adminSetup = await loadModule(`${Date.now()}-run-setup-state-probe-existing-state`);
      await withMockedPrompt('vault-secret', async () => {
        await assert.rejects(
          () =>
            adminSetup.runAdminSetupCli([
              '--yes',
              '--daemon-socket',
              trustedSocket,
              '--bootstrap-output',
              path.join(agentpayHome, 'bootstrap-existing-state.json'),
            ]),
          /managed daemon state already exists .* encrypted with a different vault password/u,
        );
      });
    });
  });
});

test('runAdminSetupCli surfaces managed-state probe errors after daemon password rejection', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome, toolDir }) => {
      writeExecutable(
        path.join(toolDir, 'sudo'),
        [
          'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
          '  cat >/dev/null',
          '  exit 0',
          'fi',
          'if [ "$1" = "-n" ] && [ "$2" = "/bin/test" ]; then',
          "  echo 'managed state probe failed' >&2",
          '  exit 2',
          'fi',
          'if [ "$1" = "-n" ]; then',
          '  exit 0',
          'fi',
          'exit 0',
        ].join('\n'),
      );

      process.env.AGENTPAY_MOCK_RELAY_SEQUENCE = '0,9';
      process.env.AGENTPAY_MOCK_RELAY_COUNTER = path.join(agentpayHome, 'relay-call-count-state-probe-fail.txt');

      const adminSetup = await loadModule(`${Date.now()}-run-setup-state-probe-fail`);
      await withMockedPrompt('vault-secret', async () => {
        await assert.rejects(
          () =>
            adminSetup.runAdminSetupCli([
              '--yes',
              '--daemon-socket',
              trustedSocket,
              '--bootstrap-output',
              path.join(agentpayHome, 'bootstrap-state-probe-fail.json'),
            ]),
          /managed state probe failed/u,
        );
      });
    });
  });
});

test('runAdminSetupCli builds the managed-state probe socket under a root-created temp dir', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome, toolDir }) => {
      const probeScriptPath = path.join(agentpayHome, 'captured-state-probe.sh');
      writeNodeExecutable(
        path.join(toolDir, 'sudo'),
        [
          "const fs = require('node:fs');",
          'const args = process.argv.slice(2);',
          `const probeScriptPath = ${JSON.stringify(probeScriptPath)};`,
          "if (args[0] === '-S' && args[3] === '-v') {",
          '  process.stdin.resume();',
          "  process.stdin.on('end', () => process.exit(0));",
          '  return;',
          '}',
          "if (args[0] === '-n' && args[1] === '/bin/test') {",
          '  process.exit(0);',
          '}',
          "if (args[0] === '-n' && args[1] === '/bin/bash') {",
          "  fs.writeFileSync(probeScriptPath, String(args[3] ?? ''), 'utf8');",
          "  process.stderr.write('failed to initialize daemon\\nCaused by: failed to decrypt state (wrong password or tampered file)\\n');",
          '  process.exit(1);',
          '}',
          "if (args[0] === '-n') {",
          '  process.exit(0);',
          '}',
          'process.exit(0);',
        ].join('\n'),
      );

      process.env.AGENTPAY_MOCK_RELAY_AUTH_FAIL = '1';

      try {
        const adminSetup = await loadModule(`${Date.now()}-run-setup-state-probe-script`);
        await withMockedPrompt('vault-secret', async () => {
          await assert.rejects(
            () =>
              adminSetup.runAdminSetupCli([
                '--yes',
                '--daemon-socket',
                trustedSocket,
                '--bootstrap-output',
                path.join(agentpayHome, 'bootstrap-state-probe-script.json'),
              ]),
            /managed daemon state already exists .* encrypted with a different vault password/u,
          );
        });
      } finally {
        delete process.env.AGENTPAY_MOCK_RELAY_AUTH_FAIL;
      }

      const captured = fs.readFileSync(probeScriptPath, 'utf8');
      assert.match(captured, /mktemp -d/u);
      assert.match(captured, /agentpay-managed-state-probe-XXXXXX/u);
      assert.match(captured, /daemon_socket="\$temp_root\/daemon\.sock"/u);
    });
  });
});

test('runAdminSetupCli preserves managed-state mismatch errors when probe temp cleanup fails', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome, toolDir }) => {
      writeExecutable(
        path.join(toolDir, 'sudo'),
        [
          'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
          '  cat >/dev/null',
          '  exit 0',
          'fi',
          'if [ "$1" = "-n" ] && [ "$2" = "/bin/test" ]; then',
          '  exit 0',
          'fi',
          'if [ "$1" = "-n" ]; then',
          "  echo 'authentication failed' >&2",
          '  exit 9',
          'fi',
          'exit 0',
        ].join('\n'),
      );

      process.env.AGENTPAY_MOCK_RELAY_SEQUENCE = '0,9';
      process.env.AGENTPAY_MOCK_RELAY_COUNTER = path.join(
        agentpayHome,
        'relay-call-count-state-probe-cleanup-fail.txt',
      );

      const originalRmSync = fs.rmSync;
      fs.rmSync = (targetPath, ...args) => {
        if (path.basename(path.resolve(String(targetPath))).startsWith('agentpay-managed-state-probe-')) {
          throw new Error('probe cleanup failed');
        }
        return originalRmSync.call(fs, targetPath, ...args);
      };

      try {
        const adminSetup = await loadModule(`${Date.now()}-run-setup-state-probe-cleanup-fail`);
        await withMockedPrompt('vault-secret', async () => {
          await assert.rejects(
            () =>
              adminSetup.runAdminSetupCli([
                '--yes',
                '--daemon-socket',
                trustedSocket,
                '--bootstrap-output',
                path.join(agentpayHome, 'bootstrap-state-probe-cleanup-fail.json'),
              ]),
            /managed daemon state already exists .* encrypted with a different vault password/u,
          );
        });
      } finally {
        fs.rmSync = originalRmSync;
      }
    });
  });
});

test('resolveAdminSetupVaultPassword reads hidden prompt input through the default tty path', async () => {
  const adminSetup = await loadModule(`${Date.now()}-resolve-hidden-prompt-default-path`);

  let rendered = '';
  const originalStderrWrite = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((chunk, ...args) => {
    rendered += String(chunk);
    return originalStderrWrite(chunk, ...args);
  });

  try {
    await withMockedPrompt(
      'vault-secret',
      async () => {
        const password = await adminSetup.resolveAdminSetupVaultPassword({});
        assert.equal(password, 'vault-secret');
      },
    );
  } finally {
    process.stderr.write = originalStderrWrite;
  }

  assert.match(rendered, /\n/u);
  assert.match(rendered, /Vault password \(input hidden; this unlocks the wallet, not sudo\): /u);
  assert.match(rendered, /Confirm vault password: /u);
  assert.doesNotMatch(rendered, /vault-secret/u);
});

test('resolveAdminSetupVaultPassword rejects mismatched confirmation input', async () => {
  const adminSetup = await loadModule(`${Date.now()}-resolve-hidden-prompt-mismatch`);
  let promptCount = 0;

  await withMockedPrompt(() => {
    promptCount += 1;
    return promptCount === 1 ? 'vault-secret' : 'vault-secret-typo';
  }, async () => {
    await assert.rejects(
      () => adminSetup.resolveAdminSetupVaultPassword({}),
      /vault passwords did not match/u,
    );
  });
});

test('runAdminSetupCli plan mode prints text output when --json is omitted', async () => {
  await withMockedAdminSetupEnv(async () => {
    const stdoutChunks = [];
    const originalStdoutWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((chunk, ...args) => {
      stdoutChunks.push(String(chunk));
      return originalStdoutWrite(chunk, ...args);
    });

    try {
      const adminSetup = await loadModule(`${Date.now()}-run-setup-plan-text`);
      await adminSetup.runAdminSetupCli(['--plan']);
    } finally {
      process.stdout.write = originalStdoutWrite;
    }

    const output = stdoutChunks.join('');
    assert.match(output, /Admin Setup Preview/u);
    assert.match(output, /Wallet Setup Preview/u);
  });
});

test('runAdminSetupCli reuses the current launchd install when the daemon responds after an initial auth failure', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome }) => {
      process.env.AGENTPAY_MOCK_RELAY_SEQUENCE = '9,0';
      process.env.AGENTPAY_MOCK_RELAY_COUNTER = path.join(agentpayHome, 'relay-current-install-counter.txt');

      await withMockedManagedLaunchDaemonMetadata(
        {
          agentpayHome,
          daemonSocket: trustedSocket,
          stateFile: HOST_MANAGED.stateFile,
        },
        async () => {
          const adminSetup = await loadModule(`${Date.now()}-run-setup-current-install-responding`);
          await withMockedPrompt('vault-secret', async () => {
            await adminSetup.runAdminSetupCli(['--daemon-socket', trustedSocket]);
          });
        },
      );
    });
  });
});

test('runAdminSetupCli reinstalls when launchd metadata looks current but no managed state exists and the daemon is not responding', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome, toolDir }) => {
      const installMarkerPath = path.join(agentpayHome, 'install-marker.txt');
      process.env.AGENTPAY_MOCK_INSTALL_MARKER = installMarkerPath;
      writeNodeExecutable(
        path.join(toolDir, 'sudo'),
        [
          "const fs = require('node:fs');",
          'const args = process.argv.slice(2);',
          "const marker = process.env.AGENTPAY_MOCK_INSTALL_MARKER;",
          "if (args[0] === '-S' && args[3] === '-v') {",
          '  process.stdin.resume();',
          "  process.stdin.on('end', () => process.exit(0));",
          '  return;',
          '}',
          "if (args[0] === '-n' && args[1] === '/bin/test') {",
          '  process.exit(1);',
          '}',
          "if (args[0] === '-n') {",
          `  if (marker && args.some((value) => String(value).includes(${JSON.stringify(HOST_MANAGED.installScriptName)}))) {`,
          "    fs.writeFileSync(marker, 'installed\\n', 'utf8');",
          '  }',
          '  process.exit(0);',
          '}',
          'process.exit(0);',
        ].join('\n'),
      );

      try {
        await withMockedManagedLaunchDaemonMetadata(
          {
            agentpayHome,
            daemonSocket: trustedSocket,
            stateFile: HOST_MANAGED.stateFile,
          },
          async () => {
            await withInstallMarkerConnectionGate(installMarkerPath, async () => {
              const adminSetup = await loadModule(`${Date.now()}-run-setup-current-install-recover`);
              await withMockedPrompt('vault-secret', async () => {
                await adminSetup.runAdminSetupCli(['--daemon-socket', trustedSocket]);
              });
            });
          },
        );
      } finally {
        delete process.env.AGENTPAY_MOCK_INSTALL_MARKER;
      }
    });
  });
});

test('runAdminSetupCli forwards AGENTPAY_RELAY_DAEMON_TOKEN into the root install command environment', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome, toolDir }) => {
      const installMarkerPath = path.join(agentpayHome, 'install-marker-relay-token.txt');
      const relayTokenMarkerPath = path.join(agentpayHome, 'relay-token-marker.txt');
      process.env.AGENTPAY_MOCK_INSTALL_MARKER = installMarkerPath;
      process.env.AGENTPAY_RELAY_DAEMON_TOKEN = 'relay-daemon-token-1234567890abcdef';
      writeNodeExecutable(
        path.join(toolDir, 'sudo'),
        [
          "const fs = require('node:fs');",
          'const args = process.argv.slice(2);',
          "const installMarker = process.env.AGENTPAY_MOCK_INSTALL_MARKER;",
          `const relayTokenMarker = ${JSON.stringify(relayTokenMarkerPath)};`,
          "if (args[0] === '-S' && args[3] === '-v') {",
          '  process.stdin.resume();',
          "  process.stdin.on('end', () => process.exit(0));",
          '  return;',
          '}',
          "if (args[0] === '-n' && args[1] === '/bin/test') {",
          '  process.exit(1);',
          '}',
          "if (args[0] === '-n') {",
          `  if (installMarker && args.some((value) => String(value).includes(${JSON.stringify(HOST_MANAGED.installScriptName)}))) {`,
          "    fs.writeFileSync(installMarker, 'installed\\n', 'utf8');",
          '  }',
          "  const relayTokenArg = args.find((value) => String(value).startsWith('AGENTPAY_RELAY_DAEMON_TOKEN='));",
          '  if (relayTokenArg) {',
          "    fs.writeFileSync(relayTokenMarker, String(relayTokenArg).slice('AGENTPAY_RELAY_DAEMON_TOKEN='.length), 'utf8');",
          '  }',
          '  process.exit(0);',
          '}',
          'process.exit(0);',
        ].join('\n'),
      );

      try {
        await withMockedManagedLaunchDaemonMetadata(
          {
            agentpayHome,
            daemonSocket: trustedSocket,
            stateFile: HOST_MANAGED.stateFile,
          },
          async () => {
            await withInstallMarkerConnectionGate(installMarkerPath, async () => {
              const adminSetup = await loadModule(`${Date.now()}-run-setup-relay-token-env`);
              await withMockedPrompt('vault-secret', async () => {
                await adminSetup.runAdminSetupCli(['--daemon-socket', trustedSocket]);
              });
            });
          },
        );
      } finally {
        delete process.env.AGENTPAY_MOCK_INSTALL_MARKER;
        delete process.env.AGENTPAY_RELAY_DAEMON_TOKEN;
      }

      assert.equal(
        fs.readFileSync(relayTokenMarkerPath, 'utf8'),
        'relay-daemon-token-1234567890abcdef',
      );
    });
  });
});

test('runAdminSetupCli recovers when launchd metadata looks current and the requested password matches existing managed state', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome, toolDir }) => {
      const installMarkerPath = path.join(agentpayHome, 'install-marker-existing-state.txt');
      process.env.AGENTPAY_MOCK_INSTALL_MARKER = installMarkerPath;
      writeNodeExecutable(
        path.join(toolDir, 'sudo'),
        [
          "const fs = require('node:fs');",
          'const args = process.argv.slice(2);',
          "const marker = process.env.AGENTPAY_MOCK_INSTALL_MARKER;",
          "if (args[0] === '-S' && args[3] === '-v') {",
          '  process.stdin.resume();',
          "  process.stdin.on('end', () => process.exit(0));",
          '  return;',
          '}',
          "if (args[0] === '-n' && args[1] === '/bin/test') {",
          '  process.exit(0);',
          '}',
          "if (args[0] === '-n') {",
          `  if (marker && args.some((value) => String(value).includes(${JSON.stringify(HOST_MANAGED.installScriptName)}))) {`,
          "    fs.writeFileSync(marker, 'installed\\n', 'utf8');",
          '  }',
          '  process.exit(0);',
          '}',
          'process.exit(0);',
        ].join('\n'),
      );

      try {
        await withMockedManagedLaunchDaemonMetadata(
          {
            agentpayHome,
            daemonSocket: trustedSocket,
            stateFile: HOST_MANAGED.stateFile,
          },
          async () => {
            await withInstallMarkerConnectionGate(installMarkerPath, async () => {
              const adminSetup = await loadModule(`${Date.now()}-run-setup-current-install-existing-state`);
              await withMockedPrompt('vault-secret', async () => {
                await adminSetup.runAdminSetupCli(['--daemon-socket', trustedSocket]);
              });
            });
          },
        );
      } finally {
        delete process.env.AGENTPAY_MOCK_INSTALL_MARKER;
      }

      assert.equal(fs.existsSync(installMarkerPath), true);
    });
  });
});

test('runAdminTuiCli backfills missing wallet vaultKeyId before passthrough when bootstrap metadata is present', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome }) => {
      const configPath = path.join(agentpayHome, 'config.json');
      const currentConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      currentConfig.wallet = {
        vaultPublicKey: '03abcdef',
        policyAttachment: 'policy_set',
      };
      fs.writeFileSync(configPath, `${JSON.stringify(currentConfig, null, 2)}\n`, {
        encoding: 'utf8',
        mode: 0o600,
      });
      fs.chmodSync(configPath, 0o600);

      writePrivateJsonFile(
        path.join(agentpayHome, 'bootstrap-222-333.json'),
        bootstrapPayload({
          vault_key_id: 'vault-key-backfilled-from-artifact',
          vault_public_key: '03abcdef',
          policy_attachment: 'policy_set',
        }),
      );

      process.env.AGENTPAY_MOCK_SKIP_TUI_OUTPUT = '1';
      const adminSetup = await loadModule(`${Date.now()}-run-tui-backfill-before-passthrough`);
      await withMockedPrompt('vault-secret', async () => {
        await adminSetup.runAdminTuiCli([
          '--daemon-socket',
          trustedSocket,
          '--bootstrap-output',
          path.join(agentpayHome, 'bootstrap-tui-backfill-canceled.json'),
          '--json',
        ]);
      });

      const updatedConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      assert.match(String(updatedConfig.wallet?.vaultKeyId ?? ''), /^vault-key-/u);
    });
  });
});

test('runAdminTuiCli skips wallet backfill when persisted wallet metadata has no matching bootstrap artifact', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome }) => {
      const configPath = path.join(agentpayHome, 'config.json');
      const currentConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      currentConfig.wallet = {
        address: '0x1111111111111111111111111111111111111111',
        vaultPublicKey: '03abcdef',
        policyAttachment: 'policy_set',
      };
      fs.writeFileSync(configPath, `${JSON.stringify(currentConfig, null, 2)}\n`, {
        encoding: 'utf8',
        mode: 0o600,
      });
      fs.chmodSync(configPath, 0o600);

      process.env.AGENTPAY_MOCK_SKIP_TUI_OUTPUT = '1';
      const adminSetup = await loadModule(`${Date.now()}-run-tui-backfill-unresolved-wallet`);
      await withMockedPrompt('vault-secret', async () => {
        await adminSetup.runAdminTuiCli([
          '--daemon-socket',
          trustedSocket,
          '--bootstrap-output',
          path.join(agentpayHome, 'bootstrap-tui-backfill-unresolved.json'),
          '--json',
        ]);
      });

      const updatedConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      assert.equal(updatedConfig.wallet?.vaultKeyId, undefined);
      assert.equal(updatedConfig.wallet?.address, '0x1111111111111111111111111111111111111111');
    });
  });
});

test('runAdminTuiCli skips wallet backfill when the resolved wallet still lacks vaultKeyId', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome }) => {
      const configPath = path.join(agentpayHome, 'config.json');
      const currentConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      currentConfig.wallet = {
        address: '0x1111111111111111111111111111111111111111',
        vaultPublicKey: '03abcdef',
        policyAttachment: 'policy_set',
      };
      fs.writeFileSync(configPath, `${JSON.stringify(currentConfig, null, 2)}\n`, {
        encoding: 'utf8',
        mode: 0o600,
      });
      fs.chmodSync(configPath, 0o600);

      process.env.AGENTPAY_MOCK_SKIP_TUI_OUTPUT = '1';
      const adminSetup = await loadModule(`${Date.now()}-run-tui-backfill-missing-key-id`);
      await withMockedPrompt('vault-secret', async () => {
        await adminSetup.runAdminTuiCli([
          '--daemon-socket',
          trustedSocket,
          '--bootstrap-output',
          path.join(agentpayHome, 'bootstrap-tui-backfill-missing-key-id.json'),
          '--json',
        ]);
      });

      const updatedConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      assert.equal(updatedConfig.wallet?.vaultKeyId, undefined);
      assert.equal(updatedConfig.wallet?.address, '0x1111111111111111111111111111111111111111');
    });
  });
});

test('runAdminSetupCli inspects managed state and reinstalls daemon when password drifts without stored state', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome, toolDir }) => {
      writeExecutable(
        path.join(toolDir, 'sudo'),
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

      process.env.AGENTPAY_MOCK_RELAY_SEQUENCE = '0,9,0';
      process.env.AGENTPAY_MOCK_RELAY_COUNTER = path.join(agentpayHome, 'relay-call-count.txt');

      const stderrChunks = [];
      const originalStderrWrite = process.stderr.write.bind(process.stderr);
      process.stderr.write = ((chunk, ...args) => {
        stderrChunks.push(String(chunk));
        return originalStderrWrite(chunk, ...args);
      });

      try {
        const adminSetup = await loadModule(`${Date.now()}-run-setup-password-drift-reinstall-success`);
        await withMockedPrompt('vault-secret', async () => {
          await adminSetup.runAdminSetupCli([
            '--yes',
            '--daemon-socket',
            trustedSocket,
            '--bootstrap-output',
            path.join(agentpayHome, 'bootstrap-password-drift-success.json'),
          ]);
        });
      } finally {
        process.stderr.write = originalStderrWrite;
      }

      assert.equal(process.exitCode, undefined);
      const stderrOutput = stderrChunks.join('');
      assert.match(stderrOutput, /Inspecting managed daemon state/u);
      assert.match(stderrOutput, /No managed daemon state found/u);
      assert.match(stderrOutput, /Daemon reinstalled and restarted/u);
      assert.match(stderrOutput, /Re-checking daemon vault password/u);
    });
  });
});

test('runAdminSetupCli fails when daemon still rejects password after reinstall retry', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome, toolDir }) => {
      writeExecutable(
        path.join(toolDir, 'sudo'),
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

      process.env.AGENTPAY_MOCK_RELAY_SEQUENCE = '0,9,9';
      process.env.AGENTPAY_MOCK_RELAY_COUNTER = path.join(agentpayHome, 'relay-call-count.txt');

      const adminSetup = await loadModule(`${Date.now()}-run-setup-password-drift-reinstall-fail`);
      await withMockedPrompt('vault-secret', async () => {
        await assert.rejects(
          () =>
            adminSetup.runAdminSetupCli([
              '--yes',
              '--daemon-socket',
              trustedSocket,
              '--bootstrap-output',
              path.join(agentpayHome, 'bootstrap-password-drift-fail.json'),
            ]),
          /still rejects the requested vault password/u,
        );
      });
    });
  });
});

test('runAdminSetupCli surfaces reinstall launchd failures after state probe reports no managed state', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome, toolDir }) => {
      writeExecutable(
        path.join(toolDir, 'sudo'),
        [
          'if [ "$1" = "-S" ] && [ "$4" = "-v" ]; then',
          '  cat >/dev/null',
          '  exit 0',
          'fi',
          'if [ "$1" = "-n" ] && [ "$2" = "/bin/test" ]; then',
          '  exit 1',
          'fi',
          `if [ "$1" = "-n" ] && [ "\${2#*${HOST_MANAGED.installScriptName}}" != "$2" ]; then`,
          "  echo 'mock install failure' >&2",
          '  exit 73',
          'fi',
          'if [ "$1" = "-n" ]; then',
          '  exit 0',
          'fi',
          'exit 0',
        ].join('\n'),
      );

      process.env.AGENTPAY_MOCK_RELAY_SEQUENCE = '0,9';
      process.env.AGENTPAY_MOCK_RELAY_COUNTER = path.join(agentpayHome, 'relay-call-count.txt');

      const adminSetup = await loadModule(`${Date.now()}-run-setup-reinstall-install-fail`);
      await withMockedPrompt('vault-secret', async () => {
        await assert.rejects(
          () =>
            adminSetup.runAdminSetupCli([
              '--yes',
              '--daemon-socket',
              trustedSocket,
              '--bootstrap-output',
              path.join(agentpayHome, 'bootstrap-install-failure.json'),
            ]),
          /mock install failure/u,
        );
      });
    });
  });
});

test('runAdminTuiCli warns when cleanup fails after a non-zero passthrough exit', async () => {
  await withTrustedRootDaemonSocket(async (trustedSocket) => {
    await withMockedAdminSetupEnv(async ({ agentpayHome }) => {
      process.env.AGENTPAY_MOCK_TUI_EXIT = '7';
      process.env.AGENTPAY_MOCK_TUI_SYMLINK_OUTPUT = '1';
      const bootstrapPath = path.join(agentpayHome, 'bootstrap-tui-cleanup-warning.json');
      const stderrChunks = [];
      const originalStderrWrite = process.stderr.write.bind(process.stderr);
      process.stderr.write = ((chunk, ...args) => {
        stderrChunks.push(String(chunk));
        return originalStderrWrite(chunk, ...args);
      });

      try {
        const adminSetup = await loadModule(`${Date.now()}-run-tui-cleanup-warning`);
        await withMockedPrompt('vault-secret', async () => {
          await adminSetup.runAdminTuiCli([
            '--daemon-socket',
            trustedSocket,
            '--bootstrap-output',
            bootstrapPath,
            '--json',
          ]);
        });
      } finally {
        process.stderr.write = originalStderrWrite;
      }

      assert.equal(process.exitCode, 7);
      assert.match(
        stderrChunks.join(''),
        /warning: failed to scrub bootstrap output after tui failure/u,
      );
    });
  });
});
