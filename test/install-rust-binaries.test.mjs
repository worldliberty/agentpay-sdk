import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { installLocalCliLauncher } from '../scripts/install-cli-launcher.mjs';
import { installCliLauncher, resolveRepoRootFromMetaUrl } from '../scripts/install-rust-binaries.mjs';

const modulePath = new URL('../scripts/install-rust-binaries.mjs', import.meta.url);

function result(status, stdout = '', stderr = '') {
  return {
    status,
    stdout: Buffer.from(stdout),
    stderr: Buffer.from(stderr),
  };
}

function signalResult(signal, stdout = '', stderr = '') {
  return {
    status: null,
    signal,
    stdout: Buffer.from(stdout),
    stderr: Buffer.from(stderr),
  };
}

function makeTempRoot(prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.chmodSync(root, 0o700);
  return root;
}

test('verifyRustInstallPrerequisites rejects missing cargo with rerun guidance', async () => {
  const installRust = await import(`${modulePath.href}?case=${Date.now()}-missing-cargo`);

  assert.throws(
    () =>
      installRust.verifyRustInstallPrerequisites({
        platform: 'darwin',
        spawnSyncImpl(command) {
          if (command === 'cargo') {
            return result(1, '', 'spawn cargo ENOENT');
          }
          return result(0);
        },
      }),
    /Rust toolchain was not found on PATH\./,
  );
});

test('verifyRustInstallPrerequisites rejects rustc versions older than the supported minimum', async () => {
  const installRust = await import(`${modulePath.href}?case=${Date.now()}-old-rustc`);

  assert.throws(
    () =>
      installRust.verifyRustInstallPrerequisites({
        platform: 'darwin',
        spawnSyncImpl(command) {
          if (command === 'cargo') {
            return result(0, 'cargo 1.86.0');
          }
          if (command === 'rustc') {
            return result(0, 'rustc 1.86.0-nightly (deadbeef 2025-01-01)');
          }
          if (command === 'xcrun') {
            return result(0, '/Library/Developer/CommandLineTools/usr/bin/clang');
          }
          return result(0);
        },
      }),
    /Rust 1\.87\.0 or newer is required; found rustc 1\.86\.0-nightly/u,
  );
});

test('verifyRustInstallPrerequisites rejects missing macOS command line tools with rerun guidance', async () => {
  const installRust = await import(`${modulePath.href}?case=${Date.now()}-missing-clt`);

  assert.throws(
    () =>
      installRust.verifyRustInstallPrerequisites({
        platform: 'darwin',
        spawnSyncImpl(command) {
          if (command === 'cargo') {
            return result(0, 'cargo 1.89.0');
          }
          if (command === 'rustc') {
            return result(0, 'rustc 1.89.0 (deadbeef 2025-01-01)');
          }
          if (command === 'xcrun') {
            return result(
              1,
              '',
              'xcrun: error: invalid active developer path /Library/Developer/CommandLineTools',
            );
          }
          return result(0);
        },
      }),
    /Install them with `xcode-select --install`\./,
  );
});

test('verifyRustInstallPrerequisites succeeds when cargo and macOS toolchain are ready', async () => {
  const installRust = await import(`${modulePath.href}?case=${Date.now()}-ready`);
  const calls = [];

  assert.doesNotThrow(() =>
    installRust.verifyRustInstallPrerequisites({
      platform: 'darwin',
      spawnSyncImpl(command, args) {
        calls.push([command, args]);
        if (command === 'cargo') {
          return result(0, 'cargo 1.89.0');
        }
        if (command === 'rustc') {
          return result(0, 'rustc 1.89.0 (deadbeef 2025-01-01)');
        }
        if (command === 'xcrun') {
          return result(0, '/Library/Developer/CommandLineTools/usr/bin/clang');
        }
        return result(0);
      },
    }),
  );

  assert.deepEqual(calls, [
    ['cargo', ['--version']],
    ['rustc', ['--version']],
    ['xcrun', ['--sdk', 'macosx', '--find', 'clang']],
  ]);
});

test('verifyRustInstallPrerequisites preserves signal-derived exit codes from prerequisite checks', async () => {
  const installRust = await import(`${modulePath.href}?case=${Date.now()}-signal-cargo`);

  assert.throws(
    () =>
      installRust.verifyRustInstallPrerequisites({
        platform: 'darwin',
        spawnSyncImpl(command) {
          if (command === 'cargo') {
            return signalResult('SIGINT');
          }
          return result(0);
        },
      }),
    /cargo --version`\) was terminated by SIGINT \(exit code 130\)/u,
  );
});

test('installRustBinaries respects AGENTPAY_SKIP_RUST_INSTALL', async () => {
  const installRust = await import(`${modulePath.href}?case=${Date.now()}-skip-install`);
  let called = false;

  const exitCode = installRust.installRustBinaries({
    env: { AGENTPAY_SKIP_RUST_INSTALL: '1' },
    spawnSyncImpl() {
      called = true;
      return result(0);
    },
  });

  assert.equal(exitCode, 0);
  assert.equal(called, false);
});

test('installRustBinaries preserves signal-derived cargo build exit codes', async () => {
  const installRust = await import(`${modulePath.href}?case=${Date.now()}-signal-build`);
  const agentpayHome = makeTempRoot('agentpay-install-signal-build-');

  try {
    const exitCode = installRust.installRustBinaries({
      env: { ...process.env, AGENTPAY_HOME: agentpayHome },
      platform: 'linux',
      spawnSyncImpl(command, args) {
        if (command === 'cargo') {
          if (args?.[0] === '--version') {
            return result(0, 'cargo 1.89.0');
          }
          return signalResult('SIGTERM');
        }
        if (command === 'rustc') {
          return result(0, 'rustc 1.89.0 (deadbeef 2025-01-01)');
        }
        return result(0);
      },
    });

    assert.equal(exitCode, 143);
  } finally {
    fs.rmSync(agentpayHome, { recursive: true, force: true });
  }
});

test('installCliLauncher writes a POSIX agentpay launcher that forwards args', () => {
  const root = makeTempRoot('agentpay-install-cli-');
  const binDir = path.join(root, 'bin');
  const cliEntrypoint = path.join(root, 'cli.cjs');

  try {
    fs.writeFileSync(
      cliEntrypoint,
      '#!/usr/bin/env node\n' +
        'process.stdout.write(JSON.stringify(process.argv.slice(2)) + "\\n");\n',
      { mode: 0o755 },
    );

    const installed = installCliLauncher({
      binDir,
      cliEntrypoint,
      platform: 'darwin',
    });

    assert.equal(installed, true);

    const launcherPath = path.join(binDir, 'agentpay');
    assert.equal(fs.existsSync(launcherPath), true);
    assert.ok((fs.statSync(launcherPath).mode & 0o111) !== 0);

    const execResult = spawnSync(launcherPath, ['status', '--strict'], {
      encoding: 'utf8',
    });
    assert.equal(execResult.status, 0);
    assert.equal(execResult.stdout.trim(), '["status","--strict"]');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('installCliLauncher can skip missing CLI entrypoints during pre-build install', () => {
  const root = makeTempRoot('agentpay-install-cli-missing-');
  const binDir = path.join(root, 'bin');

  try {
    fs.mkdirSync(binDir, { recursive: true, mode: 0o700 });
    const installed = installCliLauncher({
      binDir,
      cliEntrypoint: path.join(root, 'missing-cli.cjs'),
      platform: 'darwin',
      allowMissingEntrypoint: true,
    });

    assert.equal(installed, false);
    assert.equal(fs.existsSync(path.join(binDir, 'agentpay')), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('resolveRepoRootFromMetaUrl preserves Windows drive-letter paths without a leading slash', () => {
  assert.equal(
    resolveRepoRootFromMetaUrl(
      'file:///C:/Users/test/wlfi-agent-sdk/scripts/install-rust-binaries.mjs',
      'win32',
    ),
    'C:\\Users\\test\\wlfi-agent-sdk',
  );
});

test('installLocalCliLauncher installs agentpay under AGENTPAY_HOME/bin', () => {
  const root = makeTempRoot('agentpay-install-local-cli-');
  const cliEntrypoint = path.join(root, 'cli.cjs');

  try {
    fs.writeFileSync(
      cliEntrypoint,
      '#!/usr/bin/env node\n' +
        'process.stdout.write(JSON.stringify(process.argv.slice(2)) + "\\n");\n',
      { mode: 0o755 },
    );

    installLocalCliLauncher({
      env: { ...process.env, AGENTPAY_HOME: root },
      platform: 'darwin',
      cliEntrypoint,
    });

    const launcherPath = path.join(root, 'bin', 'agentpay');
    const execResult = spawnSync(launcherPath, ['wallet'], { encoding: 'utf8' });
    assert.equal(execResult.status, 0);
    assert.equal(execResult.stdout.trim(), '["wallet"]');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
