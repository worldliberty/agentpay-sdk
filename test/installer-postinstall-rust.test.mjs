import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

// Covers the postinstall behaviour of scripts/install-rust-binaries.mjs when cargo is missing.
// The one-click installer and `pnpm install` on a JavaScript-only machine both depend on it.

const modulePath = new URL('../scripts/install-rust-binaries.mjs', import.meta.url);

function result(status, stdout = '', stderr = '') {
  return {
    status,
    stdout: Buffer.from(stdout),
    stderr: Buffer.from(stderr),
  };
}

function missingCargoSpawn(command) {
  if (command === 'cargo') {
    return result(1, '', 'spawn cargo ENOENT');
  }
  return result(0);
}

function makeTempHome() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-postinstall-test-'));
  fs.chmodSync(root, 0o700);
  return root;
}

test('shouldToleratePostinstallWithoutCargo is true only for postinstall without the strict flag', async () => {
  const installRust = await import(`${modulePath.href}?case=${Date.now()}-tolerate-flag`);

  assert.equal(
    installRust.shouldToleratePostinstallWithoutCargo({ npm_lifecycle_event: 'postinstall' }),
    true,
  );
  assert.equal(
    installRust.shouldToleratePostinstallWithoutCargo({
      npm_lifecycle_event: 'postinstall',
      AGENTPAY_REQUIRE_RUST_INSTALL: '1',
    }),
    false,
  );
  assert.equal(
    installRust.shouldToleratePostinstallWithoutCargo({
      npm_lifecycle_event: 'install:rust-binaries',
    }),
    false,
  );
  assert.equal(installRust.shouldToleratePostinstallWithoutCargo({}), false);
});

test('postinstall warns and exits 0 when cargo is missing', async () => {
  const installRust = await import(`${modulePath.href}?case=${Date.now()}-postinstall-soft`);
  const home = makeTempHome();
  const warnings = [];

  try {
    const exitCode = installRust.installRustBinaries({
      platform: 'darwin',
      spawnSyncImpl: missingCargoSpawn,
      env: {
        npm_lifecycle_event: 'postinstall',
        AGENTPAY_HOME: path.join(home, '.agentpay'),
      },
      warn: (message) => warnings.push(message),
    });

    assert.equal(exitCode, 0);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /Rust toolchain \(cargo\) was not found on PATH/u);
    assert.match(warnings[0], /npm run install:rust-binaries/u);
    assert.match(warnings[0], /curl -fsSL https:\/\/wlfi\.sh \| bash/u);
    assert.match(warnings[0], /AGENTPAY_REQUIRE_RUST_INSTALL=1/u);
    assert.equal(fs.existsSync(path.join(home, '.agentpay', 'bin')), false);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('postinstall still fails without cargo when AGENTPAY_REQUIRE_RUST_INSTALL=1', async () => {
  const installRust = await import(`${modulePath.href}?case=${Date.now()}-postinstall-strict`);
  const home = makeTempHome();

  try {
    assert.throws(
      () =>
        installRust.installRustBinaries({
          platform: 'darwin',
          spawnSyncImpl: missingCargoSpawn,
          env: {
            npm_lifecycle_event: 'postinstall',
            AGENTPAY_REQUIRE_RUST_INSTALL: '1',
            AGENTPAY_HOME: path.join(home, '.agentpay'),
          },
          warn: () => {
            throw new Error('warn must not be called in strict mode');
          },
        }),
      /Rust toolchain was not found on PATH\./u,
    );
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('an explicit install:rust-binaries run without cargo keeps failing loudly', async () => {
  const installRust = await import(`${modulePath.href}?case=${Date.now()}-explicit-run`);
  const home = makeTempHome();

  try {
    assert.throws(
      () =>
        installRust.installRustBinaries({
          platform: 'darwin',
          spawnSyncImpl: missingCargoSpawn,
          env: {
            npm_lifecycle_event: 'install:rust-binaries',
            AGENTPAY_HOME: path.join(home, '.agentpay'),
          },
          warn: () => {
            throw new Error('warn must not be called for explicit installs');
          },
        }),
      /Rust toolchain was not found on PATH\./u,
    );
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
