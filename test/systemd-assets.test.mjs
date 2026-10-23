import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const modulePath = new URL('../src/lib/systemd-assets.ts', import.meta.url);

async function withDevScriptsEnv(value, fn) {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-systemd-assets-'));
  const originalAgentPayHome = process.env.AGENTPAY_HOME;
  const originalDevScripts = process.env.AGENTPAY_DEV_SCRIPTS;

  process.env.AGENTPAY_HOME = path.join(tempRoot, 'home');
  if (value === undefined) {
    delete process.env.AGENTPAY_DEV_SCRIPTS;
  } else {
    process.env.AGENTPAY_DEV_SCRIPTS = value;
  }

  try {
    await fn(process.env.AGENTPAY_HOME);
  } finally {
    if (originalAgentPayHome === undefined) {
      delete process.env.AGENTPAY_HOME;
    } else {
      process.env.AGENTPAY_HOME = originalAgentPayHome;
    }
    if (originalDevScripts === undefined) {
      delete process.env.AGENTPAY_DEV_SCRIPTS;
    } else {
      process.env.AGENTPAY_DEV_SCRIPTS = originalDevScripts;
    }
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

test('resolveSystemdHelperScriptPath ignores checked-in helpers in the cwd by default', async () => {
  const systemdAssets = await import(`${modulePath.href}?case=${Date.now()}-no-cwd-fallback`);

  await withDevScriptsEnv(undefined, async (agentpayHome) => {
    assert.equal(
      systemdAssets.resolveSystemdHelperScriptPath(systemdAssets.SYSTEMD_INSTALL_SCRIPT_NAME),
      path.join(agentpayHome, 'bin', systemdAssets.SYSTEMD_INSTALL_SCRIPT_NAME),
    );
  });
});

test('resolveSystemdHelperScriptPath returns the checked-in helper only with AGENTPAY_DEV_SCRIPTS=1', async () => {
  const systemdAssets = await import(`${modulePath.href}?case=${Date.now()}-dev-scripts`);

  await withDevScriptsEnv('1', async () => {
    assert.equal(
      systemdAssets.resolveSystemdHelperScriptPath(systemdAssets.SYSTEMD_INSTALL_SCRIPT_NAME),
      path.resolve(process.cwd(), 'scripts/systemd', systemdAssets.SYSTEMD_INSTALL_SCRIPT_NAME),
    );
  });
});

test('resolveSystemdHelperScriptPath prefers the installed helper in rustBinDir', async () => {
  const systemdAssets = await import(`${modulePath.href}?case=${Date.now()}-installed`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-systemd-assets-installed-'));

  try {
    const rustBinDir = path.join(tempRoot, 'bin');
    fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
    const installed = path.join(rustBinDir, systemdAssets.SYSTEMD_INSTALL_SCRIPT_NAME);
    fs.writeFileSync(installed, '#!/bin/sh\nexit 0\n', { mode: 0o700 });

    await withDevScriptsEnv('1', async () => {
      assert.equal(
        systemdAssets.resolveSystemdHelperScriptPath(systemdAssets.SYSTEMD_INSTALL_SCRIPT_NAME, {
          rustBinDir,
        }),
        installed,
      );
    });
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
