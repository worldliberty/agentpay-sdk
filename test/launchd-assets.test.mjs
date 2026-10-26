import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const modulePath = new URL('../src/lib/launchd-assets.ts', import.meta.url);

test('resolveLaunchDaemonHelperScriptPath falls back to the configured rustBinDir path when no helper exists', async () => {
  const launchdAssets = await import(`${modulePath.href}?case=${Date.now()}-fallback`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-launchd-assets-'));

  try {
    const rustBinDir = path.join(tempRoot, 'bin');
    fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });

    const resolved = launchdAssets.resolveLaunchDaemonHelperScriptPath('missing-helper.sh', {
      rustBinDir,
    });

    assert.equal(resolved, path.join(rustBinDir, 'missing-helper.sh'));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

async function withDevScriptsEnv(value, fn) {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-launchd-assets-default-'));
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

test('resolveLaunchDaemonHelperScriptPath ignores checked-in helpers in the cwd by default', async () => {
  const launchdAssets = await import(`${modulePath.href}?case=${Date.now()}-no-cwd-fallback`);

  for (const value of [undefined, '0', 'true']) {
    await withDevScriptsEnv(value, async (agentpayHome) => {
      const resolved = launchdAssets.resolveLaunchDaemonHelperScriptPath(
        launchdAssets.LAUNCHD_INSTALL_SCRIPT_NAME,
      );

      assert.equal(
        resolved,
        path.join(agentpayHome, 'bin', launchdAssets.LAUNCHD_INSTALL_SCRIPT_NAME),
      );
    });
  }
});

test('resolveLaunchDaemonHelperScriptPath returns the checked-in launchd helper only with AGENTPAY_DEV_SCRIPTS=1', async () => {
  const launchdAssets = await import(`${modulePath.href}?case=${Date.now()}-checked-in-helper`);

  await withDevScriptsEnv('1', async () => {
    const resolved = launchdAssets.resolveLaunchDaemonHelperScriptPath(
      launchdAssets.LAUNCHD_INSTALL_SCRIPT_NAME,
    );

    assert.equal(
      resolved,
      path.resolve(process.cwd(), 'scripts/launchd', launchdAssets.LAUNCHD_INSTALL_SCRIPT_NAME),
    );
  });
});

test('developmentHelperScriptsEnabled only accepts the exact opt-in value', async () => {
  const launchdAssets = await import(`${modulePath.href}?case=${Date.now()}-dev-scripts-flag`);

  assert.equal(launchdAssets.developmentHelperScriptsEnabled({ AGENTPAY_DEV_SCRIPTS: '1' }), true);
  assert.equal(
    launchdAssets.developmentHelperScriptsEnabled({ AGENTPAY_DEV_SCRIPTS: 'yes' }),
    false,
  );
  assert.equal(launchdAssets.developmentHelperScriptsEnabled({}), false);
});
