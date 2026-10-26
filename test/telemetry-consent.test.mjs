import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const modulePath = new URL('../src/lib/telemetry-consent.ts', import.meta.url);

async function loadModule(caseSuffix) {
  return await import(`${modulePath.href}?case=${caseSuffix}-${Date.now()}`);
}

function withTempHome(run) {
  const previousHome = process.env.AGENTPAY_HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-telemetry-test-'));
  process.env.AGENTPAY_HOME = tempHome;

  try {
    return run(tempHome);
  } finally {
    if (previousHome === undefined) {
      delete process.env.AGENTPAY_HOME;
    } else {
      process.env.AGENTPAY_HOME = previousHome;
    }
    fs.rmSync(tempHome, { force: true, recursive: true });
  }
}

function readStateFile(tempHome) {
  return JSON.parse(fs.readFileSync(path.join(tempHome, 'telemetry.json'), 'utf8'));
}

test('resolveTelemetryConsent honours AGENTPAY_TELEMETRY=0', async () => {
  const { resolveTelemetryConsent } = await loadModule('env-opt-out');

  const consent = resolveTelemetryConsent({ AGENTPAY_TELEMETRY: '0' });
  assert.equal(consent.enabled, false);
  assert.equal(consent.reason, 'env-opt-out');
});

test('resolveTelemetryConsent honours the DO_NOT_TRACK convention', async () => {
  const { resolveTelemetryConsent } = await loadModule('do-not-track');

  // The convention opts out on any value that is not 0/empty, not just "1".
  for (const value of ['1', 'true', 'yes', 'on']) {
    const consent = resolveTelemetryConsent({ DO_NOT_TRACK: value });
    assert.equal(consent.enabled, false, `DO_NOT_TRACK=${value} should opt out`);
    assert.equal(consent.reason, 'do-not-track');
  }

  for (const value of ['0', '']) {
    assert.notEqual(
      resolveTelemetryConsent({ DO_NOT_TRACK: value }).reason,
      'do-not-track',
      `DO_NOT_TRACK=${value} should not opt out`,
    );
  }
});

test('resolveTelemetryConsent accepts the usual falsey spellings of AGENTPAY_TELEMETRY', async () => {
  const { resolveTelemetryConsent } = await loadModule('env-opt-out-spellings');

  for (const value of ['0', 'false', 'off', 'no']) {
    const consent = resolveTelemetryConsent({ AGENTPAY_TELEMETRY: value });
    assert.equal(consent.enabled, false, `AGENTPAY_TELEMETRY=${value} should opt out`);
    assert.equal(consent.reason, 'env-opt-out');
  }
});

test('resolveTelemetryConsent no longer has a hidden test-sandbox switch', async () => {
  const { resolveTelemetryConsent } = await loadModule('no-sandbox-switch');

  // The isolated runner used to be trusted to set AGENTPAY_TEST_ISOLATED; nothing else ever did,
  // so the test suite now opts out through the same AGENTPAY_TELEMETRY=0 a user would.
  withTempHome(() => {
    const consent = resolveTelemetryConsent({ AGENTPAY_TEST_ISOLATED: '1' });
    assert.notEqual(consent.reason, 'test-sandbox');
    assert.equal(consent.enabled, true);
  });
});

test('resolveTelemetryConsent is off when both destinations are blanked out', async () => {
  const { resolveTelemetryConsent } = await loadModule('no-credentials');

  const restoreDsn = process.env.AGENTPAY_SENTRY_DSN;
  const restoreToken = process.env.AGENTPAY_MIXPANEL_TOKEN;
  process.env.AGENTPAY_SENTRY_DSN = '';
  process.env.AGENTPAY_MIXPANEL_TOKEN = '';

  try {
    const consent = resolveTelemetryConsent({});
    assert.equal(consent.enabled, false);
    assert.equal(consent.reason, 'missing-credentials');
  } finally {
    if (restoreDsn === undefined) {
      delete process.env.AGENTPAY_SENTRY_DSN;
    } else {
      process.env.AGENTPAY_SENTRY_DSN = restoreDsn;
    }
    if (restoreToken === undefined) {
      delete process.env.AGENTPAY_MIXPANEL_TOKEN;
    } else {
      process.env.AGENTPAY_MIXPANEL_TOKEN = restoreToken;
    }
  }
});

test('ensureTelemetryState writes an install id with owner-only permissions', async () => {
  const { ensureTelemetryState } = await loadModule('install-id');

  withTempHome((tempHome) => {
    const state = ensureTelemetryState();
    assert.match(state.installId, /^[0-9a-f-]{36}$/u);
    assert.equal(state.enabled, true);

    const telemetryPath = path.join(tempHome, 'telemetry.json');
    assert.equal(fs.statSync(telemetryPath).mode & 0o777, 0o600);
  });
});

test('ensureTelemetryState reuses an existing install id', async () => {
  const { ensureTelemetryState } = await loadModule('stable-install-id');

  withTempHome(() => {
    const first = ensureTelemetryState();
    const second = ensureTelemetryState();
    assert.equal(first.installId, second.installId);
  });
});

test('setTelemetryEnabled(false) is reported as a stored opt-out', async () => {
  const { resolveTelemetryConsent, setTelemetryEnabled } = await loadModule('stored-opt-out');

  withTempHome(() => {
    setTelemetryEnabled(false);
    const consent = resolveTelemetryConsent({});
    assert.equal(consent.enabled, false);
    assert.equal(consent.reason, 'stored-opt-out');

    setTelemetryEnabled(true);
    assert.equal(resolveTelemetryConsent({}).enabled, true);
  });
});

test('a corrupt telemetry file fails closed instead of resurrecting collection', async () => {
  const { resolveTelemetryConsent, setTelemetryEnabled } = await loadModule('corrupt-fails-closed');

  withTempHome((tempHome) => {
    setTelemetryEnabled(false);
    // Simulate a truncated write or a hand edit that leaves the file unparseable.
    fs.writeFileSync(path.join(tempHome, 'telemetry.json'), '{ not json', { mode: 0o600 });

    const consent = resolveTelemetryConsent({});
    assert.equal(consent.enabled, false);
    assert.equal(consent.reason, 'unreadable-state');
  });
});

test('a telemetry file missing its install id is treated as unreadable', async () => {
  const { resolveTelemetryConsent } = await loadModule('missing-install-id');

  withTempHome((tempHome) => {
    fs.writeFileSync(path.join(tempHome, 'telemetry.json'), JSON.stringify({ enabled: true }), {
      mode: 0o600,
    });

    const consent = resolveTelemetryConsent({});
    assert.equal(consent.enabled, false);
    assert.equal(consent.reason, 'unreadable-state');
  });
});

test('setTelemetryEnabled(true) rewrites a corrupt file and recovers', async () => {
  const { resolveTelemetryConsent, setTelemetryEnabled } = await loadModule('recover-corrupt');

  withTempHome((tempHome) => {
    fs.writeFileSync(path.join(tempHome, 'telemetry.json'), '{ not json', { mode: 0o600 });

    const state = setTelemetryEnabled(true);
    assert.match(state.installId, /^[0-9a-f-]{36}$/u);
    assert.equal(resolveTelemetryConsent({}).enabled, true);
  });
});

test('patchTelemetryState re-reads the file and changes only the given fields', async () => {
  const { ensureTelemetryState, patchTelemetryState, setTelemetryEnabled } =
    await loadModule('patch');

  withTempHome((tempHome) => {
    const startup = ensureTelemetryState();
    assert.equal(startup.enabled, true);

    // A second process opts out after this one captured its startup state.
    setTelemetryEnabled(false);

    const patched = patchTelemetryState({ offlineUntil: '2030-01-01T00:00:00.000Z' });
    assert.equal(patched.enabled, false, 'the concurrent opt-out survives the patch');
    assert.equal(patched.installId, startup.installId);
    assert.equal(patched.offlineUntil, '2030-01-01T00:00:00.000Z');
    assert.deepEqual(readStateFile(tempHome), patched);

    // Patching a field to undefined removes it from the file.
    const cleared = patchTelemetryState({ offlineUntil: undefined });
    assert.equal('offlineUntil' in readStateFile(tempHome), false);
    assert.equal(cleared.enabled, false);
  });
});

test('patchTelemetryState never creates or replaces a file it cannot read', async () => {
  const { patchTelemetryState } = await loadModule('patch-missing');

  withTempHome((tempHome) => {
    const telemetryPath = path.join(tempHome, 'telemetry.json');
    assert.equal(patchTelemetryState({ noticeShownAt: 'now' }), null);
    assert.equal(fs.existsSync(telemetryPath), false);

    fs.writeFileSync(telemetryPath, '{ not json', { mode: 0o600 });
    assert.equal(patchTelemetryState({ noticeShownAt: 'now' }), null);
    assert.equal(fs.readFileSync(telemetryPath, 'utf8'), '{ not json');
  });
});

test('printFirstRunNotice writes to stderr exactly once and patches rather than rewrites', async () => {
  const { ensureTelemetryState, printFirstRunNotice, setTelemetryEnabled } =
    await loadModule('notice');

  withTempHome((tempHome) => {
    const originalError = console.error;
    const written = [];
    console.error = (message) => written.push(String(message));

    try {
      const startup = ensureTelemetryState();
      // Opt out from "another process" between reading the state and showing the notice.
      setTelemetryEnabled(false);

      const shown = printFirstRunNotice(startup);
      assert.equal(written.length, 1);
      assert.match(written[0], /never collects private keys/u);
      assert.match(written[0], /exact amounts/u);
      assert.ok(shown.noticeShownAt);
      assert.equal(shown.enabled, false, 'the notice write must not undo the opt-out');
      assert.equal(readStateFile(tempHome).enabled, false);

      printFirstRunNotice(shown);
      assert.equal(written.length, 1);
    } finally {
      console.error = originalError;
    }
  });
});
