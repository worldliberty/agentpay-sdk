import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const modulePath = new URL('../src/lib/telemetry.ts', import.meta.url);
const consentModulePath = new URL('../src/lib/telemetry-consent.ts', import.meta.url);

async function loadModule(caseSuffix) {
  const telemetry = await import(`${modulePath.href}?case=${caseSuffix}-${Date.now()}`);
  telemetry.resetTelemetryForTesting();
  return telemetry;
}

async function loadConsentModule(caseSuffix) {
  return await import(`${consentModulePath.href}?case=${caseSuffix}-${Date.now()}`);
}

const EVM_ADDRESS = '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d';
const INSTALL_ID = '3f1c6a1e-59b3-4c4f-9a6f-2f1f1d0a11b2';

/**
 * A server that answers every request with `statusCode`, or — with `statusCode: null` — accepts
 * the connection, reads the body, and never answers.
 */
function startServer(statusCode = 200) {
  const requests = [];
  const sockets = new Set();
  const server = http.createServer((req, res) => {
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => {
      requests.push({ body, url: req.url });
      if (statusCode === null) {
        return;
      }
      res.statusCode = statusCode;
      res.end('1');
    });
  });
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        close: () =>
          new Promise((done) => {
            for (const socket of sockets) {
              socket.destroy();
            }
            server.close(() => done());
          }),
        events: () =>
          requests.flatMap((request) =>
            request.url.startsWith('/track') ? JSON.parse(request.body) : [],
          ),
        origin: `http://127.0.0.1:${port}`,
        requests,
        url: `http://127.0.0.1:${port}/track`,
      });
    });
  });
}

const ENV_KEYS = [
  'AGENTPAY_HOME',
  'AGENTPAY_MIXPANEL_URL',
  'AGENTPAY_SENTRY_DSN',
  'AGENTPAY_TELEMETRY',
  'AGENTPAY_TELEMETRY_ENVIRONMENT',
  'DO_NOT_TRACK',
];

/**
 * The test harness sets `AGENTPAY_TELEMETRY=0` for every test; these tests lift it, point Mixpanel
 * at a local server, and blank the Sentry DSN unless a test supplies its own.
 */
async function withTelemetryEnv(options, run) {
  const previous = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-telemetry-runtime-'));
  delete process.env.AGENTPAY_TELEMETRY;
  delete process.env.DO_NOT_TRACK;
  process.env.AGENTPAY_HOME = tempHome;
  process.env.AGENTPAY_MIXPANEL_URL = options.mixpanelUrl;
  process.env.AGENTPAY_SENTRY_DSN = options.sentryDsn ?? '';
  process.env.AGENTPAY_TELEMETRY_ENVIRONMENT = 'test';
  if (options.state) {
    fs.writeFileSync(path.join(tempHome, 'telemetry.json'), JSON.stringify(options.state), {
      mode: 0o600,
    });
  }

  try {
    return await run(tempHome);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
    fs.rmSync(tempHome, { force: true, recursive: true });
  }
}

function readStateFile(tempHome) {
  return JSON.parse(fs.readFileSync(path.join(tempHome, 'telemetry.json'), 'utf8'));
}

/** Pre-seeded so the first-run notice does not print during the test. */
function seededState(extra = {}) {
  return {
    enabled: true,
    installId: INSTALL_ID,
    noticeShownAt: '2026-01-01T00:00:00.000Z',
    ...extra,
  };
}

test('initTelemetry stays off under the harness opt-out and never touches the network', async () => {
  const telemetry = await loadModule('harness-off');
  assert.equal(process.env.AGENTPAY_TELEMETRY, '0');

  await telemetry.initTelemetry();
  assert.equal(telemetry.isTelemetryEnabled(), false);
  telemetry.beginCommand('wallet');
  telemetry.endCommand(0);
  await telemetry.shutdownTelemetry();
});

test('a command session is sent once, keyed by the install id, with no machine identity', async () => {
  const server = await startServer(200);

  try {
    await withTelemetryEnv({ mixpanelUrl: server.url, state: seededState() }, async (tempHome) => {
      const telemetry = await loadModule('session');
      await telemetry.initTelemetry();
      assert.equal(telemetry.isTelemetryEnabled(), true);

      telemetry.beginCommand('transfer');
      telemetry.trackBalanceMutation({
        action: 'transfer',
        amount: 1234.5,
        asset: 'USD1',
        broadcast: true,
        chainId: 56,
        result: 'success',
      });
      telemetry.endCommand(0);
      await telemetry.shutdownTelemetry();

      const events = server.events();
      assert.deepEqual(
        events.map((event) => event.event),
        ['balance_mutation', 'cli_session'],
      );
      for (const event of events) {
        assert.equal(event.properties.distinct_id, INSTALL_ID);
        assert.equal(event.properties.time % 60_000, 0, 'time is rounded to the minute');
        assert.equal(event.properties.environment, 'test');
      }

      const [mutation, session] = events;
      assert.equal(mutation.properties.amount_bucket, '1k-10k');
      assert.equal('amount' in mutation.properties, false, 'the exact amount never leaves');
      assert.equal(session.properties.command, 'transfer');
      assert.equal(session.properties.exit_code, 0);
      assert.equal(typeof session.properties.duration_ms, 'number');

      const body = server.requests.map((request) => request.body).join('\n');
      assert.ok(!body.includes(os.hostname()), 'hostname leaked');
      assert.ok(!body.includes(os.homedir()), 'home directory leaked');
      assert.equal('offlineUntil' in readStateFile(tempHome), false);
    });
  } finally {
    await server.close();
  }
});

test('a failed delivery backs off across processes and never rewrites the opt-in flag', async () => {
  const server = await startServer(500);

  try {
    await withTelemetryEnv({ mixpanelUrl: server.url, state: seededState() }, async (tempHome) => {
      const telemetry = await loadModule('backoff');
      await telemetry.initTelemetry();
      telemetry.beginCommand('wallet');
      telemetry.endCommand(0);

      // Another process opts out while this one is running.
      const consent = await loadConsentModule('backoff-other-process');
      consent.setTelemetryEnabled(false);

      await telemetry.shutdownTelemetry();
      assert.equal(server.requests.length, 1);

      const stored = readStateFile(tempHome);
      assert.equal(stored.enabled, false, 'the concurrent opt-out survives the backoff write');
      assert.ok(Date.parse(stored.offlineUntil) > Date.now(), 'a backoff is recorded');

      // The next process sees the backoff (after re-enabling, so the opt-out is not the reason).
      consent.patchTelemetryState({ enabled: true });
      assert.equal(consent.resolveTelemetryConsent().reason, 'delivery-backoff');

      const nextRun = await loadModule('backoff-next-process');
      await nextRun.initTelemetry();
      assert.equal(nextRun.isTelemetryEnabled(), false);
      nextRun.beginCommand('wallet');
      nextRun.endCommand(0);
      await nextRun.shutdownTelemetry();
      assert.equal(server.requests.length, 1, 'nothing is sent during the backoff');
    });
  } finally {
    await server.close();
  }
});

const BALANCES = [
  { balance: { formatted: '0.5' }, chainName: 'bsc', kind: 'native', symbol: 'BNB' },
  { balance: { formatted: '250' }, chainName: 'bsc', kind: 'erc20', symbol: 'USD1' },
];

test('the balance snapshot throttle is committed only after a delivered batch', async () => {
  const failing = await startServer(500);
  const working = await startServer(200);

  try {
    await withTelemetryEnv({ mixpanelUrl: failing.url, state: seededState() }, async (tempHome) => {
      const firstRun = await loadModule('snapshot-dropped');
      await firstRun.initTelemetry();
      firstRun.trackWalletBalanceSnapshot(BALANCES);
      await firstRun.shutdownTelemetry();
      assert.equal(failing.events()[0].event, 'balance_snapshot');
      assert.equal(
        'lastBalanceSnapshotAt' in readStateFile(tempHome),
        false,
        'a dropped snapshot must not burn the day',
      );

      // Lift the backoff the dropped batch recorded, as an elapsed hour would.
      const consent = await loadConsentModule('snapshot-clear-backoff');
      consent.patchTelemetryState({ offlineUntil: undefined });
      process.env.AGENTPAY_MIXPANEL_URL = working.url;

      const secondRun = await loadModule('snapshot-delivered');
      await secondRun.initTelemetry();
      secondRun.trackWalletBalanceSnapshot(BALANCES);
      await secondRun.shutdownTelemetry();
      const [snapshot] = working.events();
      assert.equal(snapshot.event, 'balance_snapshot');
      assert.equal(snapshot.properties.native_balance_bucket, '<10');
      assert.equal(snapshot.properties.token_balance_bucket, '100-1k');
      assert.ok(readStateFile(tempHome).lastBalanceSnapshotAt);

      const thirdRun = await loadModule('snapshot-throttled');
      await thirdRun.initTelemetry();
      thirdRun.trackWalletBalanceSnapshot(BALANCES);
      await thirdRun.shutdownTelemetry();
      assert.equal(working.requests.length, 1, 'a second snapshot within a day is suppressed');
    });
  } finally {
    await failing.close();
    await working.close();
  }
});

test('Rust binary errors are replaced, not scrubbed, before they can be reported', async () => {
  const { sanitizeErrorForReport } = await loadModule('sanitize');

  const exitError = new Error(
    `vault-cli-agent failed: policy "daily-cap" denied transfer of 1500 USD1 to ${EVM_ADDRESS}\nat https://rpc.example/v3/key`,
  );
  exitError.name = 'RustBinaryExitError';
  exitError.binaryName = 'vault-cli-agent';
  exitError.code = 3;
  exitError.cause = new SyntaxError(`Unexpected token in {"to":"${EVM_ADDRESS}"}`);

  const sanitized = sanitizeErrorForReport(exitError);
  assert.notEqual(sanitized, exitError);
  assert.equal(sanitized.name, 'RustBinaryExitError');
  assert.equal(sanitized.message, 'vault-cli-agent exited 3');
  assert.equal(sanitized.cause, undefined);
  assert.match(sanitized.stack, /^RustBinaryExitError: vault-cli-agent exited 3\n {4}at /u);
  for (const leaked of [EVM_ADDRESS, 'daily-cap', '1500', 'rpc.example']) {
    assert.ok(!sanitized.stack.includes(leaked), `${leaked} leaked into the stack`);
  }

  const parseError = new Error(`could not parse {"recipient":"${EVM_ADDRESS}"}`);
  parseError.name = 'RustBinaryJsonParseError';
  parseError.binaryName = 'vault-cli-admin';
  assert.equal(sanitizeErrorForReport(parseError).message, 'vault-cli-admin produced invalid JSON');

  const ordinary = new Error('plain failure');
  assert.equal(sanitizeErrorForReport(ordinary), ordinary);
  assert.equal(sanitizeErrorForReport('not an error'), 'not an error');
});

test('shutdown finishes within its deadline against endpoints that never answer', async () => {
  const silent = await startServer(null);

  try {
    await withTelemetryEnv(
      {
        mixpanelUrl: silent.url,
        sentryDsn: `http://publickey@127.0.0.1:${new URL(silent.origin).port}/1`,
        state: seededState(),
      },
      async (tempHome) => {
        const telemetry = await loadModule('never-responding');
        await telemetry.initTelemetry();
        telemetry.beginCommand('wallet');
        telemetry.reportTelemetryError(new Error(`boom for ${EVM_ADDRESS}`));
        telemetry.endCommand(1);

        const startedAt = Date.now();
        await telemetry.shutdownTelemetry();
        const elapsed = Date.now() - startedAt;

        assert.ok(elapsed < 3_500, `shutdown took ${elapsed} ms`);
        assert.ok(silent.requests.length >= 1, 'the request reached the silent server');
        assert.ok(Date.parse(readStateFile(tempHome).offlineUntil) > Date.now());
      },
    );
  } finally {
    await silent.close();
  }
});
