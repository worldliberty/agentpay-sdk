import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';

const modulePath = new URL('../src/lib/telemetry-mixpanel.ts', import.meta.url);

async function loadModule(caseSuffix) {
  return await import(`${modulePath.href}?case=${caseSuffix}-${Date.now()}`);
}

const EVM_ADDRESS = '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d';
const INSTALL_ID = '3f1c6a1e-59b3-4c4f-9a6f-2f1f1d0a11b2';

function startServer(statusCode = 200) {
  const requests = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => {
      requests.push({ body: JSON.parse(body), headers: req.headers, url: req.url });
      res.statusCode = statusCode;
      res.end('1');
    });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        close: () => new Promise((done) => server.close(() => done())),
        requests,
        url: `http://127.0.0.1:${port}/track`,
      });
    });
  });
}

async function withMixpanelEnv(url, run) {
  const previous = {
    token: process.env.AGENTPAY_MIXPANEL_TOKEN,
    url: process.env.AGENTPAY_MIXPANEL_URL,
  };
  process.env.AGENTPAY_MIXPANEL_TOKEN = 'test-token';
  process.env.AGENTPAY_MIXPANEL_URL = url;

  try {
    return await run();
  } finally {
    for (const [key, value] of [
      ['AGENTPAY_MIXPANEL_TOKEN', previous.token],
      ['AGENTPAY_MIXPANEL_URL', previous.url],
    ]) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
}

test('flushMixpanel posts one batch whose events carry the install id and a minute-rounded time', async () => {
  const server = await startServer();

  try {
    await withMixpanelEnv(server.url, async () => {
      const { configureMixpanel, flushMixpanel, pendingMixpanelEventCount, trackMixpanelEvent } =
        await loadModule('payload');

      configureMixpanel(INSTALL_ID, { cli_version: '0.4.0', platform: 'darwin' });
      const before = Date.now();
      trackMixpanelEvent('cli_session', { command: 'wallet', exit_code: 0, duration_ms: 12 });
      trackMixpanelEvent('balance_mutation', {
        action: 'transfer',
        amount_bucket: '<10',
        recipientAddress: EVM_ADDRESS,
      });
      assert.equal(pendingMixpanelEventCount(), 2);

      assert.equal(await flushMixpanel(), true);
      assert.equal(pendingMixpanelEventCount(), 0);
      assert.equal(server.requests.length, 1);

      const [request] = server.requests;
      assert.equal(request.url, '/track');
      assert.equal(request.headers['content-type'], 'application/json');
      assert.equal(request.body.length, 2);

      const [session, mutation] = request.body;
      assert.equal(session.event, 'cli_session');
      assert.equal(session.properties.distinct_id, INSTALL_ID);
      assert.equal(session.properties.token, 'test-token');
      assert.equal(session.properties.cli_version, '0.4.0');
      assert.equal(session.properties.platform, 'darwin');
      assert.equal(session.properties.command, 'wallet');
      assert.match(session.properties.$insert_id, /^[0-9a-f-]{36}$/u);

      assert.equal(session.properties.time % 60_000, 0, 'time is truncated to the minute');
      assert.ok(session.properties.time <= before);
      assert.ok(session.properties.time > before - 60_000);

      assert.equal(mutation.properties.amount_bucket, '<10');
      assert.equal('recipientAddress' in mutation.properties, false);
      assert.ok(!JSON.stringify(request.body).includes(EVM_ADDRESS));
    });
  } finally {
    await server.close();
  }
});

test('trackMixpanelEvent caps the queue at 50 events per invocation', async () => {
  const server = await startServer();

  try {
    await withMixpanelEnv(server.url, async () => {
      const { configureMixpanel, flushMixpanel, pendingMixpanelEventCount, trackMixpanelEvent } =
        await loadModule('cap');

      configureMixpanel(INSTALL_ID, {});
      for (let index = 0; index < 60; index += 1) {
        trackMixpanelEvent('cli_session', { exit_code: index });
      }
      assert.equal(pendingMixpanelEventCount(), 50);

      await flushMixpanel();
      assert.equal(server.requests[0].body.length, 50);
      assert.equal(server.requests[0].body[49].properties.exit_code, 49);
    });
  } finally {
    await server.close();
  }
});

test('trackMixpanelEvent queues nothing before configureMixpanel or without a token', async () => {
  await withMixpanelEnv('http://127.0.0.1:1/track', async () => {
    const { configureMixpanel, pendingMixpanelEventCount, trackMixpanelEvent } =
      await loadModule('unconfigured');

    trackMixpanelEvent('cli_session', {});
    assert.equal(pendingMixpanelEventCount(), 0);

    process.env.AGENTPAY_MIXPANEL_TOKEN = '';
    configureMixpanel(INSTALL_ID, {});
    trackMixpanelEvent('cli_session', {});
    assert.equal(pendingMixpanelEventCount(), 0);
  });
});

test('flushMixpanel reports a rejected or unreachable endpoint and drops the batch', async () => {
  const server = await startServer(500);

  try {
    await withMixpanelEnv(server.url, async () => {
      const { configureMixpanel, flushMixpanel, pendingMixpanelEventCount, trackMixpanelEvent } =
        await loadModule('failure');

      configureMixpanel(INSTALL_ID, {});
      trackMixpanelEvent('cli_session', {});
      assert.equal(await flushMixpanel(), false);
      assert.equal(pendingMixpanelEventCount(), 0);

      process.env.AGENTPAY_MIXPANEL_URL = 'http://127.0.0.1:1/track';
      trackMixpanelEvent('cli_session', {});
      assert.equal(await flushMixpanel(), false);
      assert.equal(pendingMixpanelEventCount(), 0);

      // Nothing queued is a successful (empty) delivery, not a failure.
      assert.equal(await flushMixpanel(), true);
    });
  } finally {
    await server.close();
  }
});
