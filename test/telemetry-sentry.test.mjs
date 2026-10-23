import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import test from 'node:test';
import zlib from 'node:zlib';

const modulePath = new URL('../src/lib/telemetry-sentry.ts', import.meta.url);

async function loadModule(caseSuffix) {
  return await import(`${modulePath.href}?case=${caseSuffix}-${Date.now()}`);
}

const EVM_ADDRESS = '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d';
const INSTALL_ID = '3f1c6a1e-59b3-4c4f-9a6f-2f1f1d0a11b2';

function fabricatedEvent() {
  return {
    message: `failed for ${EVM_ADDRESS}`,
    exception: {
      values: [
        {
          type: 'Error',
          value: `transfer to ${EVM_ADDRESS} rejected`,
          stacktrace: {
            frames: [
              {
                filename: `${os.homedir()}/agentpay-sdk/src/cli.ts`,
                abs_path: `${os.homedir()}/agentpay-sdk/src/cli.ts`,
                module: 'cli',
              },
            ],
          },
        },
      ],
    },
    server_name: 'alices-macbook.local',
    user: {
      id: INSTALL_ID,
      ip_address: '203.0.113.7',
      email: 'alice@example.com',
      username: 'alice',
      geo: { city: 'Lisbon' },
    },
    contexts: {
      app: { app_start_time: '2026-09-25T00:00:00Z', app_memory: 123 },
      culture: { locale: 'en-US', timezone: 'Europe/Lisbon' },
      device: { arch: 'arm64', boot_time: '…', memory_size: 1, cpu_description: 'M3' },
      os: { name: 'macOS', version: '15.5', kernel_version: '25.5.0', build: '24F74' },
      runtime: { name: 'node', version: 'v25.2.1', argv: ['node', 'cli.ts', EVM_ADDRESS] },
      trace: { trace_id: 'abc', span_id: 'def' },
    },
    extra: { recipientAddress: EVM_ADDRESS, note: `hash ${'0x' + 'ab'.repeat(32)}` },
    tags: { platform: 'darwin', hostname: 'alices-macbook' },
    breadcrumbs: [{ message: `console: ${EVM_ADDRESS}` }],
    modules: { viem: '2.47.6' },
    request: { url: 'https://example.com/secret' },
    debug_meta: { images: [{ code_file: `${os.homedir()}/x.js` }] },
  };
}

test('scrubEvent removes machine and person identity while keeping what explains the crash', async () => {
  const { scrubEvent } = await loadModule('scrub');

  const event = scrubEvent(fabricatedEvent());
  const serialized = JSON.stringify(event);

  assert.ok(!serialized.includes(EVM_ADDRESS), 'address leaked');
  assert.ok(!serialized.includes(os.homedir()), 'home directory leaked');
  assert.ok(!serialized.includes('alice'), 'person identity leaked');
  assert.ok(!serialized.includes('macbook'), 'machine identity leaked');
  assert.ok(!serialized.includes('Lisbon'), 'location leaked');

  assert.equal('server_name' in event, false);
  assert.equal('breadcrumbs' in event, false);
  assert.equal('modules' in event, false);
  assert.equal('request' in event, false);
  assert.equal('debug_meta' in event, false);

  assert.deepEqual(event.user, { id: INSTALL_ID });
  assert.deepEqual(event.contexts, {
    os: { name: 'macOS', version: '15.5' },
    runtime: { name: 'node', version: 'v25.2.1' },
    trace: { trace_id: 'abc', span_id: 'def' },
  });
  assert.deepEqual(event.extra, { note: 'hash <redacted>' });
  assert.deepEqual(event.tags, { platform: 'darwin' });

  assert.equal(event.message, 'failed for <redacted>');
  const [exception] = event.exception.values;
  assert.equal(exception.type, 'Error');
  assert.equal(exception.value, 'transfer to <redacted> rejected');
  assert.equal(exception.stacktrace.frames[0].filename, '~/agentpay-sdk/src/cli.ts');
  assert.equal(exception.stacktrace.frames[0].abs_path, '~/agentpay-sdk/src/cli.ts');
});

test('scrubEvent drops a user without an id and empty contexts instead of leaving stubs', async () => {
  const { scrubEvent } = await loadModule('scrub-empty');

  const event = scrubEvent({
    user: { email: 'alice@example.com' },
    contexts: { device: { arch: 'arm64' }, runtime: { argv: [] } },
  });

  assert.equal('user' in event, false);
  assert.equal('contexts' in event, false);
});

function startEnvelopeServer() {
  const envelopes = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      let body = Buffer.concat(chunks);
      if (req.headers['content-encoding'] === 'gzip') {
        body = zlib.gunzipSync(body);
      }
      envelopes.push({ body: body.toString('utf8'), url: req.url });
      res.statusCode = 200;
      res.end('{}');
    });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        close: () => new Promise((done) => server.close(() => done())),
        dsn: `http://publickey@127.0.0.1:${port}/1`,
        envelopes,
      });
    });
  });
}

function parseEnvelopeEvent(body) {
  const items = body
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));
  const eventIndex = items.findIndex((item) => item.type === 'event');
  assert.ok(eventIndex > 0, 'envelope contains an event item');
  return { header: items[0], event: items[eventIndex + 1] };
}

test('initSentry sends a scrubbed event with no default integrations and no hostname', async () => {
  const server = await startEnvelopeServer();
  const previousDsn = process.env.AGENTPAY_SENTRY_DSN;
  const previousEnvironment = process.env.AGENTPAY_TELEMETRY_ENVIRONMENT;
  process.env.AGENTPAY_SENTRY_DSN = server.dsn;
  process.env.AGENTPAY_TELEMETRY_ENVIRONMENT = 'test';

  try {
    const { captureCliError, closeSentry, initSentry, isSentryActive } =
      await loadModule('integration');

    await initSentry({
      distinctId: INSTALL_ID,
      release: '0.4.0-test',
      tags: {
        arch: process.arch,
        cli_version: '0.4.0-test',
        environment: 'test',
        platform: process.platform,
      },
    });
    assert.equal(isSentryActive(), true);

    const error = new Error(`transfer to ${EVM_ADDRESS} failed at ${os.homedir()}/x.ts`, {
      cause: new Error(`rpc https://bsc-mainnet.infura.io/v3/${'a1b2c3d4'.repeat(4)} refused`),
    });
    captureCliError(error);
    assert.equal(await closeSentry(), true);

    assert.equal(server.envelopes.length, 1);
    const { body, url } = server.envelopes[0];
    assert.match(url, /^\/api\/1\/envelope\//u);
    assert.ok(!body.includes(EVM_ADDRESS), 'address leaked');
    assert.ok(!body.includes(os.homedir()), 'home directory leaked');
    assert.ok(!body.includes(os.hostname()), 'hostname leaked');
    assert.ok(!body.includes('a1b2c3d4a1b2c3d4'), 'API key leaked');

    const { event } = parseEnvelopeEvent(body);
    assert.equal('server_name' in event, false);
    assert.equal('breadcrumbs' in event, false);
    assert.equal('modules' in event, false);
    assert.deepEqual(event.user, { id: INSTALL_ID });
    assert.equal(event.release, '0.4.0-test');
    assert.equal(event.environment, 'test');
    assert.equal(event.tags.platform, process.platform);
    assert.deepEqual(event.sdk.integrations, ['LinkedErrors']);

    const values = event.exception.values;
    assert.equal(values.length, 2, 'the cause chain is attached');
    const messages = values.map((value) => value.value);
    assert.ok(
      messages.some((message) => message.includes('transfer to <redacted> failed at ~/x.ts')),
    );
    assert.ok(
      messages.some((message) => message.includes('rpc https://bsc-mainnet.infura.io refused')),
    );
  } finally {
    if (previousDsn === undefined) {
      delete process.env.AGENTPAY_SENTRY_DSN;
    } else {
      process.env.AGENTPAY_SENTRY_DSN = previousDsn;
    }
    if (previousEnvironment === undefined) {
      delete process.env.AGENTPAY_TELEMETRY_ENVIRONMENT;
    } else {
      process.env.AGENTPAY_TELEMETRY_ENVIRONMENT = previousEnvironment;
    }
    await server.close();
  }
});
