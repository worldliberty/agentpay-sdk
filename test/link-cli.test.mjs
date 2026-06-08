import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createLinkCard, linkCliVersion, runLinkCliJson } from '../src/lib/link.ts';

const repoRoot = new URL('..', import.meta.url).pathname;

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-link-test-'));
}

function writeFakeLinkCli(dir) {
  const scriptPath = path.join(dir, 'fake-link-cli.mjs');
  const logPath = path.join(dir, 'link-cli-calls.jsonl');
  fs.writeFileSync(
    scriptPath,
    `#!/usr/bin/env node
import fs from 'node:fs';

const logPath = ${JSON.stringify(logPath)};
const args = process.argv.slice(2);
fs.appendFileSync(logPath, JSON.stringify(args) + '\\n');

function optionValue(name) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
}

if (args.includes('--version')) {
  console.log('0.6.0-test');
  process.exit(0);
}

if (args[0] === 'auth' && args[1] === 'status') {
  console.log(JSON.stringify([{ authenticated: false, credentials_path: optionValue('--auth') ?? null }]));
  process.exit(0);
}

if (args[0] === 'payment-methods' && args[1] === 'list') {
  console.log(JSON.stringify([{ id: 'csmrpd_test', brand: 'visa', last4: '4242' }]));
  process.exit(0);
}

if (args[0] === 'spend-request' && args[1] === 'create') {
  console.log(JSON.stringify([{ id: 'lsrq_test', status: 'pending_approval', approval_url: 'https://app.link.test/approve' }]));
  process.exit(0);
}

if (args[0] === 'spend-request' && args[1] === 'retrieve') {
  console.log(JSON.stringify([{ id: args[2], status: 'approved', card_output_file: optionValue('--output-file') }]));
  process.exit(0);
}

console.error('unexpected fake link-cli args: ' + args.join(' '));
process.exit(2);
`,
    { mode: 0o700 },
  );
  return { scriptPath, logPath };
}

function readCallLog(logPath) {
  return fs
    .readFileSync(logPath, 'utf8')
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function runCli(args, env) {
  return spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      ...env,
    },
  });
}

test('link facade uses bundled link-cli for status and card creation', async () => {
  const dir = makeTempDir();
  const { scriptPath, logPath } = writeFakeLinkCli(dir);
  const env = { ...process.env, AGENTPAY_LINK_CLI_BIN: scriptPath };
  const outputFile = path.join(dir, 'card.json');

  try {
    assert.equal(linkCliVersion({ env }), '0.6.0-test');

    const status = await runLinkCliJson(['auth', 'status'], {
      authFile: path.join(dir, 'auth.json'),
      env,
    });
    assert.deepEqual(status, [
      { authenticated: false, credentials_path: path.join(dir, 'auth.json') },
    ]);

    const card = await createLinkCard({
      paymentMethodId: 'csmrpd_test',
      merchantName: 'Example Merchant',
      merchantUrl: 'https://merchant.example',
      context: 'Buy the selected item.',
      amountCents: 2500,
      outputFile,
      env,
    });
    assert.equal(card.spendRequestId, 'lsrq_test');
    assert.equal(card.cardOutputFile, outputFile);

    const calls = readCallLog(logPath);
    const createCall = calls.find((entry) => entry[0] === 'spend-request' && entry[1] === 'create');
    assert.ok(createCall);
    assert.ok(createCall.includes('--request-approval'));
    assert.ok(createCall.includes('--output-file'));
    assert.match(
      createCall[createCall.indexOf('--context') + 1],
      /approve or decline this request/u,
    );

    const retrieveCall = calls.find(
      (entry) => entry[0] === 'spend-request' && entry[1] === 'retrieve',
    );
    assert.ok(retrieveCall);
    assert.deepEqual(retrieveCall.slice(0, 4), [
      'spend-request',
      'retrieve',
      'lsrq_test',
      '--include',
    ]);
    assert.ok(retrieveCall.includes('--output-file'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('agentpay link card --json wraps create and retrieve', () => {
  const dir = makeTempDir();
  const { scriptPath, logPath } = writeFakeLinkCli(dir);
  const outputFile = path.join(dir, 'agentpay-card.json');

  try {
    const result = runCli(
      [
        'link',
        'card',
        '--payment-method-id',
        'csmrpd_test',
        '--merchant-name',
        'Example Merchant',
        '--merchant-url',
        'https://merchant.example',
        '--context',
        'Buy the selected item.',
        '--amount',
        '2500',
        '--output-file',
        outputFile,
        '--json',
      ],
      { AGENTPAY_LINK_CLI_BIN: scriptPath },
    );
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.spendRequestId, 'lsrq_test');
    assert.equal(payload.cardOutputFile, outputFile);

    const calls = readCallLog(logPath);
    assert.equal(
      calls.filter((entry) => entry[0] === 'spend-request' && entry[1] === 'create').length,
      1,
    );
    assert.equal(
      calls.filter((entry) => entry[0] === 'spend-request' && entry[1] === 'retrieve').length,
      1,
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
