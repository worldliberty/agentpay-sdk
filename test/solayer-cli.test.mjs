import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const repoRoot = new URL('..', import.meta.url).pathname;

function makeIsolatedHome() {
  const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-solayer-home-'));
  const agentpayHome = path.join(homeDir, '.agentpay');
  fs.mkdirSync(agentpayHome, { recursive: true, mode: 0o700 });
  return { homeDir, agentpayHome };
}

function runCli(args, { homeDir, input = '', env = {} }) {
  const agentpayHome = path.join(homeDir, '.agentpay');
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--import', 'tsx', 'src/cli.ts', ...args], {
      cwd: repoRoot,
      env: {
        ...process.env,
        HOME: homeDir,
        AGENTPAY_HOME: agentpayHome,
        ...env,
      },
      stdio: 'pipe',
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.on('error', reject);
    child.on('close', (status, signal) => {
      resolve({
        status:
          status ??
          (typeof signal === 'string' && typeof os.constants.signals[signal] === 'number'
            ? 128 + os.constants.signals[signal]
            : 1),
        stdout,
        stderr,
      });
    });
    if (input) {
      child.stdin.end(input);
    } else {
      child.stdin.end();
    }
  });
}

function combinedOutput(result) {
  return `${result.stdout ?? ''}${result.stderr ?? ''}`;
}

async function closeServer(server) {
  if (typeof server.closeAllConnections === 'function') {
    server.closeAllConnections();
  }
  await new Promise((resolve) => {
    server.close(() => resolve(undefined));
  });
}

function writeVarint(value) {
  let remaining = BigInt(value);
  const bytes = [];
  while (remaining >= 0x80n) {
    bytes.push(Number((remaining & 0x7fn) | 0x80n));
    remaining >>= 7n;
  }
  bytes.push(Number(remaining));
  return Uint8Array.from(bytes);
}

function concat(chunks) {
  const length = chunks.reduce((total, chunk) => total + chunk.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

function key(field, wire) {
  return writeVarint((field << 3) | wire);
}

function stringField(field, value) {
  if (!value) {
    return [];
  }
  const bytes = Buffer.from(value, 'utf8');
  return [key(field, 2), writeVarint(bytes.length), bytes];
}

function varintField(field, value) {
  if (value === undefined || value === null) {
    return [];
  }
  return [key(field, 0), writeVarint(value === true ? 1 : value === false ? 0 : value)];
}

function encodeMessage(fields) {
  return concat(fields.flat());
}

function grpcFrame(message) {
  const output = new Uint8Array(5 + message.length);
  output[0] = 0;
  new DataView(output.buffer).setUint32(1, message.length, false);
  output.set(message, 5);
  return Buffer.from(output);
}

function startSolayerServer() {
  const calls = [];
  const server = http.createServer((req, res) => {
    req.resume();
    const method = req.url.split('/').pop();
    calls.push({
      method,
      authorization: req.headers.authorization ?? null,
      browserId: req.headers['browser-id'] ?? null,
      platform: req.headers.platform ?? null,
    });

    let body;
    switch (method) {
      case 'GetSignatureMessage':
        body = encodeMessage([
          stringField(1, 'You are logging into Solayer.\n\n\nYour challenge is: test'),
          stringField(2, 'message-1'),
        ]);
        break;
      case 'VerifySignature':
        body = encodeMessage([stringField(1, 'solayer-token-1')]);
        break;
      case 'SendEmail':
        body = encodeMessage([stringField(1, 'email-session-1')]);
        break;
      case 'VerifyEmailOTP':
        body = encodeMessage([stringField(1, 'email-token-1')]);
        break;
      case 'CheckAccount':
        body = encodeMessage([varintField(1, true), stringField(2, 'auth-session-1')]);
        break;
      case 'SignIn':
        body = encodeMessage([stringField(1, 'solayer-email-token-1')]);
        break;
      case 'GetDepositAddress':
        body = encodeMessage([stringField(1, 'EZYC52PvmZrsifqU6Dpt9qZ3onYmBpUR1UmFn47i3KF7')]);
        break;
      default:
        res.statusCode = 404;
        res.end();
        return;
    }
    res.setHeader('content-type', 'application/grpc-web+proto');
    res.end(grpcFrame(body));
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve({
        server,
        baseUrl: `http://127.0.0.1:${address.port}`,
        calls,
      });
    });
  });
}

test('solayer external wallet prepare and verify stores a redacted session', async () => {
  const { homeDir } = makeIsolatedHome();
  const { server, baseUrl, calls } = await startSolayerServer();

  try {
    const prepare = await runCli(
      [
        'solayer',
        'login',
        'external-wallet',
        'prepare',
        '--address',
        'So11111111111111111111111111111111111111112',
        '--json',
      ],
      {
        homeDir,
        env: { AGENTPAY_SOLAYER_BASE_URL: baseUrl },
      },
    );
    assert.equal(prepare.status, 0, combinedOutput(prepare));
    const prepared = JSON.parse(prepare.stdout);
    assert.equal(prepared.messageId, 'message-1');
    assert.match(prepared.message, /logging into Solayer/u);

    const verify = await runCli(
      [
        'solayer',
        'login',
        'external-wallet',
        'verify',
        '--address',
        'So11111111111111111111111111111111111111112',
        '--message-id',
        'message-1',
        '--signature',
        `0x${'11'.repeat(64)}`,
        '--json',
      ],
      {
        homeDir,
        env: { AGENTPAY_SOLAYER_BASE_URL: baseUrl },
      },
    );
    assert.equal(verify.status, 0, combinedOutput(verify));
    assert.doesNotMatch(verify.stdout, /solayer-token-1/u);
    assert.equal(JSON.parse(verify.stdout).authenticated, true);

    const status = await runCli(['solayer', 'session', 'status', '--json'], {
      homeDir,
      env: { AGENTPAY_SOLAYER_BASE_URL: baseUrl },
    });
    assert.equal(status.status, 0, combinedOutput(status));
    assert.equal(JSON.parse(status.stdout).authenticated, true);
    assert.doesNotMatch(status.stdout, /solayer-token-1/u);
    assert.deepEqual(
      calls.map((call) => call.method),
      ['GetSignatureMessage', 'VerifySignature'],
    );
  } finally {
    await closeServer(server);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('solayer email login stores session and authenticated calls send token metadata', async () => {
  const { homeDir } = makeIsolatedHome();
  const { server, baseUrl, calls } = await startSolayerServer();

  try {
    const start = await runCli(
      ['solayer', 'login', 'email', 'start', '--email', 'user@example.com', '--json'],
      {
        homeDir,
        env: { AGENTPAY_SOLAYER_BASE_URL: baseUrl },
      },
    );
    assert.equal(start.status, 0, combinedOutput(start));
    assert.equal(JSON.parse(start.stdout).sessionId, 'email-session-1');

    const verify = await runCli(
      [
        'solayer',
        'login',
        'email',
        'verify',
        '--session-id',
        'email-session-1',
        '--otp',
        '123456',
        '--json',
      ],
      {
        homeDir,
        env: { AGENTPAY_SOLAYER_BASE_URL: baseUrl },
      },
    );
    assert.equal(verify.status, 0, combinedOutput(verify));
    assert.doesNotMatch(verify.stdout, /solayer-email-token-1/u);

    const deposit = await runCli(['solayer', 'deposit-address', '--json'], {
      homeDir,
      env: { AGENTPAY_SOLAYER_BASE_URL: baseUrl },
    });
    assert.equal(deposit.status, 0, combinedOutput(deposit));
    assert.equal(
      JSON.parse(deposit.stdout).depositAddress,
      'EZYC52PvmZrsifqU6Dpt9qZ3onYmBpUR1UmFn47i3KF7',
    );

    const depositCall = calls.find((call) => call.method === 'GetDepositAddress');
    assert.equal(depositCall.authorization, 'solayer-email-token-1');
    assert.equal(depositCall.platform, 'WEB');
    assert.ok(depositCall.browserId);
  } finally {
    await closeServer(server);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});
