import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { keccak256, parseSignature } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { Actions as TempoActions, Transaction as TempoTransaction } from 'viem/tempo';
import { estimateFees } from '../packages/rpc/src/index.ts';

const repoRoot = new URL('..', import.meta.url).pathname;
const AGENT_KEY_ID = '00000000-0000-0000-0000-000000000123';
const TOKEN_ADDRESS = '0x20C000000000000000000000b9537d11c60E8b50';
const RECIPIENT_ADDRESS = '0x000000000000000000000000000000000000dEaD';

function makeIsolatedHome() {
  const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-payment-http-'));
  const agentpayHome = path.join(homeDir, '.agentpay');
  fs.mkdirSync(agentpayHome, { recursive: true, mode: 0o700 });
  return { homeDir, agentpayHome };
}

function writeExecutable(filePath, body) {
  fs.writeFileSync(filePath, `#!/bin/sh\n${body}\n`, { mode: 0o700 });
}

function writeConfig(agentpayHome, config) {
  fs.writeFileSync(path.join(agentpayHome, 'config.json'), `${JSON.stringify(config, null, 2)}\n`);
}

function runCliAsync(args, { homeDir, env = {} }) {
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
    child.stdout?.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr?.on('data', (chunk) => {
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
  });
}

function combinedOutput(result) {
  return `${result.stdout ?? ''}${result.stderr ?? ''}`;
}

function recoverableSignatureArtifacts(signatureHex, signatureHexOutput = signatureHex) {
  const parsed = parseSignature(signatureHex);
  return {
    signatureHex: signatureHexOutput,
    rHex: parsed.r,
    sHex: parsed.s,
    v: parsed.yParity ?? Number(parsed.v - 27n),
  };
}

async function startUnixSocket(socketPath) {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => resolve(undefined));
  });
  return server;
}

async function closeServer(server) {
  if (!server) {
    return;
  }
  if (typeof server.closeAllConnections === 'function') {
    server.closeAllConnections();
  }
  await new Promise((resolve) => server.close(() => resolve(undefined)));
}

async function startForwardProxyServer() {
  let proxyHits = 0;
  const server = http.createServer((req, res) => {
    proxyHits += 1;
    const targetUrl = new URL(req.url);
    const upstream = http.request(
      {
        host: '127.0.0.1',
        port: Number(targetUrl.port),
        method: req.method,
        path: `${targetUrl.pathname}${targetUrl.search}`,
        headers: req.headers,
      },
      (upstreamResponse) => {
        res.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
        upstreamResponse.pipe(res);
      },
    );
    req.pipe(upstream);
    upstream.on('error', (error) => {
      res.statusCode = 502;
      res.end(error instanceof Error ? error.message : String(error));
    });
  });
  server.on('connect', (req, clientSocket, head) => {
    proxyHits += 1;
    const targetUrl = new URL(`http://${req.url}`);
    const upstreamSocket = net.connect(
      {
        host: '127.0.0.1',
        port: Number(targetUrl.port),
      },
      () => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head.length > 0) {
          upstreamSocket.write(head);
        }
        upstreamSocket.pipe(clientSocket);
        clientSocket.pipe(upstreamSocket);
      },
    );
    const destroyBoth = () => {
      upstreamSocket.destroy();
      clientSocket.destroy();
    };
    upstreamSocket.on('error', destroyBoth);
    clientSocket.on('error', destroyBoth);
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(undefined));
  });

  const address = server.address();
  return {
    server,
    proxyUrl: `http://127.0.0.1:${address.port}`,
    getProxyHits: () => proxyHits,
  };
}

async function startMockRpcServer({
  chainId,
  txHash,
  from,
  to,
  estimateGasErrorMessage,
  methodOverrides = {},
}) {
  const chainIdHex = `0x${chainId.toString(16)}`;
  const blockHash = `0x${'1'.repeat(64)}`;
  const logsBloom = `0x${'0'.repeat(512)}`;
  const block = {
    number: '0x64',
    hash: blockHash,
    parentHash: `0x${'0'.repeat(64)}`,
    nonce: '0x0000000000000000',
    sha3Uncles: `0x${'0'.repeat(64)}`,
    logsBloom,
    transactionsRoot: `0x${'0'.repeat(64)}`,
    stateRoot: `0x${'0'.repeat(64)}`,
    receiptsRoot: `0x${'0'.repeat(64)}`,
    miner: from,
    difficulty: '0x0',
    totalDifficulty: '0x0',
    extraData: '0x',
    size: '0x1',
    gasLimit: '0x1c9c380',
    gasUsed: '0x5208',
    timestamp: '0x1',
    transactions: [],
    uncles: [],
    baseFeePerGas: '0x3b9aca00',
  };
  const receipt = {
    transactionHash: txHash,
    transactionIndex: '0x0',
    blockHash,
    blockNumber: '0x64',
    from,
    to,
    cumulativeGasUsed: '0x5208',
    gasUsed: '0x5208',
    contractAddress: null,
    logs: [],
    logsBloom,
    status: '0x1',
    type: '0x2',
    effectiveGasPrice: '0x3b9aca00',
  };

  const handleMethod = (method) => {
    if (Object.hasOwn(methodOverrides, method)) {
      return methodOverrides[method];
    }

    switch (method) {
      case 'eth_chainId':
        return chainIdHex;
      case 'eth_blockNumber':
        return '0x64';
      case 'eth_getBlockByNumber':
        return block;
      case 'eth_getTransactionCount':
        return '0x1';
      case 'eth_estimateGas':
        if (estimateGasErrorMessage) {
          return {
            error: { code: -32000, message: estimateGasErrorMessage },
          };
        }
        return '0x5208';
      case 'eth_gasPrice':
        return '0x3b9aca00';
      case 'eth_maxPriorityFeePerGas':
        return '0x3b9aca00';
      case 'eth_feeHistory':
        return {
          oldestBlock: '0x63',
          baseFeePerGas: ['0x3b9aca00', '0x3b9aca00'],
          gasUsedRatio: [0.5],
          reward: [['0x3b9aca00']],
        };
      case 'eth_sendRawTransaction':
        return txHash;
      case 'eth_getTransactionReceipt':
        return receipt;
      default:
        return {
          error: { code: -32603, message: `unsupported method: ${method}` },
        };
    }
  };

  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk.toString();
    });
    req.on('end', () => {
      const payload = JSON.parse(body);
      const calls = Array.isArray(payload) ? payload : [payload];
      const responses = calls.map((call) => {
        const result = handleMethod(call.method);
        if (result && typeof result === 'object' && 'error' in result) {
          return {
            jsonrpc: '2.0',
            id: call.id ?? null,
            error: result.error,
          };
        }
        return { jsonrpc: '2.0', id: call.id ?? null, result };
      });

      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(Array.isArray(payload) ? responses : responses[0]));
    });
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(undefined));
  });
  const address = server.address();
  return {
    server,
    rpcUrl: `http://127.0.0.1:${address.port}`,
  };
}

test('agentpay x402 signs EIP-3009 authorizations and retries the request', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });

  const walletAddress = '0x4000000000000000000000000000000000000000';
  const socketServer = await startUnixSocket(socketPath);
  let server = null;

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-agent'),
      [
        'cmd=""',
        'for arg in "$@"; do',
        '  case "$arg" in',
        '    eip3009-transfer-with-authorization)',
        '      cmd="$arg"',
        '      break',
        '      ;;',
        '  esac',
        'done',
        'if [ "$cmd" != "eip3009-transfer-with-authorization" ]; then',
        '  echo "unexpected-command:$cmd" 1>&2',
        '  exit 9',
        'fi',
        'printf "{\\"command\\":\\"eip3009-transfer-with-authorization\\",\\"network\\":\\"8453\\",\\"asset\\":\\"erc20:' +
          TOKEN_ADDRESS +
          '\\",\\"counterparty\\":\\"' +
          RECIPIENT_ADDRESS +
          '\\",\\"amount_wei\\":\\"1000000\\",\\"signature_hex\\":\\"0x11\\"}"',
      ].join('\n'),
    );
    writeExecutable(path.join(rustBinDir, 'agentpay-admin'), 'printf "{}"');

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      agentKeyId: AGENT_KEY_ID,
      wallet: {
        address: walletAddress,
        vaultKeyId: 'vault-key-test',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
      },
    });

    let requestCount = 0;
    const paymentRequired = {
      x402Version: 2,
      resource: {
        url: 'https://api.example.com/paid',
        description: 'paid endpoint',
        mimeType: 'application/json',
      },
      accepts: [
        {
          scheme: 'exact',
          network: 'eip155:8453',
          amount: '1000000',
          asset: TOKEN_ADDRESS,
          payTo: RECIPIENT_ADDRESS,
          maxTimeoutSeconds: 60,
          extra: {
            name: 'USD Coin',
            version: '2',
          },
        },
      ],
    };
    const paymentResponse = {
      success: true,
      payer: walletAddress,
      transaction: '0xsettled',
      network: 'eip155:8453',
    };

    server = http.createServer((req, res) => {
      requestCount += 1;
      if (requestCount === 1) {
        assert.equal(req.headers['payment-signature'], undefined);
        res.statusCode = 402;
        res.setHeader(
          'PAYMENT-REQUIRED',
          Buffer.from(JSON.stringify(paymentRequired), 'utf8').toString('base64'),
        );
        res.end('');
        return;
      }

      const paymentHeader = req.headers['payment-signature'];
      assert.equal(typeof paymentHeader, 'string');
      const paymentPayload = JSON.parse(Buffer.from(paymentHeader, 'base64').toString('utf8'));
      assert.equal(paymentPayload.accepted.amount, '1000000');
      assert.equal(
        paymentPayload.payload.authorization.from.toLowerCase(),
        walletAddress.toLowerCase(),
      );
      assert.equal(
        paymentPayload.payload.authorization.to.toLowerCase(),
        RECIPIENT_ADDRESS.toLowerCase(),
      );
      assert.equal(paymentPayload.payload.signature, '0x11');

      res.statusCode = 200;
      res.setHeader(
        'PAYMENT-RESPONSE',
        Buffer.from(JSON.stringify(paymentResponse), 'utf8').toString('base64'),
      );
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ ok: true }));
    });

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve(undefined));
    });
    const address = server.address();
    const url = `http://127.0.0.1:${address.port}/paid`;

    const result = await runCliAsync(
      [
        'x402',
        url,
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'test-agent-auth-token',
        '--allow-legacy-agent-auth-source',
        '--daemon-socket',
        socketPath,
        '--json',
      ],
      { homeDir },
    );

    assert.equal(result.status, 0, combinedOutput(result));
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.protocol, 'x402');
    assert.equal(parsed.status, 200);
    assert.deepEqual(parsed.body, { ok: true });
    assert.equal(parsed.payment.transaction, '0xsettled');
    assert.equal(requestCount, 2);
  } finally {
    await closeServer(server);
    await closeServer(socketServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('agentpay x402 preserves POST requests, custom headers, and JSON bodies', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });

  const walletAddress = '0x4000000000000000000000000000000000000000';
  const expectedRequestBody = JSON.stringify({ prompt: 'hello x402' });
  const socketServer = await startUnixSocket(socketPath);
  const proxyServer = await startForwardProxyServer();
  let server = null;

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-agent'),
      [
        'cmd=""',
        'for arg in "$@"; do',
        '  case "$arg" in',
        '    eip3009-transfer-with-authorization)',
        '      cmd="$arg"',
        '      break',
        '      ;;',
        '  esac',
        'done',
        'if [ "$cmd" != "eip3009-transfer-with-authorization" ]; then',
        '  echo "unexpected-command:$cmd" 1>&2',
        '  exit 9',
        'fi',
        'printf "{\\"command\\":\\"eip3009-transfer-with-authorization\\",\\"network\\":\\"8453\\",\\"asset\\":\\"erc20:' +
          TOKEN_ADDRESS +
          '\\",\\"counterparty\\":\\"' +
          RECIPIENT_ADDRESS +
          '\\",\\"amount_wei\\":\\"1000000\\",\\"signature_hex\\":\\"0x11\\"}"',
      ].join('\n'),
    );
    writeExecutable(path.join(rustBinDir, 'agentpay-admin'), 'printf "{}"');

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      agentKeyId: AGENT_KEY_ID,
      wallet: {
        address: walletAddress,
        vaultKeyId: 'vault-key-test',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
      },
    });

    let requestCount = 0;
    const paymentRequired = {
      x402Version: 2,
      resource: {
        url: 'https://api.example.com/paid-post',
        description: 'paid post endpoint',
        mimeType: 'application/json',
      },
      accepts: [
        {
          scheme: 'exact',
          network: 'eip155:8453',
          amount: '1000000',
          asset: TOKEN_ADDRESS,
          payTo: RECIPIENT_ADDRESS,
          maxTimeoutSeconds: 60,
          extra: {
            name: 'USD Coin',
            version: '2',
          },
        },
      ],
    };

    server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => {
        body += chunk.toString();
      });
      req.on('end', () => {
        requestCount += 1;
        assert.equal(req.method, 'POST');
        assert.equal(req.headers['content-type'], 'application/json');
        assert.equal(req.headers['x-client-test'], '1');
        assert.equal(body, expectedRequestBody);

        if (requestCount === 1) {
          assert.equal(req.headers['payment-signature'], undefined);
          res.statusCode = 402;
          res.setHeader(
            'PAYMENT-REQUIRED',
            Buffer.from(JSON.stringify(paymentRequired), 'utf8').toString('base64'),
          );
          res.end('');
          return;
        }

        const paymentHeader = req.headers['payment-signature'];
        assert.equal(typeof paymentHeader, 'string');
        const paymentPayload = JSON.parse(Buffer.from(paymentHeader, 'base64').toString('utf8'));
        assert.equal(paymentPayload.accepted.amount, '1000000');
        assert.equal(
          paymentPayload.payload.authorization.from.toLowerCase(),
          walletAddress.toLowerCase(),
        );
        assert.equal(
          paymentPayload.payload.authorization.to.toLowerCase(),
          RECIPIENT_ADDRESS.toLowerCase(),
        );
        assert.equal(paymentPayload.payload.signature, '0x11');

        res.statusCode = 200;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ ok: true, method: req.method }));
      });
    });

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve(undefined));
    });
    const address = server.address();
    const url = `http://example.test:${address.port}/paid-post`;

    const result = await runCliAsync(
      [
        'x402',
        url,
        '--method',
        'POST',
        '--header',
        'X-Client-Test: 1',
        '--json-body',
        expectedRequestBody,
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'test-agent-auth-token',
        '--allow-legacy-agent-auth-source',
        '--daemon-socket',
        socketPath,
        '--json',
      ],
      {
        homeDir,
        env: {
          HTTP_PROXY: proxyServer.proxyUrl,
          NO_PROXY: '',
        },
      },
    );

    assert.equal(result.status, 0, combinedOutput(result));
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.protocol, 'x402');
    assert.equal(parsed.status, 200);
    assert.deepEqual(parsed.body, { ok: true, method: 'POST' });
    assert.equal(requestCount, 2);
    assert.equal(proxyServer.getProxyHits() > 0, true);
  } finally {
    await closeServer(server);
    await closeServer(proxyServer.server);
    await closeServer(socketServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('agentpay x402 supports legacy v1 exact EVM payment challenges', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });

  const walletAddress = '0x4000000000000000000000000000000000000000';
  const socketServer = await startUnixSocket(socketPath);
  let server = null;

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-agent'),
      [
        'cmd=""',
        'for arg in "$@"; do',
        '  case "$arg" in',
        '    eip3009-transfer-with-authorization)',
        '      cmd="$arg"',
        '      break',
        '      ;;',
        '  esac',
        'done',
        'if [ "$cmd" != "eip3009-transfer-with-authorization" ]; then',
        '  echo "unexpected-command:$cmd" 1>&2',
        '  exit 9',
        'fi',
        'printf "{\\"command\\":\\"eip3009-transfer-with-authorization\\",\\"network\\":\\"8453\\",\\"asset\\":\\"erc20:' +
          TOKEN_ADDRESS +
          '\\",\\"counterparty\\":\\"' +
          RECIPIENT_ADDRESS +
          '\\",\\"amount_wei\\":\\"1000000\\",\\"signature_hex\\":\\"0x11\\"}"',
      ].join('\n'),
    );
    writeExecutable(path.join(rustBinDir, 'agentpay-admin'), 'printf "{}"');

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      agentKeyId: AGENT_KEY_ID,
      wallet: {
        address: walletAddress,
        vaultKeyId: 'vault-key-test',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
      },
    });

    let requestCount = 0;
    const paymentRequired = {
      x402Version: 1,
      accepts: [
        {
          scheme: 'exact',
          network: 'base',
          maxAmountRequired: '1000000',
          resource: 'https://api.example.com/paid-v1',
          description: 'legacy paid endpoint',
          mimeType: 'application/json',
          payTo: RECIPIENT_ADDRESS,
          maxTimeoutSeconds: 60,
          asset: TOKEN_ADDRESS,
          extra: {
            name: 'USD Coin',
            version: '2',
          },
        },
      ],
    };

    server = http.createServer((req, res) => {
      requestCount += 1;
      if (requestCount === 1) {
        assert.equal(req.headers['x-payment'], undefined);
        res.statusCode = 402;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify(paymentRequired));
        return;
      }

      const paymentHeader = req.headers['x-payment'];
      assert.equal(typeof paymentHeader, 'string');
      const paymentPayload = JSON.parse(Buffer.from(paymentHeader, 'base64').toString('utf8'));
      assert.equal(paymentPayload.x402Version, 1);
      assert.equal(paymentPayload.scheme, 'exact');
      assert.equal(paymentPayload.network, 'base');
      assert.equal(
        paymentPayload.payload.authorization.from.toLowerCase(),
        walletAddress.toLowerCase(),
      );
      assert.equal(
        paymentPayload.payload.authorization.to.toLowerCase(),
        RECIPIENT_ADDRESS.toLowerCase(),
      );
      assert.equal(paymentPayload.payload.signature, '0x11');

      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ ok: true, version: 1 }));
    });

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve(undefined));
    });
    const address = server.address();
    const url = `http://127.0.0.1:${address.port}/paid-v1`;

    const result = await runCliAsync(
      [
        'x402',
        url,
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'test-agent-auth-token',
        '--allow-legacy-agent-auth-source',
        '--daemon-socket',
        socketPath,
        '--json',
      ],
      { homeDir },
    );

    assert.equal(result.status, 0, combinedOutput(result));
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.protocol, 'x402');
    assert.equal(parsed.status, 200);
    assert.deepEqual(parsed.body, { ok: true, version: 1 });
    assert.equal(requestCount, 2);
  } finally {
    await closeServer(server);
    await closeServer(socketServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('agentpay mpp preserves POST requests, accepts zero-priority fee estimates, broadcasts a Tempo charge, and decodes the receipt', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });

  const account = privateKeyToAccount(
    '0x59c6995e998f97a5a0044966f094538f5f4e0e46f95cebf7f5f88f5f2b5b9f10',
  );
  const walletAddress = account.address;
  const expectedRequestBody = JSON.stringify({ prompt: 'hello' });
  const challengeMemo = '0xef1ed71201000000000000000000000000000000000000000000000000000000';
  const transferCall = TempoActions.token.transfer.call({
    token: TOKEN_ADDRESS,
    to: RECIPIENT_ADDRESS,
    amount: 1_000_000n,
    memo: challengeMemo,
  });
  const rawTx = await account.signTransaction({
    chainId: 4217,
    nonce: 1,
    to: transferCall.to,
    gas: 21_000n,
    maxFeePerGas: 1_200_000_000n,
    maxPriorityFeePerGas: 0n,
    value: 0n,
    data: transferCall.data,
    type: 'eip1559',
  });
  const txHash = keccak256(rawTx);

  const socketServer = await startUnixSocket(socketPath);
  const { server: rpcServer, rpcUrl } = await startMockRpcServer({
    chainId: 4217,
    txHash,
    from: walletAddress,
    to: transferCall.to,
    methodOverrides: {
      eth_gasPrice: '0x0',
      eth_maxPriorityFeePerGas: '0x0',
      eth_feeHistory: {
        oldestBlock: '0x63',
        baseFeePerGas: ['0x3b9aca00', '0x3b9aca00'],
        gasUsedRatio: [0.5],
        reward: [['0x0']],
      },
    },
  });
  let server = null;

  try {
    const estimatedFees = await estimateFees(rpcUrl);
    assert.equal(estimatedFees.maxFeePerGas, 1_200_000_000n);
    assert.equal(estimatedFees.maxPriorityFeePerGas, 0n);

    writeExecutable(
      path.join(rustBinDir, 'agentpay-agent'),
      [
        'cmd=""',
        'for arg in "$@"; do',
        '  case "$arg" in',
        '    broadcast)',
        '      cmd="$arg"',
        '      break',
        '      ;;',
        '  esac',
        'done',
        'if [ "$cmd" != "broadcast" ]; then',
        '  echo "unexpected-command:$cmd" 1>&2',
        '  exit 9',
        'fi',
        'printf "{\\"command\\":\\"broadcast\\",\\"signature_hex\\":\\"0x11\\",\\"raw_tx_hex\\":\\"' +
          rawTx +
          '\\",\\"tx_hash_hex\\":\\"' +
          txHash +
          '\\"}"',
      ].join('\n'),
    );
    writeExecutable(path.join(rustBinDir, 'agentpay-admin'), 'printf "{}"');

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      agentKeyId: AGENT_KEY_ID,
      wallet: {
        address: walletAddress,
        vaultKeyId: 'vault-key-test',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
      },
    });

    let requestCount = 0;
    const challengeRequest = {
      amount: '1000000',
      currency: TOKEN_ADDRESS,
      recipient: RECIPIENT_ADDRESS,
      decimals: 6,
      methodDetails: {
        chainId: 4217,
        memo: challengeMemo,
      },
    };
    const challengeHeader = `Payment ${[
      'id="challenge-123"',
      'realm="api.example.com"',
      'method="tempo"',
      'intent="charge"',
      `request="${Buffer.from(JSON.stringify(challengeRequest), 'utf8').toString('base64url')}"`,
    ].join(', ')}`;
    const paymentReceipt = {
      method: 'tempo',
      intent: 'charge',
      status: 'success',
      timestamp: '2026-03-22T00:00:00.000Z',
      reference: txHash,
      txHash,
    };
    const paymentReceiptHeader = Buffer.from(JSON.stringify(paymentReceipt), 'utf8').toString(
      'base64url',
    );

    server = http.createServer((req, res) => {
      let _body = '';
      req.on('data', (chunk) => {
        _body += chunk.toString();
      });
      req.on('end', () => {
        requestCount += 1;
        assert.equal(req.method, 'POST');
        assert.equal(req.headers['content-type'], 'application/json');
        assert.equal(req.headers['x-client-test'], '1');
        assert.equal(_body, expectedRequestBody);

        if (requestCount === 1) {
          assert.equal(req.headers.authorization, undefined);
          res.statusCode = 402;
          res.setHeader('WWW-Authenticate', challengeHeader);
          res.end('');
          return;
        }

        const authHeader = req.headers.authorization;
        assert.equal(typeof authHeader, 'string');
        const encoded = authHeader.replace(/^Payment\s+/u, '');
        const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
        assert.equal(parsed.payload.type, 'hash');
        assert.equal(parsed.payload.hash, txHash);
        assert.equal(parsed.challenge.id, 'challenge-123');

        res.statusCode = 200;
        res.setHeader('Payment-Receipt', paymentReceiptHeader);
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ ok: true }));
      });
    });

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve(undefined));
    });
    const address = server.address();
    const url = `http://127.0.0.1:${address.port}/mpp`;

    const result = await runCliAsync(
      [
        'mpp',
        url,
        '--amount',
        '1',
        '--header',
        'X-Client-Test: 1',
        '--json-body',
        expectedRequestBody,
        '--rpc-url',
        rpcUrl,
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'test-agent-auth-token',
        '--allow-legacy-agent-auth-source',
        '--daemon-socket',
        socketPath,
        '--json',
      ],
      { homeDir },
    );

    assert.equal(result.status, 0, combinedOutput(result));
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.protocol, 'mpp');
    assert.equal(parsed.status, 200);
    assert.deepEqual(parsed.body, { ok: true });
    assert.equal(parsed.payment.txHash, txHash);
    assert.equal(parsed.payment.receipt.reference, txHash);
    assert.equal(parsed.payment.receipt.txHash, txHash);
    assert.equal(parsed.payment.receipt.intent, 'charge');
    assert.equal(requestCount, 2);
  } finally {
    await closeServer(server);
    await closeServer(rpcServer);
    await closeServer(socketServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('agentpay mpp opens and closes a one-shot Tempo session request', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });

  const account = privateKeyToAccount(
    '0x59c6995e998f97a5a0044966f094538f5f4e0e46f95cebf7f5f88f5f2b5b9f10',
  );
  const walletAddress = account.address;
  const openSignatureHex = await account.sign({
    hash: `0x${'1'.repeat(64)}`,
  });
  const voucherSignatureHex = await account.sign({
    hash: `0x${'2'.repeat(64)}`,
  });
  const openSignatureArtifacts = recoverableSignatureArtifacts(openSignatureHex, '0x30aa');
  const voucherSignatureArtifacts = recoverableSignatureArtifacts(voucherSignatureHex, '0x30bb');
  const expectedRequestBody = JSON.stringify({ prompt: 'session' });
  const escrowContract = '0x33b901018174DDabE4841042ab76ba85D4e24f25';

  const socketServer = await startUnixSocket(socketPath);
  const { server: rpcServer, rpcUrl } = await startMockRpcServer({
    chainId: 4217,
    txHash: `0x${'9'.repeat(64)}`,
    from: walletAddress,
    to: TOKEN_ADDRESS,
  });
  let server = null;

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-agent'),
      [
        'cmd=""',
        'for arg in "$@"; do',
        '  case "$arg" in',
        '    tempo-session-open-transaction|tempo-session-voucher)',
        '      cmd="$arg"',
        '      break',
        '      ;;',
        '  esac',
        'done',
        'case "$cmd" in',
        '  tempo-session-open-transaction)',
        '    printf "{\\"command\\":\\"tempo-session-open-transaction\\",\\"network\\":\\"4217\\",\\"asset\\":\\"erc20:' +
          TOKEN_ADDRESS +
          '\\",\\"counterparty\\":\\"' +
          RECIPIENT_ADDRESS +
          '\\",\\"amount_wei\\":\\"1000000\\",\\"signature_hex\\":\\"' +
          openSignatureArtifacts.signatureHex +
          '\\",\\"r_hex\\":\\"' +
          openSignatureArtifacts.rHex +
          '\\",\\"s_hex\\":\\"' +
          openSignatureArtifacts.sHex +
          '\\",\\"v\\":' +
          String(openSignatureArtifacts.v) +
          '}"',
        '    ;;',
        '  tempo-session-voucher)',
        '    printf "{\\"command\\":\\"tempo-session-voucher\\",\\"network\\":\\"4217\\",\\"asset\\":\\"erc20:' +
          TOKEN_ADDRESS +
          '\\",\\"counterparty\\":\\"' +
          RECIPIENT_ADDRESS +
          '\\",\\"amount_wei\\":\\"1000000\\",\\"signature_hex\\":\\"' +
          voucherSignatureArtifacts.signatureHex +
          '\\",\\"r_hex\\":\\"' +
          voucherSignatureArtifacts.rHex +
          '\\",\\"s_hex\\":\\"' +
          voucherSignatureArtifacts.sHex +
          '\\",\\"v\\":' +
          String(voucherSignatureArtifacts.v) +
          '}"',
        '    ;;',
        '  *)',
        '    echo "unexpected-command:$cmd" 1>&2',
        '    exit 9',
        '    ;;',
        'esac',
      ].join('\n'),
    );
    writeExecutable(path.join(rustBinDir, 'agentpay-admin'), 'printf "{}"');

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      agentKeyId: AGENT_KEY_ID,
      wallet: {
        address: walletAddress,
        vaultKeyId: 'vault-key-test',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
      },
    });

    let requestCount = 0;
    let openedChannelId = null;
    const challengeRequest = {
      amount: '1000000',
      currency: TOKEN_ADDRESS,
      recipient: RECIPIENT_ADDRESS,
      decimals: 6,
      methodDetails: {
        chainId: 4217,
        escrowContract,
      },
    };
    const challengeHeader = `Payment ${[
      'id="session-challenge-123"',
      'realm="api.example.com"',
      'method="tempo"',
      'intent="session"',
      `request="${Buffer.from(JSON.stringify(challengeRequest), 'utf8').toString('base64url')}"`,
    ].join(', ')}`;

    server = http.createServer((req, res) => {
      let _body = '';
      req.on('data', (chunk) => {
        _body += chunk.toString();
      });
      req.on('end', () => {
        requestCount += 1;

        if (requestCount === 1) {
          assert.equal(req.method, 'POST');
          assert.equal(req.headers.authorization, undefined);
          assert.equal(req.headers['content-type'], 'application/json');
          assert.equal(req.headers['x-client-test'], 'session');
          assert.equal(_body, expectedRequestBody);
          res.statusCode = 402;
          res.setHeader('WWW-Authenticate', challengeHeader);
          res.end('');
          return;
        }

        const authHeader = req.headers.authorization;
        assert.equal(typeof authHeader, 'string');
        const encoded = authHeader.replace(/^Payment\s+/u, '');
        const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));

        if (requestCount === 2) {
          assert.equal(req.method, 'POST');
          assert.equal(req.headers['content-type'], 'application/json');
          assert.equal(req.headers['x-client-test'], 'session');
          assert.equal(_body, expectedRequestBody);
          assert.equal(parsed.payload.action, 'open');
          assert.equal(parsed.payload.signature, voucherSignatureHex);
          assert.equal(parsed.challenge.id, 'session-challenge-123');
          const tx = TempoTransaction.deserialize(parsed.payload.transaction);
          assert.equal(Array.isArray(tx.calls), true);
          assert.equal(tx.calls.length, 2);
          assert.equal(tx.calls[0].to.toLowerCase(), TOKEN_ADDRESS.toLowerCase());
          assert.equal(tx.calls[1].to.toLowerCase(), escrowContract.toLowerCase());
          openedChannelId = parsed.payload.channelId;
          const paymentReceipt = {
            method: 'tempo',
            intent: 'session',
            status: 'success',
            timestamp: '2026-03-22T00:00:00.000Z',
            reference: openedChannelId,
            challengeId: 'session-challenge-123',
            channelId: openedChannelId,
            acceptedCumulative: '1000000',
            spent: '1000000',
            units: 1,
          };
          res.statusCode = 200;
          res.setHeader(
            'Payment-Receipt',
            Buffer.from(JSON.stringify(paymentReceipt), 'utf8').toString('base64url'),
          );
          res.setHeader('content-type', 'application/json');
          res.end(JSON.stringify({ ok: true, session: 'opened' }));
          return;
        }

        assert.equal(requestCount, 3);
        assert.equal(req.method, 'POST');
        assert.equal(req.headers['x-client-test'], undefined);
        assert.equal(_body, '');
        assert.equal(parsed.payload.action, 'close');
        assert.equal(parsed.payload.channelId, openedChannelId);
        assert.equal(parsed.payload.cumulativeAmount, '1000000');
        const closeReceipt = {
          method: 'tempo',
          intent: 'session',
          status: 'success',
          timestamp: '2026-03-22T00:00:01.000Z',
          reference: openedChannelId,
          challengeId: 'session-challenge-123',
          channelId: openedChannelId,
          acceptedCumulative: '1000000',
          spent: '1000000',
          units: 1,
        };
        res.statusCode = 200;
        res.setHeader(
          'Payment-Receipt',
          Buffer.from(JSON.stringify(closeReceipt), 'utf8').toString('base64url'),
        );
        res.end('');
      });
    });

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve(undefined));
    });
    const address = server.address();
    const url = `http://127.0.0.1:${address.port}/mpp-session`;

    const result = await runCliAsync(
      [
        'mpp',
        url,
        '--amount',
        '1',
        '--header',
        'X-Client-Test: session',
        '--json-body',
        expectedRequestBody,
        '--rpc-url',
        rpcUrl,
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'test-agent-auth-token',
        '--allow-legacy-agent-auth-source',
        '--daemon-socket',
        socketPath,
        '--json',
      ],
      { homeDir },
    );

    assert.equal(result.status, 0, combinedOutput(result));
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.protocol, 'mpp');
    assert.equal(parsed.status, 200);
    assert.deepEqual(parsed.body, { ok: true, session: 'opened' });
    assert.equal(parsed.payment.intent, 'session');
    assert.equal(parsed.payment.channelId, openedChannelId);
    assert.equal(parsed.payment.receipt.channelId, openedChannelId);
    assert.equal(parsed.payment.closeReceipt.channelId, openedChannelId);
    assert.equal(requestCount, 3);
  } finally {
    await closeServer(server);
    await closeServer(rpcServer);
    await closeServer(socketServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('agentpay mpp reports required amount details when a Tempo session open lacks balance', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });

  const walletAddress = '0x4000000000000000000000000000000000000000';
  const escrowContract = '0x33b901018174DDabE4841042ab76ba85D4e24f25';
  const socketServer = await startUnixSocket(socketPath);
  const { server: rpcServer, rpcUrl } = await startMockRpcServer({
    chainId: 4217,
    txHash: `0x${'8'.repeat(64)}`,
    from: walletAddress,
    to: TOKEN_ADDRESS,
    estimateGasErrorMessage: 'insufficient funds for gas * price + value',
  });
  let server = null;

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-agent'),
      'echo "unexpected-agent-invocation" 1>&2\nexit 9',
    );
    writeExecutable(path.join(rustBinDir, 'agentpay-admin'), 'printf "{}"');

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      agentKeyId: AGENT_KEY_ID,
      wallet: {
        address: walletAddress,
        vaultKeyId: 'vault-key-test',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
      },
    });

    let requestCount = 0;
    const challengeRequest = {
      amount: '1000000',
      suggestedDeposit: '2500000',
      currency: TOKEN_ADDRESS,
      recipient: RECIPIENT_ADDRESS,
      decimals: 6,
      methodDetails: {
        chainId: 4217,
        escrowContract,
      },
    };
    const challengeHeader = `Payment ${[
      'id="session-insufficient-open"',
      'realm="api.example.com"',
      'method="tempo"',
      'intent="session"',
      `request="${Buffer.from(JSON.stringify(challengeRequest), 'utf8').toString('base64url')}"`,
    ].join(', ')}`;

    server = http.createServer((req, res) => {
      req.resume();
      req.on('end', () => {
        requestCount += 1;
        assert.equal(requestCount, 1);
        res.statusCode = 402;
        res.setHeader('WWW-Authenticate', challengeHeader);
        res.end('');
      });
    });

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve(undefined));
    });
    const address = server.address();
    const url = `http://127.0.0.1:${address.port}/mpp-session-insufficient-open`;

    const result = await runCliAsync(
      [
        'mpp',
        url,
        '--amount',
        '1',
        '--rpc-url',
        rpcUrl,
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'test-agent-auth-token',
        '--allow-legacy-agent-auth-source',
        '--daemon-socket',
        socketPath,
      ],
      { homeDir },
    );

    const output = combinedOutput(result);
    assert.equal(result.status, 1, output);
    assert.match(
      output,
      /tempo\/session open could not be prepared because the wallet balance is insufficient\./u,
    );
    assert.match(output, /required payment amount: 1 /u);
    assert.match(output, /required session deposit: 2\.5 /u);
    assert.match(output, /underlying error:/u);
    assert.match(output, /exceeds the balance of the account|insufficient funds/iu);
    assert.equal(requestCount, 1);
  } finally {
    await closeServer(server);
    await closeServer(rpcServer);
    await closeServer(socketServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('agentpay mpp reuses persisted Tempo session state and closes it on demand', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  const sessionStatePath = path.join(agentpayHome, 'tempo-session.json');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });

  const account = privateKeyToAccount(
    '0x59c6995e998f97a5a0044966f094538f5f4e0e46f95cebf7f5f88f5f2b5b9f10',
  );
  const walletAddress = account.address;
  const openSignatureHex = await account.sign({
    hash: `0x${'4'.repeat(64)}`,
  });
  const voucherSignatureHex = await account.sign({
    hash: `0x${'5'.repeat(64)}`,
  });
  const expectedRequestBody = JSON.stringify({ prompt: 'reuse' });
  const escrowContract = '0x33b901018174DDabE4841042ab76ba85D4e24f25';

  const socketServer = await startUnixSocket(socketPath);
  const { server: rpcServer, rpcUrl } = await startMockRpcServer({
    chainId: 4217,
    txHash: `0x${'8'.repeat(64)}`,
    from: walletAddress,
    to: TOKEN_ADDRESS,
  });
  let server = null;

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-agent'),
      [
        'cmd=""',
        'for arg in "$@"; do',
        '  case "$arg" in',
        '    tempo-session-open-transaction|tempo-session-voucher)',
        '      cmd="$arg"',
        '      break',
        '      ;;',
        '  esac',
        'done',
        'case "$cmd" in',
        '  tempo-session-open-transaction)',
        '    printf "{\\"command\\":\\"tempo-session-open-transaction\\",\\"network\\":\\"4217\\",\\"asset\\":\\"erc20:' +
          TOKEN_ADDRESS +
          '\\",\\"counterparty\\":\\"' +
          RECIPIENT_ADDRESS +
          '\\",\\"amount_wei\\":\\"1000000\\",\\"signature_hex\\":\\"' +
          openSignatureHex +
          '\\"}"',
        '    ;;',
        '  tempo-session-voucher)',
        '    printf "{\\"command\\":\\"tempo-session-voucher\\",\\"network\\":\\"4217\\",\\"asset\\":\\"erc20:' +
          TOKEN_ADDRESS +
          '\\",\\"counterparty\\":\\"' +
          RECIPIENT_ADDRESS +
          '\\",\\"amount_wei\\":\\"1000000\\",\\"signature_hex\\":\\"' +
          voucherSignatureHex +
          '\\"}"',
        '    ;;',
        '  *)',
        '    echo "unexpected-command:$cmd" 1>&2',
        '    exit 9',
        '    ;;',
        'esac',
      ].join('\n'),
    );
    writeExecutable(path.join(rustBinDir, 'agentpay-admin'), 'printf "{}"');

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      agentKeyId: AGENT_KEY_ID,
      wallet: {
        address: walletAddress,
        vaultKeyId: 'vault-key-test',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
      },
    });

    let requestCount = 0;
    let openedChannelId = null;
    const challengeRequest = {
      amount: '1000000',
      currency: TOKEN_ADDRESS,
      recipient: RECIPIENT_ADDRESS,
      decimals: 6,
      methodDetails: {
        chainId: 4217,
        escrowContract,
      },
    };

    server = http.createServer((req, res) => {
      let _body = '';
      req.on('data', (chunk) => {
        _body += chunk.toString();
      });
      req.on('end', () => {
        requestCount += 1;

        if (requestCount === 1) {
          res.statusCode = 402;
          res.setHeader(
            'WWW-Authenticate',
            `Payment ${[
              'id="session-reuse-1"',
              'realm="api.example.com"',
              'method="tempo"',
              'intent="session"',
              `request="${Buffer.from(JSON.stringify(challengeRequest), 'utf8').toString('base64url')}"`,
            ].join(', ')}`,
          );
          res.end('');
          return;
        }

        if (requestCount === 3) {
          res.statusCode = 402;
          res.setHeader(
            'WWW-Authenticate',
            `Payment ${[
              'id="session-reuse-2"',
              'realm="api.example.com"',
              'method="tempo"',
              'intent="session"',
              `request="${Buffer.from(
                JSON.stringify({
                  ...challengeRequest,
                  methodDetails: {
                    ...challengeRequest.methodDetails,
                    channelId: openedChannelId,
                  },
                }),
                'utf8',
              ).toString('base64url')}"`,
            ].join(', ')}`,
          );
          res.end('');
          return;
        }

        const authHeader = req.headers.authorization;
        assert.equal(typeof authHeader, 'string');
        const encoded = authHeader.replace(/^Payment\s+/u, '');
        const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));

        if (requestCount === 2) {
          assert.equal(parsed.payload.action, 'open');
          assert.equal(req.headers['x-client-test'], 'reuse');
          assert.equal(req.headers['content-type'], 'application/json');
          assert.equal(_body, expectedRequestBody);
          const tx = TempoTransaction.deserialize(parsed.payload.transaction);
          assert.equal(tx.calls.length, 2);
          openedChannelId = parsed.payload.channelId;
          const paymentReceipt = {
            method: 'tempo',
            intent: 'session',
            status: 'success',
            timestamp: '2026-03-22T00:00:00.000Z',
            reference: openedChannelId,
            challengeId: 'session-reuse-1',
            channelId: openedChannelId,
            acceptedCumulative: '1000000',
            spent: '1000000',
            units: 1,
          };
          res.statusCode = 200;
          res.setHeader(
            'Payment-Receipt',
            Buffer.from(JSON.stringify(paymentReceipt), 'utf8').toString('base64url'),
          );
          res.setHeader('content-type', 'application/json');
          res.end(JSON.stringify({ ok: true, phase: 'opened' }));
          return;
        }

        if (requestCount === 4) {
          assert.equal(parsed.payload.action, 'voucher');
          assert.equal(parsed.payload.channelId, openedChannelId);
          assert.equal(parsed.payload.cumulativeAmount, '2000000');
          assert.equal(req.headers['x-client-test'], 'reuse');
          assert.equal(req.headers['content-type'], 'application/json');
          assert.equal(_body, expectedRequestBody);
          const paymentReceipt = {
            method: 'tempo',
            intent: 'session',
            status: 'success',
            timestamp: '2026-03-22T00:00:01.000Z',
            reference: openedChannelId,
            challengeId: 'session-reuse-2',
            channelId: openedChannelId,
            acceptedCumulative: '2000000',
            spent: '2000000',
            units: 2,
          };
          res.statusCode = 200;
          res.setHeader(
            'Payment-Receipt',
            Buffer.from(JSON.stringify(paymentReceipt), 'utf8').toString('base64url'),
          );
          res.setHeader('content-type', 'application/json');
          res.end(JSON.stringify({ ok: true, phase: 'reused' }));
          return;
        }

        assert.equal(requestCount, 5);
        assert.equal(parsed.payload.action, 'close');
        assert.equal(parsed.payload.channelId, openedChannelId);
        assert.equal(parsed.payload.cumulativeAmount, '2000000');
        assert.equal(req.headers['x-client-test'], undefined);
        assert.equal(_body, '');
        const closeReceipt = {
          method: 'tempo',
          intent: 'session',
          status: 'success',
          timestamp: '2026-03-22T00:00:02.000Z',
          reference: openedChannelId,
          challengeId: 'session-reuse-2',
          channelId: openedChannelId,
          acceptedCumulative: '2000000',
          spent: '2000000',
          units: 2,
        };
        res.statusCode = 200;
        res.setHeader(
          'Payment-Receipt',
          Buffer.from(JSON.stringify(closeReceipt), 'utf8').toString('base64url'),
        );
        res.end('');
      });
    });

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve(undefined));
    });
    const address = server.address();
    const url = `http://127.0.0.1:${address.port}/mpp-session-reuse`;

    const first = await runCliAsync(
      [
        'mpp',
        url,
        '--amount',
        '1',
        '--deposit',
        '2',
        '--session-state-file',
        sessionStatePath,
        '--header',
        'X-Client-Test: reuse',
        '--json-body',
        expectedRequestBody,
        '--rpc-url',
        rpcUrl,
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'test-agent-auth-token',
        '--allow-legacy-agent-auth-source',
        '--daemon-socket',
        socketPath,
        '--json',
      ],
      { homeDir },
    );
    assert.equal(first.status, 0, combinedOutput(first));
    const firstParsed = JSON.parse(first.stdout);
    assert.equal(firstParsed.payment.channelId, openedChannelId);
    assert.equal(firstParsed.payment.closeReceipt, null);
    assert.equal(fs.existsSync(sessionStatePath), true);
    const persisted = JSON.parse(fs.readFileSync(sessionStatePath, 'utf8'));
    assert.equal(persisted.channelId, openedChannelId);
    assert.equal(persisted.depositWei, '2000000');
    assert.equal(persisted.cumulativeAmountWei, '1000000');

    const second = await runCliAsync(
      [
        'mpp',
        url,
        '--amount',
        '1',
        '--session-state-file',
        sessionStatePath,
        '--close-session',
        '--header',
        'X-Client-Test: reuse',
        '--json-body',
        expectedRequestBody,
        '--rpc-url',
        rpcUrl,
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'test-agent-auth-token',
        '--allow-legacy-agent-auth-source',
        '--daemon-socket',
        socketPath,
        '--json',
      ],
      { homeDir },
    );
    assert.equal(second.status, 0, combinedOutput(second));
    const secondParsed = JSON.parse(second.stdout);
    assert.equal(secondParsed.payment.channelId, openedChannelId);
    assert.equal(secondParsed.payment.receipt.acceptedCumulative, '2000000');
    assert.equal(secondParsed.payment.closeReceipt.channelId, openedChannelId);
    assert.equal(fs.existsSync(sessionStatePath), false);
    assert.equal(requestCount, 5);
  } finally {
    await closeServer(server);
    await closeServer(rpcServer);
    await closeServer(socketServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('agentpay mpp automatically tops up persisted Tempo session state when needed', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  const sessionStatePath = path.join(agentpayHome, 'tempo-session-topup.json');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });

  const account = privateKeyToAccount(
    '0x59c6995e998f97a5a0044966f094538f5f4e0e46f95cebf7f5f88f5f2b5b9f10',
  );
  const walletAddress = account.address;
  const openSignatureHex = await account.sign({
    hash: `0x${'6'.repeat(64)}`,
  });
  const topUpSignatureHex = await account.sign({
    hash: `0x${'7'.repeat(64)}`,
  });
  const voucherSignatureHex = await account.sign({
    hash: `0x${'8'.repeat(64)}`,
  });
  const expectedRequestBody = JSON.stringify({ prompt: 'topup' });
  const escrowContract = '0x33b901018174DDabE4841042ab76ba85D4e24f25';

  const socketServer = await startUnixSocket(socketPath);
  const { server: rpcServer, rpcUrl } = await startMockRpcServer({
    chainId: 4217,
    txHash: `0x${'7'.repeat(64)}`,
    from: walletAddress,
    to: TOKEN_ADDRESS,
  });
  let server = null;

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-agent'),
      [
        'cmd=""',
        'for arg in "$@"; do',
        '  case "$arg" in',
        '    tempo-session-open-transaction|tempo-session-top-up-transaction|tempo-session-voucher)',
        '      cmd="$arg"',
        '      break',
        '      ;;',
        '  esac',
        'done',
        'case "$cmd" in',
        '  tempo-session-open-transaction)',
        '    printf "{\\"command\\":\\"tempo-session-open-transaction\\",\\"network\\":\\"4217\\",\\"asset\\":\\"erc20:' +
          TOKEN_ADDRESS +
          '\\",\\"counterparty\\":\\"' +
          RECIPIENT_ADDRESS +
          '\\",\\"amount_wei\\":\\"1000000\\",\\"signature_hex\\":\\"' +
          openSignatureHex +
          '\\"}"',
        '    ;;',
        '  tempo-session-top-up-transaction)',
        '    printf "{\\"command\\":\\"tempo-session-top-up-transaction\\",\\"network\\":\\"4217\\",\\"asset\\":\\"erc20:' +
          TOKEN_ADDRESS +
          '\\",\\"counterparty\\":\\"' +
          RECIPIENT_ADDRESS +
          '\\",\\"amount_wei\\":\\"1000000\\",\\"signature_hex\\":\\"' +
          topUpSignatureHex +
          '\\"}"',
        '    ;;',
        '  tempo-session-voucher)',
        '    printf "{\\"command\\":\\"tempo-session-voucher\\",\\"network\\":\\"4217\\",\\"asset\\":\\"erc20:' +
          TOKEN_ADDRESS +
          '\\",\\"counterparty\\":\\"' +
          RECIPIENT_ADDRESS +
          '\\",\\"amount_wei\\":\\"1000000\\",\\"signature_hex\\":\\"' +
          voucherSignatureHex +
          '\\"}"',
        '    ;;',
        '  *)',
        '    echo "unexpected-command:$cmd" 1>&2',
        '    exit 9',
        '    ;;',
        'esac',
      ].join('\n'),
    );
    writeExecutable(path.join(rustBinDir, 'agentpay-admin'), 'printf "{}"');

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      agentKeyId: AGENT_KEY_ID,
      wallet: {
        address: walletAddress,
        vaultKeyId: 'vault-key-test',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
      },
    });

    let requestCount = 0;
    let openedChannelId = null;
    const challengeRequest = {
      amount: '1000000',
      currency: TOKEN_ADDRESS,
      recipient: RECIPIENT_ADDRESS,
      decimals: 6,
      methodDetails: {
        chainId: 4217,
        escrowContract,
      },
    };

    server = http.createServer((req, res) => {
      let _body = '';
      req.on('data', (chunk) => {
        _body += chunk.toString();
      });
      req.on('end', () => {
        requestCount += 1;

        if (requestCount === 1) {
          res.statusCode = 402;
          res.setHeader(
            'WWW-Authenticate',
            `Payment ${[
              'id="session-topup-1"',
              'realm="api.example.com"',
              'method="tempo"',
              'intent="session"',
              `request="${Buffer.from(JSON.stringify(challengeRequest), 'utf8').toString('base64url')}"`,
            ].join(', ')}`,
          );
          res.end('');
          return;
        }

        if (requestCount === 3) {
          res.statusCode = 402;
          res.setHeader(
            'WWW-Authenticate',
            `Payment ${[
              'id="session-topup-2"',
              'realm="api.example.com"',
              'method="tempo"',
              'intent="session"',
              `request="${Buffer.from(
                JSON.stringify({
                  ...challengeRequest,
                  methodDetails: {
                    ...challengeRequest.methodDetails,
                    channelId: openedChannelId,
                  },
                }),
                'utf8',
              ).toString('base64url')}"`,
            ].join(', ')}`,
          );
          res.end('');
          return;
        }

        const authHeader = req.headers.authorization;
        assert.equal(typeof authHeader, 'string');
        const encoded = authHeader.replace(/^Payment\s+/u, '');
        const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));

        if (requestCount === 2) {
          assert.equal(parsed.payload.action, 'open');
          assert.equal(req.headers['x-client-test'], 'topup');
          assert.equal(req.headers['content-type'], 'application/json');
          assert.equal(_body, expectedRequestBody);
          openedChannelId = parsed.payload.channelId;
          const paymentReceipt = {
            method: 'tempo',
            intent: 'session',
            status: 'success',
            timestamp: '2026-03-22T00:00:00.000Z',
            reference: openedChannelId,
            challengeId: 'session-topup-1',
            channelId: openedChannelId,
            acceptedCumulative: '1000000',
            spent: '1000000',
            units: 1,
          };
          res.statusCode = 200;
          res.setHeader(
            'Payment-Receipt',
            Buffer.from(JSON.stringify(paymentReceipt), 'utf8').toString('base64url'),
          );
          res.setHeader('content-type', 'application/json');
          res.end(JSON.stringify({ ok: true, phase: 'opened' }));
          return;
        }

        if (requestCount === 4) {
          assert.equal(parsed.payload.action, 'topUp');
          assert.equal(parsed.payload.channelId, openedChannelId);
          assert.equal(parsed.payload.additionalDeposit, '1000000');
          assert.equal(req.method, 'POST');
          assert.equal(_body, '');
          res.statusCode = 204;
          res.end('');
          return;
        }

        assert.equal(requestCount, 5);
        assert.equal(parsed.payload.action, 'voucher');
        assert.equal(parsed.payload.channelId, openedChannelId);
        assert.equal(parsed.payload.cumulativeAmount, '2000000');
        assert.equal(req.headers['x-client-test'], 'topup');
        assert.equal(req.headers['content-type'], 'application/json');
        assert.equal(_body, expectedRequestBody);
        const paymentReceipt = {
          method: 'tempo',
          intent: 'session',
          status: 'success',
          timestamp: '2026-03-22T00:00:01.000Z',
          reference: openedChannelId,
          challengeId: 'session-topup-2',
          channelId: openedChannelId,
          acceptedCumulative: '2000000',
          spent: '2000000',
          units: 2,
        };
        res.statusCode = 200;
        res.setHeader(
          'Payment-Receipt',
          Buffer.from(JSON.stringify(paymentReceipt), 'utf8').toString('base64url'),
        );
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ ok: true, phase: 'topped-up' }));
      });
    });

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve(undefined));
    });
    const address = server.address();
    const url = `http://127.0.0.1:${address.port}/mpp-session-topup`;

    const first = await runCliAsync(
      [
        'mpp',
        url,
        '--amount',
        '1',
        '--session-state-file',
        sessionStatePath,
        '--header',
        'X-Client-Test: topup',
        '--json-body',
        expectedRequestBody,
        '--rpc-url',
        rpcUrl,
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'test-agent-auth-token',
        '--allow-legacy-agent-auth-source',
        '--daemon-socket',
        socketPath,
        '--json',
      ],
      { homeDir },
    );
    assert.equal(first.status, 0, combinedOutput(first));
    assert.equal(fs.existsSync(sessionStatePath), true);
    const persistedAfterFirst = JSON.parse(fs.readFileSync(sessionStatePath, 'utf8'));
    assert.equal(persistedAfterFirst.depositWei, '1000000');
    assert.equal(persistedAfterFirst.cumulativeAmountWei, '1000000');

    const second = await runCliAsync(
      [
        'mpp',
        url,
        '--amount',
        '1',
        '--session-state-file',
        sessionStatePath,
        '--header',
        'X-Client-Test: topup',
        '--json-body',
        expectedRequestBody,
        '--rpc-url',
        rpcUrl,
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'test-agent-auth-token',
        '--allow-legacy-agent-auth-source',
        '--daemon-socket',
        socketPath,
        '--json',
      ],
      { homeDir },
    );
    assert.equal(second.status, 0, combinedOutput(second));
    const secondParsed = JSON.parse(second.stdout);
    assert.equal(secondParsed.payment.channelId, openedChannelId);
    assert.equal(secondParsed.payment.receipt.acceptedCumulative, '2000000');
    assert.equal(secondParsed.payment.closeReceipt, null);
    const persistedAfterSecond = JSON.parse(fs.readFileSync(sessionStatePath, 'utf8'));
    assert.equal(persistedAfterSecond.depositWei, '2000000');
    assert.equal(persistedAfterSecond.cumulativeAmountWei, '2000000');
    assert.equal(requestCount, 5);
  } finally {
    await closeServer(server);
    await closeServer(rpcServer);
    await closeServer(socketServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('agentpay mpp reports required amount details when a Tempo session topUp lacks balance', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  const sessionStatePath = path.join(agentpayHome, 'tempo-session-insufficient-topup.json');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });

  const walletAddress = '0x4000000000000000000000000000000000000000';
  const escrowContract = '0x33b901018174DDabE4841042ab76ba85D4e24f25';
  const channelId = `0x${'1'.repeat(64)}`;
  const socketServer = await startUnixSocket(socketPath);
  const { server: rpcServer, rpcUrl } = await startMockRpcServer({
    chainId: 4217,
    txHash: `0x${'6'.repeat(64)}`,
    from: walletAddress,
    to: TOKEN_ADDRESS,
    estimateGasErrorMessage: 'insufficient funds for gas * price + value',
  });
  let server = null;

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-agent'),
      'echo "unexpected-agent-invocation" 1>&2\nexit 9',
    );
    writeExecutable(path.join(rustBinDir, 'agentpay-admin'), 'printf "{}"');

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      agentKeyId: AGENT_KEY_ID,
      wallet: {
        address: walletAddress,
        vaultKeyId: 'vault-key-test',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
      },
    });
    fs.writeFileSync(
      sessionStatePath,
      `${JSON.stringify(
        {
          version: 1,
          kind: 'tempo_session',
          chainId: 4217,
          rpcUrl,
          escrowContract,
          token: TOKEN_ADDRESS,
          recipient: RECIPIENT_ADDRESS,
          walletAddress,
          channelId,
          depositWei: '1000000',
          cumulativeAmountWei: '1000000',
        },
        null,
        2,
      )}\n`,
    );

    let requestCount = 0;
    const challengeRequest = {
      amount: '1000000',
      currency: TOKEN_ADDRESS,
      recipient: RECIPIENT_ADDRESS,
      decimals: 6,
      methodDetails: {
        chainId: 4217,
        escrowContract,
        channelId,
      },
    };
    const challengeHeader = `Payment ${[
      'id="session-insufficient-topup"',
      'realm="api.example.com"',
      'method="tempo"',
      'intent="session"',
      `request="${Buffer.from(JSON.stringify(challengeRequest), 'utf8').toString('base64url')}"`,
    ].join(', ')}`;

    server = http.createServer((req, res) => {
      req.resume();
      req.on('end', () => {
        requestCount += 1;
        assert.equal(requestCount, 1);
        res.statusCode = 402;
        res.setHeader('WWW-Authenticate', challengeHeader);
        res.end('');
      });
    });

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve(undefined));
    });
    const address = server.address();
    const url = `http://127.0.0.1:${address.port}/mpp-session-insufficient-topup`;

    const result = await runCliAsync(
      [
        'mpp',
        url,
        '--amount',
        '1',
        '--session-state-file',
        sessionStatePath,
        '--rpc-url',
        rpcUrl,
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'test-agent-auth-token',
        '--allow-legacy-agent-auth-source',
        '--daemon-socket',
        socketPath,
      ],
      { homeDir },
    );

    const output = combinedOutput(result);
    assert.equal(result.status, 1, output);
    assert.match(
      output,
      /tempo\/session topUp could not be prepared because the wallet balance is insufficient\./u,
    );
    assert.match(output, /required payment amount: 1 /u);
    assert.match(output, /required additional session deposit: 1 /u);
    assert.match(output, /target session deposit: 2 /u);
    assert.match(output, /required cumulative paid amount: 2 /u);
    assert.match(output, /underlying error:/u);
    assert.equal(requestCount, 1);
  } finally {
    await closeServer(server);
    await closeServer(rpcServer);
    await closeServer(socketServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('agentpay mpp handles payment-need-voucher events during a Tempo session stream', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });

  const account = privateKeyToAccount(
    '0x59c6995e998f97a5a0044966f094538f5f4e0e46f95cebf7f5f88f5f2b5b9f10',
  );
  const walletAddress = account.address;
  const openSignatureHex = await account.sign({
    hash: `0x${'9'.repeat(64)}`,
  });
  const topUpSignatureHex = await account.sign({
    hash: `0x${'a'.repeat(64)}`,
  });
  const voucherSignatureHex = await account.sign({
    hash: `0x${'b'.repeat(64)}`,
  });
  const expectedRequestBody = JSON.stringify({ prompt: 'stream' });
  const escrowContract = '0x33b901018174DDabE4841042ab76ba85D4e24f25';

  const socketServer = await startUnixSocket(socketPath);
  const { server: rpcServer, rpcUrl } = await startMockRpcServer({
    chainId: 4217,
    txHash: `0x${'6'.repeat(64)}`,
    from: walletAddress,
    to: TOKEN_ADDRESS,
  });
  let server = null;

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-agent'),
      [
        'cmd=""',
        'for arg in "$@"; do',
        '  case "$arg" in',
        '    tempo-session-open-transaction|tempo-session-top-up-transaction|tempo-session-voucher)',
        '      cmd="$arg"',
        '      break',
        '      ;;',
        '  esac',
        'done',
        'case "$cmd" in',
        '  tempo-session-open-transaction)',
        '    printf "{\\"command\\":\\"tempo-session-open-transaction\\",\\"network\\":\\"4217\\",\\"asset\\":\\"erc20:' +
          TOKEN_ADDRESS +
          '\\",\\"counterparty\\":\\"' +
          RECIPIENT_ADDRESS +
          '\\",\\"amount_wei\\":\\"1000000\\",\\"signature_hex\\":\\"' +
          openSignatureHex +
          '\\"}"',
        '    ;;',
        '  tempo-session-top-up-transaction)',
        '    printf "{\\"command\\":\\"tempo-session-top-up-transaction\\",\\"network\\":\\"4217\\",\\"asset\\":\\"erc20:' +
          TOKEN_ADDRESS +
          '\\",\\"counterparty\\":\\"' +
          RECIPIENT_ADDRESS +
          '\\",\\"amount_wei\\":\\"1000000\\",\\"signature_hex\\":\\"' +
          topUpSignatureHex +
          '\\"}"',
        '    ;;',
        '  tempo-session-voucher)',
        '    printf "{\\"command\\":\\"tempo-session-voucher\\",\\"network\\":\\"4217\\",\\"asset\\":\\"erc20:' +
          TOKEN_ADDRESS +
          '\\",\\"counterparty\\":\\"' +
          RECIPIENT_ADDRESS +
          '\\",\\"amount_wei\\":\\"1000000\\",\\"signature_hex\\":\\"' +
          voucherSignatureHex +
          '\\"}"',
        '    ;;',
        '  *)',
        '    echo "unexpected-command:$cmd" 1>&2',
        '    exit 9',
        '    ;;',
        'esac',
      ].join('\n'),
    );
    writeExecutable(path.join(rustBinDir, 'agentpay-admin'), 'printf "{}"');

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      agentKeyId: AGENT_KEY_ID,
      wallet: {
        address: walletAddress,
        vaultKeyId: 'vault-key-test',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
      },
    });

    let requestCount = 0;
    let openedChannelId = null;
    let streamResponse = null;
    const challengeRequest = {
      amount: '1000000',
      currency: TOKEN_ADDRESS,
      recipient: RECIPIENT_ADDRESS,
      decimals: 6,
      methodDetails: {
        chainId: 4217,
        escrowContract,
      },
    };

    server = http.createServer((req, res) => {
      let _body = '';
      req.on('data', (chunk) => {
        _body += chunk.toString();
      });
      req.on('end', () => {
        requestCount += 1;

        if (requestCount === 1) {
          res.statusCode = 402;
          res.setHeader(
            'WWW-Authenticate',
            `Payment ${[
              'id="session-stream-1"',
              'realm="api.example.com"',
              'method="tempo"',
              'intent="session"',
              `request="${Buffer.from(JSON.stringify(challengeRequest), 'utf8').toString('base64url')}"`,
            ].join(', ')}`,
          );
          res.end('');
          return;
        }

        const authHeader = req.headers.authorization;
        assert.equal(typeof authHeader, 'string');
        const encoded = authHeader.replace(/^Payment\s+/u, '');
        const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));

        if (requestCount === 2) {
          assert.equal(parsed.payload.action, 'open');
          assert.equal(req.headers['x-client-test'], 'stream');
          assert.equal(req.headers['content-type'], 'application/json');
          assert.equal(_body, expectedRequestBody);
          openedChannelId = parsed.payload.channelId;
          streamResponse = res;
          res.statusCode = 200;
          res.setHeader('content-type', 'text/event-stream');
          res.write('event: message\ndata: hello\n\n');
          res.write(
            `event: payment-need-voucher\ndata: ${JSON.stringify({
              channelId: openedChannelId,
              requiredCumulative: '2000000',
              acceptedCumulative: '1000000',
              deposit: '1000000',
            })}\n\n`,
          );
          return;
        }

        if (requestCount === 3) {
          assert.equal(parsed.payload.action, 'topUp');
          assert.equal(parsed.payload.channelId, openedChannelId);
          assert.equal(parsed.payload.additionalDeposit, '1000000');
          assert.equal(_body, '');
          res.statusCode = 204;
          res.end('');
          return;
        }

        if (requestCount === 4) {
          assert.equal(parsed.payload.action, 'voucher');
          assert.equal(parsed.payload.channelId, openedChannelId);
          assert.equal(parsed.payload.cumulativeAmount, '2000000');
          assert.equal(_body, '');
          res.statusCode = 200;
          res.end('');
          streamResponse.write(
            `event: payment-receipt\ndata: ${JSON.stringify({
              method: 'tempo',
              intent: 'session',
              status: 'success',
              timestamp: '2026-03-22T00:00:01.000Z',
              reference: openedChannelId,
              challengeId: 'session-stream-1',
              channelId: openedChannelId,
              acceptedCumulative: '2000000',
              spent: '2000000',
              units: 2,
            })}\n\n`,
          );
          streamResponse.write('event: message\ndata: world\n\n');
          streamResponse.end();
          return;
        }

        assert.equal(requestCount, 5);
        assert.equal(parsed.payload.action, 'close');
        assert.equal(parsed.payload.channelId, openedChannelId);
        assert.equal(parsed.payload.cumulativeAmount, '2000000');
        assert.equal(_body, '');
        const closeReceipt = {
          method: 'tempo',
          intent: 'session',
          status: 'success',
          timestamp: '2026-03-22T00:00:02.000Z',
          reference: openedChannelId,
          challengeId: 'session-stream-1',
          channelId: openedChannelId,
          acceptedCumulative: '2000000',
          spent: '2000000',
          units: 2,
        };
        res.statusCode = 200;
        res.setHeader(
          'Payment-Receipt',
          Buffer.from(JSON.stringify(closeReceipt), 'utf8').toString('base64url'),
        );
        res.end('');
      });
    });

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve(undefined));
    });
    const address = server.address();
    const url = `http://127.0.0.1:${address.port}/mpp-session-stream`;

    const result = await runCliAsync(
      [
        'mpp',
        url,
        '--amount',
        '1',
        '--header',
        'X-Client-Test: stream',
        '--json-body',
        expectedRequestBody,
        '--rpc-url',
        rpcUrl,
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'test-agent-auth-token',
        '--allow-legacy-agent-auth-source',
        '--daemon-socket',
        socketPath,
      ],
      { homeDir },
    );

    assert.equal(result.status, 0, combinedOutput(result));
    assert.match(result.stdout, /hello/);
    assert.match(result.stdout, /world/);
    assert.equal(requestCount, 5);
  } finally {
    await closeServer(server);
    await closeServer(rpcServer);
    await closeServer(socketServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('agentpay mpp emits NDJSON events for Tempo session streams in --json mode', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });

  const account = privateKeyToAccount(
    '0x59c6995e998f97a5a0044966f094538f5f4e0e46f95cebf7f5f88f5f2b5b9f10',
  );
  const walletAddress = account.address;
  const openSignatureHex = await account.sign({
    hash: `0x${'c'.repeat(64)}`,
  });
  const topUpSignatureHex = await account.sign({
    hash: `0x${'d'.repeat(64)}`,
  });
  const voucherSignatureHex = await account.sign({
    hash: `0x${'e'.repeat(64)}`,
  });
  const expectedRequestBody = JSON.stringify({ prompt: 'stream-json' });
  const escrowContract = '0x33b901018174DDabE4841042ab76ba85D4e24f25';

  const socketServer = await startUnixSocket(socketPath);
  const { server: rpcServer, rpcUrl } = await startMockRpcServer({
    chainId: 4217,
    txHash: `0x${'5'.repeat(64)}`,
    from: walletAddress,
    to: TOKEN_ADDRESS,
  });
  let server = null;

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-agent'),
      [
        'cmd=""',
        'for arg in "$@"; do',
        '  case "$arg" in',
        '    tempo-session-open-transaction|tempo-session-top-up-transaction|tempo-session-voucher)',
        '      cmd="$arg"',
        '      break',
        '      ;;',
        '  esac',
        'done',
        'case "$cmd" in',
        '  tempo-session-open-transaction)',
        '    printf "{\\"command\\":\\"tempo-session-open-transaction\\",\\"network\\":\\"4217\\",\\"asset\\":\\"erc20:' +
          TOKEN_ADDRESS +
          '\\",\\"counterparty\\":\\"' +
          RECIPIENT_ADDRESS +
          '\\",\\"amount_wei\\":\\"1000000\\",\\"signature_hex\\":\\"' +
          openSignatureHex +
          '\\"}"',
        '    ;;',
        '  tempo-session-top-up-transaction)',
        '    printf "{\\"command\\":\\"tempo-session-top-up-transaction\\",\\"network\\":\\"4217\\",\\"asset\\":\\"erc20:' +
          TOKEN_ADDRESS +
          '\\",\\"counterparty\\":\\"' +
          RECIPIENT_ADDRESS +
          '\\",\\"amount_wei\\":\\"1000000\\",\\"signature_hex\\":\\"' +
          topUpSignatureHex +
          '\\"}"',
        '    ;;',
        '  tempo-session-voucher)',
        '    printf "{\\"command\\":\\"tempo-session-voucher\\",\\"network\\":\\"4217\\",\\"asset\\":\\"erc20:' +
          TOKEN_ADDRESS +
          '\\",\\"counterparty\\":\\"' +
          RECIPIENT_ADDRESS +
          '\\",\\"amount_wei\\":\\"1000000\\",\\"signature_hex\\":\\"' +
          voucherSignatureHex +
          '\\"}"',
        '    ;;',
        '  *)',
        '    echo "unexpected-command:$cmd" 1>&2',
        '    exit 9',
        '    ;;',
        'esac',
      ].join('\n'),
    );
    writeExecutable(path.join(rustBinDir, 'agentpay-admin'), 'printf "{}"');

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      agentKeyId: AGENT_KEY_ID,
      wallet: {
        address: walletAddress,
        vaultKeyId: 'vault-key-test',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
      },
    });

    let requestCount = 0;
    let openedChannelId = null;
    let streamResponse = null;
    const challengeRequest = {
      amount: '1000000',
      currency: TOKEN_ADDRESS,
      recipient: RECIPIENT_ADDRESS,
      decimals: 6,
      methodDetails: {
        chainId: 4217,
        escrowContract,
      },
    };

    server = http.createServer((req, res) => {
      let _body = '';
      req.on('data', (chunk) => {
        _body += chunk.toString();
      });
      req.on('end', () => {
        requestCount += 1;

        if (requestCount === 1) {
          res.statusCode = 402;
          res.setHeader(
            'WWW-Authenticate',
            `Payment ${[
              'id="session-stream-json-1"',
              'realm="api.example.com"',
              'method="tempo"',
              'intent="session"',
              `request="${Buffer.from(JSON.stringify(challengeRequest), 'utf8').toString('base64url')}"`,
            ].join(', ')}`,
          );
          res.end('');
          return;
        }

        const authHeader = req.headers.authorization;
        assert.equal(typeof authHeader, 'string');
        const encoded = authHeader.replace(/^Payment\s+/u, '');
        const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));

        if (requestCount === 2) {
          assert.equal(parsed.payload.action, 'open');
          openedChannelId = parsed.payload.channelId;
          streamResponse = res;
          res.statusCode = 200;
          res.setHeader('content-type', 'text/event-stream');
          res.write('event: message\ndata: hello-json\n\n');
          res.write(
            `event: payment-need-voucher\ndata: ${JSON.stringify({
              channelId: openedChannelId,
              requiredCumulative: '2000000',
              acceptedCumulative: '1000000',
              deposit: '1000000',
            })}\n\n`,
          );
          return;
        }

        if (requestCount === 3) {
          assert.equal(parsed.payload.action, 'topUp');
          assert.equal(parsed.payload.channelId, openedChannelId);
          res.statusCode = 204;
          res.end('');
          return;
        }

        if (requestCount === 4) {
          assert.equal(parsed.payload.action, 'voucher');
          assert.equal(parsed.payload.channelId, openedChannelId);
          res.statusCode = 200;
          res.end('');
          streamResponse.write(
            `event: payment-receipt\ndata: ${JSON.stringify({
              method: 'tempo',
              intent: 'session',
              status: 'success',
              timestamp: '2026-03-22T00:00:03.000Z',
              reference: openedChannelId,
              challengeId: 'session-stream-json-1',
              channelId: openedChannelId,
              acceptedCumulative: '2000000',
              spent: '2000000',
              units: 2,
            })}\n\n`,
          );
          streamResponse.write('event: message\ndata: world-json\n\n');
          streamResponse.end();
          return;
        }

        assert.equal(requestCount, 5);
        assert.equal(parsed.payload.action, 'close');
        assert.equal(parsed.payload.channelId, openedChannelId);
        const closeReceipt = {
          method: 'tempo',
          intent: 'session',
          status: 'success',
          timestamp: '2026-03-22T00:00:04.000Z',
          reference: openedChannelId,
          challengeId: 'session-stream-json-1',
          channelId: openedChannelId,
          acceptedCumulative: '2000000',
          spent: '2000000',
          units: 2,
        };
        res.statusCode = 200;
        res.setHeader(
          'Payment-Receipt',
          Buffer.from(JSON.stringify(closeReceipt), 'utf8').toString('base64url'),
        );
        res.end('');
      });
    });

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => resolve(undefined));
    });
    const address = server.address();
    const url = `http://127.0.0.1:${address.port}/mpp-session-stream-json`;

    const result = await runCliAsync(
      [
        'mpp',
        url,
        '--amount',
        '1',
        '--header',
        'X-Client-Test: stream-json',
        '--json-body',
        expectedRequestBody,
        '--rpc-url',
        rpcUrl,
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'test-agent-auth-token',
        '--allow-legacy-agent-auth-source',
        '--daemon-socket',
        socketPath,
        '--json',
      ],
      { homeDir },
    );

    assert.equal(result.status, 0, combinedOutput(result));
    const events = result.stdout
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    assert.equal(events[0].event, 'mppStreamStart');
    assert.equal(events[1].event, 'mppStreamMessage');
    assert.equal(events[1].data, 'hello-json');
    assert.equal(events[2].event, 'mppStreamNeedVoucher');
    assert.equal(events[3].event, 'mppStreamTopUp');
    assert.equal(events[3].depositWei, '2000000');
    assert.equal(events[4].event, 'mppStreamVoucher');
    assert.equal(events[4].cumulativeAmountWei, '2000000');
    assert.equal(events[5].event, 'mppStreamReceipt');
    assert.equal(events[6].event, 'mppStreamMessage');
    assert.equal(events[6].data, 'world-json');
    assert.equal(events.at(-1).event, 'mppStreamEnd');
    assert.equal(events.at(-1).closeReceipt.channelId, openedChannelId);
    assert.equal(requestCount, 5);
  } finally {
    await closeServer(server);
    await closeServer(rpcServer);
    await closeServer(socketServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});
