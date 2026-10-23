import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';
import { keccak256 } from 'viem';

const modulePath = new URL('../packages/rpc/src/index.ts', import.meta.url);

test('createRpcClient rejects insecure remote http rpc urls before building a client', async () => {
  const rpc = await import(modulePath.href + `?case=${Date.now()}-reject-http`);

  let createPublicClientCalled = false;
  let httpCalled = false;
  assert.throws(
    () =>
      rpc.createRpcClient(
        { rpcUrl: 'http://rpc.example' },
        {
          createPublicClient: () => {
            createPublicClientCalled = true;
            return { unexpected: true };
          },
          http: () => {
            httpCalled = true;
            return { unexpected: true };
          },
        },
      ),
    /must use https unless it targets localhost or a loopback address/,
  );
  assert.equal(createPublicClientCalled, false);
  assert.equal(httpCalled, false);
});

test('createRpcClient rejects rpc urls with embedded credentials', async () => {
  const rpc = await import(modulePath.href + `?case=${Date.now()}-reject-credentials`);

  assert.throws(
    () =>
      rpc.createRpcClient(
        { rpcUrl: 'https://user:secret@rpc.example' },
        {
          createPublicClient: () => ({ unexpected: true }),
          http: () => ({ unexpected: true }),
        },
      ),
    /must not include embedded credentials/,
  );
});

test('createRpcClient accepts localhost http endpoints and trims whitespace', async () => {
  const rpc = await import(modulePath.href + `?case=${Date.now()}-localhost-http`);

  const seen = { url: null, transport: null };
  const client = rpc.createRpcClient(
    { rpcUrl: ' http://127.0.0.1:8545 ' },
    {
      createPublicClient: ({ transport }) => {
        seen.transport = transport;
        return { transport };
      },
      http: (url) => {
        seen.url = url;
        return { kind: 'http', url };
      },
    },
  );

  assert.equal(seen.url, 'http://127.0.0.1:8545');
  assert.deepEqual(seen.transport, { kind: 'http', url: 'http://127.0.0.1:8545' });
  assert.deepEqual(client, { transport: { kind: 'http', url: 'http://127.0.0.1:8545' } });
});

async function withJsonRpcServer(respond, fn) {
  const calls = [];
  const server = http.createServer((request, response) => {
    let body = '';
    request.on('data', (chunk) => {
      body += chunk;
    });
    request.on('end', () => {
      const payload = JSON.parse(body);
      calls.push(payload);
      const reply = respond(payload, calls.length);
      response.writeHead(reply.status ?? 200, { 'content-type': 'application/json' });
      response.end(JSON.stringify(reply.body ?? {}));
    });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const rpcUrl = `http://127.0.0.1:${server.address().port}`;
  try {
    return await fn(rpcUrl, calls);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('createBroadcastRpcClient disables transport retries and sets an explicit timeout', async () => {
  const rpc = await import(modulePath.href + `?case=${Date.now()}-broadcast-client`);

  const seen = { url: null, config: null };
  rpc.createBroadcastRpcClient(
    { rpcUrl: 'https://rpc.example' },
    {
      createPublicClient: ({ transport }) => ({ transport }),
      http: (url, config) => {
        seen.url = url;
        seen.config = config;
        return { kind: 'http', url, config };
      },
    },
  );

  assert.equal(seen.url, 'https://rpc.example');
  assert.deepEqual(seen.config, { retryCount: 0, timeout: rpc.BROADCAST_RPC_TIMEOUT_MS });
  assert.equal(rpc.BROADCAST_RPC_TIMEOUT_MS > 0, true);
});

test('getNativeBalance formats balances using the supplied native decimals', async () => {
  const rpc = await import(modulePath.href + `?case=${Date.now()}-native-decimals`);

  await withJsonRpcServer(
    (payload) => ({ body: { jsonrpc: '2.0', id: payload.id, result: '0x16e360' } }),
    async (rpcUrl, calls) => {
      const sixDecimals = await rpc.getNativeBalance(
        rpcUrl,
        '0x1111111111111111111111111111111111111111',
        6,
      );
      assert.equal(sixDecimals.raw, 1_500_000n);
      assert.equal(sixDecimals.formatted, '1.5');

      const defaultDecimals = await rpc.getNativeBalance(
        rpcUrl,
        '0x1111111111111111111111111111111111111111',
      );
      assert.equal(defaultDecimals.raw, 1_500_000n);
      assert.equal(defaultDecimals.formatted, '0.0000000000015');
      assert.equal(
        calls.every((call) => call.method === 'eth_getBalance'),
        true,
      );
    },
  );
});

test('getNativeBalance rejects invalid native decimals before hitting the RPC', async () => {
  const rpc = await import(modulePath.href + `?case=${Date.now()}-native-decimals-invalid`);

  await assert.rejects(
    rpc.getNativeBalance('https://rpc.example', '0x1111111111111111111111111111111111111111', 1.5),
    /native decimals must be an integer between 0 and 255/,
  );
});

test('broadcastRawTransaction treats already-known transactions as success with the local hash', async () => {
  const rpc = await import(modulePath.href + `?case=${Date.now()}-broadcast-already-known`);
  const rawTransaction = '0x02f8deadbeefcafebabe';

  for (const message of [
    'already known',
    'ALREADY_EXISTS: already known',
    'known transaction: 0xabc',
    'transaction already imported',
  ]) {
    await withJsonRpcServer(
      (payload) => ({
        body: { jsonrpc: '2.0', id: payload.id, error: { code: -32000, message } },
      }),
      async (rpcUrl, calls) => {
        const hash = await rpc.broadcastRawTransaction(rpcUrl, rawTransaction);
        assert.equal(hash, keccak256(rawTransaction));
        assert.equal(calls.length, 1);
        assert.equal(calls[0].method, 'eth_sendRawTransaction');
        assert.deepEqual(calls[0].params, [rawTransaction]);
      },
    );
  }
});

test('broadcastRawTransaction surfaces other node errors without retrying', async () => {
  const rpc = await import(modulePath.href + `?case=${Date.now()}-broadcast-no-retry`);

  await withJsonRpcServer(
    (payload) => ({
      body: { jsonrpc: '2.0', id: payload.id, error: { code: -32000, message: 'nonce too low' } },
    }),
    async (rpcUrl, calls) => {
      await assert.rejects(rpc.broadcastRawTransaction(rpcUrl, '0x02f8aa'), /nonce too low/i);
      assert.equal(calls.length, 1);
    },
  );

  await withJsonRpcServer(
    () => ({ status: 503, body: { error: 'upstream unavailable' } }),
    async (rpcUrl, calls) => {
      await assert.rejects(rpc.broadcastRawTransaction(rpcUrl, '0x02f8bb'));
      assert.equal(calls.length, 1, 'retryable HTTP failures must not re-send the transaction');
    },
  );
});

test('isAlreadyKnownTransactionError inspects nested viem error causes', async () => {
  const rpc = await import(modulePath.href + `?case=${Date.now()}-already-known-detector`);

  const nested = new Error('RPC Request failed.');
  nested.cause = { details: 'ALREADY_EXISTS: already known' };
  assert.equal(rpc.isAlreadyKnownTransactionError(nested), true);
  assert.equal(rpc.isAlreadyKnownTransactionError(new Error('nonce too low')), false);
  assert.equal(rpc.isAlreadyKnownTransactionError(null), false);
  assert.equal(rpc.isAlreadyKnownTransactionError('already known'), false);
});
