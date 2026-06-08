import assert from 'node:assert/strict';
import test from 'node:test';

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
