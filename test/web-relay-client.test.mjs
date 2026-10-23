import assert from 'node:assert/strict';
import test from 'node:test';

const modulePath = new URL('../apps/web/src/lib/relay-client.ts', import.meta.url);

async function loadModule(caseSuffix) {
  return await import(`${modulePath.href}?case=${caseSuffix}-${Date.now()}`);
}

test('requestSecureApprovalLink sends admin bearer auth and parses the secure-link payload', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (target, init) => {
    calls.push({ target: String(target), init });
    return new Response(
      JSON.stringify({
        approvalCapability: 'aa'.repeat(32),
        approvalId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        approvalUrl:
          'http://127.0.0.1:8787/approvals/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa#approvalCapability=' +
          'aa'.repeat(32),
        daemonId: 'bb'.repeat(32),
        daemonPublicKey: 'cc'.repeat(32),
      }),
      {
        status: 200,
        headers: {
          'content-type': 'application/json',
        },
      },
    );
  };

  try {
    const relayClient = await loadModule('secure-link-success');
    const result = await relayClient.requestSecureApprovalLink(
      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      'relay-admin-token',
    );

    assert.equal(calls.length, 1);
    assert.equal(
      calls[0].target,
      'http://localhost:8787/v1/admin/approvals/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/secure-link',
    );
    assert.equal(calls[0].init.method, 'POST');
    assert.equal(calls[0].init.headers.authorization, 'Bearer relay-admin-token');
    assert.equal(result.approvalCapability, 'aa'.repeat(32));
    assert.equal(result.daemonPublicKey, 'cc'.repeat(32));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('requestSecureApprovalLink surfaces relay error messages', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ error: 'Admin token is required' }), {
      status: 401,
      statusText: 'Unauthorized',
      headers: {
        'content-type': 'application/json',
      },
    });

  try {
    const relayClient = await loadModule('secure-link-error');
    await assert.rejects(
      () =>
        relayClient.requestSecureApprovalLink('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'bad-token'),
      /Admin token is required/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});
