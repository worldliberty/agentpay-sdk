import assert from 'node:assert/strict';
import test from 'node:test';

const relayModulePath = new URL('../apps/web/src/lib/relay-client.ts', import.meta.url);

const validApproval = {
  approvalId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  daemonId: '11'.repeat(32),
  agentKeyId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  status: 'pending',
  reason: 'Manual approval required',
  actionType: 'transfer_native',
  chainId: 1,
  recipient: '0x3333333333333333333333333333333333333333',
  asset: 'native_eth',
  amountWei: '1000000000000000000',
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
};

const validDaemon = {
  daemonId: '11'.repeat(32),
  daemonPublicKey: '22'.repeat(32),
  vaultEthereumAddress: '0x3333333333333333333333333333333333333333',
  relayBaseUrl: 'https://relay.example',
  updatedAt: new Date().toISOString(),
};

async function loadRelay(caseSuffix) {
  process.env.NEXT_PUBLIC_AGENTPAY_RELAY_BASE_URL = 'https://relay.example';
  return await import(`${relayModulePath.href}?case=${caseSuffix}-${Date.now()}`);
}

test('getApprovalRequest encodes approval ids before calling the relay', async () => {
  const relay = await loadRelay('approval-path');
  const originalFetch = global.fetch;
  const seenTargets = [];

  global.fetch = async (target) => {
    seenTargets.push(String(target));
    return new Response(JSON.stringify(validApproval), {
      status: 200,
      headers: {
        'content-type': 'application/json',
      },
    });
  };

  try {
    await relay.getApprovalRequest('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/../stolen');
  } finally {
    global.fetch = originalFetch;
  }

  assert.equal(
    seenTargets[0],
    'https://relay.example/v1/approvals/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa%2F..%2Fstolen',
  );
});

test('getDaemonRecord rejects malformed relay payloads instead of trusting them', async () => {
  const relay = await loadRelay('invalid-daemon-payload');
  const originalFetch = global.fetch;

  global.fetch = async () =>
    new Response(
      JSON.stringify({
        ...validDaemon,
        daemonPublicKey: 'not-hex',
      }),
      {
        status: 200,
        headers: {
          'content-type': 'application/json',
        },
      },
    );

  try {
    await assert.rejects(
      relay.getDaemonRecord(validDaemon.daemonId),
      /Relay response was invalid for \/v1\/daemons\//,
    );
  } finally {
    global.fetch = originalFetch;
  }
});

test('listDaemonApprovals validates approval arrays from the relay', async () => {
  const relay = await loadRelay('approval-list');
  const originalFetch = global.fetch;

  global.fetch = async () =>
    new Response(JSON.stringify([validApproval]), {
      status: 200,
      headers: {
        'content-type': 'application/json',
      },
    });

  try {
    const approvals = await relay.listDaemonApprovals(validDaemon.daemonId);
    assert.deepEqual(approvals, [validApproval]);
  } finally {
    global.fetch = originalFetch;
  }
});
