import assert from 'node:assert/strict';
import test from 'node:test';
import { privateKeyToAccount } from 'viem/accounts';

const modulePath = new URL('../src/lib/signed-tx.ts', import.meta.url);
const account = privateKeyToAccount(
  '0x59c6995e998f97a5a004497e5f2d65f5d8ca7d2714b3f1c5f4f8bb15e95b6c4d',
);

async function buildSignedTx(overrides = {}) {
  return await account.signTransaction({
    chainId: 1,
    nonce: 7,
    to: '0x0000000000000000000000000000000000000001',
    value: 3n,
    data: '0x1234',
    gas: 21000n,
    maxFeePerGas: 5n,
    maxPriorityFeePerGas: 1n,
    type: 'eip1559',
    ...overrides,
  });
}

async function buildMinimalSignedTx(overrides = {}) {
  return await account.signTransaction({
    chainId: 1,
    nonce: 7,
    to: '0x0000000000000000000000000000000000000001',
    gas: 21000n,
    maxFeePerGas: 5n,
    maxPriorityFeePerGas: 1n,
    type: 'eip1559',
    ...overrides,
  });
}

test('assertSignedBroadcastTransactionMatchesRequest accepts matching signed tx payloads', async () => {
  const signedTx = await import(`${modulePath.href}?case=${Date.now()}-match`);
  const rawTxHex = await buildSignedTx();

  await assert.doesNotReject(() =>
    signedTx.assertSignedBroadcastTransactionMatchesRequest({
      rawTxHex,
      from: account.address,
      to: '0x0000000000000000000000000000000000000001',
      chainId: 1,
      nonce: 7,
      value: 3n,
      data: '0x1234',
      gasLimit: 21000n,
      maxFeePerGas: 5n,
      maxPriorityFeePerGas: 1n,
      txType: '0x02',
    }),
  );
});

test('assertSignedBroadcastTransactionMatchesRequest treats missing parsed zero priority fee as zero', async () => {
  const signedTx = await import(`${modulePath.href}?case=${Date.now()}-zero-priority-fee`);
  const rawTxHex = await buildSignedTx({
    value: 0n,
    data: '0x',
    maxPriorityFeePerGas: 0n,
  });

  await assert.doesNotReject(() =>
    signedTx.assertSignedBroadcastTransactionMatchesRequest({
      rawTxHex,
      from: account.address,
      to: '0x0000000000000000000000000000000000000001',
      chainId: 1,
      nonce: 7,
      value: 0n,
      data: '0x',
      gasLimit: 21000n,
      maxFeePerGas: 5n,
      maxPriorityFeePerGas: 0n,
      txType: '0x02',
    }),
  );
});

test('assertSignedBroadcastTransactionMatchesRequest still rejects non-zero expected priority fee', async () => {
  const signedTx = await import(`${modulePath.href}?case=${Date.now()}-nonzero-priority-mismatch`);
  const rawTxHex = await buildSignedTx({
    value: 0n,
    data: '0x',
    maxPriorityFeePerGas: 0n,
  });

  await assert.rejects(
    signedTx.assertSignedBroadcastTransactionMatchesRequest({
      rawTxHex,
      from: account.address,
      to: '0x0000000000000000000000000000000000000001',
      chainId: 1,
      nonce: 7,
      value: 0n,
      data: '0x',
      gasLimit: 21000n,
      maxFeePerGas: 5n,
      maxPriorityFeePerGas: 1n,
      txType: '0x02',
    }),
    /maxPriorityFeePerGas mismatch: expected 1, received 0/u,
  );
});

test('assertSignedBroadcastTransactionMatchesRequest rejects mismatched sender recovery', async () => {
  const signedTx = await import(`${modulePath.href}?case=${Date.now()}-from-mismatch`);
  const rawTxHex = await buildSignedTx();

  await assert.rejects(
    signedTx.assertSignedBroadcastTransactionMatchesRequest({
      rawTxHex,
      from: '0x0000000000000000000000000000000000000002',
      to: '0x0000000000000000000000000000000000000001',
      chainId: 1,
      nonce: 7,
      value: 3n,
      data: '0x1234',
      gasLimit: 21000n,
      maxFeePerGas: 5n,
      maxPriorityFeePerGas: 1n,
      txType: '0x02',
    }),
    /from mismatch/,
  );
});

test('assertSignedBroadcastTransactionMatchesRequest rejects mismatched signed fields', async () => {
  const signedTx = await import(`${modulePath.href}?case=${Date.now()}-field-mismatch`);
  const rawTxHex = await buildSignedTx({ nonce: 9 });

  await assert.rejects(
    signedTx.assertSignedBroadcastTransactionMatchesRequest({
      rawTxHex,
      from: account.address,
      to: '0x0000000000000000000000000000000000000001',
      chainId: 1,
      nonce: 7,
      value: 3n,
      data: '0x1234',
      gasLimit: 21000n,
      maxFeePerGas: 5n,
      maxPriorityFeePerGas: 1n,
      txType: '0x02',
    }),
    /nonce mismatch/,
  );
});

test('assertSignedBroadcastTransactionMatchesRequest accepts a higher signed nonce when allowed', async () => {
  const signedTx = await import(`${modulePath.href}?case=${Date.now()}-higher-nonce`);
  const rawTxHex = await buildSignedTx({ nonce: 9 });

  const inspected = await signedTx.assertSignedBroadcastTransactionMatchesRequest({
    rawTxHex,
    from: account.address,
    to: '0x0000000000000000000000000000000000000001',
    chainId: 1,
    nonce: 7,
    allowHigherNonce: true,
    value: 3n,
    data: '0x1234',
    gasLimit: 21000n,
    maxFeePerGas: 5n,
    maxPriorityFeePerGas: 1n,
    txType: '0x02',
  });

  assert.equal(inspected.nonce, 9);
});

test('assertSignedBroadcastTransactionMatchesRequest rejects lower nonce when allowHigherNonce is enabled', async () => {
  const signedTx = await import(`${modulePath.href}?case=${Date.now()}-allow-higher-reject-lower`);
  const rawTxHex = await buildSignedTx({ nonce: 5 });

  await assert.rejects(
    signedTx.assertSignedBroadcastTransactionMatchesRequest({
      rawTxHex,
      from: account.address,
      to: '0x0000000000000000000000000000000000000001',
      chainId: 1,
      nonce: 7,
      allowHigherNonce: true,
      value: 3n,
      data: '0x1234',
      gasLimit: 21000n,
      maxFeePerGas: 5n,
      maxPriorityFeePerGas: 1n,
      txType: '0x02',
    }),
    /expected at least 7, received 5/,
  );
});

test('assertSignedBroadcastTransactionMatchesRequest rejects mismatched recipient and calldata', async () => {
  const signedTx = await import(`${modulePath.href}?case=${Date.now()}-to-and-data-mismatch`);
  const rawTxHex = await buildSignedTx();

  await assert.rejects(
    signedTx.assertSignedBroadcastTransactionMatchesRequest({
      rawTxHex,
      from: account.address,
      to: '0x0000000000000000000000000000000000000002',
      chainId: 1,
      nonce: 7,
      value: 3n,
      data: '0x1234',
      gasLimit: 21000n,
      maxFeePerGas: 5n,
      maxPriorityFeePerGas: 1n,
      txType: '0x02',
    }),
    /to mismatch/,
  );

  await assert.rejects(
    signedTx.assertSignedBroadcastTransactionMatchesRequest({
      rawTxHex,
      from: account.address,
      to: '0x0000000000000000000000000000000000000001',
      chainId: 1,
      nonce: 7,
      value: 3n,
      data: '0xdead',
      gasLimit: 21000n,
      maxFeePerGas: 5n,
      maxPriorityFeePerGas: 1n,
      txType: '0x02',
    }),
    /data mismatch/,
  );
});

test('assertSignedBroadcastTransactionMatchesRequest reports null recipients for contract-creation transactions', async () => {
  const signedTx = await import(`${modulePath.href}?case=${Date.now()}-null-recipient`);
  const rawTxHex = await buildSignedTx({
    to: undefined,
    data: '0x1234',
  });

  await assert.rejects(
    signedTx.assertSignedBroadcastTransactionMatchesRequest({
      rawTxHex,
      from: account.address,
      to: '0x0000000000000000000000000000000000000001',
      chainId: 1,
      nonce: 7,
      value: 0n,
      data: '0x1234',
      gasLimit: 21000n,
      maxFeePerGas: 5n,
      maxPriorityFeePerGas: 1n,
      txType: '0x02',
    }),
    /received null/,
  );
});

test('assertSignedBroadcastTransactionMatchesRequest accepts default zero value and empty calldata', async () => {
  const signedTx = await import(`${modulePath.href}?case=${Date.now()}-default-value-data`);
  const rawTxHex = await buildMinimalSignedTx();

  await assert.doesNotReject(() =>
    signedTx.assertSignedBroadcastTransactionMatchesRequest({
      rawTxHex,
      from: account.address,
      to: '0x0000000000000000000000000000000000000001',
      chainId: 1,
      nonce: 7,
      value: 0n,
      data: '0x',
      gasLimit: 21000n,
      maxFeePerGas: 5n,
      maxPriorityFeePerGas: 1n,
      txType: '0x02',
    }),
  );
});

test('assertSignedBroadcastTransactionMatchesRequest validates txType normalization and rejects unsupported types', async () => {
  const signedTx = await import(`${modulePath.href}?case=${Date.now()}-tx-type-validation`);
  const rawTxHex = await buildSignedTx();
  const baseExpected = {
    rawTxHex,
    from: account.address,
    to: '0x0000000000000000000000000000000000000001',
    chainId: 1,
    nonce: 7,
    value: 3n,
    data: '0x1234',
    gasLimit: 21000n,
    maxFeePerGas: 5n,
    maxPriorityFeePerGas: 1n,
  };

  await assert.doesNotReject(() =>
    signedTx.assertSignedBroadcastTransactionMatchesRequest({
      ...baseExpected,
      txType: '2',
    }),
  );

  await assert.doesNotReject(() =>
    signedTx.assertSignedBroadcastTransactionMatchesRequest({
      ...baseExpected,
      txType: ' 0X02 ',
    }),
  );

  await assert.rejects(
    signedTx.assertSignedBroadcastTransactionMatchesRequest({
      ...baseExpected,
      txType: '   ',
    }),
    /txType is required/,
  );

  await assert.rejects(
    signedTx.assertSignedBroadcastTransactionMatchesRequest({
      ...baseExpected,
      txType: 'not-a-type',
    }),
    /Unsupported txType/,
  );

  await assert.rejects(
    signedTx.assertSignedBroadcastTransactionMatchesRequest({
      ...baseExpected,
      txType: '0x99',
    }),
    /Unsupported txType/,
  );

  for (const txType of ['0', '1', '3', '4']) {
    await assert.rejects(
      signedTx.assertSignedBroadcastTransactionMatchesRequest({
        ...baseExpected,
        txType,
      }),
      /txType mismatch/,
    );
  }
});
