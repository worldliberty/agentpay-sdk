import assert from 'node:assert/strict';
import test from 'node:test';
import { Transaction as TempoTransaction } from 'viem/tempo';

const modulePath = new URL('../src/lib/tempo-transaction-args.ts', import.meta.url);

const FEE_TOKEN = '0x20c0000000000000000000000000000000000001';

function preparedTransaction(overrides = {}) {
  return {
    type: 'tempo',
    chainId: 4217,
    calls: [{ to: FEE_TOKEN, data: '0x' }],
    gas: 100_000n,
    maxFeePerGas: 20_000_000_000n,
    maxPriorityFeePerGas: 1n,
    nonce: 3,
    feeToken: FEE_TOKEN,
    ...overrides,
  };
}

function flagValue(args, name) {
  const index = args.indexOf(`--${name}`);
  return index >= 0 ? args[index + 1] : undefined;
}

test('tempoTransactionCliArgs omits zero validAfter and validBefore', async () => {
  const { tempoTransactionCliArgs } = await import(modulePath.href);
  const args = tempoTransactionCliArgs(
    preparedTransaction({ validAfter: 0, validBefore: 0 }),
    false,
  );
  assert.equal(args.includes('--valid-after'), false);
  assert.equal(args.includes('--valid-before'), false);

  const zeroHexArgs = tempoTransactionCliArgs(
    preparedTransaction({ validAfter: '0x0', validBefore: 0n }),
    false,
  );
  assert.equal(zeroHexArgs.includes('--valid-after'), false);
  assert.equal(zeroHexArgs.includes('--valid-before'), false);
});

test('tempoTransactionCliArgs forwards positive validity bounds', async () => {
  const { tempoTransactionCliArgs } = await import(modulePath.href);
  const args = tempoTransactionCliArgs(
    preparedTransaction({ validAfter: 0, validBefore: 1_900_000_000 }),
    false,
  );
  assert.equal(flagValue(args, 'valid-before'), '1900000000');
  assert.equal(args.includes('--valid-after'), false);

  const both = tempoTransactionCliArgs(
    preparedTransaction({ validAfter: 1_800_000_000, validBefore: 1_900_000_000 }),
    false,
  );
  assert.equal(flagValue(both, 'valid-after'), '1800000000');
  assert.equal(flagValue(both, 'valid-before'), '1900000000');
});

test('withoutZeroTempoValidityBounds makes a validAfter 0 envelope match the omitted-flag envelope', async () => {
  const { withoutZeroTempoValidityBounds } = await import(modulePath.href);
  const prepared = preparedTransaction({ validAfter: 0, validBefore: 1_900_000_000 });
  const normalized = withoutZeroTempoValidityBounds(prepared);
  assert.equal('validAfter' in normalized, false);
  assert.equal(normalized.validBefore, 1_900_000_000);
  assert.equal(prepared.validAfter, 0, 'input must not be mutated');

  // The daemon rebuilds the envelope from the CLI flags, so with --valid-after omitted it signs
  // an envelope without validAfter. A literal 0 serializes differently in viem.
  const withoutBound = preparedTransaction({ validBefore: 1_900_000_000 });
  assert.equal(
    await TempoTransaction.serialize(normalized),
    await TempoTransaction.serialize(withoutBound),
  );
  assert.notEqual(
    await TempoTransaction.serialize(prepared),
    await TempoTransaction.serialize(withoutBound),
  );
});
