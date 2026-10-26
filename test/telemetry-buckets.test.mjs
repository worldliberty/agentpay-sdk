import assert from 'node:assert/strict';
import test from 'node:test';

const modulePath = new URL('../src/lib/telemetry-buckets.ts', import.meta.url);

async function loadModule(caseSuffix) {
  return await import(`${modulePath.href}?case=${caseSuffix}-${Date.now()}`);
}

test('bucketAmount maps balances onto the published ranges', async () => {
  const { bucketAmount } = await loadModule('ranges');

  assert.equal(bucketAmount(0), '0');
  assert.equal(bucketAmount(0.01), '<10');
  assert.equal(bucketAmount(9.99), '<10');
  assert.equal(bucketAmount(10), '10-100');
  assert.equal(bucketAmount(99.99), '10-100');
  assert.equal(bucketAmount(100), '100-1k');
  assert.equal(bucketAmount(1_000), '1k-10k');
  assert.equal(bucketAmount(10_000), '10k+');
  assert.equal(bucketAmount(5_000_000), '10k+');
});

test('bucketAmount rejects values that cannot describe a balance', async () => {
  const { bucketAmount } = await loadModule('invalid');

  assert.equal(bucketAmount(-1), undefined);
  assert.equal(bucketAmount(Number.NaN), undefined);
  assert.equal(bucketAmount(Number.POSITIVE_INFINITY), undefined);
});

test('bucketDecimalString parses decimal strings and ignores blanks', async () => {
  const { bucketDecimalString } = await loadModule('decimal-string');

  assert.equal(bucketDecimalString('250.5'), '100-1k');
  assert.equal(bucketDecimalString('0'), '0');
  assert.equal(bucketDecimalString(''), undefined);
  assert.equal(bucketDecimalString(undefined), undefined);
});
