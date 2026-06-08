import assert from 'node:assert/strict';
import test from 'node:test';

const modulePath = new URL('../src/lib/rpc-guard.ts', import.meta.url);

test('assertRpcChainIdMatches accepts matching chain ids', async () => {
  const guard = await import(modulePath.href + `?case=${Date.now()}-1`);

  assert.doesNotThrow(() => guard.assertRpcChainIdMatches(1, 1));
});

test('assertRpcChainIdMatches rejects mismatched chain ids', async () => {
  const guard = await import(modulePath.href + `?case=${Date.now()}-2`);

  assert.throws(
    () => guard.assertRpcChainIdMatches(1, 11155111),
    /RPC endpoint chainId 11155111 does not match expected chainId 1/,
  );
});
