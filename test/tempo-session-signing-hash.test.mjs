/**
 * Regression test: Tempo session signing hash must NOT use Keychain wrapping.
 *
 * The CLI must call getSignPayload() without `from` for session open and
 * top-up transactions.  Passing `from` produces a Keychain-wrapped hash
 * (0x04 || txHash || address) that breaks ecrecover on the server when
 * the actual signature is a plain secp256k1 signature.
 *
 * Bug: https://github.com/wlfi-infra/agentpay-sdk-internal — session intent
 * "Computed channelId does not match payload.channelId"
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import { keccak256, parseSignature, recoverAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { Transaction as TempoTransaction } from 'viem/tempo';

const TEST_PRIVATE_KEY = (() => {
  const bytes = new Uint8Array(32);
  for (;;) {
    globalThis.crypto.getRandomValues(bytes);
    const candidate = `0x${Buffer.from(bytes).toString('hex')}`;
    try {
      privateKeyToAccount(candidate); // validate key is usable
      return candidate;
    } catch {
      // retry on the extremely rare invalid secp256k1 scalar
    }
  }
})();

function buildTestEnvelope() {
  return TempoTransaction.z_TxEnvelopeTempo.from({
    chainId: 4217,
    maxPriorityFeePerGas: 0n,
    maxFeePerGas: 1_000_000_000n,
    gas: 200_000n,
    calls: [
      {
        to: '0x0000000000000000000000000000000000000001',
        data: '0x',
        value: 0n,
      },
    ],
    type: 'tempo',
    feeToken: '0x20C000000000000000000000b9537d11c60E8b50',
  });
}

test('getSignPayload with and without `from` produce different hashes', () => {
  const envelope = buildTestEnvelope();
  const account = privateKeyToAccount(TEST_PRIVATE_KEY);

  const hashWithout = TempoTransaction.z_TxEnvelopeTempo.getSignPayload(envelope);
  const hashWith = TempoTransaction.z_TxEnvelopeTempo.getSignPayload(envelope, {
    from: account.address,
  });

  assert.notEqual(hashWithout, hashWith, 'hashes must differ — `from` enables Keychain wrapping');
});

test('signing hash without `from` round-trips through ecrecover correctly', async () => {
  const envelope = buildTestEnvelope();
  const account = privateKeyToAccount(TEST_PRIVATE_KEY);

  // This is the correct path: no `from` → standard Tempo tx hash
  const signingHash = TempoTransaction.z_TxEnvelopeTempo.getSignPayload(envelope);
  const signature = await account.sign({ hash: signingHash });
  const recovered = await recoverAddress({
    hash: signingHash,
    signature,
  });

  assert.equal(
    recovered.toLowerCase(),
    account.address.toLowerCase(),
    'ecrecover must return the signer address when using standard (non-Keychain) hash',
  );
});

test('signing hash WITH `from` does NOT round-trip through standard ecrecover', async () => {
  const envelope = buildTestEnvelope();
  const account = privateKeyToAccount(TEST_PRIVATE_KEY);

  // This is the buggy path: `from` → Keychain-wrapped hash
  const keychainHash = TempoTransaction.z_TxEnvelopeTempo.getSignPayload(envelope, {
    from: account.address,
  });
  const signature = await account.sign({ hash: keychainHash });

  // Server does ecrecover using the standard (non-Keychain) hash
  const standardHash = TempoTransaction.z_TxEnvelopeTempo.getSignPayload(envelope);
  const recovered = await recoverAddress({
    hash: standardHash,
    signature,
  });

  assert.notEqual(
    recovered.toLowerCase(),
    account.address.toLowerCase(),
    'ecrecover with standard hash must NOT match signer when signature was made with Keychain hash — this is the bug scenario',
  );
});

test('serialize + keccak256 matches getSignPayload without `from`', async () => {
  const envelope = buildTestEnvelope();

  // What viem's signTransaction does internally:
  const serialized = TempoTransaction.z_TxEnvelopeTempo.serialize(envelope);
  const hashFromSerialize = keccak256(serialized);

  // What getSignPayload does without `from`:
  const hashFromGetSignPayload = TempoTransaction.z_TxEnvelopeTempo.getSignPayload(envelope);

  assert.equal(
    hashFromSerialize,
    hashFromGetSignPayload,
    'serialize+keccak256 must equal getSignPayload() — both are the standard Tempo signing hash',
  );
});
