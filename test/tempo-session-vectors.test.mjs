/**
 * Pins the Tempo session fixture consumed by crates/vault-domain/src/tests.rs to the viem/ox
 * reference encoders. If a viem/ox upgrade changes the Tempo envelope or voucher encoding, the
 * regenerated vectors differ from the checked-in file and this test fails before the Rust daemon
 * silently signs digests the network no longer accepts.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { keccak256 } from 'viem';
import { Transaction as TempoTransaction } from 'viem/tempo';
import {
  serializeTempoSessionVectors,
  tempoSessionVectorsPath,
} from '../scripts/generate-tempo-session-vectors.mjs';

test('checked-in Tempo session vectors match a fresh viem regeneration', async () => {
  const regenerated = await serializeTempoSessionVectors();
  const checkedIn = fs.readFileSync(tempoSessionVectorsPath, 'utf8');
  assert.equal(checkedIn, regenerated);
});

test('vectors cover both chains, both fee modes, and both nonce modes', () => {
  const { vectors } = JSON.parse(fs.readFileSync(tempoSessionVectorsPath, 'utf8'));
  assert.deepEqual(
    vectors.map((vector) => vector.name).sort(),
    [
      '4217-sponsored-expiring-nonce',
      '4217-sponsored-sequential-nonce',
      '4217-unsponsored-expiring-nonce',
      '4217-unsponsored-sequential-nonce',
      '42431-sponsored-expiring-nonce',
      '42431-sponsored-sequential-nonce',
      '42431-unsponsored-expiring-nonce',
      '42431-unsponsored-sequential-nonce',
    ].sort(),
  );
  for (const vector of vectors) {
    const sponsored = vector.name.includes('-sponsored-');
    assert.equal(vector.open.tx.fee_payer, sponsored);
    assert.equal('fee_token' in vector.open.tx, !sponsored);
  }
});

test('sponsored sender digest differs from getSignPayload, which ignores feePayer', async () => {
  // viem's reference signer hashes keccak256(serialize(unsigned)); with feePayer: true that drops
  // the fee token and writes the 0x00 fee-payer marker. getSignPayload(from(tx)) does not, which
  // is why the CLI no longer uses it for its local cross-check.
  const unsigned = {
    type: 'tempo',
    chainId: 42431,
    calls: [{ to: '0x20c0000000000000000000000000000000000001', data: '0x' }],
    gas: 100_000n,
    maxFeePerGas: 20_000_000_000n,
    maxPriorityFeePerGas: 1n,
    nonce: 0,
    feeToken: '0x20c0000000000000000000000000000000000001',
    feePayer: true,
  };
  const referenceDigest = keccak256(await TempoTransaction.serialize(unsigned));
  const legacyDigest = TempoTransaction.z_TxEnvelopeTempo.getSignPayload(
    TempoTransaction.z_TxEnvelopeTempo.from({ ...unsigned, feePayer: undefined }),
  );
  assert.notEqual(referenceDigest, legacyDigest);
});
