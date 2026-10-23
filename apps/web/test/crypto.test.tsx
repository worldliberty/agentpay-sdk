import fs from 'node:fs';
import path from 'node:path';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { x25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { describe, expect, it } from 'vitest';
import {
  deriveRelayEnvelopeKey,
  encryptApprovalUpdate,
  RELAY_ENVELOPE_ALGORITHM,
  relayEnvelopeAad,
  sealApprovalUpdate,
} from '@/lib/crypto';

const vector = JSON.parse(
  fs.readFileSync(
    path.resolve(__dirname, '../../../crates/vault-daemon/tests/fixtures/relay_envelope_v2.json'),
    'utf8',
  ),
);

const payload = {
  approvalId: '6f1b8f5e-3a52-4c1e-9d0b-2b7f2f0b9a11',
  daemonId: 'ab'.repeat(32),
  vaultPassword: 'vault-password',
  decision: 'approve' as const,
};

function open(
  daemonPrivateKey: Uint8Array,
  envelope: { ephemeralPublicKey: string; nonce: string; ciphertext: string },
  aad: Uint8Array,
) {
  const daemonPublicKey = x25519.getPublicKey(daemonPrivateKey);
  const ephemeralPublicKey = hexToBytes(envelope.ephemeralPublicKey);
  const sharedSecret = x25519.getSharedSecret(daemonPrivateKey, ephemeralPublicKey);
  const key = deriveRelayEnvelopeKey(sharedSecret, ephemeralPublicKey, daemonPublicKey);
  return xchacha20poly1305(key, hexToBytes(envelope.nonce), aad).decrypt(
    hexToBytes(envelope.ciphertext),
  );
}

describe('relay envelope v2', () => {
  it('matches the committed cross-language vector', () => {
    const plaintext = JSON.parse(vector.plaintext);
    const envelope = sealApprovalUpdate(vector.daemonPublicKeyHex, plaintext, {
      ephemeralSecretKey: hexToBytes(vector.ephemeralSecretKeyHex),
      nonce: hexToBytes(vector.envelope.nonce),
    });
    expect(envelope).toEqual(vector.envelope);
    expect(bytesToHex(relayEnvelopeAad(vector.approvalId, vector.daemonId))).toBe(vector.aadHex);
  });

  it('binds the ciphertext to approval id and daemon id', () => {
    const daemonPrivateKey = x25519.utils.randomPrivateKey();
    const envelope = encryptApprovalUpdate(
      bytesToHex(x25519.getPublicKey(daemonPrivateKey)),
      payload,
    );
    expect(envelope.algorithm).toBe(RELAY_ENVELOPE_ALGORITHM);
    expect(envelope.algorithm).toBe('x25519-hkdf-xchacha20poly1305-v2');

    const decrypted = open(
      daemonPrivateKey,
      envelope,
      relayEnvelopeAad(payload.approvalId, payload.daemonId),
    );
    expect(JSON.parse(new TextDecoder().decode(decrypted))).toEqual(payload);

    expect(() =>
      open(daemonPrivateKey, envelope, relayEnvelopeAad(payload.approvalId, 'cd'.repeat(32))),
    ).toThrow();
    expect(() =>
      open(daemonPrivateKey, envelope, utf8ToBytes(`other|${payload.daemonId}`)),
    ).toThrow();
  });

  it('rejects low-order daemon public keys', () => {
    expect(() => encryptApprovalUpdate('00'.repeat(32), payload)).toThrow();
    expect(() =>
      deriveRelayEnvelopeKey(new Uint8Array(32), new Uint8Array(32), new Uint8Array(32)),
    ).toThrow(/non-contributory/u);
  });
});
