import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes } from '@noble/ciphers/webcrypto';
import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import type { ApprovalUpdateInput, EncryptedApprovalUpdateEnvelope } from './types';

export const RELAY_ENVELOPE_ALGORITHM = 'x25519-hkdf-xchacha20poly1305-v2';
const RELAY_ENVELOPE_HKDF_INFO_PREFIX = utf8ToBytes('agentpay-relay-v2');

export interface SealApprovalUpdateOptions {
  ephemeralSecretKey: Uint8Array;
  nonce: Uint8Array;
}

/** AAD binding the envelope to one approval on one daemon: `approvalId|daemonId`. */
export function relayEnvelopeAad(approvalId: string, daemonId: string): Uint8Array {
  return utf8ToBytes(`${approvalId}|${daemonId}`);
}

/**
 * HKDF-SHA256(ikm = X25519 shared secret, salt = empty,
 * info = "agentpay-relay-v2" || ephemeralPublicKey || daemonPublicKey).
 */
export function deriveRelayEnvelopeKey(
  sharedSecret: Uint8Array,
  ephemeralPublicKey: Uint8Array,
  daemonPublicKey: Uint8Array,
): Uint8Array {
  if (sharedSecret.every((byte) => byte === 0)) {
    throw new Error('daemon public key produced a non-contributory shared secret');
  }
  const info = concatBytes(RELAY_ENVELOPE_HKDF_INFO_PREFIX, ephemeralPublicKey, daemonPublicKey);
  return hkdf(sha256, sharedSecret, new Uint8Array(0), info, 32);
}

/** Deterministic core of `encryptApprovalUpdate`; exported for cross-language test vectors. */
export function sealApprovalUpdate(
  daemonPublicKeyHex: string,
  payload: ApprovalUpdateInput,
  { ephemeralSecretKey, nonce }: SealApprovalUpdateOptions,
): EncryptedApprovalUpdateEnvelope {
  const daemonPublicKey = hexToBytes(daemonPublicKeyHex.replace(/^0x/u, ''));
  if (daemonPublicKey.length !== 32) {
    throw new Error('daemon public key must be 32 bytes');
  }
  if (nonce.length !== 24) {
    throw new Error('nonce must be 24 bytes');
  }
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralSecretKey);
  const sharedSecret = x25519.getSharedSecret(ephemeralSecretKey, daemonPublicKey);
  const key = deriveRelayEnvelopeKey(sharedSecret, ephemeralPublicKey, daemonPublicKey);
  const aad = relayEnvelopeAad(payload.approvalId, payload.daemonId);
  const plaintext = utf8ToBytes(JSON.stringify(payload));
  const ciphertext = xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
  sharedSecret.fill(0);
  key.fill(0);

  return {
    algorithm: RELAY_ENVELOPE_ALGORITHM,
    ephemeralPublicKey: bytesToHex(ephemeralPublicKey),
    nonce: bytesToHex(nonce),
    ciphertext: bytesToHex(ciphertext),
  };
}

export function encryptApprovalUpdate(
  daemonPublicKeyHex: string,
  payload: ApprovalUpdateInput,
): EncryptedApprovalUpdateEnvelope {
  const ephemeralSecretKey = x25519.utils.randomPrivateKey();
  try {
    return sealApprovalUpdate(daemonPublicKeyHex, payload, {
      ephemeralSecretKey,
      nonce: randomBytes(24),
    });
  } finally {
    ephemeralSecretKey.fill(0);
  }
}
