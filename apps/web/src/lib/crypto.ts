import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes } from '@noble/ciphers/webcrypto';
import { x25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import type { ApprovalUpdateInput, EncryptedApprovalUpdateEnvelope } from './types';

export function encryptApprovalUpdate(
  daemonPublicKeyHex: string,
  payload: ApprovalUpdateInput,
): EncryptedApprovalUpdateEnvelope {
  const daemonPublicKey = hexToBytes(daemonPublicKeyHex.replace(/^0x/u, ''));
  const ephemeralSecretKey = x25519.utils.randomPrivateKey();
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralSecretKey);
  const sharedSecret = x25519.getSharedSecret(ephemeralSecretKey, daemonPublicKey);
  const nonce = randomBytes(24);
  const plaintext = utf8ToBytes(JSON.stringify(payload));
  const cipher = xchacha20poly1305(sharedSecret, nonce);
  const ciphertext = cipher.encrypt(plaintext);

  return {
    algorithm: 'x25519-xchacha20poly1305-v1',
    ephemeralPublicKey: bytesToHex(ephemeralPublicKey),
    nonce: bytesToHex(nonce),
    ciphertext: bytesToHex(ciphertext),
  };
}
