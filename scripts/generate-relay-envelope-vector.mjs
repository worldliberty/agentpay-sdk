#!/usr/bin/env node

// Generates the cross-language relay envelope v2 test vector consumed by
// crates/vault-daemon/src/tests.rs. The envelope is sealed with the web console's
// apps/web/src/lib/crypto.ts implementation so the Rust daemon decrypts exactly
// what the browser produces.
//
// Usage: node scripts/generate-relay-envelope-vector.mjs [--check]

import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { register } from 'tsx/esm/api';

const repoRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const cryptoModulePath = path.join(repoRoot, 'apps', 'web', 'src', 'lib', 'crypto.ts');
const fixturePath = path.join(
  repoRoot,
  'crates',
  'vault-daemon',
  'tests',
  'fixtures',
  'relay_envelope_v2.json',
);

register();
const { RELAY_ENVELOPE_ALGORITHM, relayEnvelopeAad, sealApprovalUpdate } = await import(
  pathToFileURL(cryptoModulePath).href
);
const { x25519 } = createRequire(path.join(repoRoot, 'apps', 'web', 'package.json'))(
  '@noble/curves/ed25519',
);

const fill = (byte, length) => new Uint8Array(length).fill(byte);
const toHex = (bytes) => Buffer.from(bytes).toString('hex');

// Fixed, test-only key material. Never use these values outside tests.
const daemonPrivateKey = fill(0x11, 32);
const ephemeralSecretKey = fill(0x22, 32);
const nonce = fill(0x33, 24);
const daemonPublicKeyHex = toHex(x25519.getPublicKey(daemonPrivateKey));

const payload = {
  approvalId: '6f1b8f5e-3a52-4c1e-9d0b-2b7f2f0b9a11',
  daemonId: 'ab'.repeat(32),
  vaultPassword: 'test-vector-vault-password',
  decision: 'approve',
  note: 'relay envelope v2 cross-language vector',
};

const envelope = sealApprovalUpdate(daemonPublicKeyHex, payload, {
  ephemeralSecretKey,
  nonce,
});

const vector = {
  description:
    'Relay manual-approval envelope v2 sealed by apps/web/src/lib/crypto.ts. Regenerate with node scripts/generate-relay-envelope-vector.mjs.',
  algorithm: RELAY_ENVELOPE_ALGORITHM,
  daemonPrivateKeyHex: toHex(daemonPrivateKey),
  daemonPublicKeyHex,
  ephemeralSecretKeyHex: toHex(ephemeralSecretKey),
  approvalId: payload.approvalId,
  daemonId: payload.daemonId,
  aadHex: toHex(relayEnvelopeAad(payload.approvalId, payload.daemonId)),
  plaintext: JSON.stringify(payload),
  envelope,
};

const serialized = `${JSON.stringify(vector, null, 2)}\n`;

if (process.argv.includes('--check')) {
  const existing = fs.existsSync(fixturePath) ? fs.readFileSync(fixturePath, 'utf8') : '';
  if (existing !== serialized) {
    console.error(`relay envelope vector is stale: ${path.relative(repoRoot, fixturePath)}`);
    process.exit(1);
  }
  console.log('relay envelope vector is up to date');
} else {
  fs.mkdirSync(path.dirname(fixturePath), { recursive: true });
  fs.writeFileSync(fixturePath, serialized);
  console.log(`wrote ${path.relative(repoRoot, fixturePath)}`);
}
