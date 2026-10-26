/**
 * Deterministic Railgun engine test-vector generator.
 *
 * Imports the upstream `@railgun-community/engine` package and dumps a JSON
 * fixture with every primitive output the Track 2 Phase B Rust port needs to
 * cross-check. The fixture is committed to the repo so Rust CI does not need
 * a Node toolchain to run the crypto unit tests.
 *
 * NEVER imported at runtime — this package lives in devDependencies only.
 *
 * ## Import strategy
 *
 * The engine's `package.json` declares `"exports": { ".": "./dist/index.js" }`,
 * which blocks deep subpath imports. The root entrypoint only re-exports a
 * narrow subset of what we need (it omits `WalletNode`, `deriveNodes`,
 * `encodeAddress`, `AES`, `signEDDSA`, `verifyEDDSA`, `getSharedSymmetricKey`,
 * `poseidon`). We bypass the exports map with absolute `file://` URLs against
 * `node_modules/@railgun-community/engine/dist/...` — this is a deliberate
 * workaround that only this dev-only generator package needs. Runtime code
 * never does this.
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// Resolve the engine's installed location so we can build file URLs to the
// deep dist paths. `createRequire` gives us a require() bound to this file,
// which `require.resolve` then uses to find the engine entrypoint regardless
// of which workspace directory `pnpm install` ended up planting it in.
const localRequire = createRequire(import.meta.url);
const ENGINE_DIST = dirname(localRequire.resolve('@railgun-community/engine'));
const ENGINE_PACKAGE_ROOT = dirname(ENGINE_DIST);

async function engineImport<T>(relative: string): Promise<T> {
  return import(pathToFileURL(resolve(ENGINE_DIST, relative)).href) as Promise<T>;
}

// -- Engine subpath imports (subpath → real module shape via dynamic import). --

const { Mnemonic } = await engineImport<{
  Mnemonic: { toSeed(mnemonic: string, password?: string): Promise<string> };
}>('key-derivation/bip39.js');

const { WalletNode, deriveNodes } = await engineImport<{
  WalletNode: {
    getMasterPublicKey(spendingPubkey: [bigint, bigint], nullifyingKey: bigint): bigint;
  };
  deriveNodes: (
    mnemonic: string,
    index?: number,
  ) => {
    spending: WalletNodeInstance;
    viewing: WalletNodeInstance;
  };
}>('key-derivation/wallet-node.js');

interface WalletNodeInstance {
  getSpendingKeyPair(): { privateKey: Uint8Array; pubkey: [bigint, bigint] };
  getViewingKeyPair(): Promise<{ privateKey: Uint8Array; pubkey: Uint8Array }>;
  getNullifyingKey(): Promise<bigint>;
}

const { encodeAddress } = await engineImport<{
  encodeAddress(addressData: {
    masterPublicKey: bigint;
    viewingPublicKey: Uint8Array;
    chain?: { type: number; id: number };
  }): string;
}>('key-derivation/bech32.js');

const { poseidon } = await engineImport<{
  poseidon: (inputs: bigint[]) => bigint;
}>('utils/poseidon.js');

const { AES } = await engineImport<{
  AES: {
    encryptGCM(plaintext: string[], key: Uint8Array): { iv: string; tag: string; data: string[] };
    decryptGCM(encrypted: { iv: string; tag: string; data: string[] }, key: Uint8Array): string[];
  };
}>('utils/encryption/aes.js');

const { signEDDSA, verifyEDDSA, getSharedSymmetricKey, getPublicViewingKey } = await engineImport<{
  signEDDSA(privateKey: Uint8Array, message: bigint): { R8: [bigint, bigint]; S: bigint };
  verifyEDDSA(
    message: bigint,
    signature: { R8: [bigint, bigint]; S: bigint },
    pubkey: [bigint, bigint],
  ): boolean;
  getSharedSymmetricKey(
    privateKeyA: Uint8Array,
    blindedPublicKeyB: Uint8Array,
  ): Promise<Uint8Array | undefined>;
  getPublicViewingKey(privateViewingKey: Uint8Array): Promise<Uint8Array>;
}>('utils/keys-utils.js');

const { TransactNote } = await engineImport<{
  TransactNote: {
    getNullifier(nullifyingKey: bigint, leafIndex: number): bigint;
  };
}>('note/transact-note.js');

const ByteUtilsModule = await engineImport<{
  ByteUtils: { randomHex(length: number): string };
}>('utils/bytes.js');
const { ByteUtils } = ByteUtilsModule;

// -----------------------------------------------------------------------------
// Fixtures: a single fixed mnemonic + small set of sample inputs.
// -----------------------------------------------------------------------------

const FIXTURE_MNEMONIC =
  // Standard BIP39 sample mnemonic. NEVER load funds into any wallet derived
  // from this — it is public knowledge.
  'test test test test test test test test test test test junk';

const FIXTURE_PASSWORD = '';

// Sample wallet indices to derive. Covers the off-by-one corners and a wide
// index to flush out any 32-bit truncation bugs in the Rust port.
const FIXTURE_INDICES = [0, 1, 7, 1024] as const;

// Sample leaf indices for nullifier computation.
const FIXTURE_LEAF_INDICES = [0n, 1n, 7n, 42n, 1_000_000n] as const;

// Fixed plaintext (three 32-byte field elements) for AES-GCM round-trip.
// Mirrors the on-wire shape Railgun uses for note payloads.
const FIXTURE_AES_PLAINTEXT: readonly [string, string, string] = [
  '11'.repeat(32),
  '22'.repeat(32),
  '33'.repeat(32),
];

// Fixed 16-byte IV. AES-GCM with a 16-byte IV is non-standard (NIST recommends
// 12). Railgun's `AES.encryptGCM` defaults to a 16-byte random IV — we patch
// `ByteUtils.randomHex` below to force this exact IV during generation.
const FIXTURE_AES_IV_HEX = 'ab'.repeat(16);

// Fixed viewing private keys used to derive a valid X25519 ECDH pair. The
// receiver public key is computed at generation time via `getPublicViewingKey`
// (raw bytes like `0x02..02` are not on the curve and produce undefined shared
// keys — the engine accepts only proper Ed25519/Curve25519 pubkeys here).
const FIXTURE_SENDER_VIEWING_PRIV_HEX = '01'.repeat(32);
const FIXTURE_RECEIVER_VIEWING_PRIV_HEX = '02'.repeat(32);

// EdDSA message inputs (raw scalars; the actual signed value is
// `poseidon([scalar])` so Rust signs in the same order).
const FIXTURE_EDDSA_MESSAGES: readonly bigint[] = [0n, 1n, 0x1234567890abcdef1234567890abcdefn];

// -----------------------------------------------------------------------------
// Helpers: byte / bigint encoding for JSON-friendly hex output.
// -----------------------------------------------------------------------------

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function bigintToHex(value: bigint, byteLength = 32): string {
  if (value < 0n) {
    throw new Error(`negative bigint cannot be serialized as fixed-length hex: ${value}`);
  }
  const hex = value.toString(16);
  if (hex.length > byteLength * 2) {
    throw new Error(`bigint exceeds ${byteLength}-byte canonical encoding: ${value}`);
  }
  return hex.padStart(byteLength * 2, '0');
}

// -----------------------------------------------------------------------------
// Determinism patch: lock ByteUtils.randomHex so AES-GCM produces a stable IV.
// -----------------------------------------------------------------------------

const originalRandomHex = ByteUtils.randomHex;
ByteUtils.randomHex = (length: number): string => {
  if (length === 16) {
    return FIXTURE_AES_IV_HEX;
  }
  // Any other length signals a code path we did not anticipate — fail loudly
  // so a future fixture extension does not silently produce non-deterministic
  // output.
  throw new Error(
    `vector generator only patches randomHex(16); generator asked for length ${length}. ` +
      'Update the generator to handle this case explicitly before extending the fixture.',
  );
};

process.on('exit', () => {
  ByteUtils.randomHex = originalRandomHex;
});

// -----------------------------------------------------------------------------
// Vector generation.
// -----------------------------------------------------------------------------

interface DerivedWalletVector {
  index: number;
  spending: {
    derivationPath: string;
    chainKeyHex: string;
    chainCodeHex: string;
    privateKeyHex: string;
    publicKey: { xHex: string; yHex: string };
  };
  viewing: {
    derivationPath: string;
    chainKeyHex: string;
    chainCodeHex: string;
    privateKeyHex: string;
    publicKeyHex: string;
  };
  nullifyingKeyHex: string;
  masterPublicKeyHex: string;
  address: string;
  nullifiers: Array<{ leafIndex: string; nullifierHex: string }>;
  eddsaSignatures: Array<{
    messageScalarHex: string;
    messageHashHex: string;
    signature: { r8XHex: string; r8YHex: string; sHex: string };
    verified: boolean;
  }>;
}

interface PoseidonVector {
  description: string;
  inputsHex: string[];
  outputHex: string;
}

interface AesGcmVector {
  description: string;
  sharedKeyHex: string;
  ivHex: string;
  plaintextChunksHex: string[];
  ciphertextChunksHex: string[];
  tagHex: string;
}

interface SharedKeyVector {
  description: string;
  senderViewingPrivHex: string;
  receiverViewingPrivHex: string;
  // Derived from `receiverViewingPrivHex` via the engine's
  // `getPublicViewingKey`. Surfaced so the Rust port can either re-derive it
  // from the privkey or use it directly as a fixed point for ECDH.
  receiverViewingPubHex: string;
  sharedKeyHex: string;
}

// Full ECDH+AES round-trip vector for `railgun_decrypt_note`. The receiver
// re-derives the shared key from (`receiverViewingPrivHex`,
// `senderEphemeralPubHex`), then AES-GCM-decrypts the 3 chunks. Authenticates
// against the same engine code path the on-chain commitment events use.
interface NoteEncryptionVector {
  description: string;
  senderViewingPrivHex: string;
  // The "ephemeral" point the receiver sees on-chain. For this synthetic
  // vector we publish the sender's static viewing public key directly (no
  // blinding) — Railgun's real broadcaster path adds blinding helpers, but
  // those are pure-data and live in the sidecar layer.
  senderEphemeralPubHex: string;
  receiverViewingPrivHex: string;
  receiverViewingPubHex: string;
  sharedKeyHex: string;
  ivHex: string;
  tagHex: string;
  plaintextChunksHex: string[];
  ciphertextChunksHex: string[];
}

interface VectorFile {
  schemaVersion: 1;
  generatedBy: string;
  engineVersion: string;
  mnemonic: { mnemonic: string; password: string; seedHex: string };
  wallets: DerivedWalletVector[];
  poseidonSamples: PoseidonVector[];
  sharedKeySamples: SharedKeyVector[];
  aesGcmSamples: AesGcmVector[];
  noteEncryptionSamples: NoteEncryptionVector[];
}

function derivationPath(coin: number, index: number): string {
  return `m/${coin}'/1984'/0'/0'/${index}'`;
}

async function deriveWalletVector(index: number): Promise<DerivedWalletVector> {
  const { spending, viewing } = deriveNodes(FIXTURE_MNEMONIC, index);

  // chainKey + chainCode are private in the type definition. Read them
  // reflectively for the fixture; the Rust port needs both to cross-check
  // intermediate BIP32 nodes, not just leaf keys.
  const spendingRaw = spending as unknown as { chainKey: string; chainCode: string };
  const viewingRaw = viewing as unknown as { chainKey: string; chainCode: string };

  const spendingKeyPair = spending.getSpendingKeyPair();
  const viewingKeyPair = await viewing.getViewingKeyPair();
  const nullifyingKey = await viewing.getNullifyingKey();
  const masterPublicKey = WalletNode.getMasterPublicKey(spendingKeyPair.pubkey, nullifyingKey);
  const address = encodeAddress({
    masterPublicKey,
    viewingPublicKey: viewingKeyPair.pubkey,
    chain: undefined,
  });

  const nullifiers = FIXTURE_LEAF_INDICES.map((leafIndex) => ({
    leafIndex: leafIndex.toString(),
    nullifierHex: bigintToHex(TransactNote.getNullifier(nullifyingKey, Number(leafIndex))),
  }));

  const eddsaSignatures = FIXTURE_EDDSA_MESSAGES.map((messageScalar) => {
    const messageHash = poseidon([messageScalar]);
    const signature = signEDDSA(spendingKeyPair.privateKey, messageHash);
    const verified = verifyEDDSA(messageHash, signature, spendingKeyPair.pubkey);
    return {
      messageScalarHex: bigintToHex(messageScalar),
      messageHashHex: bigintToHex(messageHash),
      signature: {
        r8XHex: bigintToHex(signature.R8[0]),
        r8YHex: bigintToHex(signature.R8[1]),
        sHex: bigintToHex(signature.S),
      },
      verified,
    };
  });

  return {
    index,
    spending: {
      derivationPath: derivationPath(44, index),
      chainKeyHex: spendingRaw.chainKey,
      chainCodeHex: spendingRaw.chainCode,
      privateKeyHex: bytesToHex(spendingKeyPair.privateKey),
      publicKey: {
        xHex: bigintToHex(spendingKeyPair.pubkey[0]),
        yHex: bigintToHex(spendingKeyPair.pubkey[1]),
      },
    },
    viewing: {
      derivationPath: derivationPath(420, index),
      chainKeyHex: viewingRaw.chainKey,
      chainCodeHex: viewingRaw.chainCode,
      privateKeyHex: bytesToHex(viewingKeyPair.privateKey),
      publicKeyHex: bytesToHex(viewingKeyPair.pubkey),
    },
    nullifyingKeyHex: bigintToHex(nullifyingKey),
    masterPublicKeyHex: bigintToHex(masterPublicKey),
    address,
    nullifiers,
    eddsaSignatures,
  };
}

function buildPoseidonSamples(): PoseidonVector[] {
  const cases: Array<{ description: string; inputs: bigint[] }> = [
    { description: 'poseidon([1])', inputs: [1n] },
    { description: 'poseidon([1, 2])', inputs: [1n, 2n] },
    { description: 'poseidon([1, 2, 3])', inputs: [1n, 2n, 3n] },
    {
      description: 'poseidon([0xdeadbeef, 0xcafebabe])',
      inputs: [0xdeadbeefn, 0xcafebaben],
    },
  ];
  return cases.map(({ description, inputs }) => ({
    description,
    inputsHex: inputs.map((value) => bigintToHex(value)),
    outputHex: bigintToHex(poseidon(inputs)),
  }));
}

async function buildSharedKeySamples(): Promise<SharedKeyVector[]> {
  const senderPriv = Uint8Array.from(Buffer.from(FIXTURE_SENDER_VIEWING_PRIV_HEX, 'hex'));
  const receiverPriv = Uint8Array.from(Buffer.from(FIXTURE_RECEIVER_VIEWING_PRIV_HEX, 'hex'));
  const receiverPub = await getPublicViewingKey(receiverPriv);
  const sharedKey = await getSharedSymmetricKey(senderPriv, receiverPub);
  if (sharedKey === undefined) {
    throw new Error('getSharedSymmetricKey returned undefined for the fixture pair');
  }
  return [
    {
      description:
        'getSharedSymmetricKey(senderPriv=0x01..01, receiverPub=getPublicViewingKey(0x02..02))',
      senderViewingPrivHex: FIXTURE_SENDER_VIEWING_PRIV_HEX,
      receiverViewingPrivHex: FIXTURE_RECEIVER_VIEWING_PRIV_HEX,
      receiverViewingPubHex: bytesToHex(receiverPub),
      sharedKeyHex: bytesToHex(sharedKey),
    },
  ];
}

function buildAesGcmSamples(sharedKeyHex: string): AesGcmVector[] {
  const sharedKey = Uint8Array.from(Buffer.from(sharedKeyHex, 'hex'));
  const ct = AES.encryptGCM([...FIXTURE_AES_PLAINTEXT], sharedKey);
  return [
    {
      description: `AES-256-GCM, 16-byte IV, sharedKey=${sharedKeyHex.slice(0, 16)}…`,
      sharedKeyHex,
      ivHex: ct.iv,
      plaintextChunksHex: [...FIXTURE_AES_PLAINTEXT],
      ciphertextChunksHex: ct.data,
      tagHex: ct.tag,
    },
  ];
}

async function buildNoteEncryptionSamples(): Promise<NoteEncryptionVector[]> {
  // Reuses the same sender/receiver viewing keypair the shared-key sample
  // builds — the on-wire-format Rust port can drive the entire chain from a
  // single shared (sender_priv, receiver_priv) → ECDH → AES path.
  const senderPriv = Uint8Array.from(Buffer.from(FIXTURE_SENDER_VIEWING_PRIV_HEX, 'hex'));
  const receiverPriv = Uint8Array.from(Buffer.from(FIXTURE_RECEIVER_VIEWING_PRIV_HEX, 'hex'));
  const senderPub = await getPublicViewingKey(senderPriv);
  const receiverPub = await getPublicViewingKey(receiverPriv);
  // The sender computes the shared key against the receiver's pubkey when
  // encrypting; the receiver re-derives the SAME key against the sender's
  // ephemeral pubkey when decrypting. Verify both directions produce the
  // same bytes so the Rust port can pick either direction freely.
  const senderSideShared = await getSharedSymmetricKey(senderPriv, receiverPub);
  const receiverSideShared = await getSharedSymmetricKey(receiverPriv, senderPub);
  if (senderSideShared === undefined || receiverSideShared === undefined) {
    throw new Error('getSharedSymmetricKey returned undefined for the note-encryption pair');
  }
  if (bytesToHex(senderSideShared) !== bytesToHex(receiverSideShared)) {
    throw new Error(
      'ECDH(senderPriv, receiverPub) and ECDH(receiverPriv, senderPub) disagreed — ' +
        'the Rust port relies on this symmetry; investigate before regenerating',
    );
  }
  const ct = AES.encryptGCM([...FIXTURE_AES_PLAINTEXT], senderSideShared);
  return [
    {
      description: 'note round-trip: ECDH(senderPriv, receiverPub) → SHA-256 → AES-256-GCM',
      senderViewingPrivHex: FIXTURE_SENDER_VIEWING_PRIV_HEX,
      senderEphemeralPubHex: bytesToHex(senderPub),
      receiverViewingPrivHex: FIXTURE_RECEIVER_VIEWING_PRIV_HEX,
      receiverViewingPubHex: bytesToHex(receiverPub),
      sharedKeyHex: bytesToHex(senderSideShared),
      ivHex: ct.iv,
      tagHex: ct.tag,
      plaintextChunksHex: [...FIXTURE_AES_PLAINTEXT],
      ciphertextChunksHex: ct.data,
    },
  ];
}

function loadEngineVersion(): string {
  // The engine's `exports` map blocks `require('@railgun-community/engine/package.json')`,
  // so we read the manifest off disk directly. Safe because we already
  // resolved the engine's install path above.
  const manifestPath = resolve(ENGINE_PACKAGE_ROOT, 'package.json');
  const pkg = JSON.parse(readFileSync(manifestPath, 'utf8')) as { version?: string };
  return pkg.version ?? 'unknown';
}

async function main(): Promise<void> {
  const engineVersion = loadEngineVersion();
  const seedHex = await Mnemonic.toSeed(FIXTURE_MNEMONIC, FIXTURE_PASSWORD);

  const wallets: DerivedWalletVector[] = [];
  for (const index of FIXTURE_INDICES) {
    wallets.push(await deriveWalletVector(index));
  }

  const sharedKeySamples = await buildSharedKeySamples();
  const firstSharedKey = sharedKeySamples[0];
  if (firstSharedKey === undefined) {
    throw new Error('buildSharedKeySamples produced no entries; cannot build AES-GCM sample');
  }
  const aesGcmSamples = buildAesGcmSamples(firstSharedKey.sharedKeyHex);
  const noteEncryptionSamples = await buildNoteEncryptionSamples();
  const poseidonSamples = buildPoseidonSamples();

  const vectors: VectorFile = {
    schemaVersion: 1,
    generatedBy: '@worldlibertyfinancial/railgun-vector-generator',
    engineVersion,
    mnemonic: {
      mnemonic: FIXTURE_MNEMONIC,
      password: FIXTURE_PASSWORD,
      seedHex,
    },
    wallets,
    poseidonSamples,
    sharedKeySamples,
    aesGcmSamples,
    noteEncryptionSamples,
  };

  const here = dirname(fileURLToPath(import.meta.url));
  const outputPath = resolve(
    here,
    '../../../crates/vault-signer/tests/fixtures/railgun_vectors.json',
  );
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(vectors, null, 2)}\n`);
  process.stdout.write(`wrote ${outputPath}\n`);
}

await main();
