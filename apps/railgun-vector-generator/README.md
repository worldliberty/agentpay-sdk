# @worldlibertyfinancial/railgun-vector-generator

Deterministic test-vector generator for the Track 2 Phase B Rust crypto port.

## Why this exists

Railgun's cryptography is a stack of primitives that are easy to get wrong in
subtle, security-critical ways: a non-standard hardened-only BIP32 scheme that
HMACs ASCII-hex pre-images, an iden3 EdDSA-Poseidon variant with no vetted
Rust crate, X25519 ECDH followed by AES-256-GCM with a non-standard 16-byte
IV, and Poseidon constants that match circomlibjs exactly. Bit-equality with
the reference implementation is the only practical correctness check.

This package imports the upstream `@railgun-community/engine` package, runs
it against a fixed mnemonic, and dumps the resulting derivation chain, key
material, address encoding, nullifiers, AES-GCM ciphertexts, and EdDSA
signatures to a JSON fixture. The Rust crypto port asserts byte-equality
against that fixture in its unit tests.

## Output

The generator writes
`../../crates/vault-signer/tests/fixtures/railgun_vectors.json`.

The fixture is **committed to the repository** so:

- Rust CI does not need a Node toolchain to run the crypto unit tests.
- Reproducing the vectors from scratch (running `pnpm run generate` again
  and diffing the output against the checked-in file) is the only "did this
  get tampered with" check we need.

## Running

```bash
pnpm install
pnpm --filter @worldlibertyfinancial/railgun-vector-generator run generate
git diff --exit-code crates/vault-signer/tests/fixtures/railgun_vectors.json
```

The `git diff` step must produce no output. If it does, either upstream
`@railgun-community/engine` changed its primitives (rare; should track a
version bump) or the generator script changed (intentional and should be
reviewed alongside the fixture).

## Determinism

Random IVs and ephemeral keys in note encryption are replaced with fixed
inputs (the generator monkey-patches the engine's randomness source). All
other primitives are pure functions of the fixed mnemonic and a small set of
fixed sample inputs.

## NOT for runtime

This package is in `devDependencies` only on the workspace level — never
import it from the daemon, CLI, or any runtime path. It exists solely to
produce a JSON file.
