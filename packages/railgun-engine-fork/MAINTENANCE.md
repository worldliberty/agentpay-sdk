# Maintaining the Railgun engine fork

This package will hold AgentPay's internal fork of
[`@railgun-community/engine`](https://github.com/Railgun-Community/engine).
The current revision is a **skeleton only**; the actual fork lands in
Track 3. This document captures the rules the fork must follow once the
~10k-line vendoring is in.

## Upstream tracked

- **Repository:** https://github.com/Railgun-Community/engine
- **NPM package:** `@railgun-community/engine`

The fork tracks tagged releases on `main`. We never bump in the middle
of a release cycle, and we never bump to an untagged commit.

## Pinning strategy

1. Snapshot a single upstream tag at a time. The exact tag lives in the
   `UPSTREAM_PIN` block immediately below. Never carry partial cherry-
   picks across tags — rebase the full delta or stay pinned.
2. Rebase **quarterly** by default (4 times per year). Security advisories
   on `@railgun-community/engine` move the next rebase forward.
3. When a rebase lands, update `UPSTREAM_PIN`, regenerate the diff
   summary, and re-run `cargo test --workspace` plus the TypeScript
   suite end-to-end.

```text
UPSTREAM_PIN
  tag: <unset — Track 3 vendoring pending>
  commit: <unset>
  rebased-at: <unset>
```

## What we modify

The fork's whole purpose is to replace every code path that touches a
raw Railgun spending or viewing key with a call into the AgentPay Rust
daemon. We do not need to enumerate every line that changes — the
categories below are the source of truth.

- **`Wallet.signTransaction*`** — every variant that builds a Railgun
  transaction with a spending key. These become RPC calls into the
  daemon's witness-bundle endpoint; the engine never sees the spending
  key.
- **`Wallet.decryptNote*`** — every code path that trial-decrypts an
  on-chain commitment with the viewing key. These delegate to the
  daemon's note-decryption endpoint.
- **Nullifier derivation inside `Note.*`** — every callsite that hashes
  a note with the spending key to produce a Poseidon nullifier. These
  delegate to the daemon's nullifier endpoint.

Anywhere the upstream code reads a spending key, viewing key, or master
seed directly is a fork-divergence point. If a rebase reintroduces a
direct key read, that change must be re-replaced before the rebase is
considered done.

## Daemon RPC surface

The fork calls into the new `railgun_*` methods on the
`VaultSignerBackend` trait. The authoritative declarations live in
[`crates/vault-signer/src/lib.rs`](../../crates/vault-signer/src/lib.rs)
under the comment "Returns the encoded Railgun shielded address". The
methods are:

- `railgun_master_public_key` — derives and returns the encoded
  `0zk1...` shielded address for a vault key.
- `railgun_viewing_public_key` — returns the X25519 viewing public key
  and Baby Jubjub spending master public key used for trial-decrypting
  notes and pinning spend authority in zk witnesses.
- `railgun_compute_nullifier` — returns the Poseidon nullifier for a
  spent note without ever exposing the spending key.
- `railgun_decrypt_note` — attempts to trial-decrypt one on-chain
  commitment ciphertext.
- `railgun_witness_inputs` — bundles per-note nullifiers, per-note
  Baby Jubjub spend signatures, and the spend authority public key for
  the snarkjs prover.

These are surfaced through the admin / agent transports in the same
way as the existing signer entry points; the fork must not assume any
private state lives inside the engine process.

As of this revision the daemon backends return
`SignerError::Unsupported("... is not yet implemented (Track 2 Phase B)")`
for all five methods. The TypeScript admin setup flow (Track 6)
detects that specific error and treats it as "Railgun derivation
pending Phase B" rather than failing.

## Circuit artifacts

The Railgun proving system requires per-circuit `.wasm` and `.zkey`
artifacts. The policy is:

- Artifacts live under `circuits/<circuit-name>/<version>/` inside this
  package. Each version directory is immutable once published.
- The artifact version is pinned per upstream tag. When the upstream
  rebase lands we either reuse the existing artifact version (if the
  circuit input layout is unchanged) or bump to the next version that
  matches the new layout.
- We never load an artifact whose SHA-256 differs from the expected
  hash recorded in `circuits/<circuit-name>/<version>/MANIFEST.json`.
- Artifacts are not committed as part of this skeleton — they land
  alongside the vendored engine in Track 3.

## Risk

- **Largest risk:** silent divergence from upstream. An upstream change
  that re-routes a spend through a path we did not replace would leak
  the spending key. Every rebase must include a fresh grep for direct
  spending/viewing/master-seed reads outside the daemon RPC layer.
- **Second risk:** circuit / artifact mismatch. Proofs built against
  the wrong artifact silently fail on-chain. The MANIFEST.json hash
  check is the single source of truth.
- **Third risk:** rebase fatigue. Skipping a quarterly rebase
  compounds; the more upstream drift, the harder the next rebase. The
  cadence is firm.

## Rebase cadence

- Default: once per calendar quarter.
- Mandatory: within 14 days of a CVE on `@railgun-community/engine`.
- Optional: any time upstream lands a circuit upgrade we want to
  consume.

Each rebase produces a commit message referencing the old and new
`UPSTREAM_PIN` values, a short diff summary, and a checklist confirming
the key-access categories above were re-replaced.
