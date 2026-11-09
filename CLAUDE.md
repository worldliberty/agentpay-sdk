# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

AgentPay is a self-custodial, policy-gated payments service for AI agents on macOS and Linux: a
root signer daemon, an unprivileged payments daemon, and a small TypeScript Ink client that talks
to them over a documented JSON-RPC API (API `1.1.0`). Architecture overview:
`docs/architecture.md`.

## Workspace (`crates/`)

| Crate | Responsibility |
|---|---|
| `agentpay-api` | The public wire contract (JSON-RPC methods, types, errors, `api_version`). No I/O. Generates `docs/api/schema.json` and `client/src/generated/*.ts`. Spec: `docs/daemon-api.md`. |
| `agentpay-domain` | Domain model: actions (EVM, Solana, Tempo, EIP-712/3009), policies, keys, addresses, approvals. |
| `agentpay-policy` | Policy evaluation engine over domain types. |
| `agentpay-signer` | Signer backends: software (k256, ed25519) and Linux TPM seal/unseal. |
| `agentpay-signerd` | Transport-agnostic daemon core: authorization, policy checks, signing, nonces, manual approvals, admin auth (root peer, Secure Enclave challenge, leases), encrypted state (HKDF-SHA256 + XChaCha20-Poly1305) keyed by the machine state secret; Argon2 is only used to open legacy vault-password files during migration. |
| `agentpay-signerd-cli` | Daemon binaries `agentpay-daemon` and `agentpay-system-keychain` (binary names are fixed by the install layout). |
| `agentpay-paymentd` | Unprivileged payments service (runs as `_agentpay`/`agentpay`, refuses root): own socket, config (`config.json` in its state dir), delegated agent auth via signerd `AuthenticateAgent`, `AgentSigner` (nonces, signing, bounded manual-approval wait). Feature families plug in as `features/<family>.rs` + one arm in `dispatch.rs`; see "Adding a paymentd method" in `docs/daemon-api.md`. |
| `agentpay-transport` | Unix socket server/client for any `RpcService` (signerd, paymentd), length-prefixed framing, peer-uid checks, root- and service-owned socket trust. |
| `agentpay-agent-sdk` | Agent-side client (`AgentOperations` / `AgentSdk`) over any `KeyManagerDaemonApi`. |
| `agentpay-setup` | Privileged installer run under `sudo`: binaries, machine secret, service account, launchd/systemd units for signerd and paymentd (paymentd's uid on signerd's agent allowlist), migration from vault-password installs. |
| `xtask` | Repo tooling (`cargo xtask ...`). |

Other directories: `examples/sample-llm` (an example third-party tool: streams LLM answers from an MPP merchant through `agentpay proxy`, decoding the CLI's `--json` with `agentpay-api`; a workspace member, see its README), `native/macos/AgentPayAuth.swift` (the `agentpay-auth` Secure Enclave admin
credential helper, built by xtask), `client/` (the `agentpay` Ink client and CLI; see
`client/README.md`), `docs/` (architecture, API spec and schema), `scripts/launchd`,
`scripts/systemd` (service runner scripts), `skills/` (agent skill packs and adapters).

## Commands

```bash
just build              # cargo build --workspace
just test               # cargo test --workspace
just lint               # fmt --check, clippy -D warnings, file-length, no-JS, gen-api --check, API docs
just dev                # fmt, lint, test
cargo test -p agentpay-signerd               # one crate
cargo xtask gen-api [--check]                # regenerate (or drift-check) schema + TS types
cargo xtask check-file-length                # every .rs/.ts/.tsx file <= 1000 lines
cargo xtask check-no-js                      # no .js/.mjs/.cjs/.jsx outside build output
cargo xtask build-macos-auth                 # build agentpay-auth (Swift) into target/
cargo xtask test-macos-auth                  # its end-to-end checks; AGENTPAY_SE_TESTS=1 adds Secure Enclave checks
RUSTDOCFLAGS="-D warnings" cargo doc -p agentpay-api --no-deps
just client-install && just client-test && just client-lint   # client: npm ci, tsc + Vitest, Biome
```

The toolchain is pinned in `rust-toolchain.toml`; keep `rust-version` in the root `Cargo.toml` in
sync (CI checks it). CI (`.github/workflows/ci.yml`) runs lint and tests on macOS and Linux.

## Testing

- Every crate has its own unit tests (`cargo test --workspace`); `xtask` tests its own helpers.
- `agentpay-api` fixtures under `crates/agentpay-api/fixtures/` are checked against the Rust
  types and reproduced by the daemon in `agentpay-signerd`'s `api_examples` tests.
- `agentpay-setup` runs its step logic against an in-memory fake `System`; no root needed.
- Secure Enclave checks never run on CI (no Secure Enclave) and never prompt.
- The client (`client/`) uses Vitest with `ink-testing-library` and a fake daemon that answers
  with the `agentpay-api` fixtures.

## Conventions

- **No JavaScript.** Only `.rs`, `.ts` and `.tsx`; repo tooling goes in `xtask`.
- **Files stay under 1,000 lines.** Split into modules instead; there are no exceptions.
- **`agentpay-api` is a public contract.** `#![deny(missing_docs)]`; document purpose, units,
  permissions, errors and side effects. Update `docs/daemon-api.md` and run
  `cargo xtask gen-api` with every change.
- **Secrets only travel on stdin or pipes**, never in arguments or environment variables. Use
  `zeroize` for secret memory. No `unwrap` in daemon code paths.
- **No vault password.** Daemon state is keyed by a machine secret that `agentpay-setup` creates.
  Admin auth on macOS is a Secure Enclave key (`.userPresence`: Touch ID or login password)
  through `agentpay-auth`; the daemon verifies its challenge signatures with p256. Everywhere
  else (Linux, SSH) admin auth is `sudo`: the daemon trusts peer euid 0. The legacy
  vault-password state is only read for one-time migration.
- Keep the `agentpay-auth` key reload on CryptoKit; reloading through `SecKeyCreateWithData`
  skips the access-control check (`test-macos-auth` guards this).
- `clippy -D warnings` and rustfmt are enforced.

## Status

- **The rewrite is done** (release 1.0.0, API 1.0.0; API 1.1.0 adds `AddToken`): Railgun, XPC, Windows TPM, Secure Enclave
  wallet, relay/web, the TypeScript CLI, and the legacy Rust CLIs are removed; signerd, paymentd
  (chains, x402, MPP, paying proxy, wallet and funding, telemetry), `agentpay-setup`,
  `agentpay-auth`, and the Ink client are in place.
- The workspace is on one alloy line (alloy 2.x / alloy-core 1.7, the one `mpp` 0.19 and
  `x402-types` 2.0 use); keep them in step.
- Stripe Link and Bitrefill are removed; there are no `link` or `bitrefill` commands.
- The API is a published contract: follow the versioning and deprecation policy in
  `docs/daemon-api.md` for every wire change.

## Instructions

- **Always** switch to _Plan Mode_ whenever a complex task is being requested (3 or more steps in achieving it qualifies a task as being complex)
- **Consistency is key**, always write new code in the style of the already existing code, following the already availalble patterns
