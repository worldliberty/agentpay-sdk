# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
# Install dependencies (also builds Rust binaries via postinstall when cargo is on PATH;
# without cargo, postinstall warns and exits 0 unless AGENTPAY_REQUIRE_RUST_INSTALL=1)
pnpm install

# Build everything (Turbo + tsup CLI bundle)
npm run build

# Full check (cargo test compile + turbo typecheck)
npm run check

# TypeScript type checking
npm run typecheck

# Lint (Biome)
npm run lint
npm run lint:fix          # auto-fix

# Run all TypeScript integration tests (isolated HOME/AGENTPAY_HOME/TMPDIR sandbox under the
# system temp dir; sudo, launchctl, and systemctl are stubbed out)
npm run test:ts

# Run a single TypeScript test through the same isolated harness (tsx, not --experimental-strip-types)
node scripts/run-ts-tests.mjs test/<file>.test.mjs

# Run Rust tests
cargo test --workspace

# Run a single Rust crate's tests
cargo test -p vault-domain

# Build/install Rust binaries to ~/.agentpay/bin
npm run install:rust-binaries

# Package-specific commands (vitest)
pnpm --filter @worldlibertyfinancial/agent-relay test:unit
pnpm --filter @worldlibertyfinancial/agent-web test:unit

# Relay deployment: these scripts are fail-closed stubs (scripts/unsupported-release-surface.mjs)
# that print "unsupported in this release" and exit 1. Relay deployment is not supported.
pnpm --filter @worldlibertyfinancial/agent-relay deploy:local
pnpm --filter @worldlibertyfinancial/agent-relay deploy:development
pnpm --filter @worldlibertyfinancial/agent-relay deploy:production
```

## Architecture

This is a monorepo for a macOS/Linux signing CLI built around a self-custodial local daemon. The system has two language layers: Rust handles cryptography, policy evaluation, and daemon operations; TypeScript handles CLI orchestration, configuration, and web interfaces.

### How the layers interact (daemon mode)

The TypeScript CLI (`src/cli.ts`) is the user-facing entry point (`agentpay`). It spawns Rust binaries (`vault-cli-admin`, `vault-cli-agent`, `vault-cli-daemon`) as child processes for security-critical operations. The Rust daemon runs persistently and communicates via Unix domain sockets (or macOS XPC). The relay server bridges external requests to the daemon, and the web UI provides a manual approval console.

```
TypeScript CLI (src/cli.ts)
    │ spawns Rust binaries
    ▼
Rust CLIs (vault-cli-*)
    │ Unix socket / XPC
    ▼
Daemon (vault-daemon) ← Relay (apps/relay, tRPC/Hono) ← Web UI (apps/web, Next.js)
```

### Rust crates (crates/)

Organized in dependency layers:

- **Domain** (`vault-domain`): Core types — `AgentAction`, `SignRequest`, `SpendingPolicy`, `ManualApprovalRequest`. No transport or IO dependencies.
- **Policy** (`vault-policy`): Policy evaluation engine consuming domain types.
- **Signer** (`vault-signer`): Signing backends — macOS Secure Enclave, software, TEE. Uses k256 for ECDSA.
- **Daemon** (`vault-daemon`): Authorization pipeline, encrypted state persistence (Argon2), nonce management. Transport-agnostic.
- **Transport** (`vault-transport-unix`, `vault-transport-xpc`): Wire protocols. Unix socket has 256KB max body.
- **SDK** (`vault-sdk-agent`): Agent-side client with `AgentOperations` trait (`approve()`, `transfer()`, `broadcast_tx()`).
- **CLIs** (`vault-cli-admin`, `vault-cli-agent`, `vault-cli-daemon`): Binary entry points using clap.

### TypeScript packages (packages/)

- **config** (`@worldlibertyfinancial/agent-config`): Chain/network configuration, token profiles, RPC URLs
- **rpc** (`@worldlibertyfinancial/agent-rpc`): Blockchain RPC via Viem — balance queries, tx broadcast, fee estimation
- **ui** (`@worldlibertyfinancial/agent-ui`): Shared React components (Tailwind CSS) for web app
- **cache** (`@worldlibertyfinancial/agent-cache`): Redis/Valkey client abstraction (ioredis)
- **railgun-engine-fork** (`@worldlibertyfinancial/railgun-engine-fork`): Vendored Railgun engine fork used by the Railgun privacy flows
- **typescript** (`@worldlibertyfinancial/agent-typescript`): Shared TypeScript configuration presets

### Applications (apps/)

- **relay** (`@worldlibertyfinancial/agent-relay`): Hono + tRPC server, routes: daemon, admin, public. Backed by Valkey cache. Its `deploy:*` scripts are fail-closed stubs; deployment is unsupported in this release.
- **web** (`@worldlibertyfinancial/agent-web`): Next.js 16 + React 19. Approval console (`/approvals`), daemon management (`/daemons`). Uses @noble crypto libs for client-side encryption.
- **railgun-prover** (`@worldlibertyfinancial/agent-railgun-prover`): Railgun proof generation service used by the privacy transfer flows.
- **railgun-vector-generator** (`@worldlibertyfinancial/railgun-vector-generator`): Deterministic Railgun engine test-vector generator. Dumps a JSON fixture that the Rust crypto port cross-checks bit-for-bit. Dev-only; never imported by the daemon or the CLI.

### CLI library (src/lib/)

62 TypeScript modules organizing CLI functionality: admin setup/reset, agent authentication (auth/rotate/revoke/migrate), asset broadcast, bootstrap, config management, macOS/Linux integration (launchd, systemd, keychain, Secure Enclave), wallet status/repair, MPP and Link payments, Railgun, Solana transfers, telemetry. The `rust.ts` module handles spawning Rust binaries.

Imports inside `src/` use `.js` specifiers (for example `./lib/rust.js`) that tsup, tsx, and TypeScript's `moduleResolution: Bundler` resolve to the `.ts` sources. There are no `.js` shim files in `src/`; do not add any.

## Monorepo Tooling

- **pnpm 10.6** workspaces (`packages/*`, `apps/*`)
- **Turbo** for task orchestration with caching (`turbo.json`)
- **tsup** bundles the CLI to `dist/cli.cjs` (CJS, node20 target, with shebang, no sourcemaps)
- **Cargo** workspace for Rust crates (`[profile.release]` keeps `overflow-checks = true`)
- **Biome** for formatting/linting (line width 100, single quotes, 2-space indent, trailing commas); `skills/agentpay-sdk/scripts/vendor/` is vendored and excluded from linting
- **Rust 1.89.0+** minimum required (`rust-version` in the Cargo workspace; CI has an MSRV job pinned to 1.89.0)

## Testing

- **TypeScript integration tests** (`test/`): Node.js built-in `test` module (not vitest), run through `scripts/run-ts-tests.mjs` -> `scripts/run-tests-isolated.mjs`. The harness gives every run a throwaway `HOME`, `AGENTPAY_HOME`, and `TMPDIR` under the system temp directory and blocks `sudo`, `launchctl`, and `systemctl`. When spawning the CLI from a test, set `AGENTPAY_TELEMETRY=0`.
- **Package/app unit tests**: vitest (relay, web, cache).
- **Rust tests**: Standard `cargo test`. Domain model, policy engine, and signer tests.
- **Installer tests**: `test/setup-agentpay-script.test.mjs` drives `scripts/installer.sh` against fixture bundles, including SHA-256 verification, protected install-directory refusal, and shell rc handling.

## Key Conventions

- The CLI output is `dist/cli.cjs` — a single CJS bundle despite the project being ESM (`"type": "module"`)
- Rust binaries install to `~/.agentpay/bin/`
- macOS-specific: LaunchDaemon management, System Keychain storage, Secure Enclave signing; Linux uses systemd units and a password helper
- Security-sensitive memory uses `zeroize` in Rust
- Web app enforces strict CSP and security headers
- `agentpay admin approve-manual-approval-request` and `agentpay admin reject-manual-approval-request` display the pending request and ask for confirmation before acting; pass `--yes` for non-interactive use
- The one-click installer (`scripts/installer.sh`) verifies the downloaded bundle's SHA-256 against the digest templated in at release time (`SHA256SUMS` is published with every release) before extracting it, and refuses `$HOME`, `/`, `/usr*`, `/opt`, and unrecognized non-empty directories as install or skill-pack destinations

## Instructions

- **Always** switch to _Plan Mode_ whenever a complex task is being requested (3 or more steps in achieving it qualifies a task as being complex)
- **Consistency is key**, always write new code in the style of the already existing code, following the already availalble patterns
