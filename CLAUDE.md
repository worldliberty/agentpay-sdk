# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
# Install dependencies (also builds Rust binaries via postinstall)
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

# Run all TypeScript integration tests
npm run test:ts

# Run a single TypeScript test
node --experimental-strip-types --test test/<file>.test.mjs

# Run Rust tests
cargo test --workspace

# Run a single Rust crate's tests
cargo test -p vault-domain

# Build/install Rust binaries to ~/.agentpay/bin
npm run install:rust-binaries

# Package-specific commands (vitest)
pnpm --filter @worldlibertyfinancial/agent-relay test:unit
pnpm --filter @worldlibertyfinancial/agent-web test:unit

# Relay deployment
pnpm --filter @worldlibertyfinancial/agent-relay deploy:local
pnpm --filter @worldlibertyfinancial/agent-relay deploy:development
pnpm --filter @worldlibertyfinancial/agent-relay deploy:production
```

## Architecture

This is a monorepo for a macOS signing CLI built around a self-custodial local daemon. The system has two language layers: Rust handles cryptography, policy evaluation, and daemon operations; TypeScript handles CLI orchestration, configuration, and web interfaces.

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

- **config**: Chain/network configuration, token profiles, RPC URLs
- **rpc**: Blockchain RPC via Viem — balance queries, tx broadcast, fee estimation
- **ui**: Shared React components (Tailwind CSS) for web app
- **cache**: Redis/Valkey client abstraction (ioredis)

### Applications (apps/)

- **relay**: Hono + tRPC server, routes: daemon, admin, public. Backed by Valkey cache. Deploys via Serverless Framework.
- **web**: Next.js 16 + React 19. Approval console (`/approvals`), daemon management (`/daemons`). Uses @noble crypto libs for client-side encryption.

### CLI library (src/lib/)

66 TypeScript modules organizing CLI functionality: admin setup/reset, agent authentication (auth/rotate/revoke/migrate), asset broadcast, bootstrap, config management, macOS integration (launchd, keychain, Secure Enclave), wallet status/repair. The `rust.ts` module handles spawning Rust binaries.

## Monorepo Tooling

- **pnpm 10.6** workspaces (`packages/*`, `apps/*`)
- **Turbo** for task orchestration with caching (`turbo.json`)
- **tsup** bundles the CLI to `dist/cli.cjs` (CJS, node20 target, with shebang)
- **Cargo** workspace for Rust crates
- **Biome** for formatting/linting (line width 100, single quotes, 2-space indent, trailing commas)
- **Rust 1.87.0+** minimum required

## Testing

- **TypeScript integration tests** (`test/`): Node.js built-in `test` module (not vitest). Tests use isolated home directories for CLI smoke tests.
- **Package/app unit tests**: vitest (relay, web, cache).
- **Rust tests**: Standard `cargo test`. Domain model, policy engine, and signer tests.

## Key Conventions

- The CLI output is `dist/cli.cjs` — a single CJS bundle despite the project being ESM (`"type": "module"`)
- Rust binaries install to `~/.agentpay/bin/`
- macOS-specific: LaunchDaemon management, System Keychain storage, Secure Enclave signing
- Security-sensitive memory uses `zeroize` in Rust
- Web app enforces strict CSP and security headers

## Instructions

- **Always** switch to _Plan Mode_ whenever a complex task is being requested (3 or more steps in achieving it qualifies a task as being complex)
- **Consistency is key**, always write new code in the style of the already existing code, following the already availalble patterns
