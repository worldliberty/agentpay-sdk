# AgentPay client

The `agentpay` command line and terminal UI. It is a thin client: every payment, chain call, key, policy, and approval lives in the two daemons (`agentpay-signerd`, `agentpay-paymentd`). The client talks to them over their Unix sockets exactly as documented in [`docs/daemon-api.md`](../docs/daemon-api.md), using the generated types in `src/generated/` (`cargo xtask gen-api`; never edit them by hand).

## Toolchain

- Node.js: the version in [`.nvmrc`](.nvmrc) (Node 20 or newer is supported, see `engines`).
- Package manager: **npm**, with the committed `package-lock.json`. Install with `npm ci`. npm ships with Node, so there is no extra tool to install or pin.
- TypeScript only: sources are `.ts` / `.tsx`, and so is every config file. `tsc` builds ESM into `dist/` (git-ignored).

| Task | Command | `just` recipe |
|---|---|---|
| Install | `npm ci` | `just client-install` |
| Build | `npm run build` | `just client-build` |
| Typecheck + test | `npm run typecheck && npm test` | `just client-test` |
| Lint (Biome) | `npm run lint` (`npm run lint:fix` to fix) | `just client-lint` |

Tests run under Vitest with a private `HOME` and `AGENTPAY_HOME` (see `test/setup.ts`). Daemon tests use real Unix sockets served by a fake daemon (`test/helpers/fake-daemon.ts`) and answer with the API's own fixtures from `crates/agentpay-api/fixtures`. Screens are tested with `ink-testing-library`.

## Layout

| Path | Contents |
|---|---|
| `src/cli.ts`, `src/program.ts` | entry point and the commander program |
| `src/commands/` | one module per command group; `--json` output for agents |
| `src/daemon/` | framing, transport, socket trust checks, typed signer and payments clients |
| `src/auth/` | agent credentials (keychain / Secret Service / 0600 file), Touch ID helper, admin authorization, sudo relay |
| `src/app/` | the process context and the services that connect screens to the daemons |
| `src/screens/` | Ink screens: onboarding, home, receive, approvals, limits, security |
| `src/ui/` | design system: tokens (with `NO_COLOR`), layout, controls |
| `src/copy/` | every user-facing string |

## Exit codes

`0` success, `1` failure, `2` usage error, `3` a payment is waiting for manual approval, `4` AgentPay is not installed or this user has no agent credentials. With `--json`, errors are printed on stdout as `{"error": {"code", "message", "next_action"}}`.
