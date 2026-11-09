# AgentPay SDK

AgentPay is a self-custodial wallet AI agents can pay from, within limits you set. It runs
locally on macOS and Linux: keys never leave your machine, every signature is checked against your
spending policy, and anything above your limits waits for your approval.

Agents can send tokens on EVM chains and Solana, pay [x402](https://x402.org) and
[MPP](https://mpp.dev) APIs, and route any HTTP client through a local paying proxy. Every command
has a `--json` mode for agents.

![AgentPay status and home screen, then sample-llm streaming an answer paid per request over MPP](docs/assets/agentpay-demo.gif)


## Install

```bash
curl -fsSL https://wlfi.sh | sh
agentpay setup
```

Requirements: macOS 13 or later, or a Linux distribution with systemd. Touch ID approvals need a Mac
with a Secure Enclave; everywhere else admin actions use sudo.

## Quick start

1. **Set up.** `agentpay setup` walks through one guided flow:
   - create a new wallet, restore one from an encrypted backup, or keep the existing one;
   - turn on Touch ID for admin approvals (macOS, optional);
   - set spending limits: every asset gets a per-payment, daily, and weekly limit, or is blocked;
   - export an encrypted offline backup.
2. **Fund the wallet.** `agentpay fund --qr` shows the address, network, and a QR code. The default
   payment asset is USD1 on BSC; ERC-20 payments also need BNB for gas.
3. **Make a first payment.**

   ```bash
   agentpay wallet                                   # addresses and balances
   agentpay transfer --to 0x… --amount 1 --broadcast # 1 USD1 on BSC
   ```

Run `agentpay` with no arguments for the home screen: balances, receive, limits, approvals, and
security settings.

## Agent usage

Agents run the same commands with `--json`. Each command prints exactly one JSON document on stdout,
including errors: `{"error": {"code", "message", "next_action"}}`.

```bash
agentpay status --json                    # services, chains, limits, warnings
agentpay wallet --json                    # addresses and balances
agentpay fund --json                      # funding address, URI, and gas hint
agentpay transfer --to 0x… --amount 5 --broadcast --json
agentpay transfer-native --network bsc --to 0x… --amount 0.01 --broadcast --json
agentpay transfer-sol --network solana-mainnet --to <address> --amount 0.5 --broadcast --json
agentpay x402 https://api.example.com/data --max-amount 10000 --json
agentpay mpp https://api.example.com/chat --session-key chat --json-body '{"q":"hi"}' --json
agentpay proxy start --allow-host api.example.com --json
```

| Exit code | Meaning |
|---|---|
| `0` | success |
| `1` | failure (the JSON error says what to do next) |
| `2` | usage error |
| `3` | waiting for manual approval: approve, then `agentpay resume --approval-request-id <id>` |
| `4` | AgentPay is not installed, or this user has no agent credentials: run `agentpay setup` |

Amounts for `transfer`, `transfer-native`, `approve`, `fund`, and the Solana transfers are decimal
whole units (`1.5`). Amounts for `x402` and `mpp` are integer base units, as in the merchant's
challenge (`10000` is 0.01 of a 6-decimal stablecoin). `agentpay <command> --help` is the reference
for every flag.

The agent skill pack in [`skills/agentpay-sdk`](skills/agentpay-sdk/SKILL.md) teaches coding agents
these flows, with adapters for Claude, Codex, Cursor, Copilot, Gemini, and Cline in
[`skills/agentpay-sdk/agents`](skills/agentpay-sdk/agents).

## Architecture

```text
  agent / person
        │  agentpay … [--json]          (TypeScript + Ink client: CLI and terminal UI)
        v
  ┌───────────────────┐   payments    ┌──────────────────────────────┐
  │ agentpay client   │ ────────────> │ agentpay-paymentd            │ ──> chain RPC, x402, MPP
  └───────────────────┘ paymentd.sock │ unprivileged service account │
     │          │                     └──────────────────────────────┘
     │          │ admin                               │ signatures, as the calling agent
     │          v                                     v
     │   ┌────────────────────────────────────────────────────────────┐
     │   │ agentpay-daemon (signerd), root                            │
     │   │ keys · policies · spending limits · approvals · nonces     │
     │   └────────────────────────────────────────────────────────────┘
     │          ^ signed challenge → admin lease
     v          │
  ┌───────────────────┐
  │ agentpay-auth     │  Secure Enclave key: Touch ID or Mac password (macOS)
  └───────────────────┘
```

- **signerd** (`agentpay-daemon`, root) holds every key, policy, and manual approval, and signs only
  what policy allows. Its state is encrypted under a machine secret only root can read.
- **paymentd** (`agentpay-paymentd`, its own unprivileged account) does all network work: RPC,
  transaction building and broadcast, x402, MPP, the paying proxy, balances, and funding requests.
  It holds no keys and asks signerd for every signature as the calling agent.
- **The client** (`agentpay`) parses commands and renders the terminal UI. It contains no payment
  logic.
- **`agentpay-auth`** (macOS) signs signerd's admin challenges with a Secure Enclave key after
  Touch ID or your Mac password.

See [docs/architecture.md](docs/architecture.md) for trust boundaries, data flows, and the files and
sockets on each OS.


## Security model

- **Deny by default.** An agent can only spend an asset that has a spending limit. Limits are per
  network and asset: per payment, rolling 24 hours, and rolling 7 days. Assets without a limit are
  blocked, and calldata the policy engine does not recognize is refused.
- **Manual approval.** Policies can hold payments for an operator instead of rejecting them.
  `agentpay admin approvals` lists them; `agentpay admin approve <id>` and
  `agentpay admin reject <id>` decide.
- **Admin actions need you.** Approvals, limit changes, and backups need Touch ID or your Mac
  password (a Secure Enclave key) on macOS, or `sudo` on Linux, over SSH, or when Touch ID is off.
  An agent's credentials never grant admin authority.
- **No vault password.** signerd's state is encrypted under a random machine secret stored
  root-only (System Keychain on macOS, a `0600` root file on Linux). Encrypted offline backups use
  their own passphrase (at least 12 characters).
- **Secrets stay out of argv and the environment.** Agent tokens, backup passphrases, and lease
  secrets travel only over stdin, pipes, or the daemon sockets. Agent tokens live in the login
  keychain or Secret Service.
- **Least privilege.** Only signerd runs as root. Network-facing code runs in paymentd under its own
  account, which is on signerd's agent allowlist but never its admin allowlist.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Telemetry and privacy

paymentd sends anonymous usage analytics (Mixpanel) and crash reports (Sentry). It is on by
default. Turn it off with `agentpay telemetry disable`; `agentpay telemetry status` shows the
current setting. Setting `AGENTPAY_TELEMETRY=0` or `DO_NOT_TRACK=1` in the service's environment
also turns it off.

Events carry a random install id, the method name and outcome, a duration bucket, coarse amount
buckets (`0`, `<10`, `10-100`, `100-1k`, `1k-10k`, `10k+`), the service version, OS, and CPU
architecture, with timestamps truncated to the minute. Addresses, keys, tokens, signatures,
transaction hashes, exact amounts, RPC and merchant URL paths, e-mail addresses, the host name, and
the home directory are never sent. The full rules are documented on
`agentpay_api::payments::telemetry`.

## Uninstall

```bash
sudo ~/.agentpay/bin/agentpay-setup uninstall               # remove both services and the wallet state
sudo ~/.agentpay/bin/agentpay-setup uninstall --keep-state  # keep the encrypted state and machine secret
rm -rf ~/.agentpay                                          # then remove the client
```

Export a backup first (`agentpay admin wallet-backup export --output <path>`) unless you already
have a verified one. `sudo ~/.agentpay/bin/agentpay-setup status` reports what is installed.

## Third-party integrations

The daemons speak a documented, versioned JSON-RPC API over Unix sockets (API `1.1.0`). See
[docs/daemon-api.md](docs/daemon-api.md) for the transport, authentication, every method with
examples, errors, and a minimal client walkthrough. A JSON Schema is in
[docs/api/schema.json](docs/api/schema.json).

## Development

| Tool | Version |
|---|---|
| Rust | pinned in [`rust-toolchain.toml`](rust-toolchain.toml) |
| Node.js (client only) | [`client/.nvmrc`](client/.nvmrc), npm with the committed lockfile |
| [`just`](https://github.com/casey/just) | any recent version |

```bash
just build        # cargo build --workspace
just test         # cargo test --workspace
just lint         # fmt, clippy -D warnings, file length, no JavaScript, API drift, API docs
just dev          # fmt, lint, test
just client-install && just client-test && just client-lint
cargo xtask gen-api                # regenerate docs/api/schema.json and client/src/generated
cargo xtask build-macos-auth       # build agentpay-auth (Swift)
```

Repository layout: `crates/` (Rust workspace), `client/` (TypeScript + Ink client),
`native/macos/` (the `agentpay-auth` helper), `scripts/` (installer and service runner scripts),
`docs/` (architecture and API), `skills/` (agent skill packs). See [CONTRIBUTING.md](CONTRIBUTING.md)
for the rules every change follows.

## License and governance

- License: [MIT](LICENSE)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Security policy: [SECURITY.md](SECURITY.md)
- Legal disclaimer: [LEGAL_DISCLAIMER.md](LEGAL_DISCLAIMER.md)
- Changelog: [CHANGELOG.md](CHANGELOG.md)
