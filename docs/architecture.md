# Architecture

AgentPay is split into two daemons and a thin client. All product logic (keys, policy, chains,
payments) runs in Rust inside the daemons. The client only renders screens, parses arguments, and
calls the daemons over the API documented in [`daemon-api.md`](daemon-api.md).

```text
 user session (the installing user)                    system services
 ─────────────────────────────────────                 ────────────────────────────────────────────

  agent / script ──┐
                   │  agentpay … --json
  person ──────────┤  agentpay (Ink TUI)
                   v
            ┌──────────────┐  payments, config   ┌──────────────────────────────┐
            │ agentpay     │ ──────────────────> │ agentpay-paymentd            │ ──> chain RPC
            │ client       │   paymentd.sock     │ service account              │ ──> x402 / MPP
            │ (TS + Ink)   │                     │ (_agentpay / agentpay)       │     merchants
            └──────────────┘                     └──────────────────────────────┘
               │      │                                        │ AuthenticateAgent, ReserveNonce,
               │      │ admin: approvals, limits,              │ SignForAgent … as the calling
               │      │ backups, Touch ID enrollment           │ agent (agent allowlist)
               │      v                                        v
               │   ┌──────────────────────────────────────────────────────────────────┐
               │   │ agentpay-daemon (signerd), root                                  │
               │   │ keys · policies · spending limits · manual approvals · nonces    │
               │   │ encrypted state keyed by the machine secret                      │
               │   └──────────────────────────────────────────────────────────────────┘
               │      ^ daemon.sock (root-owned)
               │      │
               v      │ signed admin challenge → short-lived lease
         ┌──────────────┐
         │ agentpay-auth│  Secure Enclave P-256 key (macOS): Touch ID or Mac login password
         └──────────────┘

  sudo agentpay-setup install   installs both services, the machine secret, and the units
```

## Components

| Component | Runs as | Responsibility | Source |
|---|---|---|---|
| `agentpay-daemon` (signerd) | root | Holds every wallet key, policy, spending limit, and manual approval. Authenticates agents (bearer tokens) and admins (root peer or Touch ID lease). Evaluates policy and signs. Persists encrypted state. | `crates/agentpay-signerd`, `crates/agentpay-signerd-cli` |
| `agentpay-paymentd` | unprivileged service account (`_agentpay` on macOS, `agentpay` on Linux); refuses root | All network I/O: EVM and Solana RPC, transaction building and broadcast, x402, MPP (Tempo charge and sessions), the local paying proxy, balances and funding requests, telemetry. Holds no keys; asks signerd for every signature as the calling agent. | `crates/agentpay-paymentd` |
| `agentpay` client | the user | Command line (`--json` for agents) and Ink TUI (onboarding wizard, home, receive, approvals, limits, security). Calls paymentd for payments and signerd for admin work. No crypto, no RPC, no merchant HTTP. | `client/` |
| `agentpay-auth` | the user (macOS) | Creates a Secure Enclave P-256 key with `.userPresence` and signs signerd's admin challenges after one system prompt (Touch ID or the Mac login password). | `native/macos/AgentPayAuth.swift` |
| `agentpay-setup` | root, via `sudo` | Installs or upgrades binaries, the machine secret, the paymentd service account, and the launchd/systemd units; migrates vault-password installs; uninstalls. Idempotent. | `crates/agentpay-setup` |
| `agentpay-system-keychain` | root (macOS) | Reads the machine secret from the System Keychain for the signerd runner script. | `crates/agentpay-signerd-cli` |

Shared libraries: `agentpay-api` (the wire contract), `agentpay-domain` (actions, policies,
addresses), `agentpay-policy` (policy engine), `agentpay-signer` (software and Linux TPM
backends), `agentpay-transport` (Unix socket server and client), `agentpay-agent-sdk` (Rust agent
client).

## Trust boundaries

1. **Agent → client.** An agent runs `agentpay` as the installing user. The client reads that
   user's agent credentials (key id in `~/.agentpay/client.json`, token in the login keychain, the
   Secret Service, or a `0600` file) and never prints the token.
2. **Client → paymentd.** The payments socket is owned by the service account. The client checks
   the socket path and the peer euid before sending anything. paymentd accepts only the installing
   user's uid (`--allow-client-euid`) and authenticates every call except `Hello` and the
   read-only `LookupToken` by passing the agent credentials to signerd (`AuthenticateAgent`). Nothing is cached, so a revoked token stops
   working on the next request.
3. **paymentd → signerd.** paymentd's uid is on signerd's **agent** allowlist, never the admin
   allowlist. Every signature it asks for carries the agent's credentials, so the agent's own
   policies, limits, and manual approvals apply. paymentd verifies every signature signerd returns
   before it leaves the process.
4. **Admin → signerd.** Admin methods need either a root peer (`sudo agentpay admin …`) or a lease
   obtained by signing a single-use, operation-bound challenge with the enrolled Secure Enclave key
   (`BeginAdminChallenge` → `agentpay-auth sign` → `CompleteAdminChallenge`). Leases are short-lived
   and bound to the uid that obtained them. When Touch ID is off or unavailable (Linux, SSH), the
   interactive screens relay admin calls through `sudo agentpay admin privileged`, which forwards
   only an allowlist of admin methods.
5. **signerd → disk.** The state file is encrypted (HKDF-SHA256 + XChaCha20-Poly1305) under a
   random 32-byte machine secret that only root can read. There is no vault password.

Secrets (agent tokens, lease secrets, backup passphrases, the machine secret) only travel on stdin,
pipes, or socket frames, never in arguments or environment variables.

## Data flows

**Payment (for example `agentpay transfer --amount 1 --to 0x… --broadcast --json`).**
The client sends `Transfer` to paymentd with the agent's credentials. paymentd authenticates the
agent with signerd, resolves the network and asset from its configuration (default USD1 on BSC),
reserves a nonce from signerd, builds the EIP-1559 transaction, and asks signerd to sign it as a
`BroadcastTx`. signerd checks the agent's policies and spending limits, signs, and records the
spend. paymentd verifies the signature, broadcasts, waits for the receipt, and returns the result.

**Manual approval.** When a policy holds a request for an operator, signerd queues a manual
approval request. paymentd resends the identical signing request with backoff for up to
`--approval-wait` seconds (default 300 with `--broadcast`). The operator decides with
`agentpay admin approve <id>` or `agentpay admin approvals` (Touch ID or sudo). If the wait runs
out, the command exits with code `3` and prints the request id; EVM and Solana payments then finish
with `agentpay resume --approval-request-id <id>`, which resends the stored action unchanged.

**Paid HTTP.** `agentpay x402 <url>` and `agentpay mpp <url>` make the request from paymentd, pay a
`402` within the agent's policies (EIP-3009 for x402; Tempo charge or TIP-1034 session for MPP),
and return the merchant's response. `agentpay proxy start` runs a loopback HTTP proxy that does the
same for any HTTP client.

**Setup.** `agentpay setup` runs `sudo agentpay-setup install --user <you>`, then the onboarding
wizard: create, restore, or keep a wallet (`BootstrapWallet`), optionally enroll Touch ID, set
spending limits (every seeded asset gets a limit or is blocked), and export an encrypted backup.

## Sockets, state, and files

| | macOS | Linux |
|---|---|---|
| Binaries | `/Library/AgentPay/bin` | `/opt/agentpay/bin` |
| Install record | `/Library/AgentPay/install.json` | `/opt/agentpay/install.json` |
| signerd socket | `/Library/AgentPay/run/daemon.sock` | `/run/agentpay/daemon.sock` |
| signerd state | `/var/db/agentpay/daemon-state.enc` | `/var/lib/agentpay/daemon-state.enc` |
| Machine secret | System Keychain (`/Library/Keychains/System.keychain`) | `/var/lib/agentpay/daemon-secret` (root, `0600`) |
| signerd unit | `/Library/LaunchDaemons/com.agentpay.daemon.plist` | `/etc/systemd/system/agentpay-daemon.service` |
| signerd logs | `/var/log/agentpay` | journald |
| paymentd account | `_agentpay` | `agentpay` |
| paymentd socket | `/Library/AgentPay/run/paymentd/paymentd.sock` | `/run/agentpay-paymentd/paymentd.sock` |
| paymentd state | `/var/db/agentpay-paymentd` | `/var/lib/agentpay-paymentd` |
| paymentd unit | `/Library/LaunchDaemons/com.agentpay.paymentd.plist` | `/etc/systemd/system/agentpay-paymentd.service` |
| paymentd logs | `/var/log/agentpay-paymentd` | journald |

paymentd's state directory holds `config.json` (chains, tokens, RPC URLs, defaults),
`telemetry.json` (opt-out and random install id), `mpp-sessions.json` (persisted MPP session
channels, no secrets), and pending EVM and Solana actions awaiting `ResumeApproved` (kept 24
hours). Every file is `0600` and owned by the service account.

Per user, `~/.agentpay` (or `$AGENTPAY_HOME`) holds `client.json` (agent key id and the enrolled
Touch ID credential id; no secrets), `admin-key.json` (the Secure Enclave key reference written by
`agentpay-auth`; the private key never leaves the Enclave), `agent-auth/` (token files only where
no keychain or Secret Service is available), and `proxy.env` / `proxy-ca.pem` while a paying proxy
runs.

In development, both daemons accept explicit socket and state paths, and the client accepts
`--daemon-socket` and `--payments-socket` (or `AGENTPAY_DAEMON_SOCKET` and
`AGENTPAY_PAYMENTS_SOCKET`). `$AGENTPAY_HOME` never moves the client's sockets: the previous
installer exported it into shells and editors.
