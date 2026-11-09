---
name: agentpay-sdk
description: Install and operate the AgentPay SDK. Trigger this when an agent needs to install `agentpay`, explain AgentPay SDK capabilities without probing the machine first, set up or reuse the local wallet, check funding, generate funding instructions or a QR, guide the user through spending limits, route manual approvals to the user's local admin commands, send tokens on EVM chains or Solana, or pay x402 and MPP APIs using the current CLI behavior instead of stale examples.
homepage: https://worldlibertyfinancial.com
metadata: {"openclaw":{"skillKey":"agentpay-sdk","homepage":"https://worldlibertyfinancial.com","os":["darwin","linux"],"requires":{"bins":["agentpay"]}}}
---

# AgentPay SDK

Use this skill as an operator playbook. Do not make the user design command flows or policy objects
from scratch.

## What This Skill Covers

If the user asks what this skill can do, answer from this list. Do not probe the machine unless the
user is asking you to act.

- install `agentpay` and set up a self-custodial local wallet (`agentpay setup`)
- reuse an existing wallet, or restore one from an encrypted offline backup
- export and verify encrypted offline wallet backups
- check balances and stop for funding when the payment asset or gas is missing
- generate funding instructions and a QR code
- send ERC-20 tokens and native coins, approve allowances, and sign or broadcast agent-built EVM
  transactions
- send SOL and SPL tokens on Solana
- sign EIP-712 typed data within policy
- pay x402 APIs (EIP-3009) and MPP APIs (Tempo charge and sessions)
- run a local paying proxy so any HTTP client can pay `402` responses
- guide the user through spending limits (per payment, daily, weekly; deny by default)
- explain pending manual approvals and how the user approves or rejects them

Not available: Stripe Link card payments, Bitrefill, and private (Railgun) transfers. There are no
`link` or `bitrefill` commands.

## Ground Truth

- `agentpay --help` and `agentpay <command> --help` are the source of truth for flags.
- Install: `curl -fsSL https://wlfi.sh | sh` (installs into `~/.agentpay`, no sudo), then the user
  runs `agentpay setup`. Rerun the installer to update.
- `agentpay setup` installs the two services with sudo and runs the setup wizard (create, restore,
  or keep a wallet; Touch ID; spending limits; backup). The user runs it in their own terminal.
- `agentpay wallet --json` is the wallet reuse check. `agentpay status --json` reports service,
  chain, and limit health with warnings.
- `agentpay config show --json` shows networks, tokens, RPC URLs, and the defaults.
- Every command accepts `--json` and then prints exactly one JSON document on stdout, including
  errors: `{"error": {"code", "message", "next_action"}}`. Follow `next_action`.
- Exit codes: `0` success, `1` failure, `2` usage error, `3` waiting for manual approval, `4`
  AgentPay not installed or no agent credentials for this user.
- There is no vault password. Admin actions (approvals, limits, backups, Touch ID) need Touch ID or
  the Mac password on macOS, or `sudo` elsewhere. Only the user can do that.
- Agent credentials are found automatically (saved by setup). Never pass tokens as arguments; use
  `--agent-auth-token-stdin` only when a token must be supplied explicitly.

## Default Payment Assumption

- Default network: `bsc`
- Default asset for unspecified payments: `USD1` (token key `usd1`)
- USD1 contract on BSC: `0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d`
- Gas asset on BSC: `BNB`

## Secure Input Rule

- Never ask the user to paste a wallet backup passphrase, agent auth token, or proxy URL/token into
  chat.
- Never run `sudo` or `agentpay admin …` decisions on the user's behalf. Tell the user the exact
  command to run locally.
- For first-run setup, tell the user to run `agentpay setup` in their terminal.
- After a fresh setup, strongly recommend `agentpay admin wallet-backup export --output <PATH>`
  unless the user already has a verified backup. The passphrase is entered locally (at least 12
  characters).

## Deterministic Flow

1. Classify the request: explain capabilities, install, set up wallet, back up, restore, fund,
   change limits, send token, send native coin, approve allowance, broadcast a built transaction,
   Solana transfer, pay x402 API, pay MPP API, run paying proxy, resolve manual approval, uninstall.
2. If the user only asks what the skill can do, answer from `What This Skill Covers` and stop.
3. Start with `agentpay config show --json`.
4. Run `agentpay wallet --json`. Exit code `4` means AgentPay is not set up for this user: tell the
   user to run `agentpay setup` locally.
5. To re-run setup without changing the wallet, the user runs `agentpay setup` and chooses
   "Keep the existing wallet".
6. To restore on a new machine from an encrypted backup, the user runs `agentpay setup` and chooses
   "Restore from a backup".
7. For limit changes, default to `agentpay admin limits` (interactive) run by the user.
8. If the user did not specify network or asset, use `bsc` and `USD1` before asking anything.
9. Before any outbound payment, check funding (see below).
10. If funding is missing, stop and ask the user to fund the wallet.
11. Only then run the exact current command with `--json`.
12. If the result is pending manual approval (exit code `3`), follow the Manual Approval Rule.

## Funding Rule

- Treat a fresh wallet as unfunded until `agentpay wallet --json` proves otherwise.
- Native transfers: check the native balance.
- ERC-20 transfers and approvals: check the token balance and the native gas balance.
- Default path: the user may need both `USD1` (value) and `BNB` (gas).
- Tempo payments (MPP) pay fees in the stablecoin; no native gas coin is needed.
- When funding is missing, run `agentpay fund --network <net> --asset <asset> [--amount <amount>] --json`
  (add `--qr` for a terminal QR) and give the user: the address, network and chain id, the asset
  for value, the gas asset (`gas` field), and the funding `uri`.

## Current Command Shapes

- Wallet and balances: `agentpay wallet --json`
- Health: `agentpay status --json`
- Funding: `agentpay fund [--network <net>] [--asset <asset>] [--amount <amount>] [--qr] --json`
- ERC-20 transfer: `agentpay transfer [--network <net>] [--token <key|address>] --to <address> --amount <amount> --broadcast --json`
- Native transfer: `agentpay transfer-native --network <net> --to <address> --amount <amount> --broadcast --json`
- Approve: `agentpay approve [--network <net>] [--token <key|address>] --spender <address> --amount <amount> --broadcast --json`
- Agent-built transaction: `agentpay broadcast --network <net> --to <address> [--value-wei <wei>] [--data-hex <0x…>] --broadcast --json`
- Typed data: `agentpay sign-typed-data --typed-data-file <path> --json`
- Solana: `agentpay transfer-sol --network solana-mainnet --to <address> --amount <amount> --broadcast --json`;
  `agentpay transfer-spl --network solana-mainnet --mint <address> --to <address> --amount <amount> --broadcast --json`
- Resume an approved payment: `agentpay resume --approval-request-id <UUID> --json`
- x402: `agentpay x402 <url> [--max-amount <base units>] [--method POST --json-body '<json>'] --json`
- MPP: `agentpay mpp <url> [--amount <base units>] [--session-key <name>] [--max-deposit <base units>] --json`
- Paying proxy: `agentpay proxy start [--allow-host <host>] [--max-amount <base units>] --json`,
  `agentpay proxy status --json`, `agentpay proxy stop --json`
- Configuration: `agentpay config show --json`, `agentpay config set <key> <value>` (keys:
  `default_network`, `default_asset`, `chains.<network>.rpc_url`, `agent_key_id`)
- Telemetry: `agentpay telemetry status|enable|disable`

User-run admin commands (Touch ID or Mac password on macOS; otherwise prefix with `sudo`):

- Setup, reuse, or restore: `agentpay setup`
- Approval queue: `agentpay admin approvals` (`--all` includes decided requests)
- Decide: `agentpay admin approve <UUID>` / `agentpay admin reject <UUID> [--reason <text>]`
  (`--yes` skips the confirmation prompt)
- Limits: `agentpay admin limits` (interactive) or
  `agentpay admin limits set <asset> --network <net> --per-tx <amount> --daily <amount> --weekly <amount>`
  (`--exclude` blocks the asset)
- Backups: `agentpay admin wallet-backup export --output <PATH>`,
  `agentpay admin wallet-backup verify <PATH>`
- Touch ID: `agentpay admin touch-id enable|status|disable`

## Amount Units

- `transfer`, `transfer-native`, `approve`, `fund`, `transfer-sol`, `transfer-spl`, and
  `admin limits set` take decimal whole units (`1.5`). Solana also accepts `--amount-base-units`.
- `x402` and `mpp` take integer base units, as in the merchant challenge (`10000` = 0.01 of a
  6-decimal token).
- `broadcast` takes `--value-wei` in wei.
- Without `--broadcast`, `transfer`, `transfer-native`, and `approve` only sign, and the signature
  still counts toward spending limits. Use `--broadcast` for real payments.

## Policy Rules

- Spending limits are deny by default: an asset without a limit cannot be spent.
- Map user requests to: keep the current limits, change one asset's limits, block an asset, or
  resolve pending approvals.
- Default to `agentpay admin limits` (interactive) run by the user.
- If the user gives concrete limits and wants an exact command, give
  `agentpay admin limits set <asset> --network <net> --per-tx <amount> --daily <amount> --weekly <amount>`
  for them to run locally. Do not claim a limit changed unless the command succeeded.
- Limits are auto-approve limits: a payment within the per-payment, daily, weekly, and daily-count
  limits goes out on its own; a payment beyond any of them waits for the user's approval (it is
  not refused). There is no separate approval threshold to set. An asset with no limit is
  blocked. `agentpay activity --json` lists the agent's waiting approvals (with why) and recent
  payments.
- Recipient-specific policies are not client commands in this version; they are set through the
  signer daemon API (`AddPolicy`, see `docs/daemon-api.md`).

## Manual Approval Rule

- Treat a manual approval hit as pending, not failed. Tell the user the request is waiting for their
  approval and give them `agentpay admin approve <UUID>` (or the interactive `agentpay admin approvals`).
- EVM and Solana payments with `--broadcast` wait up to 300 seconds (`--approval-wait`, max 600) and
  finish on their own once approved. Tell the user to keep the original command running and not to
  rerun it.
- If the command already exited with code `3` (`"status": "manual_approval_pending"`), finish it
  after approval with `agentpay resume --approval-request-id <UUID> --json`. Never rerun the original
  command: it would build a new transaction and a new approval request.
- `x402` and `mpp` do not wait by default and cannot be resumed (each challenge is single-use). Pass
  `--approval-wait <secs>` so the call waits while the user decides; a rerun creates a new request.
- The paying proxy never waits for approval.

## Minimal Clarification Rule

- If the user says "send money" without network or asset, use the defaults. Only ask for what is
  missing: amount, recipient, or spender.

## Extra References

- [references/capabilities.md](./references/capabilities.md): every command, flag, JSON shape, and
  exit code.
- [references/install-and-workflows.md](./references/install-and-workflows.md): install, setup,
  backup, restore, funding, limits, approvals, uninstall.
- [references/intents-and-policies.md](./references/intents-and-policies.md): intent mapping.
- [references/mpp-services.md](./references/mpp-services.md): x402, MPP, and the paying proxy.
