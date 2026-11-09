# Capabilities

Exact commands, flags, and output. `agentpay <command> --help` wins if anything here disagrees.

## Common Options

Every agent command accepts:

| Option | Meaning |
|---|---|
| `--json` | print exactly one JSON document on stdout (results, pending approvals, and errors) |
| `--agent-key-id <uuid>` | act as this agent key (default: the one saved by setup) |
| `--agent-auth-token-stdin` | read the agent auth token from stdin instead of the keychain |

Payment commands also accept `--approval-wait <secs>`: how long to wait for a manual approval
before returning (default 300 with `--broadcast`, else 0; max 600).

## Exit Codes

| Code | Meaning | What to do |
|---|---|---|
| `0` | success | |
| `1` | failure | read `error.message` and follow `error.next_action` |
| `2` | usage error | fix the flags (`agentpay <command> --help`) |
| `3` | waiting for manual approval | see the Manual Approval Rule in `SKILL.md` |
| `4` | AgentPay is not installed, or this user has no agent credentials | the user runs `agentpay setup` |

Errors with `--json`:

```json
{"error": {"code": "Policy", "message": "…", "next_action": "…"}}
```

`code` is the daemon error kind (for example `Policy`, `ChainRpc`, `Merchant`,
`ManualApprovalPending`) or a client code (`usage`, `socket_missing`, `sudo_required`, …). A pending
approval error also carries `approval_request_id`.

## Wallet And Health

| Command | Result |
|---|---|
| `agentpay wallet --json` | `agent_key_id`, `evm_address`, `solana_address`, `default_network`, `default_asset`, `balances[]` (`network`, `chain_id`, `asset`, `symbol`, `kind`, `token`, `decimals`, `balance`, `balance_base_units`, `error`) |
| `agentpay status --json` | service and signer versions, `can_spend`, per-chain reachability, spending policy summary, `warnings[]` |
| `agentpay fund [--network <net>] [--asset <asset>] [--amount <amount>] [--qr] --json` | `address`, `network`, `chain_id`, `symbol`, `token`, `uri` (EIP-681 or Solana Pay), `gas` (`symbol`, `note`) for token funding, `qr.terminal` with `--qr`, `instructions` |
| `agentpay config show --json` | `default_network`, `default_asset`, `chains`, `tokens` |

A balance entry whose chain did not answer has `balance: null` and an `error`; the rest are still
returned.

## EVM Payments

| Command | Required | Optional |
|---|---|---|
| `agentpay transfer` | `--to`, `--amount` | `--token`/`--asset` (default `usd1`), `--network` (default `bsc`) |
| `agentpay transfer-native` | `--to`, `--amount` | `--network` |
| `agentpay approve` | `--spender`, `--amount` | `--token`/`--asset`, `--network` |
| `agentpay broadcast` | `--to` | `--value-wei`, `--data-hex`, `--network` |
| `agentpay sign-typed-data` | `--typed-data <json>` or `--typed-data-file <path>` | |

Shared transaction options: `--broadcast`, `--no-wait`, `--receipt-timeout <secs>` (max 120),
`--nonce`, `--gas-limit`, `--max-fee-per-gas-wei`, `--max-priority-fee-per-gas-wei`.

- `--amount` is decimal whole units (`1.5`); `--value-wei` is wei.
- Without `--broadcast`, `transfer`, `transfer-native`, and `approve` return a signature only, and
  `broadcast` returns a signed transaction (`raw_tx_hex`) without sending it. Signatures count
  toward spending limits either way.
- With `--broadcast` the result includes `tx_hash`, `nonce`, fees, and `receipt` (`success`,
  `block_number`) unless `--no-wait`. A reverted transaction exits `1`.

## Solana

| Command | Required | Optional |
|---|---|---|
| `agentpay transfer-sol` | `--network`, `--to`, `--amount` or `--amount-base-units` | |
| `agentpay transfer-spl` | `--network`, `--to`, `--mint`, `--amount` or `--amount-base-units` | |

Shared options: `--broadcast`, `--no-wait`, `--nonce <auto|recent|managed|<nonce account>>`,
`--compute-unit-limit`, `--compute-unit-price`, `--reveal-raw-tx`. Networks: `solana-mainnet`,
`solana-devnet`, `solana-testnet`. Manual approval on Solana needs a durable nonce (the default
when broadcasting).

## Manual Approval Results

A payment held for approval prints (exit code `3`):

```json
{
  "status": "manual_approval_pending",
  "approval_request_id": "…",
  "method": "Transfer",
  "network": "bsc",
  "chain_id": 56,
  "payment": {"…": "…"},
  "action": {"…": "…"},
  "next_action": "Approve it with: agentpay admin approve <id>. Then finish the payment with: agentpay resume --approval-request-id <id>"
}
```

`agentpay resume --approval-request-id <UUID> --json` finishes an approved EVM or Solana payment by
resending the stored action unchanged.

## Paid HTTP

| Command | Options |
|---|---|
| `agentpay x402 <url>` | `--max-amount <base units>`, `--expected-amount <base units>` |
| `agentpay mpp <url>` | `--amount`, `--deposit`, `--max-deposit` (base units), `--currency <token address>`, `--session-key <name>`, `--session-state-file <path>`, `--close-session` |

Both accept `--method`, `--header "Name: value"` (repeatable), `--data <text>` or
`--json-body <json>`, and `--approval-wait`. The result has `protocol`, `url`, `status`, `ok`,
`headers`, `body` (parsed JSON when the response is JSON), `body_truncated`, and `payment` (`null`
when nothing was paid). See [mpp-services.md](./mpp-services.md).

## Paying Proxy

| Command | Result |
|---|---|
| `agentpay proxy start [--port <port>] [--allow-host <host>]… [--max-amount <base units>] --json` | proxy `status`, the secret `proxy_url` and `token`, `env_file` (`~/.agentpay/proxy.env`, `HTTP(S)_PROXY` plus CA bundle variables), and `ca_file` (`~/.agentpay/proxy-ca.pem`). Never echo `proxy_url` or `token` into chat; load `env_file` into the child process instead |
| `agentpay proxy status --json` | whether a proxy runs and its settings |
| `agentpay proxy stop --json` | stops it |

## Configuration And Telemetry

- `agentpay config show --json`
- `agentpay config set <key> <value>` with `default_network`, `default_asset`,
  `chains.<network>.rpc_url`, or `agent_key_id`
- `agentpay config agent-auth set --agent-key-id <uuid> --agent-auth-token-stdin` /
  `agentpay config agent-auth clear`
- `agentpay telemetry status|enable|disable`

## Admin Commands (User-Run)

These need Touch ID or the Mac password (macOS with Touch ID enabled) or `sudo`:

- `agentpay admin approvals [--all]`
- `agentpay admin approve <UUID> [--yes]`
- `agentpay admin reject <UUID> [--reason <text>] [--yes]`
- `agentpay admin limits` and `agentpay admin limits set <asset> --network <net> [--per-tx <amount>] [--daily <amount>] [--weekly <amount>] [--exclude]`
- `agentpay admin wallet-backup export --output <PATH>` (passphrase entered locally, or
  `--passphrase-stdin`; at least 12 characters)
- `agentpay admin wallet-backup verify <PATH>`
- `agentpay admin touch-id enable|status|disable`

## Built-In Defaults

- Networks: `bsc` (56), `eth` (1), `tempo` (4217), `tempo-testnet` (42431), `solana-mainnet`,
  `solana-devnet`, `solana-testnet`
- Tokens: `usd1` (bsc, eth, tempo), `bnb`, `eth`, `sol`, `usdc` (Solana), `usdc.e`, `pathusd`, `usd`
  (Tempo)
- Default payment: `usd1` on `bsc`

## Do Not Say

- Do not mention a vault password; there is none.
- Do not suggest `agentpay admin setup`, `agentpay admin tui`, `--reuse-existing-wallet`,
  `--restore-wallet-from`, or `admin resume-manual-approval-request`; they are replaced by
  `agentpay setup`, `agentpay admin limits`, the setup wizard choices, and `agentpay resume`.
- Do not offer Stripe Link, Bitrefill, or private transfers; they are not part of AgentPay.
- Do not pass agent tokens, passphrases, or proxy URLs as command-line arguments.
