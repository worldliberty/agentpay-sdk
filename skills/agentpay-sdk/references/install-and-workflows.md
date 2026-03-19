# Install And Workflows

## Install The Skill

Fastest end-to-end bootstrap on macOS:

```bash
curl -fsSL https://wlfi.sh | bash
```

That installer can:

- choose an install directory
- download a prebuilt macOS AgentPay SDK runtime bundle instead of compiling locally
- bootstrap missing Node 20+ when the machine does not already have it
- install `agentpay`
- auto-detect and preselect supported agent destinations that already exist
- let the user toggle preset destinations and add custom skill-pack or adapter paths
- install the AgentPay skill pack into Codex, Claude, Cline, Goose, Windsurf, OpenClaw, portable `.config/agents`, legacy `.agents`, and matching workspace skill directories
- install workspace adapters for `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.github/copilot-instructions.md`, `.clinerules/agentpay-sdk.md`, and Cursor
- stop after installation so the user can run `agentpay admin setup` separately
- do not configure browser-based relay or web approval services

If the user only wants the skill pack and editor adapters, use:

```bash
curl -fsSL https://wlfi.sh | bash -s -- --skills-only
```

That path skips the AgentPay SDK runtime install and only writes the AI skill targets.
It reuses the standard macOS AgentPay SDK bundle, so release publishing only needs the normal installer assets.

Useful workspace overrides:

- `AGENTPAY_SETUP_WORKSPACE=/path/to/repo` for workspace adapters such as `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, Copilot, or project-local skill directories
- `AGENTPAY_SETUP_CURSOR_WORKSPACE=/path/to/repo` for the Cursor `.cursor/rules/agentpay-sdk.mdc` adapter

OpenClaw should consume the `agentpay-sdk/` folder directly as a skill pack.

Codex / local install:

```bash
mkdir -p ~/.codex/skills
cp -R /path/to/agentpay-sdk ~/.codex/skills/agentpay-sdk
```

OpenClaw / local install:

```bash
mkdir -p ~/.openclaw/skills
cp -R /path/to/agentpay-sdk ~/.openclaw/skills/agentpay-sdk
```

Claude Code / local install:

```bash
mkdir -p ~/.claude/skills
cp -R /path/to/agentpay-sdk ~/.claude/skills/agentpay-sdk
```

Cursor root adapter:

```bash
cp /path/to/agentpay-sdk/agents/AGENTS.md AGENTS.md
```

## Install Or Update From Source

From a repo checkout:

```bash
pnpm install
pnpm run build
pnpm run install:cli-launcher
pnpm run install:rust-binaries
```

One-click updates use the same bootstrap entrypoint:

```bash
curl -fsSL https://wlfi.sh | bash
```

If the runtime has already been refreshed and the user only needs to reconnect the existing local vault, use:

```bash
agentpay admin setup --reuse-existing-wallet
```

## Default Payment Assumption

If the user asks to send money and does not name a network or asset, use these defaults:

- network: `bsc`
- asset: `USD1`
- token address: `0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d`

This default removes two unnecessary clarification steps. The agent should still ask for the amount and recipient if those are missing.

## Wallet Reuse vs Setup

Start here:

```bash
agentpay config show --json
```

Then try:

```bash
agentpay wallet --json
```

Interpret the result like this:

- If `wallet --json` works, reuse the existing wallet.
- If it fails with `wallet metadata is unavailable`, the agent should treat that as "wallet setup is not in a reusable state yet" and move to setup.
- If `wallet --json` works but the user needs to re-run setup while preserving the same vault, use `agentpay admin setup --reuse-existing-wallet`.

## First-Run Setup

Do not ask the user to paste `VAULT_PASSWORD` into chat.

Run:

```bash
agentpay admin setup
```

The command:

- installs or refreshes the managed daemon
- creates the vault key and agent key
- imports the agent auth token into macOS Keychain
- prints the wallet address
- prompts securely in the local terminal if it needs vault input

Capture these values immediately:

- wallet address
- vault key id
- agent key id
- daemon socket
- state file

Do not discard the wallet address. The skill should remember it and use it for future funding prompts.

After a fresh setup, create and verify an encrypted offline wallet backup immediately:

```bash
agentpay admin wallet-backup export --output ~/agentpay-backups/agentpay-wallet-backup.json
agentpay admin wallet-backup verify ~/agentpay-backups/agentpay-wallet-backup.json
```

If the user skips the backup prompt during interactive setup, bring them back to this command pair before treating the wallet as safely recoverable.

## Reuse Existing Wallet During Setup Recovery

Use this when the local vault still exists but the user needs to recover the managed daemon, fix root-owned setup state, or refresh local credentials without creating a new wallet.

```bash
agentpay admin setup --reuse-existing-wallet
```

Important behavior:

- interactive mode asks for `REUSE`
- non-interactive mode still needs `--yes`
- the command preserves the current vault instead of generating a fresh one

## Restore A Wallet From Backup

Use this when the original machine is gone, local wallet metadata was lost, or the user is intentionally rebuilding the same wallet on a new machine and has an encrypted backup file.

```bash
agentpay admin setup --restore-wallet-from /path/to/agentpay-wallet-backup.json
```

Important behavior:

- the CLI asks locally for the backup password
- the restored wallet keeps the same address
- the managed daemon and local agent credentials are recreated on the new machine
- if the user does not have the backup file, this restore path is unavailable

## Funding A Wallet Before Sending Money

For outbound actions, always decide the network first.

Built-in practical examples in the current SDK:

- `bsc` -> chain id `56`, default RPC `https://bsc.drpc.org`
- `eth` -> chain id `1`
- `usd1` has built-in token mappings on `eth` and `bsc`
- `bnb` is the built-in native asset for `bsc`
- default settlement path for unspecified payments: `USD1` on `bsc`

Native balance check:

```bash
agentpay rpc balance \
  --address <ADDRESS> \
  --rpc-url <RPC_URL> \
  --json
```

ERC-20 balance check:

```bash
agentpay rpc balance \
  --address <ADDRESS> \
  --token <TOKEN_ADDRESS> \
  --rpc-url <RPC_URL> \
  --json
```

If native balance is zero or obviously too low for the requested action, stop and ask the user to fund the wallet first.

For the default `USD1 on bsc` flow:

- check `USD1` balance for the transfer value
- check `BNB` balance for gas
- if both are missing, tell the user to send the requested amount of `USD1` to the wallet on BSC and add a small amount of `BNB` for gas
- if only gas is missing, ask for `BNB` only
- if only token balance is missing, ask for `USD1` only

Generate a funding request payload:

```bash
node scripts/prepare-funding-request.mjs \
  --address <ADDRESS> \
  --chain-id <CHAIN_ID> \
  --network-name <NETWORK_NAME> \
  --amount-wei <SUGGESTED_TOP_UP_WEI> \
  --token-symbol <SYMBOL> \
  --json
```

That helper returns:

- the raw address
- a human-readable network label
- an `ethereum:` funding URI
- a local SVG data URI for image rendering
- a QR URL fallback
- a ready-to-send reminder sentence

Default to the rendered QR image in chat. Use the QR URL if the host strips data-URI images.

## Policy Setup

Do not ask the user to paste `VAULT_PASSWORD` into chat for policy work.

Default path:

```bash
agentpay admin tui
```

Use the TUI when the user wants to:

- change default token limits
- add manual approval rules
- add destination-specific rules
- review or resolve approval requests

When guiding the user, keep it concrete:

- tell them to open `agentpay admin tui`
- tell them which network and token to edit
- tell them the exact ceilings or approval thresholds to enter

## Policy CLI Reference

Only use the raw commands below if the user explicitly asks for exact CLI commands instead of the TUI.

### Native or Token Default Limits

Use this when the user gives concrete spending ceilings.

Example for BNB on BSC:

```bash
agentpay admin token set-chain bnb bsc \
  --native \
  --decimals 18 \
  --per-tx 0.01 \
  --daily 0.2 \
  --weekly 1.4 \
  --json
```

Example for USD1 on BSC:

```bash
agentpay admin token set-chain usd1 bsc \
  --address 0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d \
  --decimals 18 \
  --per-tx 10 \
  --daily 100 \
  --weekly 700 \
  --json
```

### Manual Approval Overlay

Use this when the user wants risky or high-value payments paused for review.

Native example:

```bash
agentpay admin add-manual-approval-policy \
  --network 56 \
  --allow-native-eth \
  --recipient 0x1111111111111111111111111111111111111111 \
  --min-amount-wei 1000000000000000 \
  --max-amount-wei 5000000000000000
```

ERC-20 example:

```bash
agentpay admin add-manual-approval-policy \
  --network 56 \
  --token 0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d \
  --recipient 0x2222222222222222222222222222222222222222 \
  --min-amount-wei 1000000000000000000 \
  --max-amount-wei 10000000000000000000
```

### Recipient-Specific Overrides

Current CLI exposes recipient-specific overrides through the TUI rather than a direct non-interactive command.

Only do that when a human is actively present in the terminal and has explicitly asked for destination-specific rules.

## Manual Approval Flow

If a payment hits a manual approval rule, do not describe it as a failed send.

Tell the user:

- the request was created and is waiting for approval
- they should use the local admin CLI approval commands
- for `transfer --broadcast`, `transfer-native --broadcast`, `approve --broadcast`, and `bitrefill buy --broadcast`, they should keep the original command running instead of rerunning it after approval
- if that original broadcast command is already gone after approval, they should use `agentpay admin resume-manual-approval-request --approval-request-id <UUID>`

If they explicitly want CLI commands, use:

```bash
agentpay admin list-manual-approval-requests
agentpay admin approve-manual-approval-request --approval-request-id <UUID>
agentpay admin resume-manual-approval-request --approval-request-id <UUID>
agentpay admin reject-manual-approval-request --approval-request-id <UUID> --rejection-reason "user rejected"
```

## Send Money

Native asset request:

```bash
agentpay transfer-native \
  --network bsc \
  --to 0x1111111111111111111111111111111111111111 \
  --amount 0.001 \
  --json
```

ERC-20 request:

```bash
agentpay transfer \
  --network bsc \
  --token 0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d \
  --to 0x2222222222222222222222222222222222222222 \
  --amount 1 \
  --json
```

Approve allowance:

```bash
agentpay approve \
  --network bsc \
  --token 0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d \
  --spender 0x3333333333333333333333333333333333333333 \
  --amount 1 \
  --json
```

If the user wants the signed transaction actually sent to the network in the same step, add `--broadcast` for `transfer`, `transfer-native`, `approve`, or `bitrefill buy`, or use `agentpay tx broadcast`.

For Bitrefill quote and preview output, `amount` is the raw onchain base-unit integer, not a human-decimal amount. Example: ETH base units are wei, and `amount: 1000000` with `decimals: 6` means `1 USDC`.

## Unsupported Features

Browser-based relay and web approval are unsupported in this release.

Legacy relay config commands remain present only for compatibility and return `unsupported`:

```bash
agentpay admin set-relay-config
agentpay admin get-relay-config
```
