# AgentPay SDK

AgentPay SDK is a local runtime for self-custodial, policy-aware wallet operations. It lets you construct, sign, and broadcast blockchain transactions while keeping full control of the wallet and approval path.

The main entrypoint is the `agentpay` CLI, which manages the local daemon, wallet access, balances, policy, transfers, and approvals.

## Install

### One-click install

The fastest operator path is the interactive bootstrap script:

```bash
curl -fsSL https://wlfi.sh | bash
```

Documentation: `https://docs.worldlibertyfinancial.com/agentpay-sdk`

The script can:

- let the user choose an install directory
- download a prebuilt macOS runtime bundle instead of compiling Cargo or pnpm workspaces locally
- bootstrap Node 20+ when needed
- install `agentpay` into a dedicated `AGENTPAY_HOME`
- auto-detect and preselect supported AI agent targets and already-installed paths
- let the user toggle preset destinations and add custom skill/adaptor paths during install
- install skill packs for Codex, Claude, Cline, Goose, Windsurf, OpenClaw, portable `~/.config/agents`, legacy `~/.agents`, and matching workspace skill directories
- install workspace adapters for `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.github/copilot-instructions.md`, `.clinerules/agentpay-sdk.md`, and the Cursor rule pack
- install the Cursor adapter when the current directory is already a Cursor workspace or `AGENTPAY_SETUP_CURSOR_WORKSPACE` is set
- when no supported AI target is detected, offer the same integrations with all options enabled by default
- finish after installation and hand off wallet creation to a separate `agentpay admin setup` step by default
- do not configure browser-based relay or web approval services

### Skills only

If you only want the AI skill pack and adapters, without installing the local AgentPay SDK runtime:

```bash
curl -fsSL https://wlfi.sh | bash -s -- --skills-only
```

That mode:

- downloads the same macOS AgentPay SDK bundle used by the full installer and only applies the embedded skill files
- auto-detects supported AI agent paths and already-installed destinations
- presents a toggleable target list and lets the user add custom skill-pack or adapter destinations
- supports Codex, Claude, Cline, Goose, Windsurf, OpenClaw, portable/legacy `.agents`, Cursor, and workspace adapters like `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, and Copilot instructions
- installs the Cursor adapter when `AGENTPAY_SETUP_CURSOR_WORKSPACE` is set or the current directory is already a Cursor workspace
- does not install `agentpay`, Node.js, shell PATH exports, or wallet runtime files

### Prerequisites

- Full AgentPay SDK runtime install: macOS, network access to download the public installer assets, and Homebrew only when the machine does not already have Node.js `20+`
- `--skills-only`: network access plus a writable home directory or Cursor workspace target

The full one-click installer does not require local Cargo, pnpm, or a preinstalled Node runtime. It still installs Node `20+` locally when the machine does not already have a compatible Node available, because the `agentpay` launcher runs on Node.

### Install from source

```bash
pnpm install
pnpm run build
pnpm run install:cli-launcher
pnpm run install:rust-binaries
```

On macOS, add `export PATH="$HOME/.agentpay/bin:$PATH"` to `~/.zshrc`, then reload your shell with `source ~/.zshrc`.

On Linux, add `export PATH="$HOME/.agentpay/bin:$PATH"` to your shell startup file such as `~/.bashrc`, `~/.zshrc`, or `~/.profile`, then reload that file or open a new shell.

`npm run install:cli-launcher` installs the `agentpay` launcher into `~/.agentpay/bin`, and `npm run install:rust-binaries` installs the Rust runtime into the same directory.

### Update an existing install

- One-click install: rerun `curl -fsSL https://wlfi.sh | bash`
- Source install: pull the latest source and rerun:

```bash
pnpm install
pnpm run build
pnpm run install:cli-launcher
pnpm run install:rust-binaries
```

- If you only need to reconnect the current local vault after refreshing the runtime, use `agentpay admin setup --reuse-existing-wallet`

### Reinstall Rust daemon

If you update Rust daemon code from a source checkout, rerun `npm run install:rust-binaries` so the root-managed daemon uses the new installed binaries under `~/.agentpay/bin`.

## Usage

The main user path is:

1. run `agentpay admin setup`
2. let it install the daemon and set up a wallet
3. use `agentpay transfer`, `agentpay transfer-native`, `agentpay approve`, or `agentpay broadcast`
4. use the local admin approval commands when a policy pauses a request for manual review

User-facing examples below avoid shell env vars on purpose. Prefer prompts, config files, `agentpay admin tui`, and explicit command flags.

## Command model

- `agentpay admin setup`
  - first-run setup
  - `--reuse-existing-wallet` reattaches the current local vault when you need to recover the daemon or refresh local credentials without creating a fresh wallet
  - stores the vault password in macOS System Keychain
  - installs the root LaunchDaemon
  - creates a vault key + agent key
  - prints the Ethereum address
- `agentpay admin tui`
  - token-first policy editor for per-token defaults, destination overrides, and manual approvals
  - when a token or network draft is dirty, `Ctrl+S` saves that draft and reapplies wallet policies in one step
- `agentpay admin reset`
  - removes the managed daemon state and local wallet credentials
  - use it only when you are intentionally discarding the current wallet
- `agentpay admin uninstall`
  - fully removes the managed daemon, root-owned state, local config, local binaries, and logs
  - also removes one-click shell exports plus AgentPay SDK AI skill/adaptor installs created by the one-click bootstrap
  - use it when you want AgentPay SDK removed from the machine instead of preparing for another setup
  - after uninstall, there is no local wallet left on that machine to reuse; use `agentpay admin setup --reuse-existing-wallet` before uninstalling when you want to keep the current wallet
- `agentpay admin ...`
  - direct policy and manual-approval configuration commands
- `agentpay transfer`, `agentpay transfer-native`, `agentpay approve`, `agentpay broadcast`
  - submits signing requests through the daemon
  - uses the configured agent key id plus the macOS Keychain token by default
- `agentpay status`
  - inspects local wallet security posture, daemon/socket trust, state-file trust, bootstrap artifacts, and agent token storage
  - use `--strict` when you want CI or automation to fail on warnings
- `agentpay repair`
  - non-privileged local cleanup for plaintext bootstrap artifacts and legacy `agentAuthToken` config storage
  - uses `--overwrite-keychain` only when you have confirmed the plaintext config token is the credential you intend to keep
- `agentpay daemon`
  - not a user entrypoint; daemon lifecycle is managed by `agentpay admin setup`

## Shared config vs live wallet state

- `agentpay admin token set-chain ...` and the other `agentpay admin chain/token ...` editors update the local shared config in `~/.agentpay/config.json`. They do not change the live daemon wallet by themselves.
- `agentpay config show --json` prints that local shared config snapshot. Treat it as your saved source-of-truth draft, not as proof that the current daemon policy attachment already changed.
- Common shared-config commands:
  - add or update a saved network: `agentpay admin chain add <key> --chain-id <id> --name <name> --rpc-url <url>`
  - remove a saved network profile: `agentpay admin chain remove <key>`
  - add or update a token on one saved network: `agentpay admin token set-chain <tokenKey> <chainKey> --symbol <symbol> --native|--address <token> --decimals <count>`
  - remove one token/network mapping without deleting the token everywhere: `agentpay admin token remove-chain <tokenKey> <chainKey>`
  - remove a configured token entirely: `agentpay admin token remove <tokenKey>`
- To inspect the concrete contents behind wallet `attachedPolicyIds`, first read the ids from `agentpay config show --json`, then query the daemon policies directly with `agentpay admin list-policies --policy-id <uuid>`.
- To apply shared-config edits to the live wallet, use `agentpay admin tui` and save the draft there, or rerun `agentpay admin setup --reuse-existing-wallet` / `agentpay-admin bootstrap --from-shared-config`.
- `agentpay admin wallet-backup export --output ...` is the supported backup command and remains available under the `admin wallet-backup` subcommand tree.

## Easiest wallet setup

Run this once:

```bash
agentpay admin setup
```

Preview the exact sanitized setup plan first:

```bash
agentpay admin setup --plan
```

The preview is read-only. It does not prompt for the vault password, does not touch sudo, and does not mutate wallet or policy state. It prints the planned Rust command, trust preflight results, overwrite risk, and the password transport mode that would be used for the real setup.

During a real `agentpay admin setup`, you may be prompted for two different secrets:

- `Vault password`: the wallet password you choose for encrypted local state; local entry is confirmed twice to catch typos
- `macOS admin password for sudo`: your macOS login/admin password, used only when setup needs elevated privileges to install or recover the root LaunchDaemon

On a fresh wallet, interactive setup now skips the offline backup wizard by default so the first-run path stays short. If you want a backup during setup, pass `--backup-output <path>`. Otherwise export one afterward with `agentpay admin wallet-backup export --output <path>`.

If the local vault already exists and you only need to recover the managed daemon or refresh local setup state, reuse the current wallet instead of creating a fresh one:

```bash
agentpay admin setup --reuse-existing-wallet
```

This reuse path keeps the current vault address, prompts for `REUSE` in interactive mode, and still requires `--yes` in non-interactive mode.

## Offline wallet backup and restore

After first-run setup, keep an encrypted offline backup of the wallet somewhere separate from the machine itself.

Export a backup:

```bash
agentpay admin wallet-backup export --output ~/agentpay-backups/agentpay-wallet-backup.json
```

Verify the file before you depend on it:

```bash
agentpay admin wallet-backup verify ~/agentpay-backups/agentpay-wallet-backup.json
```

If you are moving to a new machine or recovering after local wallet loss, restore the same wallet with:

```bash
agentpay admin setup --restore-wallet-from ~/agentpay-backups/agentpay-wallet-backup.json
```

That restore flow keeps the wallet address the same, prompts for the backup password locally, and re-establishes the managed daemon plus fresh local agent credentials on the new machine.

After that, the command:

- installs or refreshes the root daemon
- waits for the daemon to come up
- configures the requested spending policies
- imports the agent token into macOS Keychain
- prints the wallet address

By default, setup keeps the freshly issued agent auth token in macOS Keychain and redacts it from CLI output. Only use `--print-agent-auth-token` when you intentionally need to export that secret.

Example with explicit chain config:

```bash
agentpay admin setup \
  --network 11155111 \
  --chain-name sepolia \
  --rpc-url https://rpc.sepolia.example \
  --allow-native-eth \
  --per-tx-max-wei 1000000000000000000 \
  --daily-max-wei 5000000000000000000 \
  --weekly-max-wei 20000000000000000000
```

Typical output ends with:

```text
setup complete
address: 0x...
vault key id: ...
agent key id: ...
daemon socket: /Library/AgentPay/run/daemon.sock
state file: /var/db/agentpay/daemon-state.enc
```

## Policy definition

There are three practical policy layers:

1. default limits for every destination
2. stricter per-destination overrides
3. manual-approval overlays for transactions that should pause for operator review

### Token-first policy setup: `agentpay admin tui`

Use the TUI when you want the easiest way to define:

- a saved token inventory as the primary view
- per-token per-tx / daily / weekly limits in token decimals
- per-token gas / fee / calldata caps
- token-specific destination overrides
- token-specific manual approval overlays
- token mappings across multiple saved networks

Run:

```bash
agentpay admin tui
```

Like `admin setup`, the TUI stores the new agent auth token in macOS Keychain by default and does not print it unless you pass `--print-agent-auth-token`.

The TUI starts on the token list, lets you add new tokens or networks, fetches token name/symbol/decimals from the selected network RPC, and bootstraps every saved token across its selected networks.

In the `Network Multi-Select` field, first save the networks you want in the Networks view, then use `←/→` or `h/l` (also `a/d`) to move the focus marker across those saved networks and press `Space` or `Enter` to toggle the focused network into the token.

There is no separate "save only" step for dirty token/network drafts in the TUI. `Ctrl+S` persists the draft and reapplies the wallet together.

Important rule: destination overrides can only tighten the matching token policy; they cannot relax it.

Spend window policies are signing-budget controls, not post-settlement accounting. A request counts against daily/weekly usage once the daemon successfully approves and signs it, including completed manual approvals, even if the signed transaction is broadcast later or ultimately fails on-chain.

### Direct setup flags

If you prefer direct flags over the TUI, `agentpay admin setup` already passes through the common policy and wallet-setup options shown above.

Useful direct flags include:

- `--per-tx-max-wei`
- `--daily-max-wei`
- `--weekly-max-wei`
- `--max-gas-per-chain-wei`
- `--daily-max-tx-count`
- `--per-tx-max-fee-per-gas-wei`
- `--per-tx-max-priority-fee-per-gas-wei`
- `--per-tx-max-calldata-bytes`
- `--network`
- `--token`
- `--allow-native-eth`
- `--recipient`

### Manual approval policies

Manual approval is an overlay policy: matching requests are held until an operator approves or rejects them.

Create one with direct flags:

```bash
agentpay admin add-manual-approval-policy \
  --network 11155111 \
  --recipient 0x1111111111111111111111111111111111111111 \
  --allow-native-eth \
  --min-amount-wei 1000000000000000 \
  --max-amount-wei 2000000000000000
```

ERC-20 example:

```bash
agentpay admin add-manual-approval-policy \
  --network 11155111 \
  --recipient 0x2222222222222222222222222222222222222222 \
  --token 0x3333333333333333333333333333333333333333 \
  --min-amount-wei 1000000 \
  --max-amount-wei 5000000
```

The policy matches all transactions of the requested type that fall inside the destination / token / amount range.

Manual approval is still an overlay, not an override. Matching transfers must continue to satisfy every stricter hard limit such as per-tx, daily, weekly, gas, fee, and calldata caps before they can reach the approval flow.

### Inspect and resolve manual approvals locally

```bash
agentpay admin list-manual-approval-requests
```

Approve locally:

```bash
agentpay admin approve-manual-approval-request \
  --approval-request-id <REQUEST_ID>
```

Resume an already-approved broadcast-backed request on this machine:

```bash
agentpay admin resume-manual-approval-request \
  --approval-request-id <REQUEST_ID>
```

Reject locally:

```bash
agentpay admin reject-manual-approval-request \
  --approval-request-id <REQUEST_ID>
```

## Agent requests

Top-level signing commands always go through the daemon.

After `agentpay admin setup`, the normal path is to rely on the configured agent key id plus the token already stored in macOS Keychain. You only need `--agent-key-id` or `--agent-auth-token-stdin` when overriding that default.

Native transfer:

```bash
agentpay transfer-native \
  --network 11155111 \
  --to 0x1111111111111111111111111111111111111111 \
  --amount-wei 1500000000000000
```

ERC-20 transfer:

```bash
agentpay transfer \
  --network 11155111 \
  --token 0x3333333333333333333333333333333333333333 \
  --to 0x2222222222222222222222222222222222222222 \
  --amount-wei 1000000
```

Approve allowance:

```bash
agentpay approve \
  --network 11155111 \
  --token 0x3333333333333333333333333333333333333333 \
  --spender 0x4444444444444444444444444444444444444444 \
  --amount-wei 1000000
```

Raw policy-checked transaction request:

```bash
agentpay broadcast \
  --network 11155111 \
  --to 0x1111111111111111111111111111111111111111 \
  --gas-limit 21000 \
  --max-fee-per-gas-wei 2000000000 \
  --value-wei 1500000000000000
```

If a request hits a manual-approval policy, the CLI prints:

- approval request id
- local admin CLI approval command

## Local health checks and cleanup

Inspect the current machine state:

```bash
agentpay status
```

Strict mode is useful in automation:

```bash
agentpay status --strict
```

Repair local non-root issues such as lingering plaintext bootstrap files or legacy `agentAuthToken` config storage:

```bash
agentpay repair
```

If you intentionally want to keep bootstrap artifacts but redact them in place instead of deleting them:

```bash
agentpay repair --redact-bootstrap
```

## Manual approval flow

Browser-based relay and web approval are unsupported in this release. Legacy relay config commands remain present only for compatibility and return `unsupported`.

When a request requires manual approval:

1. the agent CLI prints an approval request id and a local admin CLI approval command
2. the operator approves or rejects the request locally with:

```bash
agentpay admin list-manual-approval-requests
agentpay admin approve-manual-approval-request --approval-request-id <UUID>
agentpay admin reject-manual-approval-request --approval-request-id <UUID> --rejection-reason "<TEXT>"
```

3. for `agentpay transfer --broadcast`, `agentpay transfer-native --broadcast`, and `agentpay approve --broadcast`, the original CLI command keeps waiting on that same approval request and continues automatically after approval
4. if that original broadcast command has already exited after the request was approved, recover the same approved request locally with `agentpay admin resume-manual-approval-request --approval-request-id <UUID>`

For the auto-waiting broadcast flows above:

- do not rerun the original command after approving locally
- the CLI polls every 2 seconds for up to 5 minutes
- if the daemon returns a different approval request id while waiting, the CLI stops and tells you to inspect the approval status before rerunning
- approval details and waiting events go to `stderr`; the final successful `--json` result still goes to `stdout`
- if the original command is already gone but the request is still `Approved`, use `agentpay admin resume-manual-approval-request --approval-request-id <UUID>` instead of rebuilding the transaction by hand

## Operational notes

- The daemon state file lives at `/var/db/agentpay/daemon-state.enc` and is intended to be root-only.
- The managed socket lives at `/Library/AgentPay/run/daemon.sock`.
- If `setup` says the daemon password does not unlock the stored state, use the original vault password or reset the managed state before setting up a fresh wallet.
- If the machine is lost or the local wallet is gone, restore from your encrypted offline backup with `agentpay admin setup --restore-wallet-from <backup.json>`.
- Forgotten vault password recovery is still destructive if you do not have a valid offline backup: run `agentpay admin reset`, then `agentpay admin setup` to create a new wallet.
- After changing daemon-side Rust code, run `npm run install:rust-binaries` and restart the managed daemon through `agentpay admin setup`.

## Reset a forgotten password

If you forgot the vault password and do not have a valid offline backup, there is no recovery path for the existing encrypted daemon state. Use reset only when you intentionally want to discard the old wallet and create a new wallet.

If you do have a wallet backup, do not reset. Use:

```bash
agentpay admin setup --restore-wallet-from <backup.json>
```

```bash
agentpay admin reset
```

For automation or CI-style local flows:

```bash
agentpay admin reset --yes
```

By default, reset keeps non-secret config like chain settings, but removes the managed daemon state, the daemon password stored in System Keychain, the local agent token, and lingering bootstrap artifacts.

If you want a totally clean local slate too:

```bash
agentpay admin reset --yes --delete-config
```

After reset, run `agentpay admin setup` to create a new wallet.

## Fully uninstall AgentPay SDK

Use uninstall when you want a full local cleanup instead of preparing for another setup. It removes:

- the managed LaunchDaemon
- `/Library/AgentPay`
- `/var/db/agentpay`
- `/var/log/agentpay`
- `~/.agentpay`
- the daemon password in System Keychain
- the local agent auth token in Keychain

`agentpay admin uninstall` removes the managed daemon and local AgentPay SDK files on that machine. If you are running from a repo checkout or another non-managed source path, the managed state is still removed but your current source checkout is left alone.

```bash
agentpay admin uninstall
```

For automation or CI-style local flows:

```bash
agentpay admin uninstall --yes
```

## Open-source governance

- License: [MIT](LICENSE)
- Contributing guide: [CONTRIBUTING.md](CONTRIBUTING.md)
- Security policy and vulnerability reporting: [SECURITY.md](SECURITY.md)
- Legal disclaimer: [LEGAL_DISCLAIMER.md](LEGAL_DISCLAIMER.md)
