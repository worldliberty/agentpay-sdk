# Install And Workflows

## Install AgentPay

```bash
curl -fsSL https://wlfi.sh | sh
agentpay setup
```

- The installer downloads the release for the OS and CPU, verifies its SHA-256 against the
  release's `SHA256SUMS`, installs it into `~/.agentpay`, and puts `agentpay` on `PATH`. It never
  uses sudo. Options go after `sh -s --`: `--yes`, `--verbose`, `--no-modify-path`;
  `AGENTPAY_VERSION` pins a release.
- `agentpay setup` asks for the user's password once (sudo) to install the signer daemon and the
  payments service (launchd on macOS, systemd on Linux), then opens the setup wizard.
- The wizard is interactive. The user runs it in their own terminal; an agent cannot complete it.
- Supported: macOS 13 or later, and Linux with systemd.

To update, rerun the installer and then `agentpay setup` (choose "Keep the existing wallet").

## Install The Skill

Copy the `agentpay-sdk/` folder into the agent's skill directory, for example:

```bash
mkdir -p ~/.claude/skills && cp -R /path/to/skills/agentpay-sdk ~/.claude/skills/agentpay-sdk
mkdir -p ~/.codex/skills && cp -R /path/to/skills/agentpay-sdk ~/.codex/skills/agentpay-sdk
mkdir -p ~/.openclaw/skills && cp -R /path/to/skills/agentpay-sdk ~/.openclaw/skills/agentpay-sdk
```

Workspace adapters live in `agents/`: `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`,
`copilot-instructions.md` (`.github/`), `cline-agentpay-sdk.md` (`.clinerules/`), and
`cursor-agentpay-sdk.mdc` (`.cursor/rules/`).

## Wallet Reuse vs Setup

```bash
agentpay wallet --json
```

- Exit `0`: the wallet exists; reuse it. Note `evm_address` and `solana_address`.
- Exit `4`: AgentPay is not installed or this user has no agent credentials. Tell the user to run
  `agentpay setup` locally.
- Exit `1` with `socket_untrusted`, `connect_failed`, or a `SignerUnavailable` error: the services
  are installed but unhealthy. `agentpay status --json` shows what is wrong; rerunning
  `agentpay setup` and choosing "Keep the existing wallet" repairs the install without changing the
  wallet.

## First-Run Setup

The user runs `agentpay setup`. The wizard steps:

1. **Welcome**: create a new wallet, restore from a backup, or keep the existing wallet.
2. **Protect your wallet** (macOS): turn on Touch ID for admin approvals, or skip and use sudo.
3. **Spending limits**: every seeded asset gets per-payment, daily, and weekly limits, or is
   blocked. Assets without a limit cannot be spent.
4. **Create wallet**: keys, agent credentials (saved to the keychain), and limits.
5. **Back up**: export an encrypted backup (passphrase of at least 12 characters).
6. **Done**: shows the wallet address and how to add funds.

If the user skipped the backup, recommend:

```bash
agentpay admin wallet-backup export --output ~/agentpay-backup.json
agentpay admin wallet-backup verify ~/agentpay-backup.json
```

The passphrase is entered in the local prompt. Never ask for it in chat.

## Re-Run Setup Without Changing The Wallet

The user runs `agentpay setup` and chooses **Keep the existing wallet**. This reinstalls or upgrades
the services, keeps the wallet key and spend history, rotates the agent token, and applies the
limits chosen in the wizard.

## Restore A Wallet From Backup

On the new machine the user installs AgentPay, runs `agentpay setup`, and chooses **Restore from a
backup**, then enters the backup file path and passphrase locally. Backups from earlier AgentPay
releases (formats v1 and v2) restore.

## Upgrading From A Vault-Password Install

Running `agentpay setup` on a machine set up by an earlier release migrates the daemon state from
the old vault password to a machine secret automatically. The wallet and its address stay the same.
No password is needed afterwards.

## Funding A Wallet Before Sending Money

1. `agentpay wallet --json` and read the `balances` entry for the network and asset.
2. For ERC-20 payments also read the native coin entry for gas (BNB on BSC, ETH on Ethereum).
   Tempo needs no native gas.
3. If either is short, stop and run:

   ```bash
   agentpay fund --network bsc --asset usd1 --amount 25 --json
   ```

4. Give the user the `address`, the network and `chain_id`, the asset (`symbol`, `token`), the gas
   asset from `gas`, and the `uri`. Add `--qr` to show a QR code in the terminal.
5. Wait for the user to confirm funding, then check `agentpay wallet --json` again.

## Spending Limits

- Interactive (default): the user runs `agentpay admin limits`.
- Exact command, when the user asks for one:

  ```bash
  agentpay admin limits set usd1 --network bsc --per-tx 10 --daily 50 --weekly 200
  agentpay admin limits set eth --network eth --exclude
  ```

- Show current limits and usage: `agentpay admin limits --json` (admin authority needed).
- Limits are per network and asset; daily and weekly are rolling 24 hours and 7 days. Per day
  should be at least per payment, and per week at least per day.
- Admin authority: Touch ID or Mac password on macOS with Touch ID enabled; otherwise `sudo`
  (`sudo agentpay admin limits set …`).

## Manual Approval Flow

1. A payment returns or waits with `manual_approval_pending` and an `approval_request_id`.
2. Tell the user it is waiting for their approval and give them:
   - `agentpay admin approve <UUID>` (or review everything with `agentpay admin approvals`)
   - `agentpay admin reject <UUID> --reason "<text>"` to refuse
3. If the original EVM or Solana `--broadcast` command is still running, it finishes on its own
   once approved. Do not rerun it.
4. If it already exited with code `3`, run `agentpay resume --approval-request-id <UUID> --json`
   after approval.
5. For `x402` and `mpp`, rerunning creates a new approval request. Use `--approval-wait <secs>` so
   the call waits while the user decides.

## Send Money

```bash
# USD1 on BSC (defaults)
agentpay transfer --to 0xRecipient --amount 5 --broadcast --json

# Native coin
agentpay transfer-native --network bsc --to 0xRecipient --amount 0.01 --broadcast --json

# Another ERC-20 by key or address
agentpay transfer --network eth --token 0xTokenAddress --to 0xRecipient --amount 12.5 --broadcast --json

# Allowance
agentpay approve --network bsc --token usd1 --spender 0xSpender --amount 100 --broadcast --json

# Agent-built transaction (calldata the policy engine does not recognize is refused)
agentpay broadcast --network bsc --to 0xContract --data-hex 0x… --broadcast --json

# Solana
agentpay transfer-sol --network solana-mainnet --to <address> --amount 0.25 --broadcast --json
agentpay transfer-spl --network solana-mainnet --mint <mint> --to <address> --amount 10 --broadcast --json
```

Check the result's `receipt.success` (EVM) before telling the user the payment landed.

## Uninstall

```bash
agentpay admin wallet-backup export --output <PATH>   # first, unless a verified backup exists
sudo ~/.agentpay/bin/agentpay-setup uninstall              # removes services and wallet state
sudo ~/.agentpay/bin/agentpay-setup uninstall --keep-state # keeps encrypted state and machine secret
rm -rf ~/.agentpay                                         # removes the client
```

## Not Available In This Version

- Stripe Link card payments and Bitrefill (removed; there are no `link` or `bitrefill` commands)
- Private (Railgun) transfers
- MPP sessions v1 (legacy escrow channels)
- Browser relay and web approval console
