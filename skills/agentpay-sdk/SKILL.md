---
name: agentpay-sdk
description: Install and operate the AgentPay SDK. Trigger this when an agent needs to install `agentpay`, explain AgentPay SDK capabilities without probing the machine first, set up or reuse a wallet, check funding, generate funding instructions or a QR, guide the user through policy changes in the TUI or exact admin CLI when explicitly requested, route manual approvals to the local admin approval commands, execute transfers, approvals, or broadcasts using the current CLI behavior instead of stale examples, or use supported plugin-backed merchant payment flows when explicitly relevant.
homepage: https://worldlibertyfinancial.com
metadata: {"openclaw":{"skillKey":"agentpay-sdk","homepage":"https://worldlibertyfinancial.com","os":["darwin"],"requires":{"bins":["agentpay"]}}}
---

# AgentPay SDK

Use this skill as an operator playbook. Do not make the user design command flows or policy objects from scratch.

## What This Skill Covers

If the user asks what this skill can do, answer from this list first. Do not probe the local machine unless the user is asking you to act.

- install `agentpay`
- bootstrap `agentpay` and the AgentPay skill pack with the one-click installer
- explain whether the wallet can be reused or needs first-run setup
- guide the user through local wallet setup (self-custodial daemon mode)
- export, verify, and restore encrypted offline wallet backups
- check balances and stop for funding when money or gas is missing
- generate funding instructions and a QR
- send native assets, send ERC-20 tokens, approve allowances, and broadcast transactions
- pay x402-protected APIs (EIP-3009 signing)
- pay MPP-protected APIs on any EVM chain (charge on any chain, session on Tempo)
- use supported plugin-backed merchant payment flows when relevant
- guide the user through policy configuration in the TUI
- route manual approvals to the local admin approval commands
- surface pending manual approvals and tell the user how to approve or reject them

## Ground Truth

- Use `agentpay --help` and the relevant subcommand help as the source of truth when examples disagree.
- One-click bootstrap: `curl -fsSL https://wlfi.sh | bash`
- One-click skills only: `curl -fsSL https://wlfi.sh | bash -s -- --skills-only`
- One-click update: rerun `curl -fsSL https://wlfi.sh | bash`
- Source install or update: from the repo checkout run `pnpm install && npm run build && npm run install:cli-launcher && npm run install:rust-binaries`
- `agentpay wallet --json` is the wallet reuse check.
- `agentpay admin setup` is the first-run wallet setup path.
- Plugin-specific help lives under the current CLI. For Bitrefill, use `agentpay bitrefill --help`.
- Browser-based relay and web approval are unsupported in this release.
- `agentpay admin set-relay-config` and `agentpay admin get-relay-config` are legacy compatibility commands and return `unsupported`.
- `agentpay admin setup --reuse-existing-wallet` is the daemon recovery / local re-setup path when the current vault should be preserved.
- `agentpay admin setup --restore-wallet-from <PATH>` restores the same wallet from an encrypted offline backup.
- `agentpay admin wallet-backup export --output <PATH>` creates an encrypted offline backup.
- Do not use `sudo agentpay ...`.
- Do not tell users to run `agentpay daemon` directly.

## Wallet Model

AgentPay uses a self-custodial local daemon wallet.

- Setup: `agentpay admin setup`
- Local Rust daemon manages keys, policy enforcement, manual approval, and wallet backup
- Supports `transfer`, `transfer-native`, `approve`, `broadcast`, `x402`, and `mpp`
- Tempo session mode is available through `agentpay mpp`

## Default Payment Assumption

- Default network: `bsc`
- Default asset for unspecified payments: `USD1`
- Default USD1 contract on BSC: `0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d`
- Default gas asset on BSC: `BNB`

## Secure Input Rule

- Never ask the user to paste `VAULT_PASSWORD` into chat.
- Never ask the user to paste a wallet backup password into chat.
- Never ask the user to paste plugin session material into chat, including Bitrefill cookies, captcha tokens, or browser session material.
- Never collect or store the vault password inside the agent.
- If a flow needs vault input, move the user to a secure local prompt.
- For first-run setup, tell the user to run `agentpay admin setup` locally and follow the secure prompt there.
- After first-run setup, strongly prefer `agentpay admin wallet-backup export --output <PATH>` unless the user already has a verified backup.
- For daemon recovery with an existing wallet, tell the user to run `agentpay admin setup --reuse-existing-wallet` locally.
- For machine loss or local wallet loss when the user has a backup, tell them to run `agentpay admin setup --restore-wallet-from <PATH>` locally.
- For policy changes, default to `agentpay admin tui`.
- For manual approvals, prefer the local admin CLI approval commands.
- `agentpay transfer --broadcast`, `agentpay transfer-native --broadcast`, `agentpay approve --broadcast`, and `agentpay bitrefill buy --broadcast` keep the original CLI process alive while waiting for manual approval. Do not tell the user to rerun those commands after approving.
- If the original broadcast command has already exited but the request is approved, use `agentpay admin resume-manual-approval-request --approval-request-id <UUID>` instead of reconstructing the transaction by hand.

## Deterministic Flow

1. Classify the request as explain capabilities, install, setup wallet, back up wallet, restore wallet, fund wallet, set policy, send native asset, send ERC-20, approve allowance, broadcast raw tx, pay MPP API, plugin-backed merchant payment, or uninstall.
2. If the user is only asking what this skill can do, answer from `What This Skill Covers` and stop there.
3. For wallet or payment work, start with `agentpay config show --json`.
4. Run `agentpay wallet --json` to check wallet status.
5. If the wallet is unavailable and the task needs one, tell the user to run `agentpay admin setup` locally.
6. If the wallet exists but the user needs to re-run setup without changing vaults, use `agentpay admin setup --reuse-existing-wallet`.
7. If the user needs disaster recovery on a new machine and has an encrypted backup, use `agentpay admin setup --restore-wallet-from <PATH>`.
8. For policy configuration, default to `agentpay admin tui`.
9. If a request is queued for manual approval, tell the user it is waiting for approval and use the local admin CLI approval commands.
10. For `transfer --broadcast`, `transfer-native --broadcast`, `approve --broadcast`, and `bitrefill buy --broadcast`, tell the user to keep that original command running while they approve it.
11. For plugin-backed merchant payments, use the relevant current CLI plugin flow. If the user is specifically using Bitrefill, or the request is to pay a traditional merchant that only accepts cards and Bitrefill is the supported path, use Bitrefill.
12. If the user did not specify network or asset for a payment, fill in `bsc` and `USD1` before asking follow-up questions.
13. Before any outbound action, check funding.
14. If funding is missing, stop and ask the user to top up the wallet.
15. Only then run the exact current CLI command.

## Funding Rule

- Treat a fresh wallet as unfunded until the balance check proves otherwise.
- For native transfers, check native balance.
- For ERC-20 transfers and approvals, check both token balance and native gas balance.
- For Bitrefill purchases, check the settlement asset and the native gas asset on the chosen EVM chain before buying with `--broadcast`.
- For the default path, tell the user they may need both `USD1` for value and `BNB` for gas.
- When funding is missing, give the user:
  - wallet address
  - network and chain id
  - asset needed for value, if relevant
  - asset needed for gas
  - funding URI
  - a rendered QR image if the host supports markdown images
  - a `qrUrl` as fallback

## Bitrefill Plugin Rule

- For payment to traditional merchants that only accept cards, use bitrefill.
- If the merchant is present on bitrefill, directly purchase the gift card.
- Otherwise, purchase a prepaid VISA card.
- Bitrefill in this repo is EVM-only. Do not propose bitcoin, lightning, solana, or other non-EVM settlement methods.
- Default to preview first with `agentpay bitrefill buy ...` and add `--broadcast` only when the user wants to pay immediately.
- In Bitrefill quote and preview output, treat `amount` as the raw onchain base-unit integer, not a human-decimal amount. Examples: ETH base units are wei, and `amount: 1000000` with `decimals: 6` means `1 USDC`.
- `agentpay bitrefill buy --broadcast` pays through the existing Rust daemon signing path. It is not a separate wallet flow.
- If Bitrefill triggers a browser challenge, let the CLI bootstrap a local browser session and have the user complete the challenge locally.
- Bitrefill checkout still follows the normal funding and manual-approval rules in this skill.

## Current Command Shapes

- Wallet check: `agentpay wallet --json`
- Setup: `agentpay admin setup`
- Reuse existing wallet during setup recovery: `agentpay admin setup --reuse-existing-wallet`
- Restore wallet from encrypted backup: `agentpay admin setup --restore-wallet-from <PATH>`
- Export encrypted wallet backup: `agentpay admin wallet-backup export --output <PATH>`
- Verify encrypted wallet backup: `agentpay admin wallet-backup verify <PATH>`
- Native transfer: `agentpay transfer-native --network <name> --to <address> --amount <amount>`
- ERC-20 transfer: `agentpay transfer --network <name> --token <address> --to <address> --amount <amount>`
- Approve: `agentpay approve --network <name> --token <address> --spender <address> --amount <amount>`
- Policy-checked raw request: `agentpay broadcast --network <name> --to <address> --value-wei <wei> ...`
- Sign and send: `agentpay tx broadcast --network <name> --rpc-url <url> --from <address> --to <address> --value-wei <wei> ...`
- Policy editing: `agentpay admin tui`
- Default token limits: `agentpay admin token set-chain <tokenKey> <chainKey> --per-tx <amount> --daily <amount> --weekly <amount>`
- Manual approval policy: `agentpay admin add-manual-approval-policy --network <id> --min-amount-wei <wei> --max-amount-wei <wei> ...`
- Manual approval queue: `agentpay admin list-manual-approval-requests`
- Manual approval decision: `agentpay admin approve-manual-approval-request` or `agentpay admin reject-manual-approval-request`
- Resume approved broadcast-backed manual approval: `agentpay admin resume-manual-approval-request --approval-request-id <UUID>`
- Bitrefill search: `agentpay bitrefill search --query <text>`
- Bitrefill product: `agentpay bitrefill product --slug <slug>`
- Bitrefill buy quote: `agentpay bitrefill buy --slug <slug> --amount <value> [--payment-method <method>]`
- Bitrefill quote fields: `availablePaymentMethods[].amount` is the raw onchain base-unit integer.
- Bitrefill buy and pay: `agentpay bitrefill buy --slug <slug> --amount <value> --payment-method <method> --email <email> --broadcast [--no-wait]`
- Bitrefill preview payment fields: `payment.amount` is the raw onchain base-unit integer.
- Bitrefill invoice list: `agentpay bitrefill invoice list`
- Bitrefill invoice lookup: `agentpay bitrefill invoice get --invoice-id <id> [--access-token <token>]`
- Bitrefill invoice wait: `agentpay bitrefill invoice wait --invoice-id <id> [--access-token <token>] [--timeout <sec>]`

## Policy Rules

- Do not ask open-ended policy questions.
- Map user requests into one of these:
  - keep the existing policy
  - tighten default token limits in the TUI
  - add a manual approval range in the TUI
  - inspect or resolve manual approval requests
- Policy work should default to `agentpay admin tui`.
- Destination-specific overrides are a TUI path. Do not claim they were applied unless the user actually went through the TUI.
- Do not ask for `VAULT_PASSWORD` in chat for policy work. If the CLI or UI prompts locally, that secure prompt happens outside chat.

## Manual Approval Rule

- Treat a manual approval hit as pending, not failed.
- Tell the user the request is waiting for their approval.
- Use the local admin CLI approval commands first.
- For `transfer --broadcast`, `transfer-native --broadcast`, `approve --broadcast`, and `bitrefill buy --broadcast`, tell the user not to rerun the original command after approval. The CLI polls every 2 seconds for up to 5 minutes and continues automatically if the same approval request is approved.
- If the original broadcast command is already gone after approval, use `agentpay admin resume-manual-approval-request --approval-request-id <UUID>`.
- `agentpay broadcast` and other non-auto-waiting flows still print approval details and exit.
- If the user explicitly asks for raw CLI commands, use:
  - `agentpay admin list-manual-approval-requests`
  - `agentpay admin approve-manual-approval-request --approval-request-id <UUID>`
  - `agentpay admin resume-manual-approval-request --approval-request-id <UUID>`
  - `agentpay admin reject-manual-approval-request --approval-request-id <UUID> --rejection-reason <TEXT>`

## Minimal Clarification Rule

- If the user says "send money" and omits network or asset, do not ask for them first. Use the defaults.
- Only ask for the remaining critical fields:
  - amount
  - recipient
  - spender

## MPP Services

AgentPay can pay for any MPP-enabled API using `agentpay mpp`. No API keys or accounts are needed — payment happens inline via the HTTP 402 protocol. The CLI resolves the payment chain from the server challenge and supports any EVM-compatible network.

- Discover current MPP LLM/search services from `https://mpp.dev/services/llms.txt`. Do not rely on a static in-repo service directory.
- `--amount` is optional. When omitted, the CLI pays the server's challenge amount automatically. When provided, the CLI verifies the challenge amount matches before paying.
- The wallet must hold the payment token on the chain specified by the service challenge.
- `mpp` supports charge on any EVM-compatible chain.
- Session mode (escrow channels) is Tempo-only.

## Extra References

- Read [references/capabilities.md](./references/capabilities.md) only when you need exact flags or examples.
- Read [references/demo-walkthrough.md](./references/demo-walkthrough.md) only when you need a short live demo script.
