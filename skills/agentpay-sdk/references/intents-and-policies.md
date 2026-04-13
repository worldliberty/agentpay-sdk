# Intents And Policies

## Deterministic Intent Handling

- `install`: install `agentpay`
- `setup-wallet`: run `agentpay admin setup`
- `reuse-wallet-setup`: run `agentpay admin setup --reuse-existing-wallet`
- `backup-wallet`: run `agentpay admin wallet-backup export --output <PATH>`
- `restore-wallet`: run `agentpay admin setup --restore-wallet-from <PATH>`
- `fund-wallet`: provide address, network, asset, and QR
- `send-native`: use `agentpay transfer-native`
- `send-token`: use `agentpay transfer`
- `approve-token`: use `agentpay approve`
- `set-policy`: guide the user through `agentpay admin tui`
- `manual-approval`: tell the user the request is waiting for approval, then guide them to the exact local admin CLI approval commands

## Minimal Clarification

- If network is missing, use `bsc`.
- If asset is missing for a payment, use `USD1` on `bsc`.
- Only ask for the remaining critical fields:
  - amount
  - recipient
  - spender

## Wallet Logic

- If `agentpay wallet --json` works, reuse that wallet.
- If it fails with wallet metadata unavailable, run `agentpay admin setup` when the user is trying to transact now.
- If the wallet exists but the user needs to re-run setup without changing vaults, run `agentpay admin setup --reuse-existing-wallet`.
- If the wallet or machine is gone but the user has an encrypted backup file, run `agentpay admin setup --restore-wallet-from <PATH>`.
- Save the printed wallet address immediately after setup.

## Funding Logic

- Native transfer: check native balance first.
- ERC-20 transfer or approve: check token balance and native gas balance.
- For default `USD1 on bsc`, explain that `USD1` is the payment asset and `BNB` is the gas asset.
- If funding is missing, stop and ask the user to top up before sending.

## Policy Logic

- Never ask the user to paste `VAULT_PASSWORD` into chat.
- Default to `agentpay admin tui` for policy changes.
- If the user gives concrete limits, tell them exactly which network, token, and ceilings to enter in the TUI.
- If the user says "pause bigger payments", tell them to add a manual approval threshold in the TUI for that amount range.
- If the user wants destination-specific overrides, use `agentpay admin tui` or say plainly that the current non-interactive path does not apply them.
- If a payment is waiting for manual approval, describe it as pending approval and explain how the user can approve or reject it.
- Prefer the local admin CLI approval commands for manual approvals.
- For `transfer --broadcast`, `transfer-native --broadcast`, `approve --broadcast`, and `bitrefill buy --broadcast`, tell the user to keep the original command running after approving locally.
- If that original broadcast command is already gone after approval, tell the user to use `agentpay admin resume-manual-approval-request --approval-request-id <UUID>`.
