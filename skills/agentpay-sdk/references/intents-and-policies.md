# Intents And Policies

## Deterministic Intent Handling

| Intent | Action |
|---|---|
| `install` | install script, then the user runs `agentpay setup` |
| `setup-wallet` | the user runs `agentpay setup` and chooses "Create a new wallet" |
| `reuse-wallet-setup` | the user runs `agentpay setup` and chooses "Keep the existing wallet" |
| `restore-wallet` | the user runs `agentpay setup` and chooses "Restore from a backup" |
| `backup-wallet` | the user runs `agentpay admin wallet-backup export --output <PATH>` |
| `fund-wallet` | `agentpay fund --json` (add `--qr`); give address, network, asset, gas, URI |
| `send-token` | `agentpay transfer … --broadcast --json` |
| `send-native` | `agentpay transfer-native … --broadcast --json` |
| `approve-token` | `agentpay approve … --broadcast --json` |
| `broadcast-tx` | `agentpay broadcast … --broadcast --json` |
| `send-solana` | `agentpay transfer-sol` / `agentpay transfer-spl … --broadcast --json` |
| `pay-api` | `agentpay x402 <url> --json` or `agentpay mpp <url> --json` |
| `proxy` | `agentpay proxy start --json` |
| `set-limits` | the user runs `agentpay admin limits` |
| `manual-approval` | say it is waiting for approval; the user runs `agentpay admin approve <UUID>` |
| `resume-payment` | `agentpay resume --approval-request-id <UUID> --json` after approval |

## Minimal Clarification

- If network is missing, use `bsc`.
- If asset is missing for a payment, use `USD1` on `bsc`.
- Only ask for the remaining critical fields: amount, recipient, or spender.

## Wallet Logic

- If `agentpay wallet --json` succeeds, reuse that wallet.
- If it exits with code `4`, the user runs `agentpay setup` when they want to transact now.
- If the services are unhealthy, the user reruns `agentpay setup` and keeps the existing wallet.
- If the machine or wallet is gone and the user has an encrypted backup, the user restores it in
  `agentpay setup`.
- Save the wallet address after setup.

## Funding Logic

- Native transfer: check the native balance first.
- ERC-20 transfer or approve: check the token balance and the native gas balance.
- For the default `USD1` on `bsc`, `USD1` is the payment asset and `BNB` is the gas asset.
- If funding is missing, stop and ask the user to top up before sending.

## Policy Logic

- Never ask for a backup passphrase or agent token in chat.
- Limits are deny by default: an asset with no limit cannot be spent. If a payment fails with a
  `Policy` error for an unlisted asset, the user adds a limit for it.
- Default to `agentpay admin limits` for limit changes.
- If the user gives concrete limits, give the exact
  `agentpay admin limits set <asset> --network <net> --per-tx <amount> --daily <amount> --weekly <amount>`
  for them to run.
- To stop an asset entirely, `agentpay admin limits set <asset> --network <net> --exclude`.
- Approval follows the limits: within them a payment goes out on its own, beyond any of them
  (per payment, per day, per week, daily count) it waits for the user's approval instead of being
  refused. There is no separate approval threshold. `agentpay activity --json` shows what waits
  and why.
- Recipient-specific overrides are not client commands in this version; say so plainly and point
  to the signer daemon API (`AddPolicy`) for integrators.
- If a payment is waiting for manual approval, describe it as pending and tell the user how to
  approve or reject it locally.
- For EVM and Solana `--broadcast` payments, the original command waits (up to `--approval-wait`,
  300 seconds by default). Tell the user to keep it running.
- If that command already exited with code `3`, use
  `agentpay resume --approval-request-id <UUID> --json` after approval. Do not rerun the original.
