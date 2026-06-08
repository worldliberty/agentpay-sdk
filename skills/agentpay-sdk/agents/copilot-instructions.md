# AgentPay SDK Adapter

When a task touches Link fiat setup, wallet setup, funding, policy, transfers, approvals, cards, or backups, load and follow the installed `agentpay-sdk` skill.

Mandatory rules:

- start from `agentpay config show --json`
- for fiat/card payments, start with `agentpay link status --json`; if Link is not authenticated, use `agentpay link onboard`
- list Link payment methods with `agentpay link payment-methods --json`
- create one-time card credentials with `agentpay link card --payment-method-id <id> --merchant-name <name> --merchant-url <url> --amount <cents> --context <100+ char explanation> --output-file <PATH>` and never print full card details into chat
- for third-party program integration, use `@worldlibertyfinancial/agentpay-sdk/link` helpers through the AgentPay Link facade
- use `agentpay wallet --json` to determine whether a reusable wallet already exists
- if the user only asks what the skill can do, answer from `SKILL.md` and do not probe the machine first
- never ask the user to paste `VAULT_PASSWORD` or a wallet backup password into chat
- never ask the user to paste Link card numbers, CVCs, access tokens, refresh tokens, or full credential files into chat
- if wallet metadata is unavailable and the user is trying to use the wallet, tell them to run `agentpay admin setup` locally
- if the wallet exists and the user wants to preserve it while re-running setup, tell them to run `agentpay admin setup --reuse-existing-wallet` locally
- if the local wallet is gone but the user has an encrypted backup, tell them to run `agentpay admin setup --restore-wallet-from <PATH>` locally
- after a fresh setup, tell them to create an encrypted offline backup with `agentpay admin wallet-backup export --output <PATH>` unless they already have a verified backup
- default unspecified payments to `USD1` on `bsc`
- check funding before outbound actions
- if funding is missing, stop and ask the user to fund the wallet with the exact address, network, token needs, and BNB gas needs
- if a request hits manual approval, say it is waiting for user approval and route the user to the local admin CLI approval commands first; for `transfer --broadcast`, `transfer-native --broadcast`, `approve --broadcast`, and `bitrefill buy --broadcast`, tell them to keep the original command running and not rerun it after approval; if that original broadcast command is already gone after approval, use `agentpay admin resume-manual-approval-request --approval-request-id <UUID>`
- use `agentpay --help` and subcommand help as the source of truth for exact flags
- prefer `agentpay admin tui` for policy changes
