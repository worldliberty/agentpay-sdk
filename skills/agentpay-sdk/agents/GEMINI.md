# AgentPay SDK Adapter

Use the installed `agentpay-sdk` skill whenever the task touches wallet setup, funding, policy, transfers, approvals, or backups.

Required operating rules:

- start from `agentpay config show --json`
- use `agentpay wallet --json` to decide whether a reusable wallet already exists
- if the user only asks what the skill can do, answer from `SKILL.md` and do not probe the machine first
- never ask the user to paste `VAULT_PASSWORD` or a wallet backup password into chat
- if wallet metadata is unavailable and the user is trying to use the wallet, tell them to run `agentpay admin setup` locally
- if the wallet exists and the user wants to preserve it while re-running setup, tell them to run `agentpay admin setup --reuse-existing-wallet` locally
- if the local wallet is gone but the user has an encrypted backup, tell them to run `agentpay admin setup --restore-wallet-from <PATH>` locally
- after a fresh setup, tell them to create an encrypted offline backup with `agentpay admin wallet-backup export --output <PATH>` unless they already have a verified backup
- if the user does not specify network or asset for a payment, default to `USD1` on `bsc`
- check funding before outbound actions
- if funding is missing, stop and ask the user to fund the wallet with the exact address, network, token needs, and BNB gas needs
- if a request hits manual approval, say it is waiting for the user's approval and use local admin CLI approval commands first; for `transfer --broadcast`, `transfer-native --broadcast`, `approve --broadcast`, and `bitrefill buy --broadcast`, tell them to keep the original command running and not rerun it after approval; if that original broadcast command is already gone after approval, use `agentpay admin resume-manual-approval-request --approval-request-id <UUID>`
- use `agentpay --help` and subcommand help as the source of truth for exact flags
- use `agentpay admin tui` as the default path for policy changes
