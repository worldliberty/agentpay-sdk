# AgentPay SDK Adapter

When a task touches wallet setup, funding, spending limits, transfers, paid APIs, approvals, or backups, load and follow the installed `agentpay-sdk` skill.

Mandatory rules:

- start from `agentpay config show --json`
- use `agentpay wallet --json` to decide whether a reusable wallet already exists; exit code `4` means AgentPay is not set up for this user
- if the user only asks what the skill can do, answer from `SKILL.md` and do not probe the machine first
- never ask the user to paste a wallet backup passphrase, agent auth token, or paying-proxy URL into chat; there is no vault password
- never run `sudo` or `agentpay admin` decisions for the user; admin actions need the user's Touch ID, Mac password, or sudo, so give them the exact command to run locally
- if AgentPay is not set up and the user is trying to use the wallet, tell them to run `agentpay setup` locally
- if the wallet exists and the user wants to preserve it while re-running setup, tell them to run `agentpay setup` locally and choose "Keep the existing wallet"
- if the local wallet is gone but the user has an encrypted backup, tell them to run `agentpay setup` locally and choose "Restore from a backup"
- after a fresh setup, tell the user to create an encrypted offline backup with `agentpay admin wallet-backup export --output <PATH>` unless they already have a verified backup
- if the user does not specify network or asset for a payment, default to `USD1` on `bsc`
- check funding before outbound actions
- if funding is missing, stop and ask the user to fund the wallet with the exact address, network, token needs, and BNB gas needs (`agentpay fund --json`)
- pass `--json` and read exit codes: `0` ok, `1` failure (follow `error.next_action`), `2` usage, `3` waiting for manual approval, `4` not set up
- amounts for `transfer`, `transfer-native`, `approve`, and the Solana transfers are decimal whole units; amounts for `x402` and `mpp` are integer base units
- if a request hits manual approval, say it is waiting for the user's approval and give them `agentpay admin approve <UUID>`; for EVM and Solana `--broadcast` payments, tell them to keep the original command running and not rerun it; if that command already exited with code `3`, use `agentpay resume --approval-request-id <UUID>` after approval
- Stripe Link, Bitrefill, and private transfers are not available
- use `agentpay --help` and subcommand help as the source of truth for exact flags
- use `agentpay admin limits` (run by the user) as the default path for spending limit changes
