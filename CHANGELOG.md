# Changelog

All notable changes to AgentPay SDK are documented in this file.

## [1.0.0] - 2026-11-08

AgentPay 1.0.0 is a rewrite. All product logic moves into two Rust daemons with a documented API,
and the TypeScript CLI is replaced by a small Ink client. Changes are relative to 0.5.0; the 0.6.0
development line was never released and is folded into this release.

### Architecture

- `agentpay-daemon` (signer daemon, root) keeps keys, policies, spending limits, manual approvals,
  and nonces, as before, but its state is now encrypted (HKDF-SHA256 + XChaCha20-Poly1305) under a
  random machine secret stored root-only: the System Keychain on macOS, a `0600` root file on Linux
- new `agentpay-paymentd` payments service, running as an unprivileged service account
  (`_agentpay` / `agentpay`), does all network work: EVM (alloy) and Solana RPC, transaction
  building, verification, and broadcast, x402, MPP, the paying proxy, balances, funding requests,
  and telemetry. It holds no keys and asks the signer daemon for every signature as the calling
  agent
- new `agentpay` client (TypeScript + Ink): the command line with `--json` output and the terminal
  UI (setup wizard, home, receive, approvals, limits, security). It contains no payment logic
- new `agentpay-setup` installer, run under sudo: installs binaries, the machine secret, the
  payments service account, and launchd/systemd units for both services; idempotent; `uninstall
  [--keep-state]`
- new `agentpay-auth` helper (macOS, Swift/CryptoKit): a Secure Enclave P-256 admin key that
  signs the signer daemon's admin challenges after Touch ID or the Mac login password
- `crates/agentpay-api`: the public daemon API contract, published as API `1.1.0`, with
  `docs/daemon-api.md`, a JSON Schema (`docs/api/schema.json`), and generated TypeScript types
  (`cargo xtask gen-api`)
- Rust crates renamed from `vault-*` to `agentpay-*`; the repository is one Cargo workspace plus
  `client/` (npm), with `just` recipes and `cargo xtask` tooling instead of pnpm, turbo, and tsup

### Added

- setup wizard (`agentpay setup`): create, restore, or keep a wallet; Touch ID; spending limits;
  encrypted backup. Keeping a wallet shows its address, and asks which one when the machine has
  several
- `agentpay admin wallets [--json]` lists the wallets on the machine (signer daemon `ListWallets`:
  addresses, creation time, agent keys; no secrets); `agentpay admin wallet-backup export
  --wallet <vault-key-id|address>` picks the wallet to back up when there are several
- spending limits per network and asset (per payment, rolling 24 hours, rolling 7 days), deny by
  default: an asset without a limit cannot be spent. `agentpay admin limits` (interactive) and
  `agentpay admin limits set`
- admin approvals with Touch ID or the Mac password (`agentpay admin touch-id enable`), or `sudo`
  on Linux, over SSH, or when Touch ID is off
- `agentpay resume --approval-request-id <id>` finishes an EVM or Solana payment that waited for
  manual approval by resending the stored action unchanged
- `agentpay proxy start|stop|status`: a loopback HTTP proxy that pays x402 and MPP `402` answers for
  any HTTP client, with a per-run token and certificate authority, `--allow-host`, and
  `--max-amount`
- `agentpay fund [--qr]`: funding address, EIP-681 or Solana Pay URI, gas hint, and a terminal QR
  code rendered by the payments service
- `agentpay status`: service, signer, chain, and limit health with warnings
- built-in Arbitrum, Arbitrum Sepolia, Base, Base Sepolia, Optimism, and Polygon networks with
  public RPC endpoints and backups, native USDC and ETH on each (POL on Polygon); paymentd adds
  them to a stored configuration once when it loads it, without changing existing entries, and a
  network removed afterwards stays removed
- built-in tokens: USDC on Ethereum and BSC, and USD1 on Solana and on Tempo (the TIP-20
  `0x20c0…e910f0f`), added to stored configurations once like new networks
- MPP charges on any configured EVM network: `evm` (`draft-evm-charge-00`, BNB Chain's MPP SDK)
  and `arbitrum` (`@arbitrum/mpp`), paid with the first credential the merchant accepts in the
  order `authorization` (EIP-3009), `permit2` (a Permit2 witness permit, with a one-time Permit2
  approval per token and chain), `hash`, `transaction`, so the agent pays no gas when it can;
  split payments are paid with `permit2`
- MPP `solana` charges (`draft-solana-charge-00`, `@solana/pay-kit`) in pull mode, including
  merchant-paid fees, splits, and `externalId` memos
- `agentpay mpp` and `agentpay proxy start` take `--network`, and `--currency` takes an EVM
  token, a Solana mint, or `sol`
- `examples/sample-llm`: an example third-party tool that streams LLM answers from an MPP merchant
  through `agentpay proxy` and reports what it was charged
- Tempo MPP sessions on TIP-1034 reserve channels (sessions v2), with `--session-key`,
  `--max-deposit`, `--currency`, and `--close-session`; channels are bound to the opening agent key
  and vouchers are capped at the deposited total
- exit codes: `0` success, `1` failure, `2` usage error, `3` waiting for manual approval, `4` not
  installed or no agent credentials; `--json` errors are `{"error": {"code", "message",
  "next_action"}}`

### Changed

- `agentpay setup` replaces `agentpay admin setup`; reusing (`--reuse-existing-wallet`) and
  restoring (`--restore-wallet-from`) a wallet are choices in the setup wizard
- `agentpay admin approvals`, `approve <id>`, and `reject <id>` replace the
  `*-manual-approval-request` commands; `agentpay admin limits` replaces `agentpay admin tui` for
  limits
- `agentpay mpp` and `agentpay x402` amounts (`--amount`, `--deposit`, `--max-deposit`,
  `--max-amount`) are integer base units, as in the merchant challenge
- `agentpay mpp --session-state-file <path>` maps to a session key; session state is kept by the
  payments service instead of a client file
- wallet backups (`agentpay admin wallet-backup export|verify`) are written and read inside the
  signer daemon (format v2: scrypt N=2^18 + AES-256-GCM); the passphrase needs at least 12
  characters
- telemetry (Mixpanel usage analytics, Sentry crash reports) is sent by the payments service under
  the same privacy rules; `agentpay telemetry disable` turns it off
- `u128` amounts, counts, and limits are decimal strings everywhere on the wire
- MPP challenge ranking puts challenges the wallet cannot pay last (balances are read before
  choosing), then prefers payments that need no native coin for gas; a transaction the wallet
  cannot pay the gas for is refused before anything is signed
- one MPP request pays at most one charge: a merchant that answers a charge credential with
  another `402` does not get a second one

### Removed

- the TypeScript CLI (`src/`), its npm package and `./link` export, and the pnpm/turbo/tsup
  monorepo
- the vault password: no prompts, no `--vault-password-stdin`, no password lockout
- Railgun private transfers (`private-balance` and related commands, the prover and vector
  generator apps)
- the relay and web approval console (`apps/relay`, `apps/web`) and `set-relay-config` /
  `get-relay-config`
- Stripe Link (`agentpay link …`) and Bitrefill (`agentpay bitrefill …`)
- MPP sessions v1 (legacy escrow channels) and the TypeScript MPP implementation
- plaintext private key export (`export-vault-private-key`, `--print-vault-private-key`)
- the XPC transport, the Windows TPM backend, and the Secure Enclave wallet backend
- the old `agentpay-admin` and `agentpay-agent` binaries
- the bash one-click installer and its Node.js/Homebrew bootstrap and skill-pack installation;
  `curl -fsSL https://wlfi.sh | sh` now runs `scripts/install.sh`, which installs the release into
  `~/.agentpay` without sudo

### Security

- calldata the policy engine does not recognize is denied by default; value-bearing EIP-712 data
  cannot bypass spending limits; an attachment with no enabled policies denies
- manual-approval policies no longer mask hard limits
- the signer daemon reconstructs every Tempo session payload from structured fields before signing
- capped nonce skipping and the number of pending manual-approval requests
- secrets travel only on stdin, pipes, or the daemon sockets, never in arguments or environment
  variables
- the payments service runs unprivileged and is on the signer daemon's agent allowlist only
- Permit2: permits are signed only as the policy-checked `Permit2WitnessTransfer` action (the sum
  of the entries counts against limits, with the spender as the recipient); generic EIP-712 data
  bound to the Permit2 contract is always refused (`Permit2TypedDataDenied`); an approval of
  Permit2 has a policy amount of 0 but otherwise needs a policy for its network and token, like
  any payment
- upgrades keep working when a new release replaces the keychain helper that sealed the machine
  secret, and an interrupted setup restarts the services on the next run

### Migration

- `agentpay setup` (through `agentpay-setup install`) migrates a vault-password install
  automatically: it stores a new machine secret, re-encrypts the daemon state under it, and only
  then deletes the stored vault password. The wallet and its addresses are unchanged
- encrypted wallet backups from earlier releases (formats v1 and v2) restore in the setup wizard
- agents that used `agentpay admin setup`, `admin tui`, or the `*-manual-approval-request` commands
  must switch to the commands above; the updated skills in `skills/agentpay-sdk` do this
- open MPP sessions v1 channels cannot be used or closed by 1.0.0; close them with an earlier
  release before upgrading

Detailed release notes: [releases/v1.0.0.md](releases/v1.0.0.md)

## [0.5.1] - 2026-10-23

### Breaking

- Tempo session open, top-up, and voucher signing is now reconstructed and verified by the daemon:
  the `agentpay-agent` Tempo session commands take the channel and transaction fields as flags
  instead of a precomputed signing hash, so older CLIs cannot drive a newer daemon
- Tempo session state files are now v2 (they record the channel salt and authorized signer); v1
  files are rejected with the old channel id, escrow contract, and chain so the escrowed deposit
  can be closed and withdrawn before the file is deleted
- the daemon now tracks which agent key opened each Tempo session channel and how much it
  deposited; vouchers and top-ups are rejected for channels it did not open (including channels
  opened before this release or before a daemon reset), for channels opened by another agent key,
  and for voucher amounts above the deposited total
- encrypted wallet backups are now written in format v2; older CLIs cannot read v2 backups, while
  v1 backups remain readable
- relay envelopes use `x25519-hkdf-xchacha20poly1305-v2`; relays, web consoles, and daemons must
  be upgraded together
- removed the `--agent-auth-token <value>` argument from the Rust agent, and
  `AGENTPAY_AGENT_AUTH_TOKEN` is rejected for passthrough commands
- `agentpay private-balance` now exits with code 3 (was 2) when the balance is unavailable, matching
  the Rust agent's `Unavailable` outcome
- `agentpay admin approve-manual-approval-request` and `reject-manual-approval-request` now show
  the pending request and ask for confirmation; pass `--yes` for non-interactive use
- the minimum supported Rust version is now 1.89

### Security

- `BroadcastTx` calldata that the policy engine does not recognize is denied by default
- an `AllPolicies` attachment with zero enabled policies now denies instead of allowing everything
- value-bearing EIP-712 typed data (permits and similar) is denied under `Eip712Signing=Allow`
  instead of bypassing spend limits
- manual-approval policies no longer mask hard limits; a request that exceeds a hard limit is denied
  rather than queued for approval
- capped how far a requested nonce may skip ahead of the daemon's tracked nonce, and capped the
  number of pending manual-approval requests
- approval links carry their secret in the URL fragment instead of the query string, and the web
  console pins the daemon's public key
- the decrypted wallet restore key is handed to the Rust admin binary over an inherited pipe
  instead of a temporary key file
- MPP challenges must include a `chainId`, and Tempo session challenges must use a pinned escrow
  contract
- the one-click installer verifies the downloaded bundle's SHA-256 against the release digest and
  refuses `$HOME`, `/`, `/usr*`, `/opt`, and unrecognized non-empty directories as install or
  skill-pack destinations

### Added

- added Sentry crash reporting and Mixpanel usage analytics to the CLI, enabled by default
- added `agentpay telemetry status|enable|disable`, which do not require root access
- telemetry can also be disabled with `AGENTPAY_TELEMETRY=0` or the `DO_NOT_TRACK` convention
- telemetry sends only a random install id, the command, exit code, duration, platform details,
  bucketed amounts and balances, and scrubbed error text; timestamps are rounded to the minute, and
  nothing is derived from the wallet address
- Rust signing-binary output is replaced with `<binary> exited <code>` in crash reports rather than
  scrubbed; wallet and recipient addresses, transaction hashes, RPC URL paths, hostnames, and
  secrets are never transmitted
- telemetry waits at most 3 seconds at exit and backs off for an hour after a failed delivery
- documented the collection in [Telemetry and privacy](README.md#telemetry-and-privacy)

### Fixed

- moving the system clock backwards no longer resets spend budgets
- the daemon shuts down cleanly on `SIGTERM` and `SIGHUP`, and refuses to start while another
  daemon holds the lock
- the admin TUI restores the terminal when it exits
- native balances use the chain's own decimals
- transaction broadcasts are no longer retried
- removing a built-in chain or token from the config now persists
- the Linux TPM signer backend rejects Railgun key creation as unsupported, which fixes the Linux
  build of `vault-signer`

Detailed release notes: [releases/v0.5.1.md](releases/v0.5.1.md)

## [0.5.0] - 2026-06-07

- added Fiat payment onboarding with Stripe Link through the bundled Link CLI
- added `agentpay link onboard`, `agentpay link status`, `agentpay link payment-methods`, `agentpay link card`, and Link CLI passthrough commands
- added installer payment setup selection for Fiat with Link, Crypto wallet setup, or later
- added `@worldlibertyfinancial/agentpay-sdk/link` helper exports so third-party agents can bind Link, list payment methods, and create approved one-time card credentials through the AgentPay Link facade
- updated AgentPay skills and adapters to route Fiat/card payments through Link while keeping full card credentials out of chat and logs

Detailed release notes: [releases/v0.5.0.md](releases/v0.5.0.md)

## [0.4.0] - 2026-05-07

- added first-class Solana vault account support with software-backed Ed25519 keys plus persisted Solana public key/address wallet metadata
- added `agentpay transfer-spl` for original-program SPL token transfers with daemon policy checks, optional broadcast, and optional compute budget overrides
- added built-in Solana network/config support and updated wallet/setup/status flows to surface Solana chain family metadata correctly
- extended policy/domain/signer/daemon plumbing to model Solana recipients/assets and sign structured Solana SPL transfers instead of arbitrary transactions
- manual approval is not supported for Solana SPL transfers in this release and now fails closed instead of creating stale approval requests
- Solana V1 is limited to software-backed Ed25519 wallets and original SPL `TransferChecked` flows with existing associated token accounts

Detailed release notes: [releases/v0.4.0.md](releases/v0.4.0.md)

## [0.3.1] - 2026-04-13

- added managed Linux wallet support with system `systemd` services and Linux Secret Service-backed agent auth storage
- enabled `agentpay admin setup`, `agentpay admin tui`, `agentpay admin reset`, and `agentpay admin uninstall` on Linux alongside macOS
- updated the packaged installer/runtime guidance to describe the Linux managed-wallet path instead of stopping at runtime-only install
- extended shared-config/live-apply and wallet status flows to report Linux credential storage and managed daemon state correctly
- fixed macOS default bash (3.2) installer compatibility for file descriptor allocation and arrow-key read timeouts
- changed CI concurrency grouping so duplicate push/pull_request workflows on the same branch are deduplicated

Detailed release notes: [releases/v0.3.1.md](releases/v0.3.1.md)

## [0.3.0] - 2026-04-05

- added `agentpay sign-typed-data` for arbitrary EIP-712 typed-data signatures through daemon policy checks
- added `agentpay admin add-eip712-signing-policy` with `allow`, `manual-approval`, and `deny` modes scoped by network
- generic EIP-712 signing now defaults to manual approval and is evaluated separately from spend-limit accounting
- improved `agentpay mpp` session flows by selecting the correct challenge when a server returns multiple MPP challenges and by handling `payment-need-voucher` stream control events in text mode with automatic voucher/top-up follow-up
- added Tempo session demo tooling with `pnpm example:mpp:session-demo`, `pnpm example:mpp:session-server`, and expanded local server examples for persisted session open, reuse, and close flows
- improved source-install and admin-setup ergonomics: Windows source installs fail fast with a JavaScript-only fallback hint, and runtime refresh still reuses the existing wallet through `agentpay admin setup --reuse-existing-wallet`
- fixed Tempo session open/top-up signing so the daemon signs the standard transaction payload hash instead of a Keychain-wrapped hash, restoring server-side channel verification
- fixed `agentpay admin token set-chain` so saved per-token limit changes refresh the live daemon policy attachment for existing wallets instead of leaving the daemon pinned to bootstrap-time limits

Detailed release notes: [releases/v0.3.0.md](releases/v0.3.0.md)

## [0.2.0] - 2026-03-27

- added `agentpay x402 <url>` for exact/EIP-3009 x402 HTTP payments
- added `agentpay mpp <url>` for MPP HTTP 402 payments; charge flow supports any EVM-compatible chain (standard ERC-20 on generic chains, TIP-20 with attribution memo on Tempo)
- expanded `agentpay mpp` with reusable HTTP request flags (`--method`, repeatable `--header`, `--data`, `--json-body`) and decoded `Payment-Receipt` JSON output
- added session support to `agentpay mpp` (Tempo-only), including daemon-backed open/voucher digest signing, optional `--deposit`, and automatic session close
- added persisted session reuse for `agentpay mpp` via `--session-state-file`, with explicit teardown through `--close-session`
- added automatic persisted-session topUp and `payment-need-voucher` stream handling for `agentpay mpp` session flows in text mode
- added Rust agent CLI support for EIP-3009 transfer and receive authorization signing requests
- added Tempo mainnet (chain ID 4217) as a built-in chain with default RPC
- the local signer path supports `transfer`, `transfer-native`, `approve`, `broadcast`, `x402`, and `mpp`

Detailed release notes: [releases/v0.2.0.md](releases/v0.2.0.md)

## [0.1.0] - 2026-03-17

Initial public local-first release of AgentPay SDK.

Highlights:

- macOS local runtime for self-custodial, policy-aware wallet operations
- one-click install via `curl -fsSL https://wlfi.sh | bash` and a full source install path
- wallet setup, wallet reuse, encrypted backup export, verification, and restore
- local daemon-managed signing with policy enforcement before signing
- support for EVM-compatible chains with USD1 as the default asset path
- plugin system for third-party integrations and contributions
- Bitrefill included as an example integration

Detailed release notes: [releases/v0.1.0.md](releases/v0.1.0.md)
