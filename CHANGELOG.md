# Changelog

All notable changes to AgentPay SDK are documented in this file.

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
