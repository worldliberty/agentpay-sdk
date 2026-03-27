# Changelog

All notable changes to AgentPay SDK are documented in this file.

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
