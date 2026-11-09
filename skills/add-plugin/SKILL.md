---
name: add-plugin
description: Use this skill when the user wants to add a new payment feature family to AgentPay (a new merchant protocol, chain flow, or paid-API integration) or generalize an existing one. Features live in the unprivileged payments service (`crates/agentpay-paymentd/src/features/<family>`), are exposed through documented methods in `crates/agentpay-api`, sign only through the signer daemon as the calling agent, and get a thin `agentpay` client command. Follow "Adding a paymentd method" in `docs/daemon-api.md`.
---

# Add A Payments Feature Family

Use this skill for tasks like "add support for merchant protocol X" or "add a new chain flow".

## Ground Truth

- All payment logic lives in `agentpay-paymentd`, which runs as an unprivileged service account,
  holds no keys, and does all network I/O. The client (`client/`) only parses flags, calls the
  service through the generated types, and renders output.
- The wire contract is `crates/agentpay-api` (`#![deny(missing_docs)]`), documented in
  `docs/daemon-api.md`. It is a public, versioned contract (API `1.x`): new methods, optional fields,
  and new error kinds are minor additions; anything else is a major change.
- Every signature comes from the signer daemon through the agent's own credentials, so its policies,
  spending limits, and manual approvals apply. Never sign in paymentd, never add a key, and never
  call signer admin methods from paymentd.
- The step-by-step recipe is "Adding a paymentd method" in `docs/daemon-api.md`. Follow it exactly.

## Layout

| Piece | Location |
|---|---|
| Wire types and docs | `crates/agentpay-api/src/payments/<family>.rs`, variants in `payments/mod.rs` |
| Fixtures | `crates/agentpay-api/fixtures/payments/<family>/<Method>.{request,response}.json` |
| Spec | a `#### <Method>` entry under "Payments methods" in `docs/daemon-api.md` |
| Handler | `crates/agentpay-paymentd/src/features/<family>.rs` or `features/<family>/` |
| Route | one arm in `crates/agentpay-paymentd/src/dispatch.rs` |
| Chain access | a `ChainProvider` under `crates/agentpay-paymentd/src/chains/` |
| Paid HTTP helpers | `features/http.rs` (merchant client), `features/payer.rs` (`Payer`) |
| Client command | `client/src/commands/<group>.ts`, wording in `client/src/copy/` |

Reference implementations: `features/x402/` (paid HTTP with a structured EIP-3009 signature),
`features/mpp/` (charges, sessions, persisted state), `features/evm/` (transactions, nonces,
manual-approval resume), `features/solana/`.

## Deterministic Workflow

1. Read "Adding a paymentd method" and "Manual approval in payment flows" in `docs/daemon-api.md`,
   then the closest reference family above.
2. Define the wire types, request and response variants, and error kinds in `agentpay-api`, with
   rustdoc covering access, auth, units, side effects, idempotency, and errors.
3. Add request and response fixtures, register them in `src/tests/payments.rs`, and add the spec
   entry with the fixtures verbatim.
4. Run `cargo xtask gen-api` to regenerate `docs/api/schema.json` and `client/src/generated/`.
5. Implement the handler under `features/<family>`; route it with one arm in `dispatch.rs`.
6. If the feature needs a new signed action, add it to `agentpay-domain` and `agentpay-policy`
   first, so the signer daemon can reconstruct and policy-check it from structured fields. Never ask
   the signer daemon to sign an opaque hash.
7. Add the client command (`--json` output, exit codes `0`/`1`/`2`/`3`/`4`, all text in `copy/`).
8. Update `skills/agentpay-sdk` (SKILL.md and references) with the new command.
9. Verify (below).

## Implementation Rules

- Amounts on the wire are `DecimalU128` strings; say whether a field is base units or whole units.
- Validate every merchant input before signing; check every signature signerd returns before it
  leaves the process.
- Manual approval: either resend the exact stored action (`ResumeApproved`) or document why the
  flow cannot be resumed, as for x402 and MPP.
- Secrets (tokens, merchant credentials, passphrases) never go in logs, error messages, arguments,
  or environment variables; wipe them after use with `zeroize`.
- No `unwrap` outside tests. Every file stays under 1,000 lines.
- Third-party protocols: reuse an existing crate where it exposes open traits for signing (as
  `x402-types` and `mpp` do) rather than reimplementing the protocol.

## Testing Rule

- Unit-test handlers with `signer::testing::InProcessSigner` (a real in-memory signer daemon with
  policies) and `ScriptedSigner`; use mock RPC servers and the scripted merchant in
  `features/http/merchant.rs`. Never hit live third-party services in tests.
- Cover policy denial, manual approval, malformed merchant answers, and the "nothing was signed"
  guarantee for rejected inputs.
- Extend `crates/agentpay-paymentd/tests/e2e.rs` for an end-to-end check over real sockets.
- Client: Vitest tests against the fake daemon (`client/test/helpers/fake-daemon.ts`) using the API
  fixtures.

## Verify

```bash
just lint     # fmt, clippy -D warnings, file length, no JavaScript, gen-api --check, API docs
just test
just client-test && just client-lint
```
