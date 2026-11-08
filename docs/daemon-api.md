# AgentPay daemon API

**API version 1.1.0.** This is the specification of the local socket APIs of the two AgentPay services and their clients (the bundled `agentpay` client and any third-party integration):

- the **signer daemon** (`agentpay-daemon`, root): keys, policies, manual approvals, and signing;
- the **payments service** (`agentpay-paymentd`, an unprivileged service account): chains, RPC endpoints, and payment flows. It asks the signer daemon for every signature as the calling agent.

Both use the same transport, envelopes, encodings, and versioning; they differ in socket, request family, and error type. Most of this document describes the signer daemon; [Payments service](#payments-service) covers the second service. The contract is defined in Rust in [`crates/agentpay-api`](../crates/agentpay-api). Two machine-readable forms are generated from it:

- [`docs/api/schema.json`](api/schema.json): a JSON Schema (draft 2020-12) of every wire type.
- [`client/src/generated/`](../client/src/generated): TypeScript types.

Regenerate both with `cargo xtask gen-api`. CI runs `cargo xtask gen-api --check` and fails if either is out of date. Every JSON example in this document comes from `crates/agentpay-api/fixtures/`. The test suite checks each one against the Rust types. The admin challenge, key, identity, and signature examples are real values: the daemon reproduces them in `agentpay-signerd`'s `api_examples` tests, and `agentpay-paymentd` reproduces its default configuration.

## Contents

1. [Architecture](#architecture)
2. [Transport](#transport)
3. [Connection lifecycle and handshake](#connection-lifecycle-and-handshake)
4. [Encoding conventions](#encoding-conventions)
5. [Authentication and authorization](#authentication-and-authorization)
6. [Methods](#methods)
7. [Errors](#errors)
8. [Manual approval](#manual-approval)
9. [Payments service](#payments-service)
10. [Adding a paymentd method](#adding-a-paymentd-method)
11. [Versioning and deprecation](#versioning-and-deprecation)
12. [Security notes for integrators](#security-notes-for-integrators)
13. [Writing a client: a minimal walkthrough](#writing-a-client-a-minimal-walkthrough)

## Architecture

```text
   agent / CLI / TUI / third-party client                     (the installing user)
      |                                     |
      | payments, config                    | administration: policies, keys, approvals
      v                                     v
 paymentd.sock (service account)         daemon.sock (root)
      |                                     ^
      v                                     |
 +---------------------------------+        |  AuthenticateAgent, ReserveNonce,
 | payments service (paymentd)     |        |  SignForAgent ... as the calling agent
 | runs as _agentpay / agentpay    |--------+  (paymentd's uid is on the agent allowlist)
 |  dispatch -> auth -> features   |
 |  config.json (its state dir)    |----> chain RPC, x402, MPP (network)
 +---------------------------------+
                                     +--------------------------------------------------+
                                     | signer daemon (root)                             |
                                     |  transport: peer-euid allowlists (admin / agent) |
                                     |  handle_rpc: admin auth (root peer | lease),      |
                                     |              agent auth (bearer token)           |
                                     |  policies, keys, approvals -> policy engine ->   |
                                     |  signer backend; encrypted state (machine secret)|
                                     +--------------------------------------------------+
        admin leases: Secure Enclave P-256 key (Touch ID / login password) signs the
        signer daemon's challenge through the `agentpay-auth` helper (macOS)
```

Every connection carries one request frame and one response frame: `[u32 big-endian length][JSON WireRequest / WireResponse]`. The kernel reports each peer's euid (`getpeereid` / `SO_PEERCRED`), and each service filters peers by it.

| Client wants to | Talks to |
|---|---|
| pay, transfer, broadcast, read or change the payments configuration | the payments service |
| manage policies, keys, agent tokens, admin credentials, manual approvals | the signer daemon |
| sign within its own policies without network help (advanced agents) | the signer daemon (agent methods) |

The signer daemon holds every key, policy, and approval. Private keys never leave it in the clear: a wallet backup (`ExportWalletBackup`) is encrypted inside the daemon under the user's passphrase. Clients cannot change policy without admin authority. The payments service holds no keys and no credentials of its own.

## Transport

| Property | Value |
|---|---|
| Socket (macOS) | `/Library/AgentPay/run/daemon.sock` |
| Socket (Linux) | `/run/agentpay/daemon.sock` |
| Socket (development) | `$AGENTPAY_HOME/daemon.sock`, else `~/.agentpay/daemon.sock`, or `--daemon-socket` |
| Payments socket | see [Payments service](#payments-service): `/Library/AgentPay/run/paymentd/paymentd.sock` (macOS), `/run/agentpay-paymentd/paymentd.sock` (Linux) |
| Socket type | Unix domain, `SOCK_STREAM` |
| Socket mode | `0600` when both allowlists are root-only, otherwise `0666` (peers are still filtered by euid) |
| Framing | 4-byte big-endian unsigned length, then that many bytes of UTF-8 JSON |
| Maximum frame payload | 262144 bytes (256 KiB), both directions |
| Requests per connection | exactly one |
| Daemon I/O timeout | 10 s per frame read or write |
| Concurrent connections | 64; further clients wait in the listen backlog |

A client writes one frame with a `WireRequest`. The `body_json` field holds the request serialized as a JSON **string**, so the request is JSON-encoded twice:

```json
{"body_json": "{\"method\":\"Hello\"}"}
```

On the wire, with the length prefix shown as hex: `00 00 00 26 {"body_json":"{\"method\":\"Hello\"}"}`.

The daemon answers with one frame holding a `WireResponse` and then closes the connection:

```json
{"ok": true, "body_json": "{\"type\":\"Unit\"}"}
```

```json
{"ok": false, "body_json": "{\"kind\":\"UnknownLease\"}"}
```

When `ok` is `true`, `body_json` is a `DaemonRpcResponse`. When `ok` is `false`, it is a `WireDaemonError` (see [Errors](#errors)).

The daemon closes the connection **without writing a response** in these cases:

- the peer euid is on neither allowlist;
- the frame is too large or not valid JSON;
- the request does not decode, for example an unknown method, a missing field, or an invalid `SpendingPolicy`;
- the peer is not on the allowlist for the requested method.

Treat end-of-file before a response as "rejected by the transport". Use a client-side timeout of about 10 seconds.

## Connection lifecycle and handshake

1. **Verify the socket.** Check that the socket and every parent directory are owned by root and are not group- or world-writable. After connecting, check that the peer euid is `0`. See [Security notes](#security-notes-for-integrators).
2. **Call `Hello`.** It is open to every allowlisted peer and needs no credentials. The response carries `api_version`, `daemon_version`, and `capabilities`.
3. **Check compatibility.** The client and the daemon are compatible exactly when the **major** versions of `api_version` match. Stop if they differ.
4. **Detect features from `capabilities`.** It lists every method name the daemon serves, plus dotted feature names: `admin_challenge.v1` (the challenge format below) and `amounts.decimal_string` (every `u128` is a decimal string). Ignore entries you do not know.
5. **Make calls.** Open a new connection for every call.

Daemons from AgentPay releases before 1.0 predate this contract: they do not know `Hello` and close the connection without a response. Treat that as "incompatible daemon".

## Encoding conventions

| Rust type | JSON | Example |
|---|---|---|
| `Uuid` | lowercase hyphenated string | `"9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"` |
| `u128` amounts and limits (`DecimalU128`) | base-10 string, no sign, exponent, or `0x` | `"1000000000000000000"` |
| `u64` chain ids, nonces, gas limits | JSON number | `56` |
| `OffsetDateTime` (`Timestamp`) | 9-element array `[year, day_of_year, hour, minute, second, nanosecond, offset_h, offset_m, offset_s]`; the daemon emits UTC | `[2026, 309, 12, 0, 0, 0, 0, 0, 0]` is 2026-11-05T12:00:00Z |
| `Vec<u8>` | array of byte values | `[123, 34]` |
| EVM address | `0x` + 40 hex characters; mixed case must be EIP-55-valid; emitted lower case | `"0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"` |
| Solana address | base58 32-byte public key | `"9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"` |
| `*_hex` fields | as documented per field; `0x` only where stated | |

The tagged unions use these forms:

| Type | Form | Example |
|---|---|---|
| `DaemonRpcRequest` | `{"method": ..., "params": ...}`; `Hello` has no `params` | `{"method":"Hello"}` |
| `DaemonRpcResponse` | `{"type": ..., "data": ...}`; `Unit` has no `data` | `{"type":"Unit"}` |
| `WireDaemonError` | `{"kind": ..., "data": ...}`; unit kinds have no `data` | `{"kind":"UnknownLease"}` |
| `AgentAction` | internally tagged by `kind` | `{"kind":"Transfer","chain_id":56,...}` |
| `AssetId` | `kind` / `value`, snake case | `{"kind":"erc20","value":"0x..."}` |
| `RecipientId` | `kind` / `value`, snake case; input also accepts a bare address string | `{"kind":"evm","value":"0x..."}` |
| `EntityScope<T>` | `mode` / `values` | `{"mode":"All"}`, `{"mode":"Set","values":[56]}` |
| `AdminAuth` | `"peer_credentials"` or `{"lease": {...}}` | |
| `PolicyAttachment` | `"AllPolicies"` or `{"PolicySet": [...]}` | |
| `KeyCreateRequest` | externally tagged | `"Generate"`, `{"Import":{"private_key_hex":"..."}}` |
| `PolicyError`, `SignerError` | externally tagged | `"NoAttachedPolicies"`, `{"Unsupported":"..."}` |

Amount fields named `*_wei` hold the asset's smallest unit: wei for native EVM coins, token base units for ERC-20 and TIP-20 tokens, and lamports for SOL. EVM and Tempo actions use the EVM chain id. Solana actions use the daemon's internal Solana network ids, which policies see as one Solana policy chain id. The exact shape of every type, including every action variant, is in [`schema.json`](api/schema.json).

## Authentication and authorization

Authorization has two independent layers.

### 1. Peer allowlists (transport)

The daemon reads the caller's effective uid from the kernel and never trusts a uid claimed inside a request. It keeps two allowlists, and both always include root (`0`):

| Allowlist | Daemon flag | Gates |
|---|---|---|
| admin | `--allow-admin-euid <uid>` | admin methods |
| agent | `--allow-agent-euid <uid>` | agent methods |

`Hello` is open to every uid on either list. A uid on neither list is disconnected before its request is read.

### 2. Credentials inside the request (daemon)

**Agent methods** carry `agent_key_id` and `agent_auth_token` (inside `request`, or as `auth` for `AuthenticateAgent`). The token is the opaque bearer string returned once by `CreateAgentKey`, `RefreshAgentKey`, or `RotateAgentAuthToken`, and the daemon stores only its SHA-256. A wrong token fails with `AgentAuthenticationFailed`. The payments service authenticates its own callers by forwarding their credentials to `AuthenticateAgent`; see [Payments service authentication](#payments-service-authentication).

**Admin methods** carry `auth`. A missing `auth` means `"peer_credentials"`.

- `"peer_credentials"`: authorized only when the peer is **root**. The usual case is the CLI run under `sudo`, which also covers SSH and Linux, with no GUI. Other peers get `AdminAuthenticationRequired`.
- `{"lease": {"lease_id": "...", "lease_secret": "..."}}`: an admin lease from the challenge flow below. It is valid for 5 minutes and is bound to the peer euid that completed the challenge. The daemon keeps leases in memory only and verifies a presented lease even for root peers.

`EnrollAdminCredential` accepts only root peers and never a lease.

### Admin challenge flow (`agentpay-admin-challenge-v1`)

On macOS, admin authority without `sudo` comes from a P-256 key in the Secure Enclave. Its access control is `.privateKeyUsage` + `.userPresence`, so every signature asks for Touch ID or the login password. The `agentpay-auth` helper (`native/macos/AgentPayAuth.swift`) creates and uses this key.

1. **Enroll** (once, as root): `EnrollAdminCredential` with the key's SEC1 public key. The helper prints it with `agentpay-auth create --key-file <path>`, which outputs `{"publicKeySec1Hex": "..."}`. Up to 8 credentials may be enrolled.
2. **Begin**: `BeginAdminChallenge` with `credential_id` and a `purpose`, for example `admin-session` or `approve:<approval id>`. A purpose is 1 to 128 characters of `[A-Za-z0-9._:/-]`. The daemon returns `challenge_id`, `message_hex`, and `expires_at`. The challenge is single use, expires after 2 minutes, and is bound to your peer euid.
3. **Sign** the bytes of `message_hex` exactly as received. The signature is ECDSA P-256 over **SHA-256 of the message**, encoded as ASN.1 DER. This is CryptoKit's `P256.Signing.PrivateKey.signature(for:)`, OpenSSL's `ecdsa-with-SHA256`, or `agentpay-auth sign --key-file <path> --reason <text> --message-hex <hex>`, which outputs `{"signatureDerHex": "..."}`.
4. **Complete**: `CompleteAdminChallenge` with `challenge_id` and `signature_der_hex` (DER as hex, no `0x`). The daemon returns an `AdminLease`. The challenge is consumed even when the signature is wrong. Five consecutive failures lock the credential for 30 seconds (`AdminCredentialLocked`).
5. **Use** `{"lease": {"lease_id": ..., "lease_secret": ...}}` as `auth` on admin calls until `expires_at`. Revoke the lease with `RevokeAdminLease` when you are done.

The message is the concatenation of these fields:

| # | Field | Bytes | Encoding |
|---|---|---|---|
| 1 | domain tag | 27 | ASCII `agentpay-admin-challenge-v1` |
| 2 | separator | 1 | `0x00` |
| 3 | daemon instance id | 16 | UUID bytes, random per daemon process |
| 4 | credential id | 16 | UUID bytes |
| 5 | challenge id | 16 | UUID bytes |
| 6 | nonce | 32 | random |
| 7 | purpose length | 2 | big-endian `u16` |
| 8 | purpose | variable | UTF-8 |
| 9 | expiry | 8 | big-endian `i64` Unix seconds (equal to `expires_at`) |

Clients may parse the message to show the purpose and expiry in a prompt. They must sign the bytes they received, not a rebuilt message. The examples under [Admin authentication](#admin-authentication) are real: the `signature_der_hex` in the `CompleteAdminChallenge` example verifies against the enrolled public key over the `message_hex` in the `BeginAdminChallenge` example.

## Methods

Every method lists its access level, authentication, response variant, side effects, idempotency, and errors. Every admin method can also fail with the admin-auth errors: `AdminAuthenticationRequired`, `UnknownLease`, `InvalidLease`, and `AuthenticationFailed`. Every method can fail with `LockPoisoned`, and every method that persists state can fail with `Persistence`.

### Handshake

#### `Hello`

Returns the API version, the daemon release, and the capabilities.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| any allowlisted peer | none | `Hello` | none | yes |

Errors: none.

```json
{
  "method": "Hello"
}
```

```json
{
  "type": "Hello",
  "data": {
    "api_version": "1.1.0",
    "daemon_version": "1.0.0",
    "capabilities": ["Hello", "EnrollAdminCredential", "SignForAgent", "admin_challenge.v1", "amounts.decimal_string"]
  }
}
```

### Admin authentication

#### `EnrollAdminCredential`

Enrolls a P-256 public key whose holder can obtain admin leases. The daemon stores the key in canonical uncompressed form, so the same key cannot be enrolled twice under different encodings. `public_key_sec1_hex` is SEC1 hex without `0x`, compressed or uncompressed. `label` is 1 to 64 characters without control characters.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | **root peer only** | `AdminCredential` | persists the credential | no: re-enrolling fails |

Errors: `RootPeerRequired`, `InvalidAdminCredential`, `TooManyAdminCredentials`, `Persistence`.

```json
{
  "method": "EnrollAdminCredential",
  "params": {
    "public_key_sec1_hex": "04d143abdfd310eadde5b905c83e8967e1e15fb8e1c09537344528f6dc37252cabd5e5a6ab6b4eadc242db1aff339fe385abb657e0b9cbade40a45531300694b19",
    "label": "MacBook Pro Touch ID"
  }
}
```

```json
{
  "type": "AdminCredential",
  "data": {
    "id": "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b",
    "public_key_sec1_hex": "04d143abdfd310eadde5b905c83e8967e1e15fb8e1c09537344528f6dc37252cabd5e5a6ab6b4eadc242db1aff339fe385abb657e0b9cbade40a45531300694b19",
    "label": "MacBook Pro Touch ID",
    "created_at": [2026, 309, 11, 58, 12, 0, 0, 0, 0]
  }
}
```

#### `ListAdminCredentials`

Lists enrolled credentials, oldest first.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `AdminCredentials` | none | yes |

```json
{
  "method": "ListAdminCredentials",
  "params": {
    "auth": "peer_credentials"
  }
}
```

```json
{
  "type": "AdminCredentials",
  "data": [
    {
      "id": "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b",
      "public_key_sec1_hex": "04d143abdfd310eadde5b905c83e8967e1e15fb8e1c09537344528f6dc37252cabd5e5a6ab6b4eadc242db1aff339fe385abb657e0b9cbade40a45531300694b19",
      "label": "MacBook Pro Touch ID",
      "created_at": [2026, 309, 11, 58, 12, 0, 0, 0, 0]
    }
  ]
}
```

#### `RevokeAdminCredential`

Removes a credential together with its leases, pending challenges, and lockout state. Revocation takes effect immediately, including for the caller's own lease.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `Unit` | persists the removal | no |

Errors: `UnknownAdminCredential`, `Persistence`.

```json
{
  "method": "RevokeAdminCredential",
  "params": {
    "auth": "peer_credentials",
    "id": "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b"
  }
}
```

```json
{
  "type": "Unit"
}
```

#### `BeginAdminChallenge`

Issues a single-use challenge for an enrolled credential. See the [challenge flow](#admin-challenge-flow-agentpay-admin-challenge-v1).

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | none | `AdminChallenge` | in-memory pending challenge (2 min) bound to the peer euid | no |

Errors: `InvalidAdminChallengePurpose`, `UnknownAdminCredential`, `AdminCredentialLocked`, `TooManyPendingAdminChallenges`.

```json
{
  "method": "BeginAdminChallenge",
  "params": {
    "credential_id": "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b",
    "purpose": "admin-session"
  }
}
```

```json
{
  "type": "AdminChallenge",
  "data": {
    "challenge_id": "0b8e4f2a-7c1d-4a3e-9b5f-6d2c8e1a4f70",
    "message_hex": "6167656e747061792d61646d696e2d6368616c6c656e67652d7631001a2b3c4d5e6f40718293a4b5c6d7e8f96f1c2a9e3b4d4e5f8a7b9c0d1e2f3a4b0b8e4f2a7c1d4a3e9b5f6d2c8e1a4f705f3a1e7c9b2d4f6a8c0e1b3d5f7a9c2e4b6d8f0a1c3e5b7d9f2a4c6e8b0d1f3a000d61646d696e2d73657373696f6e000000006aec7038",
    "expires_at": [2026, 309, 12, 2, 0, 0, 0, 0, 0]
  }
}
```

#### `CompleteAdminChallenge`

Exchanges a signed challenge for an admin lease. The call must come from the same peer euid that began the challenge.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | the signature | `AdminLease` | consumes the challenge; a failure counts toward the lockout | no |

Errors: `InvalidAdminChallenge` (unknown, expired, used, or begun by a different peer), `AdminCredentialLocked`, `UnknownAdminCredential`, `AuthenticationFailed`, `TooManyActiveLeases`.

```json
{
  "method": "CompleteAdminChallenge",
  "params": {
    "challenge_id": "0b8e4f2a-7c1d-4a3e-9b5f-6d2c8e1a4f70",
    "signature_der_hex": "3045022100cb67edea00738b8d58107cb800b40f0faa0a52208281e4d7786cb7e089f7405c02204a510839863316625bcf0e05ff4aa634ec76dbc19b7848b3ea5c9ded41a19e64"
  }
}
```

```json
{
  "type": "AdminLease",
  "data": {
    "lease_id": "c3d2e1f0-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
    "lease_secret": "3f9a6c1e8b2d47f0a5c3e9b1d7f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8",
    "issued_at": [2026, 309, 12, 0, 30, 0, 0, 0, 0],
    "expires_at": [2026, 309, 12, 5, 30, 0, 0, 0, 0]
  }
}
```

#### `RevokeAdminLease`

Revokes a lease before it expires. A lease may revoke itself, which is how a client logs out.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `Unit` | forgets the lease | no |

Errors: `UnknownLease`.

```json
{
  "method": "RevokeAdminLease",
  "params": {
    "auth": {
      "lease": {
        "lease_id": "c3d2e1f0-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
        "lease_secret": "3f9a6c1e8b2d47f0a5c3e9b1d7f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8"
      }
    },
    "lease_id": "c3d2e1f0-5a6b-4c7d-8e9f-0a1b2c3d4e5f"
  }
}
```

```json
{
  "type": "Unit"
}
```

### Policies

A `SpendingPolicy` limits what agents may sign. For each request, the daemon takes the enabled policies attached to the agent key whose `recipients`, `assets`, and `networks` scopes match the action, and evaluates them in ascending `priority`. Any hard limit denies the request. A `SolanaPaymentTransaction` pays several recipients: a policy matches when its `recipients` scope covers any of them, every recipient must be covered by some matching policy (otherwise `NoApplicablePolicies`), and each matching policy checks the sum of all legs. A manual-approval rule holds it for an operator. *Since API 1.1.0:* an ERC-20 `approve` whose spender is the canonical Permit2 (`0x000000000022d473030f116ddee9f6b43ac78ba3`; as the `Approve` action, or `BroadcastTx` calldata with no value) has a policy amount of 0: Permit2 moves nothing without a signed permit, the daemon signs Permit2 permits only as the policy-checked `Permit2WitnessTransfer` action, generic typed data bound to Permit2 is refused (`Permit2TypedDataDenied`), and Permit2's own `approve` calldata is not recognized. Policies' `recipients` scopes do not apply to it (Permit2 is not a payee); everything else does: a policy must cover its network and the token (the transaction's `to`), or it is refused with `NoApplicablePolicies`; fee, gas, calldata, and `DailyMaxTxCount` policies apply; every `ManualApproval` policy that covers it holds it for an operator whatever its `min_amount_wei`; and it records a zero-amount spend event (one transaction for daily counts). Each `policy_type` uses one dedicated limit field:

| `policy_type` | Limit field | Meaning |
|---|---|---|
| `PerTxMaxSpending` | `max_amount_wei` | amount of a single action |
| `DailyMaxSpending` | `max_amount_wei` | total over a rolling 24 h |
| `WeeklyMaxSpending` | `max_amount_wei` | total over a rolling 7 days |
| `DailyMaxTxCount` | `max_tx_count` | signatures per rolling 24 h |
| `PerTxMaxFeePerGas` | `max_fee_per_gas_wei` | `maxFeePerGas` of a broadcast |
| `PerTxMaxPriorityFeePerGas` | `max_priority_fee_per_gas_wei` | `maxPriorityFeePerGas` of a broadcast |
| `PerTxMaxCalldataBytes` | `max_calldata_bytes` | calldata length of a broadcast |
| `PerChainMaxGasSpend` | `max_gas_spend_wei` | `gas_limit * max_fee_per_gas` per chain per rolling 24 h |
| `ManualApproval` | `min_amount_wei` (optional), `max_amount_wei` | amounts in the range need an operator decision |
| `Eip712Signing` | `approval_type` (`allow`, `manual_approval`, `deny`) | generic EIP-712 typed data; no numeric fields |

Limits must be greater than zero. A specialized type also echoes its limit as `max_amount_wei` for older clients and accepts it as a legacy alias on input.

`over_limit` (API 1.1, optional) says what happens to a request beyond the limit of a `PerTxMaxSpending`, `DailyMaxSpending`, `WeeklyMaxSpending`, or `DailyMaxTxCount` policy: `"deny"` (the default, omitted when encoding, and what stored policies from before 1.1 decode as) or `"manual_approval"`, which holds the request for an operator ([Manual approval](#manual-approval)) with the soft `PolicyError` `LimitApprovalRequired {policy_id, limit, max, used, requested_amount_wei}`. Any other policy type with `"manual_approval"` does not decode. A policy that fails validation does not decode, so the daemon closes the connection without a response.

#### `AddPolicy`

Adds a new policy. The `id` must be new. The policy applies at once to agents attached to `AllPolicies`. Agents attached to a `PolicySet` keep their snapshot; attach the new policy with `RefreshAgentKey`.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `Unit` | persists the policy | no: an existing `id` fails |

Errors: `InvalidPolicy`, `Persistence`.

```json
{
  "method": "AddPolicy",
  "params": {
    "auth": {
      "lease": {
        "lease_id": "c3d2e1f0-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
        "lease_secret": "3f9a6c1e8b2d47f0a5c3e9b1d7f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8"
      }
    },
    "policy": {
      "id": "a1b2c3d4-0000-4000-8000-000000000001",
      "priority": 10,
      "policy_type": "PerTxMaxSpending",
      "max_amount_wei": "100000000000000000000",
      "recipients": {
        "mode": "All"
      },
      "assets": {
        "mode": "Set",
        "values": [
          {
            "kind": "erc20",
            "value": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
          }
        ]
      },
      "networks": {
        "mode": "Set",
        "values": [56]
      },
      "enabled": true
    }
  }
}
```

```json
{
  "type": "Unit"
}
```

#### `ListPolicies`

Lists every policy, enabled or not, ordered by priority.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `Policies` | none | yes |

```json
{
  "method": "ListPolicies",
  "params": {
    "auth": {
      "lease": {
        "lease_id": "c3d2e1f0-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
        "lease_secret": "3f9a6c1e8b2d47f0a5c3e9b1d7f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8"
      }
    }
  }
}
```

```json
{
  "type": "Policies",
  "data": [
    {
      "id": "a1b2c3d4-0000-4000-8000-000000000001",
      "priority": 10,
      "policy_type": "PerTxMaxSpending",
      "max_amount_wei": "100000000000000000000",
      "recipients": {
        "mode": "All"
      },
      "assets": {
        "mode": "Set",
        "values": [
          {
            "kind": "erc20",
            "value": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
          }
        ]
      },
      "networks": {
        "mode": "Set",
        "values": [56]
      },
      "enabled": true
    },
    {
      "id": "a1b2c3d4-0000-4000-8000-000000000002",
      "priority": 20,
      "policy_type": "ManualApproval",
      "min_amount_wei": "50000000000000000000",
      "max_amount_wei": "100000000000000000000",
      "recipients": {
        "mode": "All"
      },
      "assets": {
        "mode": "All"
      },
      "networks": {
        "mode": "All"
      },
      "enabled": true
    }
  ]
}
```

#### `ListPolicySummaries`

Lists the id and enabled state of every policy.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `PolicySummaries` | none | yes |

```json
{
  "method": "ListPolicySummaries",
  "params": {
    "auth": {
      "lease": {
        "lease_id": "c3d2e1f0-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
        "lease_secret": "3f9a6c1e8b2d47f0a5c3e9b1d7f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8"
      }
    }
  }
}
```

```json
{
  "type": "PolicySummaries",
  "data": [
    {
      "id": "a1b2c3d4-0000-4000-8000-000000000001",
      "enabled": true
    },
    {
      "id": "a1b2c3d4-0000-4000-8000-000000000002",
      "enabled": false
    }
  ]
}
```

#### `DisablePolicy`

Disables a policy and removes it from every agent's `PolicySet`. Disabled policies stay listed. There is no re-enable method; add a new policy instead.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `Unit` | persists the change | yes |

Errors: `UnknownPolicy`, `Persistence`.

```json
{
  "method": "DisablePolicy",
  "params": {
    "auth": {
      "lease": {
        "lease_id": "c3d2e1f0-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
        "lease_secret": "3f9a6c1e8b2d47f0a5c3e9b1d7f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8"
      }
    },
    "policy_id": "a1b2c3d4-0000-4000-8000-000000000002"
  }
}
```

```json
{
  "type": "Unit"
}
```

### Keys

A **vault key** is a signing key held by the daemon's signer backend: software, or sealed by the Linux TPM. An **agent key** is an identity that may ask one vault key to sign within its attached policies.

#### `CreateVaultKey`

Generates or imports a vault key. `request` is `"Generate"` (secp256k1), `{"GenerateWithAlgorithm":{"algorithm":"ed25519"}}`, `{"Import":{"private_key_hex":"<64 hex>"}}`, or `{"ImportWithAlgorithm":{"algorithm":...,"private_key_hex":...}}`. The hex may have a `0x` prefix.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `VaultKey` | creates and persists the key | no |

Errors: `Signer`, `Persistence`.

```json
{
  "method": "CreateVaultKey",
  "params": {
    "auth": "peer_credentials",
    "request": "Generate"
  }
}
```

```json
{
  "type": "VaultKey",
  "data": {
    "id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
    "source": "Generated",
    "algorithm": "secp256k1",
    "public_key_hex": "044e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e47fd35c4215d1edf53e6f83de344615ce719bdb0fd878f6ed76f06dd277956de",
    "created_at": [2026, 309, 11, 59, 0, 0, 0, 0, 0]
  }
}
```

#### `CreateAgentKey`

Creates an agent key for a vault key and returns its bearer token. The token is shown only once. `AllPolicies` is dynamic: policies added later apply too. `PolicySet` is a static snapshot of existing, enabled policies.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `AgentCredentials` | persists the agent and its token hash | no |

Errors: `UnknownVaultKey`, `UnknownPolicy`, `InvalidPolicyAttachment`, `Persistence`.

```json
{
  "method": "CreateAgentKey",
  "params": {
    "auth": "peer_credentials",
    "vault_key_id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
    "attachment": "AllPolicies"
  }
}
```

```json
{
  "type": "AgentCredentials",
  "data": {
    "agent_key": {
      "id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "vault_key_id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
      "policies": "AllPolicies",
      "created_at": [2026, 309, 11, 59, 5, 0, 0, 0, 0]
    },
    "auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
  }
}
```

#### `RefreshAgentKey`

Replaces an agent's policy attachment and rotates its token. The agent must belong to `vault_key_id`.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `AgentCredentials` | persists; the old token stops working | no |

Errors: `UnknownAgentKey`, `UnknownPolicy`, `InvalidPolicyAttachment`, `Persistence`.

```json
{
  "method": "RefreshAgentKey",
  "params": {
    "auth": {
      "lease": {
        "lease_id": "c3d2e1f0-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
        "lease_secret": "3f9a6c1e8b2d47f0a5c3e9b1d7f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8"
      }
    },
    "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
    "vault_key_id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
    "attachment": {
      "PolicySet": ["a1b2c3d4-0000-4000-8000-000000000001"]
    }
  }
}
```

```json
{
  "type": "AgentCredentials",
  "data": {
    "agent_key": {
      "id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "vault_key_id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
      "policies": {
        "PolicySet": ["a1b2c3d4-0000-4000-8000-000000000001"]
      },
      "created_at": [2026, 309, 11, 59, 5, 0, 0, 0, 0]
    },
    "auth_token": "2b7e1f9c4a6d48e0b3c5a7f1e9d2c4b6.0e1d2c3b4a5948f7a6b5c4d3e2f1a0b9"
  }
}
```

#### `SolanaPublicKey`

Returns the Ed25519 public key that the vault key uses for Solana, as hex. The Solana address is its base58 encoding.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `PublicKey` | none | yes |

Errors: `UnknownVaultKey`, `Signer`.

```json
{
  "method": "SolanaPublicKey",
  "params": {
    "auth": {
      "lease": {
        "lease_id": "c3d2e1f0-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
        "lease_secret": "3f9a6c1e8b2d47f0a5c3e9b1d7f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8"
      }
    },
    "vault_key_id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d"
  }
}
```

```json
{
  "type": "PublicKey",
  "data": "80c8c02fd8526709aff4b62492d9725940ee512c9ad36d49f2df8e6e0526875d"
}
```

#### `RotateAgentAuthToken`

Issues a new bearer token. The old token stops working.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `AuthToken` | persists the new token hash | no |

Errors: `UnknownAgentKey`, `Persistence`.

```json
{
  "method": "RotateAgentAuthToken",
  "params": {
    "auth": {
      "lease": {
        "lease_id": "c3d2e1f0-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
        "lease_secret": "3f9a6c1e8b2d47f0a5c3e9b1d7f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8"
      }
    },
    "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
  }
}
```

```json
{
  "type": "AuthToken",
  "data": "2b7e1f9c4a6d48e0b3c5a7f1e9d2c4b6.0e1d2c3b4a5948f7a6b5c4d3e2f1a0b9"
}
```

#### `RevokeAgentKey`

Deletes an agent key and everything tied to it: its token, spend history, nonce reservations, manual approval requests, and recoverable results.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `Unit` | persists the removal | no |

Errors: `UnknownAgentKey`, `Persistence`.

```json
{
  "method": "RevokeAgentKey",
  "params": {
    "auth": {
      "lease": {
        "lease_id": "c3d2e1f0-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
        "lease_secret": "3f9a6c1e8b2d47f0a5c3e9b1d7f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8"
      }
    },
    "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
  }
}
```

```json
{
  "type": "Unit"
}
```

### Wallet

The **wallet** is the daemon's `secp256k1` vault key; its Solana key is derived from it. These methods give a client the whole wallet lifecycle in a few calls: set it up, list what is on the machine, name it, back it up, check the backup.

#### `BootstrapWallet`

Sets up the wallet, its agent key, and the agent's spending limits in one atomic step. `mode` is one of:

- `{"kind": "create", "replace_existing": false, "name"?: "Trading bot"}`: generate a new key.
- `{"kind": "reuse", "vault_key_id"?: ..., "agent_key_id"?: ...}`: keep the existing key (the only vault key when `vault_key_id` is absent) and refresh its agent key (the only one when `agent_key_id` is absent; one is created when there is none). The token is rotated; spend history is kept.
- `{"kind": "restore_from_backup", "backup_json": "...", "passphrase": "...", "replace_existing": false, "name"?: "..."}`: import the key from an [encrypted backup](#encrypted-wallet-backups). The daemon decrypts it; the key never crosses the socket in the clear.

**Wallet names** (API 1.1): `create` stores `name`; `restore_from_backup` stores `name`, else the name the backup carries; `reuse` keeps the wallet's name. A name is trimmed and must be 1 to 32 characters without control characters (`InvalidWalletRequest`). Rename a wallet later with [`RenameWallet`](#renamewallet).

`create` and `restore_from_backup` fail with `WalletAlreadyExists` when the daemon holds any vault key, unless `replace_existing` is `true`. Replacing **deletes** every existing vault key with its private key, every agent key of those vault keys (tokens, spend history, nonce state, approval requests), and disables their spending policies; funds of a replaced wallet are reachable only through a backup of it. Restoring a key the daemon already holds fails with `InvalidWalletRequest`; use `reuse`.

`limits` becomes the agent's limit set exactly as in [`SetSpendingLimits`](#setspendinglimits): **deny by default**, the agent can spend only the listed network and asset pairs. Everything is validated before anything changes, and the change is applied and persisted as a whole or not at all. The response carries the agent's bearer token, shown only here.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `WalletBootstrap` | creates, keeps, or imports the key; creates or refreshes the agent key (new token); replaces its limits; with `replace_existing`, destroys the previous wallets | no |

Errors: `WalletAlreadyExists`, `WalletNotFound` (`reuse` without a wallet), `InvalidWalletRequest`, `InvalidSpendingLimits`, `InvalidWalletBackup`, `WalletBackupDecryptionFailed`, `UnknownVaultKey`, `UnknownAgentKey`, `Signer`, `Persistence`.

```json
{
  "method": "BootstrapWallet",
  "params": {
    "auth": "peer_credentials",
    "mode": {
      "kind": "create",
      "replace_existing": false
    },
    "limits": [
      {
        "chain_id": 56,
        "asset": {
          "kind": "erc20",
          "value": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
        },
        "per_tx_max_wei": "100000000000000000000",
        "daily_max_wei": "500000000000000000000",
        "weekly_max_wei": "1000000000000000000000",
        "max_gas_per_tx_wei": "2000000000000000"
      },
      {
        "chain_id": 56,
        "asset": {
          "kind": "native_eth"
        },
        "per_tx_max_wei": "10000000000000000",
        "daily_max_wei": "50000000000000000",
        "weekly_max_wei": "100000000000000000"
      }
    ]
  }
}
```

```json
{
  "type": "WalletBootstrap",
  "data": {
    "outcome": "created",
    "vault_key": {
      "id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
      "source": "Generated",
      "algorithm": "secp256k1",
      "public_key_hex": "044e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e47fd35c4215d1edf53e6f83de344615ce719bdb0fd878f6ed76f06dd277956de",
      "created_at": [2026, 309, 11, 59, 0, 0, 0, 0, 0]
    },
    "evm_address": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
    "solana_address": "9fijMemJYwXS5QD85Qxsq7iKqvSebgb6LvpGftgkeigk",
    "agent_credentials": {
      "agent_key": {
        "id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
        "vault_key_id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
        "policies": {
          "PolicySet": ["b1c2d3e4-0000-4000-8000-000000000001", "b1c2d3e4-0000-4000-8000-000000000002", "b1c2d3e4-0000-4000-8000-000000000003", "b1c2d3e4-0000-4000-8000-000000000004", "b1c2d3e4-0000-4000-8000-000000000005", "b1c2d3e4-0000-4000-8000-000000000006", "b1c2d3e4-0000-4000-8000-000000000007", "b1c2d3e4-0000-4000-8000-000000000008"]
        },
        "created_at": [2026, 309, 11, 59, 5, 0, 0, 0, 0]
      },
      "auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "spending_limits": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "limits": [
        {
          "limit": {
            "chain_id": 56,
            "asset": {
              "kind": "native_eth"
            },
            "per_tx_max_wei": "10000000000000000",
            "daily_max_wei": "50000000000000000",
            "weekly_max_wei": "100000000000000000"
          },
          "policy_ids": ["b1c2d3e4-0000-4000-8000-000000000006", "b1c2d3e4-0000-4000-8000-000000000007", "b1c2d3e4-0000-4000-8000-000000000008"],
          "usage": {
            "spent_24h_wei": "0",
            "spent_7d_wei": "0",
            "tx_count_24h": 0,
            "remaining_24h_wei": "50000000000000000",
            "remaining_7d_wei": "100000000000000000",
            "available_now_wei": "10000000000000000"
          }
        },
        {
          "limit": {
            "chain_id": 56,
            "asset": {
              "kind": "erc20",
              "value": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
            },
            "per_tx_max_wei": "100000000000000000000",
            "daily_max_wei": "500000000000000000000",
            "weekly_max_wei": "1000000000000000000000",
            "max_gas_per_tx_wei": "2000000000000000"
          },
          "policy_ids": ["b1c2d3e4-0000-4000-8000-000000000001", "b1c2d3e4-0000-4000-8000-000000000002", "b1c2d3e4-0000-4000-8000-000000000003", "b1c2d3e4-0000-4000-8000-000000000004"],
          "usage": {
            "spent_24h_wei": "0",
            "spent_7d_wei": "0",
            "tx_count_24h": 0,
            "remaining_24h_wei": "500000000000000000000",
            "remaining_7d_wei": "1000000000000000000000",
            "available_now_wei": "100000000000000000000"
          }
        }
      ],
      "other_policy_ids": [],
      "as_of": [2026, 309, 11, 59, 5, 0, 0, 0, 0]
    },
    "replaced_vault_key_ids": []
  }
}
```

#### `ListWallets`

Lists every vault key on the machine with its addresses and agent keys, oldest first (by `created_at`, then id). Use it before `BootstrapWallet` `reuse` or `ExportWalletBackup` to show the user which wallet they act on, and to pass `vault_key_id` when the daemon holds several. An empty list means no wallet is set up.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `Wallets` | none | yes |

Each entry holds public metadata only, never key material, agent tokens, or token hashes:

| Field | Meaning |
|---|---|
| `vault_key_id` | the id to pass as `vault_key_id` |
| `algorithm` | `secp256k1` (every wallet `BootstrapWallet` sets up) or `ed25519` |
| `evm_address` | the EVM and Tempo address, lower case; `null` for an `ed25519` key |
| `solana_address` | the Solana address; `null` when the signer backend cannot sign for Solana (the Linux TPM) |
| `created_at` | when the key was created or imported |
| `source` | `Generated` or `Imported` (restored from a backup or imported) |
| `name` | the operator's display name (API 1.1), `null` when unnamed |
| `agent_key_ids` | the agent keys bound to the wallet, ascending |

Errors: `Signer` (the backend failed to derive a Solana address).

```json
{
  "method": "ListWallets",
  "params": {
    "auth": {
      "lease": {
        "lease_id": "c3d2e1f0-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
        "lease_secret": "3f9a6c1e8b2d47f0a5c3e9b1d7f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8"
      }
    }
  }
}
```

```json
{
  "type": "Wallets",
  "data": [
    {
      "vault_key_id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
      "algorithm": "secp256k1",
      "evm_address": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
      "solana_address": "9fijMemJYwXS5QD85Qxsq7iKqvSebgb6LvpGftgkeigk",
      "created_at": [2026, 309, 11, 59, 0, 0, 0, 0, 0],
      "source": "Generated",
      "name": "Trading bot",
      "agent_key_ids": ["9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"]
    }
  ]
}
```

#### `RenameWallet`

*Since API 1.1.* Sets a wallet's display name, or clears it with `"name": null`, and returns the wallet as `ListWallets` shows it. The name is trimmed and must then be 1 to 32 characters without control characters. It is a label only: nothing addresses a wallet by name, and two wallets may share one.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `Wallet` | renames the vault key; persists | yes |

Errors: `UnknownVaultKey`, `InvalidWalletRequest` (invalid name), `Signer`, `Persistence`.

```json
{
  "method": "RenameWallet",
  "params": {
    "auth": {
      "lease": {
        "lease_id": "c3d2e1f0-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
        "lease_secret": "3f9a6c1e8b2d47f0a5c3e9b1d7f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8"
      }
    },
    "vault_key_id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
    "name": "Trading bot"
  }
}
```

```json
{
  "type": "Wallet",
  "data": {
    "vault_key_id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
    "algorithm": "secp256k1",
    "evm_address": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
    "solana_address": "9fijMemJYwXS5QD85Qxsq7iKqvSebgb6LvpGftgkeigk",
    "created_at": [2026, 309, 11, 59, 0, 0, 0, 0, 0],
    "source": "Generated",
    "name": "Trading bot",
    "agent_key_ids": ["9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"]
  }
}
```

#### Encrypted wallet backups

A backup is a JSON document holding the wallet's private key encrypted under a passphrase. It is the format the TypeScript CLI of releases before 1.0 wrote (`agentpay admin wallet-backup export`), so backups from earlier releases restore unchanged, and backups written by the daemon open with the earlier CLI.

| Part | Format |
|---|---|
| Key derivation | scrypt over the UTF-8 passphrase and the 16-byte salt: N = 2^18 (256 MiB), r = 8, p = 1, 32-byte key. Backups with N from 2^15 to 2^20 (r = 8, p = 1) are read; anything else is rejected before any work. |
| Encryption | AES-256-GCM, 12-byte IV, 16-byte tag (`authTagHex`). |
| Additional data (version 2) | the compact JSON `{"kind","version","createdAt","wallet":{"address","vaultPublicKey"[,"sourceVaultKeyId"]},"encryption":{"algorithm","kdf","saltHex","ivHex","n","r","p"}}` in exactly that key order, so editing any header field breaks the tag. Version 1 (early CLIs) has none and is still read. |
| Plaintext | the compact JSON `{"createdAt","privateKeyHex","address","vaultPublicKey"[,"sourceVaultKeyId"][,"name"]}`; `privateKeyHex` is 64 hex characters without `0x`. `name` (API 1.1) is the wallet's name when it has one: encrypted and authenticated with the key, ignored by readers that do not know it, absent in older backups. A restore keeps it unless `BootstrapWallet` passes another name; an invalid stored name is dropped. `VerifyWalletBackup` and `ExportWalletBackup` report it as `summary.name`. |
| Checks on reading | the daemon derives the address and public key from the decrypted key and requires the encrypted and the cleartext copies of the metadata to match it. |

A new backup's **passphrase** needs at least 12 characters (Unicode scalar values, counted as given, not only whitespace) and at most 16 KiB. Reading accepts any non-empty passphrase, since earlier CLIs had no minimum. A forgotten passphrase cannot be recovered. A wrong passphrase and an altered document are indistinguishable (`WalletBackupDecryptionFailed`). Key derivation takes about a second and 256 MiB of memory; the daemon runs one at a time.

#### `ExportWalletBackup`

Encrypts the wallet's private key under `passphrase` inside the daemon and returns the backup document (`backup_json`: pretty-printed with a trailing newline, ready to write to a file as is) with a summary. `vault_key_id` is needed only when the daemon holds several vault keys (see [`ListWallets`](#listwallets)). Write the document to a file only the user can read, keep it offline, and check it with `VerifyWalletBackup`.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `WalletBackup` | none (the daemon keeps no copy) | yes in effect (a fresh salt and IV each time) |

Errors: `WeakBackupPassphrase`, `WalletNotFound`, `InvalidWalletRequest` (several vault keys without `vault_key_id`, an `ed25519` key, an oversized passphrase), `UnknownVaultKey`, `Signer` (`Unsupported` when the backend keeps keys non-exportable, as the Linux TPM does).

```json
{
  "method": "ExportWalletBackup",
  "params": {
    "auth": {
      "lease": {
        "lease_id": "c3d2e1f0-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
        "lease_secret": "3f9a6c1e8b2d47f0a5c3e9b1d7f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8"
      }
    },
    "passphrase": "correct horse battery staple"
  }
}
```

```json
{
  "type": "WalletBackup",
  "data": {
    "backup_json": "{\n  \"kind\": \"agentpay-wallet-backup\",\n  \"version\": 2,\n  \"createdAt\": \"2026-11-05T12:00:00.000Z\",\n  \"wallet\": {\n    \"address\": \"0x2c7536E3605D9C16a7a3D7b1898e529396a65c23\",\n    \"vaultPublicKey\": \"0x044e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e47fd35c4215d1edf53e6f83de344615ce719bdb0fd878f6ed76f06dd277956de\",\n    \"sourceVaultKeyId\": \"5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d\"\n  },\n  \"encryption\": {\n    \"algorithm\": \"aes-256-gcm\",\n    \"kdf\": \"scrypt\",\n    \"saltHex\": \"28c3e98d8d7bafd940830c489a04883a\",\n    \"ivHex\": \"6ff1f3acce295b0a9eda9fab\",\n    \"n\": 262144,\n    \"r\": 8,\n    \"p\": 1,\n    \"authTagHex\": \"933455f2529998e455b38ebea9731074\"\n  },\n  \"ciphertextHex\": \"53b4debb8483b8fa1700cec7f82ac8a39a50e21ed1d2faaf5cc3d90a9b60c665ac1d7fc46a21533c479f6ed1e82af0f0342cb0f7e595d18d60d7acde01365df9a4653f2b89ddfceb17748420a35efcc1964e43bc207f70347c29fb374c9fcbb18d66524c070aa43aa4d75516f6b37020a2d4adedab0e93ffaf77ff4d5644fdef70d915051ce0cdca306e6a87a7fa0dcb72a2c55b3a42d0816b44314f0c51b7fb2012d3b29c39acfd86003a276f229ae1c26acb01196104e3707652bf2b437240a7058c6088c7096bd4e2c828177a1d7c122a9d37a0bf068c2a8a177f2aa8949be23a5abbcebd662dc380df11ab324837d1b9cf746331699403df967d5c19fe8adcd3812341016fec82e24172facce323f33cd0dd5fc041426f5eadff42a7ffebc78f4327b4e3d9434359216c0d241af62004be56271e0e295dcf10c246297d6b815ae6f8712d08474bd61b1359eab74b8dd98a0855726ea908992d36bf8b33516b44396bc5ef498979aa2f03566895630ddd5aef32d3669a9c562d0a4bbef9d381b63715\"\n}\n",
    "summary": {
      "version": 2,
      "created_at": "2026-11-05T12:00:00.000Z",
      "address": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
      "public_key_hex": "044e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e47fd35c4215d1edf53e6f83de344615ce719bdb0fd878f6ed76f06dd277956de",
      "source_vault_key_id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
      "matching_vault_key_id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
      "name": null
    }
  }
}
```

#### `VerifyWalletBackup`

Decrypts a backup document with its passphrase and reports what it holds, without changing anything. `matching_vault_key_id` names the vault key in this daemon that holds the same key, if any.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `WalletBackupSummary` | none | yes |

Errors: `InvalidWalletBackup` (not a backup, an unsupported version or parameters, metadata that does not match the key), `WalletBackupDecryptionFailed`.

```json
{
  "method": "VerifyWalletBackup",
  "params": {
    "auth": "peer_credentials",
    "backup_json": "{\n  \"kind\": \"agentpay-wallet-backup\",\n  \"version\": 2,\n  \"createdAt\": \"2026-11-05T12:00:00.000Z\",\n  \"wallet\": {\n    \"address\": \"0x2c7536E3605D9C16a7a3D7b1898e529396a65c23\",\n    \"vaultPublicKey\": \"0x044e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e47fd35c4215d1edf53e6f83de344615ce719bdb0fd878f6ed76f06dd277956de\",\n    \"sourceVaultKeyId\": \"5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d\"\n  },\n  \"encryption\": {\n    \"algorithm\": \"aes-256-gcm\",\n    \"kdf\": \"scrypt\",\n    \"saltHex\": \"28c3e98d8d7bafd940830c489a04883a\",\n    \"ivHex\": \"6ff1f3acce295b0a9eda9fab\",\n    \"n\": 262144,\n    \"r\": 8,\n    \"p\": 1,\n    \"authTagHex\": \"933455f2529998e455b38ebea9731074\"\n  },\n  \"ciphertextHex\": \"53b4debb8483b8fa1700cec7f82ac8a39a50e21ed1d2faaf5cc3d90a9b60c665ac1d7fc46a21533c479f6ed1e82af0f0342cb0f7e595d18d60d7acde01365df9a4653f2b89ddfceb17748420a35efcc1964e43bc207f70347c29fb374c9fcbb18d66524c070aa43aa4d75516f6b37020a2d4adedab0e93ffaf77ff4d5644fdef70d915051ce0cdca306e6a87a7fa0dcb72a2c55b3a42d0816b44314f0c51b7fb2012d3b29c39acfd86003a276f229ae1c26acb01196104e3707652bf2b437240a7058c6088c7096bd4e2c828177a1d7c122a9d37a0bf068c2a8a177f2aa8949be23a5abbcebd662dc380df11ab324837d1b9cf746331699403df967d5c19fe8adcd3812341016fec82e24172facce323f33cd0dd5fc041426f5eadff42a7ffebc78f4327b4e3d9434359216c0d241af62004be56271e0e295dcf10c246297d6b815ae6f8712d08474bd61b1359eab74b8dd98a0855726ea908992d36bf8b33516b44396bc5ef498979aa2f03566895630ddd5aef32d3669a9c562d0a4bbef9d381b63715\"\n}\n",
    "passphrase": "correct horse battery staple"
  }
}
```

```json
{
  "type": "WalletBackupSummary",
  "data": {
    "version": 2,
    "created_at": "2026-11-05T12:00:00.000Z",
    "address": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
    "public_key_hex": "044e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e47fd35c4215d1edf53e6f83de344615ce719bdb0fd878f6ed76f06dd277956de",
    "source_vault_key_id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
    "matching_vault_key_id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
    "name": null
  }
}
```

### Spending limits

A spending limit row gives an agent a per-transaction, daily, and weekly limit for one network and asset, optionally with gas and fee caps and a daily transaction count. Rows are ordinary policies, each scoped to exactly that asset and network (recipients: all):

| Row field | Policy |
|---|---|
| `per_tx_max_wei` | `PerTxMaxSpending`, `over_limit: manual_approval` |
| `daily_max_wei` | `DailyMaxSpending` (rolling 24 hours), `over_limit: manual_approval` |
| `weekly_max_wei` | `WeeklyMaxSpending` (rolling 7 days), `over_limit: manual_approval` |
| `max_gas_per_tx_wei` | `PerChainMaxGasSpend` (`gas_limit * max_fee_per_gas`) |
| `max_fee_per_gas_wei` | `PerTxMaxFeePerGas` |
| `max_priority_fee_per_gas_wei` | `PerTxMaxPriorityFeePerGas` |
| `daily_max_tx_count` | `DailyMaxTxCount` (rolling 24 hours), `over_limit: manual_approval` |

**Beyond a limit: approval.** The per-payment, daily, weekly, and daily-count limits are what an agent pays **on its own**. A payment beyond any of them is not denied: `SignForAgent` holds it as a [manual approval request](#manual-approval) (`ManualApprovalRequired`), whose `reasons` list every limit it goes beyond (for example the daily limit, what was already used today, and this payment's amount). One request covers all of them. Once approved, the identical payment is signed and counts toward the windows like any other; the next payment beyond a limit asks again. Gas and fee caps stay hard limits. A row read back from older policies ignores a legacy `ManualApproval` range policy of its network and asset; replacing the rows retires it.

**Deny by default.** An agent may spend only the assets that have a row. There is no unrestricted fallback: an asset without a row has no applicable policy and every payment in it fails with `Policy` / `NoApplicablePolicies`. Gas and fee caps are scoped to their row's asset too, so a row never makes another asset spendable. To allow a token, add a row; to stop an agent entirely, revoke its key.

**Validation** (`InvalidSpendingLimits`): 1 to 64 rows; `chain_id` not 0; the asset matches the chain family (`native_eth`/`erc20` on EVM chains, `native_sol`/`spl_token` on Solana); `0 < per_tx_max_wei <= daily_max_wei <= weekly_max_wei`; optional caps greater than zero, and the gas and fee caps on EVM chains only; no network and asset twice. Every Solana cluster is one policy network, reported as `900000001`.

**Usage** comes from the daemon's spend log exactly as the policy engine counts it: every signature for the agent, asset, and network in the rolling window, including a signed transaction that was never sent and approved payments beyond a limit. `available_now_wei` is the largest payment the agent can make on its own right now (0 once `daily_max_tx_count` is used up); larger payments need approval.

#### `ListSpendingLimits`

Returns an agent's rows with usage. Rows are read back from the enabled policies that govern the agent: a network and asset appear when single-network, single-asset, all-recipient policies give them a per-transaction, daily, and weekly cap (when several policies cap the same thing, the smallest cap is shown). Any other enabled spending policy that governs the agent is listed in `other_policy_ids`: it still applies, but cannot be shown as a row.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `SpendingLimits` | none | yes |

Errors: `UnknownAgentKey`.

```json
{
  "method": "ListSpendingLimits",
  "params": {
    "auth": {
      "lease": {
        "lease_id": "c3d2e1f0-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
        "lease_secret": "3f9a6c1e8b2d47f0a5c3e9b1d7f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8"
      }
    },
    "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
  }
}
```

```json
{
  "type": "SpendingLimits",
  "data": {
    "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
    "limits": [
      {
        "limit": {
          "chain_id": 56,
          "asset": {
            "kind": "native_eth"
          },
          "per_tx_max_wei": "10000000000000000",
          "daily_max_wei": "50000000000000000",
          "weekly_max_wei": "100000000000000000"
        },
        "policy_ids": ["b1c2d3e4-0000-4000-8000-000000000006", "b1c2d3e4-0000-4000-8000-000000000007", "b1c2d3e4-0000-4000-8000-000000000008"],
        "usage": {
          "spent_24h_wei": "0",
          "spent_7d_wei": "0",
          "tx_count_24h": 0,
          "remaining_24h_wei": "50000000000000000",
          "remaining_7d_wei": "100000000000000000",
          "available_now_wei": "10000000000000000"
        }
      },
      {
        "limit": {
          "chain_id": 56,
          "asset": {
            "kind": "erc20",
            "value": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
          },
          "per_tx_max_wei": "100000000000000000000",
          "daily_max_wei": "500000000000000000000",
          "weekly_max_wei": "1000000000000000000000",
          "max_gas_per_tx_wei": "2000000000000000"
        },
        "policy_ids": ["b1c2d3e4-0000-4000-8000-000000000001", "b1c2d3e4-0000-4000-8000-000000000002", "b1c2d3e4-0000-4000-8000-000000000003", "b1c2d3e4-0000-4000-8000-000000000004"],
        "usage": {
          "spent_24h_wei": "1000000000000000000",
          "spent_7d_wei": "41000000000000000000",
          "tx_count_24h": 1,
          "remaining_24h_wei": "499000000000000000000",
          "remaining_7d_wei": "959000000000000000000",
          "available_now_wei": "100000000000000000000"
        }
      }
    ],
    "other_policy_ids": [],
    "as_of": [2026, 309, 12, 5, 0, 0, 0, 0, 0]
  }
}
```

#### `SetSpendingLimits`

Replaces an agent's limit set atomically. The daemon adds one policy per configured cap and attaches exactly those, plus the agent's `Eip712Signing` policies, as the agent's `PolicySet`. The agent's previous spending policies are disabled when no other agent key can be governed by them, and only detached otherwise: another agent's `PolicySet` may list them, and an agent attached to `AllPolicies` is governed by every enabled policy. The token does not change and the spend history is kept.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `SpendingLimits` | adds the row policies, replaces the agent's attachment, disables unused previous policies | yes in effect (same rows, new policy ids) |

Errors: `UnknownAgentKey`, `InvalidSpendingLimits`, `Persistence`.

```json
{
  "method": "SetSpendingLimits",
  "params": {
    "auth": {
      "lease": {
        "lease_id": "c3d2e1f0-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
        "lease_secret": "3f9a6c1e8b2d47f0a5c3e9b1d7f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8"
      }
    },
    "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
    "limits": [
      {
        "chain_id": 56,
        "asset": {
          "kind": "erc20",
          "value": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
        },
        "per_tx_max_wei": "25000000000000000000",
        "daily_max_wei": "100000000000000000000",
        "weekly_max_wei": "300000000000000000000",
        "daily_max_tx_count": "20"
      }
    ]
  }
}
```

```json
{
  "type": "SpendingLimits",
  "data": {
    "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
    "limits": [
      {
        "limit": {
          "chain_id": 56,
          "asset": {
            "kind": "erc20",
            "value": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
          },
          "per_tx_max_wei": "25000000000000000000",
          "daily_max_wei": "100000000000000000000",
          "weekly_max_wei": "300000000000000000000",
          "daily_max_tx_count": "20"
        },
        "policy_ids": ["b1c2d3e4-0000-4000-8000-000000000009", "b1c2d3e4-0000-4000-8000-000000000010", "b1c2d3e4-0000-4000-8000-000000000011", "b1c2d3e4-0000-4000-8000-000000000012"],
        "usage": {
          "spent_24h_wei": "1000000000000000000",
          "spent_7d_wei": "41000000000000000000",
          "tx_count_24h": 1,
          "remaining_24h_wei": "99000000000000000000",
          "remaining_7d_wei": "259000000000000000000",
          "available_now_wei": "25000000000000000000"
        }
      }
    ],
    "other_policy_ids": [],
    "as_of": [2026, 309, 12, 6, 0, 0, 0, 0, 0]
  }
}
```

### Manual approvals

See [Manual approval](#manual-approval) for the end-to-end semantics.

#### `ListManualApprovalRequests`

Lists every retained approval request, newest first, in every status. Filter on `status == "pending"` to get the queue.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `ManualApprovalRequests` | none | yes |

```json
{
  "method": "ListManualApprovalRequests",
  "params": {
    "auth": {
      "lease": {
        "lease_id": "c3d2e1f0-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
        "lease_secret": "3f9a6c1e8b2d47f0a5c3e9b1d7f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8"
      }
    }
  }
}
```

```json
{
  "type": "ManualApprovalRequests",
  "data": [
    {
      "id": "e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090",
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "vault_key_id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
      "request_payload_hash_hex": "b6f0c4a1e9d27f3c58a0e4b2d6c8f1a3e5b7d9f0c2a4e6b8d0f2a4c6e8b0d2f4",
      "action": {
        "kind": "Transfer",
        "chain_id": 56,
        "token": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
        "to": "0x5aeda56215b167893e80b4fe645ba6d5bab767de",
        "amount_wei": "1000000000000000000"
      },
      "chain_id": 56,
      "asset": {
        "kind": "erc20",
        "value": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
      },
      "recipient": {
        "kind": "evm",
        "value": "0x5aeda56215b167893e80b4fe645ba6d5bab767de"
      },
      "amount_wei": "1000000000000000000",
      "created_at": [2026, 309, 12, 0, 0, 0, 0, 0, 0],
      "updated_at": [2026, 309, 12, 0, 0, 0, 0, 0, 0],
      "status": "pending",
      "triggered_by_policy_ids": ["a1b2c3d4-0000-4000-8000-000000000002"],
      "reasons": [
        {
          "limit": "policy",
          "policy_id": "a1b2c3d4-0000-4000-8000-000000000002",
          "max": "100000000000000000000",
          "used": null,
          "requested_amount_wei": "1000000000000000000"
        }
      ],
      "completed_at": null,
      "rejection_reason": null
    }
  ]
}
```

#### `DecideManualApprovalRequest`

Approves or rejects a pending request. `rejection_reason` is recorded, trimmed, only for rejections. To approve, every triggering policy must still exist, be enabled, and be a manual-approval policy. On macOS, the lease for this call typically comes from a Touch ID challenge with the purpose `approve:<approval_request_id>`.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| admin allowlist | root peer or lease | `ManualApprovalRequest` | persists the decision | no |

Errors: `UnknownManualApprovalRequest`, `ManualApprovalRequestNotPending`, `UnknownPolicy`, `InvalidPolicy`, `Persistence`.

```json
{
  "method": "DecideManualApprovalRequest",
  "params": {
    "auth": {
      "lease": {
        "lease_id": "c3d2e1f0-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
        "lease_secret": "3f9a6c1e8b2d47f0a5c3e9b1d7f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8"
      }
    },
    "approval_request_id": "e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090",
    "decision": "approve",
    "rejection_reason": null
  }
}
```

```json
{
  "type": "ManualApprovalRequest",
  "data": {
    "id": "e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090",
    "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
    "vault_key_id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
    "request_payload_hash_hex": "b6f0c4a1e9d27f3c58a0e4b2d6c8f1a3e5b7d9f0c2a4e6b8d0f2a4c6e8b0d2f4",
    "action": {
      "kind": "Transfer",
      "chain_id": 56,
      "token": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
      "to": "0x5aeda56215b167893e80b4fe645ba6d5bab767de",
      "amount_wei": "1000000000000000000"
    },
    "chain_id": 56,
    "asset": {
      "kind": "erc20",
      "value": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
    },
    "recipient": {
      "kind": "evm",
      "value": "0x5aeda56215b167893e80b4fe645ba6d5bab767de"
    },
    "amount_wei": "1000000000000000000",
    "created_at": [2026, 309, 12, 0, 0, 0, 0, 0, 0],
    "updated_at": [2026, 309, 12, 1, 15, 0, 0, 0, 0],
    "status": "approved",
    "triggered_by_policy_ids": ["a1b2c3d4-0000-4000-8000-000000000002"],
    "reasons": [
      {
        "limit": "policy",
        "policy_id": "a1b2c3d4-0000-4000-8000-000000000002",
        "max": "100000000000000000000",
        "used": null,
        "requested_amount_wei": "1000000000000000000"
      }
    ],
    "completed_at": null,
    "rejection_reason": null
  }
}
```

### Agent

Every agent request except `AuthenticateAgent`, `AgentPolicySummary`, and `AgentActivity` carries `request_id`, `agent_key_id`, `agent_auth_token`, `requested_at`, and `expires_at`. Their timestamps must satisfy these rules:

- `requested_at < expires_at`;
- `expires_at` is in the future;
- `requested_at` is at most 30 s ahead of the daemon clock;
- `expires_at - requested_at` is at most 5 minutes.

A `SignRequest` also carries the `action` and a `payload`. The `payload` must be the bytes of the **canonical compact JSON** of `action`: `serde_json` output with fields in the order this document shows, no whitespace, and non-ASCII characters left unescaped. The payload is at most 32 KiB.

A typical EVM flow:

1. `ReserveNonce` with the account's pending nonce from RPC.
2. `SignForAgent` with a `BroadcastTx` that uses the reserved nonce.
3. Broadcast `raw_tx_hex` with `eth_sendRawTransaction`. If the send certainly never reached the node, return the nonce with `ReleaseSignedNonce`.

#### `AuthenticateAgent`

Verifies agent credentials and returns the agent key, its vault key's public metadata, and the addresses the vault key signs for: `evm_address` for a `secp256k1` key (`null` for `ed25519`), and `solana_address` (`null` when the signer backend cannot sign for Solana, as with the Linux TPM). The request has no timestamps, so the freshness rules do not apply and no `request_id` is consumed. The payments service calls it for every authenticated request it serves.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| agent allowlist | agent token | `AgentIdentity` | none | yes |

Errors: `AgentAuthenticationFailed`, `UnknownVaultKey`, `Signer`.

```json
{
  "method": "AuthenticateAgent",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    }
  }
}
```

```json
{
  "type": "AgentIdentity",
  "data": {
    "agent_key": {
      "id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "vault_key_id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
      "policies": "AllPolicies",
      "created_at": [2026, 309, 11, 59, 5, 0, 0, 0, 0]
    },
    "vault_key": {
      "id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
      "source": "Generated",
      "algorithm": "secp256k1",
      "public_key_hex": "044e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e47fd35c4215d1edf53e6f83de344615ce719bdb0fd878f6ed76f06dd277956de",
      "created_at": [2026, 309, 11, 59, 0, 0, 0, 0, 0]
    },
    "evm_address": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
    "solana_address": "9fijMemJYwXS5QD85Qxsq7iKqvSebgb6LvpGftgkeigk"
  }
}
```

#### `AgentPolicySummary`

Lists the enabled policies that govern the agent, in evaluation order (ascending `priority`, then id): each policy's `id`, `priority`, `policy_type`, and `assets` and `networks` scope. Limit amounts and recipient lists are not included; they stay admin-only (`ListPolicies`). `attachment` is the agent key's attachment (`"AllPolicies"` or `{"PolicySet": [...]}`), and `spending_policy_count` counts the policies of every type except `Eip712Signing`. When it is `0`, the agent cannot spend: every payment is denied (`NoAttachedPolicies` or `NoApplicablePolicies`) until an operator sets limits. The payments service's [`Status`](#status) reports this as the `no_spending_policy` warning. Like `AuthenticateAgent`, the request has no timestamps and consumes no request id.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| agent allowlist | agent token | `AgentPolicySummary` | none | yes |

Errors: `AgentAuthenticationFailed`.

```json
{
  "method": "AgentPolicySummary",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    }
  }
}
```

```json
{
  "type": "AgentPolicySummary",
  "data": {
    "attachment": "AllPolicies",
    "policies": [
      {
        "id": "a1b2c3d4-0000-4000-8000-000000000001",
        "priority": 10,
        "policy_type": "PerTxMaxSpending",
        "assets": {
          "mode": "Set",
          "values": [
            {
              "kind": "erc20",
              "value": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
            }
          ]
        },
        "networks": {
          "mode": "Set",
          "values": [56]
        }
      },
      {
        "id": "a1b2c3d4-0000-4000-8000-000000000002",
        "priority": 20,
        "policy_type": "ManualApproval",
        "assets": {
          "mode": "All"
        },
        "networks": {
          "mode": "All"
        }
      }
    ],
    "spending_policy_count": 2
  }
}
```

#### `EvaluateForAgent`

Reports whether a request would be allowed, without signing. It records no spend and does not consume `request_id`. A denial is an error (`Policy`), including the soft `ManualApprovalRequired` policy outcome.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| agent allowlist | agent token | `PolicyEvaluation` | none | yes |

Errors: `AgentAuthenticationFailed`, `InvalidRequestTimestamps`, `RequestExpired`, `PayloadTooLarge`, `PayloadActionMismatch`, `InvalidAction`, `Policy`.

```json
{
  "method": "EvaluateForAgent",
  "params": {
    "request": {
      "request_id": "4d3c2b1a-0f9e-4d8c-b7a6-958473625140",
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7",
      "payload": [123, 34, 107, 105, 110, 100, 34, 58, 34, 84, 114, 97, 110, 115, 102, 101, 114, 34, 44, 34, 99, 104, 97, 105, 110, 95, 105, 100, 34, 58, 53, 54, 44, 34, 116, 111, 107, 101, 110, 34, 58, 34, 48, 120, 56, 100, 48, 100, 48, 48, 48, 101, 101, 52, 52, 57, 52, 56, 102, 99, 57, 56, 99, 57, 98, 57, 56, 97, 52, 102, 97, 52, 57, 50, 49, 52, 55, 54, 102, 48, 56, 98, 48, 100, 34, 44, 34, 116, 111, 34, 58, 34, 48, 120, 53, 97, 101, 100, 97, 53, 54, 50, 49, 53, 98, 49, 54, 55, 56, 57, 51, 101, 56, 48, 98, 52, 102, 101, 54, 52, 53, 98, 97, 54, 100, 53, 98, 97, 98, 55, 54, 55, 100, 101, 34, 44, 34, 97, 109, 111, 117, 110, 116, 95, 119, 101, 105, 34, 58, 34, 49, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 34, 125],
      "action": {
        "kind": "Transfer",
        "chain_id": 56,
        "token": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
        "to": "0x5aeda56215b167893e80b4fe645ba6d5bab767de",
        "amount_wei": "1000000000000000000"
      },
      "requested_at": [2026, 309, 12, 0, 0, 0, 0, 0, 0],
      "expires_at": [2026, 309, 12, 2, 0, 0, 0, 0, 0]
    }
  }
}
```

```json
{
  "type": "PolicyEvaluation",
  "data": {
    "evaluated_policy_ids": ["a1b2c3d4-0000-4000-8000-000000000001", "a1b2c3d4-0000-4000-8000-000000000002"]
  }
}
```

#### `ExplainForAgent`

Explains the policy decision without signing. A denial is returned as `{"decision":"deny","reason":<PolicyError>}`, and a request that would wait for approval as `{"decision":"manual_approval","reason":[<PolicyError>, ...]}` (every rule that holds it; see [Manual approval](#manual-approval)), not as an error.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| agent allowlist | agent token | `PolicyExplanation` | none | yes |

Errors: `AgentAuthenticationFailed`, `InvalidRequestTimestamps`, `RequestExpired`, `PayloadTooLarge`, `PayloadActionMismatch`, `InvalidAction`.

```json
{
  "method": "ExplainForAgent",
  "params": {
    "request": {
      "request_id": "4d3c2b1a-0f9e-4d8c-b7a6-958473625140",
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7",
      "payload": [123, 34, 107, 105, 110, 100, 34, 58, 34, 84, 114, 97, 110, 115, 102, 101, 114, 34, 44, 34, 99, 104, 97, 105, 110, 95, 105, 100, 34, 58, 53, 54, 44, 34, 116, 111, 107, 101, 110, 34, 58, 34, 48, 120, 56, 100, 48, 100, 48, 48, 48, 101, 101, 52, 52, 57, 52, 56, 102, 99, 57, 56, 99, 57, 98, 57, 56, 97, 52, 102, 97, 52, 57, 50, 49, 52, 55, 54, 102, 48, 56, 98, 48, 100, 34, 44, 34, 116, 111, 34, 58, 34, 48, 120, 53, 97, 101, 100, 97, 53, 54, 50, 49, 53, 98, 49, 54, 55, 56, 57, 51, 101, 56, 48, 98, 52, 102, 101, 54, 52, 53, 98, 97, 54, 100, 53, 98, 97, 98, 55, 54, 55, 100, 101, 34, 44, 34, 97, 109, 111, 117, 110, 116, 95, 119, 101, 105, 34, 58, 34, 49, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 34, 125],
      "action": {
        "kind": "Transfer",
        "chain_id": 56,
        "token": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
        "to": "0x5aeda56215b167893e80b4fe645ba6d5bab767de",
        "amount_wei": "1000000000000000000"
      },
      "requested_at": [2026, 309, 12, 0, 0, 0, 0, 0, 0],
      "expires_at": [2026, 309, 12, 2, 0, 0, 0, 0, 0]
    }
  }
}
```

```json
{
  "type": "PolicyExplanation",
  "data": {
    "attached_policy_ids": ["a1b2c3d4-0000-4000-8000-000000000001", "a1b2c3d4-0000-4000-8000-000000000002"],
    "applicable_policy_ids": ["a1b2c3d4-0000-4000-8000-000000000001", "a1b2c3d4-0000-4000-8000-000000000002"],
    "evaluated_policy_ids": ["a1b2c3d4-0000-4000-8000-000000000001", "a1b2c3d4-0000-4000-8000-000000000002"],
    "decision": {
      "decision": "allow"
    }
  }
}
```

#### `ReserveNonce`

Reserves a unique EVM nonce for a future `BroadcastTx`. The daemon returns the lowest nonce at or above `min_nonce` that is not reserved or already signed for this vault key and chain, and it reuses released gaps. With `exact_nonce`, it reserves exactly `min_nonce` or fails. A reservation expires after 2 minutes. A reservation may skip at most 1024 nonces past the tracked head.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| agent allowlist | agent token | `NonceReservation` | persists the reservation; consumes `request_id` | per `request_id`: an identical retry returns the same reservation |

Errors: `AgentAuthenticationFailed`, `InvalidRequestTimestamps`, `RequestExpired`, `RequestReplayDetected`, `TooManyTrackedReplayIds`, `InvalidNonceReservation`, `NonceSkipTooLarge`, `TooManyActiveNonceReservations`, `Persistence`.

```json
{
  "method": "ReserveNonce",
  "params": {
    "request": {
      "request_id": "5e4d3c2b-1a0f-4e9d-8c7b-a69584736251",
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7",
      "chain_id": 56,
      "min_nonce": 7,
      "exact_nonce": false,
      "requested_at": [2026, 309, 12, 0, 0, 0, 0, 0, 0],
      "expires_at": [2026, 309, 12, 2, 0, 0, 0, 0, 0]
    }
  }
}
```

```json
{
  "type": "NonceReservation",
  "data": {
    "reservation_id": "7f6e5d4c-3b2a-4190-8f7e-6d5c4b3a2918",
    "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
    "vault_key_id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
    "chain_id": 56,
    "nonce": 7,
    "issued_at": [2026, 309, 12, 0, 0, 0, 0, 0, 0],
    "expires_at": [2026, 309, 12, 2, 0, 0, 0, 0, 0]
  }
}
```

#### `ReleaseNonce`

Releases an unused reservation and returns its nonce to the pool. The reservation must belong to the calling agent.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| agent allowlist | agent token | `Unit` | removes the reservation; consumes `request_id` | per `request_id` |

Errors: `AgentAuthenticationFailed`, `InvalidRequestTimestamps`, `RequestExpired`, `RequestReplayDetected`, `TooManyTrackedReplayIds`, `UnknownNonceReservation`, `Persistence`.

```json
{
  "method": "ReleaseNonce",
  "params": {
    "request": {
      "request_id": "6f5e4d3c-2b1a-4f0e-9d8c-b7a695847362",
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7",
      "reservation_id": "7f6e5d4c-3b2a-4190-8f7e-6d5c4b3a2918",
      "requested_at": [2026, 309, 12, 0, 0, 0, 0, 0, 0],
      "expires_at": [2026, 309, 12, 2, 0, 0, 0, 0, 0]
    }
  }
}
```

```json
{
  "type": "Unit"
}
```

#### `ReleaseSignedNonce`

Returns the nonce of a signed `BroadcastTx` whose transaction never reached the network. Signing consumes a nonce, and the daemon never hands a consumed nonce out again; without this call a failed send leaves a gap, and every later transaction waits behind it. The request names the transaction by `tx_hash_hex` (from `SignForAgent`) with its `chain_id` and `nonce`; only the agent that signed it can release it, once, within 10 minutes of signing. The nonce goes back to the pool unless an exact-nonce reservation holds it again, and the recorded signature is dropped, so retrying the original `SignForAgent` request fails with `RequestReplayDetected` instead of returning the released transaction.

**Only call it when the transaction certainly never reached a node**: the send request could not be delivered (the connection was refused), the node answered it with a JSON-RPC error (nodes do not relay transactions they reject), or it was never sent (for example the signed transaction failed local verification). After a timeout, a lost response, or an HTTP error from a proxy the node may have the transaction; keep the nonce. A released nonce is handed out again, and a second transaction with it replaces or races the first: both were allowed by policy and at most one is mined, so this cannot exceed a limit, but it can replace a payment. The spend **stays counted** against the window limits: the daemon cannot see the network, and refunding it on the agent's word would let an agent that broadcasts the transaction itself spend past its limits.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| agent allowlist | agent token; the signing agent only | `Unit` | frees the nonce, forgets the transaction and its recorded signature; consumes `request_id` | per `request_id` |

Errors: `AgentAuthenticationFailed` (also when another agent signed it), `InvalidRequestTimestamps`, `RequestExpired`, `RequestReplayDetected`, `TooManyTrackedReplayIds`, `UnknownSignedTransaction` (not signed here, already released, or older than 10 minutes), `InvalidNonceReservation` (`chain_id` or `nonce` do not match, or a malformed hash), `Persistence`.

```json
{
  "method": "ReleaseSignedNonce",
  "params": {
    "request": {
      "request_id": "4d3c2b1a-0f9e-4d8c-8b7a-695847362514",
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7",
      "chain_id": 56,
      "nonce": 7,
      "tx_hash_hex": "0xeea2f8bd120806cc3bdd89e0640411ed04e47d11b01305059fd0948e887eaeaf",
      "requested_at": [2026, 309, 12, 0, 1, 0, 0, 0, 0],
      "expires_at": [2026, 309, 12, 2, 1, 0, 0, 0, 0]
    }
  }
}
```

```json
{
  "type": "Unit"
}
```

#### `SignForAgent`

Evaluates policies and, when they allow it, signs. What the daemon signs depends on the action:

| Action | Result |
|---|---|
| `BroadcastTx` | a signed EIP-1559 (type `0x02`) transaction: `raw_tx_hex`, `tx_hash_hex`, `r_hex`, `s_hex`, `v` |
| EIP-3009, `Permit2WitnessTransfer`, Tempo session v2, `Eip712TypedData` | a signature over the EIP-712 digest: `r_hex`, `s_hex`, `v` |
| Solana actions | a signed transaction: `raw_tx_base64`, `tx_id`, `signature_base58` |
| `SolanaPaymentTransaction` | a v0 transaction signed by the agent: `raw_tx_base64`, `signature_base58` and `bytes` (the agent's signature), and `tx_id` only when the agent is the fee payer. With a foreign `fee_payer` the transaction is partially signed: the fee payer's signature slot (account 0) is all zero until the fee payer signs |
| `Approve`, `Transfer`, `TransferNative` | a DER signature over the payload |

*Since API 1.1.0:* `Permit2WitnessTransfer` (`{"kind": "Permit2WitnessTransfer", "permit": {...}}`) signs the `permit2` credential of an MPP `evm` / `arbitrum` charge: a Permit2 `SignatureTransfer` permit with a payment witness for the canonical Permit2 deployment `0x000000000022d473030f116ddee9f6b43ac78ba3` (EIP-712 domain `{name: "Permit2", chainId, verifyingContract}`). `permit` holds `chain_id`, `token`, `permitted` (1 to 11 entries `{"amount_wei"}`: one is `PermitWitnessTransferFrom`, more are `PermitBatchWitnessTransferFrom`, all in `token`), `spender`, `nonce` (a decimal `uint256`), `deadline` (Unix seconds, in the future and at most an hour away), and `witness`: `{"kind": "challenge_external_id", "challenge_hash", "external_id"}` (`PaymentWitness(bytes32 challengeHash,string externalId)`; `external_id` at most 256 bytes) or `{"kind": "challenge", "challenge_hash"}` (`PaymentWitness(bytes32 challengeHash)`). The signature binds the spender, not the recipients (the spender chooses them when redeeming), so policies see one payment of the sum of the entries in `token`, to `spender`.

*Since API 1.1.0:* `SolanaPaymentTransaction` (`{"kind": "SolanaPaymentTransaction", "payment": {...}}`) pays an MPP `solana` charge (draft-solana-charge-00). `payment` holds `chain_id`, `recent_blockhash`, `fee_payer` (the agent's Solana address or the payee's fee payer), `asset` (`{"kind": "native_sol"}` or `{"kind": "spl_token", "mint": ..., "decimals": ..., "token_program": "token" | "token2022"}`), `transfers` (1 to 9 legs `{"recipient_owner", "amount_wei", "create_ata", "memo"?}`; the first is the primary payment, the rest are splits), and optional `memo`, `compute_unit_limit` (at most 200000), and `compute_unit_price_micro_lamports`. Amounts are greater than zero and sum to at most `u64::MAX`; memos are 1 to 566 UTF-8 bytes; `create_ata` is only valid for SPL splits, and the primary leg has neither `create_ata` nor its own `memo` (its memo is `payment.memo`). The daemon builds a v0 transaction (no address lookup tables) with the instructions in this order: `SetComputeUnitPrice`, `SetComputeUnitLimit` (each when set), the primary transfer, the `memo`, then per split its associated-token-account `CreateIdempotent` (paid by `fee_payer`, when `create_ata`), its transfer, and its memo. SOL legs are System transfers from the agent; SPL legs are `TransferChecked` from the agent's associated token account to the recipient's. Policies see one payment of the sum of all legs in `asset`, to the primary recipient, on the Solana policy network.

A successful signature records the spend for window limits. It also consumes `request_id`, consumes the nonce reservation for a `BroadcastTx`, and completes an approved manual approval request. Resending an identical request (same `request_id` and payload) within 8 days returns the recorded signature. Reusing a `request_id` with a different payload fails with `RequestReplayDetected`.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| agent allowlist | agent token | `Signature` | spend log, replay id, nonce, approvals, Tempo channel deposits, persisted | per `request_id` |

Errors: `AgentAuthenticationFailed`, `InvalidRequestTimestamps`, `RequestExpired`, `RequestReplayDetected`, `TooManyTrackedReplayIds`, `PayloadTooLarge`, `PayloadActionMismatch`, `InvalidAction`, `Policy`, `ManualApprovalRequired`, `ManualApprovalRejected`, `TooManyPendingManualApprovalRequests`, `MissingNonceReservation`, `UnknownVaultKey`, `Signer`, `Persistence`.

The example below is a transfer of 1 USD1 on BNB Smart Chain (chain id 56), using the nonce reserved in the `ReserveNonce` example. The response is the real signed transaction for the example wallet (the key held by the `ExportWalletBackup` example backup).

```json
{
  "method": "SignForAgent",
  "params": {
    "request": {
      "request_id": "708f6e5d-4c3b-4a1f-8e9d-c8b7a6958473",
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7",
      "payload": [123, 34, 107, 105, 110, 100, 34, 58, 34, 66, 114, 111, 97, 100, 99, 97, 115, 116, 84, 120, 34, 44, 34, 116, 120, 34, 58, 123, 34, 99, 104, 97, 105, 110, 95, 105, 100, 34, 58, 53, 54, 44, 34, 110, 111, 110, 99, 101, 34, 58, 55, 44, 34, 116, 111, 34, 58, 34, 48, 120, 56, 100, 48, 100, 48, 48, 48, 101, 101, 52, 52, 57, 52, 56, 102, 99, 57, 56, 99, 57, 98, 57, 56, 97, 52, 102, 97, 52, 57, 50, 49, 52, 55, 54, 102, 48, 56, 98, 48, 100, 34, 44, 34, 118, 97, 108, 117, 101, 95, 119, 101, 105, 34, 58, 34, 48, 34, 44, 34, 100, 97, 116, 97, 95, 104, 101, 120, 34, 58, 34, 48, 120, 97, 57, 48, 53, 57, 99, 98, 98, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 53, 97, 101, 100, 97, 53, 54, 50, 49, 53, 98, 49, 54, 55, 56, 57, 51, 101, 56, 48, 98, 52, 102, 101, 54, 52, 53, 98, 97, 54, 100, 53, 98, 97, 98, 55, 54, 55, 100, 101, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 100, 101, 48, 98, 54, 98, 51, 97, 55, 54, 52, 48, 48, 48, 48, 34, 44, 34, 103, 97, 115, 95, 108, 105, 109, 105, 116, 34, 58, 54, 48, 48, 48, 48, 44, 34, 109, 97, 120, 95, 102, 101, 101, 95, 112, 101, 114, 95, 103, 97, 115, 95, 119, 101, 105, 34, 58, 34, 49, 48, 48, 48, 48, 48, 48, 48, 48, 48, 34, 44, 34, 109, 97, 120, 95, 112, 114, 105, 111, 114, 105, 116, 121, 95, 102, 101, 101, 95, 112, 101, 114, 95, 103, 97, 115, 95, 119, 101, 105, 34, 58, 34, 49, 48, 48, 48, 48, 48, 48, 48, 48, 48, 34, 44, 34, 116, 120, 95, 116, 121, 112, 101, 34, 58, 50, 44, 34, 100, 101, 108, 101, 103, 97, 116, 105, 111, 110, 95, 101, 110, 97, 98, 108, 101, 100, 34, 58, 102, 97, 108, 115, 101, 125, 125],
      "action": {
        "kind": "BroadcastTx",
        "tx": {
          "chain_id": 56,
          "nonce": 7,
          "to": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
          "value_wei": "0",
          "data_hex": "0xa9059cbb0000000000000000000000005aeda56215b167893e80b4fe645ba6d5bab767de0000000000000000000000000000000000000000000000000de0b6b3a7640000",
          "gas_limit": 60000,
          "max_fee_per_gas_wei": "1000000000",
          "max_priority_fee_per_gas_wei": "1000000000",
          "tx_type": 2,
          "delegation_enabled": false
        }
      },
      "requested_at": [2026, 309, 12, 0, 0, 0, 0, 0, 0],
      "expires_at": [2026, 309, 12, 2, 0, 0, 0, 0, 0]
    }
  }
}
```

```json
{
  "type": "Signature",
  "data": {
    "bytes": [48, 69, 2, 33, 0, 208, 227, 168, 140, 4, 20, 14, 95, 82, 36, 124, 90, 225, 125, 137, 100, 235, 130, 232, 86, 106, 69, 15, 233, 122, 101, 124, 252, 58, 252, 219, 160, 2, 32, 117, 165, 55, 109, 167, 184, 64, 104, 124, 184, 137, 220, 98, 129, 106, 230, 28, 31, 117, 209, 88, 88, 52, 19, 135, 207, 50, 179, 58, 202, 177, 0],
    "r_hex": "0xd0e3a88c04140e5f52247c5ae17d8964eb82e8566a450fe97a657cfc3afcdba0",
    "s_hex": "0x75a5376da7b840687cb889dc62816ae61c1f75d15858341387cf32b33acab100",
    "v": 0,
    "raw_tx_hex": "0x02f8af3807843b9aca00843b9aca0082ea60948d0d000ee44948fc98c9b98a4fa4921476f08b0d80b844a9059cbb0000000000000000000000005aeda56215b167893e80b4fe645ba6d5bab767de0000000000000000000000000000000000000000000000000de0b6b3a7640000c080a0d0e3a88c04140e5f52247c5ae17d8964eb82e8566a450fe97a657cfc3afcdba0a075a5376da7b840687cb889dc62816ae61c1f75d15858341387cf32b33acab100",
    "tx_hash_hex": "0xeea2f8bd120806cc3bdd89e0640411ed04e47d11b01305059fd0948e887eaeaf"
  }
}
```

#### `AgentActivity`

*Since API 1.1.* The calling agent's own recent activity, for the agent itself (the payments service's `Activity` shows it to the user):

- `spends`: the agent's spend log entries, newest first: every signature that counts toward its limits, with `approval_request_id` set when an approved request let it go beyond them. The log keeps 8 days.
- `approvals`: the agent's manual approval requests with their `reasons`: every pending one first (newest first), then the decided ones (`approved`, `rejected`, `completed`) by last change, newest first.

`since` (optional) keeps spends at or after it and decided requests changed at or after it; pending requests are always listed. `limit` caps each list (default 50, at most 200; `0` returns empty lists). The result is strictly the authenticated agent's: another agent's spends and requests never appear. Nothing in it is secret. The request carries no timestamps, so the freshness rules do not apply and no request id is consumed.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| agent allowlist | agent token | `AgentActivity` | none | yes |

Errors: `AgentAuthenticationFailed`.

```json
{
  "method": "AgentActivity",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "limit": 20
  }
}
```

```json
{
  "type": "AgentActivity",
  "data": {
    "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
    "spends": [
      {
        "chain_id": 56,
        "asset": {
          "kind": "erc20",
          "value": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
        },
        "recipient": {
          "kind": "evm",
          "value": "0x5aeda56215b167893e80b4fe645ba6d5bab767de"
        },
        "amount_wei": "150000000000000000000",
        "at": [2026, 309, 12, 5, 0, 0, 0, 0, 0],
        "approval_request_id": "e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090"
      },
      {
        "chain_id": 56,
        "asset": {
          "kind": "erc20",
          "value": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
        },
        "recipient": {
          "kind": "evm",
          "value": "0x5aeda56215b167893e80b4fe645ba6d5bab767de"
        },
        "amount_wei": "40000000000000000000",
        "at": [2026, 309, 12, 0, 0, 0, 0, 0, 0],
        "approval_request_id": null
      }
    ],
    "approvals": [
      {
        "id": "e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090",
        "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
        "vault_key_id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
        "request_payload_hash_hex": "a2e484ad65cc73d6b3e29c747d69111704fd790c9891dce3d9b30b6fd03ece76",
        "action": {
          "kind": "Transfer",
          "chain_id": 56,
          "token": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
          "to": "0x5aeda56215b167893e80b4fe645ba6d5bab767de",
          "amount_wei": "150000000000000000000"
        },
        "chain_id": 56,
        "asset": {
          "kind": "erc20",
          "value": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
        },
        "recipient": {
          "kind": "evm",
          "value": "0x5aeda56215b167893e80b4fe645ba6d5bab767de"
        },
        "amount_wei": "150000000000000000000",
        "created_at": [2026, 309, 12, 1, 0, 0, 0, 0, 0],
        "updated_at": [2026, 309, 12, 5, 0, 0, 0, 0, 0],
        "status": "completed",
        "triggered_by_policy_ids": ["b1c2d3e4-0000-4000-8000-000000000001"],
        "reasons": [
          {
            "limit": "per_payment",
            "policy_id": "b1c2d3e4-0000-4000-8000-000000000001",
            "max": "100000000000000000000",
            "used": null,
            "requested_amount_wei": "150000000000000000000"
          }
        ],
        "completed_at": [2026, 309, 12, 5, 0, 0, 0, 0, 0],
        "rejection_reason": null
      }
    ],
    "as_of": [2026, 309, 13, 0, 0, 0, 0, 0, 0]
  }
}
```

## Errors

A failed call returns `{"ok": false, "body_json": "<WireDaemonError>"}`. The error's `kind` names are stable within a major version. New kinds may be added in minor versions, so treat an unknown `kind` as a generic failure.

| Kind | `data` | Meaning |
|---|---|---|
| `AuthenticationFailed` | none | admin proof rejected: bad challenge signature, or wrong lease secret or peer |
| `AdminAuthenticationRequired` | none | admin method from a non-root peer without a lease |
| `RootPeerRequired` | none | method reserved for root peers (`EnrollAdminCredential`) |
| `UnknownLease` | none | lease unknown, revoked, or forgotten on daemon restart |
| `InvalidLease` | none | lease expired |
| `TooManyActiveLeases` | none | 64 active leases already exist |
| `UnknownAdminCredential` | UUID | no such credential |
| `InvalidAdminCredential` | string | bad key or label, or the key is already enrolled |
| `TooManyAdminCredentials` | `{max}` | credential limit (8) reached |
| `InvalidAdminChallenge` | none | challenge unknown, expired, used, or begun by another peer |
| `InvalidAdminChallengePurpose` | string | purpose is not 1 to 128 characters of `[A-Za-z0-9._:/-]` |
| `TooManyPendingAdminChallenges` | `{max}` | too many unanswered challenges |
| `AdminCredentialLocked` | `{credential_id}` | locked for 30 s after 5 failed signatures |
| `UnknownVaultKey` | UUID | no such vault key |
| `UnknownAgentKey` | UUID | no such agent key |
| `UnknownPolicy` | UUID | no such policy |
| `UnknownManualApprovalRequest` | UUID | no such (retained) approval request |
| `AgentAuthenticationFailed` | none | unknown agent, wrong token, or a reservation owned by another agent |
| `PayloadActionMismatch` | none | `payload` is not the canonical JSON of `action` |
| `PayloadTooLarge` | `{max_bytes}` | payload over 32 KiB |
| `InvalidRequestTimestamps` | none | timestamps violate the freshness rules |
| `RequestExpired` | none | `expires_at` is in the past |
| `RequestReplayDetected` | none | `request_id` already used for a different request |
| `TooManyTrackedReplayIds` | `{max_tracked}` | replay table full; retry later |
| `InvalidPolicyAttachment` | string | empty set, disabled policy, or agent/vault mismatch |
| `InvalidNonceReservation` | string | invalid reservation request |
| `TooManyActiveNonceReservations` | `{max_active}` | too many active reservations |
| `NonceSkipTooLarge` | `{requested_skip, max_skip}` | skips more than 1024 nonces past the head |
| `UnknownNonceReservation` | UUID | no such active reservation |
| `MissingNonceReservation` | `{chain_id, nonce}` | `BroadcastTx` nonce was not reserved |
| `InvalidPolicy` | string | invalid policy, or duplicate id |
| `InvalidAction` | string | action failed validation, for example unrecognized calldata |
| `ManualApprovalRequired` | `{approval_request_id}` | held for an operator; see [Manual approval](#manual-approval) |
| `ManualApprovalRejected` | `{approval_request_id}` | an operator rejected this action |
| `ManualApprovalRequestNotPending` | `{approval_request_id, status}` | already decided or completed |
| `TooManyPendingManualApprovalRequests` | `{agent_key_id, max_pending}` | 64 pending requests for this agent |
| `WalletAlreadyExists` | `{vault_key_ids}` | `BootstrapWallet` would replace an existing wallet without `replace_existing` |
| `WalletNotFound` | none | no wallet (vault key) to reuse or back up |
| `InvalidWalletRequest` | string | ambiguous or inconsistent wallet request, for example several vault keys and no `vault_key_id` |
| `InvalidSpendingLimits` | string | a spending limit row failed validation |
| `InvalidWalletBackup` | string | not a valid backup: malformed, unsupported version or parameters, or metadata that does not match the key |
| `WalletBackupDecryptionFailed` | none | wrong passphrase or altered backup |
| `WeakBackupPassphrase` | `{min_chars}` | a new backup's passphrase has fewer than 12 characters |
| `UnknownSignedTransaction` | string (hash) | `ReleaseSignedNonce`: not signed here for the agent, already released, or older than 10 minutes |
| `Policy` | `PolicyError` | policy engine denied the request |
| `Signer` | `SignerError` | signer backend failure |
| `InvalidConfig` | string | invalid daemon configuration |
| `LockPoisoned` | none | internal failure; restart the daemon |
| `Transport` | string | internal transport or serialization failure |
| `Persistence` | string | saving state failed; the change was rolled back |

`PolicyError` is externally tagged: for example `"NoAttachedPolicies"`, `"NoApplicablePolicies"`, or `{"PerTxLimitExceeded":{"policy_id":...,"max_amount_wei":"...","requested_amount_wei":"..."}}`. *Since API 1.1.0:* `{"Permit2TypedDataDenied":{"primary_type":"..."}}` refuses `Eip712TypedData` whose domain's `verifyingContract` is the canonical Permit2, under every policy (manual approval included, and also without any `Eip712Signing` policy): such a signature can move any token the wallet approved Permit2 for, which MPP `permit2` payments leave unlimited, with no spending limit applied. Every amount, count, and limit inside it is a decimal string. `SignerError` is `{"UnknownKey":"<uuid>"}`, `"InvalidPrivateKey"`, `{"Unsupported":"..."}`, `{"PermissionDenied":"..."}`, or `{"Internal":"..."}`.

One example of every kind:

```json
[
  {"kind": "AuthenticationFailed"},
  {"kind": "AdminAuthenticationRequired"},
  {"kind": "RootPeerRequired"},
  {"kind": "UnknownLease"},
  {"kind": "InvalidLease"},
  {"kind": "TooManyActiveLeases"},
  {"kind": "UnknownAdminCredential", "data": "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b"},
  {"kind": "InvalidAdminCredential", "data": "public key is already enrolled"},
  {"kind": "TooManyAdminCredentials", "data": {"max": 8}},
  {"kind": "InvalidAdminChallenge"},
  {"kind": "InvalidAdminChallengePurpose", "data": "challenge purpose must be 1 to 128 characters of [A-Za-z0-9._:/-]"},
  {"kind": "TooManyPendingAdminChallenges", "data": {"max": 64}},
  {"kind": "AdminCredentialLocked", "data": {"credential_id": "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b"}},
  {"kind": "UnknownVaultKey", "data": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d"},
  {"kind": "UnknownAgentKey", "data": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"},
  {"kind": "UnknownPolicy", "data": "a1b2c3d4-0000-4000-8000-000000000001"},
  {"kind": "UnknownManualApprovalRequest", "data": "e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090"},
  {"kind": "AgentAuthenticationFailed"},
  {"kind": "PayloadActionMismatch"},
  {"kind": "PayloadTooLarge", "data": {"max_bytes": 32768}},
  {"kind": "InvalidRequestTimestamps"},
  {"kind": "RequestExpired"},
  {"kind": "RequestReplayDetected"},
  {"kind": "TooManyTrackedReplayIds", "data": {"max_tracked": 65536}},
  {"kind": "InvalidPolicyAttachment", "data": "policy set cannot be empty"},
  {"kind": "InvalidNonceReservation", "data": "chain_id must be greater than zero"},
  {"kind": "TooManyActiveNonceReservations", "data": {"max_active": 16384}},
  {"kind": "NonceSkipTooLarge", "data": {"requested_skip": 5000, "max_skip": 1024}},
  {"kind": "UnknownNonceReservation", "data": "7f6e5d4c-3b2a-4190-8f7e-6d5c4b3a2918"},
  {"kind": "MissingNonceReservation", "data": {"chain_id": 56, "nonce": 7}},
  {"kind": "InvalidPolicy", "data": "policy id a1b2c3d4-0000-4000-8000-000000000001 already exists"},
  {"kind": "InvalidAction", "data": "unrecognized calldata"},
  {"kind": "ManualApprovalRequired", "data": {"approval_request_id": "e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090"}},
  {"kind": "ManualApprovalRejected", "data": {"approval_request_id": "e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090"}},
  {"kind": "ManualApprovalRequestNotPending", "data": {"approval_request_id": "e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090", "status": "approved"}},
  {"kind": "TooManyPendingManualApprovalRequests", "data": {"agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d", "max_pending": 64}},
  {"kind": "WalletAlreadyExists", "data": {"vault_key_ids": ["5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d"]}},
  {"kind": "WalletNotFound"},
  {"kind": "InvalidWalletRequest", "data": "the daemon holds 2 vault keys; pass vault_key_id"},
  {"kind": "InvalidSpendingLimits", "data": "erc20:0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d on chain 56: daily_max_wei must be at least per_tx_max_wei"},
  {"kind": "InvalidWalletBackup", "data": "wallet backup encryption parameters are unsupported"},
  {"kind": "WalletBackupDecryptionFailed"},
  {"kind": "WeakBackupPassphrase", "data": {"min_chars": 12}},
  {"kind": "UnknownSignedTransaction", "data": "0xeea2f8bd120806cc3bdd89e0640411ed04e47d11b01305059fd0948e887eaeaf"},
  {"kind": "Policy", "data": {"PerTxLimitExceeded": {"policy_id": "a1b2c3d4-0000-4000-8000-000000000001", "max_amount_wei": "100000000000000000000", "requested_amount_wei": "250000000000000000000"}}},
  {"kind": "Signer", "data": {"Unsupported": "broadcast transaction type 0x04 is unsupported for signing"}},
  {"kind": "InvalidConfig", "data": "lease_ttl must be greater than zero"},
  {"kind": "LockPoisoned"},
  {"kind": "Transport", "data": "unexpected response type"},
  {"kind": "Persistence", "data": "failed to write state file"}
]
```

## Manual approval

A request needs an operator's decision when one of these covers it and no hard limit denies it:

- a payment goes beyond a limit policy with `over_limit: "manual_approval"` (API 1.1; every [spending limit row](#spending-limits) sets it on its per-payment, daily, weekly, and daily-count limits);
- a `ManualApproval` policy;
- an `Eip712Signing` policy with `approval_type: "manual_approval"`;
- the default gate for typed data that no `Eip712Signing` policy evaluated.

All of them are collected: one request covers every rule that holds the payment, and its `triggered_by_policy_ids` and `reasons` list each one. `ExplainForAgent` reports this outcome as `{"decision": "manual_approval", "reason": [<PolicyError>, ...]}` (API 1.1; before, the first such outcome was reported as a `deny`), with `LimitApprovalRequired` for a limit, and `EvaluateForAgent` fails with the first of them.

Each entry of `reasons` (`ApprovalReason`) is `{"limit", "policy_id", "max", "used", "requested_amount_wei"}`: `limit` is `per_payment`, `daily`, `weekly`, `daily_count`, `policy` (a `ManualApproval` policy), or `eip712`; `max` is the limit and `used` what the window had already used before this payment, both in base units except for `daily_count`, where they count transactions; `requested_amount_wei` is the payment's amount. Fields that do not apply are `null`. Requests stored before API 1.1 have `reasons: []`.

The flow then runs as follows:

1. `SignForAgent` fails with `ManualApprovalRequired {approval_request_id}`. Nothing is signed or spent, and `request_id` is **not** consumed. The daemon reuses an existing request when the same agent sends the same payload bytes (matched by SHA-256) for the same set of triggering policies.
2. An operator finds it with `ListManualApprovalRequests` (`status: "pending"`). The operator approves or rejects it with `DecideManualApprovalRequest`, usually with a Touch ID lease or `sudo`.
3. The agent **resends the same action**. It may use a new `request_id` and fresh timestamps, but the payload bytes must be identical.
   - If the request was approved, the daemon signs, and the request becomes `completed`. The payment is evaluated again first: the approval applies when the same policies hold it. If the set changed meanwhile (a window rolled over, the limits were edited), the payment is signed when nothing holds it any more, and otherwise needs a new approval.
   - If it was rejected, the call fails with `ManualApprovalRejected`.
   - If it is still pending, the call fails with `ManualApprovalRequired` again; poll with backoff.

Pending and approved requests expire after 24 hours. Decided requests are kept for 8 days and then removed. Each agent may hold at most 64 pending requests (`TooManyPendingManualApprovalRequests`). Solana transfers need a durable nonce account (`durable_nonce_account`) to be eligible for approval, because a recent blockhash would expire while waiting. A `SolanaPaymentTransaction` has no durable nonce (the payee verifies its exact instruction list) and may still wait for approval; its transaction only lands when the approval arrives before the payee's recent blockhash expires (about a minute).

## Payments service

`agentpay-paymentd` runs as an unprivileged service account: `_agentpay` on macOS, `agentpay` on Linux, created by `agentpay-setup`. It refuses to run as root. It does the network work (chain RPC, x402, MPP, funding) and asks the signer daemon for every signature as the calling agent, so the signer daemon's policies apply to everything it does. It stores no keys and no tokens (only a running [paying proxy](#local-paying-proxy) keeps its starting agent's token, in memory).

### Transport

| Property | Value |
|---|---|
| Socket (macOS) | `/Library/AgentPay/run/paymentd/paymentd.sock` |
| Socket (Linux) | `/run/agentpay-paymentd/paymentd.sock` |
| Socket (development) | `$AGENTPAY_HOME/paymentd.sock`, else `~/.agentpay/paymentd.sock`, or `--socket` |
| Owner | the service account (its uid is `service_uid` in the install record `install.json`) |
| Peers | one allowlist, `--allow-client-euid` (the installing user); no root default |
| Framing, limits, timeouts, one request per connection | as for the signer daemon ([Transport](#transport)) |
| Request / response / error | `PaymentsRpcRequest` / `PaymentsRpcResponse` / `WirePaymentsError` |

A client verifies the payments socket like the signer daemon's, with the service account in place of root: the socket must belong to the service uid, every directory from `/` down to it must be owned by root or the service uid and not be group- or world-writable, and after connecting the peer euid must be the service uid. (`agentpay_transport::assert_service_socket_path` implements the path check.)

Calls that wait for a manual approval keep the connection open while they wait. Use a response timeout longer than the wait you ask for.

### Payments service authentication

Every method except `Hello` and the read-only [`LookupToken`](#lookuptoken) carries `auth`: `{"agent_key_id": ..., "agent_auth_token": ...}`, the same credentials agents use with the signer daemon.

1. paymentd decodes the request and checks the peer euid against its client allowlist.
2. It calls the signer daemon's [`AuthenticateAgent`](#authenticateagent) with the caller's credentials, over the root-owned signer socket, after checking that socket and pinning the peer euid to `0`. The signer daemon accepts the call only because the service account's uid is on its agent allowlist (`--allow-agent-euid`), which `agentpay-setup` configures. It is not on the admin allowlist.
3. If the signer daemon accepts the credentials, the request reaches its feature handler with the agent's identity and addresses. Otherwise the call fails with `AgentAuthenticationFailed` (bad credentials) or `SignerUnavailable` (no answer).
4. Every signer daemon call the handler makes (`ReserveNonce`, `SignForAgent`, ...) carries the same credentials, so the agent's own policies, limits, and manual approvals apply.

Nothing is cached: a rotated or revoked token stops working on the next request. The credentials live only as long as the request and are wiped afterwards; paymentd never logs them.

### Configuration

The payments configuration (chains, tokens, RPC URLs, and the default network and asset, `bsc` and `usd1`) belongs to the payments service. It lives in the service's state directory, `config.json` with mode `0600`: `/var/db/agentpay-paymentd` on macOS, `/var/lib/agentpay-paymentd` on Linux, or `$AGENTPAY_HOME/paymentd` in development. paymentd refuses a file that is a symlink, belongs to another uid, or is readable by group or others. Clients read and replace the configuration with `GetConfig` and `SetConfig`, or add one token with `AddToken`; they never edit the file. Until the first change, the service serves the built-in default shown in the `GetConfig` example. The validation rules are documented on `agentpay_api::payments::config`.

**RPC endpoints and backups.** Each chain has an `rpc_url` and, since API 1.1, up to 4 `fallback_rpc_urls` (always present in responses, `[]` when none; optional in `SetConfig` requests). When paymentd connects to a chain it tries `rpc_url`, then each backup in order; the endpoint must pass the usual check (EVM `eth_chainId` equals the configured id, Solana genesis hash matches the cluster). A backup that answered stays preferred for 10 minutes, then `rpc_url` is tried first again. With backups configured, each connection attempt is capped at 3 seconds so a hanging endpoint leaves time for the next. Failover happens only while connecting: every later request of the call, a transaction send included, goes to that one endpoint, so a send is never repeated across endpoints. If every endpoint fails, the error is `rpc_url`'s, with `(N backup RPCs also failed)` appended. `Status` reports `using_backup_rpc` per chain. URLs are never logged, reported in `Status`, or quoted in errors, because they may embed API keys.

**Retired defaults.** When paymentd loads a stored configuration in which a built-in chain still uses a retired built-in default (`https://bsc.drpc.org`, `https://eth.llamarpc.com`, `https://rpc.presto.tempo.xyz`) and has no backups, it switches that chain to the current default endpoints and rewrites `config.json`. URLs an operator chose are never changed.

**New built-in networks.** When a release adds networks to the built-in default (Arbitrum, Arbitrum Sepolia, Base, Base Sepolia, Optimism, and Polygon were added after the first configurations were stored), paymentd adds each one to a stored configuration when it loads it, with the built-in token deployments on that network (for example USDC, ETH, and POL), and rewrites `config.json`. A network is not added when the configuration already has a chain under its key or with its chain id, and `config.json` records which built-in networks it has been offered, so a network removed with `SetConfig` stays removed. Existing chains, RPC URLs, tokens, and deployments are never changed.

### Payments methods

#### `Hello` (payments)

Returns the API version, the service release, and the capabilities: every payments method name plus `amounts.decimal_string`.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | none | `Hello` | none | yes |

```json
{
  "method": "Hello"
}
```

```json
{
  "type": "Hello",
  "data": {
    "api_version": "1.1.0",
    "daemon_version": "1.0.0",
    "capabilities": ["Hello", "GetConfig", "SetConfig", "TransferSol", "TransferSpl", "Transfer", "TransferNative", "Approve", "Broadcast", "SignTypedData", "ResumeApproved", "RpcChainInfo", "RpcBlockNumber", "RpcBalance", "RpcNonce", "RpcFees", "RpcGasEstimate", "RpcTx", "RpcReceipt", "RpcCode", "X402Fetch", "MppFetch", "ProxyStart", "ProxyStop", "ProxyStatus", "WalletSummary", "WalletBalance", "FundingRequest", "Status", "TelemetryStatus", "SetTelemetry", "AddToken", "LookupToken", "Activity", "amounts.decimal_string", "mpp.evm_charge", "mpp.solana_charge"]
  }
}
```

#### `GetConfig`

Returns the configuration.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `Config` | none | yes |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`.

```json
{
  "method": "GetConfig",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    }
  }
}
```

```json
{
  "type": "Config",
  "data": {
    "default_network": "bsc",
    "default_asset": "usd1",
    "chains": {
      "arbitrum": {
        "chain_id": 42161,
        "name": "Arbitrum",
        "family": "evm",
        "rpc_url": "https://arbitrum-one-rpc.publicnode.com",
        "fallback_rpc_urls": [
          "https://arb1.arbitrum.io/rpc",
          "https://arbitrum.drpc.org"
        ]
      },
      "arbitrum-sepolia": {
        "chain_id": 421614,
        "name": "Arbitrum Sepolia",
        "family": "evm",
        "rpc_url": "https://sepolia-rollup.arbitrum.io/rpc",
        "fallback_rpc_urls": [
          "https://arbitrum-sepolia-rpc.publicnode.com",
          "https://arbitrum-sepolia.drpc.org"
        ]
      },
      "base": {
        "chain_id": 8453,
        "name": "Base",
        "family": "evm",
        "rpc_url": "https://base-rpc.publicnode.com",
        "fallback_rpc_urls": [
          "https://mainnet.base.org",
          "https://base.drpc.org"
        ]
      },
      "base-sepolia": {
        "chain_id": 84532,
        "name": "Base Sepolia",
        "family": "evm",
        "rpc_url": "https://base-sepolia-rpc.publicnode.com",
        "fallback_rpc_urls": [
          "https://sepolia.base.org",
          "https://base-sepolia.drpc.org"
        ]
      },
      "bsc": {
        "chain_id": 56,
        "name": "BSC",
        "family": "evm",
        "rpc_url": "https://bsc-rpc.publicnode.com",
        "fallback_rpc_urls": [
          "https://1rpc.io/bnb",
          "https://bsc-dataseed.bnbchain.org"
        ]
      },
      "eth": {
        "chain_id": 1,
        "name": "ETH",
        "family": "evm",
        "rpc_url": "https://ethereum-rpc.publicnode.com",
        "fallback_rpc_urls": [
          "https://1rpc.io/eth",
          "https://eth.drpc.org"
        ]
      },
      "optimism": {
        "chain_id": 10,
        "name": "Optimism",
        "family": "evm",
        "rpc_url": "https://optimism-rpc.publicnode.com",
        "fallback_rpc_urls": [
          "https://mainnet.optimism.io",
          "https://1rpc.io/op"
        ]
      },
      "polygon": {
        "chain_id": 137,
        "name": "Polygon",
        "family": "evm",
        "rpc_url": "https://polygon-bor-rpc.publicnode.com",
        "fallback_rpc_urls": [
          "https://1rpc.io/matic",
          "https://polygon.drpc.org"
        ]
      },
      "solana-devnet": {
        "chain_id": 900000002,
        "name": "Solana Devnet",
        "family": "solana",
        "rpc_url": "https://api.devnet.solana.com",
        "fallback_rpc_urls": []
      },
      "solana-mainnet": {
        "chain_id": 900000001,
        "name": "Solana",
        "family": "solana",
        "rpc_url": "https://api.mainnet-beta.solana.com",
        "fallback_rpc_urls": [
          "https://solana-rpc.publicnode.com"
        ]
      },
      "solana-testnet": {
        "chain_id": 900000003,
        "name": "Solana Testnet",
        "family": "solana",
        "rpc_url": "https://api.testnet.solana.com",
        "fallback_rpc_urls": []
      },
      "tempo": {
        "chain_id": 4217,
        "name": "Tempo",
        "family": "evm",
        "rpc_url": "https://rpc.tempo.xyz",
        "fallback_rpc_urls": [
          "https://tempo-mainnet.drpc.org"
        ]
      },
      "tempo-testnet": {
        "chain_id": 42431,
        "name": "Tempo Testnet (Moderato)",
        "family": "evm",
        "rpc_url": "https://rpc.moderato.tempo.xyz",
        "fallback_rpc_urls": []
      }
    },
    "tokens": {
      "bnb": {
        "name": "BNB",
        "symbol": "BNB",
        "recommended_limits": {
          "per_tx": "0.01",
          "daily": "0.2",
          "weekly": "1.4"
        },
        "chains": {
          "bsc": {
            "chain_id": 56,
            "is_native": true,
            "address": null,
            "decimals": 18
          }
        }
      },
      "eth": {
        "name": "ETH",
        "symbol": "ETH",
        "recommended_limits": null,
        "chains": {
          "arbitrum": {
            "chain_id": 42161,
            "is_native": true,
            "address": null,
            "decimals": 18
          },
          "arbitrum-sepolia": {
            "chain_id": 421614,
            "is_native": true,
            "address": null,
            "decimals": 18
          },
          "base": {
            "chain_id": 8453,
            "is_native": true,
            "address": null,
            "decimals": 18
          },
          "base-sepolia": {
            "chain_id": 84532,
            "is_native": true,
            "address": null,
            "decimals": 18
          },
          "eth": {
            "chain_id": 1,
            "is_native": true,
            "address": null,
            "decimals": 18
          },
          "optimism": {
            "chain_id": 10,
            "is_native": true,
            "address": null,
            "decimals": 18
          }
        }
      },
      "pathusd": {
        "name": "PATH/USD",
        "symbol": "PATH/USD",
        "recommended_limits": {
          "per_tx": "10",
          "daily": "100",
          "weekly": "700"
        },
        "chains": {
          "tempo": {
            "chain_id": 4217,
            "is_native": false,
            "address": "0x20c0000000000000000000000000000000000000",
            "decimals": 6
          },
          "tempo-testnet": {
            "chain_id": 42431,
            "is_native": false,
            "address": "0x20c0000000000000000000000000000000000000",
            "decimals": 6
          }
        }
      },
      "pol": {
        "name": "Polygon",
        "symbol": "POL",
        "recommended_limits": {
          "per_tx": "20",
          "daily": "400",
          "weekly": "2800"
        },
        "chains": {
          "polygon": {
            "chain_id": 137,
            "is_native": true,
            "address": null,
            "decimals": 18
          }
        }
      },
      "sol": {
        "name": "Solana",
        "symbol": "SOL",
        "recommended_limits": {
          "per_tx": "0.05",
          "daily": "1",
          "weekly": "7"
        },
        "chains": {
          "solana-devnet": {
            "chain_id": 900000002,
            "is_native": true,
            "address": null,
            "decimals": 9
          },
          "solana-mainnet": {
            "chain_id": 900000001,
            "is_native": true,
            "address": null,
            "decimals": 9
          },
          "solana-testnet": {
            "chain_id": 900000003,
            "is_native": true,
            "address": null,
            "decimals": 9
          }
        }
      },
      "usd": {
        "name": "USD",
        "symbol": "USD",
        "recommended_limits": {
          "per_tx": "10",
          "daily": "100",
          "weekly": "700"
        },
        "chains": {
          "tempo": {
            "chain_id": 4217,
            "is_native": true,
            "address": null,
            "decimals": 6
          }
        }
      },
      "usd1": {
        "name": "USD1",
        "symbol": "USD1",
        "recommended_limits": {
          "per_tx": "10",
          "daily": "100",
          "weekly": "700"
        },
        "chains": {
          "bsc": {
            "chain_id": 56,
            "is_native": false,
            "address": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
            "decimals": 18
          },
          "eth": {
            "chain_id": 1,
            "is_native": false,
            "address": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
            "decimals": 18
          },
          "solana-mainnet": {
            "chain_id": 900000001,
            "is_native": false,
            "address": "USD1ttGY1N17NEEHLmELoaybftRBUSErhqYiQzvEmuB",
            "decimals": 6
          },
          "tempo": {
            "chain_id": 4217,
            "is_native": false,
            "address": "0x20c000000000000000000000111111111e910f0f",
            "decimals": 6
          }
        }
      },
      "usdc": {
        "name": "USDC",
        "symbol": "USDC",
        "recommended_limits": {
          "per_tx": "10",
          "daily": "100",
          "weekly": "700"
        },
        "chains": {
          "arbitrum": {
            "chain_id": 42161,
            "is_native": false,
            "address": "0xaf88d065e77c8cc2239327c5edb3a432268e5831",
            "decimals": 6
          },
          "arbitrum-sepolia": {
            "chain_id": 421614,
            "is_native": false,
            "address": "0x75faf114eafb1bdbe2f0316df893fd58ce46aa4d",
            "decimals": 6
          },
          "base": {
            "chain_id": 8453,
            "is_native": false,
            "address": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            "decimals": 6
          },
          "base-sepolia": {
            "chain_id": 84532,
            "is_native": false,
            "address": "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
            "decimals": 6
          },
          "bsc": {
            "chain_id": 56,
            "is_native": false,
            "address": "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
            "decimals": 18
          },
          "eth": {
            "chain_id": 1,
            "is_native": false,
            "address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "decimals": 6
          },
          "optimism": {
            "chain_id": 10,
            "is_native": false,
            "address": "0x0b2c639c533813f4aa9d7837caf62653d097ff85",
            "decimals": 6
          },
          "polygon": {
            "chain_id": 137,
            "is_native": false,
            "address": "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
            "decimals": 6
          },
          "solana-devnet": {
            "chain_id": 900000002,
            "is_native": false,
            "address": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            "decimals": 6
          },
          "solana-mainnet": {
            "chain_id": 900000001,
            "is_native": false,
            "address": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "decimals": 6
          }
        }
      },
      "usdc.e": {
        "name": "Bridged USDC (Stargate)",
        "symbol": "USDC.e",
        "recommended_limits": {
          "per_tx": "10",
          "daily": "100",
          "weekly": "700"
        },
        "chains": {
          "tempo": {
            "chain_id": 4217,
            "is_native": false,
            "address": "0x20c000000000000000000000b9537d11c60e8b50",
            "decimals": 6
          },
          "tempo-testnet": {
            "chain_id": 42431,
            "is_native": false,
            "address": "0x20c0000000000000000000009e8d7eb59b783726",
            "decimals": 6
          }
        }
      }
    }
  }
}
```

#### `SetConfig`

Validates and replaces the whole configuration, then returns what was stored (EVM addresses in lower case). To change one entry, edit the result of `GetConfig` and send it back. An invalid configuration is rejected and nothing changes. Changing an RPC URL changes where the service reads balances and nonces and where it broadcasts. It never changes what the signer daemon's policies allow.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `Config` | atomically rewrites `config.json` | yes |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`, `InvalidConfig`, `Persistence`.

```json
{
  "method": "SetConfig",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "config": {
      "default_network": "bsc",
      "default_asset": "usd1",
      "chains": {
        "bsc": {
          "chain_id": 56,
          "name": "BSC",
          "family": "evm",
          "rpc_url": "https://bsc-rpc.publicnode.com",
          "fallback_rpc_urls": [
            "https://1rpc.io/bnb"
          ]
        }
      },
      "tokens": {
        "usd1": {
          "name": "USD1",
          "symbol": "USD1",
          "recommended_limits": {
            "per_tx": "10",
            "daily": "100",
            "weekly": "700"
          },
          "chains": {
            "bsc": {
              "chain_id": 56,
              "is_native": false,
              "address": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
              "decimals": 18
            }
          }
        }
      }
    }
  }
}
```

```json
{
  "type": "Config",
  "data": {
    "default_network": "bsc",
    "default_asset": "usd1",
    "chains": {
      "bsc": {
        "chain_id": 56,
        "name": "BSC",
        "family": "evm",
        "rpc_url": "https://bsc-rpc.publicnode.com",
        "fallback_rpc_urls": [
          "https://1rpc.io/bnb"
        ]
      }
    },
    "tokens": {
      "usd1": {
        "name": "USD1",
        "symbol": "USD1",
        "recommended_limits": {
          "per_tx": "10",
          "daily": "100",
          "weekly": "700"
        },
        "chains": {
          "bsc": {
            "chain_id": 56,
            "is_native": false,
            "address": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
            "decimals": 18
          }
        }
      }
    }
  }
}
```

#### `AddToken`

*Since API 1.1.0 (capability `AddToken`).* Adds one ERC-20 token or SPL mint to the configuration, with its decimals (and on EVM chains its symbol) read from the chain, so a client can add a token by network and address without chain I/O of its own. Returns the token entry and the stored configuration. Adding a token never changes what the signer daemon's policies allow.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `TokenAdded` | reads the chain; atomically rewrites `config.json` unless the token is already configured | yes |

Params: `network` (a configured chain key, case-insensitive), `address` (EVM: `0x` + 40 hex characters, mixed case only with a valid checksum, stored lower case; Solana: a base58 mint), optional `symbol` (1 to 32 characters) and `decimals` (at most 36).

1. Native coins are refused (the zero address, `0xeeee...eeee`, the system program). On a Solana chain `symbol` is required, because SPL mints have no on-chain symbol; this is checked before any chain I/O.
2. If a token already has a deployment on `network` at `address`, it is returned unchanged with `added: false` and `verified_on_chain: false`, without reading the chain; `symbol` and `decimals` are ignored.
3. The chain is read through the network's `rpc_url`. EVM: the endpoint's chain id must match, the address must hold contract code, then `decimals()` and (unless `symbol` is given) `symbol()` are called. Solana: the endpoint must serve the configured cluster, and the mint must exist, belong to the SPL Token or Token-2022 program, and have no transfer hook.
4. Decimals are the chain's; a `decimals` that differs is refused. If the chain cannot be read (no `rpc_url`, endpoint unreachable or serving another chain, `decimals()` failing), the given `decimals` is stored unverified (`verified_on_chain: false`); without one the call fails with `ChainRpc`, whose message names `agentpay config set chains.<network>.rpc_url <url>` and passing `decimals`.
5. The symbol is `symbol` when given, else the on-chain `symbol()`; the token's `name` is the symbol. The key is the symbol in lower case with every run of characters outside `[a-z0-9._-]` replaced by `-` (dropped at either end; `token` if nothing is left). An existing token with that key and no deployment on `network` gains the deployment; one with another deployment on `network` makes the key `<key>-<first 6 characters of the address after 0x, or of the mint>`; otherwise a new token is created without `recommended_limits`.
6. The new configuration is validated and stored exactly like `SetConfig`.

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`; `InvalidRequest` (unknown network, malformed or native address, invalid symbol or decimals, missing symbol for a Solana mint or an EVM token without `symbol()`, no contract at the address, missing or unsupported mint, `decimals` that differ from the chain's, both candidate keys taken); `ChainRpc` (chain unreadable and no `decimals`); `InvalidConfig`; `Persistence`.

```json
{
  "method": "AddToken",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "network": "bsc",
    "address": "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d"
  }
}
```

```json
{
  "type": "TokenAdded",
  "data": {
    "key": "usdc",
    "token": {
      "name": "USDC",
      "symbol": "USDC",
      "recommended_limits": null,
      "chains": {
        "bsc": {
          "chain_id": 56,
          "is_native": false,
          "address": "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
          "decimals": 18
        }
      }
    },
    "network": "bsc",
    "deployment": {
      "chain_id": 56,
      "is_native": false,
      "address": "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
      "decimals": 18
    },
    "verified_on_chain": true,
    "added": true,
    "config": {
      "default_network": "bsc",
      "default_asset": "usd1",
      "chains": {
        "bsc": {
          "chain_id": 56,
          "name": "BSC",
          "family": "evm",
          "rpc_url": "https://bsc-rpc.publicnode.com",
          "fallback_rpc_urls": [
            "https://1rpc.io/bnb"
          ]
        }
      },
      "tokens": {
        "usd1": {
          "name": "USD1",
          "symbol": "USD1",
          "recommended_limits": {
            "per_tx": "10",
            "daily": "100",
            "weekly": "700"
          },
          "chains": {
            "bsc": {
              "chain_id": 56,
              "is_native": false,
              "address": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
              "decimals": 18
            }
          }
        },
        "usdc": {
          "name": "USDC",
          "symbol": "USDC",
          "recommended_limits": null,
          "chains": {
            "bsc": {
              "chain_id": 56,
              "is_native": false,
              "address": "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
              "decimals": 18
            }
          }
        }
      }
    }
  }
}
```

#### `LookupToken`

*Since API 1.1.0 (capability `LookupToken`).* Reads an ERC-20 token's or SPL mint's metadata from the chain **without agent credentials and without changing anything**, so a client can verify a token before agent credentials exist (for example while setting spending limits during setup). It is the read and validation half of [`AddToken`](#addtoken): the same rules for `network`, `address` (native coins refused), `symbol`, `decimals`, the EVM contract-code check, and an unreadable chain (given `decimals` are returned unverified; without them the call fails with `ChainRpc` and the same guidance). It never answers from the configuration: a configured token is read from the chain too.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | none | `TokenInfo` | none (reads the chain; never changes the configuration) | yes |

Why no credentials are needed: it reads only public chain data, only through the endpoints the configuration already names (`rpc_url` and `fallback_rpc_urls`, never a URL from the request), stores nothing, signs nothing, and never calls the signer daemon. The socket still admits only peers on the client allowlist. `address` in the response is normalized the way the configuration stores it (EVM lower case).

Errors: `InvalidRequest`, `ChainRpc` (as for `AddToken`).

```json
{
  "method": "LookupToken",
  "params": {
    "network": "bsc",
    "address": "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d"
  }
}
```

```json
{
  "type": "TokenInfo",
  "data": {
    "network": "bsc",
    "chain_id": 56,
    "address": "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
    "symbol": "USDC",
    "decimals": 18,
    "verified_on_chain": true
  }
}
```

#### `TransferSol`

Sends native SOL from the agent's Solana wallet (`AgentIdentity.solana_address`), which is the fee payer and only signer. The amount is `{"base_units": "<lamports>"}` or `{"decimal": "<SOL>"}` (at most 9 decimals). `network` must name a configured chain with `family: "solana"`.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `SolanaTransfer` or `ManualApprovalPending` | one policy-checked signature; with `broadcast`, a transaction on chain; may first create the managed nonce account | no (resending while an approval is pending resumes it) |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer` (policy denial, rejected approval, ...), `InvalidRequest`, `ChainRpc`, `SignedTransactionMismatch`, `Persistence`.

The service:

1. checks once per RPC URL that the endpoint serves the cluster of the chain id (its genesis hash; loopback URLs, which run local validators, are not checked);
2. picks the transaction's blockhash from `options.nonce`: `"auto"` (default) uses the **managed durable nonce account** when broadcasting and a recent blockhash when only signing; `"recent_blockhash"`; `"managed"`; or `{"account": "<address>"}`, an existing nonce account whose authority is the wallet. The managed account is derived from the wallet with the seed `agentpay-<chain_id>-nonce` and, when missing, created first through the signer daemon's `SolanaNonceAccountCreate` action (wallet maintenance, about 0.0015 SOL of rent, outside spending policies), then confirmed. Transactions that use the same nonce account are serialized;
3. sets the compute budget: `compute_unit_limit` (default 5,000) and `compute_unit_price_micro_lamports` (default: the median of recent non-zero prioritization fees). Priority fees are capped at 10,000,000 micro-lamports per unit and 0.01 SOL per transaction: an explicit price above the caps is refused, an estimate is clamped;
4. asks the signer daemon to sign a `SolanaSolTransfer` action as the agent;
5. decodes the signed transaction and verifies it against the request: one signer (the wallet) with a valid signature, the blockhash or nonce, the nonce advance as first instruction, the compute budget, exactly one transfer with the expected recipient and amount, no other program, fees within the caps. A mismatch fails with `SignedTransactionMismatch`, and nothing is returned or sent;
6. with `broadcast`, sends it and, unless `wait_for_confirmation` is `false`, polls its status for up to 30 seconds. `broadcast.status` is `submitted`, `confirmed`, `finalized`, `failed` (with `error`), or `timed_out`.

`raw_tx_base64` (bincode, base64) is returned when not broadcasting, or with `reveal_raw_tx`. Only durable nonce transfers can wait for an operator (see [Manual approval in payment flows](#manual-approval-in-payment-flows)).

```json
{
  "method": "TransferSol",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "network": "solana-devnet",
    "to": "3D34zRx4vQzu1hMJsk9kMSduU6pNwDeSxEg95DMNMZGG",
    "amount": {"decimal": "0.0015"},
    "options": {
      "broadcast": true,
      "wait_for_confirmation": true,
      "nonce": "auto",
      "approval_wait_secs": 60,
      "reveal_raw_tx": false
    }
  }
}
```

```json
{
  "type": "SolanaTransfer",
  "data": {
    "network": "solana-devnet",
    "chain_id": 900000002,
    "fee_payer": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
    "transfer": {
      "kind": "sol",
      "to": "3D34zRx4vQzu1hMJsk9kMSduU6pNwDeSxEg95DMNMZGG",
      "amount_wei": "1500000"
    },
    "recent_blockhash": "GX3RiF2msGtyjBWRjFaZasYoVWnnpRvqzTDtwcdjXbd1",
    "durable_nonce": {
      "account": "GFB4F5gNLxVxShmbud4BpcYBuH2h6fbzu8TcDhUt5gna",
      "managed": true,
      "created_signature": "4C5GRqZ4Xmqwvc2tnwAmwVGPRWoczV8G4A5U3aD8TCGpAPxKw1KFfrCAKr3LPbgLku28ZHWqiS3BH5akj8rvTqVW"
    },
    "compute_unit_limit": 5000,
    "compute_unit_price_micro_lamports": 2000,
    "signature": "59Q8GrLkSFXeiZBppEJqVpVEsgiCMMH8foHRybR49ZYv5oSVxcsddszwxxrcDm9cyBWnRQ8u8tB67fMQgYesgJMg",
    "broadcast": {
      "status": "confirmed",
      "slot": 412345678
    }
  }
}
```

#### `TransferSpl`

Sends SPL Token or Token-2022 tokens from the wallet's associated token account for `mint` to the associated token account of `to`. The token program and decimals come from the mint on chain; `decimal` amounts may have at most the mint's decimals. Otherwise it works like [`TransferSol`](#transfersol) (default compute unit limit 20,000).

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `SolanaTransfer` or `ManualApprovalPending` | one policy-checked signature; with `broadcast`, a transaction on chain; may first create the managed nonce account | no (resending while an approval is pending resumes it) |

Errors: as for `TransferSol`.

- Both associated token accounts must exist and belong to the mint's token program. The signed transaction never creates accounts, so a missing one fails with `InvalidRequest` before anything is signed; create the recipient's account first.
- Token-2022 mints with a transfer hook are refused. For a mint with a transfer fee configuration the service computes the fee for the current epoch and signs `transfer_checked_with_fee`; the recipient receives `amount_wei - transfer_fee_wei`. Otherwise it signs `transfer_checked`.
- Verification also checks the token program, the source and destination accounts, the mint, the decimals, the transfer fee, and that the transfer has no extra signers.

```json
{
  "method": "TransferSpl",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "network": "solana",
    "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "to": "3D34zRx4vQzu1hMJsk9kMSduU6pNwDeSxEg95DMNMZGG",
    "amount": {"base_units": "2500000"},
    "options": {
      "broadcast": true,
      "wait_for_confirmation": false,
      "nonce": {"account": "HNttzqyo9wN9AEjVbStaouHXc3LRsfnVpyze4arAVN3B"},
      "compute_unit_limit": 30000,
      "compute_unit_price_micro_lamports": 5000,
      "reveal_raw_tx": false
    }
  }
}
```

```json
{
  "type": "SolanaTransfer",
  "data": {
    "network": "solana",
    "chain_id": 900000001,
    "fee_payer": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
    "transfer": {
      "kind": "spl",
      "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      "recipient_owner": "3D34zRx4vQzu1hMJsk9kMSduU6pNwDeSxEg95DMNMZGG",
      "source_token_account": "F4YA4H7HeXLCvjLRKdh56FgE4cyHpPqLP1VCM6fEqEmX",
      "destination_token_account": "H7U1xjt75A8UGZPvreRaAFaUCRb1kB93WX3pARfcHQQC",
      "token_program": "token",
      "decimals": 6,
      "amount_wei": "2500000"
    },
    "recent_blockhash": "2GacFrCmYvGb6juhAXp2Tt4otSJrtzrbGTtpb4k1nUGe",
    "durable_nonce": {
      "account": "HNttzqyo9wN9AEjVbStaouHXc3LRsfnVpyze4arAVN3B",
      "managed": false
    },
    "compute_unit_limit": 30000,
    "compute_unit_price_micro_lamports": 5000,
    "signature": "2iFVmhjdYvV7ABLGiXcrGXAofEKwUHZc82w7vdg3kDeeezKUMxoAG3HZ8hfnKhiZ1NdzgsN5b5EiTkn9nA6mdEaG",
    "broadcast": {
      "status": "submitted"
    }
  }
}
```

#### EVM payments: shared rules

`Transfer`, `TransferNative`, `Approve`, `Broadcast`, `SignTypedData`, `ResumeApproved`, and the `Rpc*` read helpers work on the configured EVM chains (`family: "evm"`).

**Network and asset.** `network` is a chain key (`"bsc"`, `"eth"`, ...) and `asset` a token key (`"usd1"`) or an ERC-20 contract address. When omitted, `network` is the configuration's `default_network` and `asset` its `default_asset`, so a bare `Transfer` pays **USD1 on BSC** with the built-in configuration. Network calls need the chain's `rpc_url`.

**Amounts.** `amount` is a positive decimal string in whole units (`"1.5"`) with at most as many fractional digits as the asset has decimals. Decimals come from the configuration; for an unconfigured ERC-20 contract the service reads `decimals()` and `symbol()` from the chain. A native coin without a configured deployment uses 18 decimals. Raw values (`*_wei`) are decimal strings in base units.

**Sign only or send.**

| Method | `broadcast: false` (default) | `broadcast: true` |
|---|---|---|
| `Transfer`, `TransferNative`, `Approve` | the signer daemon signs the typed action (`Transfer`, `TransferNative`, `Approve`) and the call returns `EvmSignature`; no transaction is built and, for configured assets, no RPC call is made | the service builds an EIP-1559 transaction, has it signed as a `BroadcastTx`, verifies and sends it, and returns `EvmTransaction` |
| `Broadcast` | the transaction is built, signed, and verified but not sent; `raw_tx_hex` can be sent later | as above |

Policies apply either way, and a signature counts toward spending limits whether or not it is ever sent.

**Transaction options** (flattened into `params`; the nonce, gas, fee, and receipt options need `broadcast: true` on the transfer methods):

| Field | Default | Meaning |
|---|---|---|
| `broadcast` | `false` | send the transaction |
| `wait_for_receipt` | `false` | after sending, poll for the receipt every 2 s |
| `receipt_timeout_secs` | 30 (capped at 120) | how long to poll; `receipt_timed_out: true` when it ran out (the transaction may still be mined) |
| `nonce` | pending nonce | an exact nonce; the signer daemon must be able to reserve exactly it |
| `gas_limit` | `eth_estimateGas` | gas limit |
| `max_fee_per_gas_wei`, `max_priority_fee_per_gas_wei` | estimated | EIP-1559 fees; the estimate uses `eth_feeHistory`, or `eth_gasPrice` for both on chains without base fees |
| `approval_wait_secs` | 0 (capped at 600) | how long to wait for an operator before returning `ManualApprovalPending` |

**The transaction pipeline.**

1. Connect to the chain's `rpc_url` (`https`, or `http` to loopback, without credentials; no redirects; 30 s timeout) and require `eth_chainId` to equal the configured `chain_id`. Otherwise the call fails with `ChainRpc` before anything is reserved or signed.
2. Reserve the nonce with the signer daemon (`ReserveNonce`: exactly the given `nonce`, or the lowest free nonce at or above the pending nonce).
3. Sign the `BroadcastTx` through `SignForAgent` as the calling agent. If nothing is signed (policy denial, pending approval, outage), the reservation is released.
4. Verify the signed transaction before it is returned or sent: it must decode exactly as an EIP-1559 envelope whose recovered signer is the agent's wallet, whose chain id, nonce, recipient, value, calldata, gas limit, and fees equal the request, whose access list is empty, and whose hash is the one the signer daemon reported. Otherwise the call fails with `SignedTransactionMismatch` and nothing is sent.
5. Send it once with `eth_sendRawTransaction` (never retried; a node answer of "already known" counts as sent), then optionally wait for the receipt. A failed receipt lookup after a successful send is reported as `receipt_timed_out`, never as an error.

Signing consumes the nonce. When the signed transaction certainly never reached the network (step 4 failed, the node answered the send with a JSON-RPC error, or the connection to the node could not be established), the service returns the nonce to the signer daemon with [`ReleaseSignedNonce`](#releasesignednonce), so the next payment uses it instead of waiting behind a gap. After an ambiguous failure (a timeout, a dropped connection, an HTTP error from a proxy) the node may have the transaction, so the nonce stays used. Either way the payment counts toward the spending limits.

**Manual approval.** When a policy holds the signature for an operator and `approval_wait_secs` runs out, the EVM methods **return** `ManualApprovalPending` (a result, not an error): `approval_request_id`, the method, network, payment, and the exact `action` waiting for approval. The service stores that action (`evm-pending/<approval id>.json`, mode `0600`, in its state directory) and releases the nonce reservation. After the operator decides, call `ResumeApproved`: it resends the identical action, so the approval applies; see [`ResumeApproved`](#resumeapproved).

#### `Transfer`

Sends ERC-20 tokens: calldata `transfer(to, amount)` to the token contract, with zero value. The asset must be an ERC-20 deployment on the network; use `TransferNative` for the native coin.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `EvmSignature`, `EvmTransaction`, or `ManualApprovalPending` | one policy-checked signature (spend recorded); with `broadcast`, a nonce reservation and a transaction on chain; a pending-approval record while held | no |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer` (policy denial, rejected approval, ...), `InvalidRequest`, `ChainRpc`, `SignedTransactionMismatch`, `Persistence`.

This example sends 1 USD1 on BSC and waits for the receipt. The signed transaction is the one in the [`SignForAgent`](#signforagent) example: nonce 7 from the chain, gas and fees estimated.

```json
{
  "method": "Transfer",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "network": "bsc",
    "asset": "usd1",
    "to": "0x5aeda56215b167893e80b4fe645ba6d5bab767de",
    "amount": "1",
    "broadcast": true,
    "wait_for_receipt": true
  }
}
```

```json
{
  "type": "EvmTransaction",
  "data": {
    "network": "bsc",
    "chain_id": 56,
    "payment": {
      "asset": {
        "key": "usd1",
        "symbol": "USD1",
        "decimals": 18,
        "token": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
      },
      "counterparty": "0x5aeda56215b167893e80b4fe645ba6d5bab767de",
      "amount": "1",
      "amount_wei": "1000000000000000000"
    },
    "from": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
    "to": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
    "value_wei": "0",
    "data_hex": "0xa9059cbb0000000000000000000000005aeda56215b167893e80b4fe645ba6d5bab767de0000000000000000000000000000000000000000000000000de0b6b3a7640000",
    "nonce": 7,
    "gas_limit": 60000,
    "max_fee_per_gas_wei": "1000000000",
    "max_priority_fee_per_gas_wei": "1000000000",
    "tx_hash": "0xeea2f8bd120806cc3bdd89e0640411ed04e47d11b01305059fd0948e887eaeaf",
    "raw_tx_hex": "0x02f8af3807843b9aca00843b9aca0082ea60948d0d000ee44948fc98c9b98a4fa4921476f08b0d80b844a9059cbb0000000000000000000000005aeda56215b167893e80b4fe645ba6d5bab767de0000000000000000000000000000000000000000000000000de0b6b3a7640000c080a0d0e3a88c04140e5f52247c5ae17d8964eb82e8566a450fe97a657cfc3afcdba0a075a5376da7b840687cb889dc62816ae61c1f75d15858341387cf32b33acab100",
    "broadcast": true,
    "receipt": {
      "tx_hash": "0xeea2f8bd120806cc3bdd89e0640411ed04e47d11b01305059fd0948e887eaeaf",
      "success": true,
      "block_number": 45000123,
      "block_hash": "0x5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b",
      "gas_used": 34512,
      "effective_gas_price_wei": "1000000000",
      "contract_address": null
    },
    "receipt_timed_out": false
  }
}
```

#### `TransferNative`

Sends the chain's native coin (BNB, ETH, ...): `amount` to `to` with empty calldata.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `EvmSignature`, `EvmTransaction`, or `ManualApprovalPending` | one policy-checked signature (spend recorded); with `broadcast`, a nonce reservation and a transaction on chain; a pending-approval record while held | no |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer` (policy denial, rejected approval, ...), `InvalidRequest`, `ChainRpc`, `SignedTransactionMismatch`, `Persistence`.

Signed only (no `broadcast`): the signature covers the canonical JSON of the `TransferNative` action.

```json
{
  "method": "TransferNative",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "network": "bsc",
    "to": "0x5aeda56215b167893e80b4fe645ba6d5bab767de",
    "amount": "0.01",
    "broadcast": false,
    "wait_for_receipt": false
  }
}
```

```json
{
  "type": "EvmSignature",
  "data": {
    "network": "bsc",
    "chain_id": 56,
    "payment": {
      "asset": {
        "key": "bnb",
        "symbol": "BNB",
        "decimals": 18,
        "token": null
      },
      "counterparty": "0x5aeda56215b167893e80b4fe645ba6d5bab767de",
      "amount": "0.01",
      "amount_wei": "10000000000000000"
    },
    "action": {
      "kind": "TransferNative",
      "chain_id": 56,
      "to": "0x5aeda56215b167893e80b4fe645ba6d5bab767de",
      "amount_wei": "10000000000000000"
    },
    "signature_hex": "0x3045022100ec45bc19c47411c28bdb8943d47eb123593560791f14f510bf05a16a60a6a6a6022042ea02dd8828c6eb17c5110b124b0b93e9840ddddda46637f2a7f6703ef39567",
    "r_hex": null,
    "s_hex": null,
    "v": null
  }
}
```

#### `Approve`

Sets an ERC-20 allowance: calldata `approve(spender, amount)` to the token contract. Policies treat the spender as the recipient.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `EvmSignature`, `EvmTransaction`, or `ManualApprovalPending` | one policy-checked signature (spend recorded); with `broadcast`, a nonce reservation and a transaction on chain; a pending-approval record while held | no |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer` (policy denial, rejected approval, ...), `InvalidRequest`, `ChainRpc`, `SignedTransactionMismatch`, `Persistence`.

In this example a `ManualApproval` policy covers allowances above 50 USD1, so the call returns `ManualApprovalPending` with the stored transaction (nonce 8).

```json
{
  "method": "Approve",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "network": "bsc",
    "asset": "usd1",
    "spender": "0x10ed43c718714eb63d5aa57b78b54704e256024e",
    "amount": "100",
    "broadcast": true,
    "wait_for_receipt": false,
    "gas_limit": 60000,
    "max_fee_per_gas_wei": "1000000000",
    "max_priority_fee_per_gas_wei": "1000000000",
    "approval_wait_secs": 30
  }
}
```

```json
{
  "type": "ManualApprovalPending",
  "data": {
    "approval_request_id": "e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090",
    "method": "Approve",
    "network": "bsc",
    "chain_id": 56,
    "payment": {
      "asset": {
        "key": "usd1",
        "symbol": "USD1",
        "decimals": 18,
        "token": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
      },
      "counterparty": "0x10ed43c718714eb63d5aa57b78b54704e256024e",
      "amount": "100",
      "amount_wei": "100000000000000000000"
    },
    "action": {
      "kind": "BroadcastTx",
      "tx": {
        "chain_id": 56,
        "nonce": 8,
        "to": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
        "value_wei": "0",
        "data_hex": "0x095ea7b300000000000000000000000010ed43c718714eb63d5aa57b78b54704e256024e0000000000000000000000000000000000000000000000056bc75e2d63100000",
        "gas_limit": 60000,
        "max_fee_per_gas_wei": "1000000000",
        "max_priority_fee_per_gas_wei": "1000000000",
        "tx_type": 2,
        "delegation_enabled": false
      }
    }
  }
}
```

#### `Broadcast`

Signs, and with `broadcast` sends, an agent-built transaction: `to`, `value_wei` (default `"0"`), `data_hex` (default `"0x"`), and the transaction options. The signer daemon accepts empty calldata (a native transfer) or a recognized token call (ERC-20 `transfer`/`approve`, TIP-20 `transferWithMemo`, Permit2 `permit`, EIP-3009 `transferWithAuthorization`/`receiveWithAuthorization`) with zero value, and applies its policies to the decoded asset, recipient, and amount; other calldata fails with `Signer` / `InvalidAction`.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `EvmTransaction` or `ManualApprovalPending` | a nonce reservation and signature; with `broadcast`, a transaction on chain; a pending-approval record while held | no |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer` (policy denial, rejected approval, ...), `InvalidRequest`, `ChainRpc`, `SignedTransactionMismatch`, `Persistence`.

Signed with an explicit nonce, gas, and fees, but not sent:

```json
{
  "method": "Broadcast",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "network": "bsc",
    "to": "0x5aeda56215b167893e80b4fe645ba6d5bab767de",
    "value_wei": "10000000000000000",
    "data_hex": "0x",
    "broadcast": false,
    "wait_for_receipt": false,
    "nonce": 9,
    "gas_limit": 21000,
    "max_fee_per_gas_wei": "1000000000",
    "max_priority_fee_per_gas_wei": "1000000000"
  }
}
```

```json
{
  "type": "EvmTransaction",
  "data": {
    "network": "bsc",
    "chain_id": 56,
    "payment": null,
    "from": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
    "to": "0x5aeda56215b167893e80b4fe645ba6d5bab767de",
    "value_wei": "10000000000000000",
    "data_hex": "0x",
    "nonce": 9,
    "gas_limit": 21000,
    "max_fee_per_gas_wei": "1000000000",
    "max_priority_fee_per_gas_wei": "1000000000",
    "tx_hash": "0x1df188baac172aea61551550edd687ab693ca8239efb227b5287e277ab5f23b8",
    "raw_tx_hex": "0x02f8713809843b9aca00843b9aca00825208945aeda56215b167893e80b4fe645ba6d5bab767de872386f26fc1000080c080a09576686159d5823255751fdd03cf5ea440a40bd2ee0db14d60569da2107be3bea00b5fa0ae36a1b270251a0c77a0a34ed71d196c8e61c6a4bfa281d72b711c522f",
    "broadcast": false,
    "receipt": null,
    "receipt_timed_out": false
  }
}
```

#### `SignTypedData`

Signs EIP-712 typed data (`typed_data_json`, the `eth_signTypedData_v4` object as a string; `domain.chainId` is required) under the agent's policies. Typed data that no `Eip712Signing` policy covers needs manual approval. `signature_hex` is the 65-byte `r || s || v` signature with `v` = 27 or 28.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `EvmSignature` or `ManualApprovalPending` | one policy-checked signature; a pending-approval record while held | no |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`, `InvalidRequest`, `Persistence`.

```json
{
  "method": "SignTypedData",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "typed_data_json": "{\"types\":{\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"},{\"name\":\"version\",\"type\":\"string\"},{\"name\":\"chainId\",\"type\":\"uint256\"},{\"name\":\"verifyingContract\",\"type\":\"address\"}],\"Order\":[{\"name\":\"buyer\",\"type\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\"},{\"name\":\"nonce\",\"type\":\"uint256\"}]},\"primaryType\":\"Order\",\"domain\":{\"name\":\"Example Shop\",\"version\":\"1\",\"chainId\":56,\"verifyingContract\":\"0x1111111111111111111111111111111111111111\"},\"message\":{\"buyer\":\"0x2c7536e3605d9c16a7a3d7b1898e529396a65c23\",\"amount\":\"1000000000000000000\",\"nonce\":1}}",
    "approval_wait_secs": 60
  }
}
```

The signature, after an operator approved the request:

```json
{
  "type": "EvmSignature",
  "data": {
    "network": null,
    "chain_id": 56,
    "payment": null,
    "action": {
      "kind": "Eip712TypedData",
      "typed_data": {
        "typed_data_json": "{\"types\":{\"EIP712Domain\":[{\"name\":\"name\",\"type\":\"string\"},{\"name\":\"version\",\"type\":\"string\"},{\"name\":\"chainId\",\"type\":\"uint256\"},{\"name\":\"verifyingContract\",\"type\":\"address\"}],\"Order\":[{\"name\":\"buyer\",\"type\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\"},{\"name\":\"nonce\",\"type\":\"uint256\"}]},\"primaryType\":\"Order\",\"domain\":{\"name\":\"Example Shop\",\"version\":\"1\",\"chainId\":56,\"verifyingContract\":\"0x1111111111111111111111111111111111111111\"},\"message\":{\"buyer\":\"0x2c7536e3605d9c16a7a3d7b1898e529396a65c23\",\"amount\":\"1000000000000000000\",\"nonce\":1}}"
      }
    },
    "signature_hex": "0xc4a6a183d77063e829112fe80ac7178ca21c33ff6aa6082dc5891cd6d27f5fdd4ed81d33c5b0917a27f689e2e8563ebdcca38e0d9586fc48ff54be9930aee2541b",
    "r_hex": "0xc4a6a183d77063e829112fe80ac7178ca21c33ff6aa6082dc5891cd6d27f5fdd",
    "s_hex": "0x4ed81d33c5b0917a27f689e2e8563ebdcca38e0d9586fc48ff54be9930aee254",
    "v": 0
  }
}
```

#### `ResumeApproved`

Continues a call that returned `ManualApprovalPending`, after the operator decided. Only the agent that made the original call can resume it; other agents get `UnknownPendingApproval`. The service resends the stored action unchanged. For a transaction it first checks that the stored nonce is still unused on chain (otherwise `InvalidRequest`: start a new payment) and reserves exactly that nonce again, then verifies, sends, and waits as the original call asked. While the request is still pending the result is `ManualApprovalPending` again; a rejected request fails with `Signer` / `ManualApprovalRejected`. The stored record is removed once the request is settled, and kept after `SignerUnavailable`, `ChainRpc`, and `Persistence` failures so the call can be retried. `approval_wait_secs` works as for the original call.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | the original call's: `EvmSignature`, `EvmTransaction`, or `ManualApprovalPending` | as for the original call; removes the pending-approval record | no |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`, `UnknownPendingApproval`, `InvalidRequest`, `ChainRpc`, `SignedTransactionMismatch`, `Persistence`.

```json
{
  "method": "ResumeApproved",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "approval_request_id": "e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090"
  }
}
```

The approved `Approve` example, sent:

```json
{
  "type": "EvmTransaction",
  "data": {
    "network": "bsc",
    "chain_id": 56,
    "payment": {
      "asset": {
        "key": "usd1",
        "symbol": "USD1",
        "decimals": 18,
        "token": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
      },
      "counterparty": "0x10ed43c718714eb63d5aa57b78b54704e256024e",
      "amount": "100",
      "amount_wei": "100000000000000000000"
    },
    "from": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
    "to": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
    "value_wei": "0",
    "data_hex": "0x095ea7b300000000000000000000000010ed43c718714eb63d5aa57b78b54704e256024e0000000000000000000000000000000000000000000000056bc75e2d63100000",
    "nonce": 8,
    "gas_limit": 60000,
    "max_fee_per_gas_wei": "1000000000",
    "max_priority_fee_per_gas_wei": "1000000000",
    "tx_hash": "0xa754253ff3995dd1cc4c283e819319aca14e970ed168d2a451d3be3cdda9f29b",
    "raw_tx_hex": "0x02f8af3808843b9aca00843b9aca0082ea60948d0d000ee44948fc98c9b98a4fa4921476f08b0d80b844095ea7b300000000000000000000000010ed43c718714eb63d5aa57b78b54704e256024e0000000000000000000000000000000000000000000000056bc75e2d63100000c001a05555600efb706d1705ce849b90da9d2f47e2518bba42d73d7c6ccfcf0e07c913a003573f4d7bb9add59095ff5448bcb16b575e46ab24a226bd184469242619bcf5",
    "broadcast": true,
    "receipt": null,
    "receipt_timed_out": false
  }
}
```

#### EVM read helpers

`RpcChainInfo`, `RpcBlockNumber`, `RpcBalance`, `RpcNonce`, `RpcFees`, `RpcGasEstimate`, `RpcTx`, `RpcReceipt`, and `RpcCode` read an EVM chain through its configured `rpc_url` (`network`, default `default_network`) after the same chain-id check. They sign and change nothing. `address` and `from` default to the agent's wallet. `uint256` values that can exceed `u128` (balances, transaction values) are decimal strings.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | see below | none | yes |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`, `InvalidRequest`, `ChainRpc`.

| Method | Params | Response | Reads |
|---|---|---|---|
| `RpcChainInfo` | `network` | `EvmChainInfo` | `eth_chainId`, `eth_blockNumber` |
| `RpcBlockNumber` | `network` | `EvmChainInfo` | `eth_blockNumber` |
| `RpcBalance` | `network`, `address`, `asset` (default: the native coin) | `EvmBalance` | `eth_getBalance` or `balanceOf` |
| `RpcNonce` | `network`, `address` | `EvmNonce` | `eth_getTransactionCount` (pending) |
| `RpcFees` | `network` | `EvmFees` (`max_*` are `null` without base fees) | `eth_gasPrice`, `eth_feeHistory` |
| `RpcGasEstimate` | `network`, `from`, `to`, `value_wei`, `data_hex` | `EvmGasEstimate` | `eth_estimateGas` |
| `RpcTx` | `network`, `tx_hash` | `EvmTransactionLookup` (`transaction` is `null` when unknown) | `eth_getTransactionByHash` |
| `RpcReceipt` | `network`, `tx_hash` | `EvmReceiptLookup` (`receipt` is `null` while pending) | `eth_getTransactionReceipt` |
| `RpcCode` | `network`, `address` | `EvmCode` | `eth_getCode` |

`RpcChainInfo`:

```json
{
  "method": "RpcChainInfo",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "network": "bsc"
  }
}
```

```json
{
  "type": "EvmChainInfo",
  "data": {
    "network": "bsc",
    "chain_id": 56,
    "block_number": 45000123
  }
}
```

`RpcBlockNumber`:

```json
{
  "method": "RpcBlockNumber",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    }
  }
}
```

```json
{
  "type": "EvmChainInfo",
  "data": {
    "network": "bsc",
    "chain_id": 56,
    "block_number": 45000123
  }
}
```

`RpcBalance`:

```json
{
  "method": "RpcBalance",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "network": "bsc",
    "asset": "usd1"
  }
}
```

```json
{
  "type": "EvmBalance",
  "data": {
    "network": "bsc",
    "chain_id": 56,
    "address": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
    "asset": {
      "key": "usd1",
      "symbol": "USD1",
      "decimals": 18,
      "token": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
    },
    "balance_wei": "25500000000000000000",
    "balance": "25.5"
  }
}
```

`RpcNonce`:

```json
{
  "method": "RpcNonce",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "network": "bsc"
  }
}
```

```json
{
  "type": "EvmNonce",
  "data": {
    "network": "bsc",
    "chain_id": 56,
    "address": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
    "nonce": 8
  }
}
```

`RpcFees`:

```json
{
  "method": "RpcFees",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "network": "bsc"
  }
}
```

```json
{
  "type": "EvmFees",
  "data": {
    "network": "bsc",
    "chain_id": 56,
    "gas_price_wei": "1000000000",
    "max_fee_per_gas_wei": "3000000000",
    "max_priority_fee_per_gas_wei": "1000000000"
  }
}
```

`RpcGasEstimate`:

```json
{
  "method": "RpcGasEstimate",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "network": "bsc",
    "to": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
    "value_wei": "0",
    "data_hex": "0xa9059cbb0000000000000000000000005aeda56215b167893e80b4fe645ba6d5bab767de0000000000000000000000000000000000000000000000000de0b6b3a7640000"
  }
}
```

```json
{
  "type": "EvmGasEstimate",
  "data": {
    "network": "bsc",
    "chain_id": 56,
    "gas_limit": 34512
  }
}
```

`RpcTx`:

```json
{
  "method": "RpcTx",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "network": "bsc",
    "tx_hash": "0xeea2f8bd120806cc3bdd89e0640411ed04e47d11b01305059fd0948e887eaeaf"
  }
}
```

```json
{
  "type": "EvmTransactionLookup",
  "data": {
    "network": "bsc",
    "chain_id": 56,
    "transaction": {
      "tx_hash": "0xeea2f8bd120806cc3bdd89e0640411ed04e47d11b01305059fd0948e887eaeaf",
      "block_number": 45000123,
      "from": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
      "to": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
      "nonce": 7,
      "value_wei": "0",
      "input_hex": "0xa9059cbb0000000000000000000000005aeda56215b167893e80b4fe645ba6d5bab767de0000000000000000000000000000000000000000000000000de0b6b3a7640000",
      "gas_limit": 60000,
      "tx_type": 2,
      "chain_id": 56
    }
  }
}
```

`RpcReceipt`:

```json
{
  "method": "RpcReceipt",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "network": "bsc",
    "tx_hash": "0xeea2f8bd120806cc3bdd89e0640411ed04e47d11b01305059fd0948e887eaeaf"
  }
}
```

```json
{
  "type": "EvmReceiptLookup",
  "data": {
    "network": "bsc",
    "chain_id": 56,
    "receipt": {
      "tx_hash": "0xeea2f8bd120806cc3bdd89e0640411ed04e47d11b01305059fd0948e887eaeaf",
      "success": true,
      "block_number": 45000123,
      "block_hash": "0x5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b",
      "gas_used": 34512,
      "effective_gas_price_wei": "1000000000",
      "contract_address": null
    }
  }
}
```

`RpcCode`:

```json
{
  "method": "RpcCode",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "network": "bsc",
    "address": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
  }
}
```

```json
{
  "type": "EvmCode",
  "data": {
    "network": "bsc",
    "chain_id": 56,
    "address": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
    "code_hex": "0x363d3d373d3d3d363d73"
  }
}
```

#### Wallet and funding: shared rules

`WalletSummary`, `WalletBalance`, `FundingRequest`, and `Status` read the agent's wallet: the vault key behind its agent key, with an EVM address for a `secp256k1` key and a Solana address when the signer backend can sign for Solana (both from [`AuthenticateAgent`](#authenticateagent)). They sign nothing and change nothing. `network` and `asset` default to `default_network` and `default_asset` (USD1 on BSC); `asset` is a token key, or the contract address (any case) or mint of a configured deployment on the network. Errors never quote an RPC URL.

**Balances.** `WalletSummary` reads one balance per configured token deployment whose chain has an `rpc_url` and whose family the wallet has an address for. Native coins of Tempo chains (4217, 42431) are skipped: Tempo has no native gas coin. Reads run in parallel, at most 16 chains at a time; each chain gets 10 s to connect (including the chain id or cluster check) and 10 s per balance. A chain that is down or slow never fails the call: its entries carry `error` (`ChainRpc`) instead of `balance`, and every other entry is still returned. Entries are sorted by `network`, then `asset`.

| `kind` | Read |
|---|---|
| `native` | `eth_getBalance` |
| `erc20` | `balanceOf(wallet)` |
| `sol` | the wallet account's lamports (`getAccountInfo`; a missing account is `0`) |
| `spl` | the amount in the wallet's associated token account for the mint, under the mint's owner program (SPL Token or Token-2022); a missing account is `0` |

**Funding URIs.**

| Family | URI |
|---|---|
| EVM, native coin | EIP-681 `ethereum:<wallet>@<chain_id>[?value=<wei>]` |
| EVM, ERC-20 | EIP-681 `ethereum:<token>@<chain_id>/transfer?address=<wallet>[&uint256=<base units>]` |
| Solana, SOL | Solana Pay `solana:<wallet>[?amount=<SOL>]` |
| Solana, SPL | Solana Pay `solana:<wallet>?[amount=<tokens>&]spl-token=<mint>` |

A token transfer also needs the chain's native coin for fees, so for a non-native asset `gas` names it: the configured native token of the network (BNB on BSC for USD1), else the symbol for the chain id, and SOL on Solana. Tempo chains get no hint (fees are paid in the stablecoin).

#### `WalletSummary`

Returns the agent's addresses and every configured balance (see the shared rules above).

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `WalletSummary` | none | yes |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`. Failed reads are reported per entry.

This example uses a configuration of BSC, Ethereum (unreachable), and Solana devnet:

```json
{
  "method": "WalletSummary",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    }
  }
}
```

```json
{
  "type": "WalletSummary",
  "data": {
    "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
    "evm_address": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
    "solana_address": "9fijMemJYwXS5QD85Qxsq7iKqvSebgb6LvpGftgkeigk",
    "default_network": "bsc",
    "default_asset": "usd1",
    "balances": [
      {
        "network": "bsc",
        "chain_id": 56,
        "chain_name": "BSC",
        "family": "evm",
        "asset": "bnb",
        "symbol": "BNB",
        "kind": "native",
        "token": null,
        "decimals": 18,
        "address": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
        "balance_base_units": "2000000000000000000",
        "balance": "2",
        "error": null
      },
      {
        "network": "bsc",
        "chain_id": 56,
        "chain_name": "BSC",
        "family": "evm",
        "asset": "usd1",
        "symbol": "USD1",
        "kind": "erc20",
        "token": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
        "decimals": 18,
        "address": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
        "balance_base_units": "25500000000000000000",
        "balance": "25.5",
        "error": null
      },
      {
        "network": "eth",
        "chain_id": 1,
        "chain_name": "ETH",
        "family": "evm",
        "asset": "eth",
        "symbol": "ETH",
        "kind": "native",
        "token": null,
        "decimals": 18,
        "address": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
        "balance_base_units": null,
        "balance": null,
        "error": {
          "kind": "ChainRpc",
          "data": "eth_chainId failed: endpoint unreachable"
        }
      },
      {
        "network": "eth",
        "chain_id": 1,
        "chain_name": "ETH",
        "family": "evm",
        "asset": "usd1",
        "symbol": "USD1",
        "kind": "erc20",
        "token": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
        "decimals": 18,
        "address": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
        "balance_base_units": null,
        "balance": null,
        "error": {
          "kind": "ChainRpc",
          "data": "eth_chainId failed: endpoint unreachable"
        }
      },
      {
        "network": "solana-devnet",
        "chain_id": 900000002,
        "chain_name": "Solana Devnet",
        "family": "solana",
        "asset": "sol",
        "symbol": "SOL",
        "kind": "sol",
        "token": null,
        "decimals": 9,
        "address": "9fijMemJYwXS5QD85Qxsq7iKqvSebgb6LvpGftgkeigk",
        "balance_base_units": "1000000",
        "balance": "0.001",
        "error": null
      },
      {
        "network": "solana-devnet",
        "chain_id": 900000002,
        "chain_name": "Solana Devnet",
        "family": "solana",
        "asset": "usdc",
        "symbol": "USDC",
        "kind": "spl",
        "token": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        "decimals": 6,
        "address": "9fijMemJYwXS5QD85Qxsq7iKqvSebgb6LvpGftgkeigk",
        "balance_base_units": "12500000",
        "balance": "12.5",
        "error": null
      }
    ]
  }
}
```

#### `WalletBalance`

Returns one balance. Unlike `WalletSummary`, a failed read fails the call, so `error` is always `null`.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `WalletBalance` | none | yes |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`, `InvalidRequest` (unknown network or asset, no deployment on the network, no `rpc_url`, a Tempo native coin, or no wallet address for the family), `ChainRpc` (unreachable, too slow, or another chain).

```json
{
  "method": "WalletBalance",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "network": "bsc",
    "asset": "usd1"
  }
}
```

```json
{
  "type": "WalletBalance",
  "data": {
    "network": "bsc",
    "chain_id": 56,
    "chain_name": "BSC",
    "family": "evm",
    "asset": "usd1",
    "symbol": "USD1",
    "kind": "erc20",
    "token": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
    "decimals": 18,
    "address": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
    "balance_base_units": "25500000000000000000",
    "balance": "25.5",
    "error": null
  }
}
```

#### `FundingRequest`

Returns what a person needs to fund the wallet: the address, chain, token contract, an EIP-681 or Solana Pay URI, a QR code of the URI, the gas hint, and one sentence of `instructions`. `amount` (optional, whole units, at most as many fractional digits as the asset has decimals) goes into the URI. No RPC call is made.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `FundingRequest` | none | yes |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`, `InvalidRequest` (unknown network or asset, bad amount, a Tempo native coin, or no wallet address for the family).

`qr` (default `true`) renders the QR code (error correction level M, 4-module quiet zone). The example sets it to `false` to stay short; with it, `qr` is:

```text
"qr": {
  "modules": 41,
  "svg": "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 49 49\" width=\"392\" height=\"392\" ...><rect .../><path d=\"M4 4h7v1h-7z...\" fill=\"#000\"/></svg>",
  "terminal": "█████████████████████...\n████ ▄▄▄▄▄ █▀▄ ..."
}
```

`modules` is the side length without the quiet zone. `svg` is a standalone document, black on white, 8 pixels per module. `terminal` draws two module rows per line with `█`, `▀`, `▄`, and space, for dark terminal backgrounds (light modules are drawn); lines are separated by `\n`.

```json
{
  "method": "FundingRequest",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "network": "bsc",
    "asset": "usd1",
    "amount": "25",
    "qr": false
  }
}
```

```json
{
  "type": "FundingRequest",
  "data": {
    "network": "bsc",
    "chain_id": 56,
    "chain_name": "BSC",
    "family": "evm",
    "asset": "usd1",
    "symbol": "USD1",
    "kind": "erc20",
    "token": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
    "decimals": 18,
    "address": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
    "amount": "25",
    "amount_base_units": "25000000000000000000",
    "uri": "ethereum:0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d@56/transfer?address=0x2c7536e3605d9c16a7a3d7b1898e529396a65c23&uint256=25000000000000000000",
    "qr": null,
    "gas": {
      "asset": "bnb",
      "symbol": "BNB",
      "note": "USD1 transfers pay network fees in BNB; send a little BNB on BSC too."
    },
    "instructions": "Please send at least 25 USD1 to 0x2c7536e3605d9c16a7a3d7b1898e529396a65c23 on BSC (chain 56), plus a little BNB for network fees, then say when the transfer is confirmed."
  }
}
```

#### `Status`

Reports the service's health as seen by the calling agent: the signer daemon's `Hello` (and whether its major API version matches), the configuration (validated again), every configured chain (checked in parallel, at most 16 at a time, 5 s each: `eth_chainId` and `eth_blockNumber` on EVM chains, the cluster check and `getLatestBlockhash` on Solana; chains without `rpc_url` have `reachable: null`), the agent's identity, the policies that govern it (the signer daemon's [`AgentPolicySummary`](#agentpolicysummary)), and whether telemetry is on. `can_spend` is `false` when no spending policy governs the agent: every payment is then denied until an operator sets limits. Failed checks are reported in the result, never as errors. If the signer daemon is down the call fails with `SignerUnavailable`, because it authenticates the caller.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `Status` | none | yes |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`.

`warnings` lists what needs attention, each with a stable `code`; treat unknown codes as generic warnings.

| `code` | Meaning |
|---|---|
| `signer_incompatible` | the signer daemon speaks another major API version |
| `signer_unavailable` | the signer daemon did not answer `Hello` |
| `invalid_config` | the configuration failed validation |
| `no_spending_policy` | no spending policy governs the agent: it cannot spend until limits are set |
| `policy_status_unavailable` | the signer daemon could not report the agent's policies |
| `default_network_unconfigured` | the default network has no `rpc_url` |
| `chain_unreachable` | a configured chain did not answer (`network` names it) |
| `no_evm_address` | the vault key has no EVM address (an `ed25519` key) |
| `no_solana_address` | the signer backend cannot sign for Solana |

```json
{
  "method": "Status",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    }
  }
}
```

```json
{
  "type": "Status",
  "data": {
    "service": {
      "api_version": "1.1.0",
      "service_version": "1.0.0"
    },
    "signer": {
      "reachable": true,
      "api_version": "1.1.0",
      "daemon_version": "1.0.0",
      "compatible": true
    },
    "agent": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "vault_key_id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
      "algorithm": "secp256k1",
      "evm_address": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
      "solana_address": "9fijMemJYwXS5QD85Qxsq7iKqvSebgb6LvpGftgkeigk"
    },
    "config": {
      "valid": true,
      "error": null,
      "default_network": "bsc",
      "default_asset": "usd1",
      "chain_count": 3,
      "token_count": 5
    },
    "chains": [
      {
        "network": "bsc",
        "chain_id": 56,
        "chain_name": "BSC",
        "family": "evm",
        "rpc_configured": true,
        "reachable": true,
        "block_number": 45000123,
        "using_backup_rpc": false,
        "error": null
      },
      {
        "network": "eth",
        "chain_id": 1,
        "chain_name": "ETH",
        "family": "evm",
        "rpc_configured": true,
        "reachable": false,
        "block_number": null,
        "using_backup_rpc": false,
        "error": {
          "kind": "ChainRpc",
          "data": "eth_chainId failed: endpoint unreachable"
        }
      },
      {
        "network": "solana-devnet",
        "chain_id": 900000002,
        "chain_name": "Solana Devnet",
        "family": "solana",
        "rpc_configured": true,
        "reachable": true,
        "block_number": null,
        "using_backup_rpc": false,
        "error": null
      }
    ],
    "policies": {
      "attachment": "AllPolicies",
      "policies": [
        {
          "id": "a1b2c3d4-0000-4000-8000-000000000001",
          "priority": 10,
          "policy_type": "PerTxMaxSpending",
          "assets": {
            "mode": "Set",
            "values": [
              {
                "kind": "erc20",
                "value": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
              }
            ]
          },
          "networks": {
            "mode": "Set",
            "values": [
              56
            ]
          }
        }
      ],
      "spending_policy_count": 1
    },
    "can_spend": true,
    "telemetry_enabled": true,
    "warnings": [
      {
        "code": "chain_unreachable",
        "message": "network 'eth' did not answer as the configured chain",
        "network": "eth"
      }
    ]
  }
}
```

#### `Activity`

*Since API 1.1.0 (capability `Activity`).* The calling agent's recent payments and approval requests, for showing them to the user. paymentd forwards `since` and `limit` to the signer daemon's [`AgentActivity`](#agentactivity) (payments newest first; pending requests first, then decided ones; at most `limit` per list, default 50, capped at 200) and adds to each entry what the configuration knows about its asset on its chain:

| Field | Meaning |
|---|---|
| `network` | the configured chain key with the entry's chain id (exact match first, then any chain on the same policy network; every Solana cluster shares `900000001`, and the first one that has the asset configured wins); `null` when none |
| `symbol`, `decimals` | from the configured token with a deployment of the entry's asset on that network (the native deployment for a native coin); `null` when the asset is not configured |
| `amount` | `amount_wei` in whole tokens; `null` without `decimals` |

Each payment also carries the signer daemon's fields (`chain_id`, `asset`, `recipient`, `amount_wei`, `at`, `approval_request_id`, set when an approval let it go beyond the agent's limits), and each approval request the full `ManualApprovalRequest` with its `reasons`. The result covers only the calling agent.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `Activity` | none | yes |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`.

```json
{
  "method": "Activity",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "limit": 20
  }
}
```

```json
{
  "type": "Activity",
  "data": {
    "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
    "spends": [
      {
        "chain_id": 56,
        "asset": {
          "kind": "erc20",
          "value": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
        },
        "recipient": {
          "kind": "evm",
          "value": "0x5aeda56215b167893e80b4fe645ba6d5bab767de"
        },
        "amount_wei": "150000000000000000000",
        "at": [2026, 309, 12, 5, 0, 0, 0, 0, 0],
        "approval_request_id": "e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090",
        "network": "bsc",
        "symbol": "USD1",
        "decimals": 18,
        "amount": "150"
      },
      {
        "chain_id": 56,
        "asset": {
          "kind": "erc20",
          "value": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
        },
        "recipient": {
          "kind": "evm",
          "value": "0x5aeda56215b167893e80b4fe645ba6d5bab767de"
        },
        "amount_wei": "40000000000000000000",
        "at": [2026, 309, 12, 0, 0, 0, 0, 0, 0],
        "approval_request_id": null,
        "network": "bsc",
        "symbol": "USD1",
        "decimals": 18,
        "amount": "40"
      }
    ],
    "approvals": [
      {
        "id": "e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090",
        "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
        "vault_key_id": "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
        "request_payload_hash_hex": "a2e484ad65cc73d6b3e29c747d69111704fd790c9891dce3d9b30b6fd03ece76",
        "action": {
          "kind": "Transfer",
          "chain_id": 56,
          "token": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
          "to": "0x5aeda56215b167893e80b4fe645ba6d5bab767de",
          "amount_wei": "150000000000000000000"
        },
        "chain_id": 56,
        "asset": {
          "kind": "erc20",
          "value": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
        },
        "recipient": {
          "kind": "evm",
          "value": "0x5aeda56215b167893e80b4fe645ba6d5bab767de"
        },
        "amount_wei": "150000000000000000000",
        "created_at": [2026, 309, 12, 1, 0, 0, 0, 0, 0],
        "updated_at": [2026, 309, 12, 5, 0, 0, 0, 0, 0],
        "status": "completed",
        "triggered_by_policy_ids": ["a1b2c3d4-0000-4000-8000-000000000001"],
        "reasons": [
          {
            "limit": "per_payment",
            "policy_id": "a1b2c3d4-0000-4000-8000-000000000001",
            "max": "100000000000000000000",
            "used": null,
            "requested_amount_wei": "150000000000000000000"
          }
        ],
        "completed_at": [2026, 309, 12, 5, 0, 0, 0, 0, 0],
        "rejection_reason": null,
        "network": "bsc",
        "symbol": "USD1",
        "decimals": 18,
        "amount": "150"
      }
    ],
    "as_of": [2026, 309, 13, 0, 0, 0, 0, 0, 0]
  }
}
```

#### Telemetry

The payments service sends anonymous usage analytics (Mixpanel, `api.mixpanel.com/track?ip=0`) and crash and error reports (Sentry), on by default with an opt-out, under the rules of the TypeScript CLI:

- **Identity:** a random install id (UUID v4) in `telemetry.json` (mode `0600`) in the service's state directory, nothing else.
- **Sent:** per call, the method name, its outcome (`ok`, `approval_pending`, or `error` with the error kind), a duration bucket (`<100ms`, `100ms-1s`, `1-5s`, `5-30s`, `30s+`), and for payments an amount bucket in whole units (`0`, `<10`, `10-100`, `100-1k`, `1k-10k`, `10k+`), plus the service version, OS, CPU architecture, and environment label; timestamps are truncated to the minute. `Internal` and `SignedTransactionMismatch` errors and panics go to Sentry with the scrubbed message and stack.
- **Never sent:** addresses, keys, tokens, signatures, transaction hashes, exact amounts, URLs beyond `scheme://host`, e-mail addresses, the host name, or the home directory. Every string passes a scrubber, and property names are checked against an allowlist.
- **Never in the way:** recording is non-blocking; delivery is asynchronous and best effort (2 s per request, at most 3 s at shutdown); after a failed delivery the service stops sending for an hour. Telemetry never changes a payment's outcome.

It is off when the service's environment sets `AGENTPAY_TELEMETRY=0` (or `false`, `no`, `off`, empty) or `DO_NOT_TRACK` (anything but empty or `0`), when the stored consent is off, or when `telemetry.json` cannot be read (a damaged opt-out must not turn collection back on). `AGENTPAY_SENTRY_DSN` and `AGENTPAY_MIXPANEL_TOKEN` override the destinations (empty disables one), and `AGENTPAY_TELEMETRY_ENVIRONMENT` labels events (default `production`, or `ci` when `CI` is set). The consent is per machine: any authenticated client may read or change it. `disabled_reason` is, in order of precedence, `env_opt_out`, `do_not_track`, `missing_credentials`, `unreadable_state`, `stored_opt_out`, or `inactive` (an embedded or test instance that never sends).

#### `TelemetryStatus`

Returns whether telemetry is on and why not, the install id, the destinations, and the disclosure `notice` clients show.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `TelemetryStatus` | creates `telemetry.json` with a new install id the first time, unless the environment opts out | yes |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`.

```json
{
  "method": "TelemetryStatus",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    }
  }
}
```

```json
{
  "type": "TelemetryStatus",
  "data": {
    "enabled": true,
    "consent": true,
    "disabled_reason": null,
    "install_id": "3f6c2a9e-8b1d-4e7f-a5c0-9d2b4e6f8a1c",
    "crash_reports": true,
    "analytics": true,
    "notice": "AgentPay collects anonymous usage analytics and crash reports to understand adoption. It never collects private keys, passwords, wallet or recipient addresses, transaction hashes, or exact amounts; amounts and balances are reported only as coarse ranges. Opt out with `agentpay telemetry disable` or by setting AGENTPAY_TELEMETRY=0."
  }
}
```

#### `SetTelemetry`

Stores the consent and applies it at once; turning telemetry off drops queued events. The environment still wins: with `AGENTPAY_TELEMETRY=0` or `DO_NOT_TRACK` set, `enabled: true` is stored but `enabled` in the result stays `false`.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `TelemetryStatus` | writes `telemetry.json` (a damaged file is replaced) | yes |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`, `Persistence`.

```json
{
  "method": "SetTelemetry",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "enabled": false
  }
}
```

```json
{
  "type": "TelemetryStatus",
  "data": {
    "enabled": false,
    "consent": false,
    "disabled_reason": "stored_opt_out",
    "install_id": "3f6c2a9e-8b1d-4e7f-a5c0-9d2b4e6f8a1c",
    "crash_reports": true,
    "analytics": true,
    "notice": "AgentPay collects anonymous usage analytics and crash reports to understand adoption. It never collects private keys, passwords, wallet or recipient addresses, transaction hashes, or exact amounts; amounts and balances are reported only as coarse ranges. Opt out with `agentpay telemetry disable` or by setting AGENTPAY_TELEMETRY=0."
  }
}
```

#### Paid HTTP: shared rules

`X402Fetch` and `MppFetch` make an HTTP request **from the payments service** (as its service account), pay a `402 Payment Required` answer within the calling agent's policies, retry the request with the payment credential, and return the final response. The service holds no keys: every signature comes from the signer daemon as the calling agent, and the service checks each one before it leaves the process.

**Request** (fields flattened into `params`):

| Field | Default | Meaning |
|---|---|---|
| `url` | required | absolute `http` or `https` URL without `user:password@` |
| `method` | `GET`, or `POST` with a `body` | HTTP method (`CONNECT` refused) |
| `headers` | none | `[{"name": ..., "value": ...}]`, sent in order, at most 64; `Host`, `Connection`, `Content-Length`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, `Keep-Alive`, and `Proxy-*` are refused |
| `body` | none | `{"type": "text", "data": "..."}` or `{"type": "base64", "data": "..."}` |
| `approval_wait_secs` | 0 (capped at 600) | how long a signature may wait for an operator |

**Transport.** Redirects are never followed (a `3xx` is returned as it is, so a credential never reaches another host); the service ignores its own proxy environment; one request times out after 60 s, response included. The service can reach whatever its service account can, loopback included, so a request is no more privileged than one the agent could make itself. Request header values and bodies may carry the caller's merchant credentials: they are redacted from `Debug`, never logged, and wiped after the call.

**Response.** `response` is `{url, status, headers, body, body_truncated}`. `body` is `text` when it is UTF-8 without control characters other than tab, line feed, and carriage return, else `base64`; at most 48 KiB is returned (`body_truncated: true` beyond that) so the answer fits one frame. `payment` is `null` when the first answer was not a `402` (nothing was paid).

**Amounts** are integers in the token's base units, the unit the merchant's challenge uses (`"10000"` is 0.01 of a 6-decimal stablecoin).

**Errors.** `Merchant` means the merchant could not be reached or answered with something the service cannot accept; its message says whether anything was signed. `InvalidRequest` from these methods always means nothing was signed.

**Manual approval.** A merchant challenge is single-use and every authorization carries a fresh nonce, so a resent call creates a new approval request rather than reusing an approved one. When a policy holds a payment for an operator, the call waits up to `approval_wait_secs` and otherwise fails with `ManualApprovalPending`; set the wait long enough for the operator to decide while the call waits.

#### `X402Fetch`

Fetches `url` and pays an [x402](https://x402.org) `402` with an EIP-3009 `transferWithAuthorization` signed by the signer daemon (`Eip3009TransferWithAuthorization`). The exact-scheme client is implemented on `x402-types`' open client traits (`X402SchemeClient`, `PaymentCandidateSigner`), so no key exists in the service.

1. A `402` is decoded as x402 **v2** (`PAYMENT-REQUIRED` header, base64 JSON) or else **v1** (JSON body with `x402Version: 1`); anything else fails with `Merchant`. At most 64 KiB of a `402` body is read.
2. The first payable requirement is chosen: scheme `exact` on an `eip155` network, `asset` and `payTo` EVM addresses, the token's EIP-712 domain in `extra.name` / `extra.version`, `extra.assetTransferMethod` absent or `eip3009`, amount (`amount` in v2, `maxAmountRequired` in v1) equal to `expected_amount` and at most `max_amount` when given. If none qualifies the call fails with `InvalidRequest` naming each reason, and nothing is signed.
3. The authorization is `from` the agent's wallet `to` `payTo` for the amount, valid from now - 600 s until now + `maxTimeoutSeconds` (clamped to 30 s ... 1 h), with a random 32-byte nonce. The service recomputes the EIP-712 digest itself and requires the signature to recover to the wallet (`SignedTransactionMismatch` otherwise).
4. The request is retried once with `X-PAYMENT` (v1) or `PAYMENT-SIGNATURE` (v2): base64 JSON as the x402 reference clients build it (`{x402Version, scheme, network, payload}` in v1; `{x402Version, accepted, payload, resource, extensions}` in v2, with the chosen requirement echoed unchanged as `accepted`). The merchant's `PAYMENT-RESPONSE` / `X-PAYMENT-RESPONSE` header is decoded into `payment.payment_response`.

The authorization moves funds only when the merchant or its facilitator submits it before `validBefore`; the signature counts toward the agent's limits when it is made.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `X402Response` | HTTP requests to `url`; on a `402`, one policy-checked EIP-3009 signature (spend recorded) the merchant can settle | no |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`, `ManualApprovalPending`, `InvalidRequest`, `Merchant`, `SignedTransactionMismatch`.

```json
{
  "method": "X402Fetch",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "url": "https://api.example.com/weather?city=Lisbon",
    "headers": [
      {"name": "Accept", "value": "application/json"}
    ],
    "max_amount": "10000",
    "approval_wait_secs": 60
  }
}
```

```json
{
  "type": "X402Response",
  "data": {
    "response": {
      "url": "https://api.example.com/weather?city=Lisbon",
      "status": 200,
      "headers": [
        {"name": "content-type", "value": "application/json"},
        {"name": "payment-response", "value": "eyJzdWNjZXNzIjp0cnVlLCJ0cmFuc2FjdGlvbiI6IjB4OWQ0ZjNiMmExYzBlOGQ3ZjZhNWI0YzNkMmUxZjBhOWI4YzdkNmU1ZjRhM2IyYzFkMGU5ZjhhN2I2YzVkNGUzZiIsIm5ldHdvcmsiOiJlaXAxNTU6ODQ1MzIiLCJwYXllciI6IjB4MmM3NTM2ZTM2MDVkOWMxNmE3YTNkN2IxODk4ZTUyOTM5NmE2NWMyMyJ9"}
      ],
      "body": {"type": "text", "data": "{\"city\":\"Lisbon\",\"temperature_c\":21}"},
      "body_truncated": false
    },
    "payment": {
      "x402_version": 2,
      "scheme": "exact",
      "network": "eip155:84532",
      "chain_id": 84532,
      "asset": "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
      "pay_to": "0x209693bc6afc0c5328ba36faf03c514ef312287c",
      "amount": "1000",
      "from": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23",
      "valid_after": 1793990400,
      "valid_before": 1793991060,
      "nonce_hex": "0x5f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
      "payment_response": {
        "success": true,
        "transaction": "0x9d4f3b2a1c0e8d7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f",
        "network": "eip155:84532",
        "payer": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23"
      }
    }
  }
}
```

#### `MppFetch`

Fetches `url` and pays an MPP (`WWW-Authenticate: Payment`) `402` with a Tempo **charge** or a TIP-1034 **session** (sessions v2), or, since API 1.1.0 (capability `mpp.evm_charge`), an **`evm` / `arbitrum` charge** on any configured EVM network (see **EVM charge** below), or (capability `mpp.solana_charge`) a **`solana` charge** on a configured Solana cluster (see **Solana charge** below). `mpp` 0.19 drives the HTTP flow (challenge parsing, expiry and origin checks, `Accept-Payment` ranking, retries, receipt checks, commit and rollback); the service plugs its own `PaymentProvider` into it, whose challenge choice and signatures go through the signer daemon.

| Field | Default | Meaning |
|---|---|---|
| `amount` | any | only pay a challenge of exactly this amount (base units) |
| `deposit` | `suggestedDeposit`, else `amount` | deposit of a new channel, and the default top-up target |
| `max_deposit` | none | cap on a channel's total deposit; an explicit `deposit` above it is refused, a default one is lowered to it |
| `currency` | any | only pay challenges in this token: an EVM token address or a Solana mint (compared case-insensitively), or `sol` |
| `network` | any | only pay challenges on this configured network (a key of `chains`, for example `"base"`) |
| `session_key` | none | persist the channel under this name (1 to 64 of `A-Z a-z 0-9 . _ : -`) and reuse it; without it a session channel lives for this call only and is closed after it |
| `close_session` | `false` | close the channel after the paid response and forget it |

**Selection.** Only `tempo` challenges with intent `charge` or `session`, and `evm` / `arbitrum` / `solana` challenges with intent `charge`, count, and only on a chain id that a configured network with an `rpc_url` has (otherwise nothing is paid and the reason names the chain). Then: `network` and `currency` filter; `amount` filters; a channel persisted under `session_key` is read **before** selection and keeps only session challenges for that channel (same origin, chain, token, recipient, and channel id when the challenge names one; a mismatch fails with `InvalidRequest` rather than opening a second channel); session challenges for the legacy escrow (sessions v1: `sessionProtocol: "v1"`, or an `escrowContract` other than the TIP-1034 reserve precompile `0x4d50500000000000000000000000000000000000`) are refused with `InvalidRequest`; the rest are ranked, in order of precedence: a challenge the wallet cannot pay last (when the `402` lists several payable challenges, the service first reads, at most 8 of them within 4 s and signing nothing, whether the wallet holds the amount and, for a payment that needs gas, any native coin; a check that fails counts as payable); sessions first with a `session_key`, charges first otherwise; the chain the URL hints at (testnet words); a token configured in AgentPay before one that is not; a payment that needs no native coin for gas (any Tempo challenge, an EVM charge paid with `authorization` or `permit2`, a Solana charge whose fees the merchant pays) before one that does; mainnets before testnets (Tempo mainnet first); then an explicit `sessionProtocol: "v2"` marker breaks ties between session challenges. A caller `Accept-Payment` header ranks first. The challenge must name `methodDetails.chainId` (a Tempo chain); the service never assumes a network. The chosen challenge is echoed unchanged, `opaque` included, and the credential is sent in the header the challenge names (`Authorization`, or `Payment-Authorization` when its `header` parameter asks for it; the merchant client follows no redirects, so that header cannot leak).

**Charge.** The service sends a TIP-20 `transferWithMemo(recipient, amount, memo)` to the token as an EIP-1559 transaction through the `Transfer` pipeline (signed as a policy-checked `BroadcastTx`, verified, sent, and waited for up to 60 s) on the first configured EVM network with that chain id and an `rpc_url`, then retries the request with a `hash` credential (the fee is paid in the wallet's default Tempo fee token). The memo is the challenge's `memo`, else `mpp`'s attribution memo binding the challenge id and realm, which `mpp` servers require. Charges with `splits`, zero amounts, `supportedModes` without `push`, or a `currency` that is not a TIP-20 token (address prefix `0x20c000000000000000000000`; a `transferWithMemo` to any other contract would revert) are refused before anything is signed. If the transaction reverts or is not mined in time, the call fails with `ChainRpc` naming the hash and the merchant is not told.

**EVM charge (`evm`, `arbitrum`).** `evm` is the method of `draft-evm-charge-00` (used, for example, by BNB Chain's MPP SDK); `arbitrum` is `@arbitrum/mpp`'s name for the same request and payloads, on Arbitrum One (42161) and Arbitrum Sepolia (421614) only. The request is `amount` (a positive integer string, base units), `currency` (an ERC-20 address), `recipient`, `methodDetails.chainId`, and optionally `methodDetails.splits` (at most 10 `{recipient, amount}`, together less than `amount`); the wallet must hold the amount, or nothing is signed. Among the types in `methodDetails.credentialTypes`, AgentPay uses the first it can in this order, gasless first, whatever the merchant's order: `authorization`, `permit2`, `hash`, `transaction`. A charge with splits can only be paid with `permit2`:

| Type | What AgentPay does | Gas |
|---|---|---|
| `authorization` | signs an EIP-3009 `transferWithAuthorization` (`TransferWithAuthorization` typed data, the token's EIP-712 domain read from ERC-5267 `eip712Domain()`, else `name()` and `version()`), with `nonce = keccak256(challenge.id ‖ challenge.realm)` (UTF-8, packed), `validAfter = now − 60`, and `validBefore` = the challenge's `expires`, at most 10 minutes away; the merchant submits it | merchant |
| `permit2` | signs a Permit2 `SignatureTransfer` permit (the `Permit2WitnessTransfer` action: `PermitWitnessTransferFrom`, or `PermitBatchWitnessTransferFrom` with splits, primary recipient first) for the canonical Permit2 `0x000000000022d473030f116ddee9f6b43ac78ba3`, with `deadline` = the challenge's `expires`, at most 10 minutes away, and sends `{type: "permit2", permit: {permitted, nonce, deadline}, transferDetails, witness, signature}`; the merchant redeems it. `evm` (`@bnb-chain/mpp`): spender `methodDetails.permit2Spender`, witness `PaymentWitness(bytes32 challengeHash,string externalId)` with `challengeHash = keccak256(id ‖ realm)` and the request's `externalId` (else `""`), a random nonce. `arbitrum` (`@arbitrum/mpp`): spender = `recipient`, witness `PaymentWitness(bytes32 challengeHash)` with `challengeHash = keccak256(abi.encodePacked(string id, string realm, string[] tos, uint256[] amounts))` over the transfers as sent, nonce = `challengeHash`. Usable only when `methodDetails.permit2Address` is absent or the canonical deployment, and, for `evm`, `permit2Spender` is named; otherwise the next listed type is used. The first `permit2` payment in a token on a chain also sends `approve(Permit2, 2¹²⁸ − 1)` from the wallet and waits for it (the only gas this credential ever costs): the allowance and the approval's gas are checked first (nothing is signed if the wallet cannot pay the gas), then the permit is signed, then the approval is sent; if the approval then fails, the error says the signed permit was not sent | merchant (agent once per token and chain) |
| `hash` | sends an ERC-20 `transfer(recipient, amount)` through the `Transfer` pipeline and waits up to 60 s for a successful receipt, then sends `{type: "hash", hash}` | agent |
| `transaction` | signs the same transfer and sends `{type: "transaction", signature: <raw tx>}` without broadcasting it; if the merchant refuses the credential, the nonce is released | agent |

Without `credentialTypes`, an `evm` merchant gets `hash` (the spec's default list is `transaction`, `hash`); an `arbitrum` merchant gets `permit2`. A transaction AgentPay signs (`hash`, `transaction`, the Permit2 approval) is refused with `InvalidRequest` before anything is signed when the wallet's native balance cannot pay `gas_limit × max_fee_per_gas`; the message names the network, the coin, and the amounts. Tempo is exempt (fees are paid in the stablecoin). Every signature goes through the signer daemon (`Eip3009TransferWithAuthorization`, `Permit2WitnessTransfer`, or `BroadcastTx`), so the agent's limits and approvals apply, and the spend is recorded. One request pays at most one charge, whatever the method: if the merchant answers a charge credential with another `402`, the call fails with `Merchant` and nothing more is signed (the refused credential may still be redeemable, so paying a fresh challenge could pay twice). The credential carries `source: did:pkh:eip155:<chainId>:<wallet>`. The result's `charge` reports `credential_type`, and `tx_hash` for `hash` and `transaction`.

**Solana charge (`solana`).** `draft-solana-charge-00`: `amount` (base units or lamports, at most 2⁶⁴ − 1), `currency` (`"sol"` or a mint), `recipient` (a wallet; for tokens the owner of the destination associated token account), and `methodDetails`: `network` (`mainnet`, the default, or `devnet`; `localnet` and confidential charges are refused), `decimals` (required for a mint), `tokenProgram` (Token or Token-2022; when absent it is read from the mint account's owner and anything else is refused), `feePayer` with `feePayerKey`, `recentBlockhash` (else fetched), and up to 8 `splits` (`recipient`, `amount`, optional `memo`, `ataCreationRequired`). The primary recipient receives `amount` minus the splits, which must leave more than zero. AgentPay pays in **pull mode**: the signer daemon signs a `SolanaPaymentTransaction` (a v0 transaction without lookup tables: compute unit price 1 µlamport and limit 200,000, the primary transfer, the `externalId` memo, then per split an idempotent ATA creation when asked, the transfer, and its memo), the service rebuilds the expected message and refuses any difference, and the credential is `{type: "transaction", transaction: <base64>}` with `source` the agent's Solana wallet. With `feePayer`, the merchant's key is the fee payer, its signature slot is left empty for the merchant, and the merchant funds the split ATAs; otherwise the agent pays the fee. The merchant broadcasts the transaction. The whole amount (all legs) is checked against the agent's Solana limits and recorded as one spend. The result's `charge.tx_hash` is the agent's signature when the agent paid the fee, else `null` (the merchant's receipt `reference` names the transaction).

**Session.**

- *Open*: a Tempo transaction calling the reserve's `open(payee, operator, token, deposit, salt, payer)` with a random salt and an expiring nonce (TIP-1009, valid 25 s), plus a voucher for the first `amount`. The signer daemon signs `TempoSessionV2OpenTransaction` and `TempoSessionV2Voucher` and derives the channel id itself; the service first recomputes that id with `mpp` and refuses to sign on any difference. With `methodDetails.feePayer` the merchant sponsors the fee (MPP's `0x78` fee-payer envelope); otherwise the fee is paid in the channel token and the gas is estimated.
- *Reuse*: a voucher for the channel's signed cumulative amount plus `amount`. When that exceeds the deposit, a `TempoSessionV2TopUpTransaction` to the larger of `deposit` and the required amount (capped by `max_deposit`, else `InvalidRequest`) is first POSTed to the URL.
- *Close*: a voucher and a `TempoSessionV2CloseAuthorization` for the merchant's reported `spent` (else `acceptedCumulative`, never more than signed), POSTed to the URL.
- *Management POSTs* (top-up, stream voucher, close) echo the paid challenge; a `402` with an equivalent fresh challenge (same chain, token, recipient) is answered once more.
- *Receipts*: a `Payment-Receipt` naming another channel fails the call with `Merchant`. `mpp` only commits a voucher the merchant acknowledged with a matching receipt; an answer lost in transit keeps the signed amount (the merchant may hold the voucher). A `410 Gone` to a voucher forgets the persisted channel and opens a new one.
- *Streams*: a `text/event-stream` answer is read to its end (at most 8 MiB, within the 60 s request timeout); each `payment-need-voucher` event is answered with a voucher (after a top-up when needed), `payment-receipt` events are checked against the channel, and the collected body is returned. No event reaches the caller while the stream is open, so this method suits request/response metering, not long-lived streams (use the paying proxy, which passes streams through).
- *Checks*: transaction signatures must recover to the wallet over `tempo-alloy`'s signing hash of the transaction rebuilt from the same fields; vouchers are checked with `mpp`'s `verify_precompile_voucher_signature`, close authorizations against `mpp`'s close digest. Anything else fails with `SignedTransactionMismatch` before it is sent.
- *Persistence*: `mpp-sessions.json` in the service's state directory (mode `0600`, written to a synced temporary file and renamed), keyed by agent and `session_key`, holding the channel terms, deposit, and the highest signed cumulative amount; no secrets. Calls with the same `session_key` run one at a time.
- *Approval*: session transactions expire after 25 s, so a manual-approval policy on opens or top-ups must be approved within that window.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `MppResponse` | HTTP requests to `url`; on a `402`, policy-checked signatures (spend recorded): a charge transaction on chain, or session transactions and vouchers the merchant settles; a persisted session record | no |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`, `ManualApprovalPending`, `InvalidRequest`, `Merchant`, `ChainRpc`, `SignedTransactionMismatch`, `Persistence`.

A session voucher on a persisted channel:

```json
{
  "method": "MppFetch",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "url": "https://llm.example.com/v1/complete",
    "method": "POST",
    "headers": [
      {"name": "Content-Type", "value": "application/json"}
    ],
    "body": {"type": "text", "data": "{\"prompt\":\"Say hi\"}"},
    "deposit": "1000000",
    "max_deposit": "5000000",
    "session_key": "llm-example",
    "close_session": false,
    "approval_wait_secs": 20
  }
}
```

```json
{
  "type": "MppResponse",
  "data": {
    "response": {
      "url": "https://llm.example.com/v1/complete",
      "status": 200,
      "headers": [
        {"name": "content-type", "value": "application/json"},
        {"name": "payment-receipt", "value": "eyJtZXRob2QiOiJ0ZW1wbyIsImludGVudCI6InNlc3Npb24iLCJzdGF0dXMiOiJzdWNjZXNzIiwidGltZXN0YW1wIjoiMjAyNi0xMS0wNVQxMjozMDowMFoiLCJyZWZlcmVuY2UiOiIweDZiMGYzYzJkMWU5YThiN2M2ZDVlNGYzYTJiMWMwZDllOGY3YTZiNWM0ZDNlMmYxYTBiOWM4ZDdlNmY1YTRiM2MiLCJjaGFsbGVuZ2VJZCI6ImtNOXhQcVIyc1Q0dVY2d1g4eVowYUIiLCJjaGFubmVsSWQiOiIweDZiMGYzYzJkMWU5YThiN2M2ZDVlNGYzYTJiMWMwZDllOGY3YTZiNWM0ZDNlMmYxYTBiOWM4ZDdlNmY1YTRiM2MiLCJhY2NlcHRlZEN1bXVsYXRpdmUiOiI3NTAwMCIsInNwZW50IjoiNzUwMDAifQ"}
      ],
      "body": {"type": "text", "data": "{\"text\":\"Hi!\"}"},
      "body_truncated": false
    },
    "payment": {
      "challenge_id": "kM9xPqR2sT4uV6wX8yZ0aB",
      "realm": "llm.example.com",
      "method": "tempo",
      "intent": "session",
      "session_protocol": "v2",
      "chain_id": 42431,
      "network": "tempo-testnet",
      "currency": "0x20c0000000000000000000000000000000000000",
      "recipient": "0x742d35cc6634c0532925a3b844bc9e7595f8fe00",
      "amount": "25000",
      "charge": null,
      "session": {
        "session_key": "llm-example",
        "channel_id": "0x6b0f3c2d1e9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c",
        "opened": false,
        "deposit": "1000000",
        "topped_up": "0",
        "cumulative_amount": "75000",
        "vouchers": 1,
        "closed": false,
        "close_receipt": null
      },
      "receipt": {
        "method": "tempo",
        "intent": "session",
        "status": "success",
        "timestamp": "2026-11-05T12:30:00Z",
        "reference": "0x6b0f3c2d1e9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c",
        "challengeId": "kM9xPqR2sT4uV6wX8yZ0aB",
        "channelId": "0x6b0f3c2d1e9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c",
        "acceptedCumulative": "75000",
        "spent": "75000"
      }
    }
  }
}
```

#### Local paying proxy

`ProxyStart` runs an HTTP/1 forward proxy on `127.0.0.1` that pays `402` answers as the agent that started it, so programs that know nothing about x402 or MPP (`curl`, SDKs, browsers) can use paid APIs: point them at `proxy_url` (`HTTP_PROXY` / `HTTPS_PROXY`) and make them trust `ca_certificate_pem`. A `402` with a `Payment` challenge is paid with MPP (sessions persisted per origin under `proxy:<host>:<port>`; they stay open after the proxy stops, and `MppFetch` with that `session_key` and `close_session` closes one), any other `402` is tried as x402, and one neither can pay is passed through. A payment that fails is answered with `402`, an `x-agentpay-proxy-error: <kind>` header, and a text body. Proxied payments never wait for an operator: one held for manual approval fails with `ManualApprovalPending`. Paid event streams pass through as they arrive; their `payment-need-voucher` events are answered in the background.

**Security model.**

- *Loopback only*: the listener binds `127.0.0.1` (port `port`, or any free port).
- *Bearer token*: every request, `CONNECT` included, must carry `Proxy-Authorization: Basic base64("agentpay:" + token)` (what clients send for `proxy_url`) or `Proxy-Authorization: Bearer <token>`; otherwise the answer is `407` and nothing is forwarded. The token is 32 random bytes (64 hex characters), new for every `ProxyStart`, compared in constant time, and returned only by `ProxyStart`. **`token` and `proxy_url` are secrets**: anyone holding them can spend within the agent's policies until the proxy stops. Hand them to the child process through its environment or a private file, never on a command line.
- *Policies still apply*: the proxy keeps the starting agent's token in memory only (never on disk) and asks the signer daemon for every signature as that agent, so per-transaction, window, and manual-approval policies apply to each payment; `max_amount` adds a per-payment cap. Rotating or revoking the agent token stops all further proxied payments.
- *Allowed hosts*: with `allowed_hosts`, any other host gets `403`, for plain requests and `CONNECT` alike. Without it, every host is proxied, including loopback services the service account can reach.
- *HTTPS*: `CONNECT` tunnels are TLS-terminated with leaf certificates from a certificate authority generated for this run and kept only in memory; upstream connections verify the merchant's real certificate against the system roots. The proxy follows no redirects and strips hop-by-hop headers.
- *Lifetime*: the proxy runs until `ProxyStop` or until the service exits, and is never restarted automatically. Only the starting agent can stop it. It uses the configuration as of `ProxyStart`.

The proxy is modeled on `mpp`'s `client::ForwardProxy` (token-authenticated loopback listener, per-run CA, stream event answering) and reuses `mpp`'s payment flow, but is the service's own listener: `ForwardProxy` cannot be stopped, only binds ephemeral ports, writes its CA bundle to a shared temporary directory, and pays MPP only.

#### `ProxyStart`

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `ProxyStarted` | a loopback listener that pays as this agent until `ProxyStop` | no: `InvalidRequest` while a proxy runs |

`allowed_hosts` entries are host names or IP addresses (no scheme, port, or path), compared case-insensitively, at most 64. `max_amount` is in the challenge's base units, any asset.

`currency`, `deposit`, and `max_deposit` (all optional, new in 1.1.0) apply to MPP payments exactly as in [`MppFetch`](#mppfetch), and `ProxyStatus` echoes them:

- `currency`: only pay challenges in this token. Use it with a merchant that accepts several tokens, to pay in the one the wallet holds. Without it, a challenge in a token configured in AgentPay (one with limits and a balance) ranks before one in an unknown token; this ranking applies to `MppFetch` too.
- `deposit`: the deposit of a new session channel and the top-up target. Without it the deposit is the challenge's `suggestedDeposit`, else its amount, so a merchant that suggests none makes every later request top the channel up on chain. Size it for the stream of requests you expect; the deposit is what counts against the agent's limits.
- `max_deposit`: cap on a channel's total deposit; `deposit` above it fails with `InvalidRequest`.

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `InvalidRequest` (a proxy runs, the port is in use, a bad host, `deposit` above `max_deposit`), `Internal`.

```json
{
  "method": "ProxyStart",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    },
    "port": 8402,
    "allowed_hosts": ["api.example.com", "llm.example.com"],
    "max_amount": "100000",
    "currency": "0x20c0000000000000000000000000000000000000",
    "deposit": "1000000",
    "max_deposit": "5000000"
  }
}
```

```json
{
  "type": "ProxyStarted",
  "data": {
    "status": {
      "running": true,
      "address": "127.0.0.1:8402",
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "allowed_hosts": ["api.example.com", "llm.example.com"],
      "max_amount": "100000",
      "currency": "0x20c0000000000000000000000000000000000000",
      "deposit": "1000000",
      "max_deposit": "5000000",
      "requests": 0,
      "payments": 0,
      "failed_payments": 0
    },
    "token": "3f9a1c7e5b2d8f4a6c0e9b1d3f5a7c9e2b4d6f8a0c1e3b5d7f9a2c4e6b8d0f1a",
    "proxy_url": "http://agentpay:3f9a1c7e5b2d8f4a6c0e9b1d3f5a7c9e2b4d6f8a0c1e3b5d7f9a2c4e6b8d0f1a@127.0.0.1:8402",
    "ca_certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIBdjCCARygAwIBAgIUQ2xpZW50LXByb3h5LWNhLWV4YW1wbGUwCgYIKoZIzj0E\nAwIwIjEgMB4GA1UEAwwXQWdlbnRQYXkgcGF5aW5nIHByb3h5IENBMCAXDTc1MDEw\n...\n-----END CERTIFICATE-----\n"
  }
}
```

#### `ProxyStop`

Stops the proxy and returns its final status (`running: false`, with the run's counters). It succeeds when no proxy runs; a proxy started by another agent fails with `InvalidRequest`. Requests in flight are dropped.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `ProxyStatus` | closes the listener | yes |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`, `InvalidRequest`.

```json
{
  "method": "ProxyStop",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    }
  }
}
```

```json
{
  "type": "ProxyStatus",
  "data": {
    "running": false,
    "address": null,
    "agent_key_id": null,
    "allowed_hosts": [],
    "requests": 12,
    "payments": 3,
    "failed_payments": 1
  }
}
```

#### `ProxyStatus`

Reports whether the proxy runs, for which agent, its allowed hosts and cap, and its counters: authenticated `requests`, paid `payments`, and `failed_payments` (refused, denied, or failed). It never returns the token.

| Access | Auth | Response | Side effects | Idempotent |
|---|---|---|---|---|
| client allowlist | agent token | `ProxyStatus` | none | yes |

Errors: `AgentAuthenticationFailed`, `SignerUnavailable`.

```json
{
  "method": "ProxyStatus",
  "params": {
    "auth": {
      "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "agent_auth_token": "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7"
    }
  }
}
```

```json
{
  "type": "ProxyStatus",
  "data": {
    "running": true,
    "address": "127.0.0.1:8402",
    "agent_key_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
    "allowed_hosts": ["api.example.com", "llm.example.com"],
    "max_amount": "100000",
    "requests": 12,
    "payments": 3,
    "failed_payments": 1
  }
}
```

### Payments errors

A failed call returns `{"ok": false, "body_json": "<WirePaymentsError>"}`. As with the signer daemon, treat an unknown `kind` as a generic failure.

| Kind | `data` | Meaning |
|---|---|---|
| `AgentAuthenticationFailed` | none | the signer daemon rejected the agent credentials |
| `SignerUnavailable` | string | the signer daemon did not answer: socket missing or untrusted, connection failed, or the service account is not on its agent allowlist |
| `Signer` | `WireDaemonError` | the signer daemon refused a request made for the agent (policy denial, rejected approval, ...), passed through unchanged |
| `ManualApprovalPending` | `{approval_request_id}` | a signature still waits for an operator after the call stopped waiting; approve it, then resend the same call |
| `InvalidConfig` | string | the configuration failed validation; nothing changed |
| `Persistence` | string | saving the service's state failed; nothing changed |
| `InvalidRequest` | string | the request cannot be carried out as asked (unknown or wrong-family network, bad amount, missing token account, ...); nothing was signed |
| `ChainRpc` | string | a chain RPC call failed or returned something unusable, including an endpoint that serves another cluster; the reason never includes the RPC URL |
| `SignedTransactionMismatch` | string | the signed transaction does not match the request; it was neither returned nor broadcast |
| `UnknownPendingApproval` | UUID | `ResumeApproved` names no pending approval stored for this agent: never created, already settled, or created by another agent |
| `Merchant` | string | the paid HTTP endpoint (`X402Fetch`, `MppFetch`) could not be reached, timed out, or answered with a challenge, receipt, or management response the service cannot accept; the reason says whether anything was signed |
| `Internal` | string | unexpected internal failure |

One example of every kind:

```json
[
  {"kind": "AgentAuthenticationFailed"},
  {"kind": "SignerUnavailable", "data": "failed to connect to /Library/AgentPay/run/daemon.sock: No such file or directory"},
  {"kind": "Signer", "data": {"kind": "Policy", "data": {"PerTxLimitExceeded": {"policy_id": "a1b2c3d4-0000-4000-8000-000000000001", "max_amount_wei": "100000000000000000000", "requested_amount_wei": "250000000000000000000"}}}},
  {"kind": "ManualApprovalPending", "data": {"approval_request_id": "e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090"}},
  {"kind": "InvalidConfig", "data": "default_asset 'usd1' has no entry for default_network 'eth'"},
  {"kind": "Persistence", "data": "failed to write config.json"},
  {"kind": "InvalidRequest", "data": "the recipient's associated token account for this mint does not exist; create it before sending"},
  {"kind": "ChainRpc", "data": "Solana RPC getLatestBlockhash failed: connection refused"},
  {"kind": "SignedTransactionMismatch", "data": "signed Solana transaction SOL amount 2000000 lamports does not match expected 1500000"},
  {"kind": "UnknownPendingApproval", "data": "e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090"},
  {"kind": "Merchant", "data": "the merchant answered 402 with no x402 or MPP challenge; nothing was signed"},
  {"kind": "Internal", "data": "configuration lock poisoned"}
]
```

### Manual approval in payment flows

When a policy holds a signature for an operator, paymentd resends the identical signing request (same `request_id` and payload bytes, fresh timestamps) with exponential backoff (1 s doubling to 15 s), for as long as the method allows, at most 10 minutes. If the operator approves in time, the call completes. A rejection fails the call with `Signer` / `ManualApprovalRejected`. If time runs out, the call fails with `ManualApprovalPending`. Resend the same call after deciding the request; the payload must be byte-identical for the approval to apply.

**EVM.** `Transfer`, `TransferNative`, `Approve`, `Broadcast`, and `SignTypedData` wait for `approval_wait_secs` (default 0) and then **return** `ManualApprovalPending` instead of failing. The service stores the exact action (`evm-pending/<approval id>.json` in its state directory, removed after 24 hours) and releases the nonce reservation; `ResumeApproved` with the `approval_request_id` resends that action, reserving the same nonce again, and finishes the call. Resending the original call instead builds a new transaction (fresh nonce and fees) and so creates a new approval request. If a call waits longer than the 2-minute nonce reservation, the service reserves the same nonce again once the request is approved.

**Solana.** A Solana transfer can wait for an operator only when it uses a durable nonce (`options.nonce` other than `"recent_blockhash"`; broadcasting uses the managed nonce account by default): a recent blockhash expires within about a minute, so the signer daemon refuses manual approval for it. The durable nonce is what makes resuming possible: the transaction stays valid until the nonce account is advanced. When the wait runs out, `TransferSol` / `TransferSpl` return `ManualApprovalPending` and paymentd stores the exact signing action (`solana-pending.json` in its state directory, 24 hours). Resending the same call (same network, recipient, mint, amount, and options), or `ResumeApproved` with the `approval_request_id`, resends that stored action with the original options, so the approval applies even though a fresh priority fee estimate would differ. If the nonce account was advanced meanwhile, the stored action can never land: resending the call discards it and creates a new approval request, and `ResumeApproved` fails with `InvalidRequest`.

**Paid HTTP.** `X402Fetch` and `MppFetch` wait for `approval_wait_secs` (default 0) and then fail with `ManualApprovalPending`. Nothing is stored for `ResumeApproved`: each merchant challenge is single-use and each authorization or session transaction carries a fresh nonce (session transactions also expire after 25 s), so resending the call creates a new approval request. Ask for a wait long enough for the operator to decide while the call waits. The paying proxy never waits.

## Adding a paymentd method

The payments service is built so that each method family (EVM transfers, Solana, x402, MPP, wallet and funding) can be added independently. For a new method, `Transfer` in this example:

1. **Wire types** (`crates/agentpay-api/src/payments/`): add `transfer.rs` with a documented `TransferParams { auth: AgentAuth, ... }` and any result types, following `config.rs`. `#![deny(missing_docs)]` applies. Document access, auth, response, side effects, idempotency, and errors in the table format, and `include_str!` the two fixtures. Use `DecimalU128` strings for amounts.
2. **Request family** (`payments/mod.rs`): add the variant `Transfer(TransferParams)`, its name to `METHOD_NAMES`, and an arm in `method_name`, `agent_auth`, and `zeroize_secrets`. Add the response variant to `PaymentsRpcResponse`. Add new error kinds to `WirePaymentsError` only if your handler produces them, with an example in `fixtures/payments_errors.json`.
3. **Fixtures**: `crates/agentpay-api/fixtures/payments/Transfer.request.json` and `.response.json`, using the example agent credentials. Add `("Transfer", "<ResponseVariant>")` to `EXPECTED_RESPONSES` in `src/tests/payments.rs`.
4. **Docs**: a `#### Transfer` entry under [Payments methods](#payments-methods) with the table and both fixtures verbatim; add any new error kind to [Payments errors](#payments-errors). The `agentpay-api` tests fail until the examples, the error table, and the error example list match.
5. **Generate**: `cargo xtask gen-api` (CI runs `--check`).
6. **Handler** (`crates/agentpay-paymentd/src/features/transfer.rs`): `pub async fn handle(state: &AppState, agent: &AuthenticatedAgent, request: PaymentsRpcRequest) -> Result<PaymentsRpcResponse, PaymentsError>`, matching only its own variants. Register the module in `features/mod.rs`.
7. **Route** (`crates/agentpay-paymentd/src/dispatch.rs`): one arm, `Req::Transfer(_) => features::transfer::handle(state, agent(caller)?, request).await`. Authentication already happened; never re-implement it.
8. **Chains**: put RPC and transaction building in a chain provider (`src/chains/evm.rs`) implementing `ChainProvider`. Register it once in `AppState::new`, and fetch it with `state.chains.get::<EvmProvider>()?`.
9. **Signing**: use `agent.signer(state.signer.as_ref())`: `reserve_nonce`, `release_nonce` (on abandon), and `sign(action, wait)` with an `ApprovalWait`. Never build `DaemonRpcRequest`s by hand. To resume after `ManualApprovalPending`, persist and resend the exact same action. A rebuilt transaction with a new nonce or fee creates a new approval request.
10. **Tests**: unit-test the handler with `signer::testing::InProcessSigner` (a real in-memory signer daemon with policies) and `ScriptedSigner` (canned failures, request assertions), and use mock RPC servers for chain calls. For an end-to-end check, extend `tests/e2e.rs`, which runs client, paymentd, and signer daemon over real sockets.
    For a method that pays an HTTP endpoint, reuse `features/http.rs` (the redirect-free merchant client, request validation, bounded response reading) and `features/payer.rs` (`Payer`, an owned paying context that the paying proxy also uses, and checks for the signatures signerd returns), and test against the scripted merchant in `features/http/merchant.rs`.
11. **Logging**: `tracing` with method names, outcomes, and error kinds only. Never log tokens, keys, request bodies, wallet or recipient addresses, or RPC URLs (they can embed API keys). Keep them out of error messages too, because the server returns those to the client.

Keep every file under 1,000 lines (`cargo xtask check-file-length`), and do not use `unwrap` outside tests.

## Versioning and deprecation

`API_VERSION` (currently `1.1.0`) follows semantic versioning and versions **the wire contract only**, independently of the daemon release (`daemon_version`). It covers both services: the signer daemon and the payments service report the same `api_version`. 1.0.0 is the first published version of the contract; the compatibility rules and the deprecation policy below apply to every change from here on.

| API version | Changes |
|---|---|
| 1.1.0 | MPP `evm` / `arbitrum` charges (capability `mpp.evm_charge`) and `solana` charges (capability `mpp.solana_charge`): `MppFetch` and `ProxyStart` gain `network`, their `currency` is a string; `MppPayment` gains `network`, its `currency` and `recipient` are strings; `MppCharge` gains `credential_type`, its `tx_hash` and `memo_hex` are nullable. Signer methods [`RenameWallet`](#renamewallet) (response `Wallet`) and [`AgentActivity`](#agentactivity); agent action `SolanaPaymentTransaction` (types `SolanaPaymentTransaction`, `SolanaPaymentLeg`, `SolanaPaymentAsset`; see [`SignForAgent`](#signforagent)) for MPP `solana` charges; agent action `Permit2WitnessTransfer` (types `Permit2WitnessTransfer`, `Permit2Permission`, `Permit2Witness`) for the MPP `permit2` credential, approvals of the canonical Permit2 with a policy amount of 0, and `PolicyError::Permit2TypedDataDenied`; MPP ranks challenges the wallet cannot pay last and pays at most one charge per request; MPP EVM charges prefer gasless credentials (`authorization`, then `permit2`), pay splits with `permit2`, and refuse a transaction whose gas the wallet cannot pay; wallet names (`VaultKey.name`, `WalletInfo.name`, `BootstrapWallet` `name`, `WalletBackupSummary.name`, the backup payload's `name`); `SpendEvent` approval ids; payments method [`Activity`](#activity). Spending limits: payments beyond a row's limits wait for approval instead of being denied (`SpendingPolicy.over_limit`, `PolicyError::LimitApprovalRequired`, `PolicyDecision` `manual_approval`, `ManualApprovalRequest.reasons`); `SpendingLimit.manual_approval_min_wei` removed (1.0.0 was never published, so it is removed rather than deprecated). Payments method [`AddToken`](#addtoken) (capability `AddToken`), response variant `TokenAdded`; unauthenticated read-only [`LookupToken`](#lookuptoken) (capability `LookupToken`), response variant `TokenInfo`; `ChainProfile.fallback_rpc_urls`; `ChainStatus.using_backup_rpc`; [`ProxyStart`](#proxystart) `currency`, `deposit`, `max_deposit` (echoed in `ProxyStatus`), and MPP challenges in configured tokens rank first |
| 1.0.0 | First published version |

| Change | Version bump | Examples |
|---|---|---|
| Documentation or validation fix, no wire change | patch | clarified docs, stricter input check that was already documented |
| Additive | minor | new method, new optional request field, new response field, new error kind, new capability |
| Breaking | major | removed or renamed method or field, changed encoding or semantics |

Clients and daemons with the same major version are compatible. Within a major version, use `capabilities` from `Hello` to detect optional methods and features instead of comparing minor versions. Clients must ignore unknown response fields, unknown capabilities, and unknown error kinds.

To deprecate a method or field, mark it deprecated in the rustdoc of `crates/agentpay-api` and in this document, and name its replacement. It keeps working, and its capability stays advertised, for at least one more minor release. It is removed only in the next major version.

## Security notes for integrators

- **Pin the services.** For the signer daemon, check that the socket path and each of its parent directories are owned by root and not writable by group or others. After connecting, check that the peer's euid is `0` (`getpeereid` on macOS, `SO_PEERCRED` on Linux). Pin the payments service to its service account the same way (see [Payments service](#payments-service)). The bundled clients refuse anything else. A socket that a user could replace would let that user impersonate a service and collect agent tokens or lease secrets.
- **Treat these as secrets:** `agent_auth_token`, `lease_secret`, `private_key_hex` in `CreateVaultKey`, backup `passphrase`s (`BootstrapWallet`, `ExportWalletBackup`, `VerifyWalletBackup`), and the `token` and `proxy_url` that `ProxyStart` returns (they spend through the paying proxy). Request headers and bodies of `X402Fetch` and `MppFetch` may carry your merchant credentials; the service redacts and wipes them. Keep them out of logs, command lines, environment dumps, and crash reports. Pass them over stdin or pipes, never as arguments, and wipe buffers after use. Every request and response carrying one is a secret as a whole, including the `body_json` string.
- **Least privilege.** Put agent processes on the agent allowlist only. Run admin work under `sudo` or with a short-lived lease, and revoke the lease (`RevokeAdminLease`) when done. A lease only works from the uid that obtained it.
- **Sign what you show.** For admin challenges, sign the exact `message_hex` bytes. Show the user the `purpose` from the message, not one you built yourself.
- **Canonical payloads.** Build `payload` from the same `action` you send. The daemon rejects any mismatch. Never sign or forward a payload you did not build.
- **Retries.** Retry a `SignForAgent` or `ReserveNonce` that timed out with the **same** `request_id` and payload. The daemon returns the recorded result instead of signing twice. Use a fresh `request_id` only for a new intent.
- **Amounts.** Parse `DecimalU128` strings with arbitrary-precision integers (`BigInt` in JavaScript, `int` in Python), never as floating-point numbers.
- **Clock.** Generate `requested_at` from an accurate UTC clock. The daemon allows only 30 s of skew and a 5-minute lifetime.

## Writing a client: a minimal walkthrough

This Python 3 client has no dependencies. It performs the handshake and then evaluates a transfer for an agent. The same steps apply in any language: frame, double-encode, parse, check `ok`.

```python
import datetime, json, os, socket, stat, struct, sys, uuid

SOCKET = "/Library/AgentPay/run/daemon.sock" if sys.platform == "darwin" else "/run/agentpay/daemon.sock"
MAX_FRAME = 256 * 1024


def check_socket_is_root_owned(path):
    """Refuse sockets that a non-root user could have planted."""
    while True:
        info = os.lstat(path)
        if info.st_uid != 0 or (stat.S_ISDIR(info.st_mode) and info.st_mode & 0o022):
            raise RuntimeError(f"{path} is not root-owned and protected")
        parent = os.path.dirname(path)
        if parent == path:
            return
        path = parent


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("daemon closed the connection (request rejected)")
        data += chunk
    return data


def call(request):
    envelope = json.dumps({"body_json": json.dumps(request)}).encode()
    if len(envelope) > MAX_FRAME:
        raise ValueError("request too large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(SOCKET)
        if hasattr(socket, "SO_PEERCRED"):  # Linux: the daemon must run as root
            _, uid, _ = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != 0:
                raise RuntimeError("daemon is not running as root")
        sock.sendall(struct.pack(">I", len(envelope)) + envelope)
        (length,) = struct.unpack(">I", recv_exact(sock, 4))
        if length > MAX_FRAME:
            raise ValueError("response frame too large")
        response = json.loads(recv_exact(sock, length))
    body = json.loads(response["body_json"])
    if not response["ok"]:
        raise RuntimeError(f"daemon error: {body}")
    return body


def timestamp(moment):
    """Encode a datetime as the daemon's 9-element UTC timestamp array."""
    t = moment.astimezone(datetime.timezone.utc)
    return [t.year, t.timetuple().tm_yday, t.hour, t.minute, t.second, t.microsecond * 1000, 0, 0, 0]


def canonical(action):
    """Compact JSON, fields in declaration order, UTF-8 unescaped: what the daemon expects."""
    return list(json.dumps(action, separators=(",", ":"), ensure_ascii=False).encode())


check_socket_is_root_owned(SOCKET)
hello = call({"method": "Hello"})["data"]
if hello["api_version"].split(".")[0] != "1":
    sys.exit(f"incompatible daemon API {hello['api_version']}")
print("daemon", hello["daemon_version"], "API", hello["api_version"])

agent_key_id = os.environ["AGENTPAY_AGENT_KEY_ID"]
agent_token = sys.stdin.readline().strip()  # never pass tokens as arguments
action = {  # field order matters: it must match the schema
    "kind": "Transfer",
    "chain_id": 56,
    "token": "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
    "to": "0x5aeda56215b167893e80b4fe645ba6d5bab767de",
    "amount_wei": "1000000000000000000",
}
now = datetime.datetime.now(datetime.timezone.utc)
result = call({
    "method": "ExplainForAgent",
    "params": {"request": {
        "request_id": str(uuid.uuid4()),
        "agent_key_id": agent_key_id,
        "agent_auth_token": agent_token,
        "payload": canonical(action),
        "action": action,
        "requested_at": timestamp(now),
        "expires_at": timestamp(now + datetime.timedelta(minutes=2)),
    }},
})
print(json.dumps(result["data"]["decision"]))
```

To sign instead of explain, send the same request with `"method": "SignForAgent"`. If the result is `ManualApprovalRequired`, wait for the operator, then resend the same action. TypeScript clients can import the generated types from `client/src/generated` (`DaemonRpcRequest`, `DaemonRpcResponse`, `WireDaemonError`, ...), which match this document exactly.
