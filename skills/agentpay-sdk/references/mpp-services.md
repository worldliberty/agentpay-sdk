# Paid APIs: MPP, x402, And The Paying Proxy

AgentPay pays HTTP `402 Payment Required` answers inline. No API keys or accounts are needed. The
payments service makes the request, pays within the agent's spending limits, retries with the
payment credential, and returns the merchant's response.

All amounts here are **integer base units** of the challenge's token (`10000` = 0.01 of a
6-decimal stablecoin).

## Discover Services

Do not hardcode endpoints from this repo. Pick a current one from the live directory:

```bash
curl https://mpp.dev/services/llms.txt
```

## MPP

`agentpay mpp <url>` pays MPP challenges (`WWW-Authenticate: Payment`) with:

- **Tempo charge**: a one-off TIP-20 transfer on Tempo, sent and confirmed before the retry.
- **Tempo session** (TIP-1034 reserve channels, "sessions v2"): opens a channel with a deposit, then
  pays each request with an off-chain voucher. Legacy v1 escrow sessions are refused.

The wallet needs the challenge's token on the Tempo chain it names (`tempo` mainnet 4217, or
`tempo-testnet` 42431). Tempo fees are paid in the stablecoin, so no native gas coin is needed.

| Option | Meaning |
|---|---|
| `--amount <units>` | only pay a challenge of exactly this amount; omitted, the challenge amount is paid |
| `--currency <address>` | only pay in this token |
| `--deposit <units>` | deposit for a new session channel (default: the server's suggestion) |
| `--max-deposit <units>` | cap on the channel's total deposit, top-ups included |
| `--session-key <name>` | persist the channel under this name and reuse it on later calls |
| `--session-state-file <path>` | older flag; mapped to a session key derived from the path (no file is written) |
| `--close-session` | close the channel after this response and recover the unused deposit |
| `--approval-wait <secs>` | wait this long for a manual approval (default 0) |

Without `--session-key`, a session channel lives for one call and is closed after it. Sessions are
stored by the payments service per agent and key; calls with the same key run one at a time.

```bash
# One paid request
agentpay mpp https://parallelmpp.dev/api/search \
  --method POST --json-body '{"query":"latest AI news","numResults":5}' --json

# Verify the price before paying
agentpay mpp https://parallelmpp.dev/api/search --amount 5000 \
  --method POST --json-body '{"query":"latest AI news"}' --json

# Paid LLM gateway: reuse one channel across calls, cap the deposit
agentpay mpp https://llm.example.com/openai/v1/chat/completions \
  --session-key llm --max-deposit 2000000 \
  --method POST --json-body '{"model":"<model>","messages":[{"role":"user","content":"hello"}]}' --json

# Last call: close the channel and recover the deposit
agentpay mpp https://llm.example.com/openai/v1/chat/completions \
  --session-key llm --close-session \
  --method POST --json-body '{"model":"<model>","messages":[{"role":"user","content":"bye"}]}' --json
```

A streamed (`text/event-stream`) answer is collected and returned when it ends (up to 8 MiB within
60 seconds), with vouchers signed whenever the server asks. For long-lived streams, use the paying
proxy, which passes events through as they arrive.

## x402

`agentpay x402 <url>` pays x402 v1 and v2 challenges with the `exact` scheme on EVM networks by
signing an EIP-3009 `transferWithAuthorization` for the token.

| Option | Meaning |
|---|---|
| `--max-amount <units>` | refuse to pay more than this |
| `--expected-amount <units>` | only pay exactly this amount |
| `--approval-wait <secs>` | wait this long for a manual approval (default 0) |

```bash
agentpay x402 https://api.example.com/premium --max-amount 10000 --json
```

## Request Options (Both)

`--method <method>`, `--header "Name: value"` (repeatable), `--data <text>`, or
`--json-body <json>` (sets `Content-Type: application/json`). Redirects are never followed. At most
48 KiB of the response body is returned (`body_truncated: true` beyond that).

## Result

```json
{
  "protocol": "mpp",
  "url": "https://…",
  "status": 200,
  "ok": true,
  "headers": {"content-type": "application/json"},
  "body": {"…": "parsed JSON, a string, or {\"base64\": \"…\"}"},
  "body_truncated": false,
  "payment": {"…": "what was paid; null when the first answer was not a 402"}
}
```

`Merchant` errors mean the merchant could not be reached or answered with something AgentPay cannot
accept; the message says whether anything was signed.

## Manual Approval

A merchant challenge is single-use, so paid HTTP calls cannot be resumed. When a policy holds the
payment, the call waits for `--approval-wait` seconds and otherwise exits with code `3`. Rerunning
creates a new approval request. When approval is likely, pass `--approval-wait 300` and tell the
user to approve while the command waits.

## Paying Proxy

For programs that know nothing about x402 or MPP (`curl`, SDKs, browsers):

```bash
agentpay proxy start --allow-host api.example.com --max-amount 100000 --json
set -a; . ~/.agentpay/proxy.env; set +a   # HTTP(S)_PROXY and CA bundle variables
curl https://api.example.com/paid-endpoint
agentpay proxy stop --json
```

- The proxy listens on `127.0.0.1` and requires the secret token embedded in its URL. Treat
  `proxy_url`, `token`, and `proxy.env` as secrets; never put them on a command line or in chat.
- Every payment is still checked against the agent's limits; `--max-amount` adds a per-payment cap
  and `--allow-host` restricts which hosts are proxied.
- HTTPS is intercepted with a per-run certificate authority (`~/.agentpay/proxy-ca.pem`); the
  client must trust it (the env file sets the usual CA variables).
- Proxied payments never wait for manual approval.
- The proxy runs until `agentpay proxy stop` or until the payments service restarts.
