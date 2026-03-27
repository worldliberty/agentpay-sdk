# MPP Services

Pay-per-request APIs that agents can call using `agentpay mpp`. No API keys or accounts required -- payment is handled inline via the HTTP 402 challenge/response protocol. The CLI determines the payment chain from the server challenge and supports any EVM-compatible network.

Live service discovery: https://mpp.dev/services/llms.txt

## Quick Start

```bash
# Ensure a local wallet is available first
agentpay wallet --json

# Discover a current endpoint from the live directory
curl https://mpp.dev/services/llms.txt

# Call a current MPP service -- amount is auto-accepted from the server challenge
agentpay mpp https://parallelmpp.dev/api/search \
  --method POST \
  --header 'Content-Type: application/json' \
  --json-body '{"query":"latest AI news","numResults":5}' \
  --json

# Same thing with --amount to verify the price before paying
agentpay mpp https://parallelmpp.dev/api/search \
  --amount 0.005 \
  --method POST \
  --header 'Content-Type: application/json' \
  --json-body '{"query":"latest AI news","numResults":5}' \
  --json
```

## How It Works

1. Agent sends a normal HTTP request to an MPP-enabled endpoint.
2. Server responds with `402 Payment Required` and a `WWW-Authenticate` header containing a payment challenge (method, token, amount, recipient, chain).
3. The CLI signs and broadcasts the chain-appropriate token payment for the challenge amount.
4. The CLI retries the original request with an `Authorization: Payment ...` header containing the tx hash.
5. Server verifies the payment on-chain and returns the real response.

The `--amount` flag is optional. When omitted, the CLI pays whatever the server asks. When provided, the CLI compares it against the challenge amount and refuses to pay if they differ.

## Prerequisites

The wallet must hold the payment token on the chain specified by the service challenge. Do not assume a fixed chain from this repo; discover the live endpoint from `https://mpp.dev/services/llms.txt`, then let the challenge determine the settlement chain.

To check your balance:

```bash
agentpay rpc balance \
  --address <WALLET_ADDRESS> \
  --token <TOKEN_ADDRESS> \
  --rpc-url <RPC_URL> \
  --json
```

If the wallet lacks funds on the required chain, the user must bridge or deposit assets to their wallet address on that chain before calling MPP services.

## Discover Current Services

Do not hardcode service endpoints from this repo. Discover the current list from the live directory:

```bash
curl https://mpp.dev/services/llms.txt
```

When writing examples or guiding a user, pick a currently listed endpoint from that document. Prefer stable, simple examples such as `https://parallelmpp.dev/api/search`.

Not every MPP endpoint supports session mode. For a `tempo/session` example, replace the placeholder URL below with a current session-capable endpoint you discovered from that live directory.

## Usage Examples

### Parallel search

```bash
agentpay mpp https://parallelmpp.dev/api/search \
  --method POST \
  --header 'Content-Type: application/json' \
  --json-body '{"query":"latest AI news","numResults":5}' \
  --json
```

### Exa web search

```bash
agentpay mpp https://exa.mpp.tempo.xyz/search \
  --method POST \
  --header 'Content-Type: application/json' \
  --json-body '{"query":"USD1 stablecoin policy controls","numResults":5}' \
  --json
```

### Tempo one-shot session

```bash
# Replace with a current session-capable endpoint from
# https://mpp.dev/services/llms.txt
agentpay mpp https://api.example.com/mpp-session \
  --method POST \
  --header 'Content-Type: application/json' \
  --json-body '{"prompt":"hello"}' \
  --json
```

### Tempo session with a persisted channel

```bash
agentpay mpp https://api.example.com/mpp-session \
  --session-state-file ~/.agentpay/tempo-session.json \
  --method POST \
  --header 'Content-Type: application/json' \
  --json-body '{"prompt":"hello"}' \
  --json

# Reuse the same channel and close it after this request
agentpay mpp https://api.example.com/mpp-session \
  --session-state-file ~/.agentpay/tempo-session.json \
  --close-session \
  --method POST \
  --header 'Content-Type: application/json' \
  --json-body '{"prompt":"follow up"}' \
  --json
```

### Tempo session with an explicit larger deposit

```bash
agentpay mpp https://api.example.com/mpp-session \
  --deposit 2 \
  --session-state-file ~/.agentpay/tempo-session.json \
  --method POST \
  --header 'Content-Type: application/json' \
  --json-body '{"prompt":"hello"}' \
  --json
```

## Live Directory

- LLM-optimized directory: `https://mpp.dev/services/llms.txt`
- Use that live directory instead of a static in-repo endpoint list.
