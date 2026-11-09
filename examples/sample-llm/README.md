# sample-llm

An example **third-party tool** built on AgentPay. It streams answers from
[`openai.mpp.tempo.xyz`](https://openai.mpp.tempo.xyz) (OpenAI behind MPP) and pays per request
with a Tempo payment channel. AgentPay holds the keys and enforces the limits.

```console
$ sample-llm wallet
Wallet      0x7df8…cf39 · agent key 80510431-fcc4-4279-b9e8-56b2f635fa4f
Network     Tempo (chain 4217)
Receive at  0x7df8772cb1534ac8a1a21e202f065847f363cf39
Balances    1.49 OUSD · 2 PATH/USD · 0 USD1 · 0 USDC.e
Pays with   OUSD, USDC.e on openai.mpp.tempo.xyz

$ sample-llm run "Write a haiku about paying for tokens one at a time."
Coins drop one by one,
A slow dance of fate unfolds—
Patience in each chip.
─ Charged 0.000617 OUSD · channel 0xbdf2dd9c… total 0.001234 OUSD
```

## Build and run

```sh
cargo build -p sample-llm
./target/debug/sample-llm wallet
./target/debug/sample-llm run "your question" [--model gpt-4o-mini] [--token OUSD] [--deposit 0.10] [--max-spend 1]
```

It needs AgentPay installed and set up (`agentpay setup`). It finds `agentpay` through
`AGENTPAY_BIN`, then `~/.agentpay/bin/agentpay`, then `PATH`.

## How it works

1. **Wallet:** `agentpay wallet --json` gives the agent's address and balances. The CLI prints
   the wire types unchanged, so the tool decodes them with `agentpay-api`
   (`WalletSummaryResult`).
2. **Which token:** an unpaid request to `/v1/chat/completions` answers `402` with one challenge
   per accepted token, at no cost. The tool picks the accepted token the wallet holds most of.
   The service-wide `/.well-known/mpp` list is not used, because it differs per endpoint.
3. **Paying proxy:** the tool runs `agentpay proxy start --json` with:
   - `--allow-host openai.mpp.tempo.xyz`;
   - `--currency` (the token from step 2);
   - `--deposit` and `--max-deposit` (the channel size);
   - `--max-amount` (a per-payment cap).

   It keeps the returned `proxy_url` (a secret) and the proxy's CA in memory only.
4. **Streaming:** the request goes through the proxy like any HTTPS request.
   - The first request opens a channel with the deposit, which counts against your AgentPay
     limits.
   - Later requests, and any `payment-need-voucher` events mid-stream, are paid with
     off-chain vouchers from that deposit.
   - Tokens are printed as they arrive. `payment-receipt` events and the `Payment-Receipt`
     header say what the merchant has charged.
5. **Charges:** each channel's last charged total is kept in `~/.sample-llm/channels.json`
   (`0600`, no secrets), so each run can show its own charge.
6. **Cleanup:** the proxy is stopped when the tool exits, Ctrl+C included. The channel stays
   open for the next run.

## What the tool never sees

- **The agent token.** The `agentpay` CLI reads it from the OS secret store.
- **Keys.** The signer daemon signs every channel transaction and voucher as the agent, under
  its spending limits.

A deposit beyond a limit waits for your approval: the proxy never waits, so the tool tells you
to approve it in `agentpay` → Approvals and run again.

A token must be set up in AgentPay before you can pay with it: add it in `agentpay` → Spending
limits → `a`, with a limit. An asset without a limit is blocked.
