# Tempo Testnet MPP Charge Demo

This example follows the official one-time payment guide:

- Guide: https://mpp.dev/guides/one-time-payments
- Server package: `mppx/server`
- Payment method: `tempo`
- Network: Tempo Moderato testnet
- Token: `pathUSD` at `0x20c0000000000000000000000000000000000000`

It exposes a local `/api/photo` endpoint that charges `0.01` `PATH/USD` and returns a random image URL from `https://picsum.photos/1024/1024` after payment verification.

## Files

- `server.mjs`: official-style `mppx/server` one-time payment example
- `buy-tempo-testnet.mjs`: end-to-end demo runner that pays the local server from Tempo Moderato using the real local `wlfi-agent` wallet and daemon

## Run The End-To-End Demo

From the repo root:

```bash
pnpm example:mpp:demo
```

That script will:

1. reuse your configured local `wlfi-agent` wallet and agent key
2. fund that wallet on Tempo Moderato testnet if it lacks `PATH/USD`
3. start the local `mppx/server` example on `http://127.0.0.1:4020`
4. create a temporary compatibility `AGENTPAY_HOME` that points the repo-local `agentpay` CLI at the real `wlfi-agent` daemon/binaries
5. run `agentpay mpp http://127.0.0.1:4020/api/photo --amount 0.01 --rpc-url https://rpc.moderato.tempo.xyz`

This is a real daemon-backed payment path, not a local signing shim.

## Run The Server Manually

```bash
PORT=4020 \
MPP_REALM=127.0.0.1:4020 \
MPP_SECRET_KEY=$(openssl rand -base64 32) \
RECIPIENT_ADDRESS=0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
TOKEN_ADDRESS=0x20c0000000000000000000000000000000000000 \
PRICE_UNITS=0.01 \
node example/mpp/server/server.mjs
```

Then pay it with:

```bash
node --import tsx src/cli.ts mpp http://127.0.0.1:4020/api/photo --amount 0.01 --rpc-url https://rpc.moderato.tempo.xyz
```

If `wlfi-agent wallet --json` is not available on your machine yet, run `wlfi-agent admin setup` locally first and then rerun `pnpm example:mpp:demo`.
