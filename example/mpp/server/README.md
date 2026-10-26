# Tempo Testnet MPP Demos

This directory now contains both `charge` and `session` examples built on `mppx/server` for Tempo Moderato testnet.

- Guide: https://mpp.dev/guides/one-time-payments
- Server package: `mppx/server`
- Payment method: `tempo`
- Network: Tempo Moderato testnet
- Token: `pathUSD` at `0x20c0000000000000000000000000000000000000`

Both servers expose a local `/api/photo` endpoint that charges `0.01` `PATH/USD` and returns a random image URL from `https://picsum.photos/1024/1024` after payment verification.

## Files

- `server.mjs`: official-style `mppx/server` one-time payment `charge` example
- `session-server.mjs`: official-style `mppx/server` `session` example on Tempo Moderato
- `buy-tempo-testnet.mjs`: end-to-end demo runner that pays the local server from Tempo Moderato using the real local `agentpay` wallet and daemon
- `buy-tempo-testnet-session.mjs`: end-to-end demo runner that opens, reuses, and closes a Tempo session through the repo-local `agentpay` CLI against the local session example

## Run The Charge Demo

From the repo root:

```bash
pnpm example:mpp:demo
```

That script will:

1. reuse your configured local `agentpay` wallet and agent key
2. fund that wallet on Tempo Moderato testnet if it lacks `PATH/USD`
3. start the local `mppx/server` example on `http://127.0.0.1:4020`
4. create a temporary compatibility `AGENTPAY_HOME` that points the repo-local `agentpay` CLI at the installed `agentpay` daemon/binaries
5. run `agentpay mpp http://127.0.0.1:4020/api/photo --amount 0.01 --rpc-url https://rpc.moderato.tempo.xyz`

This is a real daemon-backed payment path, not a local signing shim.

## Run The Session Demo

From the repo root:

```bash
pnpm example:mpp:session-demo
```

That script will:

1. prefer your configured local `agentpay` wallet and agent key; if that is unavailable, fall back to legacy-layout compatibility mode (an older install whose binaries live outside `~/.agentpay/bin`)
2. fund that wallet on Tempo Moderato testnet if it lacks `PATH/USD`
3. generate a fresh testnet recipient account for the server and fund it so the server can close the session on-chain
4. start the local `mppx/server` session example on `http://127.0.0.1:4021`
5. when running in fallback mode, create a temporary compatibility `AGENTPAY_HOME` that points the repo-local `agentpay` CLI at the installed `agentpay` daemon/binaries
6. call `agentpay mpp` once with `--session-state-file` to open and persist a session
7. call `agentpay mpp` a second time with the same session state file and `--close-session` to reuse and close the channel

## Run The Server Manually

Charge server:

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

Session server:

```bash
PORT=4021 \
MPP_REALM=127.0.0.1:4021 \
MPP_SECRET_KEY=$(openssl rand -base64 32) \
RECIPIENT_PRIVATE_KEY=0x<server-private-key> \
TOKEN_ADDRESS=0x20c0000000000000000000000000000000000000 \
PRICE_UNITS=0.01 \
node example/mpp/server/session-server.mjs
```

If you omit `RECIPIENT_PRIVATE_KEY`, the server can still issue session challenges and accept `open` / `voucher` requests, but `--close-session` will fail because the server has no account available to submit the close transaction.

Then open and reuse a session with:

```bash
node --import tsx src/cli.ts mpp http://127.0.0.1:4021/api/photo \
  --amount 0.01 \
  --deposit 0.02 \
  --rpc-url https://rpc.moderato.tempo.xyz \
  --session-state-file /tmp/agentpay-tempo-session.json
```

And close it with:

```bash
node --import tsx src/cli.ts mpp http://127.0.0.1:4021/api/photo \
  --amount 0.01 \
  --deposit 0.02 \
  --rpc-url https://rpc.moderato.tempo.xyz \
  --session-state-file /tmp/agentpay-tempo-session.json \
  --close-session
```

If `agentpay wallet --json` is not available on your machine yet, run `agentpay admin setup` locally first and then rerun `pnpm example:mpp:demo`.
