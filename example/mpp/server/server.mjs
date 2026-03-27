import crypto from 'node:crypto';
import http from 'node:http';
import process from 'node:process';

import { Mppx, Request, tempo } from 'mppx/server';
import { Addresses } from 'viem/tempo';

const DEFAULT_HOST = '127.0.0.1';
const DEFAULT_PORT = 4020;
const DEFAULT_PRODUCT_NAME = 'Tempo Testnet Photo';
const DEFAULT_PRICE_UNITS = '0.01';
const DEFAULT_RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const DEFAULT_SECRET_KEY = crypto.randomBytes(32).toString('base64');

function requiredEnv(name, fallback) {
  const value = process.env[name] ?? fallback;
  if (!value) {
    throw new Error(`missing required environment variable ${name}`);
  }
  return value;
}

function createServerConfig() {
  const host = requiredEnv('HOST', DEFAULT_HOST);
  const port = Number.parseInt(requiredEnv('PORT', String(DEFAULT_PORT)), 10);
  if (!Number.isSafeInteger(port) || port <= 0) {
    throw new Error(`PORT must be a positive integer, received ${port}`);
  }

  return {
    host,
    port,
    productName: requiredEnv('PRODUCT_NAME', DEFAULT_PRODUCT_NAME),
    amount: requiredEnv('PRICE_UNITS', DEFAULT_PRICE_UNITS),
    recipient: requiredEnv('RECIPIENT_ADDRESS', DEFAULT_RECIPIENT),
    currency: requiredEnv('TOKEN_ADDRESS', Addresses.pathUsd),
    secretKey: requiredEnv('MPP_SECRET_KEY', DEFAULT_SECRET_KEY),
  };
}

const config = createServerConfig();
const realm = process.env.MPP_REALM || `${config.host}:${config.port}`;
const mppx = Mppx.create({
  realm,
  secretKey: config.secretKey,
  methods: [
    tempo({
      testnet: true,
      currency: config.currency,
      recipient: config.recipient,
    }),
  ],
});

const chargePhoto = mppx.charge({
  amount: config.amount,
  description: `${config.productName} via Tempo testnet`,
});

async function handleRequest(request) {
  const url = new URL(request.url);

  if (url.pathname === '/health') {
    return Response.json({
      ok: true,
      realm,
      amount: config.amount,
      currency: config.currency,
      recipient: config.recipient,
      methods: mppx.methods.map((method) => `${method.name}/${method.intent}`),
    });
  }

  if (url.pathname !== '/api/photo') {
    return Response.json({ error: 'not found' }, { status: 404 });
  }

  const result = await chargePhoto(request);
  if (result.status === 402) {
    return result.challenge;
  }

  const photoResponse = await fetch('https://picsum.photos/1024/1024');
  return result.withReceipt(
    Response.json({
      ok: true,
      product: config.productName,
      imageUrl: photoResponse.url,
    }),
  );
}

const server = http.createServer(
  Request.toNodeListener(async (request) => {
    try {
      return await handleRequest(request);
    } catch (error) {
      return Response.json(
        {
          error: 'server_error',
          message: error instanceof Error ? error.message : String(error),
        },
        { status: 500 },
      );
    }
  }),
);

server.listen(config.port, config.host, () => {
  const serverUrl = `http://${config.host}:${config.port}`;
  console.error(
    [
      `MPP demo server listening on ${serverUrl}`,
      `guide: https://mpp.dev/guides/one-time-payments`,
      `photo endpoint: ${serverUrl}/api/photo`,
      `health endpoint: ${serverUrl}/health`,
      `price: ${config.amount} PATH/USD`,
      `recipient: ${config.recipient}`,
      `currency: ${config.currency}`,
      `realm: ${realm}`,
      `methods: ${mppx.methods.map((method) => `${method.name}/${method.intent}`).join(', ')}`,
    ].join('\n'),
  );
});
