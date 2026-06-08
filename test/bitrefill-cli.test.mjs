import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { encodeFunctionData, keccak256 } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

const repoRoot = new URL('..', import.meta.url).pathname;
const bitrefillModulePath = new URL('../src/lib/bitrefill.ts', import.meta.url);
const AGENT_KEY_ID = '00000000-0000-0000-0000-000000000123';
const BASE_USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const BSC_USDT = '0x55d398326f99059fF775485246999027B3197955';
const ETH_USDT = '0xdAC17F958D2ee523a2206206994597C13D831ec7';
const RECIPIENT = '0x0000000000000000000000000000000000000def';

function makeIsolatedHome() {
  const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bitrefill-home-'));
  const agentpayHome = path.join(homeDir, '.agentpay');
  fs.mkdirSync(agentpayHome, { recursive: true, mode: 0o700 });
  return { homeDir, agentpayHome };
}

function writeExecutable(filePath, body) {
  fs.writeFileSync(filePath, `#!/bin/sh\n${body}\n`, { mode: 0o700 });
}

function writeConfig(agentpayHome, config) {
  fs.writeFileSync(path.join(agentpayHome, 'config.json'), `${JSON.stringify(config, null, 2)}\n`);
}

function runCli(args, { homeDir, env = {} }) {
  const agentpayHome = path.join(homeDir, '.agentpay');
  return spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', ...args], {
    cwd: repoRoot,
    env: {
      ...process.env,
      HOME: homeDir,
      AGENTPAY_HOME: agentpayHome,
      ...env,
    },
    encoding: 'utf8',
  });
}

function runCliAsync(args, { homeDir, env = {} }) {
  const agentpayHome = path.join(homeDir, '.agentpay');
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--import', 'tsx', 'src/cli.ts', ...args], {
      cwd: repoRoot,
      env: {
        ...process.env,
        HOME: homeDir,
        AGENTPAY_HOME: agentpayHome,
        ...env,
      },
      stdio: 'pipe',
    });

    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr?.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.on('error', reject);
    child.on('close', (status, signal) => {
      resolve({
        status:
          status ??
          (typeof signal === 'string' && typeof os.constants.signals[signal] === 'number'
            ? 128 + os.constants.signals[signal]
            : 1),
        stdout,
        stderr,
      });
    });
  });
}

function combinedOutput(result) {
  return `${result.stdout ?? ''}${result.stderr ?? ''}`;
}

async function closeServer(server) {
  if (!server) {
    return;
  }
  if (typeof server.closeAllConnections === 'function') {
    server.closeAllConnections();
  }
  await new Promise((resolve) => {
    server.close(() => resolve(undefined));
  });
}

function startUnixSocket(socketPath) {
  const server = net.createServer();
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => resolve(server));
  });
}

function startMockRpcServer({ chainId, txHash, from, to }) {
  const blockHash = `0x${'1'.repeat(64)}`;
  const logsBloom = `0x${'0'.repeat(512)}`;
  const chainIdHex = `0x${chainId.toString(16)}`;
  const receipt = {
    transactionHash: txHash,
    transactionIndex: '0x0',
    blockHash,
    blockNumber: '0x64',
    from,
    to,
    cumulativeGasUsed: '0x5208',
    gasUsed: '0x5208',
    contractAddress: null,
    logs: [],
    logsBloom,
    status: '0x1',
    type: '0x2',
    effectiveGasPrice: '0x3b9aca00',
  };

  const block = {
    number: '0x64',
    hash: blockHash,
    parentHash: `0x${'0'.repeat(64)}`,
    nonce: '0x0000000000000000',
    sha3Uncles: `0x${'0'.repeat(64)}`,
    logsBloom,
    transactionsRoot: `0x${'0'.repeat(64)}`,
    stateRoot: `0x${'0'.repeat(64)}`,
    receiptsRoot: `0x${'0'.repeat(64)}`,
    miner: from,
    difficulty: '0x0',
    totalDifficulty: '0x0',
    extraData: '0x',
    size: '0x1',
    gasLimit: '0x1c9c380',
    gasUsed: '0x5208',
    timestamp: '0x1',
    transactions: [],
    uncles: [],
    baseFeePerGas: '0x3b9aca00',
  };

  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk.toString();
    });
    req.on('end', () => {
      const payload = JSON.parse(body);
      const calls = Array.isArray(payload) ? payload : [payload];
      const responses = calls.map((call) => {
        switch (call.method) {
          case 'eth_chainId':
            return { jsonrpc: '2.0', id: call.id ?? null, result: chainIdHex };
          case 'eth_blockNumber':
            return { jsonrpc: '2.0', id: call.id ?? null, result: '0x64' };
          case 'eth_getBlockByNumber':
            return { jsonrpc: '2.0', id: call.id ?? null, result: block };
          case 'eth_getTransactionCount':
            return { jsonrpc: '2.0', id: call.id ?? null, result: '0x1' };
          case 'eth_estimateGas':
            return { jsonrpc: '2.0', id: call.id ?? null, result: '0x5208' };
          case 'eth_gasPrice':
            return { jsonrpc: '2.0', id: call.id ?? null, result: '0x3b9aca00' };
          case 'eth_maxPriorityFeePerGas':
            return { jsonrpc: '2.0', id: call.id ?? null, result: '0x3b9aca00' };
          case 'eth_feeHistory':
            return {
              jsonrpc: '2.0',
              id: call.id ?? null,
              result: {
                oldestBlock: '0x63',
                baseFeePerGas: ['0x3b9aca00', '0x3b9aca00'],
                gasUsedRatio: [0.5],
                reward: [['0x3b9aca00']],
              },
            };
          case 'eth_getTransactionReceipt':
            return { jsonrpc: '2.0', id: call.id ?? null, result: receipt };
          case 'eth_sendRawTransaction':
            return { jsonrpc: '2.0', id: call.id ?? null, result: txHash };
          default:
            return {
              jsonrpc: '2.0',
              id: call.id ?? null,
              error: { code: -32603, message: `unsupported method: ${call.method}` },
            };
        }
      });
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(Array.isArray(payload) ? responses : responses[0]));
    });
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve({
        server,
        rpcUrl: `http://127.0.0.1:${address.port}`,
      });
    });
  });
}

function startBitrefillServer({ challenge = false } = {}) {
  let invoicePollCount = 0;
  let lastCartBody = null;
  let lastInvoiceBody = null;
  let lastOmniUrl = null;
  let lastProductSlug = null;

  const invoiceBase = {
    id: 'invoice-1',
    accessToken: 'access-token-1',
    cart_id: 'cart-1',
    status: 'pending',
    paymentMethod: 'usdc_base',
    payment_currency: 'USDC',
    price: '50',
    subtotal: '50',
    expirationTime: '2099-01-01T00:00:00Z',
    orders: [],
    payment: {
      address: RECIPIENT,
      paymentUri: `ethereum:${RECIPIENT}`,
      altcoinPrice: '30.51',
      altBasePrice: '30510000',
      contractAddress: BASE_USDC,
    },
  };

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    let body = '';
    req.on('data', (chunk) => {
      body += chunk.toString();
    });
    req.on('end', () => {
      const jsonBody = body ? JSON.parse(body) : null;

      if (req.method === 'GET' && url.pathname === '/api/omni') {
        lastOmniUrl = req.url;
        res.setHeader('content-type', 'application/json');
        if (url.searchParams.get('q') === 'steam') {
          res.end(
            JSON.stringify([
              {
                slug: 'steam-usa',
                name: 'Steam USD',
                country: 'US',
                categories: ['games', 'game-stores'],
              },
            ]),
          );
          return;
        }
        res.end(JSON.stringify([]));
        return;
      }

      if (req.method === 'GET' && url.pathname === '/api/product/amazon-us') {
        lastProductSlug = 'amazon-us';
        res.setHeader('content-type', 'application/json');
        res.end(
          JSON.stringify({
            slug: 'amazon-us',
            name: 'Amazon US',
            currency: 'USD',
            packages: [{ id: 'pkg-50', valuePackage: '50', label: '$50' }],
          }),
        );
        return;
      }

      if (req.method === 'GET' && url.pathname === '/api/product/doordash-usa') {
        lastProductSlug = 'doordash-usa';
        res.setHeader('content-type', 'application/json');
        res.end(
          JSON.stringify({
            slug: 'doordash-usa',
            name: 'DoorDash USA',
            country: 'US',
            categories: ['food', 'food-delivery'],
            currency: 'USD',
            packages: [
              { id: 'pkg-20', valuePackage: '20', label: '$20' },
              { id: 'pkg-25', valuePackage: '25', label: '$25' },
            ],
            range: {
              min: '10',
              max: '500',
              step: '0.01',
            },
            descriptions: {
              en: '<p><strong>Meals, groceries, gifts and more, to your door.</strong></p><p>Give the gift of delivery with DoorDash.</p>',
            },
            instructions: {
              en: '<p>To redeem this gift card:</p><ol><li>Create an account or sign in.</li><li>Navigate to Account > Gift Card.</li><li>Enter your gift card PIN.</li></ol>',
            },
            terms:
              '<ul><li>This gift card can be redeemed only in the U.S.</li><li>Card cannot be returned or exchanged for cash unless required by law.</li></ul>',
            ratings: {
              reviews: [
                {
                  authorName: 'shy',
                  score: 5,
                  scoreMax: 5,
                  date: '2025-10-28',
                  content:
                    'delivery was almost instant and im extremely satisfied with my order history with bitrefill !!',
                },
                {
                  authorName: 'Anon',
                  score: 5,
                  scoreMax: 5,
                  createdTime: '2024-12-20T01:40:54.000Z',
                  content:
                    'Within 3 minutes the payment went through and then it sent me the code to the giftcard.',
                },
              ],
            },
            logo: 'https://cdn.example.com/doordash-logo.png',
            icon: 'https://cdn.example.com/doordash-icon.png',
          }),
        );
        return;
      }

      if (req.method === 'POST' && url.pathname === '/api/accounts/cart') {
        lastCartBody = jsonBody;
        res.setHeader('content-type', 'application/json');
        const slug = jsonBody?.slug ?? lastProductSlug;
        const valuePackage = String(jsonBody?.value ?? '50');
        if (slug === 'doordash-usa') {
          res.end(
            JSON.stringify({
              id: 'cart-1',
              cart_items: [
                {
                  operator_slug: 'doordash-usa',
                  valuePackage,
                  count: 1,
                  isGift: false,
                },
              ],
              payment_methods_info: {
                usdt_bsc: {
                  amount: '20.31',
                  altBasePrice: '20310000000000000000',
                },
                usdc_base: {
                  amount: '20.44',
                  altBasePrice: '20440000',
                },
                usdt_erc20: {
                  amount: '20.67',
                  altBasePrice: '20670000',
                },
                bitcoin: {
                  amount: '0.0005',
                },
              },
            }),
          );
          return;
        }
        res.end(
          JSON.stringify({
            id: 'cart-1',
            cart_items: [
              {
                operator_slug: 'amazon-us',
                valuePackage: '50',
                count: 1,
                isGift: false,
              },
            ],
            payment_methods_info: {
              usdc_base: {
                amount: '30.51',
                altBasePrice: '30510000',
              },
              bitcoin: {
                amount: '0.0005',
              },
            },
          }),
        );
        return;
      }

      if (req.method === 'POST' && url.pathname === '/api/accounts/invoice') {
        lastInvoiceBody = jsonBody;
        if (challenge) {
          res.statusCode = 403;
          res.setHeader('content-type', 'application/json');
          res.setHeader('cf-mitigated', 'challenge');
          res.end(
            JSON.stringify({
              status: 'invoice_creation_challenge',
              invoiceId: 'invoice-1',
              accessToken: 'access-token-1',
            }),
          );
          return;
        }
        res.setHeader('content-type', 'application/json');
        const selectedMethod = jsonBody?.paymentMethod ?? 'usdc_base';
        const invoiceByMethod =
          selectedMethod === 'usdt_bsc'
            ? {
                ...invoiceBase,
                paymentMethod: 'usdt_bsc',
                payment_currency: 'USDT',
                payment: {
                  ...invoiceBase.payment,
                  altcoinPrice: '20.31',
                  altBasePrice: '20310000000000000000',
                  contractAddress: BSC_USDT,
                },
              }
            : selectedMethod === 'usdt_erc20'
              ? {
                  ...invoiceBase,
                  paymentMethod: 'usdt_erc20',
                  payment_currency: 'USDT',
                  payment: {
                    ...invoiceBase.payment,
                    altcoinPrice: '20.67',
                    altBasePrice: '20670000',
                    contractAddress: ETH_USDT,
                  },
                }
              : invoiceBase;
        res.end(JSON.stringify(invoiceByMethod));
        return;
      }

      if (req.method === 'GET' && url.pathname === '/api/accounts/invoice/invoice-1') {
        invoicePollCount += 1;
        res.setHeader('content-type', 'application/json');
        res.end(
          JSON.stringify({
            ...invoiceBase,
            status: invoicePollCount >= 2 ? 'delivered' : 'pending',
            orders: invoicePollCount >= 2 ? [{ id: 'order-1', status: 'delivered' }] : [],
          }),
        );
        return;
      }

      res.statusCode = 404;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ error: 'not found', path: url.pathname }));
    });
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve({
        server,
        baseUrl: `http://127.0.0.1:${address.port}`,
        getLastCartBody: () => lastCartBody,
        getLastInvoiceBody: () => lastInvoiceBody,
        getLastOmniUrl: () => lastOmniUrl,
      });
    });
  });
}

test('resolveBitrefillInvoicePayment maps Base USDC invoices into ERC-20 transfer plans', async () => {
  const bitrefill = await import(`${bitrefillModulePath.href}?case=${Date.now()}-payment-plan`);
  const invoice = bitrefill.normalizeBitrefillInvoice({
    id: 'invoice-1',
    accessToken: 'access-token-1',
    status: 'pending',
    paymentMethod: 'usdc_base',
    payment_currency: 'USDC',
    payment: {
      address: RECIPIENT,
      altcoinPrice: '30.51',
      altBasePrice: '30510000',
      contractAddress: BASE_USDC,
    },
  });

  const resolved = bitrefill.resolveBitrefillInvoicePayment(invoice);
  assert.equal(resolved.chainId, 8453);
  assert.equal(resolved.networkSelector, 'base');
  assert.equal(resolved.asset.symbol, 'USDC');
  assert.equal(resolved.amountBaseUnits, 30510000n);
  assert.equal(resolved.broadcastTo, BASE_USDC);
  assert.match(resolved.dataHex, /^0xa9059cbb/u);
});

test('bitrefill payment method aliases normalize legacy usdt_erc20 to usdt_eth', async () => {
  const bitrefill = await import(`${bitrefillModulePath.href}?case=${Date.now()}-method-alias`);
  assert.equal(bitrefill.assertSupportedBitrefillPaymentMethod('usdt_erc20'), 'usdt_eth');
  assert.equal(bitrefill.assertSupportedBitrefillPaymentMethod('usdt_eth'), 'usdt_eth');
});

test('bitrefill bootstrap host gating and cookie jar helpers behave deterministically', async () => {
  const bitrefill = await import(
    `${bitrefillModulePath.href}?case=${Date.now()}-bootstrap-helpers`
  );
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bitrefill-cookie-jar-'));
  const cookieJarPath = path.join(tempDir, 'cookies.txt');
  const originalSkipBootstrap = process.env.AGENTPAY_BITREFILL_SKIP_BOOTSTRAP;

  try {
    delete process.env.AGENTPAY_BITREFILL_SKIP_BOOTSTRAP;
    assert.equal(bitrefill.shouldAutoBootstrapBitrefillSession('https://www.bitrefill.com'), true);
    assert.equal(bitrefill.shouldAutoBootstrapBitrefillSession('http://127.0.0.1:3000'), false);

    process.env.AGENTPAY_BITREFILL_SKIP_BOOTSTRAP = '1';
    assert.equal(bitrefill.shouldAutoBootstrapBitrefillSession('https://www.bitrefill.com'), false);

    const expectedCookies = [
      {
        name: 'cf_clearance',
        value: 'token-1',
        domain: '.bitrefill.com',
        path: '/',
        expires: 2_147_483_647,
        secure: true,
      },
      {
        name: 'session',
        value: 'token-2',
        domain: 'www.bitrefill.com',
        path: '/',
        expires: 0,
        secure: true,
      },
    ];

    bitrefill.writeBitrefillCookiesToCookieJar(expectedCookies, cookieJarPath);
    assert.deepEqual(bitrefill.readBitrefillCookiesFromCookieJar(cookieJarPath), expectedCookies);
  } finally {
    if (originalSkipBootstrap === undefined) {
      delete process.env.AGENTPAY_BITREFILL_SKIP_BOOTSTRAP;
    } else {
      process.env.AGENTPAY_BITREFILL_SKIP_BOOTSTRAP = originalSkipBootstrap;
    }
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('bitrefill search uses Bitrefill omni query parameters and returns normalized results', async () => {
  const { homeDir } = makeIsolatedHome();
  const { server: bitrefillServer, baseUrl, getLastOmniUrl } = await startBitrefillServer();

  try {
    const result = await runCliAsync(['bitrefill', 'search', '--query', 'steam', '--json'], {
      homeDir,
      env: {
        AGENTPAY_BITREFILL_TRANSPORT: 'fetch',
        AGENTPAY_BITREFILL_BASE_URL: baseUrl,
      },
    });

    assert.equal(result.status, 0, combinedOutput(result));
    const parsed = JSON.parse(result.stdout);
    assert.deepEqual(parsed, [
      {
        slug: 'steam-usa',
        name: 'Steam USD',
        country: 'US',
        categories: ['games', 'game-stores'],
        amountMode: 'unknown',
      },
    ]);

    const requestUrl = new URL(getLastOmniUrl(), baseUrl);
    assert.equal(requestUrl.searchParams.get('q'), 'steam');
    assert.equal(requestUrl.searchParams.get('src'), 'browse');
    assert.equal(requestUrl.searchParams.get('country'), 'US');
  } finally {
    await closeServer(bitrefillServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('bitrefill search defaults to YAML-like output when --json is absent', async () => {
  const { homeDir } = makeIsolatedHome();
  const { server: bitrefillServer, baseUrl } = await startBitrefillServer();

  try {
    const result = await runCliAsync(['bitrefill', 'search', '--query', 'steam'], {
      homeDir,
      env: {
        AGENTPAY_BITREFILL_TRANSPORT: 'fetch',
        AGENTPAY_BITREFILL_BASE_URL: baseUrl,
      },
    });

    assert.equal(result.status, 0, combinedOutput(result));
    assert.match(
      result.stdout,
      /^-\n {2}slug: steam-usa\n {2}name: "Steam USD"\n {2}country: US/mu,
    );
    assert.match(result.stdout, /categories:\n {4}- games\n {4}- game-stores/u);
    assert.doesNotMatch(result.stdout, /^\[/mu);
  } finally {
    await closeServer(bitrefillServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('bitrefill product defaults to YAML-like output and omits logo and icon noise', async () => {
  const { homeDir } = makeIsolatedHome();
  const { server: bitrefillServer, baseUrl } = await startBitrefillServer();

  try {
    const result = await runCliAsync(['bitrefill', 'product', '--slug', 'doordash-usa'], {
      homeDir,
      env: {
        AGENTPAY_BITREFILL_TRANSPORT: 'fetch',
        AGENTPAY_BITREFILL_BASE_URL: baseUrl,
      },
    });

    assert.equal(result.status, 0, combinedOutput(result));
    assert.match(result.stdout, /^slug: doordash-usa\nname: "DoorDash USA"\ncountry: US/mu);
    assert.match(result.stdout, /amountMode: range/u);
    assert.match(result.stdout, /categories:\n {2}- food\n {2}- food-delivery/u);
    assert.match(result.stdout, /commonAmounts:\n {2}- "\$20 \(20\)"\n {2}- "\$25 \(25\)"/u);
    assert.match(result.stdout, /amountRange:\n {2}min: "10"\n {2}max: "500"\n {2}step: "0\.01"/u);
    assert.match(
      result.stdout,
      /description: \|-\n {2}Meals, groceries, gifts and more, to your door\.\n {2}\n {2}Give the gift of delivery with DoorDash\./u,
    );
    assert.match(
      result.stdout,
      /howToRedeem: \|-\n {2}To redeem this gift card:\n {2}\n {2}- Create an account or sign in\.\n {2}- Navigate to Account > Gift Card\.\n {2}- Enter your gift card PIN\./u,
    );
    assert.match(
      result.stdout,
      /termsAndConditions: \|-\n {2}- This gift card can be redeemed only in the U\.S\.\n {2}- Card cannot be returned or exchanged for cash unless required by law\./u,
    );
    assert.match(
      result.stdout,
      /reviews:\n {2}-\n {4}rating: 5\/5\n {4}author: shy\n {4}date: 2025-10-28\n {4}content: "delivery was almost instant and im extremely satisfied with my order history with bitrefill !!"/u,
    );
    assert.match(result.stdout, /totalReviews: 2/u);
    assert.doesNotMatch(result.stdout, /logo/u);
    assert.doesNotMatch(result.stdout, /icon/u);
  } finally {
    await closeServer(bitrefillServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('bitrefill buy without --payment-method shows all supported EVM methods for the cart', async () => {
  const { homeDir } = makeIsolatedHome();
  const {
    server: bitrefillServer,
    baseUrl,
    getLastCartBody,
    getLastInvoiceBody,
  } = await startBitrefillServer();

  try {
    const result = await runCliAsync(
      ['bitrefill', 'buy', '--slug', 'doordash-usa', '--amount', '20', '--json'],
      {
        homeDir,
        env: {
          AGENTPAY_BITREFILL_TRANSPORT: 'fetch',
          AGENTPAY_BITREFILL_BASE_URL: baseUrl,
        },
      },
    );

    assert.equal(result.status, 0, combinedOutput(result));
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.mode, 'quote');
    assert.equal(parsed.product.slug, 'doordash-usa');
    assert.deepEqual(
      parsed.availablePaymentMethods.map((entry) => entry.method),
      ['usdt_bnb', 'usdt_eth', 'usdc_base'],
    );
    assert.equal(getLastCartBody().slug, 'doordash-usa');
    assert.equal(getLastCartBody().value, '20');
    assert.equal(getLastInvoiceBody(), null);
  } finally {
    await closeServer(bitrefillServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('bitrefill buy with --payment-method filters preview output to the selected method', async () => {
  const { homeDir } = makeIsolatedHome();
  const { server: bitrefillServer, baseUrl, getLastInvoiceBody } = await startBitrefillServer();

  try {
    const result = await runCliAsync(
      [
        'bitrefill',
        'buy',
        '--slug',
        'doordash-usa',
        '--amount',
        '20',
        '--payment-method',
        'usdt_bnb',
        '--json',
      ],
      {
        homeDir,
        env: {
          AGENTPAY_BITREFILL_TRANSPORT: 'fetch',
          AGENTPAY_BITREFILL_BASE_URL: baseUrl,
        },
      },
    );

    assert.equal(result.status, 0, combinedOutput(result));
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.mode, 'quote');
    assert.equal(parsed.selectedPaymentMethod, 'usdt_bnb');
    assert.deepEqual(
      parsed.availablePaymentMethods.map((entry) => entry.method),
      ['usdt_bnb'],
    );
    assert.equal(getLastInvoiceBody(), null);
  } finally {
    await closeServer(bitrefillServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('bitrefill buy accepts ranged product amounts even when Bitrefill also returns package hints', async () => {
  const { homeDir } = makeIsolatedHome();
  const { server: bitrefillServer, baseUrl, getLastCartBody } = await startBitrefillServer();

  try {
    const result = await runCliAsync(
      [
        'bitrefill',
        'buy',
        '--slug',
        'doordash-usa',
        '--amount',
        '25',
        '--payment-method',
        'usdt_eth',
        '--json',
      ],
      {
        homeDir,
        env: {
          AGENTPAY_BITREFILL_TRANSPORT: 'fetch',
          AGENTPAY_BITREFILL_BASE_URL: baseUrl,
        },
      },
    );

    assert.equal(result.status, 0, combinedOutput(result));
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.mode, 'quote');
    assert.equal(parsed.product.amount, '25');
    assert.equal(parsed.selectedPaymentMethod, 'usdt_eth');
    assert.equal(getLastCartBody().value, '25');
  } finally {
    await closeServer(bitrefillServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('bitrefill buy rejects explicitly non-EVM payment methods', async () => {
  const { homeDir } = makeIsolatedHome();
  const { server: bitrefillServer, baseUrl } = await startBitrefillServer();

  try {
    const result = await runCliAsync(
      [
        'bitrefill',
        'buy',
        '--slug',
        'amazon-us',
        '--amount',
        '50',
        '--payment-method',
        'bitcoin',
        '--email',
        'user@example.com',
        '--json',
      ],
      {
        homeDir,
        env: {
          AGENTPAY_BITREFILL_TRANSPORT: 'fetch',
          AGENTPAY_BITREFILL_BASE_URL: baseUrl,
        },
      },
    );

    assert.equal(result.status, 1);
    assert.match(combinedOutput(result), /payment method 'bitcoin' is not supported/u);
    assert.match(combinedOutput(result), /usdc_base/u);
  } finally {
    await closeServer(bitrefillServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('bitrefill buy preview filters to supported EVM methods and does not hit the Rust signer', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  const {
    server: bitrefillServer,
    baseUrl,
    getLastCartBody,
    getLastInvoiceBody,
  } = await startBitrefillServer();

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-agent'),
      'echo "rust signer should not be called for preview" 1>&2; exit 99',
    );

    const result = await runCliAsync(
      [
        'bitrefill',
        'buy',
        '--slug',
        'amazon-us',
        '--amount',
        '50',
        '--payment-method',
        'usdc_base',
        '--email',
        'user@example.com',
        '--json',
      ],
      {
        homeDir,
        env: {
          AGENTPAY_BITREFILL_TRANSPORT: 'fetch',
          AGENTPAY_BITREFILL_BASE_URL: baseUrl,
        },
      },
    );

    assert.equal(result.status, 0, combinedOutput(result));
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.mode, 'quote');
    assert.equal(parsed.broadcastRequested, false);
    assert.equal(parsed.selectedPaymentMethod, 'usdc_base');
    assert.deepEqual(
      parsed.availablePaymentMethods.map((entry) => entry.method),
      ['usdc_base'],
    );
    assert.equal(getLastCartBody().slug, 'amazon-us');
    assert.equal(getLastCartBody().value, '50');
    assert.equal(getLastInvoiceBody(), null);
  } finally {
    await closeServer(bitrefillServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('bitrefill buy --broadcast reports invoice access token before signer failure', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  const account = privateKeyToAccount(
    '0x59c6995e998f97a5a0044966f094538f5f4e0e46f95cebf7f5f88f5f2b5b9f10',
  );
  const socketServer = await startUnixSocket(socketPath);
  const { server: rpcServer, rpcUrl } = await startMockRpcServer({
    chainId: 8453,
    txHash: `0x${'2'.repeat(64)}`,
    from: account.address,
    to: BASE_USDC,
  });
  const { server: bitrefillServer, baseUrl } = await startBitrefillServer();

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-agent'),
      'echo "mock signer failure" 1>&2; exit 23',
    );

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      chainId: 8453,
      chainName: 'base',
      rpcUrl,
      agentKeyId: AGENT_KEY_ID,
      chains: {
        base: { chainId: 8453, name: 'base', rpcUrl },
      },
      wallet: {
        address: account.address,
        vaultKeyId: 'vault-key-test',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
      },
    });

    const result = await runCliAsync(
      [
        'bitrefill',
        'buy',
        '--slug',
        'amazon-us',
        '--amount',
        '50',
        '--payment-method',
        'usdc_base',
        '--email',
        'user@example.com',
        '--broadcast',
        '--json',
        '--daemon-socket',
        socketPath,
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'test-agent-auth-token',
        '--allow-legacy-agent-auth-source',
      ],
      {
        homeDir,
        env: {
          AGENTPAY_BITREFILL_TRANSPORT: 'fetch',
          AGENTPAY_BITREFILL_BASE_URL: baseUrl,
        },
      },
    );

    assert.notEqual(result.status, 0, combinedOutput(result));
    assert.match(result.stderr, /"event": "bitrefillInvoiceCreated"/u);
    assert.match(result.stderr, /"accessToken": "access-token-1"/u);
    assert.match(result.stderr, /"paymentMethod": "usdc_base"/u);
    assert.match(result.stderr, /"accessToken": "access-token-1"[\s\S]*mock signer failure/u);
    assert.equal(result.stdout, '');
  } finally {
    await closeServer(bitrefillServer);
    await closeServer(rpcServer);
    await closeServer(socketServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('bitrefill invoice get resolves the stored access token by invoice id', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  const account = privateKeyToAccount(
    '0x59c6995e998f97a5a0044966f094538f5f4e0e46f95cebf7f5f88f5f2b5b9f10',
  );
  const socketServer = await startUnixSocket(socketPath);
  const { server: rpcServer, rpcUrl } = await startMockRpcServer({
    chainId: 8453,
    txHash: `0x${'3'.repeat(64)}`,
    from: account.address,
    to: BASE_USDC,
  });
  const { server: bitrefillServer, baseUrl } = await startBitrefillServer();

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-agent'),
      'echo "mock signer failure" 1>&2; exit 23',
    );

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      chainId: 8453,
      chainName: 'base',
      rpcUrl,
      agentKeyId: AGENT_KEY_ID,
      chains: {
        base: { chainId: 8453, name: 'base', rpcUrl },
      },
      wallet: {
        address: account.address,
        vaultKeyId: 'vault-key-test',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
      },
    });

    const createResult = await runCliAsync(
      [
        'bitrefill',
        'buy',
        '--slug',
        'amazon-us',
        '--amount',
        '50',
        '--payment-method',
        'usdc_base',
        '--email',
        'user@example.com',
        '--broadcast',
        '--json',
        '--daemon-socket',
        socketPath,
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'test-agent-auth-token',
        '--allow-legacy-agent-auth-source',
      ],
      {
        homeDir,
        env: {
          AGENTPAY_BITREFILL_TRANSPORT: 'fetch',
          AGENTPAY_BITREFILL_BASE_URL: baseUrl,
        },
      },
    );

    assert.notEqual(createResult.status, 0, combinedOutput(createResult));
    assert.match(createResult.stderr, /"invoiceId": "invoice-1"/u);

    const lookupResult = await runCliAsync(
      ['bitrefill', 'invoice', 'get', '--invoice-id', 'invoice-1', '--json'],
      {
        homeDir,
        env: {
          AGENTPAY_BITREFILL_TRANSPORT: 'fetch',
          AGENTPAY_BITREFILL_BASE_URL: baseUrl,
        },
      },
    );

    assert.equal(lookupResult.status, 0, combinedOutput(lookupResult));
    const parsed = JSON.parse(lookupResult.stdout);
    assert.equal(parsed.id, 'invoice-1');
    assert.equal(parsed.accessToken, 'access-token-1');
    assert.equal(parsed.status, 'pending');

    const listResult = await runCliAsync(['bitrefill', 'invoice', 'list', '--json'], {
      homeDir,
      env: {
        AGENTPAY_BITREFILL_TRANSPORT: 'fetch',
        AGENTPAY_BITREFILL_BASE_URL: baseUrl,
      },
    });

    assert.equal(listResult.status, 0, combinedOutput(listResult));
    const listed = JSON.parse(listResult.stdout);
    assert.deepEqual(
      listed.map((entry) => ({
        invoiceId: entry.invoiceId,
        accessTokenStored: entry.accessTokenStored,
      })),
      [{ invoiceId: 'invoice-1', accessTokenStored: true }],
    );
  } finally {
    await closeServer(bitrefillServer);
    await closeServer(rpcServer);
    await closeServer(socketServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('bitrefill buy --broadcast signs via the Rust agent path and waits for invoice completion', async () => {
  const { homeDir, agentpayHome } = makeIsolatedHome();
  const rustBinDir = path.join(agentpayHome, 'bin');
  fs.mkdirSync(rustBinDir, { recursive: true, mode: 0o700 });
  const socketPath = path.join(agentpayHome, 'daemon.sock');
  const account = privateKeyToAccount(
    '0x59c6995e998f97a5a0044966f094538f5f4e0e46f95cebf7f5f88f5f2b5b9f10',
  );
  const transferDataHex = encodeFunctionData({
    abi: [
      {
        type: 'function',
        name: 'transfer',
        stateMutability: 'nonpayable',
        inputs: [
          { name: 'to', type: 'address' },
          { name: 'amount', type: 'uint256' },
        ],
        outputs: [{ name: '', type: 'bool' }],
      },
    ],
    functionName: 'transfer',
    args: [RECIPIENT, 30_510_000n],
  });
  const rawTx = await account.signTransaction({
    chainId: 8453,
    nonce: 1,
    to: BASE_USDC,
    gas: 21000n,
    maxFeePerGas: 2_200_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n,
    value: 0n,
    data: transferDataHex,
    type: 'eip1559',
  });
  const txHash = keccak256(rawTx);
  const socketServer = await startUnixSocket(socketPath);
  const { server: rpcServer, rpcUrl } = await startMockRpcServer({
    chainId: 8453,
    txHash,
    from: account.address,
    to: BASE_USDC,
  });
  const { server: bitrefillServer, baseUrl } = await startBitrefillServer();

  try {
    writeExecutable(
      path.join(rustBinDir, 'agentpay-agent'),
      [
        'printf "{\\"command\\":\\"broadcast\\",\\"network\\":\\"8453\\",\\"asset\\":\\"erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913\\",\\"counterparty\\":\\"0x0000000000000000000000000000000000000def\\",\\"amount_wei\\":\\"30510000\\",\\"estimated_max_gas_spend_wei\\":\\"21000000000000\\",\\"tx_type\\":\\"0x02\\",\\"delegation_enabled\\":false,\\"signature_hex\\":\\"0x11\\",\\"r_hex\\":\\"0x22\\",\\"s_hex\\":\\"0x33\\",\\"v\\":1,\\"raw_tx_hex\\":\\"%s\\",\\"tx_hash_hex\\":\\"%s\\"}" "$AGENTPAY_MOCK_RAW_TX" "$AGENTPAY_MOCK_TX_HASH"',
      ].join('\n'),
    );
    writeExecutable(path.join(rustBinDir, 'agentpay-admin'), 'echo "admin-help"; exit 0');

    writeConfig(agentpayHome, {
      rustBinDir,
      daemonSocket: socketPath,
      chainId: 8453,
      chainName: 'base',
      rpcUrl,
      agentKeyId: AGENT_KEY_ID,
      chains: {
        base: { chainId: 8453, name: 'base', rpcUrl },
      },
      wallet: {
        address: account.address,
        vaultKeyId: 'vault-key-test',
        vaultPublicKey: '03abcdef',
        agentKeyId: AGENT_KEY_ID,
        policyAttachment: 'policy_set',
      },
    });

    const result = await runCliAsync(
      [
        'bitrefill',
        'buy',
        '--slug',
        'amazon-us',
        '--amount',
        '50',
        '--payment-method',
        'usdc_base',
        '--email',
        'user@example.com',
        '--broadcast',
        '--json',
        '--daemon-socket',
        socketPath,
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token',
        'test-agent-auth-token',
        '--allow-legacy-agent-auth-source',
      ],
      {
        homeDir,
        env: {
          AGENTPAY_BITREFILL_TRANSPORT: 'fetch',
          AGENTPAY_BITREFILL_BASE_URL: baseUrl,
          AGENTPAY_MOCK_RAW_TX: rawTx,
          AGENTPAY_MOCK_TX_HASH: txHash,
        },
      },
    );

    assert.equal(result.status, 0, combinedOutput(result));
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.mode, 'broadcast');
    assert.equal(parsed.broadcastRequested, true);
    assert.equal(parsed.broadcast.chainId, 8453);
    assert.equal(parsed.broadcast.networkTxHash, txHash);
    assert.equal(parsed.payment.method, 'usdc_base');
    assert.equal(parsed.invoice.status, 'delivered');
    assert.equal(parsed.invoiceWait.status, 'delivered');
    assert.equal(parsed.invoiceWait.timedOut, false);
  } finally {
    await closeServer(bitrefillServer);
    await closeServer(rpcServer);
    await closeServer(socketServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('bitrefill challenge_required is surfaced with a dedicated exit code', async () => {
  const { homeDir } = makeIsolatedHome();
  const { server: bitrefillServer, baseUrl } = await startBitrefillServer({ challenge: true });

  try {
    const result = await runCliAsync(
      [
        'bitrefill',
        'buy',
        '--slug',
        'amazon-us',
        '--amount',
        '50',
        '--payment-method',
        'usdc_base',
        '--email',
        'user@example.com',
        '--broadcast',
        '--json',
      ],
      {
        homeDir,
        env: {
          AGENTPAY_BITREFILL_TRANSPORT: 'fetch',
          AGENTPAY_BITREFILL_BASE_URL: baseUrl,
        },
      },
    );

    assert.equal(result.status, 4, combinedOutput(result));
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.status, 'challenge_required');
    assert.equal(parsed.invoiceId, 'invoice-1');
  } finally {
    await closeServer(bitrefillServer);
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});
