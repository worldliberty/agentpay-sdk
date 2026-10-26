import assert from 'node:assert/strict';
import os from 'node:os';
import test from 'node:test';

const modulePath = new URL('../src/lib/telemetry-scrub.ts', import.meta.url);

async function loadModule(caseSuffix) {
  return await import(`${modulePath.href}?case=${caseSuffix}-${Date.now()}`);
}

const EVM_ADDRESS = '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d';
const SOLANA_ADDRESS = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const PRIVATE_KEY_NO_PREFIX = '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
const INFURA_KEY = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
const TX_HASH = `0x${'ab'.repeat(32)}`;
const RAILGUN_ADDRESS =
  '0zk1qyk9nn28x0u3rwn5pknglda68wrn7gw6anjw8gg94mcj6eq5u48tlrv7j6fe3z53lama02nutwtcqc979wnce0qwly4y7w4rls5cq040g7z8eagshxrw5ajy990';

test('scrubText removes EVM addresses and raw transaction hex', async () => {
  const { scrubText } = await loadModule('evm');

  const scrubbed = scrubText(`transfer to ${EVM_ADDRESS} failed`);
  assert.ok(!scrubbed.includes(EVM_ADDRESS));
  assert.ok(scrubbed.includes('<redacted>'));
});

test('scrubText removes Solana base58 addresses', async () => {
  const { scrubText } = await loadModule('solana');

  const scrubbed = scrubText(`mint ${SOLANA_ADDRESS} rejected`);
  assert.ok(!scrubbed.includes(SOLANA_ADDRESS));
});

test('scrubText replaces the home directory with a tilde', async () => {
  const { scrubText } = await loadModule('home');

  const scrubbed = scrubText(`${os.homedir()}/.agentpay/config.json is unreadable`);
  assert.ok(!scrubbed.includes(os.homedir()));
  assert.ok(scrubbed.startsWith('~/.agentpay/config.json'));
});

test('scrubText strips a viem RPC error down to the host and the shape of the failure', async () => {
  const { scrubText } = await loadModule('viem');

  const message = [
    'HTTP request failed.',
    '',
    `URL: https://bsc-mainnet.infura.io/v3/${INFURA_KEY}`,
    `Request body: {"method":"eth_sendRawTransaction","params":["0x02f8${'9c'.repeat(60)}"]}`,
    '',
    'Details: transaction underpriced',
    'Version: viem@2.47.6',
  ].join('\n');

  const scrubbed = scrubText(message);
  assert.ok(!scrubbed.includes(INFURA_KEY), 'API key in the URL path');
  assert.ok(!scrubbed.includes('9c9c9c9c'), 'raw transaction hex');
  assert.ok(scrubbed.includes('URL: https://bsc-mainnet.infura.io\n'), 'host is kept');
  assert.ok(scrubbed.includes('"method":"eth_sendRawTransaction"'), 'shape is kept');
  assert.ok(scrubbed.includes('Details: transaction underpriced'));
  assert.ok(scrubbed.includes('Version: viem@2.47.6'), 'a version tag is not an email');
});

test('scrubText redacts addresses and hashes inside a JSON body', async () => {
  const { scrubText } = await loadModule('json-body');

  const body = JSON.stringify({
    to: EVM_ADDRESS,
    from: EVM_ADDRESS.toLowerCase(),
    hash: TX_HASH,
    data: '0xa9059cbb',
    value: '0x0',
  });

  const scrubbed = scrubText(body);
  assert.ok(!scrubbed.toLowerCase().includes(EVM_ADDRESS.slice(2).toLowerCase()));
  assert.ok(!scrubbed.includes(TX_HASH));
  assert.equal(
    scrubbed,
    '{"to":"<redacted>","from":"<redacted>","hash":"<redacted>","data":"0xa9059cbb","value":"0x0"}',
  );
});

test('scrubText redacts a private key that has no 0x prefix', async () => {
  const { scrubText } = await loadModule('bare-hex');

  const scrubbed = scrubText(`invalid key: ${PRIVATE_KEY_NO_PREFIX} (64 hex chars)`);
  assert.ok(!scrubbed.includes(PRIVATE_KEY_NO_PREFIX));
  assert.equal(scrubbed, 'invalid key: <redacted> (64 hex chars)');
});

test('scrubText redacts 0x hex of 16 or more nibbles but keeps selectors and small values', async () => {
  const { scrubText } = await loadModule('short-hex');

  assert.equal(scrubText('nonce 0x1234567890abcdef too low'), 'nonce <redacted> too low');
  assert.equal(
    scrubText('selector 0xa9059cbb value 0x0 gas 0x5208'),
    'selector 0xa9059cbb value 0x0 gas 0x5208',
  );
  assert.equal(scrubText('id 0XABCDEF0123456789'), 'id <redacted>');
});

test('scrubText redacts Railgun 0zk addresses', async () => {
  const { scrubText } = await loadModule('railgun');

  const scrubbed = scrubText(`shield to ${RAILGUN_ADDRESS} rejected by policy`);
  assert.equal(scrubbed, 'shield to <redacted> rejected by policy');
});

test('scrubText reduces every URL to scheme and host, dropping userinfo, path, and query', async () => {
  const { scrubText } = await loadModule('urls');

  assert.equal(
    scrubText('fetching https://user:hunter2@rpc.example.com:8545/v1/key?token=abc#frag now'),
    'fetching https://rpc.example.com:8545 now',
  );
  assert.equal(
    scrubText('paid "http://pay.example.com/invoice/123", retrying (https://a.b/c)'),
    'paid "http://pay.example.com", retrying (https://a.b)',
  );
  assert.equal(scrubText('wss://ws.example.com/socket?x=1'), 'wss://ws.example.com');
});

test('scrubText removes the machine hostname regardless of case', async () => {
  const { scrubText } = await loadModule('hostname');

  const hostname = os.hostname();
  const scrubbed = scrubText(`connect ECONNREFUSED on ${hostname.toUpperCase()} and ${hostname}`);
  assert.ok(!scrubbed.toLowerCase().includes(hostname.toLowerCase()));
  assert.ok(scrubbed.startsWith('connect ECONNREFUSED on <redacted>'));
});

test('scrubText removes email addresses', async () => {
  const { scrubText } = await loadModule('email');

  assert.equal(
    scrubText('sent receipt to alice.smith+wallet@example.co.uk today'),
    'sent receipt to <redacted> today',
  );
});

test('scrubProperties drops credential-bearing keys entirely', async () => {
  const { scrubProperties } = await loadModule('keys');

  const scrubbed = scrubProperties({
    action: 'transfer',
    amount_bucket: '10-100',
    recipientAddress: EVM_ADDRESS,
    vaultPassword: 'hunter2',
    agentAuthToken: 'secret-token',
  });

  assert.deepEqual(scrubbed, { action: 'transfer', amount_bucket: '10-100' });
});

test('scrubProperties drops exact amounts, URLs, hostnames, and emails by key', async () => {
  const { scrubProperties } = await loadModule('amount-keys');

  const scrubbed = scrubProperties({
    action: 'transfer',
    amount: 12.5,
    amountWei: '12500000',
    amount_usd: 12.5,
    rpcUrl: 'https://example.com',
    hostname: 'alices-macbook',
    email: 'alice@example.com',
    result: 'success',
  });

  assert.deepEqual(scrubbed, { action: 'transfer', result: 'success' });
});

test('scrubProperties keeps analytics keys that contain a deny-listed substring', async () => {
  const { scrubProperties } = await loadModule('allowlist');

  // `token_balance_bucket` contains "token"; without the allow-list it would be silently dropped
  // and the headline balance metric would never reach Mixpanel.
  const scrubbed = scrubProperties({
    native_balance_bucket: '10-100',
    token_balance_bucket: '1k-10k',
    tokenAddress: EVM_ADDRESS,
  });

  assert.deepEqual(scrubbed, {
    native_balance_bucket: '10-100',
    token_balance_bucket: '1k-10k',
  });
});

test('scrubProperties recurses into nested objects and arrays', async () => {
  const { scrubProperties } = await loadModule('nested');

  const scrubbed = scrubProperties({
    context: { note: `sent to ${EVM_ADDRESS}`, password: 'nope' },
    hashes: [`${EVM_ADDRESS}`],
  });

  assert.deepEqual(scrubbed, {
    context: { note: 'sent to <redacted>' },
    hashes: ['<redacted>'],
  });
});
