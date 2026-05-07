import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const modulePath = new URL('../src/lib/config-amounts.ts', import.meta.url);
const configModulePath = new URL('../packages/config/src/index.ts', import.meta.url);

async function withSeededConfig(caseSuffix, fn) {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-amounts-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  try {
    const configModule = await import(
      `${configModulePath.href}?case=${caseSuffix}-config-${Date.now()}`
    );
    const config = configModule.readConfig();
    const amounts = await import(`${modulePath.href}?case=${caseSuffix}-amounts-${Date.now()}`);
    await fn({ config, amounts });
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

test('resolveConfiguredErc20Asset and parseConfiguredAmount use config decimals', async () => {
  await withSeededConfig('erc20', async ({ config, amounts }) => {
    const asset = amounts.resolveConfiguredErc20Asset(
      config,
      1,
      '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
    );

    assert.equal(asset.symbol, 'USD1');
    assert.equal(asset.decimals, 18);
    assert.equal(amounts.parseConfiguredAmount('10.5', asset.decimals), 10500000000000000000n);
    assert.equal(amounts.formatConfiguredAmount('10500000000000000000', asset.decimals), '10.5');
  });
});

test('resolveConfiguredNativeAsset uses configured native token metadata', async () => {
  await withSeededConfig('native', async ({ config, amounts }) => {
    config.tokens = {
      ...(config.tokens ?? {}),
      bnb: {
        name: 'BNB',
        symbol: 'BNB',
        chains: {
          bsc: {
            chainId: 56,
            isNative: true,
            decimals: 18,
          },
        },
      },
    };

    const asset = amounts.resolveConfiguredNativeAsset(config, 56);

    assert.equal(asset.symbol, 'BNB');
    assert.equal(asset.decimals, 18);
    assert.equal(amounts.parseConfiguredAmount('0.01', asset.decimals), 10000000000000000n);
  });
});

test('configured amount helpers reject missing token metadata and accept string wei inputs for formatting', async () => {
  const amounts = await import(`${modulePath.href}?case=${Date.now()}-missing-metadata`);

  assert.throws(
    () => amounts.resolveConfiguredErc20Asset({}, 1, '0x0000000000000000000000000000000000000001'),
    /is not configured/,
  );
  assert.throws(
    () => amounts.resolveConfiguredNativeAsset({}, 1),
    /native asset on chain 1 is not configured/,
  );
  assert.equal(amounts.formatConfiguredAmount('1500', 3), '1.5');
});

test('configured amount helpers reject tokens without chain metadata and format bigint values', async () => {
  const amounts = await import(`${modulePath.href}?case=${Date.now()}-empty-chain-metadata`);

  assert.throws(
    () =>
      amounts.resolveConfiguredErc20Asset(
        {
          tokens: {
            usd1: {
              symbol: 'USD1',
              chains: {},
            },
          },
        },
        1,
        '0x0000000000000000000000000000000000000001',
      ),
    /is not configured/,
  );
  assert.throws(
    () =>
      amounts.resolveConfiguredNativeAsset(
        {
          tokens: {
            bnb: {
              symbol: 'BNB',
              chains: {},
            },
          },
        },
        56,
      ),
    /native asset on chain 56 is not configured/,
  );
  assert.equal(amounts.formatConfiguredAmount(1500n, 3), '1.5');
});

test('configured amount helpers scan tokens with missing chain maps and missing token addresses safely', async () => {
  const amounts = await import(`${modulePath.href}?case=${Date.now()}-scan-missing-chain-data`);

  assert.throws(
    () =>
      amounts.resolveConfiguredErc20Asset(
        {
          tokens: {
            missingChains: {
              symbol: 'MISS',
            },
            missingAddress: {
              symbol: 'USD1',
              chains: {
                eth: {
                  chainId: 1,
                  isNative: false,
                  decimals: 18,
                },
              },
            },
          },
        },
        1,
        '0x0000000000000000000000000000000000000001',
      ),
    /is not configured/,
  );

  assert.throws(
    () =>
      amounts.resolveConfiguredNativeAsset(
        {
          tokens: {
            missingChains: {
              symbol: 'MISS',
            },
            erc20Only: {
              symbol: 'USD1',
              chains: {
                eth: {
                  chainId: 1,
                  isNative: false,
                  decimals: 18,
                  address: '0x0000000000000000000000000000000000000001',
                },
              },
            },
          },
        },
        1,
      ),
    /native asset on chain 1 is not configured/,
  );
});

test('normalizeAgentAmountOutput removes raw wei amount from user-facing output', async () => {
  await withSeededConfig('output', async ({ config, amounts }) => {
    const asset = amounts.resolveConfiguredErc20Asset(
      config,
      1,
      '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
    );

    const normalized = amounts.normalizeAgentAmountOutput(
      {
        command: 'transfer',
        network: '1',
        asset: 'erc20:0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
        counterparty: '0x3333333333333333333333333333333333333333',
        amount_wei: '10000000000000000000',
        signature_hex: '0x1234',
      },
      asset,
    );

    assert.equal(normalized.asset, 'USD1');
    assert.equal(normalized.assetId, 'erc20:0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d');
    assert.equal(normalized.amount, '10');
    assert.equal('amount_wei' in normalized, false);
  });
});

test('rewriteAmountPolicyErrorMessage rewrites per-transaction policy amounts', async () => {
  await withSeededConfig('rewrite', async ({ config, amounts }) => {
    const asset = amounts.resolveConfiguredErc20Asset(
      config,
      1,
      '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
    );

    const rewritten = amounts.rewriteAmountPolicyErrorMessage(
      'daemon call failed: policy check failed: policy 032ef8c6-4ae0-48dd-9a43-828f1fe9f4ba rejected request: per transaction max 1000000000000000000 < requested 10000000000000000000000',
      asset,
    );

    assert.equal(
      rewritten,
      'daemon call failed: policy check failed: policy 032ef8c6-4ae0-48dd-9a43-828f1fe9f4ba rejected request: per transaction max 1 USD1 < requested 10000 USD1',
    );
  });
});

test('parseConfiguredAmount rejects values above u128 range', async () => {
  await withSeededConfig('overflow', async ({ config, amounts }) => {
    const asset = amounts.resolveConfiguredErc20Asset(
      config,
      1,
      '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
    );

    assert.throws(
      () => amounts.parseConfiguredAmount('10000000000000000000000', asset.decimals),
      /amount is too large/,
    );
  });
});

test('normalizePositiveDecimalInput validates decimal strings without Number math', async () => {
  const amounts = await import(`${modulePath.href}?case=${Date.now()}-decimal-input`);

  assert.equal(amounts.normalizePositiveDecimalInput('10.25', 'amount'), '10.25');
  assert.equal(amounts.normalizePositiveDecimalInput('1', 'amount'), '1');
  assert.throws(
    () => amounts.normalizePositiveDecimalInput('0.000', 'amount'),
    /amount must be greater than zero/,
  );
  assert.throws(
    () => amounts.normalizePositiveDecimalInput('1e3', 'amount'),
    /amount must be a positive decimal string/,
  );
});

test('normalizePositiveDecimalInput and parseConfiguredAmount reject empty, invalid, and zero values', async () => {
  const amounts = await import(`${modulePath.href}?case=${Date.now()}-amount-validation-edges`);
  assert.throws(() => amounts.normalizePositiveDecimalInput('   ', 'amount'), /amount is required/);
  assert.throws(() => amounts.parseConfiguredAmount('   ', 18, 'amount'), /amount is required/);
  assert.throws(
    () => amounts.parseConfiguredAmount('1.2.3', 2, 'amount'),
    /at most 2 fractional digits/,
  );
  assert.throws(
    () => amounts.parseConfiguredAmount('0', 18, 'amount'),
    /amount must be greater than zero/,
  );
  assert.throws(
    () => amounts.parseConfiguredAmount('0.0000000000000000011', 18, 'amount'),
    /at most 18 fractional digits/,
  );
});

test('rewriteAmountPolicyErrorMessage rewrites window and manual-approval policy ranges', async () => {
  await withSeededConfig('rewrite-window-manual', async ({ config, amounts }) => {
    const asset = amounts.resolveConfiguredErc20Asset(
      config,
      1,
      '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
    );

    const windowMessage = amounts.rewriteAmountPolicyErrorMessage(
      'policy check failed: window usage 1000000000000000000 + requested 2000000000000000000 > max 3000000000000000000',
      asset,
    );
    assert.equal(
      windowMessage,
      'policy check failed: window usage 1 USD1 + requested 2 USD1 > max 3 USD1',
    );

    const manualNone = amounts.rewriteAmountPolicyErrorMessage(
      'requires manual approval for requested amount 2000000000000000000 within range None..=5000000000000000000',
      asset,
    );
    assert.equal(
      manualNone,
      'requires manual approval for requested amount 2 USD1 within range None..=5 USD1',
    );

    const manualSome = amounts.rewriteAmountPolicyErrorMessage(
      'requires manual approval for requested amount 2000000000000000000 within range Some(1000000000000000000)..=5000000000000000000',
      asset,
    );
    assert.equal(
      manualSome,
      'requires manual approval for requested amount 2 USD1 within range Some(1 USD1)..=5 USD1',
    );

    const solAsset = {
      assetId: 'native_sol',
      symbol: 'SOL',
      decimals: 9,
    };
    const amountMax = amounts.rewriteAmountPolicyErrorMessage(
      'policy check failed: policy 032ef8c6-4ae0-48dd-9a43-828f1fe9f4ba rejected request: amount max 20000 < requested 30000',
      solAsset,
    );
    assert.equal(
      amountMax,
      'policy check failed: policy 032ef8c6-4ae0-48dd-9a43-828f1fe9f4ba rejected request: amount max 0.00002 SOL < requested 0.00003 SOL',
    );
  });
});
