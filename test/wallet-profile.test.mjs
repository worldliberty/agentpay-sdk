import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { privateKeyToAccount } from 'viem/accounts';

const walletProfileModulePath = new URL('../src/lib/wallet-profile.ts', import.meta.url);

function bootstrapSummary(overrides = {}) {
  return {
    sourcePath: '/tmp/bootstrap.json',
    leaseId: 'lease-123',
    leaseExpiresAt: '2099-01-01T00:00:00Z',
    perTxPolicyId: 'policy-per-tx',
    dailyPolicyId: 'policy-daily',
    weeklyPolicyId: 'policy-weekly',
    gasPolicyId: 'policy-gas',
    perTxMaxWei: '1000000000000000000',
    dailyMaxWei: '5000000000000000000',
    weeklyMaxWei: '20000000000000000000',
    maxGasPerChainWei: '1000000000000000',
    dailyMaxTxCount: null,
    dailyTxCountPolicyId: null,
    perTxMaxFeePerGasWei: null,
    perTxMaxFeePerGasPolicyId: null,
    perTxMaxPriorityFeePerGasWei: null,
    perTxMaxPriorityFeePerGasPolicyId: null,
    perTxMaxCalldataBytes: null,
    perTxMaxCalldataBytesPolicyId: null,
    vaultKeyId: 'vault-key-123',
    vaultPublicKey: '03abcdef',
    vaultPrivateKey: null,
    agentKeyId: '00000000-0000-0000-0000-000000000001',
    networkScope: '1,56',
    assetScope: 'usd1,bnb',
    recipientScope: 'all recipients',
    destinationOverrideCount: 0,
    destinationOverrides: [],
    policyAttachment: 'policy_set',
    attachedPolicyIds: ['policy-per-tx', 'policy-daily'],
    policyNote: 'bootstrap note',
    ...overrides,
  };
}

function writePrivateJsonFile(targetPath, payload) {
  fs.mkdirSync(path.dirname(targetPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(targetPath, JSON.stringify(payload, null, 2) + '\n', {
    encoding: 'utf8',
    mode: 0o600,
  });
  fs.chmodSync(targetPath, 0o600);
}

function bootstrapPayload(overrides = {}) {
  const summary = bootstrapSummary(overrides);
  return {
    lease_id: summary.leaseId,
    lease_expires_at: summary.leaseExpiresAt,
    per_tx_policy_id: summary.perTxPolicyId,
    daily_policy_id: summary.dailyPolicyId,
    weekly_policy_id: summary.weeklyPolicyId,
    gas_policy_id: summary.gasPolicyId,
    per_tx_max_wei: summary.perTxMaxWei,
    daily_max_wei: summary.dailyMaxWei,
    weekly_max_wei: summary.weeklyMaxWei,
    max_gas_per_chain_wei: summary.maxGasPerChainWei,
    daily_max_tx_count: summary.dailyMaxTxCount ?? undefined,
    daily_tx_count_policy_id: summary.dailyTxCountPolicyId ?? undefined,
    per_tx_max_fee_per_gas_wei: summary.perTxMaxFeePerGasWei ?? undefined,
    per_tx_max_fee_per_gas_policy_id: summary.perTxMaxFeePerGasPolicyId ?? undefined,
    per_tx_max_priority_fee_per_gas_wei: summary.perTxMaxPriorityFeePerGasWei ?? undefined,
    per_tx_max_priority_fee_per_gas_policy_id:
      summary.perTxMaxPriorityFeePerGasPolicyId ?? undefined,
    per_tx_max_calldata_bytes: summary.perTxMaxCalldataBytes ?? undefined,
    per_tx_max_calldata_bytes_policy_id: summary.perTxMaxCalldataBytesPolicyId ?? undefined,
    vault_key_id: summary.vaultKeyId,
    vault_public_key: summary.vaultPublicKey,
    vault_private_key: summary.vaultPrivateKey,
    agent_key_id: summary.agentKeyId,
    agent_auth_token: 'secret-agent-token',
    agent_auth_token_redacted: true,
    network_scope: summary.networkScope,
    asset_scope: summary.assetScope,
    recipient_scope: summary.recipientScope,
    destination_override_count: summary.destinationOverrideCount,
    destination_overrides: summary.destinationOverrides,
    policy_attachment: summary.policyAttachment,
    attached_policy_ids: summary.attachedPolicyIds,
    policy_note: summary.policyNote,
    ...overrides,
  };
}

test('walletProfileFromBootstrapSummary derives address and keeps policy metadata', async () => {
  const walletProfile = await import(
    walletProfileModulePath.href + `?case=${Date.now()}-from-summary`
  );
  const account = privateKeyToAccount(`0x${'11'.repeat(32)}`);

  const profile = walletProfile.walletProfileFromBootstrapSummary(
    bootstrapSummary({
      vaultPublicKey: account.publicKey,
      attachedPolicyIds: ['policy-a', 'policy-b'],
      policyNote: 'configured by admin setup',
    }),
  );

  assert.equal(profile.vaultPublicKey, account.publicKey);
  assert.equal(profile.vaultKeyId, 'vault-key-123');
  assert.equal(profile.address, account.address);
  assert.equal(profile.policyAttachment, 'policy_set');
  assert.deepEqual(profile.attachedPolicyIds, ['policy-a', 'policy-b']);
  assert.equal(profile.policyNote, 'configured by admin setup');
  assert.equal(profile.networkScope, '1,56');
});

test('walletProfileFromBootstrapSummary derives a deterministic address for malformed public keys', async () => {
  const walletProfile = await import(
    walletProfileModulePath.href + `?case=${Date.now()}-from-summary-invalid-pubkey`
  );

  const profile = walletProfile.walletProfileFromBootstrapSummary(
    bootstrapSummary({
      vaultPublicKey: 'not-a-valid-public-key',
      policyAttachment: 'policy_set',
    }),
  );

  assert.match(profile.address ?? '', /^0x[0-9a-fA-F]{40}$/);
});

test('walletProfileFromBootstrapSummary preserves blank metadata and omits empty policy lists', async () => {
  const walletProfile = await import(
    walletProfileModulePath.href + `?case=${Date.now()}-from-summary-blank-metadata`
  );

  const profile = walletProfile.walletProfileFromBootstrapSummary(
    bootstrapSummary({
      vaultKeyId: '   ',
      vaultPublicKey: '   ',
      agentKeyId: '   ',
      policyAttachment: '   ',
      attachedPolicyIds: [],
      policyNote: '   ',
      networkScope: '   ',
      assetScope: '   ',
      recipientScope: '   ',
    }),
  );

  assert.equal(profile.vaultKeyId, '   ');
  assert.equal(profile.vaultPublicKey, '   ');
  assert.match(profile.address ?? '', /^0x[0-9a-fA-F]{40}$/);
  assert.equal(profile.agentKeyId, undefined);
  assert.equal(profile.policyAttachment, '   ');
  assert.equal(profile.attachedPolicyIds, undefined);
  assert.equal(profile.policyNote, undefined);
  assert.equal(profile.networkScope, undefined);
  assert.equal(profile.assetScope, undefined);
  assert.equal(profile.recipientScope, undefined);
});

test('walletProfileFromBootstrapSummary returns no address when the public key is missing at runtime', async () => {
  const walletProfile = await import(
    walletProfileModulePath.href + `?case=${Date.now()}-from-summary-missing-pubkey`
  );

  const profile = walletProfile.walletProfileFromBootstrapSummary(
    bootstrapSummary({
      vaultPublicKey: undefined,
      policyAttachment: 'policy_set',
    }),
  );

  assert.equal(profile.address, undefined);
});

test('resolveWalletProfile prefers persisted config wallet metadata', async () => {
  const walletProfile = await import(walletProfileModulePath.href + `?case=${Date.now()}-config`);

  const profile = walletProfile.resolveWalletProfile({
    wallet: {
      vaultPublicKey: '0x1234',
      address: '0x0000000000000000000000000000000000000001',
      agentKeyId: '00000000-0000-0000-0000-000000000001',
      policyAttachment: 'policy_set',
      attachedPolicyIds: ['policy-1'],
      policyNote: 'persisted',
      networkScope: '1',
      assetScope: 'usd1',
      recipientScope: 'all recipients',
    },
  });

  assert.deepEqual(profile, {
    vaultKeyId: undefined,
    vaultPublicKey: '0x1234',
    address: '0x0000000000000000000000000000000000000001',
    agentKeyId: '00000000-0000-0000-0000-000000000001',
    policyAttachment: 'policy_set',
    attachedPolicyIds: ['policy-1'],
    policyNote: 'persisted',
    networkScope: '1',
    assetScope: 'usd1',
    recipientScope: 'all recipients',
  });
});

test('resolveWalletProfile backfills vault key id from a matching bootstrap artifact', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-profile-backfill-'));
  process.env.AGENTPAY_HOME = tempRoot;

  try {
    const walletProfile = await import(
      walletProfileModulePath.href + `?case=${Date.now()}-backfill`
    );
    const account = privateKeyToAccount(`0x${'44'.repeat(32)}`);
    writePrivateJsonFile(
      path.join(tempRoot, 'bootstrap-100-200.json'),
      bootstrapPayload({
        vault_key_id: '11111111-1111-1111-1111-111111111111',
        vault_public_key: account.publicKey,
        agent_key_id: '00000000-0000-0000-0000-000000000099',
        policy_attachment: 'policy_set',
      }),
    );

    const profile = walletProfile.resolveWalletProfile({
      wallet: {
        vaultPublicKey: account.publicKey,
        agentKeyId: '00000000-0000-0000-0000-000000000099',
        policyAttachment: 'policy_set',
      },
    });

    assert.equal(profile.vaultKeyId, '11111111-1111-1111-1111-111111111111');
    assert.equal(profile.address, account.address);
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('resolveWalletAddress derives the configured wallet address when not persisted explicitly', async () => {
  const walletProfile = await import(walletProfileModulePath.href + `?case=${Date.now()}-address`);
  const account = privateKeyToAccount(`0x${'22'.repeat(32)}`);

  const address = walletProfile.resolveWalletAddress({
    wallet: {
      vaultPublicKey: account.publicKey,
      policyAttachment: 'policy_set',
    },
  });

  assert.equal(address, account.address);
});

test('resolveWalletProfile tolerates blank wallet public keys and resolveWalletAddress prefers explicit addresses', async () => {
  const walletProfile = await import(
    walletProfileModulePath.href + `?case=${Date.now()}-blank-pubkey-and-explicit-address`
  );

  const profile = walletProfile.resolveWalletProfile({
    wallet: {
      vaultPublicKey: '   ',
      policyAttachment: 'policy_set',
    },
  });
  assert.match(profile.address ?? '', /^0x[0-9a-fA-F]{40}$/);

  const address = walletProfile.resolveWalletAddress({
    wallet: {
      vaultPublicKey: '   ',
      address: '0x0000000000000000000000000000000000000001',
      policyAttachment: 'policy_set',
    },
  });
  assert.equal(address, '0x0000000000000000000000000000000000000001');
});

test('resolveWalletProfile falls back to the latest bootstrap artifact', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-profile-'));
  process.env.AGENTPAY_HOME = tempRoot;

  try {
    const walletProfile = await import(
      walletProfileModulePath.href + `?case=${Date.now()}-fallback`
    );
    const bootstrapPath = path.join(tempRoot, 'bootstrap-100-200.json');
    writePrivateJsonFile(
      bootstrapPath,
      bootstrapPayload({
        vault_public_key: '03abcdef',
        policy_attachment: 'policy_set',
        attached_policy_ids: ['policy-per-tx', 'policy-daily'],
      }),
    );

    const profile = walletProfile.resolveWalletProfile({});

    assert.equal(profile.vaultPublicKey, '03abcdef');
    assert.equal(profile.policyAttachment, 'policy_set');
    assert.deepEqual(profile.attachedPolicyIds, ['policy-per-tx', 'policy-daily']);
    assert.match(profile.address ?? '', /^0x[a-fA-F0-9]{40}$/);
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('resolveWalletProfile ignores expired bootstrap artifacts when a newer valid artifact exists', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-profile-expired-'));
  process.env.AGENTPAY_HOME = tempRoot;

  try {
    const walletProfile = await import(
      walletProfileModulePath.href + `?case=${Date.now()}-expired-fallback`
    );
    writePrivateJsonFile(
      path.join(tempRoot, 'bootstrap-200-300.json'),
      bootstrapPayload({
        lease_expires_at: '2000-01-01T00:00:00Z',
        vault_public_key: '031111111111111111111111111111111111111111111111111111111111111111',
        policy_attachment: 'policy_set',
      }),
    );
    writePrivateJsonFile(
      path.join(tempRoot, 'bootstrap-100-200.json'),
      bootstrapPayload({
        vault_public_key: '032222222222222222222222222222222222222222222222222222222222222222',
        policy_attachment: 'policy_set',
      }),
    );

    const profile = walletProfile.resolveWalletProfile({});

    assert.equal(
      profile.vaultPublicKey,
      '032222222222222222222222222222222222222222222222222222222222222222',
    );
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('resolveWalletProfile rejects expired bootstrap artifacts when they are the only fallback', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-profile-expired-only-'));
  process.env.AGENTPAY_HOME = tempRoot;

  try {
    const walletProfile = await import(
      walletProfileModulePath.href + `?case=${Date.now()}-expired-only`
    );
    writePrivateJsonFile(
      path.join(tempRoot, 'bootstrap-100-200.json'),
      bootstrapPayload({
        lease_expires_at: '2000-01-01T00:00:00Z',
        policy_attachment: 'policy_set',
      }),
    );

    assert.throws(
      () => walletProfile.resolveWalletProfile({}),
      /wallet metadata is unavailable; rerun `agentpay admin setup` or import a bootstrap file first/,
    );
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('resolveWalletProfileWithBalances fetches balances for configured tokens and builtin native assets', async () => {
  const walletProfile = await import(walletProfileModulePath.href + `?case=${Date.now()}-balances`);
  const account = privateKeyToAccount(`0x${'33'.repeat(32)}`);
  const nativeCalls = [];
  const erc20Calls = [];

  const profile = await walletProfile.resolveWalletProfileWithBalances(
    {
      wallet: {
        vaultPublicKey: account.publicKey,
        policyAttachment: 'policy_set',
      },
      chains: {
        eth: {
          chainId: 1,
          name: 'ETH',
          rpcUrl: 'https://eth.llamarpc.com',
        },
        bsc: {
          chainId: 56,
          name: 'BSC',
          rpcUrl: 'https://bsc.drpc.org',
        },
      },
      tokens: {
        usd1: {
          name: 'USD1',
          symbol: 'USD1',
          chains: {
            eth: {
              chainId: 1,
              isNative: false,
              address: '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
              decimals: 18,
            },
            bsc: {
              chainId: 56,
              isNative: false,
              address: '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
              decimals: 18,
            },
          },
        },
      },
    },
    {
      getNativeBalance: async (rpcUrl, address) => {
        nativeCalls.push({ rpcUrl, address });
        return {
          raw: 500000000000000000n,
          formatted: '0.5',
        };
      },
      getTokenBalance: async (rpcUrl, token, owner, decimals) => {
        erc20Calls.push({ rpcUrl, token, owner, decimals });
        return {
          raw: 123000000000000000000n,
          decimals: decimals ?? 18,
          name: 'USD1',
          symbol: 'USD1',
          formatted: '123',
        };
      },
    },
  );

  assert.equal(profile.address, account.address);
  assert.deepEqual(nativeCalls, [
    {
      rpcUrl: 'https://eth.llamarpc.com',
      address: account.address,
    },
    {
      rpcUrl: 'https://bsc.drpc.org',
      address: account.address,
    },
  ]);
  assert.deepEqual(erc20Calls, [
    {
      rpcUrl: 'https://eth.llamarpc.com',
      token: '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
      owner: account.address,
      decimals: 18,
    },
    {
      rpcUrl: 'https://bsc.drpc.org',
      token: '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
      owner: account.address,
      decimals: 18,
    },
  ]);
  assert.deepEqual(profile.balances, [
    {
      tokenKey: 'eth',
      symbol: 'ETH',
      name: 'ETH',
      chainKey: 'eth',
      chainName: 'ETH',
      chainId: 1,
      rpcUrl: 'https://eth.llamarpc.com',
      kind: 'native',
      tokenAddress: 'native',
      decimals: 18,
      balance: {
        raw: '500000000000000000',
        formatted: '0.5',
      },
    },
    {
      tokenKey: 'usd1',
      symbol: 'USD1',
      name: 'USD1',
      chainKey: 'eth',
      chainName: 'ETH',
      chainId: 1,
      rpcUrl: 'https://eth.llamarpc.com',
      kind: 'erc20',
      tokenAddress: '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
      decimals: 18,
      balance: {
        raw: '123000000000000000000',
        formatted: '123',
      },
    },
    {
      tokenKey: 'bnb',
      symbol: 'BNB',
      name: 'BNB',
      chainKey: 'bsc',
      chainName: 'BSC',
      chainId: 56,
      rpcUrl: 'https://bsc.drpc.org',
      kind: 'native',
      tokenAddress: 'native',
      decimals: 18,
      balance: {
        raw: '500000000000000000',
        formatted: '0.5',
      },
    },
    {
      tokenKey: 'usd1',
      symbol: 'USD1',
      name: 'USD1',
      chainKey: 'bsc',
      chainName: 'BSC',
      chainId: 56,
      rpcUrl: 'https://bsc.drpc.org',
      kind: 'erc20',
      tokenAddress: '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
      decimals: 18,
      balance: {
        raw: '123000000000000000000',
        formatted: '123',
      },
    },
  ]);
});

test('resolveWalletProfileWithBalances does not duplicate configured native token balances', async () => {
  const walletProfile = await import(
    walletProfileModulePath.href + `?case=${Date.now()}-balances-native-dedupe`
  );
  const account = privateKeyToAccount(`0x${'34'.repeat(32)}`);
  const nativeCalls = [];

  const profile = await walletProfile.resolveWalletProfileWithBalances(
    {
      wallet: {
        vaultPublicKey: account.publicKey,
        policyAttachment: 'policy_set',
      },
      chains: {
        eth: {
          chainId: 1,
          name: 'ETH',
          rpcUrl: 'https://eth.llamarpc.com',
        },
        bsc: {
          chainId: 56,
          name: 'BSC',
          rpcUrl: 'https://bsc.drpc.org',
        },
      },
      tokens: {
        eth: {
          symbol: 'ETH',
          chains: {
            eth: {
              chainId: 1,
              isNative: true,
              decimals: 18,
            },
          },
        },
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
      },
    },
    {
      getNativeBalance: async (rpcUrl, address) => {
        nativeCalls.push({ rpcUrl, address });
        return {
          raw: 1000000000000000000n,
          formatted: '1',
        };
      },
      getTokenBalance: async () => {
        throw new Error('no erc20 balances expected');
      },
    },
  );

  assert.deepEqual(nativeCalls, [
    {
      rpcUrl: 'https://eth.llamarpc.com',
      address: account.address,
    },
    {
      rpcUrl: 'https://bsc.drpc.org',
      address: account.address,
    },
  ]);
  assert.deepEqual(
    profile.balances.map((entry) => [entry.tokenKey, entry.chainKey, entry.kind]),
    [
      ['eth', 'eth', 'native'],
      ['bnb', 'bsc', 'native'],
    ],
  );
});

test('resolveWalletProfileWithBalances suppresses native balances on tempo chains', async () => {
  const walletProfile = await import(
    walletProfileModulePath.href + `?case=${Date.now()}-balances-tempo-native-suppressed`
  );
  const account = privateKeyToAccount(`0x${'35'.repeat(32)}`);
  const nativeCalls = [];
  const erc20Calls = [];

  const profile = await walletProfile.resolveWalletProfileWithBalances(
    {
      wallet: {
        vaultPublicKey: account.publicKey,
        policyAttachment: 'policy_set',
      },
      chains: {
        tempo: {
          chainId: 4217,
          name: 'Tempo Mainnet',
          rpcUrl: 'https://rpc.tempo.xyz',
        },
      },
      tokens: {
        usd: {
          name: 'USD',
          symbol: 'USD',
          chains: {
            tempo: {
              chainId: 4217,
              isNative: true,
              decimals: 6,
            },
          },
        },
        'usdc.e': {
          name: 'Bridged USDC (Stargate)',
          symbol: 'USDC.e',
          chains: {
            tempo: {
              chainId: 4217,
              isNative: false,
              address: '0x20c000000000000000000000b9537d11c60e8b50',
              decimals: 6,
            },
          },
        },
      },
    },
    {
      getNativeBalance: async (rpcUrl, address) => {
        nativeCalls.push({ rpcUrl, address });
        return {
          raw: 42424242424242424242n,
          formatted: '42424242.424242',
        };
      },
      getTokenBalance: async (rpcUrl, token, owner, decimals) => {
        erc20Calls.push({ rpcUrl, token, owner, decimals });
        return {
          raw: 73468n,
          decimals: decimals ?? 6,
          name: 'Bridged USDC (Stargate)',
          symbol: 'USDC.e',
          formatted: '0.073468',
        };
      },
    },
  );

  assert.deepEqual(nativeCalls, []);
  assert.deepEqual(erc20Calls, [
    {
      rpcUrl: 'https://rpc.tempo.xyz',
      token: '0x20c000000000000000000000b9537d11c60e8b50',
      owner: account.address,
      decimals: 6,
    },
  ]);
  assert.deepEqual(
    profile.balances.map((entry) => [entry.tokenKey, entry.chainKey, entry.kind, entry.symbol]),
    [['usdc.e', 'tempo', 'erc20', 'USDC.e']],
  );
  assert.equal(profile.balances[0].balance?.formatted, '0.073468');
});

test('resolveWalletProfileWithBalances skips missing token maps and empty chain maps', async () => {
  const walletProfile = await import(
    walletProfileModulePath.href + `?case=${Date.now()}-balances-empty-token-maps`
  );
  const account = privateKeyToAccount(`0x${'77'.repeat(32)}`);
  const deps = {
    getNativeBalance: async () => {
      throw new Error('should not read native balances');
    },
    getTokenBalance: async () => {
      throw new Error('should not read token balances');
    },
  };

  const withoutTokens = await walletProfile.resolveWalletProfileWithBalances(
    {
      wallet: {
        vaultPublicKey: account.publicKey,
        policyAttachment: 'policy_set',
      },
    },
    deps,
  );
  assert.deepEqual(withoutTokens.balances, []);

  const withEmptyChainMap = await walletProfile.resolveWalletProfileWithBalances(
    {
      wallet: {
        vaultPublicKey: account.publicKey,
        policyAttachment: 'policy_set',
      },
      tokens: {
        ghost: {
          name: 'Ghost',
          symbol: 'GST',
        },
      },
    },
    deps,
  );
  assert.deepEqual(withEmptyChainMap.balances, []);
});

test('resolveWalletProfileWithBalances falls back to chain keys, target metadata, and <unset> token addresses', async () => {
  const walletProfile = await import(
    walletProfileModulePath.href + `?case=${Date.now()}-balances-fallbacks-and-ordering`
  );
  const account = privateKeyToAccount(`0x${'88'.repeat(32)}`);

  const profile = await walletProfile.resolveWalletProfileWithBalances(
    {
      wallet: {
        vaultPublicKey: account.publicKey,
        policyAttachment: 'policy_set',
      },
      chains: {
        alpha: {
          chainId: 1,
          name: 'Alpha',
          rpcUrl: 'https://alpha.example',
        },
        beta: {
          chainId: 1,
          name: 'Beta',
          rpcUrl: 'https://beta.example',
        },
      },
      tokens: {
        ddd: {
          name: 'Token D',
          symbol: 'AAA',
          chains: {
            alpha: {
              chainId: 1,
              isNative: false,
              address: '0x0000000000000000000000000000000000000004',
              decimals: 18,
            },
          },
        },
        aaa: {
          name: 'Token A',
          symbol: 'AAA',
          chains: {
            alpha: {
              chainId: 1,
              isNative: false,
              address: '0x0000000000000000000000000000000000000001',
              decimals: 18,
            },
          },
        },
        bbb: {
          name: 'Token B',
          symbol: 'BBB',
          chains: {
            alpha: {
              chainId: 1,
              isNative: false,
              address: '0x0000000000000000000000000000000000000002',
              decimals: 6,
            },
          },
        },
        ccc: {
          name: 'Token C',
          symbol: 'CCC',
          chains: {
            beta: {
              chainId: 1,
              isNative: false,
              address: '0x0000000000000000000000000000000000000003',
              decimals: 6,
            },
          },
        },
        unset: {
          name: 'Unset',
          symbol: 'UNS',
          chains: {
            beta: {
              chainId: 1,
              isNative: false,
              address: '   ',
              decimals: 6,
            },
          },
        },
      },
    },
    {
      getNativeBalance: async () => {
        throw new Error('no native balances expected');
      },
      getTokenBalance: async (_rpcUrl, _token, _owner, decimals) => ({
        raw: 1n,
        decimals: decimals ?? 18,
        name: null,
        symbol: null,
        formatted: '1',
      }),
    },
  );

  assert.deepEqual(
    profile.balances.map((balance) => [balance.chainKey, balance.symbol, balance.tokenKey]),
    [
      ['alpha', 'AAA', 'aaa'],
      ['alpha', 'AAA', 'ddd'],
      ['alpha', 'BBB', 'bbb'],
      ['beta', 'CCC', 'ccc'],
      ['beta', 'UNS', 'unset'],
    ],
  );
  assert.equal(profile.balances[0].name, 'Token A');
  assert.equal(profile.balances[0].symbol, 'AAA');
  assert.equal(profile.balances[0].chainName, 'Alpha');
  assert.equal(profile.balances[4].tokenAddress, '<unset>');
  assert.match(profile.balances[4].error ?? '', /configured token address/);
});

test('formatWalletProfileText prints the wallet policy summary', async () => {
  const walletProfile = await import(walletProfileModulePath.href + `?case=${Date.now()}-format`);

  const rendered = walletProfile.formatWalletProfileText({
    vaultPublicKey: '0x1234',
    address: '0x0000000000000000000000000000000000000001',
    agentKeyId: '00000000-0000-0000-0000-000000000001',
    policyAttachment: 'policy_set',
    attachedPolicyIds: ['policy-1', 'policy-2'],
    policyNote: 'persisted',
    networkScope: '1',
    assetScope: 'usd1',
    recipientScope: 'all recipients',
    balances: [
      {
        tokenKey: 'usd1',
        symbol: 'USD1',
        name: 'USD1',
        chainKey: 'eth',
        chainName: 'ETH',
        chainId: 1,
        rpcUrl: 'https://eth.llamarpc.com',
        kind: 'erc20',
        tokenAddress: '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
        decimals: 18,
        balance: {
          raw: '1000000000000000000',
          formatted: '1',
        },
      },
    ],
  });

  assert.match(rendered, /Public Key: 0x1234/);
  assert.match(rendered, /Address: 0x0000000000000000000000000000000000000001/);
  assert.match(rendered, /Policy Attachment: policy_set/);
  assert.match(rendered, /Attached Policy IDs: policy-1, policy-2/);
  assert.match(rendered, /Balances:/);
  assert.match(rendered, /USD1 on eth \(1\): 1/);
});

test('formatWalletProfileText omits empty addresses and renders zero for missing balance payloads', async () => {
  const walletProfile = await import(
    walletProfileModulePath.href + `?case=${Date.now()}-format-empty-address-and-zero-balance`
  );

  const rendered = walletProfile.formatWalletProfileText({
    vaultPublicKey: '0x1234',
    policyAttachment: 'policy_set',
    balances: [
      {
        tokenKey: 'usd1',
        symbol: 'USD1',
        name: 'USD1',
        chainKey: 'eth',
        chainName: 'ETH',
        chainId: 1,
        rpcUrl: 'https://eth.llamarpc.com',
        kind: 'erc20',
        tokenAddress: '0x0000000000000000000000000000000000000001',
        decimals: 18,
      },
    ],
  });

  assert.doesNotMatch(rendered, /^Address:/m);
  assert.match(rendered, /USD1 on eth \(1\): 0/);
});

test('resolveWalletProfile can backfill from bootstrap artifacts by wallet public key or address', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-wallet-profile-match-'));
  process.env.AGENTPAY_HOME = tempRoot;

  try {
    const walletProfile = await import(
      walletProfileModulePath.href + `?case=${Date.now()}-match-fallbacks`
    );
    const account = privateKeyToAccount(`0x${'55'.repeat(32)}`);
    writePrivateJsonFile(
      path.join(tempRoot, 'bootstrap-100-200.json'),
      bootstrapPayload({
        vault_key_id: '22222222-2222-2222-2222-222222222222',
        vault_public_key: account.publicKey,
        agent_key_id: '00000000-0000-0000-0000-0000000000aa',
        policy_attachment: 'policy_set',
      }),
    );

    const publicKeyMatch = walletProfile.resolveWalletProfile({
      wallet: {
        vaultPublicKey: account.publicKey,
        policyAttachment: 'policy_set',
      },
    });
    assert.equal(publicKeyMatch.vaultKeyId, '22222222-2222-2222-2222-222222222222');
    assert.equal(publicKeyMatch.address, account.address);

    const addressMatch = walletProfile.resolveWalletProfile({
      wallet: {
        vaultPublicKey: '03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        address: account.address,
        policyAttachment: 'policy_set',
      },
    });
    assert.equal(addressMatch.vaultKeyId, '22222222-2222-2222-2222-222222222222');
    assert.equal(addressMatch.address, account.address);
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('resolveWalletAddress fails closed when a configured wallet address is invalid', async () => {
  const walletProfile = await import(
    walletProfileModulePath.href + `?case=${Date.now()}-invalid-address-value`
  );

  assert.throws(
    () =>
      walletProfile.resolveWalletAddress({
        wallet: {
          vaultPublicKey: '03abcdef',
          address: 'not-an-evm-address',
          policyAttachment: 'policy_set',
        },
      }),
    /wallet address is unavailable/,
  );
});

test('resolveWalletProfileWithBalances surfaces native/erc20 fetch failures and invalid token addresses', async () => {
  const walletProfile = await import(
    walletProfileModulePath.href + `?case=${Date.now()}-balance-errors`
  );
  const account = privateKeyToAccount(`0x${'66'.repeat(32)}`);

  const profile = await walletProfile.resolveWalletProfileWithBalances(
    {
      wallet: {
        vaultPublicKey: account.publicKey,
        policyAttachment: 'policy_set',
      },
      chains: {
        eth: {
          chainId: 1,
          name: 'ETH',
          rpcUrl: 'https://eth.llamarpc.com',
        },
        bsc: {
          chainId: 56,
          name: 'BSC',
          rpcUrl: 'https://bsc.drpc.org',
        },
      },
      tokens: {
        eth: {
          name: 'ETH',
          symbol: 'ETH',
          chains: {
            eth: {
              chainId: 1,
              isNative: true,
              decimals: 18,
            },
          },
        },
        invalid: {
          name: 'Invalid',
          symbol: 'BAD',
          chains: {
            bsc: {
              chainId: 56,
              isNative: false,
              decimals: 18,
              address: 'invalid-address',
            },
          },
        },
        broken: {
          name: 'Broken',
          symbol: 'BRK',
          chains: {
            eth: {
              chainId: 1,
              isNative: false,
              decimals: 6,
              address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
            },
          },
        },
      },
    },
    {
      getNativeBalance: async () => {
        throw 'native rpc unavailable';
      },
      getTokenBalance: async () => {
        throw new Error('erc20 rpc unavailable');
      },
    },
  );

  assert.equal(profile.balances.length, 4);
  const balanceErrors = profile.balances.map((entry) => entry.error ?? '');
  assert.ok(balanceErrors.some((message) => /native rpc unavailable/.test(message)));
  assert.ok(balanceErrors.some((message) => /configured token address/.test(message)));
  assert.ok(balanceErrors.some((message) => /erc20 rpc unavailable/.test(message)));

  const rendered = walletProfile.formatWalletProfileText(profile);
  assert.match(rendered, /error: native rpc unavailable/);
  assert.match(rendered, /error: configured token address/);
});
