import assert from 'node:assert/strict';
import test from 'node:test';
import { decodeFunctionData, erc20Abi } from 'viem';

const modulePath = new URL('../src/lib/asset-broadcast.ts', import.meta.url);

test('encodeErc20TransferData encodes ERC-20 transfer calldata', async () => {
  const assetBroadcast = await import(`${modulePath.href}?case=${Date.now()}-transfer`);
  const recipient = '0x1111111111111111111111111111111111111111';
  const data = assetBroadcast.encodeErc20TransferData(recipient, 25n);
  const decoded = decodeFunctionData({ abi: erc20Abi, data });

  assert.equal(decoded.functionName, 'transfer');
  assert.deepEqual(decoded.args, [recipient, 25n]);
});

test('encodeErc20ApproveData encodes ERC-20 approve calldata', async () => {
  const assetBroadcast = await import(`${modulePath.href}?case=${Date.now()}-approve`);
  const spender = '0x2222222222222222222222222222222222222222';
  const data = assetBroadcast.encodeErc20ApproveData(spender, 50n);
  const decoded = decodeFunctionData({ abi: erc20Abi, data });

  assert.equal(decoded.functionName, 'approve');
  assert.deepEqual(decoded.args, [spender, 50n]);
});

test('resolveAssetBroadcastPlan fills nonce gas and fees from RPC deps', async () => {
  const assetBroadcast = await import(`${modulePath.href}?case=${Date.now()}-plan`);
  const calls = [];

  const plan = await assetBroadcast.resolveAssetBroadcastPlan(
    {
      rpcUrl: 'https://rpc.example',
      chainId: 1,
      from: '0x3333333333333333333333333333333333333333',
      to: '0x4444444444444444444444444444444444444444',
      valueWei: 0n,
      dataHex: '0xabcdef',
      txType: '0x02',
    },
    {
      getChainInfo: async (rpcUrl) => {
        calls.push(['chain', rpcUrl]);
        return { chainId: 1, latestBlockNumber: 123n };
      },
      assertRpcChainIdMatches: (expected, actual) => {
        calls.push(['assert', expected, actual]);
        assert.equal(expected, actual);
      },
      getNonce: async (rpcUrl, from) => {
        calls.push(['nonce', rpcUrl, from]);
        return 7;
      },
      estimateGas: async (args) => {
        calls.push(['gas', args]);
        return 21001n;
      },
      estimateFees: async (rpcUrl) => {
        calls.push(['fees', rpcUrl]);
        return {
          gasPrice: 2n,
          maxFeePerGas: 3n,
          maxPriorityFeePerGas: 1n,
        };
      },
    },
  );

  assert.deepEqual(plan, {
    rpcUrl: 'https://rpc.example',
    chainId: 1,
    from: '0x3333333333333333333333333333333333333333',
    to: '0x4444444444444444444444444444444444444444',
    valueWei: 0n,
    dataHex: '0xabcdef',
    nonce: 7,
    gasLimit: 21001n,
    maxFeePerGasWei: 3n,
    maxPriorityFeePerGasWei: 1n,
    txType: '0x02',
  });
  assert.equal(calls.length, 5);
});

test('resolveAssetBroadcastPlan honors explicit fee inputs and rejects missing fee estimates', async () => {
  const assetBroadcast = await import(`${modulePath.href}?case=${Date.now()}-plan-fee-edges`);

  const explicitPlan = await assetBroadcast.resolveAssetBroadcastPlan(
    {
      rpcUrl: 'https://rpc.example',
      chainId: 1,
      from: '0x3333333333333333333333333333333333333333',
      to: '0x4444444444444444444444444444444444444444',
      valueWei: 0n,
      dataHex: '0xabcdef',
      nonce: 3,
      gasLimit: 21000n,
      maxFeePerGasWei: 9n,
      maxPriorityFeePerGasWei: 4n,
      txType: '0x02',
    },
    {
      getChainInfo: async () => ({ chainId: 1 }),
      assertRpcChainIdMatches: () => {},
      getNonce: async () => {
        throw new Error('nonce should not be queried when explicitly provided');
      },
      estimateGas: async () => {
        throw new Error('gas should not be estimated when explicitly provided');
      },
      estimateFees: async () => ({
        gasPrice: 2n,
        maxFeePerGas: 3n,
        maxPriorityFeePerGas: 1n,
      }),
    },
  );

  assert.equal(explicitPlan.maxFeePerGasWei, 9n);
  assert.equal(explicitPlan.maxPriorityFeePerGasWei, 4n);

  const gasPriceFallbackPlan = await assetBroadcast.resolveAssetBroadcastPlan(
    {
      rpcUrl: 'https://rpc.example',
      chainId: 1,
      from: '0x3333333333333333333333333333333333333333',
      to: '0x4444444444444444444444444444444444444444',
      valueWei: 0n,
      dataHex: '0xabcdef',
      txType: '0x02',
    },
    {
      getChainInfo: async () => ({ chainId: 1 }),
      assertRpcChainIdMatches: () => {},
      getNonce: async () => 1,
      estimateGas: async () => 21000n,
      estimateFees: async () => ({
        gasPrice: 7n,
        maxFeePerGas: null,
        maxPriorityFeePerGas: null,
      }),
    },
  );

  assert.equal(gasPriceFallbackPlan.maxFeePerGasWei, 7n);
  assert.equal(gasPriceFallbackPlan.maxPriorityFeePerGasWei, 7n);

  await assert.rejects(
    assetBroadcast.resolveAssetBroadcastPlan(
      {
        rpcUrl: 'https://rpc.example',
        chainId: 1,
        from: '0x3333333333333333333333333333333333333333',
        to: '0x4444444444444444444444444444444444444444',
        valueWei: 0n,
        dataHex: '0xabcdef',
        txType: '0x02',
      },
      {
        getChainInfo: async () => ({ chainId: 1 }),
        assertRpcChainIdMatches: () => {},
        getNonce: async () => 1,
        estimateGas: async () => 21000n,
        estimateFees: async () => ({
          gasPrice: null,
          maxFeePerGas: null,
          maxPriorityFeePerGas: null,
        }),
      },
    ),
    /Could not determine maxFeePerGas/,
  );

  const zeroPriorityFallbackPlan = await assetBroadcast.resolveAssetBroadcastPlan(
    {
      rpcUrl: 'https://rpc.example',
      chainId: 1,
      from: '0x3333333333333333333333333333333333333333',
      to: '0x4444444444444444444444444444444444444444',
      valueWei: 0n,
      dataHex: '0xabcdef',
      maxFeePerGasWei: 9n,
      txType: '0x02',
    },
    {
      getChainInfo: async () => ({ chainId: 1 }),
      assertRpcChainIdMatches: () => {},
      getNonce: async () => 1,
      estimateGas: async () => 21000n,
      estimateFees: async () => ({
        gasPrice: 0n,
        maxFeePerGas: 9n,
        maxPriorityFeePerGas: null,
      }),
    },
  );
  assert.equal(zeroPriorityFallbackPlan.maxPriorityFeePerGasWei, 0n);

  const explicitZeroPriorityPlan = await assetBroadcast.resolveAssetBroadcastPlan(
    {
      rpcUrl: 'https://rpc.example',
      chainId: 1,
      from: '0x3333333333333333333333333333333333333333',
      to: '0x4444444444444444444444444444444444444444',
      valueWei: 0n,
      dataHex: '0xabcdef',
      maxFeePerGasWei: 9n,
      txType: '0x02',
    },
    {
      getChainInfo: async () => ({ chainId: 1 }),
      assertRpcChainIdMatches: () => {},
      getNonce: async () => 1,
      estimateGas: async () => 21000n,
      estimateFees: async () => ({
        gasPrice: 7n,
        maxFeePerGas: 9n,
        maxPriorityFeePerGas: 0n,
      }),
    },
  );
  assert.equal(explicitZeroPriorityPlan.maxPriorityFeePerGasWei, 0n);
});

test('completeAssetBroadcast verifies then broadcasts signed raw tx', async () => {
  const assetBroadcast = await import(`${modulePath.href}?case=${Date.now()}-complete`);
  const events = [];
  const plan = {
    rpcUrl: 'https://rpc.example',
    chainId: 1,
    from: '0x5555555555555555555555555555555555555555',
    to: '0x6666666666666666666666666666666666666666',
    valueWei: 0n,
    dataHex: '0xabcdef',
    nonce: 9,
    gasLimit: 52000n,
    maxFeePerGasWei: 20n,
    maxPriorityFeePerGasWei: 2n,
    txType: '0x02',
  };

  const result = await assetBroadcast.completeAssetBroadcast(
    plan,
    {
      raw_tx_hex: '0xdeadbeef',
      tx_hash_hex: '0xsigned',
    },
    {
      assertSignedBroadcastTransactionMatchesRequest: async (expected) => {
        events.push(['verify', expected]);
        return { nonce: 11 };
      },
      broadcastRawTransaction: async (rpcUrl, rawTxHex) => {
        events.push(['broadcast', rpcUrl, rawTxHex]);
        return '0xnetwork';
      },
    },
  );

  assert.deepEqual(result, {
    signedTxHash: '0xsigned',
    networkTxHash: '0xnetwork',
    signedNonce: 11,
  });
  assert.equal(events[0][0], 'verify');
  assert.equal(events[0][1].allowHigherNonce, false);
  assert.deepEqual(events[1], ['broadcast', 'https://rpc.example', '0xdeadbeef']);
});

test('completeAssetBroadcast rejects missing raw signed transactions and tolerates missing signed tx hashes', async () => {
  const assetBroadcast = await import(`${modulePath.href}?case=${Date.now()}-complete-missing-rawtx`);
  const plan = {
    rpcUrl: 'https://rpc.example',
    chainId: 1,
    from: '0x5555555555555555555555555555555555555555',
    to: '0x6666666666666666666666666666666666666666',
    valueWei: 0n,
    dataHex: '0xabcdef',
    nonce: 9,
    gasLimit: 52000n,
    maxFeePerGasWei: 20n,
    maxPriorityFeePerGasWei: 2n,
    txType: '0x02',
  };

  await assert.rejects(
    assetBroadcast.completeAssetBroadcast(
      plan,
      {},
      {
        assertSignedBroadcastTransactionMatchesRequest: async () => ({ nonce: 9 }),
        broadcastRawTransaction: async () => '0xnetwork',
      },
    ),
    /did not return raw_tx_hex/,
  );

  const result = await assetBroadcast.completeAssetBroadcast(
    plan,
    {
      raw_tx_hex: '0xdeadbeef',
    },
    {
      assertSignedBroadcastTransactionMatchesRequest: async () => ({ nonce: 9 }),
      broadcastRawTransaction: async () => '0xnetwork',
    },
  );

  assert.equal(result.signedTxHash, null);
});

test('formatBroadcastedAssetOutput redacts raw tx and signature by default', async () => {
  const assetBroadcast = await import(`${modulePath.href}?case=${Date.now()}-format`);
  const output = assetBroadcast.formatBroadcastedAssetOutput({
    command: 'transfer',
    counterparty: '0x7777777777777777777777777777777777777777',
    asset: {
      assetId: 'erc20:0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
      decimals: 18,
      symbol: 'USD1',
    },
    signed: {
      command: 'broadcast',
      network: '1',
      asset: 'erc20:0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
      counterparty: '0x9999999999999999999999999999999999999999',
      amount_wei: '1000000000000000000',
      signature_hex: '0xsig',
      raw_tx_hex: '0xraw',
      tx_hash_hex: '0xsigned',
      r_hex: '0xr',
      s_hex: '0xs',
      v: 28,
    },
    plan: {
      rpcUrl: 'https://rpc.example',
      chainId: 1,
      from: '0x8888888888888888888888888888888888888888',
      to: '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
      valueWei: 0n,
      dataHex: '0xabcdef',
      nonce: 12,
      gasLimit: 65000n,
      maxFeePerGasWei: 3n,
      maxPriorityFeePerGasWei: 1n,
      txType: '0x02',
    },
    signedNonce: 15,
    networkTxHash: '0xnetwork',
    revealRawTx: false,
    revealSignature: false,
  });

  assert.equal(output.command, 'transfer');
  assert.equal(output.asset, 'USD1');
  assert.equal(output.counterparty, '0x7777777777777777777777777777777777777777');
  assert.equal(output.amount, '1');
  assert.equal(output.nonce, 15);
  assert.equal(output.rawTxHex, '<redacted>');
  assert.equal(output.signer, '<redacted>');
  assert.equal(output.networkTxHash, '0xnetwork');
  assert.equal('raw_tx_hex' in output, false);
  assert.equal('tx_hash_hex' in output, false);
});

test('formatBroadcastedAssetOutput can reveal raw tx and signature fields and fall back to plan nonce', async () => {
  const assetBroadcast = await import(`${modulePath.href}?case=${Date.now()}-format-reveal`);
  const output = assetBroadcast.formatBroadcastedAssetOutput({
    command: 'approve',
    counterparty: '0x7777777777777777777777777777777777777777',
    asset: {
      assetId: 'erc20:0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
      decimals: 18,
      symbol: 'USD1',
    },
    signed: {
      command: 'broadcast',
      network: '1',
      asset: 'erc20:0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
      counterparty: '0x9999999999999999999999999999999999999999',
      amount_wei: '1000000000000000000',
      signature_hex: '0xsig',
      raw_tx_hex: undefined,
      tx_hash_hex: undefined,
    },
    plan: {
      rpcUrl: 'https://rpc.example',
      chainId: 1,
      from: '0x8888888888888888888888888888888888888888',
      to: '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
      valueWei: 0n,
      dataHex: '0xabcdef',
      nonce: 12,
      gasLimit: 65000n,
      maxFeePerGasWei: 3n,
      maxPriorityFeePerGasWei: 1n,
      txType: '0x02',
    },
    networkTxHash: '0xnetwork',
    revealRawTx: true,
    revealSignature: true,
  });

  assert.equal(output.nonce, 12);
  assert.equal(output.signedTxHash, null);
  assert.equal(output.rawTxHex, null);
  assert.deepEqual(output.signer, {
    r: null,
    s: null,
    v: null,
  });
});

test('waitForOnchainReceipt polls until a receipt is available', async () => {
  const assetBroadcast = await import(`${modulePath.href}?case=${Date.now()}-receipt-found`);
  const calls = [];
  let now = 0;

  const result = await assetBroadcast.waitForOnchainReceipt(
    {
      rpcUrl: 'https://rpc.example',
      txHash: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      timeoutMs: 30_000,
      intervalMs: 2_000,
    },
    {
      getTransactionReceiptByHash: async (rpcUrl, hash) => {
        calls.push([rpcUrl, hash]);
        if (calls.length < 3) {
          throw new Error('Transaction receipt for 0xaaa was not found');
        }
        return {
          blockNumber: 123n,
          transactionIndex: 4,
          status: 'success',
        };
      },
      now: () => now,
      sleep: async (ms) => {
        now += ms;
      },
    },
  );

  assert.equal(result.timedOut, false);
  assert.equal(result.receipt?.status, 'success');
  assert.equal(result.receipt?.blockNumber, 123n);
  assert.equal(calls.length, 3);
});

test('waitForOnchainReceipt times out after 30 seconds by default', async () => {
  const assetBroadcast = await import(`${modulePath.href}?case=${Date.now()}-receipt-timeout`);
  let now = 0;
  let attempts = 0;

  const result = await assetBroadcast.waitForOnchainReceipt(
    {
      rpcUrl: 'https://rpc.example',
      txHash: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    },
    {
      getTransactionReceiptByHash: async () => {
        attempts += 1;
        throw new Error('Transaction receipt for 0xbbb could not be found');
      },
      now: () => now,
      sleep: async (ms) => {
        now += ms;
      },
    },
  );

  assert.equal(result.timedOut, true);
  assert.equal(result.receipt, null);
  assert.ok(attempts >= 2);
});

test('waitForOnchainReceipt rethrows non-pending errors and covers default now/sleep fallbacks', async () => {
  const assetBroadcast = await import(`${modulePath.href}?case=${Date.now()}-receipt-error-edges`);

  await assert.rejects(
    assetBroadcast.waitForOnchainReceipt(
      {
        rpcUrl: 'https://rpc.example',
        txHash: '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        timeoutMs: 1,
        intervalMs: 0,
      },
      {
        getTransactionReceiptByHash: async () => {
          throw 'rpc exploded';
        },
        now: () => 0,
        sleep: async () => {},
      },
    ),
    /rpc exploded/,
  );

  await assert.rejects(
    assetBroadcast.waitForOnchainReceipt(
      {
        rpcUrl: 'https://rpc.example',
        txHash: '0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        timeoutMs: 1,
        intervalMs: 0,
      },
      {
        getTransactionReceiptByHash: async () => {
          throw new Error('node reported an unrelated execution failure');
        },
        now: () => 0,
        sleep: async () => {},
      },
    ),
    /unrelated execution failure/,
  );

  const missingByAlternateMessage = await assetBroadcast.waitForOnchainReceipt(
    {
      rpcUrl: 'https://rpc.example',
      txHash: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
      timeoutMs: 0,
      intervalMs: 0,
    },
    {
      getTransactionReceiptByHash: async () => {
        throw new Error('Transaction receipt does not exist yet');
      },
      sleep: async () => {},
    },
  );
  assert.equal(missingByAlternateMessage.timedOut, true);

  let slept = false;
  const pendingByAlternateMessage = await assetBroadcast.waitForOnchainReceipt(
    {
      rpcUrl: 'https://rpc.example',
      txHash: '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      timeoutMs: 1,
      intervalMs: 0,
    },
    {
      getTransactionReceiptByHash: async () => {
        throw new Error('Transaction receipt was not found yet');
      },
      now: (() => {
        let calls = 0;
        return () => {
          calls += 1;
          return calls === 1 ? 0 : 1;
        };
      })(),
    },
  );
  slept = true;
  assert.equal(pendingByAlternateMessage.timedOut, true);
  assert.equal(slept, true);
});
