import assert from 'node:assert/strict';
import test from 'node:test';

import { Connection, Keypair, PublicKey, SystemProgram } from '@solana/web3.js';

const modulePath = new URL('../src/lib/solana-transfer.ts', import.meta.url);

function nonceAccountData({ authority, nonce }) {
  const data = Buffer.alloc(80);
  data.writeUInt32LE(1, 0);
  data.writeUInt32LE(1, 4);
  authority.toBuffer().copy(data, 8);
  nonce.toBuffer().copy(data, 40);
  data.writeBigUInt64LE(0n, 72);
  return data;
}

async function withMockedAccountInfo(accountInfo, fn) {
  const original = Connection.prototype.getAccountInfo;
  const calls = [];
  Connection.prototype.getAccountInfo = async function getAccountInfo(pubkey, commitment) {
    calls.push({ pubkey, commitment });
    return accountInfo;
  };

  try {
    return await fn(calls);
  } finally {
    Connection.prototype.getAccountInfo = original;
  }
}

async function withMockedRentExemption(lamports, fn) {
  const original = Connection.prototype.getMinimumBalanceForRentExemption;
  const calls = [];
  Connection.prototype.getMinimumBalanceForRentExemption =
    async function getMinimumBalanceForRentExemption(dataLength, commitment) {
      calls.push({ dataLength, commitment });
      return lamports;
    };

  try {
    return await fn(calls);
  } finally {
    Connection.prototype.getMinimumBalanceForRentExemption = original;
  }
}

test('resolveSolanaDurableNonceContext parses and validates nonce account authority', async () => {
  const authority = Keypair.generate().publicKey;
  const nonceAccount = Keypair.generate().publicKey;
  const nonce = Keypair.generate().publicKey;
  const solanaTransfer = await import(`${modulePath.href}?case=${Date.now()}-nonce-ok`);

  await withMockedAccountInfo(
    {
      data: nonceAccountData({ authority, nonce }),
      owner: SystemProgram.programId,
    },
    async (calls) => {
      const resolved = await solanaTransfer.resolveSolanaDurableNonceContext({
        rpcUrl: 'http://127.0.0.1:8899',
        nonceAccount: nonceAccount.toBase58(),
        expectedAuthority: authority.toBase58(),
      });

      assert.equal(resolved.nonceAccount, nonceAccount.toBase58());
      assert.equal(resolved.nonceAuthority, authority.toBase58());
      assert.equal(resolved.nonce, nonce.toBase58());
      assert.equal(calls.length, 1);
      assert.equal(calls[0].pubkey.toBase58(), nonceAccount.toBase58());
      assert.equal(calls[0].commitment, 'confirmed');
    },
  );
});

test('resolveSolanaDurableNonceContext rejects non-system nonce accounts', async () => {
  const authority = Keypair.generate().publicKey;
  const nonceAccount = Keypair.generate().publicKey;
  const nonce = Keypair.generate().publicKey;
  const solanaTransfer = await import(`${modulePath.href}?case=${Date.now()}-nonce-owner`);

  await withMockedAccountInfo(
    {
      data: nonceAccountData({ authority, nonce }),
      owner: Keypair.generate().publicKey,
    },
    async () => {
      await assert.rejects(
        () =>
          solanaTransfer.resolveSolanaDurableNonceContext({
            rpcUrl: 'http://127.0.0.1:8899',
            nonceAccount: nonceAccount.toBase58(),
            expectedAuthority: authority.toBase58(),
          }),
        /durableNonceAccount must be owned by the Solana system program/,
      );
    },
  );
});

test('resolveSolanaDurableNonceContext rejects nonce accounts for another authority', async () => {
  const authority = Keypair.generate().publicKey;
  const nonceAccount = Keypair.generate().publicKey;
  const nonce = Keypair.generate().publicKey;
  const solanaTransfer = await import(`${modulePath.href}?case=${Date.now()}-nonce-authority`);

  await withMockedAccountInfo(
    {
      data: nonceAccountData({ authority, nonce }),
      owner: SystemProgram.programId,
    },
    async () => {
      await assert.rejects(
        () =>
          solanaTransfer.resolveSolanaDurableNonceContext({
            rpcUrl: 'http://127.0.0.1:8899',
            nonceAccount: nonceAccount.toBase58(),
            expectedAuthority: Keypair.generate().publicKey.toBase58(),
          }),
        /durable nonce authority must match the fee payer/,
      );
    },
  );
});

test('resolveSolanaDurableNonceContextIfExists returns null for missing managed nonce account', async () => {
  const authority = Keypair.generate().publicKey;
  const nonceAccount = Keypair.generate().publicKey;
  const solanaTransfer = await import(`${modulePath.href}?case=${Date.now()}-nonce-missing`);

  await withMockedAccountInfo(null, async (calls) => {
    const resolved = await solanaTransfer.resolveSolanaDurableNonceContextIfExists({
      rpcUrl: 'http://127.0.0.1:8899',
      nonceAccount: nonceAccount.toBase58(),
      expectedAuthority: authority.toBase58(),
    });

    assert.equal(resolved, null);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].pubkey.toBase58(), nonceAccount.toBase58());
    assert.equal(calls[0].commitment, 'confirmed');
  });
});

test('deriveSolanaManagedNonceAccount derives a deterministic seeded system account', async () => {
  const feePayer = Keypair.generate().publicKey;
  const chainId = 900_000_002;
  const solanaTransfer = await import(`${modulePath.href}?case=${Date.now()}-nonce-derived`);

  const managed = await solanaTransfer.deriveSolanaManagedNonceAccount({
    chainId,
    feePayer: feePayer.toBase58(),
  });
  const expected = await PublicKey.createWithSeed(feePayer, managed.seed, SystemProgram.programId);

  assert.equal(managed.seed, 'agentpay-900000002-nonce');
  assert.ok(Buffer.byteLength(managed.seed, 'ascii') <= 32);
  assert.equal(managed.nonceAccount, expected.toBase58());
  assert.deepEqual(
    await solanaTransfer.deriveSolanaManagedNonceAccount({
      chainId,
      feePayer: feePayer.toBase58(),
    }),
    managed,
  );
});

test('getSolanaNonceAccountRentLamports uses the nonce account rent size', async () => {
  const solanaTransfer = await import(`${modulePath.href}?case=${Date.now()}-nonce-rent`);

  await withMockedRentExemption(1_500_000, async (calls) => {
    const lamports =
      await solanaTransfer.getSolanaNonceAccountRentLamports('http://127.0.0.1:8899');

    assert.equal(lamports, '1500000');
    assert.deepEqual(calls, [{ dataLength: 80, commitment: 'confirmed' }]);
  });
});
