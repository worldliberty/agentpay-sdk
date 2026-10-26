import assert from 'node:assert/strict';
import test from 'node:test';

import { createTransferCheckedInstruction, TOKEN_PROGRAM_ID } from '@solana/spl-token';
import {
  ComputeBudgetProgram,
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from '@solana/web3.js';

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

function buildSignedTransaction({ payer, recentBlockhash, instructions }) {
  const message = new TransactionMessage({
    payerKey: payer.publicKey,
    recentBlockhash,
    instructions,
  }).compileToV0Message();
  const transaction = new VersionedTransaction(message);
  transaction.sign([payer]);
  return Buffer.from(transaction.serialize()).toString('base64');
}

function solFixture() {
  const payer = Keypair.generate();
  const recipient = Keypair.generate().publicKey;
  const recentBlockhash = Keypair.generate().publicKey.toBase58();
  const expected = {
    feePayer: payer.publicKey.toBase58(),
    recentBlockhash,
    transfer: { kind: 'sol', recipient: recipient.toBase58(), lamports: 5_000n },
  };
  const transferIx = (overrides = {}) =>
    SystemProgram.transfer({
      fromPubkey: payer.publicKey,
      toPubkey: recipient,
      lamports: 5_000,
      ...overrides,
    });
  return { payer, recipient, recentBlockhash, expected, transferIx };
}

function splFixture() {
  const payer = Keypair.generate();
  const mint = Keypair.generate().publicKey;
  const sourceAta = Keypair.generate().publicKey;
  const destinationAta = Keypair.generate().publicKey;
  const recentBlockhash = Keypair.generate().publicKey.toBase58();
  const expected = {
    feePayer: payer.publicKey.toBase58(),
    recentBlockhash,
    transfer: {
      kind: 'spl',
      mint: mint.toBase58(),
      sourceAta: sourceAta.toBase58(),
      destinationAta: destinationAta.toBase58(),
      amountWei: 1_000_000n,
      decimals: 6,
      tokenProgram: 'token',
    },
  };
  const transferIx = (overrides = {}) =>
    createTransferCheckedInstruction(
      overrides.source ?? sourceAta,
      overrides.mint ?? mint,
      overrides.destination ?? destinationAta,
      payer.publicKey,
      overrides.amount ?? 1_000_000n,
      overrides.decimals ?? 6,
      [],
      TOKEN_PROGRAM_ID,
    );
  return { payer, mint, sourceAta, destinationAta, recentBlockhash, expected, transferIx };
}

test('verifySignedSolanaTransaction accepts a SOL transfer that matches the request', async () => {
  const solanaTransfer = await import(`${modulePath.href}?case=${Date.now()}-verify-sol-ok`);
  const { payer, recentBlockhash, expected, transferIx } = solFixture();
  const raw = buildSignedTransaction({
    payer,
    recentBlockhash,
    instructions: [
      ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
      ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1_000 }),
      transferIx(),
    ],
  });

  const decoded = solanaTransfer.verifySignedSolanaTransaction(raw, expected);
  assert.equal(decoded.feePayer, payer.publicKey.toBase58());
  assert.equal(decoded.recentBlockhash, recentBlockhash);
  assert.equal(decoded.computeUnitLimit, 200_000n);
  assert.equal(decoded.computeUnitPriceMicroLamports, 1_000n);
  assert.equal(decoded.priorityFeeLamports, 200n);
});

test('verifySignedSolanaTransaction rejects a SOL transfer to another recipient or amount', async () => {
  const solanaTransfer = await import(`${modulePath.href}?case=${Date.now()}-verify-sol-bad`);
  const { payer, recentBlockhash, expected, transferIx } = solFixture();

  const wrongRecipient = buildSignedTransaction({
    payer,
    recentBlockhash,
    instructions: [transferIx({ toPubkey: Keypair.generate().publicKey })],
  });
  assert.throws(
    () => solanaTransfer.verifySignedSolanaTransaction(wrongRecipient, expected),
    /SOL transfer recipient .* does not match expected/,
  );

  const wrongAmount = buildSignedTransaction({
    payer,
    recentBlockhash,
    instructions: [transferIx({ lamports: 5_001 })],
  });
  assert.throws(
    () => solanaTransfer.verifySignedSolanaTransaction(wrongAmount, expected),
    /SOL amount 5001 lamports does not match expected 5000/,
  );

  const doubleTransfer = buildSignedTransaction({
    payer,
    recentBlockhash,
    instructions: [transferIx(), transferIx()],
  });
  assert.throws(
    () => solanaTransfer.verifySignedSolanaTransaction(doubleTransfer, expected),
    /exactly one transfer instruction; found 2/,
  );
});

test('verifySignedSolanaTransaction rejects a mismatched fee payer or blockhash', async () => {
  const solanaTransfer = await import(`${modulePath.href}?case=${Date.now()}-verify-payer`);
  const { payer, recentBlockhash, expected, transferIx } = solFixture();
  const raw = buildSignedTransaction({ payer, recentBlockhash, instructions: [transferIx()] });

  assert.throws(
    () =>
      solanaTransfer.verifySignedSolanaTransaction(raw, {
        ...expected,
        feePayer: Keypair.generate().publicKey.toBase58(),
      }),
    /fee payer .* does not match expected/,
  );
  assert.throws(
    () =>
      solanaTransfer.verifySignedSolanaTransaction(raw, {
        ...expected,
        recentBlockhash: Keypair.generate().publicKey.toBase58(),
      }),
    /recent blockhash .* does not match expected/,
  );
});

test('verifySignedSolanaTransaction rejects unexpected programs and undecodable payloads', async () => {
  const solanaTransfer = await import(`${modulePath.href}?case=${Date.now()}-verify-program`);
  const { payer, recentBlockhash, expected, transferIx } = solFixture();
  const raw = buildSignedTransaction({
    payer,
    recentBlockhash,
    instructions: [
      transferIx(),
      new TransactionInstruction({
        programId: Keypair.generate().publicKey,
        keys: [],
        data: Buffer.from([1, 2, 3]),
      }),
    ],
  });
  assert.throws(
    () => solanaTransfer.verifySignedSolanaTransaction(raw, expected),
    /invokes an unexpected program/,
  );
  assert.throws(
    () => solanaTransfer.verifySignedSolanaTransaction('bm90IGEgdHg=', expected),
    /could not be decoded/,
  );
});

test('verifySignedSolanaTransaction checks the durable nonce advance', async () => {
  const solanaTransfer = await import(`${modulePath.href}?case=${Date.now()}-verify-nonce`);
  const { payer, recentBlockhash, expected, transferIx } = solFixture();
  const nonceAccount = Keypair.generate().publicKey;
  const advance = (noncePubkey) =>
    SystemProgram.nonceAdvance({ noncePubkey, authorizedPubkey: payer.publicKey });

  const ok = buildSignedTransaction({
    payer,
    recentBlockhash,
    instructions: [advance(nonceAccount), transferIx()],
  });
  solanaTransfer.verifySignedSolanaTransaction(ok, {
    ...expected,
    durableNonceAccount: nonceAccount.toBase58(),
  });

  assert.throws(
    () => solanaTransfer.verifySignedSolanaTransaction(ok, expected),
    /advances a durable nonce but no nonce account was requested/,
  );
  assert.throws(
    () =>
      solanaTransfer.verifySignedSolanaTransaction(ok, {
        ...expected,
        durableNonceAccount: Keypair.generate().publicKey.toBase58(),
      }),
    /durable nonce account .* does not match expected/,
  );

  const missingAdvance = buildSignedTransaction({
    payer,
    recentBlockhash,
    instructions: [transferIx()],
  });
  assert.throws(
    () =>
      solanaTransfer.verifySignedSolanaTransaction(missingAdvance, {
        ...expected,
        durableNonceAccount: nonceAccount.toBase58(),
      }),
    /missing the expected durable nonce advance/,
  );
});

test('verifySignedSolanaTransaction compares SPL mint, accounts, amount and decimals', async () => {
  const solanaTransfer = await import(`${modulePath.href}?case=${Date.now()}-verify-spl`);
  const { payer, recentBlockhash, expected, transferIx } = splFixture();
  const sign = (ix) => buildSignedTransaction({ payer, recentBlockhash, instructions: [ix] });

  solanaTransfer.verifySignedSolanaTransaction(sign(transferIx()), expected);

  assert.throws(
    () =>
      solanaTransfer.verifySignedSolanaTransaction(
        sign(transferIx({ destination: Keypair.generate().publicKey })),
        expected,
      ),
    /destination token account .* does not match expected/,
  );
  assert.throws(
    () =>
      solanaTransfer.verifySignedSolanaTransaction(
        sign(transferIx({ mint: Keypair.generate().publicKey })),
        expected,
      ),
    /mint .* does not match expected/,
  );
  assert.throws(
    () =>
      solanaTransfer.verifySignedSolanaTransaction(
        sign(transferIx({ amount: 2_000_000n })),
        expected,
      ),
    /token amount 2000000 does not match expected 1000000/,
  );
  assert.throws(
    () => solanaTransfer.verifySignedSolanaTransaction(sign(transferIx({ decimals: 9 })), expected),
    /token decimals 9 do not match expected 6/,
  );
  assert.throws(
    () =>
      solanaTransfer.verifySignedSolanaTransaction(sign(transferIx()), {
        ...expected,
        transfer: { ...expected.transfer, tokenProgram: 'token_2022' },
      }),
    /token program .* does not match expected/,
  );

  const sol = solFixture();
  assert.throws(
    () =>
      solanaTransfer.verifySignedSolanaTransaction(
        buildSignedTransaction({
          payer,
          recentBlockhash,
          instructions: [
            SystemProgram.transfer({
              fromPubkey: payer.publicKey,
              toPubkey: sol.recipient,
              lamports: 1,
            }),
          ],
        }),
        expected,
      ),
    /contains a SOL transfer but an SPL token transfer was expected/,
  );
});

test('verifySignedSolanaTransaction enforces compute unit price and priority fee caps', async () => {
  const solanaTransfer = await import(`${modulePath.href}?case=${Date.now()}-verify-fee-cap`);
  const { payer, recentBlockhash, expected, transferIx } = solFixture();
  const sign = (instructions) => buildSignedTransaction({ payer, recentBlockhash, instructions });

  const overPrice = sign([
    ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000 }),
    ComputeBudgetProgram.setComputeUnitPrice({
      microLamports: solanaTransfer.DEFAULT_SOLANA_MAX_COMPUTE_UNIT_PRICE_MICRO_LAMPORTS + 1n,
    }),
    transferIx(),
  ]);
  assert.throws(
    () => solanaTransfer.verifySignedSolanaTransaction(overPrice, expected),
    /compute unit price .* exceeds the maximum/,
  );

  // No explicit limit: the worst case assumes 1.4M units, so 10M microlamports/unit is 14M lamports.
  const overFee = sign([
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 10_000_000n }),
    transferIx(),
  ]);
  assert.throws(
    () => solanaTransfer.verifySignedSolanaTransaction(overFee, expected),
    /priority fee 14000000 lamports .* exceeds the maximum 10000000 lamports/,
  );

  const withinCustomCap = sign([
    ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 50_000 }),
    transferIx(),
  ]);
  solanaTransfer.verifySignedSolanaTransaction(withinCustomCap, expected);
  assert.throws(
    () =>
      solanaTransfer.verifySignedSolanaTransaction(withinCustomCap, {
        ...expected,
        maxPriorityFeeLamports: '5000',
      }),
    /priority fee 10000 lamports .* exceeds the maximum 5000 lamports/,
  );

  const duplicatePrice = sign([
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1 }),
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1 }),
    transferIx(),
  ]);
  assert.throws(
    () => solanaTransfer.verifySignedSolanaTransaction(duplicatePrice, expected),
    /sets the compute unit price more than once/,
  );
});

test('broadcastSignedSolanaTransaction refuses over-cap fees before sending', async () => {
  const solanaTransfer = await import(`${modulePath.href}?case=${Date.now()}-broadcast-cap`);
  const { payer, recentBlockhash, transferIx } = solFixture();
  const raw = buildSignedTransaction({
    payer,
    recentBlockhash,
    instructions: [
      ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 100_000_000n }),
      transferIx(),
    ],
  });
  const original = Connection.prototype.sendRawTransaction;
  let sent = 0;
  Connection.prototype.sendRawTransaction = async () => {
    sent += 1;
    return 'sig';
  };
  try {
    await assert.rejects(
      () => solanaTransfer.broadcastSignedSolanaTransaction('http://127.0.0.1:8899', raw),
      /compute unit price .* exceeds the maximum/,
    );
    assert.equal(sent, 0);
  } finally {
    Connection.prototype.sendRawTransaction = original;
  }
});

test('resolveSolanaComputeBudget clamps RPC prices and rejects explicit prices over the caps', async () => {
  const solanaTransfer = await import(`${modulePath.href}?case=${Date.now()}-budget-cap`);
  const original = Connection.prototype.getRecentPrioritizationFees;
  Connection.prototype.getRecentPrioritizationFees = async () => [
    { slot: 1, prioritizationFee: 1_000_000_000 },
  ];
  try {
    const budget = await solanaTransfer.resolveSolanaComputeBudget({
      rpcUrl: 'http://127.0.0.1:8899',
      defaultComputeUnitLimit: 200_000,
    });
    assert.equal(budget.computeUnitLimit, '200000');
    // 0.01 SOL over 200k units is 50,000,000 microlamports/unit, then the 10M per-unit cap applies.
    assert.equal(budget.computeUnitPriceMicroLamports, '10000000');

    await assert.rejects(
      () =>
        solanaTransfer.resolveSolanaComputeBudget({
          rpcUrl: 'http://127.0.0.1:8899',
          defaultComputeUnitLimit: 200_000,
          computeUnitPriceMicroLamports: '20000000',
        }),
      /compute unit price 20000000 microlamports exceeds the maximum/,
    );
  } finally {
    Connection.prototype.getRecentPrioritizationFees = original;
  }
});
