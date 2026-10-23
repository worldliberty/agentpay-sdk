#!/usr/bin/env node

// Generates the Tempo session signing vectors consumed by
// crates/vault-domain/src/tests.rs. Digests come from the same viem/ox code the
// CLI uses to serialize Tempo transactions, so the Rust encoder is pinned to the
// reference behavior byte for byte:
//
// - open / topUp: keccak256(await Transaction.serialize(unsigned)) from viem/tempo
//   (the sponsored layout drops the fee token and carries the 0x00 fee-payer marker)
// - voucher: hashTypedData over Voucher(bytes32 channelId, uint128 cumulativeAmount)
//
// Usage: node scripts/generate-tempo-session-vectors.mjs [--check]

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  encodeAbiParameters,
  encodeFunctionData,
  getAddress,
  hashTypedData,
  keccak256,
  maxUint256,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { Abis as TempoAbis, Transaction as TempoTransaction } from 'viem/tempo';

const repoRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
export const tempoSessionVectorsPath = path.join(
  repoRoot,
  'crates',
  'vault-domain',
  'tests',
  'fixtures',
  'tempo_session_vectors.json',
);

const PINNED_ESCROW = {
  4217: '0x33b901018174DDabE4841042ab76ba85D4e24f25',
  42431: '0xe1c4d3dce17bc111181ddf716f75bae49e61a336',
};

const tempoEscrowAbi = [
  {
    type: 'function',
    name: 'open',
    inputs: [
      { name: 'payee', type: 'address' },
      { name: 'token', type: 'address' },
      { name: 'deposit', type: 'uint128' },
      { name: 'salt', type: 'bytes32' },
      { name: 'authorizedSigner', type: 'address' },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'topUp',
    inputs: [
      { name: 'channelId', type: 'bytes32' },
      { name: 'additionalDeposit', type: 'uint256' },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
];

// Fixed, test-only key material. Never use this key outside tests.
const payerAccount = privateKeyToAccount(`0x${'11'.repeat(32)}`);
const token = '0x20c0000000000000000000000000000000000001';
const recipient = '0x7777777777777777777777777777777777777777';
const salt = `0x${'5a'.repeat(32)}`;
const depositWei = 2_500_000n;
const additionalDepositWei = 750_000n;
const cumulativeAmountWei = 1_250_000n;

const txCases = [
  {
    name: 'expiring-nonce',
    nonce: 0,
    nonceKey: maxUint256,
    validBefore: 1_900_000_025,
    validAfter: undefined,
  },
  {
    name: 'sequential-nonce',
    nonce: 7,
    nonceKey: undefined,
    validBefore: undefined,
    validAfter: 1_800_000_000,
  },
];

function computeChannelId({ chainId, escrowContract, payer }) {
  return keccak256(
    encodeAbiParameters(
      [
        { type: 'address' },
        { type: 'address' },
        { type: 'address' },
        { type: 'bytes32' },
        { type: 'address' },
        { type: 'address' },
        { type: 'uint256' },
      ],
      [payer, recipient, token, salt, payer, escrowContract, BigInt(chainId)],
    ),
  );
}

function rustTxParams(txCase, feePayer) {
  return {
    nonce: txCase.nonce,
    ...(txCase.nonceKey !== undefined ? { nonce_key: txCase.nonceKey.toString() } : {}),
    gas_limit: 412_345,
    max_fee_per_gas_wei: '20000000000',
    max_priority_fee_per_gas_wei: '1000000',
    ...(txCase.validBefore !== undefined ? { valid_before: txCase.validBefore } : {}),
    ...(txCase.validAfter !== undefined ? { valid_after: txCase.validAfter } : {}),
    ...(feePayer ? {} : { fee_token: token }),
    fee_payer: feePayer,
  };
}

async function referenceSigningHash({ chainId, calls, txCase, feePayer }) {
  // Mirrors what prepareTransactionRequest hands back: feeToken is always set, and
  // viem drops it from the sender payload when feePayer is true.
  const unsigned = {
    type: 'tempo',
    chainId,
    from: payerAccount.address,
    calls,
    gas: 412_345n,
    maxFeePerGas: 20_000_000_000n,
    maxPriorityFeePerGas: 1_000_000n,
    nonce: txCase.nonce,
    ...(txCase.nonceKey !== undefined ? { nonceKey: txCase.nonceKey } : {}),
    ...(txCase.validBefore !== undefined ? { validBefore: txCase.validBefore } : {}),
    ...(txCase.validAfter !== undefined ? { validAfter: txCase.validAfter } : {}),
    feeToken: token,
    ...(feePayer ? { feePayer: true } : {}),
  };
  return keccak256(await TempoTransaction.serialize(unsigned));
}

export async function buildTempoSessionVectors() {
  const vectors = [];
  for (const chainId of [4217, 42431]) {
    const escrowContract = getAddress(PINNED_ESCROW[chainId]);
    const payer = payerAccount.address;
    const channelId = computeChannelId({ chainId, escrowContract, payer });
    const identity = {
      chain_id: chainId,
      escrow_contract: PINNED_ESCROW[chainId],
      token,
      recipient,
      payer,
      authorized_signer: payer,
      salt_hex: salt,
    };
    const openCalls = [
      {
        to: token,
        data: encodeFunctionData({
          abi: TempoAbis.tip20,
          functionName: 'approve',
          args: [escrowContract, depositWei],
        }),
      },
      {
        to: escrowContract,
        data: encodeFunctionData({
          abi: tempoEscrowAbi,
          functionName: 'open',
          args: [recipient, token, depositWei, salt, payer],
        }),
      },
    ];
    const topUpCalls = [
      {
        to: token,
        data: encodeFunctionData({
          abi: TempoAbis.tip20,
          functionName: 'approve',
          args: [escrowContract, additionalDepositWei],
        }),
      },
      {
        to: escrowContract,
        data: encodeFunctionData({
          abi: tempoEscrowAbi,
          functionName: 'topUp',
          args: [channelId, additionalDepositWei],
        }),
      },
    ];
    const voucherSigningHashHex = hashTypedData({
      domain: {
        name: 'Tempo Stream Channel',
        version: '1',
        chainId,
        verifyingContract: escrowContract,
      },
      types: {
        Voucher: [
          { name: 'channelId', type: 'bytes32' },
          { name: 'cumulativeAmount', type: 'uint128' },
        ],
      },
      primaryType: 'Voucher',
      message: { channelId, cumulativeAmount: cumulativeAmountWei },
    });

    for (const feePayer of [false, true]) {
      for (const txCase of txCases) {
        const tx = rustTxParams(txCase, feePayer);
        vectors.push({
          name: `${chainId}-${feePayer ? 'sponsored' : 'unsponsored'}-${txCase.name}`,
          open: { ...identity, deposit_wei: depositWei.toString(), tx },
          top_up: {
            ...identity,
            channel_id_hex: channelId,
            additional_deposit_wei: additionalDepositWei.toString(),
            tx,
          },
          voucher: {
            ...identity,
            channel_id_hex: channelId,
            cumulative_amount_wei: cumulativeAmountWei.toString(),
          },
          expected: {
            channel_id_hex: channelId,
            open_calls: openCalls.map((call) => ({ to: call.to.toLowerCase(), data: call.data })),
            top_up_calls: topUpCalls.map((call) => ({
              to: call.to.toLowerCase(),
              data: call.data,
            })),
            open_signing_hash_hex: await referenceSigningHash({
              chainId,
              calls: openCalls,
              txCase,
              feePayer,
            }),
            top_up_signing_hash_hex: await referenceSigningHash({
              chainId,
              calls: topUpCalls,
              txCase,
              feePayer,
            }),
            voucher_signing_hash_hex: voucherSigningHashHex,
          },
        });
      }
    }
  }

  return {
    description:
      'Tempo session open/topUp/voucher digests produced by viem/tempo. Regenerate with node scripts/generate-tempo-session-vectors.mjs.',
    vectors,
  };
}

export async function serializeTempoSessionVectors() {
  return `${JSON.stringify(await buildTempoSessionVectors(), null, 2)}\n`;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  const serialized = await serializeTempoSessionVectors();
  if (process.argv.includes('--check')) {
    const existing = fs.existsSync(tempoSessionVectorsPath)
      ? fs.readFileSync(tempoSessionVectorsPath, 'utf8')
      : '';
    if (existing !== serialized) {
      console.error(
        `tempo session vectors are stale: ${path.relative(repoRoot, tempoSessionVectorsPath)}`,
      );
      process.exit(1);
    }
    console.log('tempo session vectors are up to date');
  } else {
    fs.mkdirSync(path.dirname(tempoSessionVectorsPath), { recursive: true });
    fs.writeFileSync(tempoSessionVectorsPath, serialized);
    console.log(`wrote ${path.relative(repoRoot, tempoSessionVectorsPath)}`);
  }
}
