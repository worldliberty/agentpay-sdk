#!/usr/bin/env node

// Test double for agentpay-agent's Tempo session commands. It rebuilds exactly what the Rust
// daemon signs from the CLI flags (channel id, escrow calls, type-0x76 envelope, voucher typed
// data) using viem as the reference encoder, so the CLI's local signature-recovery check passes
// only when the flags fully describe the payload the CLI serializes.
//
// Usage (from a generated shell wrapper):
//   node test/tempo-agent-mock.mjs <privateKeyHex> <argsLogPath|""> <agentpay-agent args...>

import fs from 'node:fs';
import {
  encodeAbiParameters,
  encodeFunctionData,
  hashTypedData,
  keccak256,
  parseSignature,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { Abis as TempoAbis, Transaction as TempoTransaction } from 'viem/tempo';

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

const TEMPO_COMMANDS = [
  'tempo-session-open-transaction',
  'tempo-session-top-up-transaction',
  'tempo-session-voucher',
];

const [privateKey, argsLogPath, ...args] = process.argv.slice(2);
const command = args.find((value) => TEMPO_COMMANDS.includes(value));
if (!command) {
  process.stderr.write(`unexpected-command:${args.join(' ')}\n`);
  process.exit(9);
}
if (argsLogPath) {
  fs.appendFileSync(argsLogPath, `${JSON.stringify({ command, args })}\n`);
}
if (args.includes('--signing-hash-hex')) {
  throw new Error('legacy --signing-hash-hex must not be sent to the agent');
}

const flag = (name) => {
  const index = args.indexOf(`--${name}`);
  return index >= 0 ? args[index + 1] : undefined;
};
const required = (name) => {
  const value = flag(name);
  if (value === undefined) {
    throw new Error(`missing --${name}`);
  }
  return value;
};

const account = privateKeyToAccount(privateKey);
const chainId = Number(required('network'));
const escrowContract = required('escrow-contract');
const token = required('token');
const recipient = required('recipient');
const payer = required('payer');
const authorizedSigner = required('authorized-signer');
const salt = required('salt-hex');
if (payer.toLowerCase() !== account.address.toLowerCase()) {
  throw new Error(`payer ${payer} is not the wallet ${account.address}`);
}
if (authorizedSigner.toLowerCase() !== payer.toLowerCase()) {
  throw new Error('authorized signer must equal payer');
}

const channelId = keccak256(
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
    [payer, recipient, token, salt, authorizedSigner, escrowContract, BigInt(chainId)],
  ),
);
if (command !== 'tempo-session-open-transaction') {
  if (required('channel-id-hex').toLowerCase() !== channelId.toLowerCase()) {
    throw new Error('channel id does not match the channel fields');
  }
}

let hash;
let amountWei;
if (command === 'tempo-session-voucher') {
  amountWei = required('cumulative-amount-wei');
  hash = hashTypedData({
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
    message: { channelId, cumulativeAmount: BigInt(amountWei) },
  });
} else {
  const isOpen = command === 'tempo-session-open-transaction';
  amountWei = required(isOpen ? 'deposit-wei' : 'additional-deposit-wei');
  const amount = BigInt(amountWei);
  const calls = [
    {
      to: token,
      data: encodeFunctionData({
        abi: TempoAbis.tip20,
        functionName: 'approve',
        args: [escrowContract, amount],
      }),
    },
    {
      to: escrowContract,
      data: isOpen
        ? encodeFunctionData({
            abi: tempoEscrowAbi,
            functionName: 'open',
            args: [recipient, token, amount, salt, authorizedSigner],
          })
        : encodeFunctionData({
            abi: tempoEscrowAbi,
            functionName: 'topUp',
            args: [channelId, amount],
          }),
    },
  ];
  const feePayer = args.includes('--fee-payer');
  const nonceKey = flag('nonce-key');
  const validBefore = flag('valid-before');
  const validAfter = flag('valid-after');
  // Mirrors the Rust agent's parse_positive_u64 for these flags.
  for (const [name, value] of [
    ['valid-before', validBefore],
    ['valid-after', validAfter],
  ]) {
    if (value !== undefined && !/^[1-9][0-9]*$/u.test(value)) {
      process.stderr.write(`invalid --${name}: must be a positive integer\n`);
      process.exit(2);
    }
  }
  const feeToken = flag('fee-token');
  const unsigned = {
    type: 'tempo',
    chainId,
    calls,
    gas: BigInt(required('gas-limit')),
    maxFeePerGas: BigInt(required('max-fee-per-gas-wei')),
    maxPriorityFeePerGas: BigInt(required('max-priority-fee-per-gas-wei')),
    nonce: Number(required('nonce')),
    ...(nonceKey !== undefined ? { nonceKey: BigInt(nonceKey) } : {}),
    ...(validBefore !== undefined ? { validBefore: Number(validBefore) } : {}),
    ...(validAfter !== undefined ? { validAfter: Number(validAfter) } : {}),
    ...(feeToken !== undefined ? { feeToken } : {}),
    ...(feePayer ? { feePayer: true } : {}),
  };
  hash = keccak256(await TempoTransaction.serialize(unsigned));
}

const signatureHex = await account.sign({ hash });
const parsed = parseSignature(signatureHex);
process.stdout.write(
  JSON.stringify({
    command,
    network: String(chainId),
    asset: `erc20:${token}`,
    counterparty: recipient,
    amount_wei: amountWei,
    signature_hex: signatureHex,
    r_hex: parsed.r,
    s_hex: parsed.s,
    v: Number(parsed.yParity ?? parsed.v - 27n),
  }),
);
