import {
  type Address,
  type Hex,
  isAddressEqual,
  parseTransaction,
  recoverTransactionAddress,
} from 'viem';

export interface ExpectedSignedBroadcastTransaction {
  rawTxHex: Hex;
  from: Address;
  to: Address;
  chainId: number;
  nonce: number;
  allowHigherNonce?: boolean;
  value: bigint;
  data: Hex;
  gasLimit: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  txType: string;
}

export interface SignedBroadcastInspection {
  nonce: number;
}

function normalizeHex(value: Hex): string {
  return value.toLowerCase();
}

function normalizeTxType(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (!normalized) {
    throw new Error('txType is required');
  }

  let parsed: bigint;
  try {
    parsed = BigInt(normalized);
  } catch {
    throw new Error(`Unsupported txType '${value}'`);
  }

  switch (parsed) {
    case 0n:
      return 'legacy';
    case 1n:
      return 'eip2930';
    case 2n:
      return 'eip1559';
    case 3n:
      return 'eip4844';
    case 4n:
      return 'eip7702';
    default:
      throw new Error(`Unsupported txType '${value}'`);
  }
}

function assertEqual<T>(actual: T, expected: T, label: string): void {
  if (actual !== expected) {
    throw new Error(
      `signed raw transaction ${label} mismatch: expected ${expected}, received ${actual}`,
    );
  }
}

function normalizeOptionalPriorityFee(value: bigint | undefined): bigint {
  return value ?? 0n;
}

export async function assertSignedBroadcastTransactionMatchesRequest(
  expected: ExpectedSignedBroadcastTransaction,
): Promise<SignedBroadcastInspection> {
  const parsed = parseTransaction(expected.rawTxHex);
  const recoveredFrom = await recoverTransactionAddress({
    serializedTransaction: expected.rawTxHex as Parameters<
      typeof recoverTransactionAddress
    >[0]['serializedTransaction'],
  });

  if (!isAddressEqual(recoveredFrom, expected.from)) {
    throw new Error(
      `signed raw transaction from mismatch: expected ${expected.from}, received ${recoveredFrom}`,
    );
  }

  const parsedTo = parsed.to;
  if (!parsedTo || !isAddressEqual(parsedTo, expected.to)) {
    throw new Error(
      `signed raw transaction to mismatch: expected ${expected.to}, received ${parsedTo ?? 'null'}`,
    );
  }

  /* c8 ignore next 3 -- supported signed transactions produced by viem always include a nonce */
  if (parsed.nonce === undefined) {
    throw new Error('signed raw transaction nonce is missing');
  }

  assertEqual(parsed.chainId, expected.chainId, 'chainId');
  if (expected.allowHigherNonce) {
    if (parsed.nonce < expected.nonce) {
      throw new Error(
        `signed raw transaction nonce mismatch: expected at least ${expected.nonce}, received ${parsed.nonce}`,
      );
    }
  } else {
    assertEqual(parsed.nonce, expected.nonce, 'nonce');
  }
  assertEqual(parsed.value ?? 0n, expected.value, 'value');
  assertEqual(parsed.gas, expected.gasLimit, 'gasLimit');
  assertEqual(parsed.maxFeePerGas ?? 0n, expected.maxFeePerGas, 'maxFeePerGas');
  assertEqual(
    normalizeOptionalPriorityFee(parsed.maxPriorityFeePerGas),
    expected.maxPriorityFeePerGas,
    'maxPriorityFeePerGas',
  );
  assertEqual(parsed.type, normalizeTxType(expected.txType), 'txType');

  const parsedData = normalizeHex((parsed.data ?? '0x') as Hex);
  const expectedData = normalizeHex(expected.data);
  if (parsedData !== expectedData) {
    throw new Error(
      `signed raw transaction data mismatch: expected ${expectedData}, received ${parsedData}`,
    );
  }

  return {
    nonce: parsed.nonce,
  };
}
