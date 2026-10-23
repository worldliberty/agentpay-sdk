import { type Address, isAddress } from 'viem';

function assertPreparedFeeToken(value: string): Address {
  if (!isAddress(value)) {
    throw new Error('prepared tempo feeToken must be a valid EVM address');
  }
  return value as Address;
}

export function tempoTransactionIntegerString(value: unknown, label: string): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value === 'bigint' && value >= 0n) {
    return value.toString();
  }
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) {
    return String(value);
  }
  if (typeof value === 'string' && /^(0x[0-9a-fA-F]+|[0-9]+)$/u.test(value.trim())) {
    return BigInt(value.trim()).toString();
  }
  throw new Error(`prepared tempo transaction ${label} must be a non-negative integer`);
}

/**
 * Drops zero validBefore/validAfter from a prepared Tempo transaction. The agent CLI omits
 * those bounds (it only accepts positive values), so the daemon signs an envelope with empty
 * fields; viem would otherwise serialize a literal 0 differently and break signature recovery.
 */
export function withoutZeroTempoValidityBounds<T extends object>(prepared: T): T {
  const copy = { ...prepared } as Record<string, unknown>;
  for (const key of ['validBefore', 'validAfter']) {
    if (tempoTransactionIntegerString(copy[key], key) === '0') {
      delete copy[key];
    }
  }
  return copy as T;
}

/** Maps a viem-prepared Tempo transaction onto the agent CLI's envelope flags. */
export function tempoTransactionCliArgs(
  prepared: Record<string, unknown>,
  feePayer: boolean,
): string[] {
  const requiredInteger = (value: unknown, label: string) => {
    const resolved = tempoTransactionIntegerString(value, label);
    if (resolved === undefined) {
      throw new Error(`prepared tempo transaction is missing ${label}`);
    }
    return resolved;
  };
  const nonceKey = tempoTransactionIntegerString(prepared.nonceKey, 'nonceKey');
  const validBefore = tempoTransactionIntegerString(prepared.validBefore, 'validBefore');
  const validAfter = tempoTransactionIntegerString(prepared.validAfter, 'validAfter');
  // Sponsored senders do not commit to a fee token; the fee payer picks it.
  const feeToken = feePayer ? undefined : prepared.feeToken;
  if (feeToken !== undefined && typeof feeToken !== 'string') {
    throw new Error('prepared tempo transaction feeToken must be an address');
  }
  return [
    '--nonce',
    tempoTransactionIntegerString(prepared.nonce, 'nonce') ?? '0',
    ...(nonceKey !== undefined && nonceKey !== '0' ? ['--nonce-key', nonceKey] : []),
    '--gas-limit',
    requiredInteger(prepared.gas, 'gas'),
    '--max-fee-per-gas-wei',
    requiredInteger(prepared.maxFeePerGas, 'maxFeePerGas'),
    '--max-priority-fee-per-gas-wei',
    tempoTransactionIntegerString(prepared.maxPriorityFeePerGas, 'maxPriorityFeePerGas') ?? '0',
    // The agent CLI only accepts positive validity bounds; 0 means "unbounded" and is omitted.
    ...(validBefore !== undefined && validBefore !== '0' ? ['--valid-before', validBefore] : []),
    ...(validAfter !== undefined && validAfter !== '0' ? ['--valid-after', validAfter] : []),
    ...(feeToken ? ['--fee-token', assertPreparedFeeToken(feeToken)] : []),
    ...(feePayer ? ['--fee-payer'] : []),
  ];
}
