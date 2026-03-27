import { setTimeout as sleep } from 'node:timers/promises';
import { encodeFunctionData, erc20Abi, type Address, type Hex, type TransactionReceipt } from 'viem';
import type { ResolvedAssetMetadata, RustAmountOutputShape } from './config-amounts.js';
import { normalizeAgentAmountOutput } from './config-amounts.js';

export interface AssetBroadcastPlanInput {
  rpcUrl: string;
  chainId: number;
  from: Address;
  to: Address;
  valueWei: bigint;
  dataHex: Hex;
  nonce?: number;
  gasLimit?: bigint;
  maxFeePerGasWei?: bigint;
  maxPriorityFeePerGasWei?: bigint;
  txType: string;
}

export interface AssetBroadcastPlan {
  rpcUrl: string;
  chainId: number;
  from: Address;
  to: Address;
  valueWei: bigint;
  dataHex: Hex;
  nonce: number;
  gasLimit: bigint;
  maxFeePerGasWei: bigint;
  maxPriorityFeePerGasWei: bigint;
  txType: string;
}

export interface SignedBroadcastResult {
  raw_tx_hex?: string;
  tx_hash_hex?: string;
  r_hex?: string;
  s_hex?: string;
  v?: number;
}

export interface CompletedAssetBroadcast {
  signedTxHash: string | null;
  networkTxHash: Hex;
  signedNonce: number;
}

export interface WaitForOnchainReceiptResult {
  receipt: TransactionReceipt | null;
  timedOut: boolean;
}

interface BroadcastFeeEstimate {
  gasPrice: bigint | null;
  maxFeePerGas: bigint | null;
  maxPriorityFeePerGas: bigint | null;
}

export interface ResolveAssetBroadcastPlanDeps {
  getChainInfo: (rpcUrl: string) => Promise<{ chainId: number }>;
  assertRpcChainIdMatches: (expectedChainId: number, actualChainId: number) => void;
  getNonce: (rpcUrl: string, address: Address) => Promise<number>;
  estimateGas: (args: {
    rpcUrl: string;
    from: Address;
    to: Address;
    value?: bigint;
    data?: Hex;
  }) => Promise<bigint>;
  estimateFees: (rpcUrl: string) => Promise<BroadcastFeeEstimate>;
}

export interface CompleteAssetBroadcastDeps {
  assertSignedBroadcastTransactionMatchesRequest: (expected: {
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
  }) => Promise<{ nonce: number }>;
  broadcastRawTransaction: (rpcUrl: string, rawTransaction: Hex) => Promise<Hex>;
}

export interface WaitForOnchainReceiptDeps {
  getTransactionReceiptByHash: (rpcUrl: string, hash: Hex) => Promise<TransactionReceipt>;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

export function resolveEstimatedPriorityFeePerGasWei(fees: BroadcastFeeEstimate): bigint {
  if (fees.maxPriorityFeePerGas !== null && fees.maxPriorityFeePerGas !== undefined) {
    return fees.maxPriorityFeePerGas;
  }
  const resolved = fees.gasPrice;
  if (resolved === null) {
    throw new Error(
      'Could not determine maxPriorityFeePerGas; pass --max-priority-fee-per-gas-wei',
    );
  }
  return resolved;
}

export function encodeErc20TransferData(recipient: Address, amountWei: bigint): Hex {
  return encodeFunctionData({
    abi: erc20Abi,
    functionName: 'transfer',
    args: [recipient, amountWei],
  });
}

export function encodeErc20ApproveData(spender: Address, amountWei: bigint): Hex {
  return encodeFunctionData({
    abi: erc20Abi,
    functionName: 'approve',
    args: [spender, amountWei],
  });
}

export async function resolveAssetBroadcastPlan(
  input: AssetBroadcastPlanInput,
  deps: ResolveAssetBroadcastPlanDeps,
): Promise<AssetBroadcastPlan> {
  const chainInfo = await deps.getChainInfo(input.rpcUrl);
  deps.assertRpcChainIdMatches(input.chainId, chainInfo.chainId);

  const nonce = input.nonce ?? await deps.getNonce(input.rpcUrl, input.from);
  const gasLimit = input.gasLimit ?? await deps.estimateGas({
    rpcUrl: input.rpcUrl,
    from: input.from,
    to: input.to,
    value: input.valueWei,
    data: input.dataHex,
  });
  const fees = await deps.estimateFees(input.rpcUrl);
  const resolvedFees = fees as BroadcastFeeEstimate;
  const maxFeePerGasWei = input.maxFeePerGasWei ?? (resolvedFees.maxFeePerGas ?? resolvedFees.gasPrice);

  if (maxFeePerGasWei === null || maxFeePerGasWei <= 0n) {
    throw new Error('Could not determine maxFeePerGas; pass --max-fee-per-gas-wei');
  }

  const maxPriorityFeePerGasWei =
    input.maxPriorityFeePerGasWei
    ?? resolveEstimatedPriorityFeePerGasWei(resolvedFees);

  return {
    rpcUrl: input.rpcUrl,
    chainId: input.chainId,
    from: input.from,
    to: input.to,
    valueWei: input.valueWei,
    dataHex: input.dataHex,
    nonce,
    gasLimit,
    maxFeePerGasWei,
    maxPriorityFeePerGasWei,
    txType: input.txType,
  };
}

export async function completeAssetBroadcast(
  plan: AssetBroadcastPlan,
  signed: SignedBroadcastResult,
  deps: CompleteAssetBroadcastDeps,
): Promise<CompletedAssetBroadcast> {
  if (!signed.raw_tx_hex) {
    throw new Error('Rust agent did not return raw_tx_hex for broadcast signing');
  }

  const inspected = await deps.assertSignedBroadcastTransactionMatchesRequest({
    rawTxHex: signed.raw_tx_hex as Hex,
    from: plan.from,
    to: plan.to,
    chainId: plan.chainId,
    nonce: plan.nonce,
    allowHigherNonce: false,
    value: plan.valueWei,
    data: plan.dataHex,
    gasLimit: plan.gasLimit,
    maxFeePerGas: plan.maxFeePerGasWei,
    maxPriorityFeePerGas: plan.maxPriorityFeePerGasWei,
    txType: plan.txType,
  });

  return {
    signedTxHash: signed.tx_hash_hex ?? null,
    networkTxHash: await deps.broadcastRawTransaction(plan.rpcUrl, signed.raw_tx_hex as Hex),
    signedNonce: inspected.nonce,
  };
}

function isPendingTransactionReceiptError(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }

  const message = error.message.toLowerCase();
  return (
    message.includes('transaction receipt')
    && (
      message.includes('not found')
      || message.includes('could not be found')
      || message.includes('was not found')
      || message.includes('does not exist')
    )
  );
}

export async function waitForOnchainReceipt(
  input: {
    rpcUrl: string;
    txHash: Hex;
    timeoutMs?: number;
    intervalMs?: number;
  },
  deps: WaitForOnchainReceiptDeps,
): Promise<WaitForOnchainReceiptResult> {
  const timeoutMs = input.timeoutMs ?? 30_000;
  const intervalMs = input.intervalMs ?? 2_000;
  const now = deps.now ?? Date.now;
  const pause = deps.sleep ?? sleep;
  const started = now();

  while (true) {
    try {
      return {
        receipt: await deps.getTransactionReceiptByHash(input.rpcUrl, input.txHash),
        timedOut: false,
      };
    } catch (error) {
      if (!isPendingTransactionReceiptError(error)) {
        throw error;
      }
    }

    if (now() - started >= timeoutMs) {
      return {
        receipt: null,
        timedOut: true,
      };
    }

    await pause(intervalMs);
  }
}

export function formatBroadcastedAssetOutput(input: {
  command: string;
  counterparty: Address;
  asset: ResolvedAssetMetadata;
  signed: RustAmountOutputShape;
  plan: AssetBroadcastPlan;
  signedNonce?: number;
  networkTxHash: Hex;
  revealRawTx: boolean;
  revealSignature: boolean;
}) {
  const {
    raw_tx_hex: _rawTxHex,
    tx_hash_hex: _txHashHex,
    ...normalized
  } = normalizeAgentAmountOutput(
    {
      ...input.signed,
      command: input.command,
      network: String(input.plan.chainId),
      counterparty: input.counterparty,
    },
    input.asset,
  );

  return {
    ...normalized,
    rpcUrl: input.plan.rpcUrl,
    chainId: input.plan.chainId,
    from: input.plan.from,
    nonce: input.signedNonce ?? input.plan.nonce,
    gasLimit: input.plan.gasLimit.toString(),
    maxFeePerGasWei: input.plan.maxFeePerGasWei.toString(),
    maxPriorityFeePerGasWei: input.plan.maxPriorityFeePerGasWei.toString(),
    signedTxHash: input.signed.tx_hash_hex ?? null,
    networkTxHash: input.networkTxHash,
    rawTxHex: input.revealRawTx ? (input.signed.raw_tx_hex ?? null) : '<redacted>',
    signer: input.revealSignature
      ? {
          r: input.signed.r_hex ?? null,
          s: input.signed.s_hex ?? null,
          v: input.signed.v ?? null,
        }
      : '<redacted>',
  };
}
