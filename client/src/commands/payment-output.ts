/** Text and JSON output of payment results (EVM and Solana), including pending approvals. */
import { copy } from '../copy/index.js';
import type { EvmPaymentResponse, SolanaPaymentResponse } from '../daemon/payments.js';
import type {
  EvmSignatureResult,
  EvmTransactionResult,
  SolanaTransferResult,
} from '../generated/index.js';
import { emit, emitPending } from './output.js';
import type { CommandEnv } from './run.js';

export function solanaText(result: SolanaTransferResult): string[] {
  const s = copy.commands.solana;
  return [
    `signature: ${result.signature}`,
    ...(result.broadcast ? [s.status(result.broadcast.status)] : [copy.commands.evm.signed]),
    ...(result.raw_tx_base64 ? [`raw_tx_base64: ${result.raw_tx_base64}`] : []),
  ];
}

export function signatureText(result: EvmSignatureResult): string[] {
  const payment = result.payment;
  return [
    copy.commands.evm.signed,
    ...(payment ? [`${payment.amount} ${payment.asset.symbol} → ${payment.counterparty}`] : []),
    `signature: ${result.signature_hex}`,
  ];
}

export function transactionText(result: EvmTransactionResult): string[] {
  const e = copy.commands.evm;
  const lines = result.payment
    ? [
        `${result.payment.amount} ${result.payment.asset.symbol} → ${result.payment.counterparty} on ${result.network}`,
      ]
    : [];
  if (!result.broadcast) {
    return [...lines, e.signed, `raw_tx_hex: ${result.raw_tx_hex}`, `tx_hash: ${result.tx_hash}`];
  }
  lines.push(e.sent(result.tx_hash));
  if (result.receipt) {
    lines.push(
      result.receipt.success
        ? e.confirmed(result.receipt.block_number)
        : e.reverted(result.receipt.block_number),
    );
  } else if (result.receipt_timed_out) {
    lines.push(e.receiptTimedOut);
  }
  return lines;
}

/** Prints any EVM or Solana payment result; returns the exit code. */
export function emitPayment(
  env: CommandEnv,
  json: boolean | undefined,
  response: EvmPaymentResponse | SolanaPaymentResponse,
): number {
  const io = env.context.io;
  switch (response.type) {
    case 'ManualApprovalPending':
      return emitPending(io, json, response.data, true);
    case 'EvmSignature':
      emit(io, json, response.data, () => signatureText(response.data));
      return 0;
    case 'EvmTransaction': {
      emit(io, json, response.data, () => transactionText(response.data));
      return response.data.receipt?.success === false ? 1 : 0;
    }
    case 'SolanaTransfer':
      emit(io, json, response.data, () => solanaText(response.data));
      return 0;
  }
}
