/** Solana payments: `transfer-sol`, `transfer-spl`. */
import type { Command } from 'commander';
import { copy } from '../copy/index.js';
import { UsageError } from '../errors.js';
import type { SolanaAmount, SolanaNonceMode } from '../generated/index.js';
import {
  type AgentOptions,
  baseUnits,
  decimalAmount,
  nonNegativeInt,
  opt,
  positiveInt,
  withAgentOptions,
} from './options.js';
import { emitPayment } from './payment-output.js';
import { type CommandEnv, handler } from './run.js';

interface SolanaOptions extends AgentOptions {
  network: string;
  to: string;
  mint?: string;
  amount?: string;
  amountBaseUnits?: string;
  broadcast?: boolean;
  wait?: boolean;
  nonce?: string;
  computeUnitLimit?: number;
  computeUnitPrice?: number;
  approvalWait?: number;
  revealRawTx?: boolean;
}

export function nonceMode(value: string | undefined): SolanaNonceMode {
  switch (value ?? 'auto') {
    case 'auto':
      return 'auto';
    case 'recent':
    case 'recent_blockhash':
      return 'recent_blockhash';
    case 'managed':
      return 'managed';
    default:
      return { account: value ?? '' };
  }
}

function amountOf(options: SolanaOptions): SolanaAmount {
  if ((options.amount === undefined) === (options.amountBaseUnits === undefined)) {
    throw new UsageError('pass exactly one of --amount or --amount-base-units');
  }
  return options.amount !== undefined
    ? { decimal: options.amount }
    : { base_units: options.amountBaseUnits ?? '0' };
}

function solanaCommand(
  program: Command,
  name: string,
  description: string,
  mint: boolean,
): Command {
  const s = copy.commands.solana;
  const command = program
    .command(name)
    .description(description)
    .requiredOption('--network <network>', s.network)
    .requiredOption('--to <address>', copy.commands.evm.to);
  if (mint) {
    command.requiredOption('--mint <address>', s.mint);
  }
  return withAgentOptions(
    command
      .option('--amount <amount>', s.amount, decimalAmount)
      .option('--amount-base-units <units>', s.amountBaseUnits, baseUnits)
      .option('--broadcast', copy.commands.evm.send)
      .option('--no-wait', s.noWait)
      .option('--nonce <mode>', s.nonce)
      .option('--compute-unit-limit <units>', s.computeUnitLimit, positiveInt)
      .option('--compute-unit-price <micro-lamports>', s.computeUnitPrice, nonNegativeInt)
      .option('--approval-wait <secs>', copy.commands.evm.approvalWait, nonNegativeInt)
      .option('--reveal-raw-tx', s.revealRawTx),
  );
}

function transferOptions(options: SolanaOptions) {
  const broadcast = options.broadcast === true;
  return {
    broadcast,
    wait_for_confirmation: broadcast && options.wait !== false,
    nonce: nonceMode(options.nonce),
    reveal_raw_tx: options.revealRawTx === true,
    approval_wait_secs: options.approvalWait ?? (broadcast ? 300 : 0),
    ...opt('compute_unit_limit', options.computeUnitLimit),
    ...opt('compute_unit_price_micro_lamports', options.computeUnitPrice),
  };
}

export function registerSolanaCommands(program: Command, env: CommandEnv): void {
  const s = copy.commands.solana;
  solanaCommand(program, 'transfer-sol', s.transferSol, false).action(
    handler(env, async (options: SolanaOptions) => {
      const amount = amountOf(options);
      const payments = await env.context.payments(options);
      const response = await payments.transferSol({
        network: options.network,
        to: options.to,
        amount,
        options: transferOptions(options),
      });
      return emitPayment(env, options.json, response);
    }),
  );

  solanaCommand(program, 'transfer-spl', s.transferSpl, true).action(
    handler(env, async (options: SolanaOptions) => {
      const amount = amountOf(options);
      const payments = await env.context.payments(options);
      const response = await payments.transferSpl({
        network: options.network,
        mint: options.mint ?? '',
        to: options.to,
        amount,
        options: transferOptions(options),
      });
      return emitPayment(env, options.json, response);
    }),
  );
}
