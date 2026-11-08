/** EVM payments: `transfer`, `transfer-native`, `approve`, `broadcast`, `sign-typed-data`, `resume`. */
import { readFileSync } from 'node:fs';
import type { Command } from 'commander';
import { expandPath } from '../app/services.js';
import { copy } from '../copy/index.js';
import { UsageError } from '../errors.js';
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

/** Default approval wait with `--broadcast`: keep the command alive while the owner decides. */
export const BROADCAST_APPROVAL_WAIT_SECS = 300;

interface TxOptions extends AgentOptions {
  network?: string;
  broadcast?: boolean;
  wait?: boolean;
  receiptTimeout?: number;
  nonce?: number;
  gasLimit?: number;
  maxFeePerGasWei?: string;
  maxPriorityFeePerGasWei?: string;
  approvalWait?: number;
}

function withTxOptions(command: Command): Command {
  const e = copy.commands.evm;
  return withAgentOptions(
    command
      .option('--network <network>', e.network)
      .option('--broadcast', e.send)
      .option('--no-wait', e.noWait)
      .option('--receipt-timeout <secs>', e.receiptTimeout, positiveInt)
      .option('--nonce <nonce>', e.nonce, nonNegativeInt)
      .option('--gas-limit <gas>', e.gasLimit, positiveInt)
      .option('--max-fee-per-gas-wei <wei>', e.maxFee, baseUnits)
      .option('--max-priority-fee-per-gas-wei <wei>', e.maxPriorityFee, baseUnits)
      .option('--approval-wait <secs>', e.approvalWait, nonNegativeInt),
  );
}

function txParams(options: TxOptions, alwaysSend = false) {
  const send = alwaysSend || options.broadcast === true;
  return {
    broadcast: options.broadcast === true,
    wait_for_receipt: options.broadcast === true && options.wait !== false,
    approval_wait_secs: options.approvalWait ?? (send ? BROADCAST_APPROVAL_WAIT_SECS : 0),
    ...opt('network', options.network),
    ...opt('receipt_timeout_secs', options.receiptTimeout),
    ...opt('nonce', options.nonce),
    ...opt('gas_limit', options.gasLimit),
    ...opt('max_fee_per_gas_wei', options.maxFeePerGasWei),
    ...opt('max_priority_fee_per_gas_wei', options.maxPriorityFeePerGasWei),
  };
}

interface TransferOptions extends TxOptions {
  token?: string;
  asset?: string;
  to: string;
  amount: string;
}

interface ApproveOptions extends TxOptions {
  token?: string;
  asset?: string;
  spender: string;
  amount: string;
}

interface BroadcastOptions extends TxOptions {
  to: string;
  valueWei?: string;
  dataHex?: string;
}

interface TypedDataOptions extends AgentOptions {
  typedData?: string;
  typedDataFile?: string;
  approvalWait?: number;
}

export interface ResumeOptions extends AgentOptions {
  approvalRequestId: string;
  approvalWait?: number;
}

/** `ResumeApproved`: finishes a payment that returned `ManualApprovalPending`. */
export async function resumePayment(env: CommandEnv, options: ResumeOptions): Promise<number> {
  const payments = await env.context.payments(options);
  const response = await payments.resumeApproved({
    approval_request_id: options.approvalRequestId,
    ...opt('approval_wait_secs', options.approvalWait),
  });
  return emitPayment(env, options.json, response);
}

export function registerEvmCommands(program: Command, env: CommandEnv): void {
  const e = copy.commands.evm;

  withTxOptions(
    program
      .command('transfer')
      .description(e.transfer)
      .option('--token <asset>', e.token)
      .option('--asset <asset>', e.token)
      .requiredOption('--to <address>', e.to)
      .requiredOption('--amount <amount>', e.amount, decimalAmount),
  ).action(
    handler(env, async (options: TransferOptions) => {
      const payments = await env.context.payments(options);
      const response = await payments.transfer({
        ...txParams(options),
        ...opt('asset', options.token ?? options.asset),
        to: options.to,
        amount: options.amount,
      });
      return emitPayment(env, options.json, response);
    }),
  );

  withTxOptions(
    program
      .command('transfer-native')
      .description(e.transferNative)
      .requiredOption('--to <address>', e.to)
      .requiredOption('--amount <amount>', e.amount, decimalAmount),
  ).action(
    handler(env, async (options: TransferOptions) => {
      const payments = await env.context.payments(options);
      const response = await payments.transferNative({
        ...txParams(options),
        to: options.to,
        amount: options.amount,
      });
      return emitPayment(env, options.json, response);
    }),
  );

  withTxOptions(
    program
      .command('approve')
      .description(e.approve)
      .option('--token <asset>', e.token)
      .option('--asset <asset>', e.token)
      .requiredOption('--spender <address>', e.spender)
      .requiredOption('--amount <amount>', e.amount, decimalAmount),
  ).action(
    handler(env, async (options: ApproveOptions) => {
      const payments = await env.context.payments(options);
      const response = await payments.approve({
        ...txParams(options),
        ...opt('asset', options.token ?? options.asset),
        spender: options.spender,
        amount: options.amount,
      });
      return emitPayment(env, options.json, response);
    }),
  );

  withTxOptions(
    program
      .command('broadcast')
      .description(e.broadcast)
      .requiredOption('--to <address>', e.to)
      .option('--value-wei <wei>', e.valueWei, baseUnits)
      .option('--data-hex <hex>', e.dataHex),
  ).action(
    handler(env, async (options: BroadcastOptions) => {
      if (options.dataHex !== undefined && !/^0x([0-9a-f]{2})*$/iu.test(options.dataHex)) {
        throw new UsageError('--data-hex must be 0x-prefixed hex');
      }
      const payments = await env.context.payments(options);
      const response = await payments.broadcast({
        ...txParams(options),
        to: options.to,
        value_wei: options.valueWei ?? '0',
        data_hex: options.dataHex ?? '0x',
      });
      return emitPayment(env, options.json, response);
    }),
  );

  withAgentOptions(
    program
      .command('sign-typed-data')
      .description(e.signTypedData)
      .option('--typed-data <json>', e.typedData)
      .option('--typed-data-file <path>', e.typedDataFile)
      .option('--approval-wait <secs>', e.approvalWait, nonNegativeInt),
  ).action(
    handler(env, async (options: TypedDataOptions) => {
      if ((options.typedData === undefined) === (options.typedDataFile === undefined)) {
        throw new UsageError('pass exactly one of --typed-data or --typed-data-file');
      }
      const text =
        options.typedData ?? readFileSync(expandPath(options.typedDataFile ?? ''), 'utf8');
      try {
        JSON.parse(text);
      } catch {
        throw new UsageError('the typed data is not valid JSON');
      }
      const payments = await env.context.payments(options);
      const response = await payments.signTypedData({
        typed_data_json: text.trim(),
        ...opt('approval_wait_secs', options.approvalWait),
      });
      return emitPayment(env, options.json, response);
    }),
  );

  withAgentOptions(
    program
      .command('resume')
      .description(e.resume)
      .requiredOption('--approval-request-id <uuid>', e.approvalRequestId)
      .option('--approval-wait <secs>', e.approvalWait, nonNegativeInt),
  ).action(handler(env, (options: ResumeOptions) => resumePayment(env, options)));
}
