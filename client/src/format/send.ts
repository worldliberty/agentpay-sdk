/**
 * Sending from the TUI: what can be sent (every configured token, with the wallet's balance),
 * checks on the recipient and the amount, and the daemon's answer in one shape (sent, or
 * waiting for approval).
 */
import { copy } from '../copy/index.js';
import type {
  PaymentsConfig,
  PaymentsRpcResponse,
  WalletSummaryResult,
} from '../generated/index.js';
import { compareDecimal, formatUnits, isDecimalString, parseUnits } from './amount.js';
import { type ReceiveOption, receiveOptions } from './receive.js';

export interface SendOption extends ReceiveOption {
  family: 'evm' | 'solana';
  /** The chain's own coin (BNB, ETH, SOL), as opposed to a token contract or mint. */
  native: boolean;
  /** Token contract (EVM) or mint (Solana); `null` for the native coin. */
  token: string | null;
  decimals: number;
  /** Whole units, `null` when the balance could not be read. */
  balance: string | null;
}

/** Native coins keep this much (whole units) back for network fees when sending the maximum. */
const FEE_RESERVE: Readonly<Record<'evm' | 'solana', string>> = { evm: '0.001', solana: '0.0001' };

export function sendOptions(
  config: PaymentsConfig,
  wallet: WalletSummaryResult,
  { includeTestnets }: { includeTestnets: boolean },
): SendOption[] {
  return receiveOptions(config, { includeTestnets }).flatMap((option) => {
    const deployment = config.tokens[option.asset]?.chains[option.network];
    const chain = config.chains[option.network];
    if (!deployment || !chain) {
      return [];
    }
    const entry = wallet.balances.find(
      (b) => b.network === option.network && b.asset === option.asset,
    );
    return [
      {
        ...option,
        family: chain.family,
        native: deployment.is_native,
        token: deployment.address,
        decimals: deployment.decimals,
        balance: entry?.balance ?? null,
      },
    ];
  });
}

/** The most that can be sent: the balance, less a fee reserve for a native coin. */
export function maxAmount(option: SendOption): string | null {
  if (option.balance === null) {
    return null;
  }
  if (!option.native) {
    return option.balance;
  }
  const units =
    parseUnits(option.balance, option.decimals) -
    parseUnits(FEE_RESERVE[option.family], option.decimals);
  return units > 0n ? formatUnits(units, option.decimals) : '0';
}

const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/u;
const SOLANA_ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/u;

/** Why `to` cannot receive this payment, or `null` when it can. */
export function recipientProblem(
  option: SendOption,
  to: string,
  ownAddresses: readonly (string | null)[],
): string | null {
  const s = copy.screens.send;
  const address = to.trim();
  const valid = option.family === 'evm' ? EVM_ADDRESS.test(address) : SOLANA_ADDRESS.test(address);
  if (!valid) {
    return option.family === 'evm' ? s.badEvmAddress : s.badSolanaAddress;
  }
  const own = ownAddresses.some(
    (mine) => mine !== null && mine.toLowerCase() === address.toLowerCase(),
  );
  return own ? s.ownAddress : null;
}

/** Why `amount` cannot be sent, or `null` when it can. */
export function amountProblem(option: SendOption, amount: string): string | null {
  const s = copy.screens.send;
  const value = amount.trim();
  if (!isDecimalString(value) || compareDecimal(value, '0') <= 0) {
    return s.badAmount;
  }
  if ((value.split('.')[1] ?? '').length > option.decimals) {
    return s.tooManyDecimals(option.symbol, option.decimals);
  }
  if (option.balance !== null && compareDecimal(value, option.balance) > 0) {
    return s.overBalance(option.balance, option.symbol);
  }
  return null;
}

export type SendOutcome =
  | { kind: 'sent'; hash: string; confirmed: boolean; failed: boolean }
  /** `reasons`: why it waits, one sentence per limit (filled in from the approval request). */
  | { kind: 'pending'; approvalRequestId: string; reasons: string[] };

type PaymentResponse = Extract<
  PaymentsRpcResponse,
  { type: 'EvmTransaction' | 'EvmSignature' | 'SolanaTransfer' | 'ManualApprovalPending' }
>;

/** The daemon's answer to a broadcast send, in the screen's terms. */
export function sendOutcome(response: PaymentResponse): SendOutcome {
  switch (response.type) {
    case 'ManualApprovalPending':
      return {
        kind: 'pending',
        approvalRequestId: response.data.approval_request_id,
        reasons: [],
      };
    case 'EvmTransaction':
      return {
        kind: 'sent',
        hash: response.data.tx_hash,
        confirmed: response.data.receipt?.success === true,
        failed: response.data.receipt?.success === false,
      };
    case 'SolanaTransfer': {
      const status = response.data.broadcast?.status;
      return {
        kind: 'sent',
        hash: response.data.signature,
        confirmed: status === 'confirmed' || status === 'finalized',
        failed: status === 'failed',
      };
    }
    case 'EvmSignature':
      // Only returned without broadcast, which the TUI never asks for.
      return { kind: 'sent', hash: response.data.signature_hex, confirmed: false, failed: false };
  }
}
