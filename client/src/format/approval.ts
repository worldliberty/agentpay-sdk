import { copy } from '../copy/index.js';
import type {
  ApprovalReason,
  AssetId,
  ManualApprovalRequest,
  PaymentsConfig,
  TokenChainProfile,
} from '../generated/index.js';
import { displayAmount, formatUnits } from './amount.js';

/** Known Solana policy chain ids (`agentpay-domain`'s internal network ids). */
const SOLANA_CHAIN_NAMES: Readonly<Record<number, string>> = {
  900000001: 'Solana',
  900000002: 'Solana Devnet',
  900000003: 'Solana Testnet',
};

/** What an approval request asks for, in the terms the approval screen shows. */
export interface ApprovalSummary {
  /** Short verb phrase: "Send", "Allow spending", ... */
  action: string;
  /** Recipient, spender, or merchant address. */
  to: string;
  /** "1 USD1", or base units with the asset when the token is unknown. */
  amount: string;
  /** Token symbol, when known. */
  symbol: string | null;
  /** Network display name. */
  network: string;
  agentKeyId: string;
  /** Why it waits for approval, one sentence per limit it goes over. */
  reasons: string[];
  /** The first reason in a few words, for the list. */
  shortReason: string | null;
}

const ACTION_LABELS: Readonly<Record<string, string>> = {
  Approve: 'Allow spending',
  Transfer: 'Send',
  TransferNative: 'Send',
  BroadcastTx: 'Send transaction',
  Eip3009TransferWithAuthorization: 'Pay (x402 or MPP)',
  Eip3009ReceiveWithAuthorization: 'Pay (x402)',
  TempoSessionV2OpenTransaction: 'Open payment session (MPP)',
  TempoSessionV2TopUpTransaction: 'Top up payment session (MPP)',
  TempoSessionV2Voucher: 'Pay (MPP session)',
  TempoSessionV2CloseAuthorization: 'Close payment session (MPP)',
  Eip712TypedData: 'Sign typed data',
  SolanaSolTransfer: 'Send',
  SolanaSplTransfer: 'Send',
  SolanaPaymentTransaction: 'Pay (MPP)',
  Permit2WitnessTransfer: 'Pay (MPP permit2)',
  SolanaNonceAccountCreate: 'Create nonce account',
};

/** Network display name for a chain id, from the payments configuration when possible. */
export function networkName(chainId: number, config: PaymentsConfig | null): string {
  const configured = config
    ? Object.values(config.chains).find((chain) => chain.chain_id === chainId)
    : undefined;
  return configured?.name ?? SOLANA_CHAIN_NAMES[chainId] ?? `chain ${chainId}`;
}

interface AssetInfo {
  symbol: string;
  decimals: number;
}

function findDeployment(
  config: PaymentsConfig | null,
  predicate: (deployment: TokenChainProfile) => boolean,
): AssetInfo | null {
  for (const token of Object.values(config?.tokens ?? {})) {
    for (const deployment of Object.values(token.chains)) {
      if (predicate(deployment)) {
        return { symbol: token.symbol, decimals: deployment.decimals };
      }
    }
  }
  return null;
}

/** Symbol and decimals of `asset` on `chainId`, when the configuration knows it. */
export function assetInfo(
  asset: AssetId,
  chainId: number,
  config: PaymentsConfig | null,
): AssetInfo | null {
  switch (asset.kind) {
    case 'native_eth':
      return (
        findDeployment(config, (d) => d.chain_id === chainId && d.is_native) ?? {
          symbol: 'native coin',
          decimals: 18,
        }
      );
    case 'native_sol':
      return { symbol: 'SOL', decimals: 9 };
    case 'erc20':
    case 'spl_token': {
      const address = asset.value.toLowerCase();
      return findDeployment(
        config,
        (d) => d.chain_id === chainId && d.address?.toLowerCase() === address,
      );
    }
  }
}

/** Formats `amountWei` of `asset` as "1.5 USD1", or "<base units> base units of 0x…" if unknown. */
export function describeAmount(
  amountWei: string,
  asset: AssetId,
  chainId: number,
  config: PaymentsConfig | null,
): { text: string; symbol: string | null } {
  const info = assetInfo(asset, chainId, config);
  if (!info) {
    const token = 'value' in asset ? asset.value : asset.kind;
    return { text: `${amountWei} base units of ${token}`, symbol: null };
  }
  return {
    text: `${displayAmount(formatUnits(BigInt(amountWei), info.decimals), info.decimals)} ${info.symbol}`,
    symbol: info.symbol,
  };
}

/** One sentence per limit the request goes over ("Over your daily limit: 80 of 100 USD1 used…"). */
export function approvalReasons(
  request: ManualApprovalRequest,
  config: PaymentsConfig | null,
): { reasons: string[]; shortReason: string | null } {
  const r = copy.screens.approvals;
  const money = (wei: string | null) =>
    wei === null ? '—' : describeAmount(wei, request.asset, request.chain_id, config).text;
  const requested = money(request.amount_wei);
  const sentence: Record<ApprovalReason['limit'], (reason: ApprovalReason) => string> = {
    per_payment: (reason) => r.reasons.perPayment(money(reason.max)),
    daily: (reason) => r.reasons.daily(money(reason.used ?? '0'), money(reason.max), requested),
    weekly: (reason) => r.reasons.weekly(money(reason.used ?? '0'), money(reason.max), requested),
    daily_count: (reason) => r.reasons.dailyCount(reason.used ?? '0', reason.max ?? '—'),
    policy: () => r.reasons.policy,
    eip712: () => r.reasons.eip712,
  };
  const reasons = request.reasons.map((reason) => sentence[reason.limit](reason));
  const first = request.reasons[0]?.limit;
  const short: Record<ApprovalReason['limit'], string> = {
    per_payment: r.short.perPayment,
    daily: r.short.daily,
    weekly: r.short.weekly,
    daily_count: r.short.dailyCount,
    policy: r.short.policy,
    eip712: r.short.eip712,
  };
  return { reasons, shortReason: first ? short[first] : null };
}

/** Summarizes an approval request for the list and detail screens. */
export function summarizeApproval(
  request: ManualApprovalRequest,
  config: PaymentsConfig | null,
): ApprovalSummary {
  const amount = describeAmount(request.amount_wei, request.asset, request.chain_id, config);
  return {
    action: ACTION_LABELS[request.action.kind] ?? request.action.kind,
    to: request.recipient.value,
    amount: amount.text,
    symbol: amount.symbol,
    network: networkName(request.chain_id, config),
    agentKeyId: request.agent_key_id,
    ...approvalReasons(request, config),
  };
}
