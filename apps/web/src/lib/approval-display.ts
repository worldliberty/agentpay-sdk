import { listBuiltinTokens } from '../../../../packages/config/src/index.ts';
import type { ApprovalRequestRecord } from './types.ts';

interface ResolvedApprovalAsset {
  decimals: number;
  symbol: string;
}

function formatTokenAmount(rawAmount: bigint, decimals: number): string {
  if (decimals <= 0) {
    return rawAmount.toString();
  }

  const divisor = 10n ** BigInt(decimals);
  const whole = rawAmount / divisor;
  const fraction = rawAmount % divisor;
  if (fraction === 0n) {
    return whole.toString();
  }

  return `${whole}.${fraction.toString().padStart(decimals, '0').replace(/0+$/u, '')}`;
}

function normalizeAddress(value: string): string {
  return value.trim().toLowerCase();
}

function builtinAssetLookupKey(chainId: number, assetAddress: string): string {
  return `${chainId}:${normalizeAddress(assetAddress)}`;
}

const BUILTIN_NATIVE_ASSETS = new Map<number, ResolvedApprovalAsset>();
const BUILTIN_ERC20_ASSETS = new Map<string, ResolvedApprovalAsset>();

for (const token of listBuiltinTokens()) {
  for (const chainProfile of token.chains) {
    const resolvedAsset = {
      decimals: chainProfile.decimals,
      symbol: token.symbol,
    };

    if (chainProfile.isNative) {
      if (!BUILTIN_NATIVE_ASSETS.has(chainProfile.chainId)) {
        BUILTIN_NATIVE_ASSETS.set(chainProfile.chainId, resolvedAsset);
      }
      continue;
    }

    if (!chainProfile.address) {
      continue;
    }

    const lookupKey = builtinAssetLookupKey(chainProfile.chainId, chainProfile.address);
    if (!BUILTIN_ERC20_ASSETS.has(lookupKey)) {
      BUILTIN_ERC20_ASSETS.set(lookupKey, resolvedAsset);
    }
  }
}

function resolveApprovalAsset(approval: ApprovalRequestRecord): ResolvedApprovalAsset | null {
  if (approval.asset === 'native_eth') {
    return BUILTIN_NATIVE_ASSETS.get(approval.chainId) ?? null;
  }

  if (!approval.asset.startsWith('erc20:')) {
    return null;
  }

  const lookupKey = builtinAssetLookupKey(approval.chainId, approval.asset.slice('erc20:'.length));
  return BUILTIN_ERC20_ASSETS.get(lookupKey) ?? null;
}

export function formatApprovalAmount(approval: ApprovalRequestRecord): string {
  const resolvedAsset = resolveApprovalAsset(approval);
  if (!resolvedAsset) {
    return approval.amountWei;
  }

  return `${formatTokenAmount(BigInt(approval.amountWei), resolvedAsset.decimals)} ${resolvedAsset.symbol}`;
}

export function formatApprovalAsset(approval: ApprovalRequestRecord): string {
  const resolvedAsset = resolveApprovalAsset(approval);
  return resolvedAsset?.symbol ?? approval.asset;
}
