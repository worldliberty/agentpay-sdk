import type { WlfiConfig } from '@worldlibertyfinancial/agent-config';
import { type Address, formatUnits, parseUnits } from 'viem';

const U128_MAX = (1n << 128n) - 1n;

export interface ResolvedAssetMetadata {
  assetId: string;
  decimals: number;
  symbol: string;
}

export interface RustAmountOutputShape {
  command: string;
  network: string;
  asset: string;
  counterparty: string;
  amount_wei: string;
  estimated_max_gas_spend_wei?: string;
  tx_type?: string;
  delegation_enabled?: boolean;
  signature_hex: string;
  r_hex?: string;
  s_hex?: string;
  v?: number;
  raw_tx_hex?: string;
  tx_hash_hex?: string;
}

function normalizeAddress(value: string): string {
  return value.trim().toLowerCase();
}

function isAllZeroDigits(value: string): boolean {
  return value.split('').every((character) => character === '0' || character === '.');
}

export function normalizePositiveDecimalInput(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized) {
    throw new Error(`${label} is required`);
  }
  if (!/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/u.test(normalized)) {
    throw new Error(`${label} must be a positive decimal string`);
  }
  if (isAllZeroDigits(normalized)) {
    throw new Error(`${label} must be greater than zero`);
  }
  return normalized;
}

export function resolveConfiguredErc20Asset(
  config: WlfiConfig,
  chainId: number,
  tokenAddress: string,
): ResolvedAssetMetadata {
  const normalizedAddress = normalizeAddress(tokenAddress);

  for (const token of Object.values(config.tokens ?? {})) {
    for (const chainProfile of Object.values(token.chains ?? {})) {
      if (
        chainProfile.chainId === chainId &&
        !chainProfile.isNative &&
        normalizeAddress(chainProfile.address ?? '') === normalizedAddress
      ) {
        return {
          assetId: `erc20:${tokenAddress}`,
          decimals: chainProfile.decimals,
          symbol: token.symbol,
        };
      }
    }
  }

  throw new Error(
    `token ${tokenAddress} on chain ${chainId} is not configured; save it first so decimals can be inferred`,
  );
}

export type TokenMetadataFetcher = (
  rpcUrl: string,
  token: Address,
) => Promise<{ symbol: string | null; decimals: number }>;

/**
 * Try local config first; fall back to an on-chain RPC call for decimals/symbol
 * when the token has not been pre-configured.
 */
export async function resolveErc20AssetWithRpcFallback(
  config: WlfiConfig,
  chainId: number,
  tokenAddress: Address,
  rpcUrl: string,
  fetchMetadata: TokenMetadataFetcher,
): Promise<ResolvedAssetMetadata> {
  let configuredError: Error | null = null;
  try {
    return resolveConfiguredErc20Asset(config, chainId, tokenAddress);
  } catch (error) {
    configuredError = error instanceof Error ? error : new Error(String(error));
  }

  try {
    const metadata = await fetchMetadata(rpcUrl, tokenAddress);
    return {
      assetId: `erc20:${tokenAddress}`,
      decimals: metadata.decimals,
      symbol: metadata.symbol ?? tokenAddress,
    };
  } catch {
    throw configuredError ?? new Error(`token ${tokenAddress} metadata lookup failed`);
  }
}

export function resolveConfiguredNativeAsset(
  config: WlfiConfig,
  chainId: number,
): ResolvedAssetMetadata {
  for (const token of Object.values(config.tokens ?? {})) {
    for (const chainProfile of Object.values(token.chains ?? {})) {
      if (chainProfile.chainId === chainId && chainProfile.isNative) {
        return {
          assetId: 'native_eth',
          decimals: chainProfile.decimals,
          symbol: token.symbol,
        };
      }
    }
  }

  throw new Error(
    `native asset on chain ${chainId} is not configured; save it first so decimals can be inferred`,
  );
}

export function parseConfiguredAmount(
  value: string,
  decimals: number,
  label = 'amount',
): bigint {
  const normalized = value.trim();
  if (!normalized) {
    throw new Error(`${label} is required`);
  }
  const decimalMatch = /^(?:0|[1-9][0-9]*)(?:\.([0-9]+))?$/u.exec(normalized);
  if (!decimalMatch || (decimalMatch[1]?.length ?? 0) > decimals) {
    throw new Error(
      `${label} must be a positive decimal amount with at most ${decimals} fractional digits`,
    );
  }

  let parsed: bigint;
  try {
    parsed = parseUnits(normalized, decimals);
  } catch {
    throw new Error(
      `${label} must be a positive decimal amount with at most ${decimals} fractional digits`,
    );
  }

  if (parsed <= 0n) {
    throw new Error(`${label} must be greater than zero`);
  }
  if (parsed > U128_MAX) {
    throw new Error(`${label} is too large`);
  }

  return parsed;
}

export function formatConfiguredAmount(value: bigint | string, decimals: number): string {
  const amount = typeof value === 'bigint' ? value : BigInt(value);
  return formatUnits(amount, decimals);
}

export function normalizeAgentAmountOutput(
  output: RustAmountOutputShape,
  asset: ResolvedAssetMetadata,
) {
  return {
    command: output.command,
    network: output.network,
    asset: asset.symbol,
    assetId: output.asset,
    counterparty: output.counterparty,
    amount: formatConfiguredAmount(output.amount_wei, asset.decimals),
    decimals: asset.decimals,
    estimated_max_gas_spend_wei: output.estimated_max_gas_spend_wei,
    tx_type: output.tx_type,
    delegation_enabled: output.delegation_enabled,
    signature_hex: output.signature_hex,
    r_hex: output.r_hex,
    s_hex: output.s_hex,
    v: output.v,
    raw_tx_hex: output.raw_tx_hex,
    tx_hash_hex: output.tx_hash_hex,
  };
}

export function rewriteAmountPolicyErrorMessage(
  message: string,
  asset: ResolvedAssetMetadata,
): string {
  const formatAmount = (value: string) =>
    `${formatConfiguredAmount(value, asset.decimals)} ${asset.symbol}`;

  return message
    .replace(
      /per transaction max (\d+) < requested (\d+)/gu,
      (_match, maxAmountWei: string, requestedAmountWei: string) =>
        `per transaction max ${formatAmount(maxAmountWei)} < requested ${formatAmount(requestedAmountWei)}`,
    )
    .replace(
      /window usage (\d+) \+ requested (\d+) > max (\d+)/gu,
      (_match, usedAmountWei: string, requestedAmountWei: string, maxAmountWei: string) =>
        `window usage ${formatAmount(usedAmountWei)} + requested ${formatAmount(requestedAmountWei)} > max ${formatAmount(maxAmountWei)}`,
    )
    .replace(
      /requires manual approval for requested amount (\d+) within range (None|Some\((\d+)\))\.\.=(\d+)/gu,
      (
        _match,
        requestedAmountWei: string,
        minAmountLiteral: string,
        minAmountWei: string | undefined,
        maxAmountWei: string,
      ) => {
        const minAmountDisplay =
          /* c8 ignore next -- both None and Some(...) paths are exercised, but c8 misattributes this ternary under --experimental-strip-types */
          minAmountLiteral === 'None' ? 'None' : `Some(${formatAmount(minAmountWei ?? '0')})`;
        return `requires manual approval for requested amount ${formatAmount(requestedAmountWei)} within range ${minAmountDisplay}..=${formatAmount(maxAmountWei)}`;
      },
    );
}
