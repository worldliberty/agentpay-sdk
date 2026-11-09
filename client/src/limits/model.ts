/**
 * Spending limits as the screens see them: one row per configured asset deployment (token on
 * one network) with per-payment, daily, and weekly limits in whole units.
 *
 * Deny by default: a row that is neither set nor blocked stays blocked in the signer daemon, and
 * the onboarding flow refuses to continue until every row is decided, so no asset is ever left
 * in an ambiguous state.
 */
import {
  compareDecimal,
  formatUnits,
  isDecimalString,
  parseUnits,
  stepAmount,
} from '../format/amount.js';
import type {
  AssetId,
  PaymentsConfig,
  SpendingLimit,
  SpendingLimitStatus,
  TokenLimits,
} from '../generated/index.js';

export type LimitStatus = 'recommended' | 'custom' | 'excluded' | 'unset';
export type LimitField = 'perTx' | 'daily' | 'weekly';
export const LIMIT_FIELDS: readonly LimitField[] = ['perTx', 'daily', 'weekly'];

/** Spent in the rolling windows (whole units). */
export interface LimitUsage {
  dailyUsed: string | null;
  weeklyUsed: string | null;
}

/** Optional caps of an existing limit that the editor does not show but must keep. */
export type LimitExtras = Omit<
  SpendingLimit,
  'chain_id' | 'asset' | 'per_tx_max_wei' | 'daily_max_wei' | 'weekly_max_wei'
>;

export interface LimitRow {
  /** `<token key>@<network key>` */
  id: string;
  tokenKey: string;
  symbol: string;
  network: string;
  networkName: string;
  chainId: number;
  decimals: number;
  asset: AssetId;
  status: LimitStatus;
  /** Whole units; `''` when unset. */
  perTx: string;
  daily: string;
  weekly: string;
  recommended: TokenLimits | null;
  usage: LimitUsage | null;
  extras: LimitExtras;
  /**
   * Set on a token added in setup before the wallet existed: it is saved to the payments
   * configuration once the wallet (and its agent credentials) are created.
   */
  newToken?: NewTokenInfo;
}

/** A token read from its network (or typed in) that is not in the configuration yet. */
export interface NewTokenInfo {
  network: string;
  address: string;
  symbol: string;
  decimals: number;
}

/** A limit row for a token that is not configured yet (unset: it needs a limit or a block). */
export function newTokenRow(config: PaymentsConfig, token: NewTokenInfo): LimitRow | null {
  const chain = config.chains[token.network];
  const asset = chain ? assetIdFor(chain.family, false, token.address) : null;
  if (!chain || !asset) {
    return null;
  }
  return {
    id: `${token.symbol.toLowerCase()}@${token.network}#${assetKey(asset)}`,
    tokenKey: token.symbol.toLowerCase(),
    symbol: token.symbol,
    network: token.network,
    networkName: chain.name,
    chainId: chain.chain_id,
    decimals: token.decimals,
    asset,
    status: 'unset',
    perTx: '',
    daily: '',
    weekly: '',
    recommended: null,
    usage: null,
    extras: {},
    newToken: token,
  };
}

/** Tempo chains have no native gas coin, so their "native" entries are not spendable assets. */
const NO_NATIVE_ASSET_CHAINS = new Set([4217, 42431]);

/** The Solana network ids (mainnet, devnet, testnet), and the one their limits are kept under. */
const SOLANA_CHAIN_IDS = new Set([900000001, 900000002, 900000003]);
const SOLANA_POLICY_CHAIN_ID = 900000001;

/**
 * Test networks: Solana devnet and testnet, Tempo Moderato, BSC testnet, Sepolia, Base Sepolia,
 * Arbitrum Sepolia. The setup wizard leaves them blocked and out of sight.
 */
const TESTNET_CHAIN_IDS = new Set([900000002, 900000003, 42431, 97, 11155111, 84532, 421614]);

/**
 * The network a limit is kept under. Every Solana cluster shares one policy network (the signer
 * daemon reports it as `900000001`), so one SOL limit covers mainnet, devnet, and testnet.
 */
export function policyChainId(chainId: number): number {
  return SOLANA_CHAIN_IDS.has(chainId) ? SOLANA_POLICY_CHAIN_ID : chainId;
}

/** Whether a chain is a test network. */
export function isTestnetChain(chainId: number): boolean {
  return TESTNET_CHAIN_IDS.has(chainId);
}

/** Whether a row is for a test network. */
export function isTestnetRow(row: Pick<LimitRow, 'chainId'>): boolean {
  return isTestnetChain(row.chainId);
}

/** Whether a chain's native entry is a real coin (Tempo's is not). */
export function hasNativeAsset(chainId: number): boolean {
  return !NO_NATIVE_ASSET_CHAINS.has(chainId);
}

function assetIdFor(family: string, isNative: boolean, address: string | null): AssetId | null {
  if (family === 'solana') {
    return isNative
      ? { kind: 'native_sol' }
      : address
        ? { kind: 'spl_token', value: address }
        : null;
  }
  return isNative
    ? { kind: 'native_eth' }
    : address
      ? { kind: 'erc20', value: address.toLowerCase() }
      : null;
}

function assetKey(asset: AssetId): string {
  return 'value' in asset ? `${asset.kind}:${asset.value.toLowerCase()}` : asset.kind;
}

/** How the signer daemon tells limits apart: their policy network and asset. */
export function limitKey(chainId: number, asset: AssetId): string {
  return `${policyChainId(chainId)}:${assetKey(asset)}`;
}

function sameAsset(a: AssetId, b: AssetId): boolean {
  if (a.kind !== b.kind) {
    return false;
  }
  return !('value' in a) || a.value.toLowerCase() === (b as { value: string }).value.toLowerCase();
}

function fromWei(value: string | null | undefined, decimals: number): string {
  return value === null || value === undefined ? '' : formatUnits(BigInt(value), decimals);
}

function statusFor(row: Pick<LimitRow, 'perTx' | 'daily' | 'weekly' | 'recommended'>): LimitStatus {
  if (!row.perTx || !row.daily || !row.weekly) {
    return 'unset';
  }
  const r = row.recommended;
  return r && r.per_tx === row.perTx && r.daily === row.daily && r.weekly === row.weekly
    ? 'recommended'
    : 'custom';
}

/**
 * Builds the rows from the payments configuration, overlaid with the daemon's current limits
 * when known. Without current limits, rows start at the recommended values (or unset).
 *
 * One row per policy network and asset, as the signer daemon keeps them: SOL configured on
 * several Solana clusters is one row, shown as its mainnet deployment.
 */
export function rowsFromConfig(
  config: PaymentsConfig,
  existing: readonly SpendingLimitStatus[] | null = null,
): LimitRow[] {
  const rows: LimitRow[] = [];
  const seen = new Set<string>();
  const deployments = Object.entries(config.tokens).flatMap(([tokenKey, token]) =>
    Object.entries(token.chains).map(([network, deployment]) => ({
      tokenKey,
      token,
      network,
      deployment,
    })),
  );
  // The deployment on the policy network itself (Solana mainnet) represents the row.
  const canonicalFirst = (chainId: number) => (policyChainId(chainId) === chainId ? 0 : 1);
  deployments.sort(
    (a, b) => canonicalFirst(a.deployment.chain_id) - canonicalFirst(b.deployment.chain_id),
  );
  for (const { tokenKey, token, network, deployment } of deployments) {
    const chain = config.chains[network];
    if (!chain || (deployment.is_native && !hasNativeAsset(deployment.chain_id))) {
      continue;
    }
    const asset = assetIdFor(chain.family, deployment.is_native, deployment.address);
    if (!asset) {
      continue;
    }
    const policyChain = policyChainId(deployment.chain_id);
    const key = limitKey(deployment.chain_id, asset);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    const current = existing?.find(
      (row) =>
        policyChainId(row.limit.chain_id) === policyChain && sameAsset(row.limit.asset, asset),
    );
    const base = {
      id: `${tokenKey}@${network}`,
      tokenKey,
      symbol: token.symbol,
      network,
      networkName: chain.name,
      chainId: deployment.chain_id,
      decimals: deployment.decimals,
      asset,
      recommended: token.recommended_limits,
    };
    if (current) {
      const {
        chain_id: _chainId,
        asset: _asset,
        per_tx_max_wei: perTxWei,
        daily_max_wei: dailyWei,
        weekly_max_wei: weeklyWei,
        ...extras
      } = current.limit;
      const values = {
        perTx: fromWei(perTxWei, deployment.decimals),
        daily: fromWei(dailyWei, deployment.decimals),
        weekly: fromWei(weeklyWei, deployment.decimals),
      };
      rows.push({
        ...base,
        ...values,
        status: statusFor({ ...values, recommended: base.recommended }),
        usage: {
          dailyUsed: fromWei(current.usage.spent_24h_wei, deployment.decimals),
          weeklyUsed: fromWei(current.usage.spent_7d_wei, deployment.decimals),
        },
        extras,
      });
    } else {
      const values = {
        perTx: token.recommended_limits?.per_tx ?? '',
        daily: token.recommended_limits?.daily ?? '',
        weekly: token.recommended_limits?.weekly ?? '',
      };
      rows.push({
        ...base,
        ...values,
        // Deny by default: an asset without a limit row in the daemon is blocked.
        status: existing ? 'excluded' : statusFor({ ...values, recommended: base.recommended }),
        usage: null,
        extras: {},
      });
    }
  }
  const defaultFirst = (row: LimitRow) => (row.network === config.default_network ? 0 : 1);
  return rows.sort(
    (a, b) =>
      defaultFirst(a) - defaultFirst(b) ||
      a.networkName.localeCompare(b.networkName) ||
      a.symbol.localeCompare(b.symbol),
  );
}

/** Rows with a limit (the agent may spend these). */
export function setCount(rows: readonly LimitRow[]): number {
  return rows.filter((row) => row.status === 'recommended' || row.status === 'custom').length;
}

/** Rows that still need a decision (a limit or blocking). */
export function undecidedCount(rows: readonly LimitRow[]): number {
  return rows.filter((row) => row.status === 'unset').length;
}

/** Whether a set row's limits are out of order (daily < per payment, or weekly < daily). */
export function hasOrderProblem(row: LimitRow): boolean {
  if (row.status === 'excluded' || row.status === 'unset') {
    return false;
  }
  return compareDecimal(row.daily, row.perTx) < 0 || compareDecimal(row.weekly, row.daily) < 0;
}

/**
 * Sets one field to a typed amount (whole units). `null` when the text is not a positive amount
 * the token can represent. Like stepping, empty fields of an unset row take the same value.
 */
export function setRowField(row: LimitRow, field: LimitField, text: string): LimitRow | null {
  const value = text.trim();
  const fraction = value.split('.')[1] ?? '';
  if (
    !isDecimalString(value) ||
    compareDecimal(value, '0') <= 0 ||
    fraction.length > row.decimals
  ) {
    return null;
  }
  const next = { ...row, [field]: value };
  for (const other of LIMIT_FIELDS) {
    if (!next[other]) {
      next[other] = value;
    }
  }
  return { ...next, status: statusFor(next) };
}

/** Blocks every row that still needs a choice. */
export function blockUndecided(rows: readonly LimitRow[]): LimitRow[] {
  return rows.map((row) => (row.status === 'unset' ? { ...row, status: 'excluded' } : row));
}

/** Applies a +/- step to one field. Stepping an unset row starts from the recommended values. */
export function stepRow(row: LimitRow, field: LimitField, direction: 1 | -1): LimitRow {
  const seeded =
    row.status === 'excluded' || row.status === 'unset'
      ? {
          ...row,
          perTx: row.perTx || row.recommended?.per_tx || '',
          daily: row.daily || row.recommended?.daily || '',
          weekly: row.weekly || row.recommended?.weekly || '',
        }
      : row;
  const next = { ...seeded, [field]: stepAmount(seeded[field] || '0', direction) };
  // Keep a fully stepped-down field at the smallest step: 0 would be a block, not a limit.
  if (!isDecimalString(next[field]) || compareDecimal(next[field], '0') === 0) {
    next[field] = stepAmount('0', 1);
  }
  for (const other of LIMIT_FIELDS) {
    if (!next[other]) {
      next[other] = next[field];
    }
  }
  return { ...next, status: statusFor(next) };
}

/** Blocks a row, or unblocks it back to its values (or the recommended ones). */
export function toggleExcluded(row: LimitRow): LimitRow {
  if (row.status !== 'excluded') {
    return { ...row, status: 'excluded' };
  }
  const restored = {
    ...row,
    perTx: row.perTx || row.recommended?.per_tx || '',
    daily: row.daily || row.recommended?.daily || '',
    weekly: row.weekly || row.recommended?.weekly || '',
  };
  return { ...restored, status: statusFor(restored) };
}

/**
 * The daemon's limit set: one `SpendingLimit` per row with a limit. Blocked rows are simply
 * absent (deny by default).
 */
export function toSpendingLimits(rows: readonly LimitRow[]): SpendingLimit[] {
  return rows
    .filter((row) => row.status === 'recommended' || row.status === 'custom')
    .map((row) => ({
      chain_id: policyChainId(row.chainId),
      asset: row.asset,
      per_tx_max_wei: parseUnits(row.perTx, row.decimals).toString(),
      daily_max_wei: parseUnits(row.daily, row.decimals).toString(),
      weekly_max_wei: parseUnits(row.weekly, row.decimals).toString(),
      ...row.extras,
    }));
}

/**
 * Limits this large mean "no limit": 0.5.x stored an unlimited window as the u128 maximum, and
 * migration keeps it. Shown as "No limit" rather than a 39-digit number; saved back unchanged.
 */
const NO_LIMIT_UNITS = 2n ** 127n;

export function isNoLimit(value: string, decimals: number): boolean {
  return isDecimalString(value) && parseUnits(value, decimals) >= NO_LIMIT_UNITS;
}

/** `used` and `left` for a usage bar, in whole units, from a limit and a used amount. */
export function remaining(
  limit: string,
  used: string,
  decimals: number,
): { used: bigint; limit: bigint; left: string } {
  const limitUnits = parseUnits(limit, decimals);
  const usedUnits = parseUnits(used, decimals);
  const left = limitUnits > usedUnits ? limitUnits - usedUnits : 0n;
  return { used: usedUnits, limit: limitUnits, left: formatUnits(left, decimals) };
}

/** Sets a row's three limits (whole units), or blocks it. */
export function setRowLimits(
  row: LimitRow,
  change: {
    perTx?: string | undefined;
    daily?: string | undefined;
    weekly?: string | undefined;
    exclude?: boolean | undefined;
  },
): LimitRow {
  if (change.exclude) {
    return { ...row, status: 'excluded' };
  }
  const next = {
    ...row,
    perTx: change.perTx ?? row.perTx,
    daily: change.daily ?? row.daily,
    weekly: change.weekly ?? row.weekly,
  };
  return { ...next, status: statusFor(next) };
}

/** The `--json` shape of one row. */
export function limitRowJson(row: LimitRow) {
  return {
    asset: row.tokenKey,
    symbol: row.symbol,
    network: row.network,
    chain_id: row.chainId,
    status: row.status,
    per_tx: row.perTx || null,
    daily: row.daily || null,
    weekly: row.weekly || null,
    daily_used: row.usage?.dailyUsed ?? null,
    weekly_used: row.usage?.weeklyUsed ?? null,
  };
}
