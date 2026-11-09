import { describe, expect, it } from 'vitest';
import type { PaymentsConfig, SpendingLimitsReport } from '../src/generated/index.js';
import { DEFAULT_PAYMENTS_CONFIG } from '../src/limits/default-config.js';
import {
  hasOrderProblem,
  isNoLimit,
  isTestnetRow,
  type LimitRow,
  policyChainId,
  rowsFromConfig,
  setCount,
  stepRow,
  toggleExcluded,
  toSpendingLimits,
  undecidedCount,
} from '../src/limits/model.js';
import { fixtureData } from './helpers/fixtures.js';

const byId = (rows: LimitRow[], id: string) => {
  const row = rows.find((r) => r.id === id);
  if (!row) {
    throw new Error(`no row ${id}`);
  }
  return row;
};

describe('limit rows', () => {
  it('seeds one row per spendable deployment with the recommended limits', () => {
    const rows = rowsFromConfig(DEFAULT_PAYMENTS_CONFIG);
    expect(rows[0]?.network).toBe('bsc');
    expect(byId(rows, 'usd1@bsc')).toMatchObject({
      status: 'recommended',
      perTx: '10',
      daily: '100',
      weekly: '700',
    });
    expect(byId(rows, 'eth@eth')).toMatchObject({ status: 'unset', perTx: '' });
    // Tempo has no native gas coin, so "usd" (native on Tempo) is not a spendable asset row.
    expect(rows.some((r) => r.id === 'usd@tempo')).toBe(false);
    // ETH has no recommended limit: one undecided row per network it is on.
    const undecided = rows.filter((r) => r.status === 'unset').map((r) => r.id);
    expect(new Set(undecided)).toEqual(
      new Set([
        'eth@eth',
        'eth@arbitrum',
        'eth@arbitrum-sepolia',
        'eth@base',
        'eth@base-sepolia',
        'eth@optimism',
      ]),
    );
    expect(undecidedCount(rows)).toBe(undecided.length);
    expect(byId(rows, 'pol@polygon')).toMatchObject({
      status: 'recommended',
      networkName: 'Polygon',
    });
    expect(byId(rows, 'usdc@base')).toMatchObject({
      status: 'recommended',
      networkName: 'Base',
      decimals: 6,
      asset: { kind: 'erc20', value: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913' },
    });
  });

  it('keeps one SOL row for every Solana cluster, under the shared policy network', () => {
    const rows = rowsFromConfig(DEFAULT_PAYMENTS_CONFIG);
    const sol = rows.filter((row) => row.asset.kind === 'native_sol');
    expect(sol).toHaveLength(1);
    expect(sol[0]).toMatchObject({ network: 'solana-mainnet', networkName: 'Solana' });
    expect(policyChainId(900000002)).toBe(900000001);
    expect(policyChainId(56)).toBe(56);

    // Different mints are different assets, even on a test cluster.
    const usdc = rows.filter((row) => row.symbol === 'USDC' && row.asset.kind === 'spl_token');
    expect(usdc.length).toBeGreaterThan(1);

    const limits = toSpendingLimits(rows.filter((row) => row.status !== 'unset'));
    const keys = limits.map((l) => `${l.chain_id}:${JSON.stringify(l.asset)}`);
    expect(new Set(keys).size).toBe(keys.length);
    expect(limits.some((l) => l.chain_id === 900000002 || l.chain_id === 900000003)).toBe(false);
  });

  it('reads a Solana limit reported under the shared network onto the SOL row', () => {
    const report = fixtureData<SpendingLimitsReport>('rpc/ListSpendingLimits.response.json');
    const [template] = report.limits;
    if (!template) {
      throw new Error('fixture has no limits');
    }
    const sol = {
      ...template,
      limit: {
        chain_id: 900000001,
        asset: { kind: 'native_sol' as const },
        per_tx_max_wei: '50000000',
        daily_max_wei: '1000000000',
        weekly_max_wei: '7000000000',
      },
    };
    const rows = rowsFromConfig(DEFAULT_PAYMENTS_CONFIG, [sol]);
    expect(rows.find((r) => r.asset.kind === 'native_sol')).toMatchObject({
      status: 'recommended',
      perTx: '0.05',
      daily: '1',
      weekly: '7',
    });
  });

  it('marks test networks', () => {
    const rows = rowsFromConfig(DEFAULT_PAYMENTS_CONFIG);
    const testnets = rows.filter(isTestnetRow).map((row) => row.network);
    expect(new Set(testnets)).toEqual(
      new Set(['solana-devnet', 'tempo-testnet', 'arbitrum-sepolia', 'base-sepolia']),
    );
    expect(rows.filter((row) => !isTestnetRow(row)).some((r) => r.network === 'bsc')).toBe(true);
  });

  it('every row must be set or blocked; blocked rows are left out of the limit set', () => {
    let rows = rowsFromConfig(DEFAULT_PAYMENTS_CONFIG);
    rows = rows.map((row) => (row.tokenKey === 'eth' ? toggleExcluded(row) : row));
    expect(undecidedCount(rows)).toBe(0);
    const limits = toSpendingLimits(rows);
    expect(limits).toHaveLength(setCount(rows));
    expect(limits.some((l) => l.chain_id === 1 && l.asset.kind === 'native_eth')).toBe(false);
    expect(limits.find((l) => l.chain_id === 56 && l.asset.kind === 'erc20')).toEqual({
      chain_id: 56,
      asset: { kind: 'erc20', value: '0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d' },
      per_tx_max_wei: '10000000000000000000',
      daily_max_wei: '100000000000000000000',
      weekly_max_wei: '700000000000000000000',
    });
  });

  it('steppers move along the ladder and mark the row custom', () => {
    const row = byId(rowsFromConfig(DEFAULT_PAYMENTS_CONFIG), 'usd1@bsc');
    const up = stepRow(row, 'perTx', 1);
    expect(up).toMatchObject({ perTx: '20', status: 'custom' });
    expect(stepRow(up, 'perTx', -1).status).toBe('recommended');
    const unset = byId(rowsFromConfig(DEFAULT_PAYMENTS_CONFIG), 'eth@eth');
    expect(stepRow(unset, 'daily', 1)).toMatchObject({
      status: 'custom',
      perTx: '0.001',
      daily: '0.001',
    });
  });

  it('flags limits out of order', () => {
    const row = byId(rowsFromConfig(DEFAULT_PAYMENTS_CONFIG), 'usd1@bsc');
    expect(hasOrderProblem(row)).toBe(false);
    expect(hasOrderProblem({ ...row, daily: '5' })).toBe(true);
  });

  it('reads the daemon report: usage, hidden caps, and deny-by-default for missing rows', () => {
    const report = fixtureData<SpendingLimitsReport>('rpc/ListSpendingLimits.response.json');
    const rows = rowsFromConfig(DEFAULT_PAYMENTS_CONFIG, report.limits);
    expect(byId(rows, 'usd1@bsc')).toMatchObject({
      perTx: '100',
      daily: '500',
      weekly: '1000',
      usage: { dailyUsed: '1', weeklyUsed: '41' },
      extras: {
        max_gas_per_tx_wei: '2000000000000000',
      },
    });
    expect(byId(rows, 'usd1@eth').status).toBe('excluded');
    expect(toSpendingLimits(rows)).toHaveLength(2);
  });

  it('reads an unlimited window (the u128 maximum) as no limit, and saves it back unchanged', () => {
    const MAX = (2n ** 128n - 1n).toString();
    const report = fixtureData<SpendingLimitsReport>('rpc/ListSpendingLimits.response.json');
    const limits = report.limits.map((entry, index) =>
      index === 0
        ? {
            ...entry,
            limit: { ...entry.limit, per_tx_max_wei: MAX, daily_max_wei: MAX, weekly_max_wei: MAX },
          }
        : entry,
    );
    const rows = rowsFromConfig(DEFAULT_PAYMENTS_CONFIG, limits);
    const bnb = byId(rows, 'bnb@bsc');
    expect(isNoLimit(bnb.perTx, bnb.decimals)).toBe(true);
    expect(isNoLimit(byId(rows, 'usd1@bsc').perTx, 18)).toBe(false);
    expect(isNoLimit('1000000000000', 6)).toBe(false);
    expect(toSpendingLimits(rows)[0]).toMatchObject({ per_tx_max_wei: MAX, daily_max_wei: MAX });
  });
});

describe('DEFAULT_PAYMENTS_CONFIG', () => {
  it("is the daemon's built-in default, token addresses included", () => {
    expect(DEFAULT_PAYMENTS_CONFIG).toEqual(
      fixtureData<PaymentsConfig>('payments/GetConfig.response.json'),
    );
  });
});
