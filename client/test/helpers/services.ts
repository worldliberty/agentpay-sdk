/** Fake screen services built from the API fixtures, recording every call. */
import { vi } from 'vitest';
import { summarizeApproval } from '../../src/format/approval.js';
import { type SendOutcome, sendOptions } from '../../src/format/send.js';
import type {
  ActivityResult,
  FundingRequestResult,
  ManualApprovalRequest,
  PaymentsConfig,
  SpendingLimitsReport,
  WalletBalanceEntry,
  WalletInfo,
  WalletSummaryResult,
} from '../../src/generated/index.js';
import { DEFAULT_PAYMENTS_CONFIG } from '../../src/limits/default-config.js';
import { type LimitRow, newTokenRow, rowsFromConfig } from '../../src/limits/model.js';
import type {
  AppServices,
  NewToken,
  OnboardingServices,
  TokenAdded,
} from '../../src/screens/types.js';
import { fixtureData } from './fixtures.js';

export const config = fixtureData<PaymentsConfig>('payments/GetConfig.response.json');
export const wallet = fixtureData<WalletSummaryResult>(
  'payments/wallet/WalletSummary.response.json',
);
export const approvals = fixtureData<ManualApprovalRequest[]>(
  'rpc/ListManualApprovalRequests.response.json',
);
export const funding: FundingRequestResult = {
  ...fixtureData<FundingRequestResult>('payments/wallet/FundingRequest.response.json'),
  qr: { modules: 21, svg: '<svg/>', terminal: '█▀▀▀▀▀█ ▄ █▀▀▀▀▀█\n█ ███ █ ▀ █ ███ █' },
};
export const activity = fixtureData<ActivityResult>('payments/wallet/Activity.response.json');
export const limitsReport = fixtureData<SpendingLimitsReport>(
  'rpc/ListSpendingLimits.response.json',
);

export function fakeAppServices(overrides: Partial<AppServices> = {}): AppServices {
  return {
    loadHome: vi.fn(async () => ({ wallet, pendingApprovals: 1 })),
    funding: vi.fn(async () => funding),
    balance: vi.fn(async () => wallet.balances[0] as WalletBalanceEntry),
    receiveOptions: vi.fn(async () => []),
    adminMethod: vi.fn(() => 'touch_id' as const),
    listApprovals: vi.fn(async () =>
      approvals.map((request) => ({ request, summary: summarizeApproval(request, config) })),
    ),
    decideApproval: vi.fn(async () => {}),
    loadLimits: vi.fn(async () => rowsFromConfig(config, limitsReport.limits)),
    saveLimits: vi.fn(async () => {}),
    touchIdState: vi.fn(async () => 'off' as const),
    enableTouchId: vi.fn(async () => {}),
    disableTouchId: vi.fn(async () => {}),
    listWallets: vi.fn(async () => []),
    currentAgentKeyId: vi.fn(() => null),
    switchWallet: vi.fn(async () => {}),
    loadActivity: vi.fn(async () => ({ result: activity, config })),
    loadSend: vi.fn(async () => ({
      options: sendOptions(config, wallet, { includeTestnets: true }),
      ownAddresses: [wallet.evm_address, wallet.solana_address],
    })),
    send: vi.fn(
      async (): Promise<SendOutcome> => ({
        kind: 'sent',
        hash: '0xabc',
        confirmed: true,
        failed: false,
      }),
    ),
    approveAndSend: vi.fn(
      async (): Promise<SendOutcome> => ({
        kind: 'sent',
        hash: '0xdef',
        confirmed: true,
        failed: false,
      }),
    ),
    alertsState: vi.fn(async () => false),
    enableAlerts: vi.fn(async () => {}),
    disableAlerts: vi.fn(async () => {}),
    renameWallet: vi.fn(async (wallet: WalletInfo, name: string | null) => ({ ...wallet, name })),
    ...tokenServices(),
    defaultBackupPath: vi.fn(() => '/home/me/agentpay-wallet-backup.json'),
    exportBackup: vi.fn(async () => {}),
    ...overrides,
  };
}

/** A new token's row, as the limits table gets it back from a lookup. */
export function newTokenRowFor(token: NewToken, symbol = token.symbol ?? 'USDT'): LimitRow {
  const row = newTokenRow(DEFAULT_PAYMENTS_CONFIG, {
    network: token.network,
    address: token.address,
    symbol,
    decimals: token.decimals ?? 18,
  });
  if (!row) {
    throw new Error(`no row for ${token.network}`);
  }
  return row;
}

const tokenServices = () => ({
  tokenNetworks: vi.fn(async () => [
    { network: 'bsc', name: 'BSC', family: 'evm' as const },
    { network: 'eth', name: 'ETH', family: 'evm' as const },
    { network: 'solana-mainnet', name: 'Solana', family: 'solana' as const },
  ]),
  lookupToken: vi.fn(
    async (token: NewToken): Promise<TokenAdded> => ({
      row: newTokenRowFor(token),
      verified: token.decimals === undefined,
    }),
  ),
});

export function fakeOnboardingServices(
  overrides: Partial<OnboardingServices> = {},
): OnboardingServices {
  return {
    listWallets: vi.fn(async () => []),
    currentAgentKeyId: vi.fn(() => null),
    touchIdState: vi.fn(async () => 'off' as const),
    enableTouchId: vi.fn(async () => {}),
    loadLimits: vi.fn(async () => rowsFromConfig(DEFAULT_PAYMENTS_CONFIG)),
    createWallet: vi.fn(async (_choice, _rows, onProgress) => {
      onProgress('keys');
      onProgress('agent');
      onProgress('store');
      return { evmAddress: wallet.evm_address, solanaAddress: wallet.solana_address };
    }),
    funding: vi.fn(async () => funding),
    balance: vi.fn(async () => wallet.balances[0] as WalletBalanceEntry),
    receiveOptions: vi.fn(async () => []),
    ...tokenServices(),
    defaultBackupPath: vi.fn(() => '/home/me/agentpay-wallet-backup.json'),
    exportBackup: vi.fn(async () => {}),
    ...overrides,
  };
}
