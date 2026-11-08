/**
 * What the screens need from the outside world. Screens depend only on these interfaces, so
 * tests drive them with fakes and `src/app/services.ts` wires them to the daemons.
 */
import type { AdminMethod } from '../auth/admin-auth.js';
import type { ApprovalSummary } from '../format/approval.js';
import type { ReceiveOption } from '../format/receive.js';
import type { SendOption, SendOutcome } from '../format/send.js';
import type {
  ActivityResult,
  FundingRequestResult,
  ManualApprovalRequest,
  PaymentsConfig,
  WalletBalanceEntry,
  WalletInfo,
  WalletSummaryResult,
} from '../generated/index.js';
import type { LimitRow } from '../limits/model.js';

export interface HomeData {
  wallet: WalletSummaryResult;
  /** `null` when the pending count is unavailable (no admin access without a prompt). */
  pendingApprovals: number | null;
  /** The one-line security summary; absent when it could not be read. */
  security?: SecuritySummary;
}

export interface SecuritySummary {
  touchId: TouchIdState;
  /** ISO time of this wallet's last backup written by this client, or `null`. */
  backedUpAt: string | null;
  /** Whether approval notifications run for this user; `null` when not supported here. */
  notifications: boolean | null;
}

export interface ApprovalItem {
  request: ManualApprovalRequest;
  summary: ApprovalSummary;
}

export type TouchIdState = 'on' | 'off' | 'unavailable';

export interface BackupServices {
  defaultBackupPath(): string;
  /** Exports an encrypted backup to a new 0600 file at `path`. */
  exportBackup(path: string, passphrase: string): Promise<void>;
}

/** Sending from the TUI (through the agent key, so the usual limits apply). */
export interface SendServices {
  /** What can be sent, with balances, and this wallet's own addresses. */
  loadSend(): Promise<{ options: SendOption[]; ownAddresses: (string | null)[] }>;
  /** Broadcasts without waiting for an approval: a payment above the limits comes back pending. */
  send(option: SendOption, to: string, amount: string): Promise<SendOutcome>;
  /** Approves a pending payment (Touch ID or sudo), then sends it. */
  approveAndSend(approvalRequestId: string): Promise<SendOutcome>;
}

/** The wallets on this machine, and which one the agents use. */
export interface WalletServices {
  /** Every wallet (an admin call: Touch ID or sudo). */
  listWallets(): Promise<WalletInfo[]>;
  /** The agent key this user set up last, if any (no daemon call). */
  currentAgentKeyId(): string | null;
  /**
   * Points the agents at `wallet`: through a key of it whose token this user has, else a new
   * agent key with the current limits.
   */
  switchWallet(wallet: WalletInfo): Promise<void>;
  /** Names a wallet, or clears its name with `null`. */
  renameWallet(wallet: WalletInfo, name: string | null): Promise<WalletInfo>;
}

/** Desktop alerts for approval requests (a per-user background service). */
export interface AlertServices {
  /** `null` where alerts are not available (no installed launcher, unsupported platform). */
  alertsState(): Promise<boolean | null>;
  enableAlerts(): Promise<void>;
  disableAlerts(): Promise<void>;
}

export interface ActivityData {
  result: ActivityResult;
  config: PaymentsConfig | null;
}

export interface AppServices
  extends BackupServices,
    TokenServices,
    WalletServices,
    AlertServices,
    SendServices {
  /** This agent's waiting approvals and recent payments. */
  loadActivity(): Promise<ActivityData>;
  loadHome(): Promise<HomeData>;
  funding(network?: string, asset?: string): Promise<FundingRequestResult>;
  /** One balance, read fresh (the Receive screen watches it). */
  balance(network?: string, asset?: string): Promise<WalletBalanceEntry>;
  /** Every configured token and network, test networks included. */
  receiveOptions(): Promise<ReceiveOption[]>;
  /** How an admin decision is confirmed right now. */
  adminMethod(): AdminMethod;
  listApprovals(): Promise<ApprovalItem[]>;
  decideApproval(
    item: ApprovalItem,
    decision: 'approve' | 'reject',
    reason: string | null,
  ): Promise<void>;
  loadLimits(): Promise<LimitRow[]>;
  saveLimits(rows: readonly LimitRow[]): Promise<void>;
  touchIdState(): Promise<TouchIdState>;
  enableTouchId(): Promise<void>;
  disableTouchId(): Promise<void>;
}

export type CreateTask = 'keys' | 'agent' | 'store' | 'tokens';

/** A main network a token can be added on. */
export interface TokenNetwork {
  network: string;
  name: string;
  family: 'evm' | 'solana';
}

/** What the user typed for a new token; `symbol` and `decimals` only when needed. */
export interface NewToken {
  network: string;
  address: string;
  symbol?: string;
  decimals?: number;
}

export interface TokenAdded {
  /** The token's limit row (unset unless it already had a limit). */
  row: LimitRow;
  /** Whether the decimals were read from the network rather than typed in. */
  verified: boolean;
}

/** Adding tokens from the spending limits table. */
export interface TokenServices {
  /** The main networks a token can be added on. */
  tokenNetworks(): Promise<TokenNetwork[]>;
  /**
   * Reads the token from its network and returns its limit row. In setup the token is saved
   * to the configuration after the wallet is created; afterwards it is saved right away.
   */
  lookupToken(token: NewToken): Promise<TokenAdded>;
}

export interface WalletCreated {
  evmAddress: string | null;
  solanaAddress: string | null;
  /** Tokens added in setup that could not be saved to the configuration (their limits are). */
  unsavedTokens?: string[];
}

/**
 * What the welcome step chose: a new wallet, a restore from backup, or the existing wallet.
 * `replaceExisting` deletes the wallets already on this machine; it starts `false` and becomes
 * `true` only after the user typed the confirmation on the overwrite warning. `vaultKeyId` names
 * the wallet to keep; it is absent only when the welcome step chose to keep the only wallet.
 */
export type WalletChoice =
  | { kind: 'create'; replaceExisting: boolean; name?: string }
  | { kind: 'restore'; path: string; passphrase: string; replaceExisting: boolean; name?: string }
  | { kind: 'reuse'; vaultKeyId?: string };

/**
 * A wallet already on this machine: its vault key id and what `ListWallets` reported for it
 * (`null` when the list could not be read; only the id is known then).
 */
export interface ExistingWallet {
  vaultKeyId: string;
  info: WalletInfo | null;
}

export interface OnboardingServices extends BackupServices, TokenServices {
  /** The wallets on this machine, oldest first (an admin call: Touch ID or sudo). */
  listWallets(): Promise<WalletInfo[]>;
  /** The agent key this user set up last, if any (no daemon call). */
  currentAgentKeyId(): string | null;
  touchIdState(): Promise<TouchIdState>;
  enableTouchId(): Promise<void>;
  /** Rows seeded with the recommended limits. */
  loadLimits(): Promise<LimitRow[]>;
  /** Creates (or restores, or keeps) the wallet with these limits, in one daemon call. */
  createWallet(
    choice: WalletChoice,
    rows: readonly LimitRow[],
    onProgress: (task: CreateTask) => void,
  ): Promise<WalletCreated>;
  funding(network?: string, asset?: string): Promise<FundingRequestResult>;
  balance(network?: string, asset?: string): Promise<WalletBalanceEntry>;
  /** The configured tokens on main networks (setup leaves test networks out). */
  receiveOptions(): Promise<ReceiveOption[]>;
}
