/** Real implementations of the screen service interfaces, backed by the daemons. */
import { chownSync, existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import type { ClientStateStore } from '../auth/client-state.js';
import { writeNewFile } from '../auth/files.js';
import { copy } from '../copy/index.js';
import type { PaymentsClient } from '../daemon/payments.js';
import { AgentPayError, EXIT, SignerCallError, staleAgentCredentials } from '../errors.js';
import { waitingApprovals } from '../format/activity.js';
import { approvalReasons, summarizeApproval } from '../format/approval.js';
import { receiveOptions } from '../format/receive.js';
import { type SendOutcome, sendOptions, sendOutcome } from '../format/send.js';
import type { PaymentsConfig, WalletBootstrapMode } from '../generated/index.js';
import { DEFAULT_PAYMENTS_CONFIG } from '../limits/default-config.js';
import { isTestnetChain, newTokenRow, rowsFromConfig, toSpendingLimits } from '../limits/model.js';
import type { AppServices, OnboardingServices, WalletChoice } from '../screens/types.js';
import type { AdminActions } from './admin-actions.js';
import { alertsFor } from './alerts.js';
import type { Context } from './context.js';
import { sendPayment } from './send.js';
import { disableTouchId, enableTouchId, touchIdStatus } from './touch-id-setup.js';

/** Expands a leading `~/` and resolves the path. */
export function expandPath(path: string): string {
  return resolve(
    path === '~' ? homedir() : path.startsWith('~/') ? join(homedir(), path.slice(2)) : path,
  );
}

/** `~/agentpay-wallet-backup.json`, or a dated name when that file already exists. */
export function defaultBackupPath(now: Date = new Date()): string {
  const plain = join(homedir(), 'agentpay-wallet-backup.json');
  if (!existsSync(plain)) {
    return plain;
  }
  return join(homedir(), `agentpay-wallet-backup-${now.toISOString().slice(0, 10)}.json`);
}

/**
 * Exports a backup into a new 0600 file (never overwrites). `vaultKeyId` is needed only when the
 * daemon holds several wallets.
 */
export async function writeBackup(
  admin: AdminActions,
  path: string,
  passphrase: string,
  command: string,
  vaultKeyId?: string,
  state?: ClientStateStore,
) {
  const target = expandPath(path);
  if (existsSync(target)) {
    throw new AgentPayError('file_exists', copy.errors.fileExists(target));
  }
  const { backup_json: backup, summary } = await admin.exportBackup(
    passphrase,
    command,
    vaultKeyId,
  );
  const contents = backup.endsWith('\n') ? backup : `${backup}\n`;
  writeNewFile(target, contents);
  // Remember the backup only once it reads back intact (the reminder on Home goes away).
  if (state && readFileSync(target, 'utf8') === contents) {
    const backups = {
      ...state.read().backups,
      [summary.address.toLowerCase()]: new Date().toISOString(),
    };
    state.update({ backups });
  }
  // Under sudo, hand the file to the user who ran sudo.
  const sudoUid = Number(process.env.SUDO_UID);
  const sudoGid = Number(process.env.SUDO_GID);
  if (process.geteuid?.() === 0 && Number.isInteger(sudoUid) && Number.isInteger(sudoGid)) {
    chownSync(target, sudoUid, sudoGid);
  }
}

const COMMANDS = {
  approvals: 'agentpay admin approvals',
  limits: 'agentpay admin limits',
  security: 'agentpay admin touch-id enable',
  backup: 'agentpay admin wallet-backup export',
  wallets: 'agentpay admin wallets',
  setup: 'agentpay setup',
};

export function createAppServices(
  context: Context,
  initialPayments: PaymentsClient,
  admin: AdminActions,
): AppServices {
  // Re-created when the user switches wallets: it carries the agent's credentials.
  let payments = initialPayments;
  let config: Promise<PaymentsConfig | null> | null = null;
  const loadConfig = () => {
    config ??= payments.getConfig().catch(() => null);
    return config;
  };
  const touchId = context.touchId(admin);
  const alerts = alertsFor(context);
  /** A pending outcome carries why it waits (this agent's own requests, from `Activity`). */
  const withReasons = async (outcome: SendOutcome): Promise<SendOutcome> => {
    if (outcome.kind !== 'pending') {
      return outcome;
    }
    const [activity, cfg] = await Promise.all([
      payments.activity({ limit: 50 }).catch(() => null),
      loadConfig(),
    ]);
    const request = activity?.approvals.find((a) => a.id === outcome.approvalRequestId);
    return { ...outcome, reasons: request ? approvalReasons(request, cfg).reasons : [] };
  };
  return {
    async loadHome() {
      const wallet = await payments.walletSummary();
      // This agent's own approval requests need no admin authority (`Activity`).
      const pendingApprovals = await payments
        .activity({ limit: 50 })
        .then((activity) => waitingApprovals(activity).length)
        .catch(() => null);
      const address = wallet.evm_address?.toLowerCase();
      const security = {
        touchId: await touchIdStatus(touchId).catch(() => 'unavailable' as const),
        backedUpAt: (address && context.state.read().backups[address]) || null,
        notifications: alerts ? alerts.installed() : null,
      };
      return { wallet, pendingApprovals, security };
    },
    funding: (network, asset) =>
      payments.fundingRequest({
        qr: true,
        ...(network ? { network } : {}),
        ...(asset ? { asset } : {}),
      }),
    balance: (network, asset) =>
      payments.walletBalance({
        ...(network ? { network } : {}),
        ...(asset ? { asset } : {}),
      }),
    async receiveOptions() {
      // Without the configuration, the screen shows the default network and asset.
      const cfg = await loadConfig();
      return cfg ? receiveOptions(cfg, { includeTestnets: true }) : [];
    },
    adminMethod: () => admin.method(),
    async listApprovals() {
      const [requests, cfg] = await Promise.all([
        admin.listApprovals(COMMANDS.approvals),
        loadConfig(),
      ]);
      return requests
        .filter((request) => request.status === 'pending')
        .map((request) => ({ request, summary: summarizeApproval(request, cfg) }));
    },
    async decideApproval(item, decision, reason) {
      const description = `${item.summary.action.toLowerCase()} ${item.summary.amount} to ${item.summary.to}`;
      await admin.decideApproval(item.request, decision, reason, description, COMMANDS.approvals);
    },
    async loadLimits() {
      const [cfg, report] = await Promise.all([
        payments.getConfig(),
        admin.listLimits(payments.agentKeyId, COMMANDS.limits),
      ]);
      return rowsFromConfig(cfg, report.limits);
    },
    async saveLimits(rows) {
      await admin.setLimits(payments.agentKeyId, toSpendingLimits(rows), COMMANDS.limits);
    },
    async tokenNetworks() {
      return tokenNetworks((await loadConfig()) ?? (await payments.getConfig()));
    },
    async lookupToken(token) {
      // With agent credentials the token is saved to the configuration right away; its limit
      // is saved with the others.
      const result = await payments.addToken({
        network: token.network,
        address: token.address,
        ...(token.symbol ? { symbol: token.symbol } : {}),
        ...(token.decimals !== undefined ? { decimals: token.decimals } : {}),
      });
      config = Promise.resolve(result.config);
      const row = rowsFromConfig(result.config).find(
        (candidate) => candidate.tokenKey === result.key && candidate.network === result.network,
      );
      if (!row) {
        throw new Error(`token ${result.key} on ${result.network} has no limit row`);
      }
      return { row, verified: result.verified_on_chain };
    },
    async loadSend() {
      const [wallet, cfg] = await Promise.all([payments.walletSummary(), payments.getConfig()]);
      return {
        options: sendOptions(cfg, wallet, { includeTestnets: true }),
        ownAddresses: [wallet.evm_address, wallet.solana_address],
      };
    },
    async send(option, to, amount) {
      const outcome = sendOutcome(await sendPayment(payments, option, to.trim(), amount.trim()));
      return withReasons(outcome);
    },
    async approveAndSend(approvalRequestId) {
      const request = (await admin.listApprovals(COMMANDS.approvals)).find(
        (candidate) => candidate.id === approvalRequestId,
      );
      if (!request) {
        throw new AgentPayError('approval_gone', copy.errors.approvalGone);
      }
      if (request.status === 'pending') {
        const cfg = await loadConfig();
        const summary = summarizeApproval(request, cfg);
        const description = `${summary.action.toLowerCase()} ${summary.amount} to ${summary.to}`;
        await admin.decideApproval(request, 'approve', null, description, COMMANDS.approvals);
      }
      return withReasons(
        sendOutcome(await payments.resumeApproved({ approval_request_id: approvalRequestId })),
      );
    },
    async loadActivity() {
      const [result, cfg] = await Promise.all([payments.activity({ limit: 50 }), loadConfig()]);
      return { result, config: cfg };
    },
    alertsState: async () => (alerts ? alerts.installed() : null),
    async enableAlerts() {
      await alerts?.install();
    },
    async disableAlerts() {
      await alerts?.uninstall();
    },
    listWallets: () => admin.listWallets(COMMANDS.wallets),
    currentAgentKeyId: () => context.state.read().agentKeyId ?? null,
    renameWallet: (wallet, name) => admin.renameWallet(wallet.vault_key_id, name, COMMANDS.wallets),
    async switchWallet(wallet) {
      // A key of that wallet whose token this user still has: just point the client at it.
      for (const agentKeyId of wallet.agent_key_ids) {
        if ((await context.secrets.read(agentKeyId).catch(() => null)) !== null) {
          context.state.update({ agentKeyId });
          payments = await context.payments({});
          config = null;
          return;
        }
      }
      // Otherwise give that wallet a new agent key with the same limits as the current one.
      const current = await admin.listLimits(payments.agentKeyId, COMMANDS.wallets);
      const created = await admin.bootstrapWallet(
        { kind: 'reuse', vault_key_id: wallet.vault_key_id },
        current.limits.map((status) => status.limit),
        COMMANDS.wallets,
      );
      const { agent_key, auth_token } = created.agent_credentials;
      await context.secrets.write(agent_key.id, auth_token);
      context.state.update({ agentKeyId: agent_key.id });
      payments = await context.payments({});
      config = null;
    },
    touchIdState: () => touchIdStatus(touchId),
    async enableTouchId() {
      await enableTouchId(touchId, COMMANDS.security);
    },
    disableTouchId: () => disableTouchId(touchId, COMMANDS.security),
    defaultBackupPath: () => defaultBackupPath(),
    exportBackup: (path, passphrase) =>
      writeBackup(admin, path, passphrase, COMMANDS.backup, undefined, context.state),
  };
}

/**
 * Whether a `reuse` naming both the wallet and the agent key failed only because that agent key
 * (the one this user set up last) belongs to another wallet or is gone.
 */
function foreignAgentKey(error: unknown): boolean {
  return (
    error instanceof SignerCallError &&
    (error.wire.kind === 'InvalidWalletRequest' || error.wire.kind === 'UnknownAgentKey')
  );
}

/** The main networks of `config` a token can be added on, the default first. */
function tokenNetworks(config: PaymentsConfig) {
  return Object.entries(config.chains)
    .filter(([, chain]) => !isTestnetChain(chain.chain_id))
    .map(([network, chain]) => ({ network, name: chain.name, family: chain.family }))
    .sort(
      (a, b) =>
        Number(b.network === config.default_network) -
          Number(a.network === config.default_network) || a.name.localeCompare(b.name),
    );
}

/** The daemon's bootstrap mode for a welcome-step choice. */
export function bootstrapMode(
  choice: WalletChoice,
  agentKeyId: string | null,
): WalletBootstrapMode {
  switch (choice.kind) {
    case 'create':
      return {
        kind: 'create',
        replace_existing: choice.replaceExisting,
        ...(choice.name ? { name: choice.name } : {}),
      };
    case 'reuse':
      return {
        kind: 'reuse',
        ...(choice.vaultKeyId ? { vault_key_id: choice.vaultKeyId } : {}),
        ...(agentKeyId ? { agent_key_id: agentKeyId } : {}),
      };
    case 'restore':
      return {
        kind: 'restore_from_backup',
        backup_json: readFileSync(expandPath(choice.path), 'utf8'),
        passphrase: choice.passphrase,
        replace_existing: choice.replaceExisting,
        ...(choice.name ? { name: choice.name } : {}),
      };
  }
}

export function createOnboardingServices(
  context: Context,
  admin: AdminActions,
): OnboardingServices {
  const touchId = context.touchId(admin);
  /** The wallet set up by `createWallet`, so the backup step exports that one. */
  let vaultKeyId: string | undefined;
  let limitsConfig: PaymentsConfig = DEFAULT_PAYMENTS_CONFIG;
  let payments: Promise<PaymentsClient> | null = null;
  const client = () => {
    payments ??= context.payments({});
    return payments;
  };
  return {
    listWallets: () => admin.listWallets(COMMANDS.setup),
    currentAgentKeyId: () => context.state.read().agentKeyId ?? null,
    touchIdState: () => touchIdStatus(touchId),
    async enableTouchId() {
      await enableTouchId(touchId, COMMANDS.setup);
    },
    async loadLimits() {
      // Before the first bootstrap there are no agent credentials, and the service still
      // serves its built-in default configuration. Credentials the daemons reject (left over
      // from an install whose state was removed) are replaced by this setup, so they count as
      // none.
      let config = DEFAULT_PAYMENTS_CONFIG;
      try {
        config = await (await client()).getConfig();
      } catch (error) {
        payments = null;
        const noCredentials =
          (error instanceof AgentPayError && error.exitCode === EXIT.notSetUp) ||
          staleAgentCredentials(error);
        if (!noCredentials) {
          throw error;
        }
      }
      limitsConfig = config;
      return rowsFromConfig(config, null);
    },
    async createWallet(choice, rows, onProgress) {
      onProgress('keys');
      const mode = bootstrapMode(choice, context.state.read().agentKeyId);
      const limits = toSpendingLimits(rows);
      const created = await admin
        .bootstrapWallet(mode, limits, COMMANDS.setup)
        .catch((error: unknown) => {
          if (
            mode.kind === 'reuse' &&
            mode.vault_key_id &&
            mode.agent_key_id &&
            foreignAgentKey(error)
          ) {
            // Keep the chosen wallet with its own agent key instead.
            const own: WalletBootstrapMode = { kind: 'reuse', vault_key_id: mode.vault_key_id };
            return admin.bootstrapWallet(own, limits, COMMANDS.setup);
          }
          throw error;
        });
      vaultKeyId = created.vault_key.id;
      onProgress('agent');
      const { agent_key, auth_token } = created.agent_credentials;
      onProgress('store');
      await context.secrets.write(agent_key.id, auth_token);
      context.state.update({ agentKeyId: agent_key.id });
      payments = null;
      // Tokens added in the limits step: their limits are in place; now that the agent has
      // credentials, save them to the payments configuration.
      const unsavedTokens: string[] = [];
      const added = rows.filter((row) => row.newToken && row.status !== 'excluded');
      if (added.length > 0) {
        onProgress('tokens');
        const payments = await client();
        for (const { newToken, symbol, networkName } of added) {
          if (newToken) {
            await payments.addToken(newToken).catch(() => {
              unsavedTokens.push(`${symbol} on ${networkName}`);
            });
          }
        }
      }
      return {
        evmAddress: created.evm_address,
        solanaAddress: created.solana_address,
        ...(unsavedTokens.length > 0 ? { unsavedTokens } : {}),
      };
    },
    async funding(network, asset) {
      return (await client()).fundingRequest({
        qr: true,
        ...(network ? { network } : {}),
        ...(asset ? { asset } : {}),
      });
    },
    async balance(network, asset) {
      return (await client()).walletBalance({
        ...(network ? { network } : {}),
        ...(asset ? { asset } : {}),
      });
    },
    async receiveOptions() {
      return receiveOptions(await (await client()).getConfig(), { includeTestnets: false });
    },
    // The configuration the limit rows were built from (the default one before setup).
    tokenNetworks: async () => tokenNetworks(limitsConfig),
    async lookupToken(token) {
      const info = await context.publicPayments().lookupToken({
        network: token.network,
        address: token.address,
        ...(token.symbol ? { symbol: token.symbol } : {}),
        ...(token.decimals !== undefined ? { decimals: token.decimals } : {}),
      });
      const row = newTokenRow(limitsConfig, {
        network: info.network,
        address: info.address,
        symbol: info.symbol,
        decimals: info.decimals,
      });
      if (!row) {
        throw new Error(`network ${info.network} is not configured`);
      }
      return { row, verified: info.verified_on_chain };
    },
    defaultBackupPath: () => defaultBackupPath(),
    exportBackup: (path, passphrase) =>
      writeBackup(admin, path, passphrase, COMMANDS.backup, vaultKeyId, context.state),
  };
}
