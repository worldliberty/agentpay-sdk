/**
 * Admin operations with the right authority: a root peer or a Touch ID lease directly, or, for
 * the interactive screens when Touch ID is off, the sudo relay. Without either, the authorizer
 * throws an `AuthError` telling the user to re-run the command with sudo.
 */
import type { AdminAuthorizer, AdminMethod, AdminOperation } from '../auth/admin-auth.js';
import type { PrivilegedRunner, RelayRequest } from '../auth/privileged.js';
import { copy } from '../copy/index.js';
import type { SignerClient } from '../daemon/signer.js';
import { AuthError, SignerCallError } from '../errors.js';
import type {
  AdminAuth,
  AdminCredential,
  ManualApprovalDecision,
  ManualApprovalRequest,
  SpendingLimit,
  SpendingLimitsReport,
  WalletBackupExport,
  WalletBackupSummary,
  WalletBootstrap,
  WalletBootstrapMode,
  WalletInfo,
} from '../generated/index.js';

export class AdminActions {
  private readonly signer: SignerClient;
  private readonly authorizer: AdminAuthorizer;
  private readonly relay: PrivilegedRunner | null;
  private readonly euid: number;

  constructor(options: {
    signer: SignerClient;
    authorizer: AdminAuthorizer;
    relay: PrivilegedRunner | null;
    euid: number;
  }) {
    this.signer = options.signer;
    this.authorizer = options.authorizer;
    this.relay = options.relay;
    this.euid = options.euid;
  }

  /** How the next admin operation will be confirmed. */
  method(): AdminMethod {
    return this.authorizer.method();
  }

  dispose(): Promise<void> {
    return this.authorizer.dispose();
  }

  private async perform<T>(
    operation: AdminOperation,
    relayRequest: RelayRequest,
    direct: (auth: AdminAuth) => Promise<T>,
  ): Promise<T> {
    if (this.authorizer.method() === 'sudo' && this.relay) {
      const response = await this.relay.run(relayRequest, operation.reason);
      return response.data as T;
    }
    const grant = await this.authorizer.authorize(operation);
    try {
      return await direct(grant.auth);
    } finally {
      await grant.release();
    }
  }

  listApprovals(command: string): Promise<ManualApprovalRequest[]> {
    return this.perform(
      { purpose: 'admin-session', reason: copy.common.reasons.session, command, reusable: true },
      { method: 'ListManualApprovalRequests', params: {} },
      (auth) => this.signer.listApprovals(auth),
    );
  }

  decideApproval(
    request: ManualApprovalRequest,
    decision: ManualApprovalDecision,
    reason: string | null,
    description: string,
    command: string,
  ): Promise<ManualApprovalRequest> {
    const r = copy.common.reasons;
    return this.perform(
      {
        purpose: `${decision}:${request.id}`,
        reason: decision === 'approve' ? r.approve(description) : r.reject(description),
        command,
      },
      {
        method: 'DecideManualApprovalRequest',
        params: {
          approval_request_id: request.id,
          decision,
          rejection_reason: decision === 'reject' ? reason : null,
        },
      },
      (auth) => this.signer.decideApproval(auth, request.id, decision, reason),
    );
  }

  /**
   * Finds a request and decides it with one authorization: the Touch ID prompt (purpose
   * `approve:<id>` / `reject:<id>`) or the root peer. `confirm` sees the request first and may
   * cancel (returns `null`).
   */
  async decideById(
    id: string,
    decision: ManualApprovalDecision,
    reason: string | null,
    command: string,
    confirm: (request: ManualApprovalRequest) => Promise<boolean>,
  ): Promise<ManualApprovalRequest | null> {
    const r = copy.common.reasons;
    const what = `AgentPay request ${id.slice(0, 8)}`;
    const grant = await this.authorizer.authorize({
      purpose: `${decision}:${id}`,
      reason: decision === 'approve' ? r.approve(what) : r.reject(what),
      command,
    });
    try {
      const request = (await this.signer.listApprovals(grant.auth)).find((item) => item.id === id);
      if (!request) {
        throw new SignerCallError({ kind: 'UnknownManualApprovalRequest', data: id });
      }
      if (request.status !== 'pending') {
        throw new SignerCallError({
          kind: 'ManualApprovalRequestNotPending',
          data: { approval_request_id: id, status: request.status },
        });
      }
      if (!(await confirm(request))) {
        return null;
      }
      return await this.signer.decideApproval(grant.auth, id, decision, reason);
    } finally {
      await grant.release();
    }
  }

  listLimits(agentKeyId: string, command: string): Promise<SpendingLimitsReport> {
    return this.perform(
      { purpose: 'admin-session', reason: copy.common.reasons.session, command, reusable: true },
      { method: 'ListSpendingLimits', params: { agent_key_id: agentKeyId } },
      (auth) => this.signer.listSpendingLimits(auth, agentKeyId),
    );
  }

  /** Replaces the agent's whole limit set (assets without a row are blocked). */
  setLimits(
    agentKeyId: string,
    limits: SpendingLimit[],
    command: string,
  ): Promise<SpendingLimitsReport> {
    return this.perform(
      { purpose: 'limits:set', reason: copy.common.reasons.limits, command, reusable: true },
      { method: 'SetSpendingLimits', params: { agent_key_id: agentKeyId, limits } },
      (auth) => this.signer.setSpendingLimits(auth, agentKeyId, limits),
    );
  }

  /** Creates, reuses, or restores the wallet, its agent key, and its limits in one step. */
  bootstrapWallet(
    mode: WalletBootstrapMode,
    limits: SpendingLimit[],
    command: string,
  ): Promise<WalletBootstrap> {
    return this.perform(
      {
        purpose: 'wallet:bootstrap',
        reason: copy.common.reasons.bootstrap,
        command,
        reusable: true,
      },
      { method: 'BootstrapWallet', params: { mode, limits } },
      (auth) => this.signer.bootstrapWallet(auth, mode, limits),
    );
  }

  /** Every wallet on the machine (public metadata only), oldest first. */
  listWallets(command: string): Promise<WalletInfo[]> {
    return this.perform(
      { purpose: 'admin-session', reason: copy.common.reasons.session, command, reusable: true },
      { method: 'ListWallets', params: {} },
      (auth) => this.signer.listWallets(auth),
    );
  }

  /** Names a wallet, or clears its name with `null`. */
  renameWallet(vaultKeyId: string, name: string | null, command: string): Promise<WalletInfo> {
    return this.perform(
      { purpose: 'admin-session', reason: copy.common.reasons.session, command, reusable: true },
      { method: 'RenameWallet', params: { vault_key_id: vaultKeyId, name } },
      (auth) => this.signer.renameWallet(auth, vaultKeyId, name),
    );
  }

  /** `vaultKeyId` is needed only when the daemon holds several wallets. */
  /** The encrypted backup and its summary (which wallet, its address). */
  async exportBackup(
    passphrase: string,
    command: string,
    vaultKeyId?: string,
  ): Promise<WalletBackupExport> {
    const backup = await this.perform(
      { purpose: 'backup:export', reason: copy.common.reasons.backup, command },
      {
        method: 'ExportWalletBackup',
        params: vaultKeyId ? { vault_key_id: vaultKeyId, passphrase } : { passphrase },
      },
      (auth) => this.signer.exportWalletBackup(auth, passphrase, vaultKeyId),
    );
    return backup;
  }

  verifyBackup(
    backupJson: string,
    passphrase: string,
    command: string,
  ): Promise<WalletBackupSummary> {
    return this.perform(
      { purpose: 'backup:verify', reason: copy.common.reasons.verifyBackup, command },
      { method: 'VerifyWalletBackup', params: { backup_json: backupJson, passphrase } },
      (auth) => this.signer.verifyWalletBackup(auth, backupJson, passphrase),
    );
  }

  /** Enrolling needs a root peer: direct under sudo, else through the sudo relay. */
  async enrollCredential(
    publicKeySec1Hex: string,
    label: string,
    command: string,
  ): Promise<AdminCredential> {
    if (this.euid === 0) {
      return this.signer.enrollCredential(publicKeySec1Hex, label);
    }
    if (!this.relay) {
      throw new AuthError('sudo_required', copy.errors.sudoRequired(command));
    }
    const response = await this.relay.run({
      method: 'EnrollAdminCredential',
      params: { public_key_sec1_hex: publicKeySec1Hex, label },
    });
    return response.data as AdminCredential;
  }

  revokeCredential(id: string, command: string): Promise<void> {
    return this.perform(
      { purpose: 'touch-id:revoke', reason: copy.common.reasons.revoke, command },
      { method: 'RevokeAdminCredential', params: { id } },
      (auth) => this.signer.revokeCredential(auth, id),
    );
  }
}
