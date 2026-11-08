/** Typed helpers for the signer daemon's admin methods the client uses. */
import type {
  AdminAuth,
  AdminChallenge,
  AdminCredential,
  AdminLease,
  DaemonRpcRequest,
  DaemonRpcResponse,
  ManualApprovalDecision,
  ManualApprovalRequest,
  SpendingLimit,
  SpendingLimitsReport,
  SpendingPolicy,
  WalletBackupExport,
  WalletBackupSummary,
  WalletBootstrap,
  WalletBootstrapMode,
  WalletInfo,
} from '../generated/index.js';
import { RpcClient, type RpcClientOptions } from './rpc.js';

export type SignerRpc = RpcClient<DaemonRpcRequest, DaemonRpcResponse>;

/** Backup key derivation (scrypt, about a second each) can queue behind another one. */
const WALLET_CALL_TIMEOUT_MS = 120_000;

export class SignerClient {
  readonly rpc: SignerRpc;

  constructor(options: RpcClientOptions | SignerRpc) {
    this.rpc = options instanceof RpcClient ? options : new RpcClient(options);
  }

  hello() {
    return this.rpc.hello();
  }

  async listApprovals(auth: AdminAuth): Promise<ManualApprovalRequest[]> {
    const response = await this.rpc.call(
      { method: 'ListManualApprovalRequests', params: { auth } },
      ['ManualApprovalRequests'],
    );
    return response.data;
  }

  async decideApproval(
    auth: AdminAuth,
    approvalRequestId: string,
    decision: ManualApprovalDecision,
    rejectionReason: string | null,
  ): Promise<ManualApprovalRequest> {
    const response = await this.rpc.call(
      {
        method: 'DecideManualApprovalRequest',
        params: {
          auth,
          approval_request_id: approvalRequestId,
          decision,
          rejection_reason: decision === 'reject' ? rejectionReason : null,
        },
      },
      ['ManualApprovalRequest'],
    );
    return response.data;
  }

  async beginChallenge(credentialId: string, purpose: string): Promise<AdminChallenge> {
    const response = await this.rpc.call(
      { method: 'BeginAdminChallenge', params: { credential_id: credentialId, purpose } },
      ['AdminChallenge'],
    );
    return response.data;
  }

  async completeChallenge(challengeId: string, signatureDerHex: string): Promise<AdminLease> {
    const response = await this.rpc.call(
      {
        method: 'CompleteAdminChallenge',
        params: { challenge_id: challengeId, signature_der_hex: signatureDerHex },
      },
      ['AdminLease'],
    );
    return response.data;
  }

  async revokeLease(auth: AdminAuth, leaseId: string): Promise<void> {
    await this.rpc.call({ method: 'RevokeAdminLease', params: { auth, lease_id: leaseId } }, [
      'Unit',
    ]);
  }

  /** Root peers only. */
  async enrollCredential(publicKeySec1Hex: string, label: string): Promise<AdminCredential> {
    const response = await this.rpc.call(
      {
        method: 'EnrollAdminCredential',
        params: { public_key_sec1_hex: publicKeySec1Hex, label },
      },
      ['AdminCredential'],
    );
    return response.data;
  }

  async revokeCredential(auth: AdminAuth, id: string): Promise<void> {
    await this.rpc.call({ method: 'RevokeAdminCredential', params: { auth, id } }, ['Unit']);
  }

  async listPolicies(auth: AdminAuth): Promise<SpendingPolicy[]> {
    const response = await this.rpc.call({ method: 'ListPolicies', params: { auth } }, [
      'Policies',
    ]);
    return response.data;
  }

  /** Creates, reuses, or restores the wallet, its agent key, and its limits in one step. */
  async bootstrapWallet(
    auth: AdminAuth,
    mode: WalletBootstrapMode,
    limits: SpendingLimit[],
  ): Promise<WalletBootstrap> {
    const response = await this.rpc.call(
      { method: 'BootstrapWallet', params: { auth, mode, limits } },
      ['WalletBootstrap'],
      WALLET_CALL_TIMEOUT_MS,
    );
    return response.data;
  }

  /** Every wallet on the machine with its addresses and agent keys, oldest first. */
  async listWallets(auth: AdminAuth): Promise<WalletInfo[]> {
    const response = await this.rpc.call({ method: 'ListWallets', params: { auth } }, ['Wallets']);
    return response.data;
  }

  /** Names a wallet (1–32 characters), or clears its name with `null`. */
  async renameWallet(
    auth: AdminAuth,
    vaultKeyId: string,
    name: string | null,
  ): Promise<WalletInfo> {
    const response = await this.rpc.call(
      { method: 'RenameWallet', params: { auth, vault_key_id: vaultKeyId, name } },
      ['Wallet'],
    );
    return response.data;
  }

  /** `vaultKeyId` is needed only when the daemon holds several wallets. */
  async exportWalletBackup(
    auth: AdminAuth,
    passphrase: string,
    vaultKeyId?: string,
  ): Promise<WalletBackupExport> {
    const response = await this.rpc.call(
      {
        method: 'ExportWalletBackup',
        params: vaultKeyId ? { auth, vault_key_id: vaultKeyId, passphrase } : { auth, passphrase },
      },
      ['WalletBackup'],
      WALLET_CALL_TIMEOUT_MS,
    );
    return response.data;
  }

  async verifyWalletBackup(
    auth: AdminAuth,
    backupJson: string,
    passphrase: string,
  ): Promise<WalletBackupSummary> {
    const response = await this.rpc.call(
      { method: 'VerifyWalletBackup', params: { auth, backup_json: backupJson, passphrase } },
      ['WalletBackupSummary'],
      WALLET_CALL_TIMEOUT_MS,
    );
    return response.data;
  }

  async listSpendingLimits(auth: AdminAuth, agentKeyId: string): Promise<SpendingLimitsReport> {
    const response = await this.rpc.call(
      { method: 'ListSpendingLimits', params: { auth, agent_key_id: agentKeyId } },
      ['SpendingLimits'],
    );
    return response.data;
  }

  /** Replaces the agent's whole limit set (assets without a row are blocked). */
  async setSpendingLimits(
    auth: AdminAuth,
    agentKeyId: string,
    limits: SpendingLimit[],
  ): Promise<SpendingLimitsReport> {
    const response = await this.rpc.call(
      { method: 'SetSpendingLimits', params: { auth, agent_key_id: agentKeyId, limits } },
      ['SpendingLimits'],
    );
    return response.data;
  }
}
