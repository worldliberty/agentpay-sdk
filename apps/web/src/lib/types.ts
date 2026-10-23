export interface RelayDaemonRecord {
  daemonId: string;
  daemonPublicKey: string;
  vaultEthereumAddress: string;
  relayBaseUrl?: string | null;
  updatedAt: string;
}

export interface ApprovalRequestRecord {
  approvalId: string;
  daemonId: string;
  agentKeyId: string;
  status: 'pending' | 'approved' | 'rejected' | 'completed' | 'expired' | 'failed';
  reason: string;
  actionType: string;
  chainId: number;
  recipient: string;
  asset: string;
  amountWei: string;
  createdAt: string;
  updatedAt: string;
}

export interface EncryptedApprovalUpdateEnvelope {
  algorithm: 'x25519-hkdf-xchacha20poly1305-v2';
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
}

export interface ApprovalUpdateInput {
  approvalId: string;
  daemonId: string;
  vaultPassword: string;
  decision: 'approve' | 'reject';
  note?: string;
}

export interface SecureApprovalLinkRecord {
  approvalCapability: string;
  approvalId: string;
  approvalUrl: string;
  daemonId: string;
  daemonPublicKey: string;
}
