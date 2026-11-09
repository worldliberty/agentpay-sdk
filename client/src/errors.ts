/**
 * Typed errors. Every error carries `guidance`: one plain-language message and the single next
 * action that fixes it, so commands and screens render failures the same way.
 */
import { copy, type Guidance } from './copy/index.js';
import type { PolicyError, WireDaemonError, WirePaymentsError } from './generated/index.js';

/** Which daemon a call went to. */
export type ServiceName = 'signer' | 'payments';

export function serviceLabel(service: ServiceName): string {
  return service === 'signer' ? 'signer daemon' : 'payments service';
}

/** Process exit codes. */
export const EXIT = {
  ok: 0,
  failure: 1,
  usage: 2,
  /** A payment is waiting for a manual approval (not a failure). */
  pendingApproval: 3,
  /** AgentPay is not installed or this user has no credentials. */
  notSetUp: 4,
} as const;

export class AgentPayError extends Error {
  readonly code: string;
  readonly guidance: Guidance;
  readonly exitCode: number;

  constructor(code: string, guidance: Guidance, exitCode: number = EXIT.failure) {
    super(guidance.message);
    this.name = new.target.name;
    this.code = code;
    this.guidance = guidance;
    this.exitCode = exitCode;
  }
}

export type TransportErrorCode =
  | 'socket_missing'
  | 'socket_untrusted'
  | 'connect_failed'
  | 'closed_without_response'
  | 'timeout'
  | 'frame_too_large'
  | 'malformed_response';

/** The socket could not be used, or the daemon closed it without a response. */
export class TransportError extends AgentPayError {
  readonly service: ServiceName;

  constructor(code: TransportErrorCode, service: ServiceName, guidance: Guidance) {
    super(code, guidance, code === 'socket_missing' ? EXIT.notSetUp : EXIT.failure);
    this.service = service;
  }
}

/** The daemon speaks another major API version. */
export class IncompatibleApiError extends AgentPayError {
  constructor(service: ServiceName, theirs: string, ours: string) {
    super('incompatible_api', copy.errors.incompatible(serviceLabel(service), theirs, ours));
  }
}

/** The daemon answered with a response variant the method never returns. */
export class ProtocolError extends AgentPayError {
  constructor(service: ServiceName, method: string, type: string) {
    super('protocol', copy.errors.unexpectedResponse(serviceLabel(service), method, type));
  }
}

/** A signer daemon error (`WireResponse.ok == false`). */
export class SignerCallError extends AgentPayError {
  readonly wire: WireDaemonError;

  constructor(wire: WireDaemonError) {
    super(wire.kind, describeDaemonError(wire));
    this.wire = wire;
  }
}

/** A payments service error (`WireResponse.ok == false`). */
export class PaymentsCallError extends AgentPayError {
  readonly wire: WirePaymentsError;

  constructor(wire: WirePaymentsError) {
    super(
      wire.kind,
      describePaymentsError(wire),
      wire.kind === 'ManualApprovalPending' ? EXIT.pendingApproval : EXIT.failure,
    );
    this.wire = wire;
  }
}

/** Bad command-line input. */
export class UsageError extends AgentPayError {
  constructor(detail: string) {
    super('usage', copy.errors.usage(detail), EXIT.usage);
  }
}

/** Credentials or admin authority are missing; `guidance` says how to get them. */
export class AuthError extends AgentPayError {}

/**
 * Whether `error` says the daemons no longer accept this user's agent credentials (revoked,
 * rotated, or left over from an install whose state was removed).
 */
export function staleAgentCredentials(error: unknown): boolean {
  return (
    (error instanceof PaymentsCallError && error.wire.kind === 'AgentAuthenticationFailed') ||
    (error instanceof SignerCallError && error.wire.kind === 'AgentAuthenticationFailed')
  );
}

/** The approval request id a wire error refers to, when it is about a manual approval. */
export function pendingApprovalId(error: unknown): string | null {
  if (error instanceof PaymentsCallError) {
    if (error.wire.kind === 'ManualApprovalPending') {
      return error.wire.data.approval_request_id;
    }
    if (error.wire.kind === 'Signer' && error.wire.data.kind === 'ManualApprovalRequired') {
      return error.wire.data.data.approval_request_id;
    }
  }
  if (error instanceof SignerCallError && error.wire.kind === 'ManualApprovalRequired') {
    return error.wire.data.approval_request_id;
  }
  return null;
}

/** The wallets a `BootstrapWallet` refused to replace (`WalletAlreadyExists`), else `null`. */
export function existingWalletIds(error: unknown): string[] | null {
  return error instanceof SignerCallError && error.wire.kind === 'WalletAlreadyExists'
    ? error.wire.data.vault_key_ids
    : null;
}

function describePolicyError(error: PolicyError): string {
  if (typeof error === 'string') {
    return error === 'NoAttachedPolicies' || error === 'NoApplicablePolicies'
      ? 'no spending limit covers this asset and network'
      : error;
  }
  const [kind, detail] = Object.entries(error)[0] ?? ['PolicyError', null];
  const words = kind.replace(/([a-z])([A-Z])/gu, '$1 $2').toLowerCase();
  if (detail && typeof detail === 'object' && 'max_amount_wei' in detail) {
    const limit = String((detail as { max_amount_wei: unknown }).max_amount_wei);
    return `${words} (limit ${limit} base units)`;
  }
  return words;
}

/** Guidance for a signer daemon error kind. */
export function describeDaemonError(error: WireDaemonError): Guidance {
  const e = copy.errors;
  switch (error.kind) {
    case 'AdminAuthenticationRequired':
    case 'RootPeerRequired':
      return e.sudoRequired('agentpay …');
    case 'UnknownLease':
    case 'InvalidLease':
      return e.leaseExpired;
    case 'AuthenticationFailed':
      return e.touchIdFailed('the signature was not accepted');
    case 'AdminCredentialLocked':
      return e.adminLocked;
    case 'UnknownAdminCredential':
      return e.touchIdKeyInvalid;
    case 'AgentAuthenticationFailed':
      return e.agentAuthFailed;
    case 'UnknownManualApprovalRequest':
      return e.approvalUnknown(error.data);
    case 'ManualApprovalRequestNotPending':
      return e.approvalNotPending(error.data.approval_request_id, error.data.status);
    case 'ManualApprovalRejected':
      return e.approvalRejected(error.data.approval_request_id);
    case 'ManualApprovalRequired':
      return {
        message: copy.commands.pending.detail(error.data.approval_request_id),
        next: copy.commands.pending.approve(error.data.approval_request_id),
      };
    case 'WalletAlreadyExists':
      return e.walletExists(error.data.vault_key_ids.length);
    case 'WalletNotFound':
      return e.walletMissing;
    case 'InvalidWalletRequest':
      return e.walletRequestInvalid(error.data);
    case 'InvalidSpendingLimits':
      return e.limitsInvalid(error.data);
    case 'InvalidWalletBackup':
      return e.backupInvalid(error.data);
    case 'WalletBackupDecryptionFailed':
      return e.backupDecryption;
    case 'WeakBackupPassphrase':
      return e.backupWeak(error.data.min_chars);
    case 'UnknownSignedTransaction':
      return e.signedTransactionUnknown(error.data);
    case 'Policy':
      return describePolicy(error.data);
    case 'Persistence':
      return e.persistence(error.data);
    case 'InvalidPolicy':
    case 'InvalidAction':
    case 'InvalidConfig':
    case 'InvalidAdminCredential':
    case 'InvalidAdminChallengePurpose':
    case 'InvalidPolicyAttachment':
    case 'InvalidNonceReservation':
    case 'Transport':
      return e.generic(error.kind, error.data);
    default:
      return e.generic(error.kind, 'data' in error ? JSON.stringify(error.data) : '');
  }
}

function describePolicy(policy: PolicyError): Guidance {
  if (policy === 'NoAttachedPolicies') {
    return copy.errors.noSpendingPolicy;
  }
  if (policy === 'NoApplicablePolicies') {
    return copy.errors.noLimitForAsset;
  }
  return copy.errors.policyDenied(describePolicyError(policy));
}

/** Guidance for a payments service error kind. */
export function describePaymentsError(error: WirePaymentsError): Guidance {
  const e = copy.errors;
  switch (error.kind) {
    case 'AgentAuthenticationFailed':
      return e.agentAuthFailed;
    case 'SignerUnavailable':
      return e.signerUnavailable(error.data);
    case 'Signer':
      return describeDaemonError(error.data);
    case 'ManualApprovalPending':
      return {
        message: copy.commands.pending.detail(error.data.approval_request_id),
        next: copy.commands.pending.approve(error.data.approval_request_id),
      };
    case 'InvalidConfig':
      return e.invalidConfig(error.data);
    case 'Persistence':
      return e.persistence(error.data);
    case 'InvalidRequest':
      return e.invalidRequest(error.data);
    case 'ChainRpc':
      return e.chainRpc(error.data);
    case 'SignedTransactionMismatch':
      return e.mismatch(error.data);
    case 'UnknownPendingApproval':
      return e.unknownPendingApproval(error.data);
    case 'Merchant':
      return e.merchant(error.data);
    case 'Internal':
      return e.generic('Internal error', error.data);
    default:
      return e.generic((error as { kind: string }).kind, '');
  }
}

/** Guidance for any thrown value. */
export function guidanceFor(error: unknown): Guidance {
  if (error instanceof AgentPayError) {
    return error.guidance;
  }
  const detail = error instanceof Error ? error.message : String(error);
  return copy.errors.generic('Unexpected error', detail);
}
