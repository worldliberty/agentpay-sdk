/**
 * Admin authority (docs/daemon-api.md, "Admin challenge flow"):
 *
 * - root peer (`sudo agentpay …`): `"peer_credentials"`;
 * - macOS with an enrolled Touch ID credential: BeginAdminChallenge → `agentpay-auth sign` with
 *   a reason naming the operation (Touch ID or the Mac password) → CompleteAdminChallenge →
 *   a 5-minute lease, revoked when the operation is done;
 * - otherwise (SSH, Linux, Touch ID off): an `AuthError` telling the user to re-run with sudo.
 *   The client never asks for a password itself.
 */
import { copy } from '../copy/index.js';
import type { SignerClient } from '../daemon/signer.js';
import { AuthError } from '../errors.js';
import { timestampToDate } from '../format/text.js';
import type { AdminAuth, AdminLease } from '../generated/index.js';
import type { ClientStateStore } from './client-state.js';
import { HelperError, type TouchIdHelper } from './touch-id.js';

export interface AdminOperation {
  /** Challenge purpose: 1-128 of `[A-Za-z0-9._:/-]`, e.g. `approve:<uuid>`. */
  purpose: string;
  /** Touch ID prompt reason, e.g. "approve sending 1 USD1 to 0x5aed…67de". */
  reason: string;
  /** The command to suggest with sudo when Touch ID is unavailable. */
  command: string;
  /** May reuse a cached session lease (setup and settings flows, not approvals). */
  reusable?: boolean;
}

export type AdminMethod = 'root' | 'touch_id' | 'sudo';

export interface AdminGrant {
  auth: AdminAuth;
  method: AdminMethod;
  release(): Promise<void>;
}

export interface AdminAuthorizer {
  /** How admin approval would be obtained right now. */
  method(): AdminMethod;
  authorize(operation: AdminOperation): Promise<AdminGrant>;
  /** Revokes a cached session lease. */
  dispose(): Promise<void>;
}

export interface AdminAuthorizerDeps {
  euid: number;
  platform: NodeJS.Platform;
  state: ClientStateStore;
  helper: TouchIdHelper | null;
  keyFile: string;
  keyFileExists: (path: string) => boolean;
  signer: SignerClient;
  now?: () => Date;
}

const DOMAIN_TAG = 'agentpay-admin-challenge-v1';
const PURPOSE = /^[A-Za-z0-9._:/-]{1,128}$/u;
const LEASE_SAFETY_MS = 30_000;

/** The fields a client may show from a challenge message. */
export interface ChallengeMessage {
  credentialId: string;
  purpose: string;
  expiresAt: Date;
}

function uuidFromBytes(bytes: Buffer): string {
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Parses `agentpay-admin-challenge-v1` message bytes (hex). Throws on malformed input. */
export function parseChallengeMessage(messageHex: string): ChallengeMessage {
  const bytes = Buffer.from(messageHex, 'hex');
  const tagLength = DOMAIN_TAG.length;
  const fixed = tagLength + 1 + 16 * 3 + 32;
  if (
    bytes.length < fixed + 2 + 8 ||
    bytes.subarray(0, tagLength).toString('ascii') !== DOMAIN_TAG
  ) {
    throw new Error('not an agentpay-admin-challenge-v1 message');
  }
  const credentialId = uuidFromBytes(bytes.subarray(tagLength + 1 + 16, tagLength + 1 + 32));
  const purposeLength = bytes.readUInt16BE(fixed);
  const purposeEnd = fixed + 2 + purposeLength;
  if (bytes.length !== purposeEnd + 8) {
    throw new Error('challenge message has the wrong length');
  }
  const purpose = bytes.subarray(fixed + 2, purposeEnd).toString('utf8');
  const expiry = Number(bytes.readBigInt64BE(purposeEnd));
  return { credentialId, purpose, expiresAt: new Date(expiry * 1000) };
}

function helperFailure(error: HelperError, command: string): AuthError {
  const e = copy.errors;
  switch (error.code) {
    case 'user_cancel':
      return new AuthError('touch_id_cancelled', e.touchIdCancelled);
    case 'interaction_not_allowed':
      return new AuthError('touch_id_no_gui', e.touchIdNoGui(command));
    case 'key_invalidated':
    case 'key_not_found':
      return new AuthError('touch_id_key_invalid', e.touchIdKeyInvalid);
    case 'helper_missing':
      return new AuthError('touch_id_helper_missing', e.helperMissing(error.message));
    case 'secure_enclave_unavailable':
      return new AuthError('touch_id_unavailable', e.touchIdUnavailable);
    default:
      return new AuthError('touch_id_failed', e.touchIdFailed(error.message));
  }
}

export function createAdminAuthorizer(deps: AdminAuthorizerDeps): AdminAuthorizer {
  const now = deps.now ?? (() => new Date());
  let session: AdminLease | null = null;

  const touchIdReady = () =>
    deps.platform === 'darwin' &&
    deps.helper !== null &&
    deps.state.read().adminCredentialId !== null &&
    deps.keyFileExists(deps.keyFile);

  const method = (): AdminMethod =>
    deps.euid === 0 ? 'root' : touchIdReady() ? 'touch_id' : 'sudo';

  const leaseGrant = (lease: AdminLease, release: () => Promise<void>): AdminGrant => ({
    auth: { lease: { lease_id: lease.lease_id, lease_secret: lease.lease_secret } },
    method: 'touch_id',
    release,
  });

  const revoke = async (lease: AdminLease) => {
    try {
      await deps.signer.revokeLease(
        { lease: { lease_id: lease.lease_id, lease_secret: lease.lease_secret } },
        lease.lease_id,
      );
    } catch {
      // An expired or forgotten lease is already unusable.
    }
  };

  const challenge = async (operation: AdminOperation): Promise<AdminLease> => {
    const credentialId = deps.state.read().adminCredentialId;
    const helper = deps.helper;
    if (!credentialId || !helper || !PURPOSE.test(operation.purpose)) {
      throw new AuthError('sudo_required', copy.errors.sudoRequired(operation.command));
    }
    const issued = await deps.signer.beginChallenge(credentialId, operation.purpose);
    const message = parseChallengeMessage(issued.message_hex);
    if (message.purpose !== operation.purpose || message.credentialId !== credentialId) {
      throw new AuthError(
        'touch_id_failed',
        copy.errors.touchIdFailed('the daemon issued a challenge for another operation'),
      );
    }
    let signature: string;
    try {
      signature = (await helper.sign(deps.keyFile, operation.reason, issued.message_hex))
        .signatureDerHex;
    } catch (error) {
      throw error instanceof HelperError ? helperFailure(error, operation.command) : error;
    }
    return deps.signer.completeChallenge(issued.challenge_id, signature);
  };

  return {
    method,
    async authorize(operation) {
      const current = method();
      if (current === 'root') {
        return { auth: 'peer_credentials', method: 'root', release: async () => {} };
      }
      if (current === 'sudo') {
        throw new AuthError('sudo_required', copy.errors.sudoRequired(operation.command));
      }
      if (operation.reusable) {
        const valid =
          session &&
          timestampToDate(session.expires_at).getTime() - LEASE_SAFETY_MS > now().getTime();
        if (!valid || !session) {
          session = await challenge({
            ...operation,
            purpose: 'admin-session',
            reason: copy.common.reasons.session,
          });
        }
        return leaseGrant(session, async () => {});
      }
      const lease = await challenge(operation);
      return leaseGrant(lease, () => revoke(lease));
    },
    async dispose() {
      if (session) {
        const lease = session;
        session = null;
        await revoke(lease);
      }
    },
  };
}
