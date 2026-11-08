/** Turning Touch ID approvals on and off for this user. */
import type { ClientStateStore } from '../auth/client-state.js';
import type { TouchIdHelper } from '../auth/touch-id.js';
import { copy } from '../copy/index.js';
import { AuthError, SignerCallError } from '../errors.js';
import type { AdminActions } from './admin-actions.js';

export interface TouchIdDeps {
  platform: NodeJS.Platform;
  helper: TouchIdHelper | null;
  keyFile: string;
  keyFileExists: (path: string) => boolean;
  state: ClientStateStore;
  admin: AdminActions;
  label: string;
}

export type TouchIdStatus = 'on' | 'off' | 'unavailable';

export async function touchIdStatus(deps: TouchIdDeps): Promise<TouchIdStatus> {
  if (deps.platform !== 'darwin' || !deps.helper) {
    return 'unavailable';
  }
  if (deps.state.read().adminCredentialId && deps.keyFileExists(deps.keyFile)) {
    return 'on';
  }
  try {
    const status = await deps.helper.status();
    return status.secureEnclaveAvailable && status.userPresenceAvailable ? 'off' : 'unavailable';
  } catch {
    return 'unavailable';
  }
}

/** Creates the Secure Enclave key (no prompt) and enrolls its public key (root, once). */
export async function enableTouchId(deps: TouchIdDeps, command: string): Promise<string> {
  const status = await touchIdStatus(deps);
  const enrolled = deps.state.read().adminCredentialId;
  if (status === 'on' && enrolled) {
    return enrolled;
  }
  if (status === 'unavailable' || !deps.helper) {
    throw new AuthError('touch_id_unavailable', copy.errors.touchIdUnavailable);
  }
  const helper = deps.helper;
  if (deps.keyFileExists(deps.keyFile)) {
    // A key file without an enrolled credential is left over from an interrupted setup.
    await helper.remove(deps.keyFile);
  }
  const { publicKeySec1Hex } = await helper.create(deps.keyFile);
  try {
    const credential = await deps.admin.enrollCredential(publicKeySec1Hex, deps.label, command);
    deps.state.update({ adminCredentialId: credential.id });
    return credential.id;
  } catch (error) {
    await helper.remove(deps.keyFile).catch(() => {});
    throw error;
  }
}

/** Revokes the credential in the signer daemon, then deletes the key file. */
export async function disableTouchId(deps: TouchIdDeps, command: string): Promise<void> {
  const credentialId = deps.state.read().adminCredentialId;
  if (credentialId) {
    try {
      await deps.admin.revokeCredential(credentialId, command);
    } catch (error) {
      if (!(error instanceof SignerCallError && error.wire.kind === 'UnknownAdminCredential')) {
        throw error;
      }
    }
  }
  if (deps.helper && deps.keyFileExists(deps.keyFile)) {
    await deps.helper.remove(deps.keyFile);
  }
  deps.state.update({ adminCredentialId: null });
}
