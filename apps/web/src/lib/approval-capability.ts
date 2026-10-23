/**
 * Secure approval links carry their secrets in the URL fragment, which the
 * browser never sends to the frontend host:
 * `/approvals/<approvalId>#approvalCapability=<token>&daemonId=<id>&daemonKey=<hex>`.
 */
export const APPROVAL_CAPABILITY_FRAGMENT_KEY = 'approvalCapability';
export const APPROVAL_DAEMON_ID_FRAGMENT_KEY = 'daemonId';
export const APPROVAL_DAEMON_KEY_FRAGMENT_KEY = 'daemonKey';
export const APPROVAL_CAPABILITY_SYNC_CHANNEL = 'agentpay:approval-capability-sync';
const APPROVAL_CAPABILITY_STORAGE_KEY_PREFIX = 'agentpay:approval-capability:';
const APPROVAL_DAEMON_KEY_STORAGE_KEY_PREFIX = 'agentpay:approval-daemon-key:';
export const MISSING_APPROVAL_CAPABILITY_REASON =
  'This page is missing its secure approval capability. Open the exact CLI-issued approval link or use the local admin CLI.';
export const INVALID_APPROVAL_CAPABILITY_REASON =
  'This approval link is malformed or has been altered. Request a fresh CLI-issued approval URL or use the local admin CLI.';
export const DAEMON_KEY_MISMATCH_REASON =
  'The relay advertises a different daemon encryption key than the CLI-issued approval link. Do not continue; use the local admin CLI.';
export const DAEMON_ID_MISMATCH_REASON =
  'The CLI-issued approval link names a different daemon than this approval request. Do not continue; use the local admin CLI.';
export const CONSUMED_APPROVAL_CAPABILITY_REASON =
  'This secure approval link was already submitted from this browser session. Wait for the daemon to apply the update, or issue a fresh secure link if the approval is still pending and you need to retry.';

const APPROVAL_CAPABILITY_PATTERN = /^[0-9a-fA-F]{64}$/u;
const HEX_32_BYTE_PATTERN = /^[0-9a-fA-F]{64}$/u;

export type ApprovalCapabilityState = 'loaded' | 'missing' | 'invalid' | 'consumed';
export type ApprovalCapabilitySyncState = 'loaded' | 'consumed';

export interface ResolvedApprovalCapability {
  value: string | null;
  state: ApprovalCapabilityState;
  reason: string | null;
}

export interface ApprovalCapabilitySyncMessage {
  approvalId: string;
  capability: string | null;
  /** Daemon X25519 key pinned alongside a loaded capability; absent for consumed messages. */
  daemonKey?: string;
  state: ApprovalCapabilitySyncState;
}

export interface ApprovalLinkFragment {
  capability: ResolvedApprovalCapability;
  daemonId: string | null;
  daemonKey: string | null;
  /** True when the fragment carried any secure-link parameter, valid or not. */
  present: boolean;
}

export interface ApprovalCapabilityStorageLike {
  getItem(key: string): string | null;
  removeItem?(key: string): void;
  setItem(key: string, value: string): void;
}

function resolveFirstValue(value: string | string[] | null | undefined): string | null {
  if (Array.isArray(value)) {
    return value[0] ?? null;
  }

  return value ?? null;
}

function normalizeApprovalId(value: string | null | undefined): string | null {
  const normalized = value?.trim() ?? '';
  // biome-ignore lint/suspicious/noControlCharactersInRegex: rejects approval ids containing control characters
  if (!normalized || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    return null;
  }

  return normalized;
}

export function resolveApprovalCapability(
  value: string | string[] | null | undefined,
): ResolvedApprovalCapability {
  const candidate = resolveFirstValue(value)?.trim() ?? '';

  if (!candidate) {
    return {
      value: null,
      state: 'missing',
      reason: MISSING_APPROVAL_CAPABILITY_REASON,
    };
  }

  if (!APPROVAL_CAPABILITY_PATTERN.test(candidate)) {
    return {
      value: null,
      state: 'invalid',
      reason: INVALID_APPROVAL_CAPABILITY_REASON,
    };
  }

  return {
    value: candidate.toLowerCase(),
    state: 'loaded',
    reason: null,
  };
}

/** Normalizes a 32-byte hex value (daemon id or X25519 key); returns null when malformed. */
export function normalizeHex32(value: string | null | undefined): string | null {
  const candidate = value?.trim() ?? '';
  return HEX_32_BYTE_PATTERN.test(candidate) ? candidate.toLowerCase() : null;
}

/**
 * Parses the secure approval link fragment. A capability without a well-formed
 * daemon id and daemon key is treated as invalid: the key is what lets the page
 * detect a relay that advertises a substituted encryption key.
 */
export function parseApprovalLinkFragment(hash: string | null | undefined): ApprovalLinkFragment {
  const params = new URLSearchParams((hash ?? '').replace(/^#/u, ''));
  const present =
    params.has(APPROVAL_CAPABILITY_FRAGMENT_KEY) ||
    params.has(APPROVAL_DAEMON_ID_FRAGMENT_KEY) ||
    params.has(APPROVAL_DAEMON_KEY_FRAGMENT_KEY);
  const capability = resolveApprovalCapability(params.getAll(APPROVAL_CAPABILITY_FRAGMENT_KEY));
  const daemonId = normalizeHex32(params.get(APPROVAL_DAEMON_ID_FRAGMENT_KEY));
  const daemonKey = normalizeHex32(params.get(APPROVAL_DAEMON_KEY_FRAGMENT_KEY));

  if (present && (capability.state !== 'loaded' || !daemonId || !daemonKey)) {
    return {
      capability: {
        value: null,
        state: 'invalid',
        reason: INVALID_APPROVAL_CAPABILITY_REASON,
      },
      daemonId,
      daemonKey,
      present,
    };
  }

  return { capability, daemonId, daemonKey, present };
}

/** Case-insensitive comparison of two hex daemon keys; false when either is malformed. */
export function daemonKeysMatch(
  pinned: string | null | undefined,
  advertised: string | null | undefined,
): boolean {
  const left = normalizeHex32(pinned);
  const right = normalizeHex32(advertised);
  return left !== null && right !== null && left === right;
}

export function approvalDaemonKeyStorageKey(approvalId: string): string {
  return `${APPROVAL_DAEMON_KEY_STORAGE_KEY_PREFIX}${approvalId.trim()}`;
}

export function persistApprovalDaemonKey(
  approvalId: string,
  daemonKey: string | null | undefined,
  storage: ApprovalCapabilityStorageLike | null | undefined,
): string | null {
  const normalized = normalizeHex32(daemonKey);
  if (normalized && storage) {
    storage.setItem(approvalDaemonKeyStorageKey(approvalId), normalized);
  }
  return normalized;
}

export function resolveStoredApprovalDaemonKey(
  approvalId: string,
  storage: ApprovalCapabilityStorageLike | null | undefined,
): string | null {
  if (!storage) {
    return null;
  }

  const normalized = normalizeHex32(storage.getItem(approvalDaemonKeyStorageKey(approvalId)));
  if (!normalized) {
    storage.removeItem?.(approvalDaemonKeyStorageKey(approvalId));
  }
  return normalized;
}

export function approvalCapabilityStorageKey(approvalId: string): string {
  return `${APPROVAL_CAPABILITY_STORAGE_KEY_PREFIX}${approvalId.trim()}`;
}

export function resolveStoredApprovalCapability(
  approvalId: string,
  storage: ApprovalCapabilityStorageLike | null | undefined,
): ResolvedApprovalCapability {
  if (!storage) {
    return resolveApprovalCapability(null);
  }

  const resolved = resolveApprovalCapability(
    storage.getItem(approvalCapabilityStorageKey(approvalId)),
  );
  if (resolved.state !== 'loaded') {
    storage.removeItem?.(approvalCapabilityStorageKey(approvalId));
  }
  return resolved;
}

export function persistApprovalCapability(
  approvalId: string,
  capability: string | null | undefined,
  storage: ApprovalCapabilityStorageLike | null | undefined,
): ResolvedApprovalCapability {
  const resolved = resolveApprovalCapability(capability);
  if (resolved.state !== 'loaded' || !resolved.value || !storage) {
    return resolved;
  }

  storage.setItem(approvalCapabilityStorageKey(approvalId), resolved.value);
  return resolved;
}

export function clearApprovalCapability(
  approvalId: string,
  storage: ApprovalCapabilityStorageLike | null | undefined,
): ResolvedApprovalCapability {
  storage?.removeItem?.(approvalCapabilityStorageKey(approvalId));
  storage?.removeItem?.(approvalDaemonKeyStorageKey(approvalId));
  return {
    value: null,
    state: 'consumed',
    reason: CONSUMED_APPROVAL_CAPABILITY_REASON,
  };
}

export function createApprovalCapabilitySyncMessage(
  approvalId: string,
  capability: string | null | undefined,
  state: ApprovalCapabilitySyncState,
  daemonKey?: string | null,
): ApprovalCapabilitySyncMessage | null {
  const normalizedApprovalId = normalizeApprovalId(approvalId);
  if (!normalizedApprovalId) {
    return null;
  }

  if (state === 'consumed') {
    return {
      approvalId: normalizedApprovalId,
      capability: null,
      state,
    };
  }

  const resolvedCapability = resolveApprovalCapability(capability);
  if (resolvedCapability.state !== 'loaded' || !resolvedCapability.value) {
    return null;
  }

  const normalizedDaemonKey = daemonKey === undefined ? undefined : normalizeHex32(daemonKey);
  if (normalizedDaemonKey === null) {
    return null;
  }

  return {
    approvalId: normalizedApprovalId,
    capability: resolvedCapability.value,
    ...(normalizedDaemonKey ? { daemonKey: normalizedDaemonKey } : {}),
    state,
  };
}

function isSyncState(value: unknown): value is ApprovalCapabilitySyncState {
  return value === 'loaded' || value === 'consumed';
}

export function parseApprovalCapabilitySyncMessage(
  value: unknown,
): ApprovalCapabilitySyncMessage | null {
  if (!value || typeof value !== 'object') {
    return null;
  }

  const candidate = value as Record<string, unknown>;
  const normalizedApprovalId = normalizeApprovalId(
    typeof candidate.approvalId === 'string' ? candidate.approvalId : null,
  );
  if (!normalizedApprovalId || !isSyncState(candidate.state)) {
    return null;
  }

  if (candidate.state === 'consumed') {
    return {
      approvalId: normalizedApprovalId,
      capability: null,
      state: candidate.state,
    };
  }

  const resolvedCapability = resolveApprovalCapability(
    typeof candidate.capability === 'string' ? candidate.capability : null,
  );
  if (resolvedCapability.state !== 'loaded' || !resolvedCapability.value) {
    return null;
  }

  let daemonKey: string | undefined;
  if (candidate.daemonKey !== undefined) {
    const normalizedDaemonKey =
      typeof candidate.daemonKey === 'string' ? normalizeHex32(candidate.daemonKey) : null;
    if (!normalizedDaemonKey) {
      return null;
    }
    daemonKey = normalizedDaemonKey;
  }

  return {
    approvalId: normalizedApprovalId,
    capability: resolvedCapability.value,
    ...(daemonKey ? { daemonKey } : {}),
    state: candidate.state,
  };
}
