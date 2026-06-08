export const APPROVAL_CAPABILITY_QUERY_KEY = 'approvalCapability';
export const APPROVAL_CAPABILITY_SYNC_CHANNEL = 'agentpay:approval-capability-sync';
const APPROVAL_CAPABILITY_STORAGE_KEY_PREFIX = 'agentpay:approval-capability:';
export const MISSING_APPROVAL_CAPABILITY_REASON =
  'This page is missing its secure approval capability. Open the exact CLI-issued approval link or use the local admin CLI.';
export const INVALID_APPROVAL_CAPABILITY_REASON =
  'This approval link is malformed or has been altered. Request a fresh CLI-issued approval URL or use the local admin CLI.';
export const CONSUMED_APPROVAL_CAPABILITY_REASON =
  'This secure approval link was already submitted from this browser session. Wait for the daemon to apply the update, or issue a fresh secure link if the approval is still pending and you need to retry.';

const APPROVAL_CAPABILITY_PATTERN = /^[0-9a-fA-F]{64}$/u;

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
  state: ApprovalCapabilitySyncState;
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

  return {
    approvalId: normalizedApprovalId,
    capability: resolvedCapability.value,
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

  return {
    approvalId: normalizedApprovalId,
    capability: resolvedCapability.value,
    state: candidate.state,
  };
}
