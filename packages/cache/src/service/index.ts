import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type Redis from 'ioredis';
import { getCacheClient } from '../client/index.js';
import { CacheError, cacheErrorCodes, toCacheError } from '../errors/index.js';

export const relayApprovalStatuses = [
  'pending',
  'approved',
  'rejected',
  'completed',
  'expired',
] as const;
export type RelayApprovalStatus = (typeof relayApprovalStatuses)[number];

export const relayUpdateStatuses = [
  'pending',
  'inflight',
  'applied',
  'rejected',
  'failed',
] as const;
export type RelayUpdateStatus = (typeof relayUpdateStatuses)[number];

export interface RelayDaemonProfile {
  daemonId: string;
  daemonPublicKey: string;
  ethereumAddress: string;
  label?: string;
  lastSeenAt: string;
  registeredAt: string;
  relayUrl?: string;
  signerBackend?: string;
  status: 'active' | 'paused';
  updatedAt: string;
  version?: string;
}

export interface RelayPolicyRecord {
  action: string;
  amountMaxWei?: string;
  amountMinWei?: string;
  maxTxCount?: string;
  maxFeePerGasWei?: string;
  maxPriorityFeePerGasWei?: string;
  maxCalldataBytes?: string;
  maxGasSpendWei?: string;
  chainId?: number;
  daemonId: string;
  destination: string;
  metadata?: Record<string, string>;
  policyId: string;
  requiresManualApproval: boolean;
  scope: 'default' | 'override';
  tokenAddress?: string;
  updatedAt: string;
}

export interface RelayAgentKeyRecord {
  agentKeyId: string;
  createdAt?: string;
  daemonId: string;
  label?: string;
  metadata?: Record<string, string>;
  status: 'active' | 'revoked';
  updatedAt: string;
}

export interface RelayApprovalRequestRecord {
  agentKeyId?: string;
  amountWei?: string;
  approvalRequestId: string;
  chainId?: number;
  daemonId: string;
  destination: string;
  metadata?: Record<string, string>;
  network?: string;
  reason?: string;
  requestedAt: string;
  status: RelayApprovalStatus;
  tokenAddress?: string;
  transactionType: string;
  updatedAt: string;
}

export interface RelayEncryptedPayload {
  aadBase64?: string;
  algorithm: string;
  ciphertextBase64: string;
  contentSha256Hex?: string;
  encapsulatedKeyBase64: string;
  nonceBase64: string;
  schemaVersion: number;
}

export interface RelayUpdateFeedbackRecord {
  daemonId: string;
  details?: Record<string, string>;
  feedbackAt: string;
  message?: string;
  status: Extract<RelayUpdateStatus, 'applied' | 'failed' | 'rejected'>;
  updateId: string;
}

export interface RelayEncryptedUpdateRecord {
  claimToken?: string;
  claimUntil?: string;
  createdAt: string;
  daemonId: string;
  feedback?: RelayUpdateFeedbackRecord;
  lastDeliveredAt?: string;
  metadata?: Record<string, string>;
  payload: RelayEncryptedPayload;
  status: RelayUpdateStatus;
  targetApprovalRequestId?: string;
  type: string;
  updateId: string;
  updatedAt: string;
}

export interface SyncDaemonRegistrationInput {
  agentKeys?: RelayAgentKeyRecord[];
  approvalRequests?: RelayApprovalRequestRecord[];
  daemon: RelayDaemonProfile;
  policies?: RelayPolicyRecord[];
}

export interface ApprovalRequestFilters {
  daemonId?: string;
  destination?: string;
  limit?: number;
  status?: RelayApprovalStatus;
  tokenAddress?: string;
}

export interface CreateEncryptedUpdateInput {
  daemonId: string;
  metadata?: Record<string, string>;
  payload: RelayEncryptedPayload;
  targetApprovalRequestId?: string;
  type: string;
  updateId?: string;
}

export interface ClaimEncryptedUpdatesInput {
  daemonId: string;
  leaseSeconds?: number;
  limit?: number;
}

export interface SubmitUpdateFeedbackInput {
  claimToken: string;
  daemonId: string;
  details?: Record<string, string>;
  message?: string;
  status: Extract<RelayUpdateStatus, 'applied' | 'failed' | 'rejected'>;
  updateId: string;
}

export interface ApprovalCapabilityFailureRecord {
  attempts: number;
  blockedUntil?: string;
  firstFailedAt: string;
  lastFailedAt: string;
}

export interface RecordApprovalCapabilityFailureResult {
  attempts: number;
  blocked: boolean;
  blockedUntil: string | null;
}

interface JsonCache {
  del(key: string): Promise<number>;
  get(key: string): Promise<string | null>;
  ping(): Promise<string>;
  quit(): Promise<string>;
  sadd(key: string, ...members: string[]): Promise<number>;
  set(key: string, value: string, mode?: 'NX' | 'XX'): Promise<'OK' | null>;
  smembers(key: string): Promise<string[]>;
  zadd(key: string, ...args: (string | number)[]): Promise<number>;
  zrange(key: string, start: number, stop: number, ...args: string[]): Promise<string[]>;
  zrem(key: string, ...members: string[]): Promise<number>;
}

const defaultNamespace = 'agentpay:relay';
const approvalCapabilityFailureWindowMs = 5 * 60 * 1000;
const approvalCapabilityMaxFailures = 5;
const approvalCapabilityBlockWindowMs = 10 * 60 * 1000;

const toIsoTimestamp = (value = new Date()): string => value.toISOString();

const dedupe = <T>(values: T[]): T[] => [...new Set(values)];

const matchesOptionalFilter = (
  value: string | undefined,
  expected: string | undefined,
): boolean => {
  if (!expected) {
    return true;
  }

  return value?.toLowerCase() === expected.toLowerCase();
};

const clampLimit = (limit: number | undefined, fallback: number, max: number): number => {
  if (!limit || Number.isNaN(limit)) {
    return fallback;
  }

  return Math.max(1, Math.min(limit, max));
};

const createApprovalCapabilityToken = (): string => randomBytes(32).toString('hex');

const approvalCapabilityHash = (token: string): string =>
  createHash('sha256').update(token, 'utf8').digest('hex');

const isActiveApprovalUpdateRecord = (
  record: RelayEncryptedUpdateRecord | null | undefined,
  approvalRequestId: string,
): record is RelayEncryptedUpdateRecord =>
  Boolean(
    record &&
      record.type === 'manual_approval_decision' &&
      record.targetApprovalRequestId === approvalRequestId &&
      (record.status === 'pending' || record.status === 'inflight'),
  );

const preserveRotatedApprovalCapability = (
  incoming: RelayApprovalRequestRecord,
  existing: RelayApprovalRequestRecord | null,
): RelayApprovalRequestRecord => {
  const existingMetadata = existing?.metadata;
  const incomingMetadata = incoming.metadata;
  const preservedCapabilityToken = existingMetadata?.approvalCapabilityToken?.trim();
  const preservedCapabilityHash = existingMetadata?.approvalCapabilityHash?.trim();

  if (!preservedCapabilityToken && !preservedCapabilityHash) {
    return incoming;
  }

  return {
    ...incoming,
    metadata: {
      ...(incomingMetadata ?? {}),
      ...(preservedCapabilityToken ? { approvalCapabilityToken: preservedCapabilityToken } : {}),
      ...(preservedCapabilityHash ? { approvalCapabilityHash: preservedCapabilityHash } : {}),
    },
  };
};

export class RelayCacheService {
  private readonly client: JsonCache;
  private readonly namespace: string;

  constructor(options: { client?: Redis; namespace?: string } = {}) {
    this.client = (options.client ?? getCacheClient()) as unknown as JsonCache;
    this.namespace = options.namespace ?? defaultNamespace;
  }

  async ping(): Promise<string> {
    try {
      return await this.client.ping();
    } catch (error) {
      throw toCacheError(error, { operation: 'ping' });
    }
  }

  async syncDaemonRegistration(input: SyncDaemonRegistrationInput): Promise<{
    agentKeyCount: number;
    approvalRequestCount: number;
    policyCount: number;
  }> {
    const profile = {
      ...input.daemon,
      lastSeenAt: input.daemon.lastSeenAt || toIsoTimestamp(),
      updatedAt: input.daemon.updatedAt || toIsoTimestamp(),
    } satisfies RelayDaemonProfile;

    try {
      await this.writeJson(this.daemonProfileKey(profile.daemonId), profile);
      await this.client.sadd(this.daemonIndexKey(), profile.daemonId);

      if (input.policies) {
        const policies = input.policies.map((policy) => ({
          ...policy,
          daemonId: profile.daemonId,
        }));
        await this.writeJson(this.daemonPoliciesKey(profile.daemonId), policies);
      }

      if (input.agentKeys) {
        const agentKeys = input.agentKeys.map((agentKey) => ({
          ...agentKey,
          daemonId: profile.daemonId,
        }));
        await this.writeJson(this.daemonAgentKeysKey(profile.daemonId), agentKeys);
      }

      if (input.approvalRequests) {
        const approvalIndexKey = this.daemonApprovalsKey(profile.daemonId);
        const existingApprovalIds = new Set(await this.client.zrange(approvalIndexKey, 0, -1));
        const nextApprovalIds = new Set<string>();

        for (const approvalRequest of input.approvalRequests) {
          const existing = await this.readJson<RelayApprovalRequestRecord>(
            this.approvalKey(approvalRequest.approvalRequestId),
          );
          const normalized = preserveRotatedApprovalCapability(
            { ...approvalRequest, daemonId: profile.daemonId },
            existing,
          );
          nextApprovalIds.add(normalized.approvalRequestId);
          await this.writeJson(this.approvalKey(normalized.approvalRequestId), normalized);
          await this.client.zadd(
            approvalIndexKey,
            Date.parse(normalized.requestedAt),
            normalized.approvalRequestId,
          );
        }

        const staleApprovalIds = [...existingApprovalIds].filter(
          (approvalRequestId) => !nextApprovalIds.has(approvalRequestId),
        );
        if (staleApprovalIds.length > 0) {
          await this.client.zrem(approvalIndexKey, ...staleApprovalIds);
          for (const approvalRequestId of staleApprovalIds) {
            await this.client.del(this.approvalKey(approvalRequestId));
            await this.client.del(this.activeApprovalUpdateKey(approvalRequestId));
            await this.client.del(this.approvalCapabilityFailuresKey(approvalRequestId));
          }
        }
      }

      return {
        agentKeyCount: input.agentKeys?.length ?? 0,
        approvalRequestCount: input.approvalRequests?.length ?? 0,
        policyCount: input.policies?.length ?? 0,
      };
    } catch (error) {
      throw toCacheError(error, {
        key: this.daemonProfileKey(profile.daemonId),
        operation: 'syncDaemonRegistration',
      });
    }
  }

  async listDaemons(): Promise<RelayDaemonProfile[]> {
    const daemonIds = await this.client.smembers(this.daemonIndexKey());
    const profiles = await Promise.all(
      daemonIds.map((daemonId) =>
        this.readJson<RelayDaemonProfile>(this.daemonProfileKey(daemonId)),
      ),
    );

    return profiles.filter((profile): profile is RelayDaemonProfile => Boolean(profile));
  }

  async getDaemonProfile(daemonId: string): Promise<RelayDaemonProfile | null> {
    return await this.readJson<RelayDaemonProfile>(this.daemonProfileKey(daemonId));
  }

  async getDaemonPolicies(daemonId: string): Promise<RelayPolicyRecord[]> {
    return (await this.readJson<RelayPolicyRecord[]>(this.daemonPoliciesKey(daemonId))) ?? [];
  }

  async getDaemonAgentKeys(daemonId: string): Promise<RelayAgentKeyRecord[]> {
    return (await this.readJson<RelayAgentKeyRecord[]>(this.daemonAgentKeysKey(daemonId))) ?? [];
  }

  async getApprovalRequest(approvalRequestId: string): Promise<RelayApprovalRequestRecord | null> {
    return await this.readJson<RelayApprovalRequestRecord>(this.approvalKey(approvalRequestId));
  }

  async listApprovalRequests(
    filters: ApprovalRequestFilters = {},
  ): Promise<RelayApprovalRequestRecord[]> {
    const limit = clampLimit(filters.limit, 100, 500);
    const daemonIds = filters.daemonId
      ? [filters.daemonId]
      : await this.client.smembers(this.daemonIndexKey());
    const requestIdsByDaemon = await Promise.all(
      daemonIds.map((daemonId) =>
        this.client.zrange(this.daemonApprovalsKey(daemonId), 0, limit * 2, 'REV'),
      ),
    );
    const requestIds = dedupe(requestIdsByDaemon.flat()).slice(0, limit * 3);
    const requests = await Promise.all(
      requestIds.map((requestId) =>
        this.readJson<RelayApprovalRequestRecord>(this.approvalKey(requestId)),
      ),
    );

    return requests
      .filter((request): request is RelayApprovalRequestRecord => Boolean(request))
      .filter((request) => (filters.daemonId ? request.daemonId === filters.daemonId : true))
      .filter((request) => (filters.status ? request.status === filters.status : true))
      .filter((request) => matchesOptionalFilter(request.destination, filters.destination))
      .filter((request) => matchesOptionalFilter(request.tokenAddress, filters.tokenAddress))
      .sort((left, right) => Date.parse(right.requestedAt) - Date.parse(left.requestedAt))
      .slice(0, limit);
  }

  async createEncryptedUpdate(
    input: CreateEncryptedUpdateInput,
  ): Promise<RelayEncryptedUpdateRecord> {
    if (input.type === 'manual_approval_decision') {
      if (!input.targetApprovalRequestId) {
        throw new CacheError({
          code: cacheErrorCodes.invalidPayload,
          message: 'Manual approval updates require a target approval request id',
          operation: 'createEncryptedUpdate',
        });
      }

      const approvalKey = this.approvalKey(input.targetApprovalRequestId);
      const approval = await this.readJson<RelayApprovalRequestRecord>(approvalKey);
      if (!approval) {
        throw new CacheError({
          code: cacheErrorCodes.notFound,
          key: approvalKey,
          message: `Unknown approval '${input.targetApprovalRequestId}'`,
          operation: 'createEncryptedUpdate',
        });
      }

      if (approval.daemonId !== input.daemonId) {
        throw new CacheError({
          code: cacheErrorCodes.invalidPayload,
          key: approvalKey,
          message: `Approval '${input.targetApprovalRequestId}' belongs to daemon '${approval.daemonId}', not '${input.daemonId}'`,
          operation: 'createEncryptedUpdate',
        });
      }

      if (approval.status !== 'pending') {
        throw new CacheError({
          code: cacheErrorCodes.invalidPayload,
          key: approvalKey,
          message: `Approval '${input.targetApprovalRequestId}' is '${approval.status}' and cannot accept new updates`,
          operation: 'createEncryptedUpdate',
        });
      }
    }

    const updateId = input.updateId ?? randomUUID();
    const now = toIsoTimestamp();
    const record: RelayEncryptedUpdateRecord = {
      createdAt: now,
      daemonId: input.daemonId,
      metadata: input.metadata,
      payload: input.payload,
      status: 'pending',
      targetApprovalRequestId: input.targetApprovalRequestId,
      type: input.type,
      updateId,
      updatedAt: now,
    };

    const activeApprovalKey =
      input.type === 'manual_approval_decision' && input.targetApprovalRequestId
        ? this.activeApprovalUpdateKey(input.targetApprovalRequestId)
        : null;
    const updateKey = this.updateKey(updateId);
    let ownsActiveApprovalSlot = false;

    await this.writeJson(updateKey, record);

    try {
      if (activeApprovalKey) {
        const reserved = await this.client.set(activeApprovalKey, updateId, 'NX');
        if (reserved !== 'OK') {
          const existingUpdateId = await this.client.get(activeApprovalKey);
          const existingRecord = existingUpdateId
            ? await this.readJson<RelayEncryptedUpdateRecord>(this.updateKey(existingUpdateId))
            : null;

          if (isActiveApprovalUpdateRecord(existingRecord, input.targetApprovalRequestId!)) {
            throw new CacheError({
              code: cacheErrorCodes.invalidPayload,
              key: activeApprovalKey,
              message: `Approval '${input.targetApprovalRequestId}' already has a queued operator update`,
              operation: 'createEncryptedUpdate',
            });
          }

          await this.client.del(activeApprovalKey);
          const retriedReservation = await this.client.set(activeApprovalKey, updateId, 'NX');
          if (retriedReservation !== 'OK') {
            throw new CacheError({
              code: cacheErrorCodes.invalidPayload,
              key: activeApprovalKey,
              message: `Approval '${input.targetApprovalRequestId}' already has a queued operator update`,
              operation: 'createEncryptedUpdate',
            });
          }
        }

        ownsActiveApprovalSlot = true;
      }

      await this.client.zadd(this.daemonUpdatesKey(input.daemonId), Date.now(), updateId);
    } catch (error) {
      await this.client.del(updateKey);
      if (activeApprovalKey && ownsActiveApprovalSlot) {
        await this.client.del(activeApprovalKey);
      }
      throw error;
    }

    return record;
  }

  async hasActiveApprovalUpdate(daemonId: string, approvalRequestId: string): Promise<boolean> {
    const indexedUpdateId = await this.client.get(this.activeApprovalUpdateKey(approvalRequestId));
    if (indexedUpdateId) {
      const indexedRecord = await this.readJson<RelayEncryptedUpdateRecord>(
        this.updateKey(indexedUpdateId),
      );
      if (isActiveApprovalUpdateRecord(indexedRecord, approvalRequestId)) {
        return true;
      }

      await this.client.del(this.activeApprovalUpdateKey(approvalRequestId));
    }

    const updateIds = await this.client.zrange(this.daemonUpdatesKey(daemonId), 0, -1, 'REV');

    for (const updateId of updateIds) {
      const record = await this.readJson<RelayEncryptedUpdateRecord>(this.updateKey(updateId));
      if (isActiveApprovalUpdateRecord(record, approvalRequestId)) {
        await this.client.set(this.activeApprovalUpdateKey(approvalRequestId), updateId, 'NX');
        return true;
      }
    }

    return false;
  }

  async consumeApprovalCapability(
    approvalRequestId: string,
    capabilityHash: string,
  ): Promise<boolean> {
    try {
      const result = await this.client.set(
        this.approvalCapabilityConsumedKey(approvalRequestId, capabilityHash),
        toIsoTimestamp(),
        'NX',
      );
      return result === 'OK';
    } catch (error) {
      throw toCacheError(error, {
        key: this.approvalCapabilityConsumedKey(approvalRequestId, capabilityHash),
        operation: 'consumeApprovalCapability',
      });
    }
  }

  async releaseApprovalCapabilityConsumption(
    approvalRequestId: string,
    capabilityHash: string,
  ): Promise<void> {
    try {
      await this.client.del(this.approvalCapabilityConsumedKey(approvalRequestId, capabilityHash));
    } catch (error) {
      throw toCacheError(error, {
        key: this.approvalCapabilityConsumedKey(approvalRequestId, capabilityHash),
        operation: 'releaseApprovalCapabilityConsumption',
      });
    }
  }

  async clearApprovalCapabilityFailures(approvalRequestId: string): Promise<void> {
    try {
      await this.client.del(this.approvalCapabilityFailuresKey(approvalRequestId));
    } catch (error) {
      throw toCacheError(error, {
        key: this.approvalCapabilityFailuresKey(approvalRequestId),
        operation: 'clearApprovalCapabilityFailures',
      });
    }
  }

  async recordApprovalCapabilityFailure(
    approvalRequestId: string,
  ): Promise<RecordApprovalCapabilityFailureResult> {
    const key = this.approvalCapabilityFailuresKey(approvalRequestId);
    const now = new Date();
    const nowMs = now.getTime();
    const existing = await this.readJson<ApprovalCapabilityFailureRecord>(key);

    if (existing?.blockedUntil && Date.parse(existing.blockedUntil) > nowMs) {
      return {
        attempts: existing.attempts,
        blocked: true,
        blockedUntil: existing.blockedUntil,
      };
    }

    const firstFailedAtMs = existing?.firstFailedAt
      ? Date.parse(existing.firstFailedAt)
      : Number.NaN;
    const withinWindow =
      Number.isFinite(firstFailedAtMs) &&
      nowMs - firstFailedAtMs <= approvalCapabilityFailureWindowMs;
    const attempts = withinWindow && existing ? existing.attempts + 1 : 1;
    const firstFailedAt = withinWindow && existing ? existing.firstFailedAt : now.toISOString();
    const blockedUntil =
      attempts >= approvalCapabilityMaxFailures
        ? new Date(nowMs + approvalCapabilityBlockWindowMs).toISOString()
        : undefined;

    await this.writeJson(key, {
      attempts,
      blockedUntil,
      firstFailedAt,
      lastFailedAt: now.toISOString(),
    } satisfies ApprovalCapabilityFailureRecord);

    return {
      attempts,
      blocked: blockedUntil !== undefined,
      blockedUntil: blockedUntil ?? null,
    };
  }

  async rotateApprovalCapability(approvalRequestId: string): Promise<RelayApprovalRequestRecord> {
    const key = this.approvalKey(approvalRequestId);
    const approval = await this.readJson<RelayApprovalRequestRecord>(key);

    if (!approval) {
      throw new CacheError({
        code: cacheErrorCodes.notFound,
        key,
        message: `Unknown approval '${approvalRequestId}'`,
        operation: 'rotateApprovalCapability',
      });
    }

    if (approval.status !== 'pending') {
      throw new CacheError({
        code: cacheErrorCodes.invalidPayload,
        key,
        message: `Approval '${approvalRequestId}' is '${approval.status}' and cannot accept a new secure approval link`,
        operation: 'rotateApprovalCapability',
      });
    }

    const capabilityToken = createApprovalCapabilityToken();
    const nextRecord: RelayApprovalRequestRecord = {
      ...approval,
      metadata: {
        ...(approval.metadata ?? {}),
        approvalCapabilityHash: approvalCapabilityHash(capabilityToken),
        approvalCapabilityToken: capabilityToken,
      },
      updatedAt: toIsoTimestamp(),
    };

    await this.writeJson(key, nextRecord);
    await this.clearApprovalCapabilityFailures(approvalRequestId);

    return nextRecord;
  }

  async claimEncryptedUpdates(
    input: ClaimEncryptedUpdatesInput,
  ): Promise<RelayEncryptedUpdateRecord[]> {
    const limit = clampLimit(input.limit, 25, 100);
    const leaseSeconds = clampLimit(input.leaseSeconds, 30, 300);
    const now = new Date();
    const nowMs = now.getTime();
    const claimUntil = new Date(nowMs + leaseSeconds * 1000).toISOString();
    const updateIds = await this.client.zrange(
      this.daemonUpdatesKey(input.daemonId),
      0,
      limit * 4,
      'REV',
    );
    const claimed: RelayEncryptedUpdateRecord[] = [];

    for (const updateId of updateIds) {
      if (claimed.length >= limit) {
        break;
      }

      const claimLockKey = this.updateClaimLockKey(updateId);
      let ownsClaimLock = false;

      try {
        const reserved = await this.client.set(claimLockKey, claimUntil, 'NX');
        if (reserved !== 'OK') {
          const existingClaimLockUntil = await this.client.get(claimLockKey);
          if (
            existingClaimLockUntil &&
            Number.isFinite(Date.parse(existingClaimLockUntil)) &&
            Date.parse(existingClaimLockUntil) > nowMs
          ) {
            continue;
          }

          await this.client.del(claimLockKey);
          const retriedReservation = await this.client.set(claimLockKey, claimUntil, 'NX');
          if (retriedReservation !== 'OK') {
            continue;
          }
        }

        ownsClaimLock = true;

        const record = await this.readJson<RelayEncryptedUpdateRecord>(this.updateKey(updateId));
        if (!record) {
          continue;
        }

        if (
          record.status === 'applied' ||
          record.status === 'failed' ||
          record.status === 'rejected'
        ) {
          continue;
        }

        if (
          record.status === 'inflight' &&
          record.claimUntil &&
          Date.parse(record.claimUntil) > nowMs
        ) {
          continue;
        }

        const nextRecord: RelayEncryptedUpdateRecord = {
          ...record,
          claimToken: randomUUID(),
          claimUntil,
          lastDeliveredAt: now.toISOString(),
          status: 'inflight',
          updatedAt: now.toISOString(),
        };
        await this.writeJson(this.updateKey(updateId), nextRecord);
        claimed.push(nextRecord);
      } finally {
        if (ownsClaimLock) {
          await this.client.del(claimLockKey);
        }
      }
    }

    return claimed;
  }

  async submitUpdateFeedback(
    input: SubmitUpdateFeedbackInput,
  ): Promise<RelayEncryptedUpdateRecord> {
    const key = this.updateKey(input.updateId);
    const record = await this.readJson<RelayEncryptedUpdateRecord>(key);
    const nowMs = Date.now();

    if (!record || record.daemonId !== input.daemonId) {
      throw new CacheError({
        code: cacheErrorCodes.notFound,
        key,
        message: `Unknown update '${input.updateId}' for daemon '${input.daemonId}'`,
        operation: 'submitUpdateFeedback',
      });
    }

    if (record.status !== 'inflight') {
      throw new CacheError({
        code: cacheErrorCodes.invalidPayload,
        key,
        message: `Update '${input.updateId}' is '${record.status}' and is not currently claimed`,
        operation: 'submitUpdateFeedback',
      });
    }

    const claimUntilMs = record.claimUntil ? Date.parse(record.claimUntil) : Number.NaN;
    if (!Number.isFinite(claimUntilMs) || claimUntilMs <= nowMs) {
      throw new CacheError({
        code: cacheErrorCodes.invalidPayload,
        key,
        message: `Claim for update '${input.updateId}' has expired`,
        operation: 'submitUpdateFeedback',
      });
    }

    if (!record.claimToken || record.claimToken !== input.claimToken) {
      throw new CacheError({
        code: cacheErrorCodes.invalidPayload,
        key,
        message: `Claim token mismatch for update '${input.updateId}'`,
        operation: 'submitUpdateFeedback',
      });
    }

    const feedback: RelayUpdateFeedbackRecord = {
      daemonId: input.daemonId,
      details: input.details,
      feedbackAt: toIsoTimestamp(),
      message: input.message,
      status: input.status,
      updateId: input.updateId,
    };
    const nextRecord: RelayEncryptedUpdateRecord = {
      ...record,
      claimToken: undefined,
      claimUntil: undefined,
      feedback,
      status: input.status,
      updatedAt: toIsoTimestamp(),
    };

    await this.writeJson(key, nextRecord);
    if (record.targetApprovalRequestId && record.type === 'manual_approval_decision') {
      const activeApprovalKey = this.activeApprovalUpdateKey(record.targetApprovalRequestId);
      const indexedUpdateId = await this.client.get(activeApprovalKey);
      if (indexedUpdateId === input.updateId) {
        await this.client.del(activeApprovalKey);
      }
    }
    return nextRecord;
  }

  async getEncryptedUpdate(updateId: string): Promise<RelayEncryptedUpdateRecord | null> {
    return await this.readJson<RelayEncryptedUpdateRecord>(this.updateKey(updateId));
  }

  async removeEncryptedUpdate(daemonId: string, updateId: string): Promise<void> {
    const key = this.updateKey(updateId);
    const record = await this.readJson<RelayEncryptedUpdateRecord>(key);
    if (!record || record.daemonId !== daemonId) {
      throw new CacheError({
        code: cacheErrorCodes.notFound,
        key,
        message: `Unknown update '${updateId}' for daemon '${daemonId}'`,
        operation: 'removeEncryptedUpdate',
      });
    }

    await this.client.zrem(this.daemonUpdatesKey(daemonId), updateId);
    await this.client.del(key);
    if (record.targetApprovalRequestId && record.type === 'manual_approval_decision') {
      const activeApprovalKey = this.activeApprovalUpdateKey(record.targetApprovalRequestId);
      const indexedUpdateId = await this.client.get(activeApprovalKey);
      if (indexedUpdateId === updateId) {
        await this.client.del(activeApprovalKey);
      }
    }
  }

  private readonly daemonIndexKey = (): string => `${this.namespace}:daemons`;
  private readonly daemonProfileKey = (daemonId: string): string =>
    `${this.namespace}:daemon:${daemonId}:profile`;
  private readonly daemonPoliciesKey = (daemonId: string): string =>
    `${this.namespace}:daemon:${daemonId}:policies`;
  private readonly daemonAgentKeysKey = (daemonId: string): string =>
    `${this.namespace}:daemon:${daemonId}:agent-keys`;
  private readonly daemonApprovalsKey = (daemonId: string): string =>
    `${this.namespace}:daemon:${daemonId}:approvals`;
  private readonly daemonUpdatesKey = (daemonId: string): string =>
    `${this.namespace}:daemon:${daemonId}:updates`;
  private readonly approvalKey = (approvalRequestId: string): string =>
    `${this.namespace}:approval:${approvalRequestId}`;
  private readonly approvalCapabilityConsumedKey = (
    approvalRequestId: string,
    capabilityHash: string,
  ): string =>
    `${this.namespace}:approval:${approvalRequestId}:capability:${capabilityHash}:consumed`;
  private readonly approvalCapabilityFailuresKey = (approvalRequestId: string): string =>
    `${this.namespace}:approval:${approvalRequestId}:capability-failures`;
  private readonly activeApprovalUpdateKey = (approvalRequestId: string): string =>
    `${this.namespace}:approval:${approvalRequestId}:active-update`;
  private readonly updateClaimLockKey = (updateId: string): string =>
    `${this.namespace}:update:${updateId}:claim-lock`;
  private readonly updateKey = (updateId: string): string => `${this.namespace}:update:${updateId}`;

  private async readJson<T>(key: string): Promise<T | null> {
    try {
      const payload = await this.client.get(key);
      if (payload === null) {
        return null;
      }

      return JSON.parse(payload) as T;
    } catch (error) {
      throw toCacheError(error, { key, operation: 'readJson' });
    }
  }

  private async writeJson(key: string, value: unknown): Promise<void> {
    try {
      await this.client.set(key, JSON.stringify(value));
    } catch (error) {
      throw toCacheError(error, { key, operation: 'writeJson' });
    }
  }
}

export const createRelayCacheService = (options: { client?: Redis; namespace?: string } = {}) => {
  return new RelayCacheService(options);
};
