import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { CacheError } from '../errors/index.js';
import { cacheErrorCodes } from '../errors/index.js';
import { RelayCacheService } from './index.js';

class InMemoryCacheClient {
  private readonly store = new Map<string, string>();
  private readonly sets = new Map<string, Set<string>>();
  private readonly zsets = new Map<string, Array<{ member: string; score: number }>>();

  async del(key: string): Promise<number> {
    const existed = this.store.delete(key);
    this.sets.delete(key);
    this.zsets.delete(key);
    return existed ? 1 : 0;
  }

  async get(key: string): Promise<string | null> {
    return this.store.get(key) ?? null;
  }

  async ping(): Promise<string> {
    return 'PONG';
  }

  async quit(): Promise<string> {
    return 'OK';
  }

  async sadd(key: string, ...members: string[]): Promise<number> {
    const bucket = this.sets.get(key) ?? new Set<string>();
    let added = 0;
    for (const member of members) {
      if (!bucket.has(member)) {
        bucket.add(member);
        added += 1;
      }
    }
    this.sets.set(key, bucket);
    return added;
  }

  async set(key: string, value: string, mode?: 'NX' | 'XX'): Promise<'OK' | null> {
    if (mode === 'NX' && this.store.has(key)) {
      return null;
    }
    if (mode === 'XX' && !this.store.has(key)) {
      return null;
    }
    this.store.set(key, value);
    return 'OK';
  }

  async smembers(key: string): Promise<string[]> {
    return [...(this.sets.get(key) ?? new Set<string>())];
  }

  async zadd(key: string, ...args: (string | number)[]): Promise<number> {
    const bucket = this.zsets.get(key) ?? [];
    for (let index = 0; index < args.length; index += 2) {
      bucket.push({ score: Number(args[index]), member: String(args[index + 1]) });
    }
    this.zsets.set(key, bucket);
    return args.length / 2;
  }

  async zrange(key: string, start: number, stop: number, ...args: string[]): Promise<string[]> {
    const bucket = [...(this.zsets.get(key) ?? [])].sort((left, right) => left.score - right.score);
    const ordered = args.includes('REV') ? bucket.reverse() : bucket;
    const normalizedStop = stop < 0 ? ordered.length + stop : stop;
    return ordered.slice(start, normalizedStop + 1).map((entry) => entry.member);
  }

  async zrem(key: string, ...members: string[]): Promise<number> {
    const bucket = this.zsets.get(key) ?? [];
    const filtered = bucket.filter((entry) => !members.includes(entry.member));
    this.zsets.set(key, filtered);
    return bucket.length - filtered.length;
  }
}

class ClaimRaceCacheClient extends InMemoryCacheClient {
  constructor(private readonly barrierKey: string) {
    super();
  }

  private barrierOpen = false;
  private barrierPromise: Promise<void> | null = null;
  private releaseBarrier: (() => void) | null = null;
  private waitingReaders = 0;

  override async get(key: string): Promise<string | null> {
    const snapshot = await super.get(key);
    if (key !== this.barrierKey || this.barrierOpen) {
      return snapshot;
    }

    this.waitingReaders += 1;
    if (!this.barrierPromise) {
      this.barrierPromise = new Promise<void>((resolve) => {
        this.releaseBarrier = resolve;
      });
      setTimeout(() => {
        if (!this.barrierOpen) {
          this.barrierOpen = true;
          this.releaseBarrier?.();
        }
      }, 0);
    }

    if (this.waitingReaders >= 2 && !this.barrierOpen) {
      this.barrierOpen = true;
      this.releaseBarrier?.();
    }

    await this.barrierPromise;
    return snapshot;
  }
}

class MutableInMemoryCacheClient extends InMemoryCacheClient {
  async forceGet(key: string): Promise<string | null> {
    return await super.get(key);
  }

  async forceSet(key: string, value: string): Promise<void> {
    await super.set(key, value);
  }
}

async function seedPendingApproval(
  service: RelayCacheService,
  daemonId: string,
  approvalRequestId: string,
): Promise<void> {
  await service.syncDaemonRegistration({
    daemon: {
      daemonId,
      daemonPublicKey: 'aa'.repeat(32),
      ethereumAddress: '0x9999999999999999999999999999999999999999',
      lastSeenAt: new Date().toISOString(),
      registeredAt: new Date().toISOString(),
      status: 'active',
      updatedAt: new Date().toISOString(),
    },
    approvalRequests: [
      {
        approvalRequestId,
        daemonId,
        destination: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        requestedAt: new Date().toISOString(),
        status: 'pending',
        transactionType: 'transfer_native',
        updatedAt: new Date().toISOString(),
      },
    ],
  });
}

describe('RelayCacheService approval capability guards', () => {
  it('consumes an approval capability only once', async () => {
    const service = new RelayCacheService({
      client: new InMemoryCacheClient() as never,
      namespace: 'test:relay',
    });

    await expect(service.consumeApprovalCapability('approval-1', 'hash-1')).resolves.toBe(true);
    await expect(service.consumeApprovalCapability('approval-1', 'hash-1')).resolves.toBe(false);
  });

  it('rate limits repeated invalid approval capability attempts', async () => {
    const service = new RelayCacheService({
      client: new InMemoryCacheClient() as never,
      namespace: 'test:relay',
    });

    for (let attempt = 1; attempt < 5; attempt += 1) {
      await expect(service.recordApprovalCapabilityFailure('approval-2')).resolves.toMatchObject({
        attempts: attempt,
        blocked: false,
        blockedUntil: null,
      });
    }

    await expect(service.recordApprovalCapabilityFailure('approval-2')).resolves.toMatchObject({
      attempts: 5,
      blocked: true,
    });
  });

  it('rotates approval capabilities for pending approvals and clears prior failure state', async () => {
    const service = new RelayCacheService({
      client: new InMemoryCacheClient() as never,
      namespace: 'test:relay',
    });

    const daemonId = '11'.repeat(32);
    const originalToken = 'aa'.repeat(32);
    const originalHash = createHash('sha256').update(originalToken).digest('hex');

    await service.syncDaemonRegistration({
      daemon: {
        daemonId,
        daemonPublicKey: '22'.repeat(32),
        ethereumAddress: '0x3333333333333333333333333333333333333333',
        lastSeenAt: new Date().toISOString(),
        registeredAt: new Date().toISOString(),
        status: 'active',
        updatedAt: new Date().toISOString(),
      },
      approvalRequests: [
        {
          approvalRequestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
          daemonId,
          destination: '0x4444444444444444444444444444444444444444',
          metadata: {
            approvalCapabilityHash: originalHash,
            approvalCapabilityToken: originalToken,
            source: 'daemon',
          },
          requestedAt: new Date().toISOString(),
          status: 'pending',
          transactionType: 'transfer_native',
          updatedAt: new Date().toISOString(),
        },
      ],
    });

    for (let attempt = 1; attempt <= 2; attempt += 1) {
      await expect(
        service.recordApprovalCapabilityFailure('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
      ).resolves.toMatchObject({
        attempts: attempt,
        blocked: false,
      });
    }

    const rotated = await service.rotateApprovalCapability('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');

    expect(rotated.metadata?.source).toBe('daemon');
    expect(rotated.metadata?.approvalCapabilityToken).toMatch(/^[a-f0-9]{64}$/u);
    expect(rotated.metadata?.approvalCapabilityToken).not.toBe(originalToken);
    expect(rotated.metadata?.approvalCapabilityHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(rotated.metadata?.approvalCapabilityHash).not.toBe(originalHash);
    expect(rotated.metadata?.approvalCapabilityHash).toBe(
      createHash('sha256')
        .update(rotated.metadata?.approvalCapabilityToken ?? '')
        .digest('hex'),
    );

    await expect(
      service.recordApprovalCapabilityFailure('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),
    ).resolves.toMatchObject({
      attempts: 1,
      blocked: false,
      blockedUntil: null,
    });
  });

  it('issues a secure approval capability for pending approvals that were synced without one', async () => {
    const service = new RelayCacheService({
      client: new InMemoryCacheClient() as never,
      namespace: 'test:relay',
    });

    const daemonId = '55'.repeat(32);

    await service.syncDaemonRegistration({
      daemon: {
        daemonId,
        daemonPublicKey: '66'.repeat(32),
        ethereumAddress: '0x7777777777777777777777777777777777777777',
        lastSeenAt: new Date().toISOString(),
        registeredAt: new Date().toISOString(),
        status: 'active',
        updatedAt: new Date().toISOString(),
      },
      approvalRequests: [
        {
          approvalRequestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
          daemonId,
          destination: '0x8888888888888888888888888888888888888888',
          metadata: {
            source: 'legacy-daemon',
          },
          requestedAt: new Date().toISOString(),
          status: 'pending',
          transactionType: 'transfer_native',
          updatedAt: new Date().toISOString(),
        },
      ],
    });

    const rotated = await service.rotateApprovalCapability('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb');

    expect(rotated.metadata).toMatchObject({
      source: 'legacy-daemon',
    });
    expect(rotated.metadata?.approvalCapabilityToken).toMatch(/^[a-f0-9]{64}$/u);
    expect(rotated.metadata?.approvalCapabilityHash).toBe(
      createHash('sha256')
        .update(rotated.metadata?.approvalCapabilityToken ?? '')
        .digest('hex'),
    );
  });

  it('preserves a rotated approval capability across later daemon syncs', async () => {
    const service = new RelayCacheService({
      client: new InMemoryCacheClient() as never,
      namespace: 'test:relay',
    });

    const daemonId = '12'.repeat(32);
    const originalToken = '34'.repeat(32);
    const originalHash = createHash('sha256').update(originalToken).digest('hex');
    const approvalRequestId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

    await service.syncDaemonRegistration({
      daemon: {
        daemonId,
        daemonPublicKey: '56'.repeat(32),
        ethereumAddress: '0x9999999999999999999999999999999999999999',
        lastSeenAt: new Date().toISOString(),
        registeredAt: new Date().toISOString(),
        status: 'active',
        updatedAt: new Date().toISOString(),
      },
      approvalRequests: [
        {
          approvalRequestId,
          daemonId,
          destination: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          metadata: {
            approvalCapabilityHash: originalHash,
            approvalCapabilityToken: originalToken,
            source: 'daemon',
          },
          requestedAt: new Date().toISOString(),
          status: 'pending',
          transactionType: 'transfer_native',
          updatedAt: new Date().toISOString(),
        },
      ],
    });

    const rotated = await service.rotateApprovalCapability(approvalRequestId);

    await service.syncDaemonRegistration({
      daemon: {
        daemonId,
        daemonPublicKey: '56'.repeat(32),
        ethereumAddress: '0x9999999999999999999999999999999999999999',
        lastSeenAt: new Date().toISOString(),
        registeredAt: new Date().toISOString(),
        status: 'active',
        updatedAt: new Date().toISOString(),
      },
      approvalRequests: [
        {
          approvalRequestId,
          daemonId,
          destination: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          metadata: {
            approvalCapabilityHash: originalHash,
            approvalCapabilityToken: originalToken,
            source: 'daemon',
          },
          requestedAt: new Date().toISOString(),
          status: 'pending',
          transactionType: 'transfer_native',
          updatedAt: new Date().toISOString(),
        },
      ],
    });

    const synced = await service.getApprovalRequest(approvalRequestId);

    expect(synced?.metadata).toMatchObject({
      source: 'daemon',
      approvalCapabilityHash: rotated.metadata?.approvalCapabilityHash,
      approvalCapabilityToken: rotated.metadata?.approvalCapabilityToken,
    });
    expect(synced?.metadata?.approvalCapabilityToken).not.toBe(originalToken);
  });

  it('removes approvals omitted from a later daemon sync snapshot', async () => {
    const client = new MutableInMemoryCacheClient();
    const service = new RelayCacheService({
      client: client as never,
      namespace: 'test:relay',
    });

    const daemonId = '44'.repeat(32);
    const retainedApprovalId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
    const removedApprovalId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
    const activeApprovalKey = `test:relay:approval:${removedApprovalId}:active-update`;
    const failureKey = `test:relay:approval:${removedApprovalId}:capability-failures`;

    await service.syncDaemonRegistration({
      daemon: {
        daemonId,
        daemonPublicKey: '12'.repeat(32),
        ethereumAddress: '0x1212121212121212121212121212121212121212',
        lastSeenAt: new Date().toISOString(),
        registeredAt: new Date().toISOString(),
        status: 'active',
        updatedAt: new Date().toISOString(),
      },
      approvalRequests: [
        {
          approvalRequestId: retainedApprovalId,
          daemonId,
          destination: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          requestedAt: new Date().toISOString(),
          status: 'pending',
          transactionType: 'transfer_native',
          updatedAt: new Date().toISOString(),
        },
        {
          approvalRequestId: removedApprovalId,
          daemonId,
          destination: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
          requestedAt: new Date().toISOString(),
          status: 'pending',
          transactionType: 'transfer_native',
          updatedAt: new Date().toISOString(),
        },
      ],
    });

    await client.forceSet(activeApprovalKey, 'stale-update-id');
    await service.recordApprovalCapabilityFailure(removedApprovalId);

    await service.syncDaemonRegistration({
      daemon: {
        daemonId,
        daemonPublicKey: '12'.repeat(32),
        ethereumAddress: '0x1212121212121212121212121212121212121212',
        lastSeenAt: new Date().toISOString(),
        registeredAt: new Date().toISOString(),
        status: 'active',
        updatedAt: new Date().toISOString(),
      },
      approvalRequests: [
        {
          approvalRequestId: retainedApprovalId,
          daemonId,
          destination: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          requestedAt: new Date().toISOString(),
          status: 'pending',
          transactionType: 'transfer_native',
          updatedAt: new Date().toISOString(),
        },
      ],
    });

    await expect(service.getApprovalRequest(removedApprovalId)).resolves.toBeNull();
    await expect(service.listApprovalRequests({ daemonId })).resolves.toMatchObject([
      {
        approvalRequestId: retainedApprovalId,
      },
    ]);
    await expect(client.forceGet(activeApprovalKey)).resolves.toBeNull();
    await expect(client.forceGet(failureKey)).resolves.toBeNull();
  });

  it('rejects secure approval capability rotation for non-pending approvals', async () => {
    const service = new RelayCacheService({
      client: new InMemoryCacheClient() as never,
      namespace: 'test:relay',
    });

    const daemonId = '99'.repeat(32);

    await service.syncDaemonRegistration({
      daemon: {
        daemonId,
        daemonPublicKey: 'aa'.repeat(32),
        ethereumAddress: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        lastSeenAt: new Date().toISOString(),
        registeredAt: new Date().toISOString(),
        status: 'active',
        updatedAt: new Date().toISOString(),
      },
      approvalRequests: [
        {
          approvalRequestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
          daemonId,
          destination: '0xdddddddddddddddddddddddddddddddddddddddd',
          requestedAt: new Date().toISOString(),
          status: 'completed',
          transactionType: 'transfer_native',
          updatedAt: new Date().toISOString(),
        },
      ],
    });

    await expect(
      service.rotateApprovalCapability('cccccccc-cccc-4ccc-8ccc-cccccccccccc'),
    ).rejects.toThrow(/cannot accept a new secure approval link/);
  });

  it('tracks active manual approval updates beyond the scan window', async () => {
    const service = new RelayCacheService({
      client: new InMemoryCacheClient() as never,
      namespace: 'test:relay',
    });

    const daemonId = 'ab'.repeat(32);
    const approvalRequestId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
    await seedPendingApproval(service, daemonId, approvalRequestId);

    await service.createEncryptedUpdate({
      daemonId,
      metadata: {
        source: 'approval_console',
      },
      payload: {
        algorithm: 'x25519-xchacha20poly1305-v1',
        ciphertextBase64: 'aa',
        encapsulatedKeyBase64: 'bb',
        nonceBase64: 'cc',
        schemaVersion: 1,
      },
      targetApprovalRequestId: approvalRequestId,
      type: 'manual_approval_decision',
    });

    for (let index = 0; index < 300; index += 1) {
      await service.createEncryptedUpdate({
        daemonId,
        metadata: {
          source: 'test-seed',
        },
        payload: {
          algorithm: 'x25519-xchacha20poly1305-v1',
          ciphertextBase64: `seed-${index}`,
          encapsulatedKeyBase64: 'bb',
          nonceBase64: 'cc',
          schemaVersion: 1,
        },
        type: 'daemon_status',
      });
    }

    await expect(service.hasActiveApprovalUpdate(daemonId, approvalRequestId)).resolves.toBe(true);
  });

  it('rejects duplicate manual approval updates until feedback clears the active slot', async () => {
    const service = new RelayCacheService({
      client: new InMemoryCacheClient() as never,
      namespace: 'test:relay',
    });

    const daemonId = 'cd'.repeat(32);
    const approvalRequestId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
    await seedPendingApproval(service, daemonId, approvalRequestId);
    const first = await service.createEncryptedUpdate({
      daemonId,
      metadata: {
        source: 'approval_console',
      },
      payload: {
        algorithm: 'x25519-xchacha20poly1305-v1',
        ciphertextBase64: 'aa',
        encapsulatedKeyBase64: 'bb',
        nonceBase64: 'cc',
        schemaVersion: 1,
      },
      targetApprovalRequestId: approvalRequestId,
      type: 'manual_approval_decision',
    });

    await expect(
      service.createEncryptedUpdate({
        daemonId,
        metadata: {
          source: 'approval_console',
        },
        payload: {
          algorithm: 'x25519-xchacha20poly1305-v1',
          ciphertextBase64: 'dd',
          encapsulatedKeyBase64: 'ee',
          nonceBase64: 'ff',
          schemaVersion: 1,
        },
        targetApprovalRequestId: approvalRequestId,
        type: 'manual_approval_decision',
      }),
    ).rejects.toThrow(/already has a queued operator update/);

    const claimed = (
      await service.claimEncryptedUpdates({
        daemonId,
        leaseSeconds: 30,
        limit: 1,
      })
    )[0];
    if (!claimed) {
      throw new Error('expected a claimed update');
    }

    await expect(
      service.submitUpdateFeedback({
        claimToken: claimed.claimToken ?? '',
        daemonId,
        status: 'applied',
        updateId: first.updateId,
      }),
    ).resolves.toMatchObject({
      status: 'applied',
      updateId: first.updateId,
    });

    await expect(
      service.createEncryptedUpdate({
        daemonId,
        metadata: {
          source: 'approval_console',
        },
        payload: {
          algorithm: 'x25519-xchacha20poly1305-v1',
          ciphertextBase64: '11',
          encapsulatedKeyBase64: '22',
          nonceBase64: '33',
          schemaVersion: 1,
        },
        targetApprovalRequestId: approvalRequestId,
        type: 'manual_approval_decision',
      }),
    ).resolves.toMatchObject({
      daemonId,
      targetApprovalRequestId: approvalRequestId,
      type: 'manual_approval_decision',
    });
  });

  it('rejects manual approval updates once the approval is not pending', async () => {
    const service = new RelayCacheService({
      client: new InMemoryCacheClient() as never,
      namespace: 'test:relay',
    });

    const daemonId = 'de'.repeat(32);
    const approvalRequestId = '12121212-1212-4212-8212-121212121212';

    await service.syncDaemonRegistration({
      daemon: {
        daemonId,
        daemonPublicKey: '34'.repeat(32),
        ethereumAddress: '0x1111111111111111111111111111111111111111',
        lastSeenAt: new Date().toISOString(),
        registeredAt: new Date().toISOString(),
        status: 'active',
        updatedAt: new Date().toISOString(),
      },
      approvalRequests: [
        {
          approvalRequestId,
          daemonId,
          destination: '0x2222222222222222222222222222222222222222',
          requestedAt: new Date().toISOString(),
          status: 'approved',
          transactionType: 'transfer_native',
          updatedAt: new Date().toISOString(),
        },
      ],
    });

    await expect(
      service.createEncryptedUpdate({
        daemonId,
        metadata: {
          source: 'approval_console',
        },
        payload: {
          algorithm: 'x25519-xchacha20poly1305-v1',
          ciphertextBase64: 'aa',
          encapsulatedKeyBase64: 'bb',
          nonceBase64: 'cc',
          schemaVersion: 1,
        },
        targetApprovalRequestId: approvalRequestId,
        type: 'manual_approval_decision',
      }),
    ).rejects.toMatchObject({
      code: cacheErrorCodes.invalidPayload,
      message: `Approval '${approvalRequestId}' is 'approved' and cannot accept new updates`,
    } satisfies Partial<CacheError>);
  });

  it('rejects manual approval updates that target another daemon approval', async () => {
    const service = new RelayCacheService({
      client: new InMemoryCacheClient() as never,
      namespace: 'test:relay',
    });

    const approvalDaemonId = '01'.repeat(32);
    const updateDaemonId = '02'.repeat(32);
    const approvalRequestId = '34343434-3434-4434-8434-343434343434';

    await service.syncDaemonRegistration({
      daemon: {
        daemonId: approvalDaemonId,
        daemonPublicKey: '56'.repeat(32),
        ethereumAddress: '0x3333333333333333333333333333333333333333',
        lastSeenAt: new Date().toISOString(),
        registeredAt: new Date().toISOString(),
        status: 'active',
        updatedAt: new Date().toISOString(),
      },
      approvalRequests: [
        {
          approvalRequestId,
          daemonId: approvalDaemonId,
          destination: '0x4444444444444444444444444444444444444444',
          requestedAt: new Date().toISOString(),
          status: 'pending',
          transactionType: 'transfer_native',
          updatedAt: new Date().toISOString(),
        },
      ],
    });

    await expect(
      service.createEncryptedUpdate({
        daemonId: updateDaemonId,
        metadata: {
          source: 'approval_console',
        },
        payload: {
          algorithm: 'x25519-xchacha20poly1305-v1',
          ciphertextBase64: 'aa',
          encapsulatedKeyBase64: 'bb',
          nonceBase64: 'cc',
          schemaVersion: 1,
        },
        targetApprovalRequestId: approvalRequestId,
        type: 'manual_approval_decision',
      }),
    ).rejects.toMatchObject({
      code: cacheErrorCodes.invalidPayload,
      message: `Approval '${approvalRequestId}' belongs to daemon '${approvalDaemonId}', not '${updateDaemonId}'`,
    } satisfies Partial<CacheError>);
  });

  it('keeps the original active slot intact after rejecting a duplicate manual approval update', async () => {
    const service = new RelayCacheService({
      client: new InMemoryCacheClient() as never,
      namespace: 'test:relay',
    });

    const daemonId = 'ef'.repeat(32);
    const approvalRequestId = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
    await seedPendingApproval(service, daemonId, approvalRequestId);
    const original = await service.createEncryptedUpdate({
      daemonId,
      metadata: {
        source: 'approval_console',
      },
      payload: {
        algorithm: 'x25519-xchacha20poly1305-v1',
        ciphertextBase64: 'aa',
        encapsulatedKeyBase64: 'bb',
        nonceBase64: 'cc',
        schemaVersion: 1,
      },
      targetApprovalRequestId: approvalRequestId,
      type: 'manual_approval_decision',
    });

    await expect(
      service.createEncryptedUpdate({
        daemonId,
        metadata: {
          source: 'approval_console',
        },
        payload: {
          algorithm: 'x25519-xchacha20poly1305-v1',
          ciphertextBase64: 'dd',
          encapsulatedKeyBase64: 'ee',
          nonceBase64: 'ff',
          schemaVersion: 1,
        },
        targetApprovalRequestId: approvalRequestId,
        type: 'manual_approval_decision',
      }),
    ).rejects.toThrow(/already has a queued operator update/);

    await expect(service.hasActiveApprovalUpdate(daemonId, approvalRequestId)).resolves.toBe(true);
    await expect(service.getEncryptedUpdate(original.updateId)).resolves.toMatchObject({
      status: 'pending',
      targetApprovalRequestId: approvalRequestId,
      updateId: original.updateId,
    });
  });

  it('claims each update at most once across concurrent pollers', async () => {
    const daemonId = '98'.repeat(32);
    const updateId = '56565656-5656-4565-8565-565656565656';
    const service = new RelayCacheService({
      client: new ClaimRaceCacheClient(`test:relay:update:${updateId}`) as never,
      namespace: 'test:relay',
    });

    await service.createEncryptedUpdate({
      daemonId,
      metadata: {
        source: 'test-seed',
      },
      payload: {
        algorithm: 'x25519-xchacha20poly1305-v1',
        ciphertextBase64: 'aa',
        encapsulatedKeyBase64: 'bb',
        nonceBase64: 'cc',
        schemaVersion: 1,
      },
      type: 'daemon_status',
      updateId,
    });

    const [firstClaim, secondClaim] = await Promise.all([
      service.claimEncryptedUpdates({
        daemonId,
        leaseSeconds: 30,
        limit: 1,
      }),
      service.claimEncryptedUpdates({
        daemonId,
        leaseSeconds: 30,
        limit: 1,
      }),
    ]);

    expect([...firstClaim, ...secondClaim]).toHaveLength(1);
    await expect(service.getEncryptedUpdate(updateId)).resolves.toMatchObject({
      status: 'inflight',
      updateId,
    });
  });

  it('rejects removing an update through the wrong daemon namespace', async () => {
    const service = new RelayCacheService({
      client: new InMemoryCacheClient() as never,
      namespace: 'test:relay',
    });

    const update = await service.createEncryptedUpdate({
      daemonId: '10'.repeat(32),
      metadata: {
        source: 'test-seed',
      },
      payload: {
        algorithm: 'x25519-xchacha20poly1305-v1',
        ciphertextBase64: 'aa',
        encapsulatedKeyBase64: 'bb',
        nonceBase64: 'cc',
        schemaVersion: 1,
      },
      type: 'daemon_status',
    });

    await expect(
      service.removeEncryptedUpdate('20'.repeat(32), update.updateId),
    ).rejects.toMatchObject({
      code: cacheErrorCodes.notFound,
      message: `Unknown update '${update.updateId}' for daemon '${'20'.repeat(32)}'`,
    } satisfies Partial<CacheError>);
    await expect(service.getEncryptedUpdate(update.updateId)).resolves.toMatchObject({
      daemonId: '10'.repeat(32),
      updateId: update.updateId,
    });
  });

  it('preserves a foreign active slot when feedback completes an older update record', async () => {
    const client = new MutableInMemoryCacheClient();
    const service = new RelayCacheService({
      client: client as never,
      namespace: 'test:relay',
    });

    const daemonId = '77'.repeat(32);
    const approvalRequestId = '78787878-7878-4787-8787-787878787878';
    await seedPendingApproval(service, daemonId, approvalRequestId);

    const update = await service.createEncryptedUpdate({
      daemonId,
      metadata: {
        source: 'approval_console',
      },
      payload: {
        algorithm: 'x25519-xchacha20poly1305-v1',
        ciphertextBase64: 'aa',
        encapsulatedKeyBase64: 'bb',
        nonceBase64: 'cc',
        schemaVersion: 1,
      },
      targetApprovalRequestId: approvalRequestId,
      type: 'manual_approval_decision',
    });

    const claimed = (
      await service.claimEncryptedUpdates({
        daemonId,
        leaseSeconds: 30,
        limit: 1,
      })
    )[0];
    if (!claimed) {
      throw new Error('expected a claimed update');
    }

    const activeApprovalKey = `test:relay:approval:${approvalRequestId}:active-update`;
    await client.forceSet(activeApprovalKey, 'other-update-id');

    await expect(
      service.submitUpdateFeedback({
        claimToken: claimed.claimToken ?? '',
        daemonId,
        status: 'applied',
        updateId: update.updateId,
      }),
    ).resolves.toMatchObject({
      status: 'applied',
      updateId: update.updateId,
    });

    await expect(client.forceGet(activeApprovalKey)).resolves.toBe('other-update-id');
  });

  it('rejects feedback for an expired claim lease even when the claim token still matches', async () => {
    const client = new MutableInMemoryCacheClient();
    const service = new RelayCacheService({
      client: client as never,
      namespace: 'test:relay',
    });

    const daemonId = '66'.repeat(32);
    const update = await service.createEncryptedUpdate({
      daemonId,
      metadata: {
        source: 'test-seed',
      },
      payload: {
        algorithm: 'x25519-xchacha20poly1305-v1',
        ciphertextBase64: 'aa',
        encapsulatedKeyBase64: 'bb',
        nonceBase64: 'cc',
        schemaVersion: 1,
      },
      type: 'daemon_status',
    });

    const claimed = (
      await service.claimEncryptedUpdates({
        daemonId,
        leaseSeconds: 30,
        limit: 1,
      })
    )[0];
    if (!claimed) {
      throw new Error('expected a claimed update');
    }

    await client.forceSet(
      `test:relay:update:${update.updateId}`,
      JSON.stringify({
        ...claimed,
        claimUntil: new Date(Date.now() - 1_000).toISOString(),
      }),
    );

    await expect(
      service.submitUpdateFeedback({
        claimToken: claimed.claimToken ?? '',
        daemonId,
        status: 'applied',
        updateId: update.updateId,
      }),
    ).rejects.toMatchObject({
      code: cacheErrorCodes.invalidPayload,
      message: `Claim for update '${update.updateId}' has expired`,
    });
  });
});
