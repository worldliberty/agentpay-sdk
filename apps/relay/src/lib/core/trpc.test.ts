import { CacheError, cacheErrorCodes } from '@worldlibertyfinancial/agent-cache/errors';
import { describe, expect, it, vi } from 'vitest';

const daemonId = '11'.repeat(32);
const daemonToken = 'relay-daemon-token-1234567890abcd';

async function loadAdminCaller(headerValue?: string) {
  process.env.RELAY_ADMIN_TOKEN = 'relay-admin-token-1234567890abcd';
  process.env.RELAY_BASE_URL = 'https://relay.example';
  process.env.RELAY_DAEMON_TOKEN = daemonToken;
  vi.resetModules();

  const { env } = await import('@/env');
  const { router } = await import('@/routers');
  const cache = {
    createEncryptedUpdate: vi.fn(),
    listApprovalRequests: vi.fn().mockResolvedValue([]),
    listDaemons: vi.fn().mockResolvedValue([]),
  };

  const caller = router.createCaller({
    cache: cache as never,
    env,
    hono: {
      req: {
        header(name: string) {
          if (name === 'authorization') {
            return headerValue;
          }
          return undefined;
        },
      },
    } as never,
  });

  return { cache, caller };
}

async function loadDaemonCaller(headerValue?: string) {
  process.env.RELAY_ADMIN_TOKEN = 'relay-admin-token-1234567890abcd';
  process.env.RELAY_BASE_URL = 'https://relay.example';
  process.env.RELAY_DAEMON_TOKEN = daemonToken;
  vi.resetModules();

  const { env } = await import('@/env');
  const { router } = await import('@/routers');
  const cache = {
    claimEncryptedUpdates: vi.fn().mockResolvedValue([]),
  };

  const caller = router.createCaller({
    cache: cache as never,
    env,
    hono: {
      req: {
        header(name: string) {
          if (name === 'x-relay-daemon-token') {
            return headerValue;
          }
          return undefined;
        },
      },
    } as never,
  });

  return { cache, caller };
}

describe('daemonProcedure auth', () => {
  it('rejects daemon tRPC procedures without daemon auth', async () => {
    const { cache, caller } = await loadDaemonCaller();

    await expect(
      caller.daemon.pollUpdates({
        daemonId,
        leaseSeconds: 30,
        limit: 1,
      }),
    ).rejects.toMatchObject({
      code: 'UNAUTHORIZED',
      message: 'Daemon token is required',
    });
    expect(cache.claimEncryptedUpdates).not.toHaveBeenCalled();
  });

  it('allows daemon tRPC procedures with daemon auth', async () => {
    const { cache, caller } = await loadDaemonCaller(daemonToken);

    await expect(
      caller.daemon.pollUpdates({
        daemonId,
        leaseSeconds: 30,
        limit: 1,
      }),
    ).resolves.toEqual({
      items: [],
      polledAt: expect.any(String),
    });
    expect(cache.claimEncryptedUpdates).toHaveBeenCalledWith({
      daemonId,
      leaseSeconds: 30,
      limit: 1,
    });
  });
});

describe('adminProcedure error mapping', () => {
  it('rejects manual approval updates without a target approval request id before hitting cache', async () => {
    const { cache, caller } = await loadAdminCaller('Bearer relay-admin-token-1234567890abcd');

    await expect(
      caller.admin.submitEncryptedUpdate({
        daemonId,
        payload: {
          algorithm: 'x25519-xchacha20poly1305-v1',
          ciphertextBase64: 'aa',
          encapsulatedKeyBase64: 'bb',
          nonceBase64: 'cc',
          schemaVersion: 1,
        },
        type: 'manual_approval_decision',
      }),
    ).rejects.toMatchObject({
      code: 'BAD_REQUEST',
      message: expect.stringContaining('targetApprovalRequestId'),
    });

    expect(cache.createEncryptedUpdate).not.toHaveBeenCalled();
  });

  it('maps duplicate encrypted update conflicts to TRPC CONFLICT', async () => {
    const { cache, caller } = await loadAdminCaller('Bearer relay-admin-token-1234567890abcd');

    cache.createEncryptedUpdate.mockRejectedValue(
      new CacheError({
        code: cacheErrorCodes.invalidPayload,
        message:
          "Approval 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' already has a queued operator update",
        operation: 'createEncryptedUpdate',
      }),
    );

    await expect(
      caller.admin.submitEncryptedUpdate({
        daemonId,
        payload: {
          algorithm: 'x25519-xchacha20poly1305-v1',
          ciphertextBase64: 'aa',
          encapsulatedKeyBase64: 'bb',
          nonceBase64: 'cc',
          schemaVersion: 1,
        },
        targetApprovalRequestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        type: 'manual_approval_decision',
      }),
    ).rejects.toMatchObject({
      code: 'CONFLICT',
      message:
        "Approval 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' already has a queued operator update",
    });
  });

  it('maps unknown manual approval targets to TRPC NOT_FOUND', async () => {
    const { cache, caller } = await loadAdminCaller('Bearer relay-admin-token-1234567890abcd');

    cache.createEncryptedUpdate.mockRejectedValue(
      new CacheError({
        code: cacheErrorCodes.notFound,
        message: "Unknown approval 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'",
        operation: 'createEncryptedUpdate',
      }),
    );

    await expect(
      caller.admin.submitEncryptedUpdate({
        daemonId,
        payload: {
          algorithm: 'x25519-xchacha20poly1305-v1',
          ciphertextBase64: 'aa',
          encapsulatedKeyBase64: 'bb',
          nonceBase64: 'cc',
          schemaVersion: 1,
        },
        targetApprovalRequestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        type: 'manual_approval_decision',
      }),
    ).rejects.toMatchObject({
      code: 'NOT_FOUND',
      message: "Unknown approval 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'",
    });
  });

  it('maps malformed encrypted update payloads to TRPC BAD_REQUEST', async () => {
    const { cache, caller } = await loadAdminCaller('Bearer relay-admin-token-1234567890abcd');

    cache.createEncryptedUpdate.mockRejectedValue(
      new CacheError({
        code: cacheErrorCodes.invalidPayload,
        message: 'Manual approval updates require a target approval request id',
        operation: 'createEncryptedUpdate',
      }),
    );

    await expect(
      caller.admin.submitEncryptedUpdate({
        daemonId,
        payload: {
          algorithm: 'x25519-xchacha20poly1305-v1',
          ciphertextBase64: 'aa',
          encapsulatedKeyBase64: 'bb',
          nonceBase64: 'cc',
          schemaVersion: 1,
        },
        type: 'operator_note_refresh',
      }),
    ).rejects.toMatchObject({
      code: 'BAD_REQUEST',
      message: 'Manual approval updates require a target approval request id',
    });
  });
});
