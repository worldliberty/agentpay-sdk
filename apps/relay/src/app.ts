import { createHash, timingSafeEqual } from 'node:crypto';
import { getConnInfo } from '@hono/node-server/conninfo';
import { trpcServer } from '@hono/trpc-server';
import {
  RelayCacheService,
  type RelayEncryptedUpdateRecord,
  type RotatedApprovalCapability,
} from '@worldlibertyfinancial/agent-cache/service';
import { type Context, Hono } from 'hono';
import { cors } from 'hono/cors';
import { z } from 'zod';
import { env } from '@/env';
import { hasAdminAccess, hasDaemonAccess } from '@/lib/auth';
import { mapCacheError } from '@/lib/cache-errors';
import { createContext, type RelayBindings } from '@/lib/core/create-context';
import { log } from '@/lib/logger';
import {
  daemonRegisterInputSchema,
  pollUpdatesInputSchema,
  submitFeedbackInputSchema,
  submitPublicApprovalUpdateInputSchema,
} from '@/lib/schemas';
import { router } from '@/routers';

const createCorsOrigins = (): string[] | '*' => {
  // env.ts refuses to start a production relay without explicit origins, so the
  // wildcard fallback is only reachable in development and test.
  return env.RELAY_ALLOWED_ORIGINS.length > 0 ? env.RELAY_ALLOWED_ORIGINS : '*';
};

const mapApprovalRecord = (record: {
  approvalRequestId: string;
  daemonId: string;
  agentKeyId?: string;
  status: string;
  reason?: string;
  transactionType: string;
  chainId?: number;
  destination: string;
  tokenAddress?: string;
  amountWei?: string;
  requestedAt: string;
  updatedAt: string;
}) => ({
  approvalId: record.approvalRequestId,
  daemonId: record.daemonId,
  agentKeyId: record.agentKeyId ?? 'unknown',
  status: record.status,
  reason: record.reason ?? '',
  actionType: record.transactionType,
  chainId: record.chainId ?? 0,
  recipient: record.destination,
  asset: record.tokenAddress ? `erc20:${record.tokenAddress}` : 'native_eth',
  amountWei: record.amountWei ?? '0',
  createdAt: record.requestedAt,
  updatedAt: record.updatedAt,
});

const readJson = async <T>(request: Request, schema: z.ZodType<T>): Promise<T> => {
  const json = await request.json();
  return schema.parse(json);
};

const badRequest = (c: Context<RelayBindings>, error: unknown) => {
  if (error instanceof z.ZodError) {
    log.warn('request.invalid', { issues: error.issues });
    return c.json({ error: 'Invalid request payload', issues: error.issues }, 400);
  }

  const mapped = mapCacheError(error);
  if (mapped) {
    if (mapped.status === 503) {
      log.error('cache.request_failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        path: c.req.path,
      });
    }
    return c.json({ error: mapped.message }, mapped.status);
  }

  if (error instanceof SyntaxError) {
    return c.json({ error: 'Invalid request payload' }, 400);
  }

  // Unexpected failures never echo internal error text back to the caller.
  log.error('request.failed', {
    error: error instanceof Error ? error.message : 'Unknown error',
    path: c.req.path,
  });
  return c.json({ error: 'Internal relay error' }, 500);
};

const notFound = (c: Context<RelayBindings>, message: string) => c.json({ error: message }, 404);

const conflict = (c: Context<RelayBindings>, message: string) => c.json({ error: message }, 409);

const unauthorized = (c: Context<RelayBindings>, message: string) =>
  c.json({ error: message }, 401);

const tooManyRequests = (c: Context<RelayBindings>, message: string) =>
  c.json({ error: message }, 429);

const applySensitiveNoStoreHeaders = (c: Context<RelayBindings>): void => {
  c.header('Cache-Control', 'private, no-store, max-age=0');
  c.header('Pragma', 'no-cache');
  c.header('Expires', '0');
};

const adminApprovalFrontendBaseUrl = (): string | null => {
  const candidate = env.RELAY_FRONTEND_BASE_URL?.trim() || env.RELAY_BASE_URL.trim();
  return candidate ? candidate.replace(/\/$/u, '') : null;
};

/**
 * Builds the secure approval deep link in the same shape the daemon emits:
 * capability, daemon id and daemon X25519 key travel in the URL fragment so
 * they never reach the frontend host or its access logs, and the approval page
 * can refuse to encrypt when the relay-advertised key differs from `daemonKey`.
 */
const buildSecureApprovalUrl = (input: {
  approvalCapability: string;
  approvalRequestId: string;
  daemonId: string;
  daemonPublicKey: string;
}): string | null => {
  const baseUrl = adminApprovalFrontendBaseUrl();
  if (!baseUrl) {
    return null;
  }

  const fragment = new URLSearchParams({
    approvalCapability: input.approvalCapability,
    daemonId: input.daemonId,
    daemonKey: input.daemonPublicKey,
  });
  return `${baseUrl}/approvals/${encodeURIComponent(input.approvalRequestId)}#${fragment.toString()}`;
};

/**
 * Identifies the submitting client for secure-link throttling. A proxy header
 * is only honoured when the operator names it in RELAY_CLIENT_IP_HEADER;
 * otherwise the socket address is used. Returns undefined when neither is
 * available so an unknown client never shares a global lockout bucket.
 */
const resolveClientAddress = (c: Context<RelayBindings>): string | undefined => {
  if (env.RELAY_CLIENT_IP_HEADER) {
    const forwarded = c.req.header(env.RELAY_CLIENT_IP_HEADER)?.split(',')[0]?.trim();
    return forwarded ? forwarded : undefined;
  }

  try {
    return getConnInfo(c).remote.address ?? undefined;
  } catch {
    return undefined;
  }
};

const INVALID_SECURE_LINK_MESSAGE = 'A valid secure approval link is required';
const LOCKED_SECURE_LINK_MESSAGE =
  'Secure approval link submissions are temporarily locked after repeated invalid attempts';

const sha256Hex = (value: string): string => createHash('sha256').update(value).digest('hex');

const constantTimeEquals = (expected: string, actual: string): boolean => {
  const expectedBuffer = Buffer.from(expected, 'utf8');
  const actualBuffer = Buffer.from(actual, 'utf8');
  if (expectedBuffer.length !== actualBuffer.length) {
    return false;
  }

  return timingSafeEqual(expectedBuffer, actualBuffer);
};

const requireDaemonAccess = (c: Context<RelayBindings>) => {
  if (hasDaemonAccess(c.req.header('x-relay-daemon-token'))) {
    return null;
  }

  return unauthorized(c, 'Daemon token is required');
};

export const createApp = (
  cacheService = new RelayCacheService({ namespace: env.RELAY_CACHE_NAMESPACE }),
) => {
  const app = new Hono<RelayBindings>();

  app.use('*', async (c, next) => {
    c.set('relayCacheService', cacheService);
    const startedAt = Date.now();
    await next();
    log.info('request.completed', {
      durationMs: Date.now() - startedAt,
      method: c.req.method,
      path: c.req.path,
      status: c.res.status,
    });
  });

  app.use(
    '/trpc/*',
    cors({
      allowHeaders: ['authorization', 'content-type', 'x-relay-daemon-token'],
      allowMethods: ['GET', 'HEAD', 'OPTIONS', 'POST'],
      credentials: true,
      origin: createCorsOrigins(),
    }),
  );

  app.use(
    '/v1/*',
    cors({
      allowHeaders: ['authorization', 'content-type', 'x-relay-daemon-token'],
      allowMethods: ['GET', 'HEAD', 'OPTIONS', 'POST'],
      credentials: true,
      origin: createCorsOrigins(),
    }),
  );

  app.use('/v1/*', async (c, next) => {
    await next();
    applySensitiveNoStoreHeaders(c);
  });

  app.get('/healthz', (c) => {
    return c.json({ ok: true, service: 'agentpay-relay' });
  });

  app.post('/v1/daemon/register', async (c) => {
    const daemonAccessError = requireDaemonAccess(c);
    if (daemonAccessError) {
      return daemonAccessError;
    }

    try {
      const input = await readJson(c.req.raw, daemonRegisterInputSchema);
      const daemonId = input.daemon.daemonId;
      // A re-registration that changes the pinned daemon key fails with a cache
      // conflict (409); rotation is only possible through admin.rekeyDaemon.
      const result = await cacheService.syncDaemonRegistration({
        ...input,
        agentKeys: input.agentKeys.map((agentKey) => ({ ...agentKey, daemonId })),
        approvalRequests: input.approvalRequests.map((request) => ({ ...request, daemonId })),
        policies: input.policies.map((policy) => ({ ...policy, daemonId })),
      });
      return c.json({
        daemonId,
        registeredAt: input.daemon.registeredAt,
        summary: result,
      });
    } catch (error) {
      return badRequest(c, error);
    }
  });

  app.post('/v1/daemon/poll-updates', async (c) => {
    const daemonAccessError = requireDaemonAccess(c);
    if (daemonAccessError) {
      return daemonAccessError;
    }

    try {
      const input = await readJson(c.req.raw, pollUpdatesInputSchema);
      const updates = await cacheService.claimEncryptedUpdates({
        daemonId: input.daemonId,
        leaseSeconds: input.leaseSeconds ?? env.RELAY_UPDATE_LEASE_SECONDS,
        limit: input.limit ?? env.RELAY_POLL_MAX_UPDATES,
      });
      return c.json({
        items: updates,
        polledAt: new Date().toISOString(),
      });
    } catch (error) {
      return badRequest(c, error);
    }
  });

  app.post('/v1/daemon/submit-feedback', async (c) => {
    const daemonAccessError = requireDaemonAccess(c);
    if (daemonAccessError) {
      return daemonAccessError;
    }

    try {
      const input = await readJson(c.req.raw, submitFeedbackInputSchema);
      const update = await cacheService.submitUpdateFeedback(input);
      return c.json({
        status: update.status,
        updateId: update.updateId,
        updatedAt: update.updatedAt,
      });
    } catch (error) {
      return badRequest(c, error);
    }
  });

  app.get('/v1/daemons/:daemonId', async (c) => {
    const daemonId = c.req.param('daemonId');
    let daemon: Awaited<ReturnType<RelayCacheService['getDaemonProfile']>>;
    try {
      daemon = await cacheService.getDaemonProfile(daemonId);
    } catch (error) {
      return badRequest(c, error);
    }
    if (!daemon) {
      return notFound(c, 'Unknown daemon');
    }
    return c.json({
      daemonId: daemon.daemonId,
      daemonPublicKey: daemon.daemonPublicKey,
      vaultEthereumAddress: daemon.ethereumAddress,
      relayBaseUrl: daemon.relayUrl ?? env.RELAY_BASE_URL,
      updatedAt: daemon.updatedAt,
    });
  });

  app.get('/v1/daemons/:daemonId/approvals', async (c) => {
    const daemonId = c.req.param('daemonId');
    try {
      const approvals = await cacheService.listApprovalRequests({ daemonId, limit: 200 });
      return c.json(approvals.map(mapApprovalRecord));
    } catch (error) {
      return badRequest(c, error);
    }
  });

  app.get('/v1/approvals/:approvalId', async (c) => {
    const approvalId = c.req.param('approvalId');
    try {
      const approval = await cacheService.getApprovalRequest(approvalId);
      if (!approval) {
        return notFound(c, 'Unknown approval');
      }
      return c.json(mapApprovalRecord(approval));
    } catch (error) {
      return badRequest(c, error);
    }
  });

  app.post('/v1/admin/approvals/:approvalId/secure-link', async (c) => {
    if (!hasAdminAccess(c.req.header('authorization'))) {
      return unauthorized(c, 'Admin token is required');
    }

    const approvalId = c.req.param('approvalId');
    let rotated: RotatedApprovalCapability;
    let daemonPublicKey: string;
    try {
      // Resolve the owning daemon's pinned key before rotating so a link is
      // never invalidated without a usable replacement being returned.
      const existing = await cacheService.getApprovalRequest(approvalId);
      if (!existing) {
        return notFound(c, `Unknown approval '${approvalId}'`);
      }
      const daemon = await cacheService.getDaemonProfile(existing.daemonId);
      if (!daemon) {
        return conflict(
          c,
          `Approval '${approvalId}' belongs to a daemon that is not registered with this relay`,
        );
      }
      daemonPublicKey = daemon.daemonPublicKey;
      rotated = await cacheService.rotateApprovalCapability(approvalId);
    } catch (error) {
      return badRequest(c, error);
    }

    const approvalUrl = buildSecureApprovalUrl({
      approvalCapability: rotated.approvalCapability,
      approvalRequestId: approvalId,
      daemonId: rotated.approval.daemonId,
      daemonPublicKey,
    });
    if (!approvalUrl) {
      return conflict(
        c,
        `Approval '${approvalId}' does not have a reissuable secure approval link`,
      );
    }

    // The plaintext capability exists only in this response; the relay keeps
    // nothing but its hash.
    return c.json({
      approvalCapability: rotated.approvalCapability,
      approvalId,
      approvalUrl,
      daemonId: rotated.approval.daemonId,
      daemonPublicKey,
    });
  });

  app.post('/v1/approvals/:approvalId/updates', async (c) => {
    const approvalId = c.req.param('approvalId');
    try {
      const input = await readJson(c.req.raw, submitPublicApprovalUpdateInputSchema);
      const clientAddress = resolveClientAddress(c);

      // Lockouts are checked before any capability comparison so a locked
      // approval (or client) is refused even when it presents a correct token.
      const blockState = await cacheService.getApprovalCapabilityBlockState(
        approvalId,
        clientAddress,
      );
      if (blockState.blocked) {
        return tooManyRequests(c, LOCKED_SECURE_LINK_MESSAGE);
      }

      const approval = await cacheService.getApprovalRequest(approvalId);
      if (!approval) {
        return notFound(c, `Unknown approval '${approvalId}'`);
      }

      // Records without a hash were never issued a secure link; they fail the
      // same way as a wrong capability.
      const expectedCapabilityHash = approval.metadata?.approvalCapabilityHash?.trim() ?? '';
      const providedCapabilityHash = sha256Hex(input.approvalCapability.trim());
      const capabilityMatches =
        expectedCapabilityHash.length > 0 &&
        constantTimeEquals(expectedCapabilityHash, providedCapabilityHash);

      // A wrong daemon id and a wrong capability get the same uniform 401 so the
      // response never reveals which daemon owns the approval.
      if (!capabilityMatches || approval.daemonId !== input.daemonId) {
        const failure = await cacheService.recordApprovalCapabilityFailure(
          approvalId,
          clientAddress,
        );
        if (failure.blocked) {
          return tooManyRequests(c, LOCKED_SECURE_LINK_MESSAGE);
        }

        return unauthorized(c, INVALID_SECURE_LINK_MESSAGE);
      }

      if (approval.status !== 'pending') {
        return conflict(
          c,
          `Approval '${approvalId}' is '${approval.status}' and cannot accept new updates`,
        );
      }

      await cacheService.clearApprovalCapabilityFailures(approvalId);

      const alreadyQueued = await cacheService.hasActiveApprovalUpdate(input.daemonId, approvalId);
      if (alreadyQueued) {
        return conflict(c, `Approval '${approvalId}' already has a queued operator update`);
      }

      const consumed = await cacheService.consumeApprovalCapability(
        approvalId,
        expectedCapabilityHash,
      );
      if (!consumed) {
        return conflict(
          c,
          `Approval '${approvalId}' secure link was already used; request a fresh approval link before retrying`,
        );
      }

      let update: RelayEncryptedUpdateRecord;
      try {
        update = await cacheService.createEncryptedUpdate({
          daemonId: input.daemonId,
          metadata: {
            source: 'approval_console',
          },
          payload: {
            algorithm: input.envelope.algorithm,
            ciphertextBase64: input.envelope.ciphertext,
            encapsulatedKeyBase64: input.envelope.ephemeralPublicKey,
            nonceBase64: input.envelope.nonce,
            schemaVersion: 1,
          },
          targetApprovalRequestId: approvalId,
          type: 'manual_approval_decision',
        });
      } catch (error) {
        await cacheService.releaseApprovalCapabilityConsumption(approvalId, expectedCapabilityHash);
        throw error;
      }

      return c.json({
        approvalId,
        daemonId: input.daemonId,
        status: update.status,
        updateId: update.updateId,
      });
    } catch (error) {
      return badRequest(c, error);
    }
  });

  app.get('/readyz', async (c) => {
    try {
      await cacheService.ping();
      return c.json({ ok: true, cache: 'ready' });
    } catch (error) {
      log.error('cache.not_ready', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return c.json({ cache: 'unavailable', ok: false }, 503);
    }
  });

  app.use(
    '/trpc/*',
    trpcServer({
      createContext,
      endpoint: '/trpc',
      onError({ error, path }) {
        log.error('trpc.error', {
          code: error.code,
          message: error.message,
          path,
        });
      },
      router,
    }),
  );

  return app;
};

export const app = createApp();
