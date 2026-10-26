import { cacheErrorCodes } from '@worldlibertyfinancial/agent-cache/errors';
import { rethrowCacheErrorAsTrpc } from '@/lib/cache-errors';
import { adminProcedure, TRPCError, t } from '@/lib/core/trpc';
import {
  listApprovalRequestsInputSchema,
  rekeyDaemonInputSchema,
  submitEncryptedUpdateInputSchema,
} from '@/lib/schemas';

/**
 * Approval metadata only ever carries the capability hash, but legacy records
 * may still hold a plaintext token; strip both so admin listings never expose
 * material that could be used to mint or verify a secure approval link.
 */
function sanitizedApprovalMetadata(
  metadata: Record<string, string> | undefined,
): Record<string, string> | undefined {
  if (!metadata) {
    return undefined;
  }

  const { approvalCapabilityHash: _hash, approvalCapabilityToken: _token, ...rest } = metadata;
  return Object.keys(rest).length > 0 ? rest : undefined;
}

function isMalformedEncryptedUpdatePayload(message: string | undefined): boolean {
  if (!message) {
    return false;
  }

  return message.includes('require a target approval request id');
}

export const adminRouter = t.router({
  listApprovalRequests: adminProcedure
    .input(listApprovalRequestsInputSchema.optional())
    .query(async ({ ctx, input }) => {
      const requests = await ctx.cache.listApprovalRequests(input ?? {});
      // Secure approval URLs are returned exactly once, by the secure-link
      // endpoint that mints them; listings never carry capability-bearing URLs.
      return {
        items: requests.map((request) => ({
          ...request,
          metadata: sanitizedApprovalMetadata(request.metadata),
        })),
      };
    }),
  listDaemons: adminProcedure.query(async ({ ctx }) => {
    const daemons = await ctx.cache.listDaemons();
    return { items: daemons };
  }),
  rekeyDaemon: adminProcedure.input(rekeyDaemonInputSchema).mutation(async ({ ctx, input }) => {
    const daemon = await ctx.cache.rekeyDaemon(input).catch(rethrowCacheErrorAsTrpc);
    return {
      daemonId: daemon.daemonId,
      daemonPublicKey: daemon.daemonPublicKey,
      updatedAt: daemon.updatedAt,
    };
  }),
  submitEncryptedUpdate: adminProcedure
    .input(submitEncryptedUpdateInputSchema)
    .mutation(async ({ ctx, input }) => {
      let update: Awaited<ReturnType<typeof ctx.cache.createEncryptedUpdate>>;
      try {
        update = await ctx.cache.createEncryptedUpdate(input);
      } catch (error) {
        const cacheError = error as { code?: string; message?: string };
        if (cacheError?.code === cacheErrorCodes.notFound) {
          throw new TRPCError({
            code: 'NOT_FOUND',
            message: cacheError.message ?? 'Unknown encrypted update target',
          });
        }

        if (
          cacheError?.code === cacheErrorCodes.invalidPayload ||
          cacheError?.code === cacheErrorCodes.conflict
        ) {
          throw new TRPCError({
            code: isMalformedEncryptedUpdatePayload(cacheError.message)
              ? 'BAD_REQUEST'
              : 'CONFLICT',
            message:
              cacheError.message ?? 'Encrypted update conflicts with an existing queued update',
          });
        }

        throw error;
      }

      return {
        daemonId: update.daemonId,
        status: update.status,
        updateId: update.updateId,
      };
    }),
});
