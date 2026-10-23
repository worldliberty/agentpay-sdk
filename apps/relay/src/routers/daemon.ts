import { rethrowCacheErrorAsTrpc } from '@/lib/cache-errors';
import { daemonProcedure, t } from '@/lib/core/trpc';
import {
  daemonRegisterInputSchema,
  pollUpdatesInputSchema,
  submitFeedbackInputSchema,
} from '@/lib/schemas';

export const daemonRouter = t.router({
  pollUpdates: daemonProcedure.input(pollUpdatesInputSchema).query(async ({ ctx, input }) => {
    const updates = await ctx.cache
      .claimEncryptedUpdates({
        daemonId: input.daemonId,
        leaseSeconds: input.leaseSeconds ?? ctx.env.RELAY_UPDATE_LEASE_SECONDS,
        limit: input.limit ?? ctx.env.RELAY_POLL_MAX_UPDATES,
      })
      .catch(rethrowCacheErrorAsTrpc);

    return {
      items: updates,
      polledAt: new Date().toISOString(),
    };
  }),
  register: daemonProcedure.input(daemonRegisterInputSchema).mutation(async ({ ctx, input }) => {
    const daemonId = input.daemon.daemonId;
    // The cache pins the daemon public key on first registration and rejects a
    // re-registration that changes it (CONFLICT); key rotation goes through the
    // admin-only `admin.rekeyDaemon` procedure.
    const result = await ctx.cache
      .syncDaemonRegistration({
        ...input,
        agentKeys: input.agentKeys.map((agentKey) => ({ ...agentKey, daemonId })),
        approvalRequests: input.approvalRequests.map((request) => ({ ...request, daemonId })),
        policies: input.policies.map((policy) => ({ ...policy, daemonId })),
      })
      .catch(rethrowCacheErrorAsTrpc);
    return {
      daemonId,
      registeredAt: input.daemon.registeredAt,
      summary: result,
    };
  }),
  submitFeedback: daemonProcedure
    .input(submitFeedbackInputSchema)
    .mutation(async ({ ctx, input }) => {
      const update = await ctx.cache.submitUpdateFeedback(input).catch(rethrowCacheErrorAsTrpc);
      return {
        status: update.status,
        updateId: update.updateId,
        updatedAt: update.updatedAt,
      };
    }),
});
