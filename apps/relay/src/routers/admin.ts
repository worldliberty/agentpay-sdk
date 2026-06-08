import { cacheErrorCodes } from '@worldlibertyfinancial/agent-cache/errors';
import { adminProcedure, TRPCError, t } from '@/lib/core/trpc';
import { listApprovalRequestsInputSchema, submitEncryptedUpdateInputSchema } from '@/lib/schemas';

function adminApprovalFrontendBaseUrl(env: {
  RELAY_BASE_URL: string;
  RELAY_FRONTEND_BASE_URL?: string | undefined;
}): string | null {
  const candidate = env.RELAY_FRONTEND_BASE_URL?.trim() || env.RELAY_BASE_URL.trim();
  return candidate ? candidate.replace(/\/$/u, '') : null;
}

function approvalCapabilityToken(metadata: Record<string, string> | undefined): string | null {
  const candidate = metadata?.approvalCapabilityToken?.trim();
  return candidate ? candidate : null;
}

function sanitizedApprovalMetadata(
  metadata: Record<string, string> | undefined,
): Record<string, string> | undefined {
  if (!metadata) {
    return undefined;
  }

  const { approvalCapabilityToken: _token, ...rest } = metadata;
  return Object.keys(rest).length > 0 ? rest : undefined;
}

function secureApprovalUrl(input: {
  approvalRequestId: string;
  daemonId: string;
  metadata?: Record<string, string>;
  status: string;
  env: { RELAY_BASE_URL: string; RELAY_FRONTEND_BASE_URL?: string | undefined };
}): string | null {
  if (input.status !== 'pending') {
    return null;
  }

  const baseUrl = adminApprovalFrontendBaseUrl(input.env);
  const capability = approvalCapabilityToken(input.metadata);
  if (!baseUrl || !capability) {
    return null;
  }

  return `${baseUrl}/approvals/${input.approvalRequestId}?daemonId=${input.daemonId}&approvalCapability=${capability}`;
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
      return {
        items: requests.map((request) => ({
          ...request,
          metadata: sanitizedApprovalMetadata(request.metadata),
          approvalUrl: secureApprovalUrl({
            approvalRequestId: request.approvalRequestId,
            daemonId: request.daemonId,
            metadata: request.metadata,
            status: request.status,
            env: ctx.env,
          }),
        })),
      };
    }),
  listDaemons: adminProcedure.query(async ({ ctx }) => {
    const daemons = await ctx.cache.listDaemons();
    return { items: daemons };
  }),
  submitEncryptedUpdate: adminProcedure
    .input(submitEncryptedUpdateInputSchema)
    .mutation(async ({ ctx, input }) => {
      let update;
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

        if (cacheError?.code === cacheErrorCodes.invalidPayload) {
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
