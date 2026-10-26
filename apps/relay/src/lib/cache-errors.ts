import { TRPCError } from '@trpc/server';
import { CacheError, cacheErrorCodes } from '@worldlibertyfinancial/agent-cache/errors';

export type RelayErrorStatus = 404 | 409 | 503;

export interface MappedCacheError {
  message: string;
  status: RelayErrorStatus;
}

export const RELAY_CACHE_UNAVAILABLE_MESSAGE = 'Relay storage is temporarily unavailable';

const cacheErrorCodeValues = new Set<string>(Object.values(cacheErrorCodes));

/**
 * Structural check rather than `instanceof`: the cache package can be loaded
 * more than once (bundling, test module resets), which breaks class identity.
 */
const isCacheError = (error: unknown): error is CacheError => {
  if (error instanceof CacheError) {
    return true;
  }
  if (!(error instanceof Error) || error.name !== 'CacheError') {
    return false;
  }
  const { code } = error as Error & { code?: unknown };
  return typeof code === 'string' && cacheErrorCodeValues.has(code);
};

/**
 * Maps cache-layer failures to HTTP semantics. Not-found and conflict/invalid
 * state messages are authored by the cache service and safe to return; any
 * other cache failure (connection loss, malformed stored JSON) is reported
 * with a generic message so internal key names never reach callers.
 */
export const mapCacheError = (error: unknown): MappedCacheError | null => {
  if (!isCacheError(error)) {
    return null;
  }

  switch (error.code) {
    case cacheErrorCodes.notFound:
      return { message: error.message, status: 404 };
    case cacheErrorCodes.conflict:
    case cacheErrorCodes.invalidPayload:
      return { message: error.message, status: 409 };
    default:
      return { message: RELAY_CACHE_UNAVAILABLE_MESSAGE, status: 503 };
  }
};

const trpcCodeForStatus = {
  404: 'NOT_FOUND',
  409: 'CONFLICT',
  503: 'INTERNAL_SERVER_ERROR',
} as const satisfies Record<RelayErrorStatus, TRPCError['code']>;

/** Rethrows cache-layer failures as typed tRPC errors; other errors pass through unchanged. */
export const rethrowCacheErrorAsTrpc = (error: unknown): never => {
  const mapped = mapCacheError(error);
  if (!mapped) {
    throw error;
  }

  throw new TRPCError({ code: trpcCodeForStatus[mapped.status], message: mapped.message });
};
