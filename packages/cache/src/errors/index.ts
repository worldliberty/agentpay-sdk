export const cacheErrorCodes = {
  conflict: 'CACHE_CONFLICT',
  connectionFailed: 'CACHE_CONNECTION_FAILED',
  invalidPayload: 'CACHE_INVALID_PAYLOAD',
  notFound: 'CACHE_NOT_FOUND',
  unknown: 'CACHE_UNKNOWN',
} as const;

export type CacheErrorCode = (typeof cacheErrorCodes)[keyof typeof cacheErrorCodes];

export class CacheError extends Error {
  readonly code: CacheErrorCode;
  readonly key?: string;
  readonly operation?: string;
  override readonly cause?: unknown;

  constructor(options: {
    cause?: unknown;
    code: CacheErrorCode;
    key?: string;
    message: string;
    operation?: string;
  }) {
    super(options.message);
    this.name = 'CacheError';
    this.code = options.code;
    this.key = options.key;
    this.operation = options.operation;
    this.cause = options.cause;
  }
}

export const toCacheError = (
  error: unknown,
  context: { key?: string; operation?: string } = {},
): CacheError => {
  if (error instanceof CacheError) {
    return error;
  }

  const message = error instanceof Error ? error.message : 'Unknown cache error';
  const normalizedMessage = message.toLowerCase();
  const code = normalizedMessage.includes('connect')
    ? cacheErrorCodes.connectionFailed
    : cacheErrorCodes.unknown;

  return new CacheError({
    cause: error,
    code,
    key: context.key,
    message,
    operation: context.operation,
  });
};
