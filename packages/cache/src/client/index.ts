/** biome-ignore-all lint/style/noProcessEnv: relay cache config is environment driven */
import Redis from 'ioredis';

export interface CacheClientOptions {
  connectTimeoutMs?: number;
  enableOfflineQueue?: boolean;
  keyPrefix?: string;
  lazyConnect?: boolean;
  maxRetriesPerRequest?: number | null;
  url?: string;
}

let singletonClient: Redis | null = null;

export const parseCachePort = (value: string | undefined): number => {
  const normalized = value?.trim() || '6379';
  if (!/^(0|[1-9][0-9]*)$/u.test(normalized)) {
    throw new Error('CACHE_PORT must be an integer between 1 and 65535');
  }

  const port = Number(normalized);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new Error('CACHE_PORT must be an integer between 1 and 65535');
  }

  return port;
};

const getDefaultCacheUrl = (): string => {
  const explicitUrl = process.env.CACHE_URL?.trim();
  if (explicitUrl) {
    return explicitUrl;
  }

  const host = process.env.CACHE_HOST?.trim() || '127.0.0.1';
  const port = parseCachePort(process.env.CACHE_PORT);

  return `redis://${host}:${port}`;
};

export const createCacheClient = (options: CacheClientOptions = {}): Redis => {
  return new Redis(options.url ?? getDefaultCacheUrl(), {
    connectTimeout: options.connectTimeoutMs ?? 5_000,
    enableOfflineQueue: options.enableOfflineQueue ?? true,
    keyPrefix: options.keyPrefix,
    lazyConnect: options.lazyConnect ?? false,
    maxRetriesPerRequest: options.maxRetriesPerRequest ?? 2,
    reconnectOnError(error) {
      return error.message.includes('READONLY') || error.message.includes('ETIMEDOUT');
    },
  });
};

export const getCacheClient = (options: CacheClientOptions = {}): Redis => {
  if (!singletonClient) {
    singletonClient = createCacheClient(options);
  }

  return singletonClient;
};

export const closeCacheClient = async (): Promise<void> => {
  if (!singletonClient) {
    return;
  }

  const client = singletonClient;
  singletonClient = null;
  await client.quit();
};
