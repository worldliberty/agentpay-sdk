/** biome-ignore-all lint/style/noProcessEnv: relay env is intentionally process driven */
import { z } from 'zod';

const booleanString = z
  .string()
  .trim()
  .default('false')
  .transform((value) => value === 'true');

const parseCsv = (value: string | undefined): string[] => {
  return (value ?? '')
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);
};

const schema = z.object({
  CACHE_URL: z.string().trim().min(1).default('redis://127.0.0.1:6379'),
  HOST: z.string().trim().min(1).default('127.0.0.1'),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(8787),
  RELAY_ADMIN_TOKEN: z.string().trim().min(24),
  RELAY_ALLOWED_ORIGINS: z.string().optional(),
  RELAY_BASE_URL: z.string().trim().url(),
  RELAY_CACHE_NAMESPACE: z.string().trim().min(1).default('agentpay:relay'),
  RELAY_CLIENT_IP_HEADER: z
    .string()
    .trim()
    .toLowerCase()
    .regex(/^[a-z0-9-]+$/u, 'RELAY_CLIENT_IP_HEADER must be an HTTP header name')
    .optional(),
  RELAY_DAEMON_TOKEN: z.string().trim().min(24),
  RELAY_ENABLE_PRETTY_LOGS: booleanString,
  RELAY_FRONTEND_BASE_URL: z.string().trim().url().optional(),
  RELAY_POLL_MAX_UPDATES: z.coerce.number().int().min(1).max(100).default(25),
  RELAY_UPDATE_LEASE_SECONDS: z.coerce.number().int().min(5).max(300).default(30),
});

export const env = (() => {
  const parsed = schema.parse({
    CACHE_URL: process.env.CACHE_URL,
    HOST: process.env.HOST,
    LOG_LEVEL: process.env.LOG_LEVEL,
    NODE_ENV: process.env.NODE_ENV,
    PORT: process.env.PORT,
    RELAY_ADMIN_TOKEN: process.env.RELAY_ADMIN_TOKEN,
    RELAY_ALLOWED_ORIGINS: process.env.RELAY_ALLOWED_ORIGINS,
    RELAY_BASE_URL: process.env.RELAY_BASE_URL,
    RELAY_CACHE_NAMESPACE: process.env.RELAY_CACHE_NAMESPACE,
    RELAY_CLIENT_IP_HEADER: process.env.RELAY_CLIENT_IP_HEADER || undefined,
    RELAY_DAEMON_TOKEN: process.env.RELAY_DAEMON_TOKEN,
    RELAY_ENABLE_PRETTY_LOGS: process.env.RELAY_ENABLE_PRETTY_LOGS,
    RELAY_FRONTEND_BASE_URL: process.env.RELAY_FRONTEND_BASE_URL,
    RELAY_POLL_MAX_UPDATES: process.env.RELAY_POLL_MAX_UPDATES,
    RELAY_UPDATE_LEASE_SECONDS: process.env.RELAY_UPDATE_LEASE_SECONDS,
  });

  const allowedOrigins = parseCsv(parsed.RELAY_ALLOWED_ORIGINS);
  // A production relay must never fall back to a wildcard CORS origin: the
  // approval console submits capability-bearing requests cross-origin.
  if (parsed.NODE_ENV === 'production' && allowedOrigins.length === 0) {
    throw new Error('RELAY_ALLOWED_ORIGINS must list the approval console origin(s) in production');
  }
  if (allowedOrigins.includes('*')) {
    throw new Error("RELAY_ALLOWED_ORIGINS must list explicit origins, not '*'");
  }

  return {
    ...parsed,
    RELAY_ALLOWED_ORIGINS: allowedOrigins,
  };
})();

export type RelayEnv = typeof env;
