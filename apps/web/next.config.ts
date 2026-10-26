import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { NextConfig } from 'next';

const workspaceRoot = fileURLToPath(new URL('../..', import.meta.url));

/**
 * Static security headers. The Content-Security-Policy is not set here: it is
 * nonce-based and therefore issued per request by `src/proxy.ts`.
 */
export const approvalConsoleSecurityHeaders = [
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=63072000; includeSubDomains; preload',
  },
  {
    key: 'Referrer-Policy',
    value: 'no-referrer',
  },
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff',
  },
  {
    key: 'X-Frame-Options',
    value: 'DENY',
  },
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=(), payment=()',
  },
];

export const approvalConsoleNoStoreHeaders = [
  {
    key: 'Cache-Control',
    value: 'private, no-store, max-age=0',
  },
  {
    key: 'Pragma',
    value: 'no-cache',
  },
  {
    key: 'Expires',
    value: '0',
  },
];

const nextConfig: NextConfig = {
  reactStrictMode: true,
  typedRoutes: true,
  turbopack: {
    root: path.join(workspaceRoot),
  },
  async headers() {
    return [
      {
        source: '/approvals/:path*',
        headers: approvalConsoleNoStoreHeaders,
      },
      {
        source: '/daemons/:path*',
        headers: approvalConsoleNoStoreHeaders,
      },
      {
        source: '/:path*',
        headers: approvalConsoleSecurityHeaders,
      },
    ];
  },
};

export default nextConfig;
