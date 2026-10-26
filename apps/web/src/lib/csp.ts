export const CSP_NONCE_HEADER = 'x-nonce';

export interface ContentSecurityPolicyOptions {
  /** Development builds need `eval` for React Refresh and inline styles for the dev overlay. */
  isDevelopment: boolean;
  nonce: string;
  /** Origin of the relay the approval console fetches from and submits to. */
  relayOrigin: string;
}

/** Returns a fresh base64 nonce for a single response. */
export function createCspNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

/** Normalizes the relay base URL to an origin usable as a CSP source. */
export function relayOriginForCsp(relayBaseUrl: string): string {
  return new URL(relayBaseUrl).origin;
}

/**
 * Builds the approval console Content-Security-Policy. Scripts only run when
 * they carry the per-request nonce (Next.js propagates it to its own scripts),
 * network access is limited to the page origin and the relay, and the page can
 * neither be framed nor submit forms anywhere else.
 */
export function buildContentSecurityPolicy({
  isDevelopment,
  nonce,
  relayOrigin,
}: ContentSecurityPolicyOptions): string {
  const directives = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDevelopment ? " 'unsafe-eval'" : ''}`,
    `style-src 'self' ${isDevelopment ? "'unsafe-inline'" : `'nonce-${nonce}'`}`,
    "img-src 'self' blob: data:",
    "font-src 'self'",
    `connect-src 'self' ${relayOrigin}`,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    ...(isDevelopment ? [] : ['upgrade-insecure-requests']),
  ];

  return `${directives.join('; ')};`;
}
