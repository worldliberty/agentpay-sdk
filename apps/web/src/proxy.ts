import { type NextRequest, NextResponse } from 'next/server';
import { clientConfig } from '@/lib/config';
import {
  buildContentSecurityPolicy,
  CSP_NONCE_HEADER,
  createCspNonce,
  relayOriginForCsp,
} from '@/lib/csp';

const relayOrigin = relayOriginForCsp(clientConfig.relayBaseUrl);

/**
 * Attaches a per-request nonce-based Content-Security-Policy. Next.js reads the
 * nonce from the request CSP header and stamps it on the scripts it renders.
 */
export function proxy(request: NextRequest) {
  const nonce = createCspNonce();
  const contentSecurityPolicy = buildContentSecurityPolicy({
    isDevelopment: process.env.NODE_ENV === 'development',
    nonce,
    relayOrigin,
  });

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set(CSP_NONCE_HEADER, nonce);
  requestHeaders.set('Content-Security-Policy', contentSecurityPolicy);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set('Content-Security-Policy', contentSecurityPolicy);
  return response;
}

export const config = {
  matcher: [
    {
      source: '/((?!_next/static|_next/image|favicon.ico).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
};
