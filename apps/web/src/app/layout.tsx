import '@worldlibertyfinancial/agent-ui/globals.css';
import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { clientConfig } from '@/lib/config';

// The proxy issues a fresh CSP nonce per request, so every page must render
// dynamically for Next.js to stamp that nonce on its scripts.
export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: clientConfig.siteName,
  description: 'Review and approve pending AgentPay signing requests.',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
