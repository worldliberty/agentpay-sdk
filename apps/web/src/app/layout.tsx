import '@worldlibertyfinancial/agent-ui/globals.css';
import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { clientConfig } from '@/lib/config';

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
