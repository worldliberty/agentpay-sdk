import { z } from 'zod';
import { clientConfig } from './config.ts';
import {
  approvalRequestListSchema,
  approvalRequestRecordSchema,
  relayDaemonRecordSchema,
  secureApprovalLinkRecordSchema,
} from './relay-schemas.ts';
import type {
  ApprovalRequestRecord,
  RelayDaemonRecord,
  SecureApprovalLinkRecord,
} from './types.ts';

export function buildRelayUrl(pathname: string): URL {
  return new URL(pathname, `${clientConfig.relayBaseUrl}/`);
}

async function fetchJson<T>(target: URL, schema: z.ZodType<T>, init?: RequestInit): Promise<T> {
  const response = await fetch(target, {
    ...init,
    headers: {
      accept: 'application/json',
      ...init?.headers,
    },
    cache: 'no-store',
  });

  if (!response.ok) {
    let message = `Relay request failed (${response.status} ${response.statusText})`;
    try {
      const payload = (await response.json()) as { error?: string };
      if (payload?.error) {
        message = payload.error;
      }
    } catch {}
    throw new Error(message);
  }

  const payload = await response.json();

  try {
    return schema.parse(payload);
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new Error(`Relay response was invalid for ${target.pathname}`);
    }
    throw error;
  }
}

export async function getApprovalRequest(approvalId: string): Promise<ApprovalRequestRecord> {
  return fetchJson<ApprovalRequestRecord>(
    buildRelayUrl(`/v1/approvals/${encodeURIComponent(approvalId)}`),
    approvalRequestRecordSchema,
  );
}

export async function listDaemonApprovals(daemonId: string): Promise<ApprovalRequestRecord[]> {
  return fetchJson<ApprovalRequestRecord[]>(
    buildRelayUrl(`/v1/daemons/${encodeURIComponent(daemonId)}/approvals`),
    approvalRequestListSchema,
  );
}

export async function getDaemonRecord(daemonId: string): Promise<RelayDaemonRecord> {
  return fetchJson<RelayDaemonRecord>(
    buildRelayUrl(`/v1/daemons/${encodeURIComponent(daemonId)}`),
    relayDaemonRecordSchema,
  );
}

export async function requestSecureApprovalLink(
  approvalId: string,
  relayAdminToken: string,
): Promise<SecureApprovalLinkRecord> {
  const normalizedToken = relayAdminToken.trim();
  if (!normalizedToken) {
    throw new Error('relay admin token is required');
  }

  return fetchJson<SecureApprovalLinkRecord>(
    buildRelayUrl(`/v1/admin/approvals/${encodeURIComponent(approvalId)}/secure-link`),
    secureApprovalLinkRecordSchema,
    {
      method: 'POST',
      headers: {
        authorization: `Bearer ${normalizedToken}`,
      },
    },
  );
}
