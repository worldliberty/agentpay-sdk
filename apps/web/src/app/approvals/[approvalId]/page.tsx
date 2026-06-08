import { Badge } from '@worldlibertyfinancial/agent-ui/badge';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@worldlibertyfinancial/agent-ui/card';
import Link from 'next/link';
import { ApprovalRequestCard } from '@/components/approval-request-card';
import { PageShell } from '@/components/page-shell';
import { getApprovalRequest, getDaemonRecord } from '@/lib/relay';
import { approvalRoutePath, daemonRoutePath } from '@/lib/routes';
import { ApprovalForm } from './approval-form';

export default async function ApprovalPage({
  params,
}: {
  params: Promise<{ approvalId: string }>;
}) {
  const { approvalId } = await params;
  const approval = await getApprovalRequest(approvalId).catch(() => ({
    approvalId,
    daemonId: 'unknown',
    agentKeyId: 'unknown',
    status: 'failed' as const,
    reason: 'The relay did not return the approval request.',
    actionType: 'unknown',
    chainId: 0,
    recipient: '0x0000000000000000000000000000000000000000',
    asset: 'native_eth',
    amountWei: '0',
    createdAt: new Date(0).toISOString(),
    updatedAt: new Date(0).toISOString(),
  }));
  const daemon =
    approval.daemonId === 'unknown'
      ? null
      : await getDaemonRecord(approval.daemonId).catch(() => null);

  return (
    <PageShell>
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <Badge
            variant={
              approval.status === 'pending'
                ? 'warning'
                : approval.status === 'approved'
                  ? 'success'
                  : approval.status === 'rejected'
                    ? 'destructive'
                    : 'secondary'
            }
          >
            {approval.status}
          </Badge>
          <h1 className="mt-3 text-3xl font-semibold tracking-tight">Approval request</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Deep link for manual approval requests emitted by the agent CLI when daemon-side
            policies require operator approval.
          </p>
        </div>
        <Link className="text-sm font-medium" href={daemonRoutePath(approval.daemonId)}>
          Open daemon dashboard
        </Link>
      </div>

      <ApprovalRequestCard approval={approval} />

      <div className="grid gap-6 lg:grid-cols-[1.2fr,0.8fr]">
        <ApprovalForm approval={approval} daemon={daemon} />
        <Card>
          <CardHeader>
            <CardTitle>CLI handoff</CardTitle>
            <CardDescription>
              The agent CLI prints the local admin command and a one-time secure frontend approval
              URL.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            <div className="rounded-xl border border-border/70 bg-background/70 p-3 font-mono">
              agentpay admin approve-manual-approval-request --approval-request-id{' '}
              {approval.approvalId}
            </div>
            <div className="rounded-xl border border-border/70 bg-background/70 p-3 font-mono">
              {approvalRoutePath(approval.approvalId)}
            </div>
            <p className="text-muted-foreground">
              The route above is only the non-secret page path. Browser submission requires the
              original CLI-issued secure URL, and its capability token is intentionally scrubbed
              from the address bar after load. If relay metadata is unavailable, use the local admin
              CLI command against the daemon socket.
            </p>
          </CardContent>
        </Card>
      </div>
    </PageShell>
  );
}
