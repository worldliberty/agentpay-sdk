import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@worldlibertyfinancial/agent-ui/card';
import Link from 'next/link';
import { PageShell } from '@/components/page-shell';
import { formatApprovalAmount } from '@/lib/approval-display';
import { getDaemonRecord, listDaemonApprovals } from '@/lib/relay';
import { approvalRoutePath } from '@/lib/routes';

export default async function DaemonPage({ params }: { params: Promise<{ daemonId: string }> }) {
  const { daemonId } = await params;
  const [daemon, approvals] = await Promise.all([
    getDaemonRecord(daemonId).catch(() => null),
    listDaemonApprovals(daemonId).catch(() => []),
  ]);
  const relayMetadataUnavailable = daemon === null;

  return (
    <PageShell>
      <Card>
        <CardHeader>
          <CardTitle>Daemon dashboard</CardTitle>
          <CardDescription>
            Approval relay metadata and pending manual approvals for daemon `{daemonId}`.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 text-sm">
          <div className="grid gap-3 md:grid-cols-2">
            <Detail label="Daemon ID" value={daemon?.daemonId ?? daemonId} />
            <Detail label="Vault address" value={daemon?.vaultEthereumAddress ?? 'Unavailable'} />
            <Detail label="Public key" value={daemon?.daemonPublicKey ?? 'Unavailable'} />
            <Detail
              label="Updated"
              value={
                daemon?.updatedAt ? new Date(daemon.updatedAt).toLocaleString() : 'Unavailable'
              }
            />
          </div>
          {relayMetadataUnavailable ? (
            <p className="text-sm text-muted-foreground">
              Relay metadata is not available for this daemon yet. Verify that the daemon is running
              and able to register with the relay.
            </p>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Pending approvals</CardTitle>
          <CardDescription>
            {approvals.length} approval request(s) are currently tracked for this daemon. Browser
            submission still requires the exact CLI-issued secure link.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {approvals.length === 0 ? (
              <p className="text-sm text-muted-foreground">No approvals are available yet.</p>
            ) : (
              approvals.map((approval) => (
                <div className="rounded-xl border border-border/70 p-4" key={approval.approvalId}>
                  <div className="flex items-center justify-between gap-4">
                    <div>
                      <div className="font-medium">{approval.actionType}</div>
                      <div className="text-sm text-muted-foreground">
                        {approval.recipient} · {formatApprovalAmount(approval)}
                      </div>
                    </div>
                    <Link
                      className="text-sm font-medium"
                      href={approvalRoutePath(approval.approvalId)}
                    >
                      View details
                    </Link>
                  </div>
                </div>
              ))
            )}
          </div>
        </CardContent>
      </Card>
    </PageShell>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-border/70 bg-background/70 p-3">
      <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
      <div className="mt-1 break-all text-sm font-medium">{value}</div>
    </div>
  );
}
