import { Badge } from '@worldlibertyfinancial/agent-ui/badge';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@worldlibertyfinancial/agent-ui/card';
import { Separator } from '@worldlibertyfinancial/agent-ui/separator';
import { formatApprovalAmount, formatApprovalAsset } from '@/lib/approval-display';
import type { ApprovalRequestRecord } from '@/lib/types';

function statusVariant(
  status: ApprovalRequestRecord['status'],
): 'default' | 'secondary' | 'success' | 'warning' | 'destructive' {
  switch (status) {
    case 'approved':
      return 'success';
    case 'rejected':
      return 'destructive';
    case 'failed':
      return 'warning';
    case 'pending':
      return 'default';
    default:
      return 'secondary';
  }
}

export function ApprovalRequestCard({ approval }: { approval: ApprovalRequestRecord }) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between gap-4">
          <div>
            <CardTitle className="text-xl">Manual approval required</CardTitle>
            <CardDescription>
              Approval request `{approval.approvalId}` for agent `{approval.agentKeyId}`.
            </CardDescription>
          </div>
          <Badge variant={statusVariant(approval.status)}>{approval.status}</Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <Detail label="Action type" value={approval.actionType} />
          <Detail label="Chain ID" value={String(approval.chainId)} />
          <Detail label="Recipient" value={approval.recipient} />
          <Detail label="Asset" value={formatApprovalAsset(approval)} />
          <Detail label="Amount" value={formatApprovalAmount(approval)} />
          <Detail label="Reason" value={approval.reason} />
        </div>
        <Separator />
        <div className="grid gap-2 text-sm text-muted-foreground sm:grid-cols-2">
          <Detail label="Created" value={new Date(approval.createdAt).toLocaleString()} />
          <Detail label="Updated" value={new Date(approval.updatedAt).toLocaleString()} />
        </div>
      </CardContent>
    </Card>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-border/70 bg-background/70 p-3">
      <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
      <div className="mt-1 break-all text-sm font-medium text-foreground">{value}</div>
    </div>
  );
}
