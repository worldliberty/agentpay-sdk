import { Badge } from '@worldlibertyfinancial/agent-ui/badge';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@worldlibertyfinancial/agent-ui/card';
import { PageShell } from '@/components/page-shell';

export default function HomePage() {
  return (
    <PageShell>
      <section className="grid gap-6">
        <Card className="border-primary/20 bg-card/90">
          <CardHeader>
            <Badge>Unsupported</Badge>
            <CardTitle className="text-4xl font-semibold tracking-tight">
              Browser approval UI is not part of this release
            </CardTitle>
            <CardDescription className="max-w-2xl text-base">
              Use local AgentPay SDK admin commands to review, approve, reject, and resume manual
              approval requests on the machine running the daemon.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <p>Supported manual approval commands:</p>
            <pre className="overflow-x-auto rounded-xl border border-border/70 bg-background/70 p-4 text-sm">
              {`agentpay admin list-manual-approval-requests
agentpay admin approve-manual-approval-request --approval-request-id <UUID>
agentpay admin reject-manual-approval-request --approval-request-id <UUID> --rejection-reason "<TEXT>"
agentpay admin resume-manual-approval-request --approval-request-id <UUID>`}
            </pre>
          </CardContent>
        </Card>
      </section>
    </PageShell>
  );
}
