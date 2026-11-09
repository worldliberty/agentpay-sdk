/**
 * An agent's activity as people read it: approval requests still waiting (with why), then
 * recent payments, each "auto" (within the limits) or "approved" (went through an approval).
 */
import { copy } from '../copy/index.js';
import type {
  ActivityApproval,
  ActivityResult,
  ActivitySpend,
  PaymentsConfig,
} from '../generated/index.js';
import { displayAmount } from './amount.js';
import { approvalReasons, networkName } from './approval.js';
import { columns, relativeTime, shortAddress, timestampToDate } from './text.js';

/** "150 USD1", or base units when the asset is not configured. */
export function activityAmount(entry: ActivitySpend | ActivityApproval): string {
  return entry.amount !== null && entry.symbol !== null
    ? `${displayAmount(entry.amount)} ${entry.symbol}`
    : `${entry.amount_wei} base units`;
}

export function waitingApprovals(result: ActivityResult): ActivityApproval[] {
  return result.approvals.filter((approval) => approval.status === 'pending');
}

/** One line for an alert: "50 USD1 on BSC" (the network key when the configuration is unknown). */
export function approvalHeadline(approval: ActivityApproval, config: PaymentsConfig | null) {
  const network =
    config || approval.network === null ? networkName(approval.chain_id, config) : approval.network;
  return `${activityAmount(approval)} on ${network}`;
}

/** Text output of `agentpay activity`. */
export function activityLines(
  result: ActivityResult,
  config: PaymentsConfig | null,
  now: Date = new Date(),
): string[] {
  const a = copy.screens.activity;
  const lines: string[] = [];
  const pending = waitingApprovals(result);
  if (pending.length > 0) {
    lines.push(a.waitingHeading(pending.length));
    for (const approval of pending) {
      lines.push(
        `  ${approvalHeadline(approval, config)} → ${shortAddress(approval.recipient.value)}`,
        ...approvalReasons(approval, config).reasons.map((reason) => `    ${reason}`),
      );
    }
    lines.push(`  ${copy.common.next}: ${a.review}`, '');
  }
  lines.push(a.paymentsHeading);
  if (result.spends.length === 0) {
    lines.push(`  ${a.noPayments}`);
    return lines;
  }
  lines.push(
    ...columns(
      result.spends.map((spend) => [
        `  ${relativeTime(timestampToDate(spend.at), now)}`,
        activityAmount(spend),
        `→ ${shortAddress(spend.recipient.value)}`,
        networkName(spend.chain_id, config),
        spend.approval_request_id ? a.approved : a.auto,
      ]),
    ),
  );
  return lines;
}
