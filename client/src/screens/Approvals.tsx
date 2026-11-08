/**
 * Approvals: the list of requests waiting for the owner, and a detail view with labeled rows
 * (To, Amount, Network, Agent) followed by "Approve with Touch ID" (Neo Financial request
 * pattern).
 */
import { Box } from 'ink';
import { useState } from 'react';
import { copy, type Guidance } from '../copy/index.js';
import { guidanceFor } from '../errors.js';
import { relativeTime, shortAddress, timestampToDate } from '../format/text.js';
import { Menu, Spinner } from '../ui/controls.js';
import { useInput } from '../ui/input.js';
import { Rows, Screen } from '../ui/layout.js';
import { glyph, T } from '../ui/theme.js';
import type { ApprovalItem, AppServices } from './types.js';
import { useAsync } from './use-async.js';

type Services = Pick<AppServices, 'listApprovals' | 'decideApproval' | 'adminMethod'>;

export function ApprovalDetail({
  item,
  services,
  onDecided,
  onBack,
  now,
}: {
  item: ApprovalItem;
  services: Services;
  onDecided: (message: string) => void;
  onBack: () => void;
  now?: Date;
}) {
  const a = copy.screens.approvals;
  const method = services.adminMethod();
  const [busy, setBusy] = useState<'approve' | 'reject' | null>(null);
  const [error, setError] = useState<Guidance | null>(null);

  useInput(
    (_input, key) => {
      if (key.escape) {
        onBack();
      }
    },
    { isActive: busy === null },
  );

  const decide = async (decision: 'approve' | 'reject') => {
    setBusy(decision);
    setError(null);
    try {
      await services.decideApproval(item, decision, null);
      onDecided(decision === 'approve' ? a.approved : a.rejected);
    } catch (failure) {
      setError(guidanceFor(failure));
      setBusy(null);
    }
  };

  const { summary, request } = item;
  const busyLabel =
    busy === 'approve' && method === 'touch_id'
      ? a.approving
      : method === 'sudo'
        ? a.approvingSudo
        : a.deciding;
  return (
    <Screen
      title={a.detailTitle}
      hints={busy ? [] : [copy.common.keys.select, copy.common.keys.confirm, copy.common.keys.back]}
      error={error}
    >
      <Rows
        rows={[
          { label: a.rows.action, value: summary.action },
          { label: a.rows.to, value: summary.to, tone: 'accent' },
          { label: a.rows.amount, value: summary.amount },
          { label: a.rows.network, value: summary.network },
          { label: a.rows.agent, value: shortAddress(summary.agentKeyId, 8, 4) },
          {
            label: a.rows.requested,
            value: relativeTime(timestampToDate(request.created_at), now),
          },
          ...summary.reasons.map((reason, index) => ({
            label: index === 0 ? a.rows.why : '',
            value: reason,
            tone: 'warning' as const,
          })),
        ]}
      />
      {busy ? (
        <Spinner label={busyLabel} />
      ) : (
        <Menu
          items={[
            {
              value: 'approve',
              label: method === 'touch_id' ? a.approveTouchId : a.approveSudo,
            },
            { value: 'reject', label: a.reject },
            { value: 'back', label: a.back },
          ]}
          onSelect={(value) => (value === 'back' ? onBack() : void decide(value))}
        />
      )}
    </Screen>
  );
}

export function ApprovalsScreen({
  services,
  onBack,
  now,
}: {
  services: Services;
  onBack: () => void;
  now?: Date;
}) {
  const a = copy.screens.approvals;
  const list = useAsync(() => services.listApprovals());
  const [open, setOpen] = useState<ApprovalItem | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useInput(
    (input, key) => {
      if (key.escape || input === 'q') {
        onBack();
      } else if (input === 'r') {
        setNotice(null);
        list.reload();
      }
    },
    { isActive: open === null },
  );

  if (open) {
    return (
      <ApprovalDetail
        item={open}
        services={services}
        {...(now ? { now } : {})}
        onBack={() => setOpen(null)}
        onDecided={(message) => {
          setOpen(null);
          setNotice(message);
          list.reload();
        }}
      />
    );
  }

  const k = copy.common.keys;
  return (
    <Screen
      title={a.title}
      hints={[k.select, k.open, k.refresh, k.back]}
      error={list.status === 'error' ? list.error : null}
    >
      {notice ? <T tone="success">{`${glyph.check} ${notice}`}</T> : null}
      {list.status === 'loading' ? <Spinner label={copy.common.loading} /> : null}
      {list.status === 'ready' && list.value.length === 0 ? <T tone="muted">{a.empty}</T> : null}
      {list.status === 'ready' && list.value.length > 0 ? (
        <Box flexDirection="column">
          <Menu
            items={list.value.map((item) => ({
              value: item.request.id,
              label: `${item.summary.action} ${item.summary.amount} ${glyph.pointer} ${shortAddress(item.summary.to)}`,
              hint: [
                item.summary.network,
                ...(item.summary.shortReason ? [item.summary.shortReason] : []),
                relativeTime(timestampToDate(item.request.created_at), now),
              ].join(` ${glyph.separator} `),
            }))}
            onSelect={(id) => setOpen(list.value.find((item) => item.request.id === id) ?? null)}
          />
        </Box>
      ) : null}
    </Screen>
  );
}
