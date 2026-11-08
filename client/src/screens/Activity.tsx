/**
 * Activity: payments waiting for approval first (with why), then the agent's recent payments,
 * each marked "within limits" or "approved by you". Refreshes in the background.
 */
import { Box } from 'ink';
import { copy } from '../copy/index.js';
import { activityAmount, waitingApprovals } from '../format/activity.js';
import { approvalReasons, networkName } from '../format/approval.js';
import { relativeTime, shortAddress, timestampToDate } from '../format/text.js';
import { Spinner } from '../ui/controls.js';
import { useInput } from '../ui/input.js';
import { Screen } from '../ui/layout.js';
import { glyph, T } from '../ui/theme.js';
import type { AppServices } from './types.js';
import { useAsync, useInterval } from './use-async.js';

export function ActivityScreen({
  services,
  onBack,
  onOpenApprovals,
  refreshMs = 15_000,
  now = () => new Date(),
}: {
  services: Pick<AppServices, 'loadActivity'>;
  onBack: () => void;
  /** Opens the Approvals screen (`a`) when something is waiting. */
  onOpenApprovals: () => void;
  refreshMs?: number;
  now?: () => Date;
}) {
  const a = copy.screens.activity;
  const k = copy.common.keys;
  const state = useAsync(() => services.loadActivity());
  useInterval(() => state.refresh(), refreshMs, state.status === 'ready');
  const data = state.status === 'ready' ? state.value : null;
  const waiting = data ? waitingApprovals(data.result) : [];
  useInput((input, key) => {
    if (key.escape || input === 'q') {
      onBack();
    } else if (input === 'r') {
      state.reload();
    } else if (input === 'a' && waiting.length > 0) {
      onOpenApprovals();
    }
  });
  const at = now();
  return (
    <Screen
      title={a.title}
      hints={[...(waiting.length > 0 ? [k.openApprovals] : []), k.refresh, k.back]}
      error={state.status === 'error' ? state.error : null}
    >
      {state.status === 'loading' ? <Spinner label={copy.common.loading} /> : null}
      {data && waiting.length > 0 ? (
        <Box flexDirection="column">
          <T tone="warning" bold>{`${glyph.warning} ${a.waitingHeading(waiting.length)}`}</T>
          {waiting.map((approval) => (
            <Box key={approval.id} flexDirection="column" marginLeft={2}>
              <T>
                {`${activityAmount(approval)} ${glyph.pointer} ${shortAddress(approval.recipient.value)} ${glyph.separator} ${networkName(approval.chain_id, data.config)}`}
              </T>
              {approvalReasons(approval, data.config).reasons.map((reason) => (
                <T key={reason} tone="muted">{`  ${reason}`}</T>
              ))}
            </Box>
          ))}
        </Box>
      ) : null}
      {data ? (
        <Box flexDirection="column">
          <T bold>{a.paymentsHeading}</T>
          {data.result.spends.length === 0 ? <T tone="muted">{`  ${a.noPayments}`}</T> : null}
          {data.result.spends.map((spend) => (
            <Box key={`${spend.at.join('-')}-${spend.amount_wei}-${spend.recipient.value}`}>
              <Box width={14}>
                <T tone="muted">{`  ${relativeTime(timestampToDate(spend.at), at)}`}</T>
              </Box>
              <Box width={20}>
                <T bold>{activityAmount(spend)}</T>
              </Box>
              <Box width={16}>
                <T>{`${glyph.pointer} ${shortAddress(spend.recipient.value)}`}</T>
              </Box>
              <Box width={10}>
                <T tone="muted">{networkName(spend.chain_id, data.config)}</T>
              </Box>
              <T tone={spend.approval_request_id ? 'accent' : 'muted'}>
                {spend.approval_request_id ? a.approved : a.auto}
              </T>
            </Box>
          ))}
        </Box>
      ) : null}
    </Screen>
  );
}
