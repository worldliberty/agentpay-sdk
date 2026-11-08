/** Home: wallet address, balances, pending approvals, and the main actions. */
import { Box, useApp } from 'ink';
import { useState } from 'react';
import { copy } from '../copy/index.js';
import { displayAmount } from '../format/amount.js';
import { chainProblem, groupBalances, isZeroBalance } from '../format/networks.js';
import { shortAddress } from '../format/text.js';
import { isTestnetChain } from '../limits/model.js';
import { Menu, Spinner } from '../ui/controls.js';
import { useInput } from '../ui/input.js';
import { Rows, Screen } from '../ui/layout.js';
import { glyph, T } from '../ui/theme.js';
import type { HomeData, SecuritySummary } from './types.js';
import { useAsync, useInterval } from './use-async.js';

export type HomeAction =
  | 'receive'
  | 'send'
  | 'approvals'
  | 'activity'
  | 'limits'
  | 'wallet'
  | 'security'
  | 'quit';

/** "Touch ID on · Backed up 2026-11-06 · Approval alerts on", or a backup reminder. */
function SecurityLine({ security }: { security: SecuritySummary }) {
  const s = copy.screens.home.security;
  const parts = [
    ...(security.touchId === 'unavailable'
      ? []
      : [security.touchId === 'on' ? s.touchIdOn : s.touchIdOff]),
    ...(security.backedUpAt ? [s.backedUp(security.backedUpAt.slice(0, 10))] : []),
    ...(security.notifications === null
      ? []
      : [security.notifications ? s.notificationsOn : s.notificationsOff]),
  ];
  return (
    <Box flexDirection="column">
      {parts.length > 0 ? <T tone="muted">{parts.join(` ${glyph.separator} `)}</T> : null}
      {security.backedUpAt ? null : <T tone="warning">{`${glyph.warning} ${s.noBackup}`}</T>}
    </Box>
  );
}

/**
 * Balances by network: the default network first, test networks only on request. A network
 * that cannot be read shows why on one line instead of a column of "unavailable".
 */
function Balances({ data, showTestnets }: { data: HomeData; showTestnets: boolean }) {
  const h = copy.screens.home;
  const { wallet } = data;
  const groups = groupBalances(wallet.balances, {
    defaultNetwork: wallet.default_network,
    defaultAsset: wallet.default_asset,
    includeTestnets: showTestnets,
  });
  if (groups.length === 0) {
    return <T tone="muted">{h.noBalances}</T>;
  }
  const networkWidth = Math.max(...groups.map((g) => g.chainName.length)) + 2;
  const amounts = groups.flatMap((g) =>
    g.entries.map((e) => (e.balance === null ? '' : displayAmount(e.balance))),
  );
  const amountWidth = Math.max(...amounts.map((a) => a.length)) + 1;
  const unreadable = groups.filter((g) => g.problem && !g.testnet);
  const [first] = unreadable;
  return (
    <Box flexDirection="column">
      <T bold>{h.balances}</T>
      {groups.map((group, index) => (
        <Box key={group.network} flexDirection="column">
          {group.testnet && !groups[index - 1]?.testnet ? (
            <T tone="muted">{copy.networks.testnets}</T>
          ) : null}
          {group.problem ? (
            <Box>
              <Box width={networkWidth}>
                <T>{group.chainName}</T>
              </Box>
              <T tone="danger">{`${glyph.cross} ${group.problem.message}`}</T>
            </Box>
          ) : (
            group.entries.map((entry, row) => (
              <Box key={entry.asset}>
                <Box width={networkWidth}>
                  <T>{row === 0 ? group.chainName : ''}</T>
                </Box>
                {entry.balance === null ? (
                  <T tone="danger">{`${glyph.cross} ${
                    chainProblem(entry.network, entry.error).message
                  }`}</T>
                ) : (
                  <>
                    <Box width={amountWidth} justifyContent="flex-end">
                      {isZeroBalance(entry) ? (
                        <T tone="muted">{displayAmount(entry.balance)}</T>
                      ) : (
                        <T bold>{displayAmount(entry.balance)}</T>
                      )}
                    </Box>
                    {isZeroBalance(entry) ? (
                      <T tone="muted">{` ${entry.symbol}`}</T>
                    ) : (
                      <T>{` ${entry.symbol}`}</T>
                    )}
                  </>
                )}
              </Box>
            ))
          )}
        </Box>
      ))}
      {first?.problem ? (
        <T tone="warning">{`${glyph.warning} ${copy.networks.unreadable(unreadable.length)}. ${
          copy.common.next
        }: ${first.problem.next}`}</T>
      ) : null}
    </Box>
  );
}

export function HomeScreen({
  load,
  onAction,
  refreshMs = 30_000,
}: {
  load: () => Promise<HomeData>;
  onAction: (action: HomeAction) => void;
  /** Balances and pending approvals refresh in the background this often. */
  refreshMs?: number;
}) {
  const h = copy.screens.home;
  const state = useAsync(load);
  useInterval(() => state.refresh(), refreshMs, state.status === 'ready');
  const { exit } = useApp();
  const [showTestnets, setShowTestnets] = useState(false);
  useInput((input) => {
    if (input === 'q') {
      onAction('quit');
      exit();
    } else if (input === 'r') {
      state.reload();
    } else if (input === 't') {
      setShowTestnets(!showTestnets);
    }
  });
  const wallet = state.status === 'ready' ? state.value.wallet : null;
  const pending = state.status === 'ready' ? state.value.pendingApprovals : null;
  const k = copy.common.keys;
  return (
    <Screen
      title={h.title}
      {...(wallet?.evm_address ? { aside: shortAddress(wallet.evm_address) } : {})}
      hints={[
        k.select,
        k.open,
        k.refresh,
        ...(wallet?.balances.some((b) => isTestnetChain(b.chain_id))
          ? [showTestnets ? k.hideTestnets : k.showTestnets]
          : []),
        k.quit,
      ]}
      error={state.status === 'error' ? state.error : null}
    >
      {state.status === 'loading' ? <Spinner label={copy.common.loading} /> : null}
      {wallet ? (
        <Rows
          rows={[
            ...(wallet.evm_address
              ? [{ label: copy.commands.wallet.evm, value: wallet.evm_address }]
              : []),
            ...(wallet.solana_address
              ? [{ label: copy.commands.wallet.solana, value: wallet.solana_address }]
              : []),
          ]}
        />
      ) : null}
      {state.status === 'ready' && state.value.security ? (
        <SecurityLine security={state.value.security} />
      ) : null}
      {state.status === 'ready' ? (
        <Balances data={state.value} showTestnets={showTestnets} />
      ) : null}
      {pending ? <T tone="warning" bold>{`${glyph.warning} ${h.pendingBadge(pending)}`}</T> : null}
      <Menu<HomeAction>
        items={[
          { value: 'receive', label: h.actions.receive, hint: h.actions.receiveHint },
          { value: 'send', label: h.actions.send, hint: h.actions.sendHint },
          {
            value: 'approvals',
            label: pending ? `${h.actions.approvals} (${pending})` : h.actions.approvals,
            hint: h.actions.approvalsHint,
          },
          { value: 'activity', label: h.actions.activity, hint: h.actions.activityHint },
          { value: 'limits', label: h.actions.limits, hint: h.actions.limitsHint },
          { value: 'wallet', label: h.actions.wallet, hint: h.actions.walletHint },
          { value: 'security', label: h.actions.security, hint: h.actions.securityHint },
          { value: 'quit', label: h.actions.quit },
        ]}
        onSelect={(action) => {
          onAction(action);
          if (action === 'quit') {
            exit();
          }
        }}
      />
    </Screen>
  );
}
