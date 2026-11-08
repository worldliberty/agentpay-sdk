/**
 * Receive / fund (Public "receive" pattern): pick the token and network, then the QR code, the
 * address, the network, and "Important things to know" before anyone sends money.
 */
import { Box, Text } from 'ink';
import { useEffect, useState } from 'react';
import { copy } from '../copy/index.js';
import { displayAmount, formatUnits } from '../format/amount.js';
import type { ReceiveOption } from '../format/receive.js';
import type { FundingRequestResult, WalletBalanceEntry } from '../generated/index.js';
import { Menu, Spinner } from '../ui/controls.js';
import { useInput } from '../ui/input.js';
import { Callout, Rows, Screen } from '../ui/layout.js';
import { glyph, T } from '../ui/theme.js';
import { useAsync, useInterval } from './use-async.js';

/**
 * Watches one balance while the funding details are open: the first read is the baseline, and
 * anything above it is shown as received. Read failures are ignored (the next poll retries).
 */
function FundsWatcher({
  watch,
  pollMs,
}: {
  watch: () => Promise<WalletBalanceEntry>;
  pollMs: number;
}) {
  const r = copy.screens.receive;
  const [baseline, setBaseline] = useState<bigint | null>(null);
  const [latest, setLatest] = useState<WalletBalanceEntry | null>(null);
  const poll = () => {
    watch().then(
      (entry) => {
        if (entry.balance_base_units === null) {
          return;
        }
        const units = BigInt(entry.balance_base_units);
        setBaseline((current) => current ?? units);
        setLatest(entry);
      },
      () => {},
    );
  };
  // biome-ignore lint/correctness/useExhaustiveDependencies: the first read is the baseline.
  useEffect(poll, []);
  useInterval(poll, pollMs);
  const received =
    latest && baseline !== null && latest.balance_base_units !== null
      ? BigInt(latest.balance_base_units) - baseline
      : 0n;
  if (received > 0n && latest) {
    return (
      <T tone="success" bold>
        {`${glyph.check} ${r.received(displayAmount(formatUnits(received, latest.decimals)), latest.symbol)}`}
      </T>
    );
  }
  return <Spinner label={r.waiting} />;
}

export function ReceiveView({ funding }: { funding: FundingRequestResult }) {
  const s = copy.screens.receive;
  const important = [...s.important(funding.symbol, funding.chain_name)];
  important.push(funding.gas ? funding.gas.note : s.noGas);
  return (
    <>
      {funding.qr ? (
        <Box flexDirection="column">
          {funding.qr.terminal.split('\n').map((line, index) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: QR lines are static and positional.
            <Text key={index}>{line}</Text>
          ))}
        </Box>
      ) : null}
      <Rows
        rows={[
          { label: s.address, value: funding.address, tone: 'accent' },
          { label: s.network, value: `${funding.chain_name} (chain ${funding.chain_id})` },
          {
            label: s.asset,
            value: funding.token ? `${funding.symbol} · ${funding.token}` : funding.symbol,
          },
        ]}
      />
      <Callout title={s.importantTitle} items={important} />
    </>
  );
}

/** The funding details for one choice. `esc` goes back to the choices (or out, with one). */
function FundingDetails({
  load,
  watch,
  pollMs,
  onBack,
  backHint,
}: {
  load: () => Promise<FundingRequestResult>;
  watch: (() => Promise<WalletBalanceEntry>) | undefined;
  pollMs: number;
  onBack: () => void;
  backHint: string;
}) {
  const state = useAsync(load);
  useInput((input, key) => {
    if (key.escape || key.return || input === 'q') {
      onBack();
    } else if (input === 'r' && state.status === 'error') {
      state.reload();
    }
  });
  const title =
    state.status === 'ready'
      ? copy.screens.receive.title(state.value.symbol)
      : copy.screens.receive.title('');
  return (
    <Screen
      title={title.trim()}
      hints={state.status === 'error' ? [copy.common.keys.retry, backHint] : [backHint]}
      error={state.status === 'error' ? state.error : null}
    >
      {state.status === 'loading' ? <Spinner label={copy.common.loading} /> : null}
      {state.status === 'ready' ? <ReceiveView funding={state.value} /> : null}
      {state.status === 'ready' && watch ? <FundsWatcher watch={watch} pollMs={pollMs} /> : null}
    </Screen>
  );
}

export function ReceiveScreen({
  options,
  load,
  watch,
  pollMs = 5_000,
  onBack,
  backHint = copy.common.keys.back,
}: {
  /** The receivable tokens; when they cannot be read, the default one is shown. */
  options: () => Promise<ReceiveOption[]>;
  /** Funding details; no choice means the configured default network and asset. */
  load: (choice?: ReceiveOption) => Promise<FundingRequestResult>;
  /** Reads the chosen balance, so arriving funds show up while the screen is open. */
  watch?: (choice?: ReceiveOption) => Promise<WalletBalanceEntry>;
  pollMs?: number;
  onBack: () => void;
  backHint?: string;
}) {
  const s = copy.screens.receive;
  const k = copy.common.keys;
  const listed = useAsync(options);
  const [chosen, setChosen] = useState<ReceiveOption | null>(null);
  const [lastIndex, setLastIndex] = useState(0);
  const choices = listed.status === 'ready' ? listed.value : null;
  useInput(
    (input, key) => {
      if (key.escape || input === 'q') {
        onBack();
      }
    },
    { isActive: chosen === null && listed.status !== 'error' },
  );
  if (listed.status === 'error' || (choices && choices.length <= 1)) {
    return (
      <FundingDetails
        load={() => load(choices?.[0])}
        watch={watch ? () => watch(choices?.[0]) : undefined}
        pollMs={pollMs}
        onBack={onBack}
        backHint={backHint}
      />
    );
  }
  if (chosen) {
    return (
      <FundingDetails
        key={chosen.id}
        load={() => load(chosen)}
        watch={watch ? () => watch(chosen) : undefined}
        pollMs={pollMs}
        onBack={() => setChosen(null)}
        backHint={k.back}
      />
    );
  }
  return (
    <Screen title={s.chooseTitle} hints={[k.select, k.open, backHint]}>
      <Box flexDirection="column" gap={1}>
        <Text>{s.chooseBody}</Text>
        {choices ? (
          <Menu
            items={choices.map((choice) => ({
              value: choice.id,
              label: s.option(choice.symbol, choice.networkName),
              ...(choice.testnet ? { hint: s.testnetHint } : {}),
            }))}
            initial={lastIndex}
            onSelect={(id) => {
              const index = choices.findIndex((choice) => choice.id === id);
              setLastIndex(Math.max(index, 0));
              setChosen(choices[index] ?? null);
            }}
          />
        ) : (
          <Spinner label={copy.common.loading} />
        )}
      </Box>
    </Screen>
  );
}
