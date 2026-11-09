/** "Creating your wallet" (Coinbase Wallet pattern): a checklist that fills in as it runs. */
import { Box } from 'ink';
import { useEffect, useState } from 'react';
import { copy, type Guidance } from '../../copy/index.js';
import { existingWalletIds, guidanceFor } from '../../errors.js';
import type { LimitRow } from '../../limits/model.js';
import { TaskList, type TaskState } from '../../ui/controls.js';
import { useInput } from '../../ui/input.js';
import { ErrorPanel } from '../../ui/layout.js';
import { glyph, T } from '../../ui/theme.js';
import type { CreateTask, OnboardingServices, WalletChoice, WalletCreated } from '../types.js';

const ORDER: readonly CreateTask[] = ['keys', 'agent', 'store', 'tokens'];

export function CreatingStep({
  services,
  choice,
  rows,
  onCreated,
  onWalletExists,
}: {
  services: Pick<OnboardingServices, 'createWallet'>;
  choice: WalletChoice;
  rows: readonly LimitRow[];
  onCreated: (wallet: WalletCreated) => void;
  /** The daemon refused to replace these wallets; the parent asks what to do. */
  onWalletExists: (vaultKeyIds: string[]) => void;
}) {
  const c = copy.onboarding.creating;
  const [current, setCurrent] = useState<CreateTask>('keys');
  const [result, setResult] = useState<WalletCreated | null>(null);
  const [error, setError] = useState<Guidance | null>(null);
  const [attempt, setAttempt] = useState(0);

  // biome-ignore lint/correctness/useExhaustiveDependencies: `attempt` re-runs creation on retry.
  useEffect(() => {
    let cancelled = false;
    setError(null);
    setCurrent('keys');
    services
      .createWallet(choice, rows, (task) => !cancelled && setCurrent(task))
      .then(
        (wallet) => !cancelled && setResult(wallet),
        (failure: unknown) => {
          if (cancelled) {
            return;
          }
          const existing = existingWalletIds(failure);
          if (existing) {
            onWalletExists(existing);
          } else {
            setError(guidanceFor(failure));
          }
        },
      );
    return () => {
      cancelled = true;
    };
  }, [attempt]);

  useInput((input, key) => {
    if (result && key.return) {
      onCreated(result);
    } else if (error && input === 'r') {
      setAttempt((a) => a + 1);
    }
  });

  const position = ORDER.indexOf(current);
  const stateOf = (task: CreateTask): TaskState => {
    if (result) {
      return 'done';
    }
    const index = ORDER.indexOf(task);
    if (index < position) {
      return 'done';
    }
    if (index > position) {
      return 'pending';
    }
    return error ? 'failed' : 'running';
  };
  return (
    <Box flexDirection="column" gap={1}>
      <TaskList
        tasks={[
          {
            label:
              choice.kind === 'restore'
                ? c.tasks.restore
                : choice.kind === 'reuse'
                  ? c.tasks.reuse
                  : c.tasks.keys,
            state: stateOf('keys'),
          },
          { label: c.tasks.agent, state: stateOf('agent') },
          { label: c.tasks.store, state: stateOf('store') },
          ...(rows.some((row) => row.newToken)
            ? [{ label: c.tasks.tokens, state: stateOf('tokens') }]
            : []),
        ]}
      />
      {result ? <T tone="success" bold>{`${glyph.check} ${c.ready}`}</T> : null}
      {result?.unsavedTokens?.length ? (
        <T tone="warning">{`${glyph.warning} ${c.unsavedTokens(result.unsavedTokens.join(', '))}`}</T>
      ) : null}
      {error ? <ErrorPanel guidance={error} /> : null}
    </Box>
  );
}
