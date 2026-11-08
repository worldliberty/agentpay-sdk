/**
 * Send: pick what to send (each with its balance), the recipient, the amount, review, send. The
 * payment goes through the agent key, so it follows the same limits as the agents: within them
 * it goes out at once; above them it waits for approval, and the screen offers to approve it
 * right away (Touch ID or sudo) or leave it in Approvals.
 */
import { Box } from 'ink';
import { useState } from 'react';
import { copy, type Guidance } from '../copy/index.js';
import { guidanceFor } from '../errors.js';
import { compareDecimal, displayAmount } from '../format/amount.js';
import {
  amountProblem,
  maxAmount,
  recipientProblem,
  type SendOption,
  type SendOutcome,
} from '../format/send.js';
import { shortAddress } from '../format/text.js';
import { Menu, Spinner, TextField } from '../ui/controls.js';
import { useInput } from '../ui/input.js';
import { ErrorPanel, Rows, Screen } from '../ui/layout.js';
import { glyph, T } from '../ui/theme.js';
import type { SendServices } from './types.js';
import { useAsync } from './use-async.js';

type Step = 'pick' | 'to' | 'amount' | 'review' | 'sending' | 'result' | 'approving';

/** `false` when the wallet holds none of it; `null` when the balance could not be read. */
function sendable(option: SendOption): boolean | null {
  return option.balance === null ? null : compareDecimal(option.balance, '0') > 0;
}

export function SendScreen({ services, onBack }: { services: SendServices; onBack: () => void }) {
  const s = copy.screens.send;
  const k = copy.common.keys;
  const loaded = useAsync(() => services.loadSend());
  const [step, setStep] = useState<Step>('pick');
  const [option, setOption] = useState<SendOption | null>(null);
  const [to, setTo] = useState('');
  const [amount, setAmount] = useState('');
  const [problem, setProblem] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<SendOutcome | null>(null);
  const [error, setError] = useState<Guidance | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const data = loaded.status === 'ready' ? loaded.value : null;

  const back: Partial<Record<Step, Step>> = { to: 'pick', amount: 'to', review: 'amount' };
  useInput(
    (input, key) => {
      if (key.escape || (input === 'q' && step === 'pick')) {
        const previous = back[step];
        setProblem(null);
        if (previous) {
          setStep(previous);
        } else {
          onBack();
        }
      } else if (input === 'm' && step === 'amount' && option) {
        setAmount(maxAmount(option) ?? '');
        setProblem(null);
      } else if (input === 'r' && loaded.status === 'error') {
        loaded.reload();
      }
    },
    { isActive: step !== 'sending' && step !== 'approving' && step !== 'result' },
  );

  const restart = () => {
    setTo('');
    setAmount('');
    setOutcome(null);
    setError(null);
    setNotice(null);
    setStep('pick');
    loaded.refresh();
  };

  const run = async (work: () => Promise<SendOutcome>, busy: Step) => {
    setStep(busy);
    setError(null);
    try {
      setOutcome(await work());
    } catch (failure) {
      setError(guidanceFor(failure));
    }
    setStep('result');
  };

  const shown = option ? `${displayAmount(amount)} ${option.symbol}` : '';
  const hints =
    step === 'pick'
      ? [k.select, k.confirm, k.back]
      : step === 'to' || step === 'amount'
        ? [k.type, k.continue, k.back]
        : step === 'review'
          ? [k.select, k.confirm, k.back]
          : step === 'result'
            ? [k.select, k.confirm]
            : [];

  return (
    <Screen
      title={step === 'review' ? s.reviewTitle : s.title}
      hints={hints}
      error={loaded.status === 'error' ? loaded.error : null}
    >
      {loaded.status === 'loading' ? <Spinner label={copy.common.loading} /> : null}

      {data && step === 'pick' ? (
        <Box flexDirection="column" gap={1}>
          <T>{s.pickBody}</T>
          {data.options.every((candidate) => sendable(candidate) === false) ? (
            <T tone="warning">{`${glyph.warning} ${s.nothingToSend}`}</T>
          ) : null}
          <Menu
            initial={Math.max(
              0,
              data.options.findIndex((candidate) => sendable(candidate) !== false),
            )}
            items={data.options.map((candidate) => ({
              value: candidate.id,
              label: s.option(candidate.symbol, candidate.networkName),
              hint:
                candidate.balance === null
                  ? s.unknownBalance
                  : s.available(displayAmount(candidate.balance)),
              disabled: sendable(candidate) === false,
            }))}
            onSelect={(id) => {
              setOption(data.options.find((candidate) => candidate.id === id) ?? null);
              setStep('to');
            }}
          />
        </Box>
      ) : null}

      {option && (step === 'to' || step === 'amount') ? (
        <Box flexDirection="column" gap={1}>
          <T bold>{s.option(option.symbol, option.networkName)}</T>
          <TextField
            label={s.to}
            hint={option.family === 'evm' ? s.toEvmHint : s.toSolanaHint}
            value={to}
            onChange={(value) => {
              setTo(value);
              setProblem(null);
            }}
            isActive={step === 'to'}
            onSubmit={() => {
              const why = recipientProblem(option, to, data?.ownAddresses ?? []);
              setProblem(why);
              if (!why) {
                setStep('amount');
              }
            }}
          />
          {step === 'amount' ? (
            <TextField
              label={s.amount}
              hint={s.amountHint(option.symbol)}
              value={amount}
              onChange={(value) => {
                setAmount(value.replace(/[^0-9.]/gu, ''));
                setProblem(null);
              }}
              onSubmit={() => {
                const why = amountProblem(option, amount);
                setProblem(why);
                if (!why) {
                  setStep('review');
                }
              }}
            />
          ) : null}
          {step === 'amount' && option.native ? (
            <T tone="muted">{s.feeNote(option.symbol)}</T>
          ) : null}
          {problem ? <T tone="danger">{`${glyph.cross} ${problem}`}</T> : null}
        </Box>
      ) : null}

      {option && step === 'review' ? (
        <Box flexDirection="column" gap={1}>
          <Rows
            rows={[
              { label: s.to, value: to.trim(), tone: 'accent' },
              { label: s.amount, value: shown },
              { label: s.network, value: option.networkName },
            ]}
          />
          <T tone="muted">{s.limitsNote}</T>
          <Menu
            items={[
              { value: 'send', label: s.confirm },
              { value: 'cancel', label: s.cancel },
            ]}
            onSelect={(value) =>
              value === 'send'
                ? void run(() => services.send(option, to, amount), 'sending')
                : setStep('amount')
            }
          />
        </Box>
      ) : null}

      {step === 'sending' ? <Spinner label={s.sending} /> : null}
      {step === 'approving' ? <Spinner label={s.approving} /> : null}

      {step === 'result' && option ? (
        <Box flexDirection="column" gap={1}>
          {error ? <ErrorPanel guidance={error} /> : null}
          {outcome?.kind === 'sent' ? (
            <>
              <T tone={outcome.failed ? 'danger' : 'success'} bold>
                {outcome.failed
                  ? `${glyph.cross} ${s.failedOnChain}`
                  : `${glyph.check} ${s.sent(shown, shortAddress(to.trim()))}`}
              </T>
              <Rows rows={[{ label: s.transaction, value: outcome.hash }]} />
              {outcome.failed ? null : (
                <T tone="muted">{outcome.confirmed ? s.confirmedOnChain : s.submitted}</T>
              )}
            </>
          ) : null}
          {outcome?.kind === 'pending' ? (
            <>
              <T tone="warning" bold>{`${glyph.warning} ${s.waitingTitle}`}</T>
              <T>{s.waitingBody}</T>
              {outcome.reasons.map((reason) => (
                <T key={reason} tone="muted">{`  ${reason}`}</T>
              ))}
            </>
          ) : null}
          {notice ? <T tone="muted">{notice}</T> : null}
          <Menu
            items={[
              ...(outcome?.kind === 'pending' && !notice
                ? [
                    { value: 'approve', label: s.approveNow },
                    { value: 'later', label: s.later },
                  ]
                : [
                    { value: 'again', label: s.sendAnother },
                    { value: 'done', label: s.done },
                  ]),
            ]}
            onSelect={(value) => {
              if (value === 'approve' && outcome?.kind === 'pending') {
                const id = outcome.approvalRequestId;
                void run(() => services.approveAndSend(id), 'approving');
              } else if (value === 'later') {
                setNotice(s.left);
              } else if (value === 'again') {
                restart();
              } else {
                onBack();
              }
            }}
          />
        </Box>
      ) : null}
    </Screen>
  );
}
