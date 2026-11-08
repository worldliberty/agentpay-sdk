/**
 * The guided first-run flow, one focused step per screen with a step indicator (Phantom /
 * Family onboarding): welcome → Touch ID → spending limits (where tokens can be added) →
 * creating the wallet → backup → done (and optionally add funds). Nothing advances on a timer.
 *
 * Creating or restoring never replaces a wallet already on the machine unless the user, warned
 * by the overwrite step, typed the confirmation word; otherwise they keep the existing wallet,
 * picking which one when the machine has several. Keeping it from the welcome step works the
 * same way: the wallets on the machine are listed by address, and several mean a picker.
 */
import { Box, useApp } from 'ink';
import { useEffect, useState } from 'react';
import { copy } from '../../copy/index.js';
import {
  hasOrderProblem,
  isTestnetRow,
  type LimitRow,
  setCount,
  undecidedCount,
} from '../../limits/model.js';
import { Menu, Spinner } from '../../ui/controls.js';
import { useInput } from '../../ui/input.js';
import { ErrorPanel, Rows, Screen } from '../../ui/layout.js';
import { T } from '../../ui/theme.js';
import type { AddTokenMode } from '../AddTokenForm.js';
import { BackupForm, backupHints } from '../BackupForm.js';
import { LimitsWithTokens, limitsTableHints } from '../LimitsWithTokens.js';
import { ReceiveScreen } from '../Receive.js';
import type { OnboardingServices, WalletChoice, WalletCreated } from '../types.js';
import { useAsync } from '../use-async.js';
import { CreatingStep } from './CreatingStep.js';
import {
  type OverwriteMode,
  OverwriteStep,
  overwriteHints,
  TouchIdStep,
  WalletPickerStep,
  WelcomeStep,
  WithExistingWallets,
  walletPickerHints,
} from './steps.js';

type StepName = 'welcome' | 'touchId' | 'limits' | 'creating' | 'backup' | 'done';
const STEPS: readonly StepName[] = ['welcome', 'touchId', 'limits', 'creating', 'backup', 'done'];

export interface OnboardingResult {
  wallet: WalletCreated | null;
  touchId: boolean;
  backupPath: string | null;
}

/**
 * Spending limits, chosen before the wallet exists: they are applied atomically with it, and
 * tokens can be added right here (`a`). Test networks are not shown: they stay blocked until
 * enabled later on the Limits screen.
 */
function LimitsStep({
  services,
  onReady,
  onAddingChange,
  onEditingChange,
}: {
  services: Pick<OnboardingServices, 'loadLimits' | 'tokenNetworks' | 'lookupToken'>;
  onReady: (rows: LimitRow[]) => void;
  onAddingChange: (mode: AddTokenMode | null) => void;
  onEditingChange: (editing: boolean) => void;
}) {
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState(false);
  const l = copy.onboarding.limits;
  const loaded = useAsync(() => services.loadLimits());
  const [rows, setRows] = useState<LimitRow[] | null>(null);
  const loadedRows = loaded.status === 'ready' ? loaded.value : null;
  useEffect(() => {
    if (loadedRows) {
      setRows(loadedRows.filter((row) => !isTestnetRow(row)));
    }
  }, [loadedRows]);
  const blockedTestnets = (): LimitRow[] =>
    (loadedRows ?? [])
      .filter(isTestnetRow)
      .map((row): LimitRow => ({ ...row, status: 'excluded' }));

  const ready =
    rows !== null &&
    undecidedCount(rows) === 0 &&
    setCount(rows) > 0 &&
    !rows.some(hasOrderProblem);
  useInput(
    (input, key) => {
      if (key.return && ready && rows) {
        onReady([...rows, ...blockedTestnets()]);
      } else if (input === 'r' && loaded.status === 'error') {
        loaded.reload();
      }
    },
    { isActive: !adding && !editing },
  );
  return (
    <Box flexDirection="column" gap={1}>
      <T>{l.body}</T>
      {loaded.status === 'loading' ? <Spinner label={copy.common.loading} /> : null}
      {loaded.status === 'error' ? <ErrorPanel guidance={loaded.error} /> : null}
      {rows ? (
        <LimitsWithTokens
          rows={rows}
          onChange={setRows}
          services={services}
          onAddingChange={(mode) => {
            setAdding(mode !== null);
            onAddingChange(mode);
          }}
          onEditingChange={(next) => {
            setEditing(next);
            onEditingChange(next);
          }}
        />
      ) : null}
      {!adding && rows && undecidedCount(rows) === 0 && setCount(rows) === 0 ? (
        <T tone="warning">{l.atLeastOne}</T>
      ) : null}
    </Box>
  );
}

export function OnboardingWizard({
  services,
  onFinish,
}: {
  services: OnboardingServices;
  onFinish?: (result: OnboardingResult) => void;
}) {
  const o = copy.onboarding;
  const k = copy.common.keys;
  const { exit } = useApp();
  const [step, setStep] = useState<StepName>('welcome');
  const [choice, setChoice] = useState<WalletChoice>({ kind: 'create', replaceExisting: false });
  /** The wallets already on the machine, while the overwrite warning is shown. */
  const [existingWallets, setExistingWallets] = useState<string[] | null>(null);
  const [overwriteMode, setOverwriteMode] = useState<OverwriteMode>('choose');
  /** Whether the user is picking which of several existing wallets to keep. */
  const [pickingWallet, setPickingWallet] = useState(false);
  /** The same, from the welcome step's "Keep the existing wallet". */
  const [welcomePicking, setWelcomePicking] = useState(false);
  const [rows, setRows] = useState<LimitRow[]>([]);
  const [touchId, setTouchId] = useState(false);
  const [wallet, setWallet] = useState<WalletCreated | null>(null);
  const [backupPath, setBackupPath] = useState<string | null>(null);
  const [backupMode, setBackupMode] = useState<'choose' | 'form'>('choose');
  const [backupKeyHints, setBackupKeyHints] = useState<string[]>(backupHints('path'));
  const [funding, setFunding] = useState(false);
  const [addingToken, setAddingToken] = useState<AddTokenMode | null>(null);
  const [editingLimit, setEditingLimit] = useState(false);

  const keepWallet = (vaultKeyId: string | undefined) => {
    setChoice(vaultKeyId ? { kind: 'reuse', vaultKeyId } : { kind: 'reuse' });
    setPickingWallet(false);
    setExistingWallets(null);
  };

  const finish = () => {
    onFinish?.({ wallet, touchId, backupPath });
    exit();
  };

  if (funding) {
    return (
      <ReceiveScreen
        options={() => services.receiveOptions()}
        load={(choice) => services.funding(choice?.network, choice?.asset)}
        watch={(choice) => services.balance(choice?.network, choice?.asset)}
        onBack={() => setFunding(false)}
      />
    );
  }

  const index = STEPS.indexOf(step);
  const stepInfo = { index, total: STEPS.length, label: o.steps[index] ?? '' };
  const hintsFor: Record<StepName, readonly string[]> = {
    welcome: welcomePicking ? walletPickerHints() : [k.select, k.continue],
    touchId: [k.select, k.confirm],
    creating: existingWallets
      ? pickingWallet
        ? walletPickerHints()
        : overwriteHints(overwriteMode)
      : [k.continue],
    limits:
      addingToken || editingLimit
        ? limitsTableHints(addingToken, editingLimit)
        : [...limitsTableHints(null, false, { blockRest: true }), k.continue],
    backup: backupMode === 'form' ? backupKeyHints : [k.select, k.confirm],
    done: [k.select, k.confirm],
  };
  const titles: Record<StepName, string> = {
    welcome: welcomePicking ? o.pickWallet.title : o.welcome.title,
    touchId: o.touchId.title,
    creating: existingWallets
      ? pickingWallet
        ? o.pickWallet.title
        : o.overwrite.title
      : choice.kind === 'restore'
        ? o.creating.restoringTitle
        : choice.kind === 'reuse'
          ? o.creating.reusingTitle
          : o.creating.title,
    limits: o.limits.title,
    backup: o.backup.title,
    done: o.done.title,
  };

  return (
    <Screen title={titles[step]} step={stepInfo} hints={hintsFor[step]}>
      {step === 'welcome' ? (
        <WelcomeStep
          services={services}
          onPickingChange={setWelcomePicking}
          onChoose={(chosen) => {
            setWelcomePicking(false);
            setChoice(chosen);
            setStep('touchId');
          }}
        />
      ) : null}
      {step === 'touchId' ? (
        <TouchIdStep
          services={services}
          onContinue={(enabled) => {
            setTouchId(enabled);
            setStep('limits');
          }}
        />
      ) : null}
      {step === 'creating' && existingWallets && choice.kind !== 'reuse' ? (
        <WithExistingWallets ids={existingWallets} services={services}>
          {(wallets) =>
            pickingWallet ? (
              <WalletPickerStep
                wallets={wallets}
                currentAgentKeyId={services.currentAgentKeyId()}
                onPick={keepWallet}
                onBack={() => setPickingWallet(false)}
              />
            ) : (
              <OverwriteStep
                wallets={wallets}
                replacing={choice.kind === 'restore' ? 'restore' : 'create'}
                onModeChange={setOverwriteMode}
                onKeep={() => {
                  // Keeping is ambiguous with several wallets: ask which one.
                  const [only, ...others] = wallets;
                  if (others.length > 0) {
                    setPickingWallet(true);
                  } else {
                    keepWallet(only?.vaultKeyId);
                  }
                }}
                onOverwrite={() => {
                  setChoice({ ...choice, replaceExisting: true });
                  setExistingWallets(null);
                }}
              />
            )
          }
        </WithExistingWallets>
      ) : null}
      {step === 'creating' && !existingWallets ? (
        <CreatingStep
          services={services}
          choice={choice}
          rows={rows}
          onCreated={(created) => {
            setWallet(created);
            setStep('backup');
          }}
          onWalletExists={(ids) => {
            setOverwriteMode('choose');
            setExistingWallets(ids);
          }}
        />
      ) : null}
      {step === 'limits' ? (
        <LimitsStep
          services={services}
          onAddingChange={setAddingToken}
          onEditingChange={setEditingLimit}
          onReady={(chosen) => {
            setRows(chosen);
            setStep('creating');
          }}
        />
      ) : null}
      {step === 'backup' && backupMode === 'choose' ? (
        <Box flexDirection="column" gap={1}>
          <T>{o.backup.body}</T>
          <Menu
            items={[
              { value: 'form', label: o.backup.export },
              { value: 'skip', label: o.backup.skip, hint: o.backup.skipWarning },
            ]}
            onSelect={(value) => (value === 'form' ? setBackupMode('form') : setStep('done'))}
          />
        </Box>
      ) : null}
      {step === 'backup' && backupMode === 'form' ? (
        <BackupForm
          services={services}
          allowSkip={false}
          onFieldChange={(field) => setBackupKeyHints(backupHints(field))}
          onBack={() => setBackupMode('choose')}
          onDone={(path) => {
            setBackupPath(path);
            setStep('done');
          }}
        />
      ) : null}
      {step === 'done' ? (
        <Box flexDirection="column" gap={1}>
          <T>{o.done.body}</T>
          {wallet?.evmAddress || wallet?.solanaAddress ? (
            <Rows
              rows={[
                ...(wallet.evmAddress
                  ? [{ label: o.done.address, value: wallet.evmAddress, tone: 'accent' as const }]
                  : []),
                ...(wallet.solanaAddress
                  ? [{ label: copy.commands.wallet.solana, value: wallet.solanaAddress }]
                  : []),
              ]}
            />
          ) : null}
          <Box flexDirection="column">
            {o.done.nextSteps.map((line) => (
              <T key={line} tone="muted">
                {line}
              </T>
            ))}
          </Box>
          <Menu
            items={[
              { value: 'fund', label: o.done.fund },
              { value: 'finish', label: o.done.finish },
            ]}
            onSelect={(value) => (value === 'fund' ? setFunding(true) : finish())}
          />
        </Box>
      ) : null}
    </Screen>
  );
}
