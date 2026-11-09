/**
 * Encrypted backup export, shared by onboarding and Security. The irreversible part is said
 * plainly and must be acknowledged before exporting (Phantom-style warning).
 */
import { Box, useApp } from 'ink';
import { useState } from 'react';
import { copy, type Guidance } from '../copy/index.js';
import { guidanceFor } from '../errors.js';
import type { WalletInfo } from '../generated/index.js';
import { Menu, Spinner, TextField } from '../ui/controls.js';
import { useInput } from '../ui/input.js';
import { Callout, ErrorPanel, Screen } from '../ui/layout.js';
import { glyph, T } from '../ui/theme.js';
import { existingWallets, WalletPickerStep, walletPickerHints } from './onboarding/steps.js';
import type { BackupServices } from './types.js';

export const MIN_PASSPHRASE_LENGTH = 12;

type Field = 'path' | 'passphrase' | 'confirm' | 'ack' | 'actions';
const ORDER: readonly Field[] = ['path', 'passphrase', 'confirm', 'ack', 'actions'];

export function backupHints(field: Field | 'busy' | 'done'): string[] {
  const k = copy.common.keys;
  switch (field) {
    case 'ack':
      return [k.acknowledge, k.continue, k.back];
    case 'actions':
      return [k.select, k.confirm, k.back];
    case 'busy':
      return [];
    case 'done':
      return [k.continue];
    default:
      return [k.type, k.continue, k.back];
  }
}

export function BackupForm({
  services,
  onDone,
  onBack,
  allowSkip,
  onFieldChange,
}: {
  services: BackupServices;
  /** Called with the written path, or `null` when skipped. */
  onDone: (path: string | null) => void;
  onBack: () => void;
  allowSkip: boolean;
  /** Lets the parent show matching key hints. */
  onFieldChange?: (field: Field | 'busy' | 'done') => void;
}) {
  const b = copy.onboarding.backup;
  const [path, setPath] = useState(() => services.defaultBackupPath());
  const [passphrase, setPassphrase] = useState('');
  const [confirm, setConfirm] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [field, setFieldState] = useState<Field>('path');
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [phase, setPhase] = useState<'form' | 'busy' | 'done'>('form');
  const [error, setError] = useState<Guidance | null>(null);

  const setField = (next: Field) => {
    setFieldState(next);
    onFieldChange?.(next);
  };

  const advance = () => {
    setFieldError(null);
    if (field === 'path' && path.trim() === '') {
      return;
    }
    if (field === 'passphrase' && passphrase.length < MIN_PASSPHRASE_LENGTH) {
      setFieldError(copy.errors.backupPassphraseShort(MIN_PASSPHRASE_LENGTH));
      return;
    }
    if (field === 'confirm' && confirm !== passphrase) {
      setFieldError(copy.errors.backupPassphraseMismatch);
      return;
    }
    if (field === 'ack' && !acknowledged) {
      return;
    }
    const next = ORDER[ORDER.indexOf(field) + 1];
    if (next) {
      setField(next);
    }
  };

  const back = () => {
    setFieldError(null);
    const previous = ORDER[ORDER.indexOf(field) - 1];
    if (previous) {
      setField(previous);
    } else {
      onBack();
    }
  };

  const run = async () => {
    setPhase('busy');
    onFieldChange?.('busy');
    setError(null);
    try {
      await services.exportBackup(path.trim(), passphrase);
      setPhase('done');
      onFieldChange?.('done');
    } catch (failure) {
      setError(guidanceFor(failure));
      setPhase('form');
      setField('actions');
    }
  };

  useInput(
    (input, key) => {
      if (phase === 'done') {
        if (key.return) {
          onDone(path.trim());
        }
        return;
      }
      if (key.escape) {
        back();
      } else if (field === 'ack' && input === ' ') {
        setAcknowledged((value) => !value);
      } else if (field === 'ack' && key.return) {
        advance();
      }
    },
    { isActive: phase !== 'busy' },
  );

  if (phase === 'busy') {
    return <Spinner label={b.exporting} />;
  }
  if (phase === 'done') {
    return <T tone="success">{`${glyph.check} ${b.written(path.trim())}`}</T>;
  }

  const textField = (name: 'path' | 'passphrase' | 'confirm') => ({
    isActive: field === name,
    onSubmit: advance,
    error: field === name ? fieldError : null,
  });

  return (
    <Box flexDirection="column" gap={1}>
      <T>{b.body}</T>
      <TextField label={b.path} value={path} onChange={setPath} {...textField('path')} />
      <TextField
        label={b.passphrase}
        value={passphrase}
        onChange={setPassphrase}
        mask
        hint={b.passphraseHint(MIN_PASSPHRASE_LENGTH)}
        {...textField('passphrase')}
      />
      <TextField
        label={b.confirm}
        value={confirm}
        onChange={setConfirm}
        mask
        {...textField('confirm')}
      />
      <Callout title={b.warningTitle} items={b.warnings}>
        <Box marginTop={1} gap={1}>
          <T tone={field === 'ack' ? 'accent' : 'muted'}>{field === 'ack' ? glyph.pointer : ' '}</T>
          <T tone={acknowledged ? 'success' : 'default'} bold={field === 'ack'}>
            {`[${acknowledged ? 'x' : ' '}] ${b.acknowledge}`}
          </T>
        </Box>
      </Callout>
      {field === 'actions' ? (
        <Box flexDirection="column">
          <Menu
            items={[
              { value: 'export', label: b.export },
              ...(allowSkip
                ? [{ value: 'skip' as const, label: b.skip, hint: b.skipWarning }]
                : []),
            ]}
            onSelect={(value) => (value === 'export' ? void run() : onDone(null))}
          />
        </Box>
      ) : null}
      {error ? <ErrorPanel guidance={error} /> : null}
    </Box>
  );
}

/** The backup form on its own screen (`agentpay admin wallet-backup export` in a terminal). */
export function BackupScreen({ services }: { services: BackupServices }) {
  const { exit } = useApp();
  const [hints, setHints] = useState<string[]>(backupHints('path'));
  return (
    <Screen title={copy.onboarding.backup.title} hints={hints}>
      <BackupForm
        services={services}
        allowSkip={false}
        onFieldChange={(field) => setHints(backupHints(field))}
        onBack={() => exit()}
        onDone={() => exit()}
      />
    </Screen>
  );
}

/**
 * "Choose the wallet to back up" (`agentpay admin wallet-backup export` in a terminal, when the
 * machine has several wallets): reports the chosen vault key id, or `null` on esc.
 */
export function BackupWalletPicker({
  wallets,
  onPick,
}: {
  wallets: readonly WalletInfo[];
  onPick: (vaultKeyId: string | null) => void;
}) {
  const { exit } = useApp();
  const p = copy.onboarding.pickWallet;
  const done = (vaultKeyId: string | null) => {
    onPick(vaultKeyId);
    exit();
  };
  return (
    <Screen title={p.backupTitle} hints={walletPickerHints()}>
      <WalletPickerStep
        wallets={existingWallets([], wallets)}
        body={p.backupBody(wallets.length)}
        onPick={done}
        onBack={() => done(null)}
      />
    </Screen>
  );
}
