/**
 * The onboarding steps before the wallet exists: welcome (create, restore, or keep the wallet
 * already on the machine), Touch ID, the overwrite warning shown when the machine already has a
 * wallet, and the wallet picker shown when it has several and the user keeps one. Existing
 * wallets are read with `ListWallets` and shown by address, age, and agent keys.
 */
import { Box } from 'ink';
import { type ReactNode, useState } from 'react';
import { copy, type Guidance } from '../../copy/index.js';
import { guidanceFor } from '../../errors.js';
import { walletLabel } from '../../format/wallets.js';
import type { WalletInfo } from '../../generated/index.js';
import { Menu, Spinner, TextField } from '../../ui/controls.js';
import { useInput } from '../../ui/input.js';
import { Callout, ErrorPanel, Rows } from '../../ui/layout.js';
import { glyph, T } from '../../ui/theme.js';
import type { ExistingWallet, OnboardingServices, WalletChoice } from '../types.js';
import { useAsync } from '../use-async.js';

/** The listed wallets, or the ids the daemon reported when the list could not be read. */
export function existingWallets(
  ids: readonly string[],
  listed: readonly WalletInfo[] | null,
): ExistingWallet[] {
  return listed && listed.length > 0
    ? listed.map((info) => ({ vaultKeyId: info.vault_key_id, info }))
    : ids.map((vaultKeyId) => ({ vaultKeyId, info: null }));
}

/**
 * "Welcome": create, restore, or keep. The wallets on the machine are read first, so keeping
 * shows the wallet it keeps (or asks which one when there are several) and is not offered when
 * there is none. When they cannot be read, keeping leaves the choice to the daemon.
 */
export function WelcomeStep({
  services,
  onChoose,
  onPickingChange,
}: {
  services: Pick<OnboardingServices, 'listWallets' | 'currentAgentKeyId'>;
  onChoose: (choice: WalletChoice) => void;
  /** Lets the parent show the picker's title and key hints. */
  onPickingChange?: (picking: boolean) => void;
}) {
  const w = copy.onboarding.welcome;
  const loaded = useAsync(() => services.listWallets());
  const [mode, setModeState] = useState<'choose' | 'path' | 'passphrase' | 'name' | 'pick'>(
    'choose',
  );
  /** Creating a new wallet, or restoring one, once the name step is reached. */
  const [naming, setNaming] = useState<'create' | 'restore'>('create');
  const [name, setName] = useState('');
  const [path, setPath] = useState('');
  const [passphrase, setPassphrase] = useState('');
  /** Back from the picker, the menu stays on "keep". */
  const [backFromPicker, setBackFromPicker] = useState(false);
  const setMode = (next: typeof mode) => {
    setModeState(next);
    onPickingChange?.(next === 'pick');
  };
  useInput(
    (_input, key) => {
      if (key.escape) {
        setMode(
          mode === 'passphrase' || (mode === 'name' && naming === 'restore')
            ? mode === 'name'
              ? 'passphrase'
              : 'path'
            : 'choose',
        );
      }
    },
    { isActive: mode === 'path' || mode === 'passphrase' || mode === 'name' },
  );
  useInput(
    (input) => {
      if (input === 'r') {
        loaded.reload();
      }
    },
    { isActive: loaded.status === 'error' },
  );
  if (loaded.status === 'loading') {
    return (
      <Box flexDirection="column" gap={1}>
        <T>{w.body}</T>
        <Spinner label={w.checking} />
      </Box>
    );
  }
  // Without the list, "Create" could replace a wallet the user meant to keep: stop here.
  if (loaded.status === 'error') {
    return (
      <Box flexDirection="column" gap={1}>
        <T>{w.body}</T>
        <ErrorPanel guidance={loaded.error} />
        <T tone="muted">{copy.common.keys.retry}</T>
      </Box>
    );
  }
  const wallets = loaded.value;
  if (mode === 'pick') {
    return (
      <WalletPickerStep
        wallets={existingWallets([], wallets)}
        currentAgentKeyId={services.currentAgentKeyId()}
        onPick={(vaultKeyId) => onChoose({ kind: 'reuse', vaultKeyId })}
        onBack={() => {
          setBackFromPicker(true);
          setMode('choose');
        }}
      />
    );
  }
  const [only, ...others] = wallets;
  const keep = () => {
    if (others.length > 0) {
      setMode('pick');
    } else if (only) {
      onChoose({ kind: 'reuse', vaultKeyId: only.vault_key_id });
    }
  };
  const keepHint = !only
    ? w.reuseHint
    : others.length > 0
      ? w.reuseHintMany(wallets.length)
      : walletLabel(only);
  return (
    <Box flexDirection="column" gap={1}>
      <T>{w.body}</T>
      {mode === 'choose' ? (
        <Menu
          items={[
            { value: 'create', label: w.create, hint: w.createHint },
            { value: 'restore', label: w.restore, hint: w.restoreHint },
            ...(only ? [{ value: 'reuse' as const, label: w.reuse, hint: keepHint }] : []),
          ]}
          // With a wallet on the machine, Enter keeps it; creating is a deliberate choice.
          initial={only || backFromPicker ? 2 : 0}
          onSelect={(value) => {
            if (value === 'restore') {
              setMode('path');
            } else if (value === 'reuse') {
              keep();
            } else {
              setNaming('create');
              setMode('name');
            }
          }}
        />
      ) : mode === 'name' ? (
        <TextField
          label={w.nameLabel}
          hint={naming === 'restore' ? w.nameRestoreHint : w.nameHint}
          value={name}
          onChange={(value) => setName(value.slice(0, 32))}
          onSubmit={() => {
            const named = name.trim() ? { name: name.trim() } : {};
            onChoose(
              naming === 'create'
                ? { kind: 'create', replaceExisting: false, ...named }
                : {
                    kind: 'restore',
                    path: path.trim(),
                    passphrase,
                    replaceExisting: false,
                    ...named,
                  },
            );
          }}
        />
      ) : (
        <>
          <TextField
            label={w.restorePath}
            hint={w.restorePathHint}
            value={path}
            onChange={setPath}
            isActive={mode === 'path'}
            onSubmit={() => path.trim() && setMode('passphrase')}
          />
          {mode === 'passphrase' ? (
            <TextField
              label={w.restorePassphrase}
              hint={w.restorePassphraseHint}
              value={passphrase}
              mask
              onChange={setPassphrase}
              onSubmit={() => {
                if (passphrase) {
                  setNaming('restore');
                  setMode('name');
                }
              }}
            />
          ) : null}
        </>
      )}
    </Box>
  );
}

/** "Protect your wallet": explains Touch ID approvals and offers to turn them on. */
export function TouchIdStep({
  services,
  onContinue,
}: {
  services: Pick<OnboardingServices, 'touchIdState' | 'enableTouchId'>;
  onContinue: (enabled: boolean) => void;
}) {
  const t = copy.onboarding.touchId;
  const state = useAsync(() => services.touchIdState());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Guidance | null>(null);

  const enable = async () => {
    setBusy(true);
    setError(null);
    try {
      await services.enableTouchId();
      onContinue(true);
    } catch (failure) {
      setError(guidanceFor(failure));
      setBusy(false);
    }
  };

  if (state.status === 'loading') {
    return <Spinner label={copy.common.loading} />;
  }
  if (state.status === 'ready' && state.value === 'on') {
    return (
      <Box flexDirection="column" gap={1}>
        <T tone="success">{`${glyph.check} ${t.enrolled}`}</T>
        <Menu
          items={[{ value: 'continue', label: t.continue }]}
          onSelect={() => onContinue(true)}
        />
      </Box>
    );
  }
  if (state.status === 'error' || state.value === 'unavailable') {
    return (
      <Box flexDirection="column" gap={1}>
        <T bold>{t.unavailableTitle}</T>
        <T>{t.unavailableBody}</T>
        <Menu
          items={[{ value: 'continue', label: t.continue }]}
          onSelect={() => onContinue(false)}
        />
      </Box>
    );
  }
  return (
    <Box flexDirection="column" gap={1}>
      <T>{t.body}</T>
      <Box flexDirection="column">
        {t.benefits.map((benefit) => (
          <T key={benefit}>{`${glyph.check} ${benefit}`}</T>
        ))}
      </Box>
      {busy ? (
        <Box flexDirection="column">
          <Spinner label={t.enabling} />
          <T tone="muted">{t.sudoNote}</T>
        </Box>
      ) : (
        <Menu
          items={[
            { value: 'enable', label: t.enable },
            { value: 'skip', label: t.skip },
          ]}
          onSelect={(value) => (value === 'enable' ? void enable() : onContinue(false))}
        />
      )}
      {error ? <ErrorPanel guidance={error} /> : null}
    </Box>
  );
}

export type OverwriteMode = 'choose' | 'confirm';

export function overwriteHints(mode: OverwriteMode): string[] {
  const k = copy.common.keys;
  return mode === 'confirm' ? [k.type, k.confirm, k.back] : [k.select, k.confirm];
}

/**
 * Reads the wallets the daemon refused to replace (`ListWallets`) before the overwrite warning
 * and the picker show them; falls back to the reported ids when the list cannot be read.
 */
export function WithExistingWallets({
  ids,
  services,
  children,
}: {
  ids: readonly string[];
  services: Pick<OnboardingServices, 'listWallets'>;
  children: (wallets: ExistingWallet[]) => ReactNode;
}) {
  const loaded = useAsync(() => services.listWallets());
  if (loaded.status === 'loading') {
    return <Spinner label={copy.onboarding.overwrite.checking} />;
  }
  return <>{children(existingWallets(ids, loaded.status === 'ready' ? loaded.value : null))}</>;
}

/**
 * "A wallet already exists": the daemon refused to replace it (`WalletAlreadyExists`). Keeping
 * it is the default; replacing it deletes it, so it needs the confirmation word typed exactly.
 */
export function OverwriteStep({
  wallets,
  replacing,
  onKeep,
  onOverwrite,
  onModeChange,
}: {
  wallets: readonly ExistingWallet[];
  /** What would replace the existing wallet. */
  replacing: 'create' | 'restore';
  onKeep: () => void;
  onOverwrite: () => void;
  /** Lets the parent show matching key hints. */
  onModeChange?: (mode: OverwriteMode) => void;
}) {
  const o = copy.onboarding.overwrite;
  const [mode, setModeState] = useState<OverwriteMode>('choose');
  const [typed, setTyped] = useState('');
  const [mismatch, setMismatch] = useState(false);
  const setMode = (next: OverwriteMode) => {
    setModeState(next);
    setTyped('');
    setMismatch(false);
    onModeChange?.(next);
  };
  useInput(
    (_input, key) => {
      if (key.escape) {
        setMode('choose');
      }
    },
    { isActive: mode === 'confirm' },
  );
  return (
    <Box flexDirection="column" gap={1}>
      <Box flexDirection="column">
        <T>{o.body(wallets.length)}</T>
        {wallets.map(({ vaultKeyId, info }) => (
          <T key={vaultKeyId} tone="muted">{`  ${info ? walletLabel(info) : vaultKeyId}`}</T>
        ))}
      </Box>
      <Callout title={o.warningTitle} items={o.warnings} tone="danger" />
      {mode === 'choose' ? (
        <Menu
          items={[
            { value: 'keep', label: o.keep, hint: o.keepHint },
            {
              value: 'replace',
              label: replacing === 'restore' ? o.replaceWithBackup : o.replaceWithNew,
            },
          ]}
          onSelect={(value) => (value === 'keep' ? onKeep() : setMode('confirm'))}
        />
      ) : (
        <TextField
          label={o.confirmLabel}
          hint={o.confirmHint}
          error={mismatch ? o.confirmMismatch : null}
          value={typed}
          onChange={(value) => {
            setTyped(value);
            setMismatch(false);
          }}
          onSubmit={() => (typed.trim() === o.confirmWord ? onOverwrite() : setMismatch(true))}
        />
      )}
    </Box>
  );
}

export function walletPickerHints(): string[] {
  const k = copy.common.keys;
  return [k.select, k.confirm, k.back];
}

/**
 * "Choose the wallet to keep": keeping the existing wallet is ambiguous when the machine has
 * several, so the user picks one, by address, creation date, and agent keys
 * (`0x2c75…5c23 · created 2026-11-05 · 1 agent key`). Without the wallet list only the vault key
 * ids are known, and those are shown instead.
 */
export function WalletPickerStep({
  wallets,
  body,
  currentAgentKeyId = null,
  onPick,
  onBack,
}: {
  wallets: readonly ExistingWallet[];
  /** What the choice is for; keeping a wallet for the agents by default. */
  body?: string;
  /** The agent key this user set up last: its wallet is marked and selected first. */
  currentAgentKeyId?: string | null;
  onPick: (vaultKeyId: string) => void;
  onBack: () => void;
}) {
  const p = copy.onboarding.pickWallet;
  const w = copy.screens.wallets;
  const current = currentAgentKeyId
    ? wallets.findIndex(({ info }) => info?.agent_key_ids.includes(currentAgentKeyId))
    : -1;
  /** A different wallet than the agents use now, waiting for the user to confirm the move. */
  const [confirming, setConfirming] = useState<ExistingWallet | null>(null);
  useInput((_input, key) => {
    if (key.escape) {
      if (confirming) {
        setConfirming(null);
      } else {
        onBack();
      }
    }
  });
  const label = (wallet: ExistingWallet) =>
    wallet.info ? walletLabel(wallet.info) : wallet.vaultKeyId;
  const currentWallet = wallets[current];
  if (confirming && currentWallet) {
    return (
      <Box flexDirection="column" gap={1}>
        <T bold>{w.confirmTitle}</T>
        <Rows
          rows={[
            { label: w.willUse, value: label(confirming), tone: 'accent' },
            { label: w.instead, value: label(currentWallet) },
          ]}
        />
        <T tone="muted">{w.confirmBody}</T>
        <Menu
          items={[
            { value: 'switch', label: w.switch },
            { value: 'cancel', label: w.cancel },
          ]}
          onSelect={(value) =>
            value === 'switch' ? onPick(confirming.vaultKeyId) : setConfirming(null)
          }
        />
      </Box>
    );
  }
  return (
    <Box flexDirection="column" gap={1}>
      <T>{body ?? p.body(wallets.length)}</T>
      {wallets.some(({ info }) => info === null) ? <T tone="muted">{p.listedBy}</T> : null}
      <Menu
        items={wallets.map(({ vaultKeyId, info }, index) =>
          info
            ? {
                value: vaultKeyId,
                label: walletLabel(info),
                ...(index === current ? { hint: p.inUse } : {}),
              }
            : { value: vaultKeyId, label: p.wallet(index + 1), hint: vaultKeyId },
        )}
        initial={Math.max(current, 0)}
        onSelect={(vaultKeyId) => {
          const picked = wallets.find((wallet) => wallet.vaultKeyId === vaultKeyId);
          // Moving the agents to another wallet always gets a confirmation that names both.
          if (picked && current >= 0 && picked !== wallets[current]) {
            setConfirming(picked);
          } else {
            onPick(vaultKeyId);
          }
        }}
      />
    </Box>
  );
}
