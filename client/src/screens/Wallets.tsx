/**
 * Wallet: every wallet on the machine, which one the agents use, and switching (always after a
 * confirmation that names both wallets, so the agents never move to another wallet unnoticed).
 */
import { Box } from 'ink';
import { useState } from 'react';
import { copy, type Guidance } from '../copy/index.js';
import { guidanceFor } from '../errors.js';
import { walletLabel } from '../format/wallets.js';
import type { WalletInfo } from '../generated/index.js';
import { Menu, Spinner, TextField } from '../ui/controls.js';
import { useInput } from '../ui/input.js';
import { Rows, Screen } from '../ui/layout.js';
import { glyph, T } from '../ui/theme.js';
import type { WalletServices } from './types.js';
import { useAsync } from './use-async.js';

/** The wallet holding `agentKeyId`, if any. */
export function walletOfAgent(
  wallets: readonly WalletInfo[],
  agentKeyId: string | null,
): WalletInfo | null {
  return agentKeyId ? (wallets.find((w) => w.agent_key_ids.includes(agentKeyId)) ?? null) : null;
}

export function WalletsScreen({
  services,
  onBack,
}: {
  services: WalletServices;
  onBack: () => void;
}) {
  const w = copy.screens.wallets;
  const k = copy.common.keys;
  const loaded = useAsync(() => services.listWallets());
  const [target, setTarget] = useState<WalletInfo | null>(null);
  /** Back from a cancelled switch, the list stays on the wallet that was picked. */
  const [picked, setPicked] = useState<string | null>(null);
  const [highlighted, setHighlighted] = useState<string | null>(null);
  /** The wallet being renamed, and the name typed so far. */
  const [renaming, setRenaming] = useState<WalletInfo | null>(null);
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<Guidance | null>(null);
  const wallets = loaded.status === 'ready' ? loaded.value : null;
  const current = wallets ? walletOfAgent(wallets, services.currentAgentKeyId()) : null;

  useInput(
    (input, key) => {
      if (renaming) {
        if (key.escape) {
          setRenaming(null);
        }
        return;
      }
      if (key.escape || input === 'q') {
        if (target) {
          setTarget(null);
        } else {
          onBack();
        }
      } else if (input === 'r' && loaded.status === 'error') {
        loaded.reload();
      } else if (input === 'n' && !target && wallets) {
        const wallet = wallets.find((candidate) => candidate.vault_key_id === highlighted);
        if (wallet) {
          setNotice(null);
          setName(wallet.name ?? '');
          setRenaming(wallet);
        }
      }
    },
    { isActive: !busy },
  );

  const rename = async (wallet: WalletInfo) => {
    const trimmed = name.trim();
    setBusy(true);
    setError(null);
    try {
      const renamed = await services.renameWallet(wallet, trimmed === '' ? null : trimmed);
      setNotice(renamed.name ? w.renamed(renamed.name) : w.nameCleared);
      // Back on the list, stay on the wallet just renamed.
      setPicked(wallet.vault_key_id);
      setRenaming(null);
      loaded.refresh();
    } catch (failure) {
      setError(guidanceFor(failure));
    } finally {
      setBusy(false);
    }
  };

  if (renaming) {
    return (
      <Screen title={w.renameTitle} hints={busy ? [] : [k.type, k.confirm, k.back]} error={error}>
        <Box flexDirection="column" gap={1}>
          <T tone="muted">{walletLabel(renaming)}</T>
          <TextField
            label={w.nameLabel}
            hint={w.nameHint}
            value={name}
            onChange={(value) => setName(value.slice(0, 32))}
            isActive={!busy}
            onSubmit={() => void rename(renaming)}
          />
          {busy ? <Spinner label={w.saving} /> : null}
        </Box>
      </Screen>
    );
  }

  const switchTo = async (wallet: WalletInfo) => {
    setBusy(true);
    setError(null);
    try {
      await services.switchWallet(wallet);
      setNotice(w.switched(walletLabel(wallet)));
      setTarget(null);
      loaded.refresh();
    } catch (failure) {
      setError(guidanceFor(failure));
    } finally {
      setBusy(false);
    }
  };

  if (target) {
    return (
      <Screen
        title={w.confirmTitle}
        hints={busy ? [] : [k.select, k.confirm, k.back]}
        error={error}
      >
        <Box flexDirection="column" gap={1}>
          <Rows
            rows={[
              { label: w.willUse, value: walletLabel(target), tone: 'accent' },
              { label: w.instead, value: current ? walletLabel(current) : w.none },
            ]}
          />
          <T tone="muted">{w.confirmBody}</T>
          {busy ? (
            <Spinner label={w.switching} />
          ) : (
            <Menu
              items={[
                { value: 'switch', label: w.switch },
                { value: 'cancel', label: w.cancel },
              ]}
              onSelect={(value) => (value === 'switch' ? void switchTo(target) : setTarget(null))}
            />
          )}
        </Box>
      </Screen>
    );
  }

  return (
    <Screen
      title={w.title}
      hints={
        loaded.status === 'error'
          ? [k.retry, k.back]
          : wallets
            ? [k.select, k.open, k.rename, k.back]
            : [k.back]
      }
      error={loaded.status === 'error' ? loaded.error : error}
    >
      {loaded.status === 'loading' ? <Spinner label={copy.common.loading} /> : null}
      {wallets ? (
        <Box flexDirection="column" gap={1}>
          <T>{w.body(wallets.length)}</T>
          <Menu
            items={wallets.map((wallet) => ({
              value: wallet.vault_key_id,
              label: walletLabel(wallet),
              ...(wallet === current ? { hint: copy.onboarding.pickWallet.inUse } : {}),
            }))}
            onHighlight={setHighlighted}
            initial={Math.max(
              0,
              picked
                ? wallets.findIndex((wallet) => wallet.vault_key_id === picked)
                : current
                  ? wallets.indexOf(current)
                  : 0,
            )}
            onSelect={(id) => {
              const chosen = wallets.find((wallet) => wallet.vault_key_id === id) ?? null;
              setNotice(null);
              setPicked(id);
              if (chosen && chosen === current) {
                setNotice(w.alreadyUsed);
              } else {
                setTarget(chosen);
              }
            }}
          />
        </Box>
      ) : null}
      {notice ? <T tone="success">{`${glyph.check} ${notice}`}</T> : null}
    </Screen>
  );
}
