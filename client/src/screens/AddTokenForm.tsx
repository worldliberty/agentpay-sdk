/**
 * Adding a token from the spending limits table: pick a main network, type the contract address
 * (or the mint and a symbol on Solana), and the payments service reads the token from the
 * network. When the network cannot be read, the symbol and decimals can be typed in instead.
 * The result is a new limit row, unset, for the user to give a limit or block.
 */
import { Box } from 'ink';
import { useEffect, useState } from 'react';
import { copy, type Guidance } from '../copy/index.js';
import { guidanceFor } from '../errors.js';
import { Menu, Spinner, TextField } from '../ui/controls.js';
import { useInput } from '../ui/input.js';
import { ErrorPanel } from '../ui/layout.js';
import { T } from '../ui/theme.js';
import type { NewToken, TokenAdded, TokenNetwork, TokenServices } from './types.js';
import { useAsync } from './use-async.js';

export type AddTokenMode = 'network' | 'address' | 'details' | 'looking';

/** Key hints for each mode, for the screen footer. */
export function addTokenHints(mode: AddTokenMode): string[] {
  const k = copy.common.keys;
  switch (mode) {
    case 'network':
      return [k.select, k.confirm, k.back];
    case 'address':
    case 'details':
      return [k.type, k.continue, k.back];
    case 'looking':
      return [];
  }
}

export function AddTokenForm({
  services,
  onAdded,
  onCancel,
  onModeChange,
}: {
  services: TokenServices;
  onAdded: (result: TokenAdded) => void;
  onCancel: () => void;
  onModeChange?: (mode: AddTokenMode) => void;
}) {
  const t = copy.onboarding.tokens;
  const networks = useAsync(() => services.tokenNetworks());
  const [mode, setModeState] = useState<AddTokenMode>('network');
  const [network, setNetwork] = useState<TokenNetwork | null>(null);
  const [address, setAddress] = useState('');
  const [symbol, setSymbol] = useState('');
  const [decimals, setDecimals] = useState('');
  /** Which details field has the cursor. */
  const [field, setField] = useState<'symbol' | 'decimals'>('symbol');
  const [error, setError] = useState<Guidance | null>(null);

  const setMode = (next: AddTokenMode) => {
    setModeState(next);
    onModeChange?.(next);
  };
  // biome-ignore lint/correctness/useExhaustiveDependencies: report the first mode once.
  useEffect(() => onModeChange?.('network'), []);

  const solana = network?.family === 'solana';

  const lookUp = async (token: NewToken) => {
    setMode('looking');
    setError(null);
    try {
      onAdded(await services.lookupToken(token));
    } catch (failure) {
      setError(guidanceFor(failure));
      // An unreadable network cannot supply the symbol either: start there.
      setField('symbol');
      setMode('details');
    }
  };

  const submit = () => {
    if (!network || !address.trim()) {
      return;
    }
    const parsed = Number.parseInt(decimals, 10);
    void lookUp({
      network: network.network,
      address: address.trim(),
      ...(symbol.trim() ? { symbol: symbol.trim() } : {}),
      ...(decimals.trim() && Number.isInteger(parsed) ? { decimals: parsed } : {}),
    });
  };

  useInput(
    (_input, key) => {
      if (!key.escape) {
        return;
      }
      if (mode === 'network') {
        onCancel();
      } else if (mode === 'address') {
        setMode('network');
      } else if (mode === 'details') {
        setError(null);
        setMode('address');
      }
    },
    { isActive: mode !== 'looking' },
  );

  return (
    <Box flexDirection="column" gap={1}>
      <T bold>{t.title}</T>
      {mode === 'network' ? (
        networks.status === 'ready' ? (
          <Box flexDirection="column">
            <T>{t.network}</T>
            <Menu
              items={networks.value.map((option) => ({
                value: option.network,
                label: option.name,
              }))}
              onSelect={(value) => {
                setNetwork(networks.value.find((option) => option.network === value) ?? null);
                setMode('address');
              }}
            />
          </Box>
        ) : networks.status === 'error' ? (
          <ErrorPanel guidance={networks.error} />
        ) : (
          <Spinner label={copy.common.loading} />
        )
      ) : null}

      {mode === 'address' || mode === 'details' ? (
        <Box flexDirection="column" gap={1}>
          <TextField
            label={solana ? t.mint : t.address}
            hint={solana ? t.mintHint : t.addressHint}
            value={address}
            onChange={setAddress}
            isActive={mode === 'address'}
            onSubmit={() => {
              if (!address.trim()) {
                return;
              }
              if (solana && !symbol.trim()) {
                // SPL tokens have no symbol on chain.
                setField('symbol');
                setMode('details');
              } else {
                submit();
              }
            }}
          />
          {mode === 'details' ? (
            <>
              {error ? (
                <>
                  <ErrorPanel guidance={error} />
                  <T tone="muted">{t.lookupFailed}</T>
                </>
              ) : null}
              <TextField
                label={t.symbol}
                hint={solana ? t.symbolHint : t.symbolOptionalHint}
                value={symbol}
                onChange={setSymbol}
                isActive={field === 'symbol'}
                onSubmit={() => (error ? setField('decimals') : submit())}
              />
              {error ? (
                <TextField
                  label={t.decimals}
                  hint={t.decimalsHint}
                  value={decimals}
                  onChange={(value) => setDecimals(value.replace(/[^0-9]/gu, ''))}
                  isActive={field === 'decimals'}
                  onSubmit={submit}
                />
              ) : null}
            </>
          ) : null}
        </Box>
      ) : null}

      {mode === 'looking' ? <Spinner label={t.looking} /> : null}
    </Box>
  );
}
