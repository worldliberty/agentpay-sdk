import { describe, expect, it, vi } from 'vitest';
import { DEFAULT_PAYMENTS_CONFIG } from '../src/limits/default-config.js';
import { blockUndecided, rowsFromConfig, setRowField } from '../src/limits/model.js';
import { LimitsScreen } from '../src/screens/Limits.js';
import { KEY, press, render, waitFor } from './helpers/ink.js';
import { fakeAppServices } from './helpers/services.js';

const rows = rowsFromConfig(DEFAULT_PAYMENTS_CONFIG);
const row = (id: string) => {
  const found = rows.find((r) => r.id === id);
  if (!found) {
    throw new Error(id);
  }
  return found;
};

describe('typed limit amounts', () => {
  it('sets a field, filling the empty ones of an unset row', () => {
    expect(setRowField(row('eth@eth'), 'perTx', '0.5')).toMatchObject({
      perTx: '0.5',
      daily: '0.5',
      weekly: '0.5',
      status: 'custom',
    });
    expect(setRowField(row('usd1@bsc'), 'daily', '250')).toMatchObject({
      perTx: '10',
      daily: '250',
      weekly: '700',
      status: 'custom',
    });
  });

  it('refuses zero, junk, and more decimals than the token has', () => {
    expect(setRowField(row('usd1@bsc'), 'perTx', '0')).toBeNull();
    expect(setRowField(row('usd1@bsc'), 'perTx', '1.2.3')).toBeNull();
    expect(setRowField(row('sol@solana-mainnet'), 'perTx', '0.0000000001')).toBeNull();
    expect(setRowField(row('sol@solana-mainnet'), 'perTx', '0.000000001')).not.toBeNull();
  });

  it('blocks only the rows that still need a choice', () => {
    const blocked = blockUndecided(rows);
    expect(blocked.find((r) => r.id === 'eth@eth')?.status).toBe('excluded');
    expect(blocked.find((r) => r.id === 'usd1@bsc')?.status).toBe('recommended');
  });

  it('takes an amount typed fast or pasted (several characters in one input)', async () => {
    const services = fakeAppServices();
    const { lastFrame, stdin } = render(<LimitsScreen services={services} onBack={() => {}} />);
    await waitFor(lastFrame, 'Per payment');
    await press(stdin, '0.25');
    await waitFor(lastFrame, '0.25▏');
    await press(stdin, KEY.enter, KEY.enter);
    await vi.waitFor(() => expect(services.saveLimits).toHaveBeenCalled());
    const [saved] = vi.mocked(services.saveLimits).mock.calls[0] ?? [];
    expect(saved?.[0]).toMatchObject({ perTx: '0.25' });
  });

  it('types into the focused cell on the Limits screen; esc cancels, enter keeps', async () => {
    const services = fakeAppServices();
    const { lastFrame, stdin } = render(<LimitsScreen services={services} onBack={() => {}} />);
    await waitFor(lastFrame, 'Per payment');
    await press(stdin, '7');
    expect(await waitFor(lastFrame, '7▏')).toContain('enter confirm · esc cancel');
    await press(stdin, KEY.escape);
    await waitFor(lastFrame, '0-9 or +/- amount');
    expect(services.saveLimits).not.toHaveBeenCalled();

    // 19 decimal places: BNB has 18.
    await press(stdin, ...`0.${'0'.repeat(18)}1`.split(''), KEY.enter);
    await waitFor(lastFrame, 'at most 18 decimal places');
    await press(stdin, ...Array.from({ length: 21 }, () => KEY.backspace), '4', '2', KEY.enter);
    await waitFor(lastFrame, '42');
    await press(stdin, KEY.enter);
    await vi.waitFor(() => expect(services.saveLimits).toHaveBeenCalled());
    const [saved] = vi.mocked(services.saveLimits).mock.calls[0] ?? [];
    expect(saved?.[0]).toMatchObject({ perTx: '42', status: 'custom' });
  });
});
