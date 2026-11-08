import { describe, expect, it, vi } from 'vitest';
import type { WalletBalanceEntry } from '../src/generated/index.js';
import { HomeScreen } from '../src/screens/Home.js';
import { ReceiveScreen } from '../src/screens/Receive.js';
import { render, waitFor } from './helpers/ink.js';
import { funding, wallet } from './helpers/services.js';

const usd1 = wallet.balances.find(
  (b) => b.asset === 'usd1' && b.network === 'bsc',
) as WalletBalanceEntry;
const withBalance = (whole: number): WalletBalanceEntry => ({
  ...usd1,
  balance: String(whole),
  balance_base_units: (BigInt(whole) * 10n ** BigInt(usd1.decimals)).toString(),
});

describe('Receive watches for arriving funds', () => {
  it('waits, then shows what arrived since the screen opened', async () => {
    const reads = [withBalance(5), withBalance(5), withBalance(30)];
    const watch = vi.fn(async () => reads.shift() ?? withBalance(30));
    const { lastFrame } = render(
      <ReceiveScreen
        options={async () => []}
        load={async () => funding}
        watch={watch}
        pollMs={20}
        onBack={() => {}}
      />,
    );
    await waitFor(lastFrame, 'Waiting for funds');
    // 5 USD1 was already there: only the 25 that arrived counts.
    await waitFor(lastFrame, '✓ Received 25 USD1');
  });

  it('keeps waiting quietly when a read fails', async () => {
    const watch = vi.fn(async () => {
      throw new Error('rate limited');
    });
    const { lastFrame } = render(
      <ReceiveScreen
        options={async () => []}
        load={async () => funding}
        watch={watch}
        pollMs={20}
        onBack={() => {}}
      />,
    );
    await waitFor(lastFrame, 'Waiting for funds');
    await vi.waitFor(() => expect(watch.mock.calls.length).toBeGreaterThan(2));
    expect(lastFrame()).not.toContain('rate limited');
  });
});

describe('Home refreshes in the background', () => {
  it('reloads balances on a timer without showing a spinner or a failed refresh', async () => {
    let calls = 0;
    const load = vi.fn(async () => {
      calls += 1;
      if (calls === 2) {
        throw new Error('flaky');
      }
      const amount = calls === 1 ? 0 : 12;
      return {
        wallet: { ...wallet, balances: [withBalance(amount)] },
        pendingApprovals: calls === 1 ? 0 : 2,
      };
    });
    const view = render(<HomeScreen load={load} onAction={() => {}} refreshMs={20} />);
    await waitFor(view.lastFrame, 'Balances');
    const seen = await waitFor(view.lastFrame, '2 requests waiting for your approval');
    expect(seen).toContain('12');
    // After the first load, no refresh put the loading spinner or the error back on screen.
    const afterFirst = view.frames.slice(view.frames.findIndex((f) => f.includes('Balances')));
    expect(afterFirst.some((f) => f.includes('Loading'))).toBe(false);
    expect(afterFirst.some((f) => f.includes('flaky'))).toBe(false);
  });
});
