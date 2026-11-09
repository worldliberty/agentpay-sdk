import { describe, expect, it, vi } from 'vitest';
import { AuthError } from '../src/errors.js';
import { type ReceiveOption, receiveOptions } from '../src/format/receive.js';
import { DEFAULT_PAYMENTS_CONFIG } from '../src/limits/default-config.js';
import { ApprovalsScreen } from '../src/screens/Approvals.js';
import { BackupForm } from '../src/screens/BackupForm.js';
import { HomeScreen } from '../src/screens/Home.js';
import { LimitsScreen } from '../src/screens/Limits.js';
import { ReceiveScreen } from '../src/screens/Receive.js';
import { SecurityScreen } from '../src/screens/Security.js';
import { KEY, press, render, waitFor } from './helpers/ink.js';
import { fakeAppServices, funding, wallet } from './helpers/services.js';

const NOW = new Date('2026-11-05T12:05:00Z');

describe('Home', () => {
  it('shows the address, balances, pending approvals, and actions', async () => {
    const services = fakeAppServices();
    const onAction = vi.fn();
    const { lastFrame, stdin } = render(
      <HomeScreen load={services.loadHome} onAction={onAction} />,
    );
    const frame = await waitFor(lastFrame, 'Balances');
    expect(frame).toContain(wallet.evm_address ?? '');
    expect(frame).toContain('25.5');
    expect(frame).toContain('1 request waiting for your approval');
    expect(frame).toMatchSnapshot();
    await press(stdin, KEY.down, KEY.enter);
    expect(onAction).toHaveBeenCalledWith('send');
    await press(stdin, KEY.down, KEY.enter);
    expect(onAction).toHaveBeenLastCalledWith('approvals');
  });
});

describe('Receive', () => {
  it('shows the QR, address, network, and important things to know', async () => {
    const onBack = vi.fn();
    const { lastFrame, stdin } = render(
      <ReceiveScreen options={async () => []} load={async () => funding} onBack={onBack} />,
    );
    const frame = await waitFor(lastFrame, 'Important things to know');
    expect(frame).toContain('█▀▀▀▀▀█');
    expect(frame).toContain(funding.address);
    expect(frame).toContain('BSC (chain 56)');
    expect(frame).toContain('Only send USD1 on BSC to this address.');
    expect(frame).toContain('send a little BNB');
    expect(frame).toMatchSnapshot();
    await press(stdin, KEY.escape);
    expect(onBack).toHaveBeenCalled();
  });

  it('shows an error with one next action and retries', async () => {
    let calls = 0;
    const load = async () => {
      calls += 1;
      if (calls === 1) {
        throw new AuthError('not_set_up', {
          message: 'No agent credentials.',
          next: 'Run `agentpay setup`.',
        });
      }
      return funding;
    };
    const { lastFrame, stdin } = render(
      <ReceiveScreen options={async () => []} load={load} onBack={() => {}} />,
    );
    expect(await waitFor(lastFrame, 'Next: Run `agentpay setup`.')).toContain(
      '✗ No agent credentials.',
    );
    await press(stdin, 'r');
    await waitFor(lastFrame, funding.address);
  });
});

describe('Receive picker', () => {
  const options: ReceiveOption[] = receiveOptions(DEFAULT_PAYMENTS_CONFIG, {
    includeTestnets: false,
  });

  it('offers every token on main networks, the default first', () => {
    expect(options[0]).toMatchObject({ network: 'bsc', asset: 'usd1' });
    const ids = options.map((option) => option.id);
    expect(ids).toEqual(expect.arrayContaining(['bsc/bnb', 'eth/eth', 'solana-mainnet/sol']));
    expect(options.some((option) => option.testnet)).toBe(false);
    // Tempo has no native coin to receive.
    expect(ids).not.toContain('tempo/usd');
    const withTestnets = receiveOptions(DEFAULT_PAYMENTS_CONFIG, { includeTestnets: true });
    expect(withTestnets.at(-1)?.testnet).toBe(true);
  });

  it('asks what to receive, shows that token, and goes back to the list with esc', async () => {
    const load = vi.fn(async (choice?: ReceiveOption) => ({
      ...funding,
      symbol: choice?.symbol ?? funding.symbol,
    }));
    const onBack = vi.fn();
    const { lastFrame, stdin } = render(
      <ReceiveScreen options={async () => options} load={load} onBack={onBack} />,
    );
    const list = await waitFor(lastFrame, '› USD1 on BSC');
    expect(list).toContain('Choose what to receive');
    expect(list).toContain('BNB on BSC');
    expect(list).toContain('SOL on Solana');
    const bnb = options.findIndex((option) => option.id === 'bsc/bnb');
    await press(stdin, ...Array.from({ length: bnb }, () => KEY.down), KEY.enter);
    await waitFor(lastFrame, 'Receive BNB');
    expect(load).toHaveBeenLastCalledWith(
      expect.objectContaining({ network: 'bsc', asset: 'bnb' }),
    );

    await press(stdin, KEY.escape);
    // Back on the list, still on the token that was opened.
    await waitFor(lastFrame, '› BNB on BSC');
    expect(onBack).not.toHaveBeenCalled();
    await press(stdin, KEY.escape);
    expect(onBack).toHaveBeenCalledTimes(1);
  });
});

describe('Approvals', () => {
  it('lists requests, opens the detail rows, and approves with Touch ID', async () => {
    const services = fakeAppServices();
    const { lastFrame, stdin } = render(
      <ApprovalsScreen services={services} onBack={() => {}} now={NOW} />,
    );
    const list = await waitFor(lastFrame, 'Send 1 USD1');
    expect(list).toContain('0x5aed…67de');
    expect(list).toContain('BSC · needs approval · 5 min ago');
    await press(stdin, KEY.enter);
    const detail = await waitFor(lastFrame, 'Review request');
    expect(detail).toMatchSnapshot();
    expect(detail).toContain('Approve with Touch ID');
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Approved. The agent’s payment continues automatically.');
    expect(services.decideApproval).toHaveBeenCalledWith(
      expect.objectContaining({ summary: expect.objectContaining({ amount: '1 USD1' }) }),
      'approve',
      null,
    );
  });

  it('rejects, and shows a failed approval with its next action', async () => {
    const services = fakeAppServices({
      adminMethod: () => 'sudo',
      decideApproval: vi.fn(async () => {
        throw new AuthError('touch_id_cancelled', {
          message: 'Touch ID was cancelled.',
          next: 'Try again.',
        });
      }),
    });
    const { lastFrame, stdin } = render(
      <ApprovalsScreen services={services} onBack={() => {}} now={NOW} />,
    );
    await waitFor(lastFrame, 'Send 1 USD1');
    await press(stdin, KEY.enter);
    expect(await waitFor(lastFrame, 'Approve')).not.toContain('Touch ID');
    await press(stdin, KEY.down, KEY.enter);
    await waitFor(lastFrame, 'Touch ID was cancelled.');
    expect(services.decideApproval).toHaveBeenCalledWith(expect.anything(), 'reject', null);
  });

  it('says when nothing is waiting', async () => {
    const services = fakeAppServices({ listApprovals: async () => [] });
    const { lastFrame } = render(<ApprovalsScreen services={services} onBack={() => {}} />);
    await waitFor(lastFrame, 'Nothing is waiting for your approval.');
  });
});

describe('Limits', () => {
  it('shows per-asset rows with usage, edits with steppers, and saves', async () => {
    const services = fakeAppServices();
    const { lastFrame, stdin } = render(<LimitsScreen services={services} onBack={() => {}} />);
    const frame = await waitFor(lastFrame, 'Per payment');
    expect(frame).toMatchSnapshot();
    await press(stdin, KEY.down);
    expect(await waitFor(lastFrame, '1 of 500 USD1 used')).toContain(
      '499 USD1 left · rolling 24 h',
    );
    await press(stdin, '+');
    await waitFor(lastFrame, '200');
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Limits saved.');
    const saved = vi.mocked(services.saveLimits).mock.calls[0]?.[0];
    expect(saved?.find((row) => row.id === 'usd1@bsc')).toMatchObject({
      perTx: '200',
      status: 'custom',
    });
  });

  it('blocks an asset with x', async () => {
    const services = fakeAppServices();
    const { lastFrame, stdin } = render(<LimitsScreen services={services} onBack={() => {}} />);
    await waitFor(lastFrame, 'Per payment');
    await press(stdin, 'x', KEY.enter);
    await waitFor(lastFrame, 'Limits saved.');
    const saved = vi.mocked(services.saveLimits).mock.calls[0]?.[0];
    expect(saved?.[0]?.status).toBe('excluded');
  });
});

describe('Security', () => {
  it('turns Touch ID on', async () => {
    const services = fakeAppServices();
    const { lastFrame, stdin } = render(<SecurityScreen services={services} onBack={() => {}} />);
    const frame = await waitFor(lastFrame, 'Turn on Touch ID');
    expect(frame).toMatchSnapshot();
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Touch ID approvals are on.');
    expect(services.enableTouchId).toHaveBeenCalled();
  });
});

describe('Backup form', () => {
  it('validates the passphrase, requires the acknowledgement, then exports', async () => {
    const exportBackup = vi.fn(async () => {});
    const onDone = vi.fn();
    const { lastFrame, stdin } = render(
      <BackupForm
        services={{ defaultBackupPath: () => '/home/me/backup.json', exportBackup }}
        onDone={onDone}
        onBack={() => {}}
        allowSkip={false}
      />,
    );
    expect(lastFrame()).toContain('/home/me/backup.json');
    await press(stdin, KEY.enter, 'short', KEY.enter);
    await waitFor(lastFrame, 'Use at least 12 characters.');
    expect(lastFrame()).not.toContain('short');
    await press(stdin, ' correct horse battery', KEY.enter, 'mismatch', KEY.enter);
    await waitFor(lastFrame, 'The passphrases do not match.');
    await press(stdin, ...Array.from({ length: 'mismatch'.length }, () => KEY.backspace));
    await press(stdin, 'short correct horse battery', KEY.enter);
    expect(await waitFor(lastFrame, 'cannot be recovered')).toMatchSnapshot();
    await press(stdin, KEY.enter);
    expect(lastFrame()).not.toContain('Export backup');
    await press(stdin, KEY.space, KEY.enter);
    await waitFor(lastFrame, 'Export backup');
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Backup saved to /home/me/backup.json.');
    expect(exportBackup).toHaveBeenCalledWith(
      '/home/me/backup.json',
      'short correct horse battery',
    );
    await press(stdin, KEY.enter);
    expect(onDone).toHaveBeenCalledWith('/home/me/backup.json');
  });
});
