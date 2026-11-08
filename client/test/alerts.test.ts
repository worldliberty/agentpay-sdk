import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import type { CommandRunner } from '../src/auth/process.js';
import {
  alertOnce,
  fileNotifiedStore,
  notificationCommand,
  type PendingAlert,
} from '../src/notify/alerts.js';
import { alertsService, launchAgentPlist, systemdUnit } from '../src/notify/service.js';

const ok = () =>
  vi.fn(async () => ({ status: 0, stdout: '', stderr: '' })) as unknown as CommandRunner & {
    mock: { calls: [string, string[]][] };
  };
const text = (alert: PendingAlert) => ({
  title: 'AgentPay',
  message: `Approve ${alert.amount}?${alert.reason ? ` ${alert.reason}` : ''}`,
});

describe('notifications', () => {
  it('quotes the text for AppleScript, so it can never become script', () => {
    const command = notificationCommand('darwin', 'AgentPay', 'Pay "50" \\ USD1? end tell');
    expect(command).toEqual({
      command: '/usr/bin/osascript',
      args: ['-e', 'display notification "Pay \\"50\\" \\\\ USD1? end tell" with title "AgentPay"'],
    });
    expect(notificationCommand('linux', 'T', 'M')?.args).toEqual(['--app-name=AgentPay', 'T', 'M']);
    expect(notificationCommand('win32', 'T', 'M')).toBeNull();
  });

  it('shows each pending request once, across restarts', async () => {
    const home = mkdtempSync(join(tmpdir(), 'apn-'));
    const run = ok();
    const pending = async () => [
      { id: 'a', amount: '50 USD1 on BSC', reason: 'over your daily limit' },
      { id: 'b', amount: '2 SOL on Solana', reason: null },
    ];
    const once = () =>
      alertOnce({ pending, store: fileNotifiedStore(home), run, platform: 'darwin', text });
    expect(await once()).toBe(2);
    expect(await once()).toBe(0);
    expect(run).toHaveBeenCalledTimes(2);
    expect(run.mock.calls[0]?.[1]?.[1]).toContain('Approve 50 USD1 on BSC? over your daily limit');
    expect(JSON.parse(readFileSync(join(home, 'notified.json'), 'utf8'))).toEqual(['a', 'b']);
  });
});

describe('the background alerts service', () => {
  it('writes a LaunchAgent that runs agentpay notify at login and restarts it', () => {
    const plist = launchAgentPlist('/Users/a b/.agentpay/bin/agentpay', '/Users/a b/.agentpay');
    expect(plist).toContain(
      '<string>/Users/a b/.agentpay/bin/agentpay</string><string>notify</string>',
    );
    expect(plist).toContain('<key>KeepAlive</key><true/>');
    expect(plist).toContain('/Users/a b/.agentpay/notify.log');
    expect(systemdUnit('/home/a/.agentpay/bin/agentpay')).toContain(
      'ExecStart="/home/a/.agentpay/bin/agentpay" notify',
    );
  });

  it('installs and removes the LaunchAgent with launchctl in the user’s GUI domain', async () => {
    const userHome = mkdtempSync(join(tmpdir(), 'aph-'));
    const run = ok();
    const service = alertsService({
      platform: 'darwin',
      userHome,
      agentpayHome: join(userHome, '.agentpay'),
      uid: 501,
      agentpay: '/x/agentpay',
      run,
    });
    expect(service?.installed()).toBe(false);
    await service?.install();
    expect(service?.installed()).toBe(true);
    expect(run.mock.calls.map(([cmd, args]) => [cmd, ...args].join(' '))).toEqual([
      'launchctl bootout gui/501/com.agentpay.notify',
      `launchctl bootstrap gui/501 ${service?.path}`,
    ]);
    await service?.uninstall();
    expect(existsSync(service?.path ?? '')).toBe(false);
  });
});

describe('alerts on a Linux login without a systemd user session', () => {
  it('fails with the reason and leaves no unit behind, so alerts never look on', async () => {
    const userHome = mkdtempSync(join(tmpdir(), 'apl-'));
    const run = vi.fn(async () => ({
      status: 1,
      stdout: '',
      stderr: 'Failed to connect to bus: No such file or directory',
    })) as unknown as CommandRunner;
    const service = alertsService({
      platform: 'linux',
      userHome,
      agentpayHome: join(userHome, '.agentpay'),
      uid: 1001,
      agentpay: '/x/agentpay',
      run,
    });
    const error = await service?.install().catch((e: unknown) => e);
    expect(String((error as { guidance?: { message: string } }).guidance?.message)).toContain(
      'no systemd user session',
    );
    expect((error as { guidance?: { next: string } }).guidance?.next).toContain(
      'loginctl enable-linger',
    );
    expect(service?.installed()).toBe(false);
  });
});
