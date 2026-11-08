/**
 * Approval alerts: a small per-user background process (`agentpay notify`) that asks the payments
 * service for this agent's approval requests and shows one desktop notification for each new
 * one. The daemons cannot do this themselves: they run as root or a service account, outside the
 * user's login session.
 *
 * Notifications go through the OS's own tool (`osascript` on macOS, `notify-send` on Linux when
 * installed), without a shell. Request ids already shown are kept in `notified.json` so a
 * restart does not repeat them.
 */
import { join } from 'node:path';
import { readPrivateFile, writePrivateFile } from '../auth/files.js';
import type { CommandRunner } from '../auth/process.js';

/** One approval request as the alerts need it. */
export interface PendingAlert {
  id: string;
  /** "50 USD1 on BSC" */
  amount: string;
  /** "over your daily limit", or `null`. */
  reason: string | null;
}

/** The program and arguments that show one notification, or `null` where none is available. */
export function notificationCommand(
  platform: NodeJS.Platform,
  title: string,
  message: string,
): { command: string; args: string[] } | null {
  if (platform === 'darwin') {
    // AppleScript string literals: escape backslashes and quotes; the text is never a script.
    const quote = (text: string) => `"${text.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
    return {
      command: '/usr/bin/osascript',
      args: ['-e', `display notification ${quote(message)} with title ${quote(title)}`],
    };
  }
  if (platform === 'linux') {
    return { command: 'notify-send', args: ['--app-name=AgentPay', title, message] };
  }
  return null;
}

/** Ids already notified, newest last, capped so the file stays small. */
export interface NotifiedStore {
  read(): string[];
  write(ids: readonly string[]): void;
}

const MAX_REMEMBERED = 500;

export function fileNotifiedStore(home: string): NotifiedStore {
  const path = join(home, 'notified.json');
  return {
    read() {
      try {
        const parsed: unknown = JSON.parse(readPrivateFile(path) ?? '[]');
        return Array.isArray(parsed) ? parsed.filter((id) => typeof id === 'string') : [];
      } catch {
        return [];
      }
    },
    write(ids) {
      writePrivateFile(path, `${JSON.stringify(ids.slice(-MAX_REMEMBERED))}\n`);
    },
  };
}

/**
 * One poll: shows a notification for each pending request not shown before, and remembers it.
 * Returns how many were shown. A failed notification is still remembered (no retry storm).
 */
export async function alertOnce(options: {
  pending: () => Promise<PendingAlert[]>;
  store: NotifiedStore;
  run: CommandRunner;
  platform: NodeJS.Platform;
  text: (alert: PendingAlert) => { title: string; message: string };
}): Promise<number> {
  const seen = new Set(options.store.read());
  const fresh = (await options.pending()).filter((alert) => !seen.has(alert.id));
  for (const alert of fresh) {
    const { title, message } = options.text(alert);
    const command = notificationCommand(options.platform, title, message);
    if (command) {
      await options.run(command.command, command.args, { timeoutMs: 10_000 }).catch(() => null);
    }
    seen.add(alert.id);
  }
  if (fresh.length > 0) {
    options.store.write([...seen]);
  }
  return fresh.length;
}
