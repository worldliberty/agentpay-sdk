/**
 * Runs `agentpay notify` in the background for this user, without sudo: a LaunchAgent on macOS
 * (`~/Library/LaunchAgents/com.agentpay.notify.plist`), a systemd user unit on Linux
 * (`~/.config/systemd/user/agentpay-notify.service`).
 */
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { CommandRunner } from '../auth/process.js';
import { copy } from '../copy/index.js';
import { AgentPayError } from '../errors.js';

/** A failed install leaves nothing behind, so "installed" always means running. */
function installFailed(path: string, detail: string): AgentPayError {
  rmSync(path, { force: true });
  return new AgentPayError('alerts_failed', copy.errors.alertsFailed(detail));
}

export const LAUNCH_AGENT_LABEL = 'com.agentpay.notify';
export const SYSTEMD_UNIT = 'agentpay-notify.service';

const xml = (text: string) =>
  text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');

/** The LaunchAgent: start at login, restart if it stops, log to `~/.agentpay/notify.log`. */
export function launchAgentPlist(agentpay: string, home: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LAUNCH_AGENT_LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>${xml(agentpay)}</string><string>notify</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>${xml(join(home, 'notify.log'))}</string>
  <key>StandardErrorPath</key><string>${xml(join(home, 'notify.log'))}</string>
</dict>
</plist>
`;
}

/** The systemd user unit (systemd quotes arguments with double quotes). */
export function systemdUnit(agentpay: string): string {
  return `[Unit]
Description=AgentPay approval alerts

[Service]
ExecStart="${agentpay.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}" notify
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
`;
}

export interface AlertsService {
  /** Where the service definition lives. */
  path: string;
  installed(): boolean;
  install(): Promise<void>;
  uninstall(): Promise<void>;
}

/** The alerts service for this user, or `null` on a platform without one. */
export function alertsService(options: {
  platform: NodeJS.Platform;
  userHome: string;
  agentpayHome: string;
  uid: number;
  /** The `agentpay` command to run (absolute path). */
  agentpay: string;
  run: CommandRunner;
}): AlertsService | null {
  const { platform, userHome, run } = options;
  const write = (path: string, contents: string) => {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, contents, { mode: 0o644 });
  };
  if (platform === 'darwin') {
    const path = join(userHome, 'Library', 'LaunchAgents', `${LAUNCH_AGENT_LABEL}.plist`);
    const domain = `gui/${options.uid}`;
    return {
      path,
      installed: () => existsSync(path),
      async install() {
        write(path, launchAgentPlist(options.agentpay, options.agentpayHome));
        // Replace a running copy so a new agentpay path takes effect.
        await run('launchctl', ['bootout', `${domain}/${LAUNCH_AGENT_LABEL}`]);
        const result = await run('launchctl', ['bootstrap', domain, path]);
        if (result.status !== 0) {
          throw installFailed(path, result.stderr.trim() || `launchctl exit ${result.status}`);
        }
      },
      async uninstall() {
        await run('launchctl', ['bootout', `${domain}/${LAUNCH_AGENT_LABEL}`]);
        rmSync(path, { force: true });
      },
    };
  }
  if (platform === 'linux') {
    const path = join(userHome, '.config', 'systemd', 'user', SYSTEMD_UNIT);
    return {
      path,
      installed: () => existsSync(path),
      async install() {
        write(path, systemdUnit(options.agentpay));
        const reload = await run('systemctl', ['--user', 'daemon-reload']);
        if (reload.status !== 0) {
          // No user manager: a headless login without lingering, or a container.
          throw installFailed(path, copy.errors.noUserSession);
        }
        const result = await run('systemctl', ['--user', 'enable', '--now', SYSTEMD_UNIT]);
        if (result.status !== 0) {
          throw installFailed(path, result.stderr.trim() || `systemctl exit ${result.status}`);
        }
      },
      async uninstall() {
        await run('systemctl', ['--user', 'disable', '--now', SYSTEMD_UNIT]);
        rmSync(path, { force: true });
        await run('systemctl', ['--user', 'daemon-reload']);
      },
    };
  }
  return null;
}
