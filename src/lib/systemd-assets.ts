import fs from 'node:fs';
import path from 'node:path';
import { defaultRustBinDir, type WlfiConfig } from '../../packages/config/src/index.js';

export const SYSTEMD_RUNNER_SCRIPT_NAME = 'run-agentpay-daemon.sh';
export const SYSTEMD_INSTALL_SCRIPT_NAME = 'install-system-daemon.sh';
export const SYSTEMD_UNINSTALL_SCRIPT_NAME = 'uninstall-system-daemon.sh';
export const SYSTEMD_PASSWORD_HELPER_SCRIPT_NAME = 'agentpay-daemon-password-helper.sh';

function resolveRustBinDir(config?: WlfiConfig): string {
  return path.resolve(config?.rustBinDir || defaultRustBinDir());
}

export function resolveSystemdHelperScriptPath(scriptName: string, config?: WlfiConfig): string {
  const candidates = [
    path.join(resolveRustBinDir(config), scriptName),
    path.resolve(process.cwd(), 'scripts/systemd', scriptName),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  return candidates[0];
}
