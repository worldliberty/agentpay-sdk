import fs from 'node:fs';
import path from 'node:path';
import { defaultRustBinDir, type WlfiConfig } from '../../packages/config/src/index.js';

export const LAUNCHD_RUNNER_SCRIPT_NAME = 'run-agentpay-daemon.sh';
export const LAUNCHD_INSTALL_SCRIPT_NAME = 'install-user-daemon.sh';
export const LAUNCHD_UNINSTALL_SCRIPT_NAME = 'uninstall-user-daemon.sh';

function resolveRustBinDir(config?: WlfiConfig): string {
  return path.resolve(config?.rustBinDir || defaultRustBinDir());
}

/**
 * The checked-in `scripts/launchd` copies are only consulted when a developer opts in with
 * `AGENTPAY_DEV_SCRIPTS=1`; installed CLIs must never execute helper scripts from the current
 * working directory as root.
 */
export function developmentHelperScriptsEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.AGENTPAY_DEV_SCRIPTS === '1';
}

export function resolveLaunchDaemonHelperScriptPath(
  scriptName: string,
  config?: WlfiConfig,
): string {
  const candidates = [path.join(resolveRustBinDir(config), scriptName)];
  if (developmentHelperScriptsEnabled()) {
    candidates.push(path.resolve(process.cwd(), 'scripts/launchd', scriptName));
  }

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  return candidates[0];
}
