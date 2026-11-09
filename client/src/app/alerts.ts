/** The approval alerts service for the user running the client (see `notify/service.ts`). */
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { type AlertsService, alertsService } from '../notify/service.js';
import type { Context } from './context.js';

/**
 * The installed `agentpay` launcher (`~/.agentpay/bin/agentpay`, stable across upgrades), or
 * `AGENTPAY_BIN`. `null` when there is no installed launcher to run in the background.
 */
export function agentpayLauncher(env: NodeJS.ProcessEnv, exists = existsSync): string | null {
  const explicit = env.AGENTPAY_BIN?.trim();
  if (explicit) {
    return explicit;
  }
  const launcher = join(env.HOME?.trim() || homedir(), '.agentpay', 'bin', 'agentpay');
  return exists(launcher) ? launcher : null;
}

export function alertsFor(context: Context): AlertsService | null {
  const agentpay = agentpayLauncher(context.env);
  if (!agentpay) {
    return null;
  }
  return alertsService({
    platform: context.platform,
    userHome: context.env.HOME?.trim() || homedir(),
    agentpayHome: context.home,
    uid: context.euid,
    agentpay,
    run: context.run,
  });
}
