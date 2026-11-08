/**
 * `setup` (install the services with `sudo agentpay-setup install`, then the onboarding
 * wizard; on a machine that is already set up, a menu of what to change) and the home screen
 * (no command).
 */
import { existsSync } from 'node:fs';
import { userInfo } from 'node:os';
import { delimiter, join } from 'node:path';
import type { Command } from 'commander';
import { createElement } from 'react';
import { alertsFor } from '../app/alerts.js';
import type { Context } from '../app/context.js';
import { createAppServices, createOnboardingServices } from '../app/services.js';
import { copy } from '../copy/index.js';
import { AgentPayError, AuthError, EXIT, guidanceFor } from '../errors.js';
import { shortAddress } from '../format/text.js';
import type { WalletSummaryResult } from '../generated/index.js';
import { App, type Route } from '../screens/App.js';
import { OnboardingWizard } from '../screens/onboarding/OnboardingWizard.js';
import { type SetupChoice, SetupMenu } from '../screens/SetupMenu.js';
import { printLines } from './output.js';
import { type CommandEnv, handler } from './run.js';

/** `AGENTPAY_SETUP_BIN`, else `agentpay-setup` on `PATH` (absolute, because sudo resets PATH). */
export function resolveSetupBinary(env: NodeJS.ProcessEnv, exists = existsSync): string {
  const explicit = env.AGENTPAY_SETUP_BIN?.trim();
  if (explicit) {
    return explicit;
  }
  for (const dir of (env.PATH ?? '').split(delimiter).filter(Boolean)) {
    const candidate = join(dir, 'agentpay-setup');
    if (exists(candidate)) {
      return candidate;
    }
  }
  return 'agentpay-setup';
}

function assertUserSession(context: Context): void {
  if (context.platform !== 'darwin' && context.platform !== 'linux') {
    throw new AgentPayError('unsupported_platform', copy.errors.unsupportedPlatform);
  }
  if (context.euid === 0) {
    throw new AuthError('root_client', copy.errors.rootClient);
  }
}

/** Installs (or repairs) the services with `sudo agentpay-setup install`. */
async function installServices(context: Context): Promise<void> {
  context.io.stderr(`${copy.commands.setup.installing}\n`);
  const result = await context.run(
    'sudo',
    [resolveSetupBinary(context.env), 'install', '--user', userInfo().username],
    { interactive: true },
  );
  if (result.status !== 0) {
    throw new AgentPayError('setup_failed', copy.errors.setupFailed);
  }
}

/**
 * The wallet the agents use when this user is fully set up (services answer and the saved agent
 * credentials work), else `null`.
 */
async function currentWallet(context: Context): Promise<WalletSummaryResult | null> {
  if (!context.state.read().agentKeyId) {
    return null;
  }
  try {
    return await (await context.payments({})).walletSummary();
  } catch {
    return null;
  }
}

/** Already set up: ask what to change instead of running everything again. */
async function runSetupMenu(env: CommandEnv, wallet: WalletSummaryResult): Promise<number> {
  const { context } = env;
  let choice: SetupChoice = 'quit';
  const address = wallet.evm_address ?? wallet.solana_address;
  await context.render(
    createElement(SetupMenu, {
      wallet: address ? shortAddress(address) : null,
      onChoose: (chosen: SetupChoice) => {
        choice = chosen;
      },
    }),
  );
  switch (choice as SetupChoice) {
    case 'limits':
    case 'wallet':
    case 'security':
      return openHome(env, choice as Route);
    case 'repair':
      await installServices(context);
      printLines(context.io, [copy.screens.setupMenu.repaired]);
      return EXIT.ok;
    case 'full':
      return runSetup(env, { full: true });
    case 'quit':
      return EXIT.ok;
  }
}

async function runSetup(
  env: CommandEnv,
  options: { skipInstall?: boolean; full?: boolean },
): Promise<number> {
  const { context } = env;
  assertUserSession(context);
  if (!options.full && context.io.isTTY) {
    const wallet = await currentWallet(context);
    if (wallet) {
      return runSetupMenu(env, wallet);
    }
  }
  if (!options.skipInstall) {
    await installServices(context);
  }
  if (!context.io.isTTY) {
    const guidance = copy.errors.notInteractive('agentpay setup --skip-install');
    printLines(context.io, [guidance.message, `${copy.common.next}: ${guidance.next}`]);
    return EXIT.usage;
  }
  const admin = context.admin({ relay: true });
  try {
    await context.render(
      createElement(OnboardingWizard, { services: createOnboardingServices(context, admin) }),
    );
  } finally {
    await admin.dispose();
  }
  await turnOnAlerts(context);
  return EXIT.ok;
}

/**
 * Approval alerts run in the background once setup is done (no sudo: a per-user service). Best
 * effort: setup succeeded either way, and Security turns them on or off later.
 */
async function turnOnAlerts(context: Context): Promise<void> {
  const alerts = alertsFor(context);
  if (!alerts || alerts.installed() || !context.state.read().agentKeyId) {
    return;
  }
  try {
    await alerts.install();
    printLines(context.io, [copy.commands.setup.alertsOn]);
  } catch (error) {
    const guidance = guidanceFor(error);
    printLines(context.io, [guidance.message, `${copy.common.next}: ${guidance.next}`]);
  }
}

export function registerSetupCommands(program: Command, env: CommandEnv): void {
  program
    .command('setup')
    .description(copy.commands.setup.description)
    .option('--skip-install', copy.commands.setup.skipInstall)
    .option('--full', copy.commands.setup.full)
    .action(
      handler(env, (options: { skipInstall?: boolean; full?: boolean }) => runSetup(env, options)),
    );

  // `agentpay admin setup` and `agentpay admin tui` from the TypeScript CLI.
  const admin = program.commands.find((command) => command.name() === 'admin');
  admin
    ?.command('setup', { hidden: true })
    .option('--skip-install')
    .allowUnknownOption()
    .action(handler(env, (options: { skipInstall?: boolean }) => runSetup(env, options)));
  admin?.command('tui', { hidden: true }).action(handler(env, () => openHome(env)));
}

/** The home screen (`agentpay` with no command, in a terminal). */
export async function openHome(env: CommandEnv, initial: Route = 'home'): Promise<number> {
  const { context } = env;
  assertUserSession(context);
  const payments = await context.payments({});
  const admin = context.admin({ relay: true });
  try {
    await context.render(
      createElement(App, { services: createAppServices(context, payments, admin), initial }),
    );
  } finally {
    await admin.dispose();
  }
  return EXIT.ok;
}
