/**
 * `agentpay admin wallets` and `agentpay admin wallet-backup export|verify`: the wallets on this
 * machine and their encrypted offline backups. A backup names its wallet with
 * `--wallet <vault-key-id|address>`; without it, a machine with several wallets gets the picker
 * in a terminal and an error listing them otherwise.
 */
import { readFileSync } from 'node:fs';
import type { Command } from 'commander';
import { createElement } from 'react';
import type { AdminActions } from '../app/admin-actions.js';
import { defaultBackupPath, expandPath, writeBackup } from '../app/services.js';
import { assertStorableSecret } from '../auth/secret-store.js';
import { copy } from '../copy/index.js';
import { AgentPayError, EXIT, SignerCallError, UsageError } from '../errors.js';
import { findWallet, walletLabel, walletLines } from '../format/wallets.js';
import type { WalletInfo } from '../generated/index.js';
import { BackupScreen, BackupWalletPicker } from '../screens/BackupForm.js';
import { type AgentOptions, type JsonOption, withAgentOptions } from './options.js';
import { emit } from './output.js';
import { type CommandEnv, handler } from './run.js';

const COMMAND = {
  wallets: 'agentpay admin wallets',
  backup: 'agentpay admin wallet-backup export',
  verify: 'agentpay admin wallet-backup verify',
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

interface RenameOptions extends JsonOption {
  clear?: boolean;
}

interface BackupOptions extends AgentOptions {
  output?: string;
  passphraseStdin?: boolean;
  wallet?: string;
}

/**
 * The vault key `--wallet` names. A vault key id is passed as given (the daemon checks it); an
 * address is looked up in the wallet list.
 */
async function namedWallet(actions: AdminActions, selector: string): Promise<string> {
  const trimmed = selector.trim();
  if (UUID.test(trimmed)) {
    return trimmed.toLowerCase();
  }
  const wallets = await actions.listWallets(COMMAND.backup);
  const found = findWallet(wallets, trimmed);
  if (!found) {
    throw new AgentPayError(
      'wallet_unknown',
      copy.errors.walletUnknown(trimmed, walletLines(wallets)),
      EXIT.usage,
    );
  }
  return found.vault_key_id;
}

function choiceNeeded(wallets: readonly WalletInfo[]): AgentPayError {
  return new AgentPayError(
    'wallet_choice_needed',
    copy.errors.walletChoiceNeeded(wallets.length, walletLines(wallets)),
    EXIT.usage,
  );
}

/**
 * The wallet to back up in a terminal: `--wallet`, else the only one, else the user's pick
 * (`null` when they backed out).
 */
async function pickBackupWallet(
  env: CommandEnv,
  actions: AdminActions,
  selector: string | undefined,
): Promise<string | null> {
  if (selector) {
    return namedWallet(actions, selector);
  }
  const wallets = await actions.listWallets(COMMAND.backup);
  const [only, ...others] = wallets;
  if (!only) {
    throw new AgentPayError('wallet_missing', copy.errors.walletMissing);
  }
  if (others.length === 0) {
    return only.vault_key_id;
  }
  let picked: string | null = null;
  await env.context.render(
    createElement(BackupWalletPicker, {
      wallets,
      onPick: (vaultKeyId: string | null) => {
        picked = vaultKeyId;
      },
    }),
  );
  return picked;
}

/** Interactive export: choose the wallet, then the backup form (path, passphrase, warning). */
async function exportInteractively(env: CommandEnv, options: BackupOptions): Promise<number> {
  const actions = env.context.admin({ relay: true });
  try {
    const vaultKeyId = await pickBackupWallet(env, actions, options.wallet);
    if (!vaultKeyId) {
      env.context.io.stderr(`${copy.commands.admin.aborted}\n`);
      return EXIT.failure;
    }
    await env.context.render(
      createElement(BackupScreen, {
        services: {
          defaultBackupPath: () =>
            options.output ? expandPath(options.output) : defaultBackupPath(),
          exportBackup: (path, passphrase) =>
            writeBackup(actions, path, passphrase, COMMAND.backup, vaultKeyId, env.context.state),
        },
      }),
    );
    return EXIT.ok;
  } finally {
    await actions.dispose();
  }
}

/**
 * Non-interactive export (`--passphrase-stdin --output <path>`). Without `--wallet` the daemon
 * picks the only wallet; when it refuses because there are several, the error lists them.
 */
async function exportFromStdin(env: CommandEnv, options: BackupOptions): Promise<number> {
  const io = env.context.io;
  if (!options.output) {
    throw new UsageError('--output is required with --passphrase-stdin');
  }
  const passphrase = assertStorableSecret(await io.readStdin());
  const actions = env.context.admin({ relay: false });
  try {
    const vaultKeyId = options.wallet ? await namedWallet(actions, options.wallet) : undefined;
    try {
      await writeBackup(
        actions,
        options.output,
        passphrase,
        COMMAND.backup,
        vaultKeyId,
        env.context.state,
      );
    } catch (error) {
      if (
        !vaultKeyId &&
        error instanceof SignerCallError &&
        error.wire.kind === 'InvalidWalletRequest'
      ) {
        const wallets = await actions.listWallets(COMMAND.backup);
        if (wallets.length > 1) {
          throw choiceNeeded(wallets);
        }
      }
      throw error;
    }
  } finally {
    await actions.dispose();
  }
  const path = expandPath(options.output);
  emit(io, options.json, { path }, () => [copy.commands.admin.backupWritten(path)]);
  return EXIT.ok;
}

export function registerAdminWalletCommands(admin: Command, env: CommandEnv): void {
  const a = copy.commands.admin;

  const walletsCommand = admin
    .command('wallets')
    .description(a.wallets)
    .option('--json', copy.commands.program.json);
  walletsCommand.action(
    handler(env, async (options: JsonOption) => {
      const actions = env.context.admin({ relay: false });
      try {
        const wallets = await actions.listWallets(COMMAND.wallets);
        emit(env.context.io, options.json, wallets, () =>
          wallets.length === 0 ? [a.noWallets] : walletLines(wallets),
        );
      } finally {
        await actions.dispose();
      }
      return EXIT.ok;
    }),
  );

  walletsCommand
    .command('rename')
    .description(a.renameWallet)
    .argument('<wallet>', a.wallet)
    .argument('[name]', a.walletName)
    .option('--clear', a.clearName)
    .option('--json', copy.commands.program.json)
    .action(
      handler(env, async (selector: string, name: string | undefined, options: RenameOptions) => {
        if (!options.clear && !name?.trim()) {
          throw new UsageError('give the wallet a name, or pass --clear to remove it');
        }
        const actions = env.context.admin({ relay: false });
        try {
          const vaultKeyId = await namedWallet(actions, selector);
          const renamed = await actions.renameWallet(
            vaultKeyId,
            options.clear ? null : (name?.trim() ?? null),
            COMMAND.wallets,
          );
          emit(env.context.io, options.json, renamed, () => [walletLabel(renamed)]);
        } finally {
          await actions.dispose();
        }
        return EXIT.ok;
      }),
    );

  const backup = admin.command('wallet-backup').description(a.backup);
  withAgentOptions(
    backup
      .command('export')
      .description(a.backupExport)
      .option('--output <path>', a.output)
      .option('--wallet <vault-key-id|address>', a.wallet)
      .option('--passphrase-stdin', a.backupExport),
  ).action(
    handler(env, async (options: BackupOptions) => {
      if (options.passphraseStdin) {
        return exportFromStdin(env, options);
      }
      if (!env.context.io.isTTY || options.json) {
        throw new UsageError('pass the backup passphrase on stdin with --passphrase-stdin');
      }
      return exportInteractively(env, options);
    }),
  );
  withAgentOptions(backup.command('verify').description(a.backupVerify).argument('<path>')).action(
    handler(env, async (path: string, options: AgentOptions) => {
      const passphrase = assertStorableSecret(await env.context.io.readStdin());
      const result = await env.context
        .admin({ relay: false })
        .verifyBackup(readFileSync(expandPath(path), 'utf8'), passphrase, COMMAND.verify);
      // A wrong passphrase fails with `WalletBackupDecryptionFailed`; success means it opens.
      emit(env.context.io, options.json, result, () => [
        a.backupValid,
        ...(result.address ? [`${copy.commands.wallet.evm}: ${result.address}`] : []),
      ]);
      return EXIT.ok;
    }),
  );
}
