import type { Command } from 'commander';

export interface TsOwnedAdminSubcommand {
  name: string;
  description: string;
}

/**
 * Admin subcommands implemented by the TypeScript CLI rather than the Rust `agentpay-admin`
 * binary. They are rendered into the merged `agentpay admin --help` output so the help text no
 * longer depends on string-matching clap output that can change between releases.
 */
export const TS_OWNED_ADMIN_SUBCOMMANDS: readonly TsOwnedAdminSubcommand[] = [
  {
    name: 'setup',
    description:
      'Store the vault password, install the root daemon autostart, and set up wallet access',
  },
  {
    name: 'tui',
    description: 'Launch interactive terminal UI for wallet setup and policy configuration',
  },
  {
    name: 'reset',
    description: 'Remove the managed daemon state and local wallet credentials',
  },
  {
    name: 'uninstall',
    description: 'Fully remove the managed daemon, local files, and logs',
  },
  {
    name: 'wallet-backup',
    description: 'Export and verify encrypted offline wallet backups',
  },
  {
    name: 'resume-manual-approval-request',
    description: 'Resume an approved broadcast-backed manual approval request on this machine',
  },
  {
    name: 'chain',
    description: 'Manage active chain selection and chain profiles',
  },
  {
    name: 'token',
    description: 'Manage shared token definitions and default policies',
  },
  {
    name: 'daemon',
    description: 'Daemon launch is managed by admin setup',
  },
];

const HIDDEN_RUST_ADMIN_SUBCOMMANDS = ['bootstrap', 'rotate-agent-auth-token', 'revoke-agent-key'];
const HELP_COLUMN_WIDTH = 33;

function renderSubcommandRow(subcommand: TsOwnedAdminSubcommand): string {
  return `  ${subcommand.name.padEnd(HELP_COLUMN_WIDTH - 2)}${subcommand.description}`;
}

export function renderTsOwnedAdminSubcommandTable(): string {
  return TS_OWNED_ADMIN_SUBCOMMANDS.map(renderSubcommandRow).join('\n');
}

/**
 * Help text shown when the Rust admin binary is unavailable so `agentpay admin --help` still
 * documents the TypeScript-owned subcommands.
 */
export function renderTsOwnedAdminHelpText(): string {
  return [
    'Admin CLI for configuring daemon setup, policies, chains, tokens, and agent keys',
    '',
    'Usage: agentpay admin <COMMAND>',
    '',
    'Commands:',
    renderTsOwnedAdminSubcommandTable(),
    '',
  ].join('\n');
}

function isRustSubcommandLine(line: string, name: string): boolean {
  return new RegExp(`^\\s{2,}${name}(\\s|$)`, 'u').test(line);
}

function isCommandsHeading(line: string): boolean {
  return /^Commands:\s*$/u.test(line);
}

function isHelpRow(line: string): boolean {
  return isRustSubcommandLine(line, 'help');
}

export function rewriteAdminHelpText(value: string): string {
  const tsOwnedNames = new Set(TS_OWNED_ADMIN_SUBCOMMANDS.map((subcommand) => subcommand.name));
  const lines = value
    .replaceAll('agentpay-admin', 'agentpay admin')
    .replace(
      'Admin CLI for configuring vault policies and agent keys',
      'Admin CLI for configuring daemon setup, policies, chains, tokens, and agent keys',
    )
    .split('\n')
    .filter(
      (line) =>
        !HIDDEN_RUST_ADMIN_SUBCOMMANDS.some((name) => isRustSubcommandLine(line, name)) &&
        !Array.from(tsOwnedNames).some((name) => isRustSubcommandLine(line, name)),
    );

  const tableRows = TS_OWNED_ADMIN_SUBCOMMANDS.map(renderSubcommandRow);
  const helpRowIndex = lines.findIndex(isHelpRow);
  if (helpRowIndex >= 0) {
    lines.splice(helpRowIndex, 0, ...tableRows);
    return lines.join('\n');
  }

  const commandsHeadingIndex = lines.findIndex(isCommandsHeading);
  if (commandsHeadingIndex >= 0) {
    let insertAt = commandsHeadingIndex + 1;
    while (insertAt < lines.length && /^\s{2,}\S/u.test(lines[insertAt])) {
      insertAt += 1;
    }
    lines.splice(insertAt, 0, ...tableRows);
    return lines.join('\n');
  }

  const trimmed = lines.join('\n').replace(/\s+$/u, '');
  return `${trimmed}\n\nCommands:\n${tableRows.join('\n')}\n`;
}

export function blockedRawAdminPassthroughMessage(command: string | undefined): string | null {
  if (command === 'rotate-agent-auth-token') {
    return '`agentpay admin rotate-agent-auth-token` is disabled; use `agentpay config agent-auth rotate` so the rotated token is stored in the local credential store.';
  }
  if (command === 'revoke-agent-key') {
    return '`agentpay admin revoke-agent-key` is disabled; use `agentpay config agent-auth revoke` so local credentials are removed safely.';
  }
  return null;
}

const COMMANDER_INFORMATIONAL_EXIT_CODES = new Set([
  'commander.help',
  'commander.helpDisplayed',
  'commander.version',
]);

interface CommanderErrorLike {
  code: string;
  exitCode?: number;
}

export function resolveCommanderErrorLike(error: unknown): CommanderErrorLike | null {
  if (!error || typeof error !== 'object' || !('code' in error)) {
    return null;
  }
  const code = (error as { code?: unknown }).code;
  if (typeof code !== 'string' || !code.startsWith('commander.')) {
    return null;
  }
  const exitCode = (error as { exitCode?: unknown }).exitCode;
  return {
    code,
    exitCode: typeof exitCode === 'number' ? exitCode : undefined,
  };
}

/**
 * Commander only copies `exitOverride` into subcommands created after it is set, so commands
 * built first (e.g. `chain add`) would still call `process.exit()` on usage errors or `--help`.
 */
function applyExitOverrideRecursively(command: Command): void {
  command.exitOverride();
  for (const subcommand of command.commands) {
    applyExitOverrideRecursively(subcommand);
  }
}

/**
 * Parses a nested commander program without letting commander call `process.exit()` itself.
 * Help/version requests resolve normally, and usage errors (which commander already printed)
 * only set the exit code so the root program does not print them a second time or surface the
 * literal `(outputHelp)` placeholder message.
 */
export async function parseNestedAdminCommand(command: Command, argv: string[]): Promise<void> {
  applyExitOverrideRecursively(command);

  try {
    await command.parseAsync(argv, { from: 'user' });
  } catch (error) {
    const commanderError = resolveCommanderErrorLike(error);
    if (!commanderError) {
      throw error;
    }
    if (COMMANDER_INFORMATIONAL_EXIT_CODES.has(commanderError.code)) {
      return;
    }
    process.exitCode = commanderError.exitCode ?? 1;
  }
}
