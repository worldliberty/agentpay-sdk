import type { Command } from 'commander';
import {
  formatWalletRepairText,
  repairWalletState,
  type WalletRepairResult,
} from './wallet-repair.js';
import {
  formatWalletStatusText,
  getWalletStatus,
  resolveWalletStatusExitCode,
  type WalletStatusExitOptions,
  type WalletStatusResult,
} from './wallet-status.js';

interface CliOutputOptions {
  asJson: boolean;
}

export interface StatusCommandDeps {
  getWalletStatus?: () => WalletStatusResult;
  print?: (payload: unknown, options: CliOutputOptions) => void;
  setExitCode?: (code: number) => void;
  resolveWalletStatusExitCode?: (
    result: WalletStatusResult,
    options?: WalletStatusExitOptions,
  ) => number;
}

export interface RepairCommandDeps {
  repairWalletState?: (input?: {
    agentKeyId?: string;
    overwriteKeychain?: boolean;
    redactBootstrap?: boolean;
  }) => WalletRepairResult;
  print?: (payload: unknown, options: CliOutputOptions) => void;
  setExitCode?: (code: number) => void;
  resolveWalletStatusExitCode?: (
    result: WalletStatusResult,
    options?: WalletStatusExitOptions,
  ) => number;
}

function defaultPrint(payload: unknown, options: CliOutputOptions): void {
  if (options.asJson) {
    process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
    return;
  }
  process.stdout.write(`${String(payload)}\n`);
}

function defaultSetExitCode(code: number): void {
  process.exitCode = code;
}

export function registerStatusCommand(program: Command, deps: StatusCommandDeps = {}): Command {
  const loadStatus = deps.getWalletStatus ?? getWalletStatus;
  const print = deps.print ?? defaultPrint;
  const setExitCode = deps.setExitCode ?? defaultSetExitCode;
  const resolveExitCode = deps.resolveWalletStatusExitCode ?? resolveWalletStatusExitCode;

  return program
    .command('status')
    .description('Inspect local wallet security, daemon, and credential health')
    .option('--strict', 'Exit with status 1 when warnings are present', false)
    .option('--json', 'Print JSON output', false)
    .action((options) => {
      const result = loadStatus();
      print(options.json ? result : formatWalletStatusText(result), {
        asJson: options.json,
      });
      setExitCode(
        resolveExitCode(result, {
          strict: options.strict,
        }),
      );
    });
}

export function registerRepairCommand(program: Command, deps: RepairCommandDeps = {}): Command {
  const runRepair = deps.repairWalletState ?? repairWalletState;
  const print = deps.print ?? defaultPrint;
  const setExitCode = deps.setExitCode ?? defaultSetExitCode;
  const resolveExitCode = deps.resolveWalletStatusExitCode ?? resolveWalletStatusExitCode;

  return program
    .command('repair')
    .description('Repair non-privileged local wallet issues and clean plaintext artifacts')
    .option('--agent-key-id <uuid>', 'Agent key id override for legacy token migration')
    .option(
      '--overwrite-keychain',
      'Replace a different existing stored local credential for this agent when migrating plaintext config storage',
      false,
    )
    .option(
      '--redact-bootstrap',
      'Redact auto-generated bootstrap files instead of deleting them',
      false,
    )
    .option('--strict', 'Exit with status 1 when warnings remain after repair', false)
    .option('--json', 'Print JSON output', false)
    .action((options) => {
      const result = runRepair({
        agentKeyId: options.agentKeyId,
        overwriteKeychain: options.overwriteKeychain,
        redactBootstrap: options.redactBootstrap,
      });
      print(options.json ? result : formatWalletRepairText(result), {
        asJson: options.json,
      });
      setExitCode(
        resolveExitCode(result.after, {
          strict: options.strict,
        }),
      );
    });
}
