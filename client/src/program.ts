/** The `agentpay` command line: every command, wired to a `Context`. */
import { Command, CommanderError } from 'commander';
import { type Context, createContext } from './app/context.js';
import { registerAdminCommands } from './commands/admin.js';
import { registerConfigCommands } from './commands/config.js';
import { registerEvmCommands } from './commands/evm.js';
import { registerHttpCommands } from './commands/http.js';
import { registerActivityCommands } from './commands/notify.js';
import { reportError } from './commands/output.js';
import { registerPrivilegedCommand } from './commands/privileged.js';
import { registerProxyCommands } from './commands/proxy.js';
import { type CommandEnv, handler } from './commands/run.js';
import { openHome, registerSetupCommands } from './commands/setup.js';
import { registerSolanaCommands } from './commands/solana.js';
import { registerWalletCommands } from './commands/wallet.js';
import { copy } from './copy/index.js';
import { EXIT, UsageError } from './errors.js';

export const VERSION = '1.0.0';

export function buildProgram(env: CommandEnv): Command {
  const io = env.context.io;
  const program = new Command('agentpay')
    .description(copy.commands.program.description)
    .version(VERSION)
    .option('--daemon-socket <path>', 'Signer daemon socket (development)')
    .option('--payments-socket <path>', 'Payments service socket (development)')
    .showHelpAfterError('(run agentpay --help for usage)')
    .allowExcessArguments()
    .exitOverride()
    .configureOutput({
      writeOut: (text) => io.stdout(text),
      writeErr: (text) => io.stderr(text),
    });

  program.hook('preAction', () => {
    const { daemonSocket, paymentsSocket } = program.opts<{
      daemonSocket?: string;
      paymentsSocket?: string;
    }>();
    if (daemonSocket || paymentsSocket) {
      env.context.setSockets({ daemonSocket, paymentsSocket });
    }
  });

  registerWalletCommands(program, env);
  registerActivityCommands(program, env);
  registerEvmCommands(program, env);
  registerSolanaCommands(program, env);
  registerHttpCommands(program, env);
  registerProxyCommands(program, env);
  registerConfigCommands(program, env);
  registerAdminCommands(program, env);
  const admin = program.commands.find((command) => command.name() === 'admin');
  if (admin) {
    registerPrivilegedCommand(admin, env);
  }
  registerSetupCommands(program, env);

  program.action(
    handler(env, async () => {
      const [unknown] = program.args;
      if (unknown !== undefined) {
        throw new UsageError(`unknown command "${unknown}"`);
      }
      if (!io.isTTY) {
        program.outputHelp();
        return EXIT.ok;
      }
      return openHome(env);
    }),
  );
  return program;
}

/** Parses `argv` (without the node and script entries) and runs the command. */
export async function runCli(
  argv: readonly string[],
  context: Context = createContext(),
): Promise<number> {
  const env: CommandEnv = { context, outcome: { exitCode: EXIT.ok } };
  const program = buildProgram(env);
  try {
    await program.parseAsync([...argv], { from: 'user' });
  } catch (error) {
    if (error instanceof CommanderError) {
      // Help and version exit with code 0; usage errors were already printed by commander.
      return error.exitCode === 0 ? EXIT.ok : EXIT.usage;
    }
    return reportError(context.io, argv.includes('--json'), error);
  }
  return env.outcome.exitCode;
}
