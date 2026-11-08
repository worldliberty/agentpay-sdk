/** Wraps command actions: errors become guidance plus an exit code, never a stack trace. */
import type { Context } from '../app/context.js';
import { reportError } from './output.js';

export interface Outcome {
  exitCode: number;
}

export interface CommandEnv {
  context: Context;
  outcome: Outcome;
}

function jsonRequested(args: readonly unknown[]): boolean {
  // Commander passes (...arguments, options, command); options carry `json`.
  const options = args[args.length - 2];
  return (
    typeof options === 'object' && options !== null && (options as { json?: unknown }).json === true
  );
}

/**
 * Options a parent command also defines (`--json`, `--agent-key-id`, ...) are parsed by the
 * parent when they follow a subcommand (`admin limits set usdc --json`): merge them in, the
 * subcommand's own values first.
 */
function withParentOptions(args: unknown[]): void {
  const command = args[args.length - 1] as { optsWithGlobals?: () => Record<string, unknown> };
  const options = args[args.length - 2];
  if (typeof command?.optsWithGlobals === 'function' && typeof options === 'object' && options) {
    args[args.length - 2] = { ...command.optsWithGlobals(), ...options };
  }
}

/** Runs `fn`, records its exit code (a returned number, else 0), and reports thrown errors. */
export function handler<A extends unknown[]>(
  env: CommandEnv,
  fn: (...args: A) => Promise<unknown>,
): (...args: A) => Promise<void> {
  return async (...args: A) => {
    withParentOptions(args);
    try {
      const result = await fn(...args);
      env.outcome.exitCode = typeof result === 'number' ? result : 0;
    } catch (error) {
      env.outcome.exitCode = reportError(env.context.io, jsonRequested(args), error);
    }
  };
}
