import { type SpawnOptions, spawn } from 'node:child_process';
import { constants as osConstants } from 'node:os';

export interface SudoCommandResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface RunSudoCommandOptions {
  stdin?: string;
  inheritOutput?: boolean;
  env?: Record<string, string | undefined>;
}

interface CreateSudoSessionDeps {
  promptPassword: () => Promise<string>;
  isRoot?: () => boolean;
  spawnCommand?: typeof spawn;
  stdout?: Pick<NodeJS.WriteStream, 'write'>;
  stderr?: Pick<NodeJS.WriteStream, 'write'>;
}

function currentProcessIsRoot(): boolean {
  return typeof process.geteuid === 'function' && process.geteuid() === 0;
}

function isSudoAuthenticationFailure(output: string): boolean {
  return (
    /sudo: .*password is required/iu.test(output) ||
    /sudo: .*incorrect password/iu.test(output) ||
    /sudo: no password was provided/iu.test(output) ||
    /sorry, try again\./iu.test(output)
  );
}

function formatSudoFailureMessage(result: SudoCommandResult): string {
  const combinedOutput = `${result.stderr}\n${result.stdout}`;
  if (isSudoAuthenticationFailure(combinedOutput)) {
    return 'sudo authentication failed. Enter your system admin password used for sudo, not the AgentPay vault password.';
  }
  return (
    result.stderr.trim() ||
    result.stdout.trim() ||
    `sudo credential check failed (exit code ${result.code})`
  );
}

function signalExitCode(signal: NodeJS.Signals | null): number {
  if (!signal) {
    return 1;
  }

  const signalNumber = osConstants.signals[signal];
  return typeof signalNumber === 'number' ? 128 + signalNumber : 128;
}

async function writeChildStdin(
  child: ReturnType<typeof spawn>,
  stdin: string,
): Promise<void> {
  const stream = child.stdin;
  if (!stream) {
    return;
  }

  await new Promise<void>((resolve, reject) => {
    let settled = false;

    const cleanup = () => {
      stream.off('close', handleClose);
      stream.off('error', handleError);
      child.off('close', handleChildClose);
    };

    const finish = () => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      resolve();
    };

    const handleError = (error: NodeJS.ErrnoException) => {
      if (settled) {
        return;
      }
      if (error?.code === 'EPIPE' || error?.code === 'ERR_STREAM_DESTROYED') {
        finish();
        return;
      }
      settled = true;
      cleanup();
      reject(error);
    };

    const handleClose = () => {
      finish();
    };

    const handleChildClose = () => {
      finish();
    };

    stream.on('error', handleError);
    stream.on('close', handleClose);
    child.on('close', handleChildClose);
    try {
      stream.end(stdin, () => {
        // Keep the error listener attached until the pipe or child actually closes.
      });
    } catch (error) {
      handleError(error as NodeJS.ErrnoException);
    }
  });
}

async function runCommand(
  command: string,
  args: string[],
  options: RunSudoCommandOptions,
  deps: {
    spawnCommand: typeof spawn;
    stdout: Pick<NodeJS.WriteStream, 'write'>;
    stderr: Pick<NodeJS.WriteStream, 'write'>;
  },
): Promise<SudoCommandResult> {
  const spawnOptions: SpawnOptions = {
    stdio: ['pipe', 'pipe', 'pipe'],
  };
  const child = deps.spawnCommand(command, args, spawnOptions);

  let stdout = '';
  let stderr = '';

  child.stdout?.on('data', (chunk: Buffer | string) => {
    const text = chunk.toString();
    stdout += text;
    if (options.inheritOutput) {
      deps.stdout.write(text);
    }
  });
  child.stderr?.on('data', (chunk: Buffer | string) => {
    const text = chunk.toString();
    stderr += text;
    if (options.inheritOutput) {
      deps.stderr.write(text);
    }
  });

  const codePromise = new Promise<SudoCommandResult>((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code, signal) =>
      resolve({ code: code ?? signalExitCode(signal), stdout, stderr }),
    );
  });
  const stdinPromise = writeChildStdin(child, options.stdin ?? '');
  const [result] = await Promise.all([codePromise, stdinPromise]);
  return result;
}

function resolveEnvAssignmentArgs(
  env: Record<string, string | undefined> | undefined,
): string[] {
  if (!env) {
    return [];
  }

  return Object.entries(env)
    .filter((entry): entry is [string, string] => {
      const [key, value] = entry;
      return key.trim().length > 0 && typeof value === 'string';
    })
    .map(([key, value]) => `${key}=${value}`);
}

export function createSudoSession(deps: CreateSudoSessionDeps) {
  const spawnCommand = deps.spawnCommand ?? spawn;
  const isRoot = deps.isRoot ?? currentProcessIsRoot;
  const stdout = deps.stdout ?? process.stdout;
  const stderr = deps.stderr ?? process.stderr;
  let primed = false;

  async function prime(): Promise<void> {
    if (isRoot()) {
      primed = true;
      return;
    }
    if (primed) {
      return;
    }

    const password = await deps.promptPassword();
    const result = await runCommand(
      'sudo',
      ['-S', '-p', '', '-v'],
      {
        stdin: `${password}\n`,
      },
      {
        spawnCommand,
        stdout,
        stderr,
      },
    );

    if (result.code !== 0) {
      throw new Error(formatSudoFailureMessage(result));
    }

    primed = true;
  }

  async function run(
    args: string[],
    options: RunSudoCommandOptions = {},
  ): Promise<SudoCommandResult> {
    if (args.length === 0) {
      throw new Error('sudo command arguments are required');
    }

    const envArgs = resolveEnvAssignmentArgs(options.env);
    const commandArgs = envArgs.length > 0 ? ['/usr/bin/env', ...envArgs, ...args] : args;

    if (isRoot()) {
      return await runCommand(commandArgs[0], commandArgs.slice(1), options, {
        spawnCommand,
        stdout,
        stderr,
      });
    }

    await prime();
    let result = await runCommand(
      'sudo',
      ['-n', ...commandArgs],
      options,
      {
        spawnCommand,
        stdout,
        stderr,
      },
    );

    if (result.code === 0) {
      return result;
    }

    const combinedOutput = `${result.stderr}\n${result.stdout}`;
    if (!isSudoAuthenticationFailure(combinedOutput)) {
      return result;
    }

    primed = false;
    await prime();
    result = await runCommand(
      'sudo',
      ['-n', ...commandArgs],
      options,
      {
        spawnCommand,
        stdout,
        stderr,
      },
    );
    return result;
  }

  return {
    prime,
    run,
  };
}
