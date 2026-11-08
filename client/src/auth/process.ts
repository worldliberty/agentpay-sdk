/**
 * Runs helper programs (`security`, `secret-tool`, `agentpay-auth`, `sudo`) without a shell.
 * Secrets only travel on stdin: never put one in `args`.
 */
import { spawn } from 'node:child_process';

export interface RunResult {
  /** Exit status; 128 + signal number when killed by a signal; -1 when it could not start. */
  status: number;
  stdout: string;
  stderr: string;
  /** Set when the program could not be started (for example `ENOENT`). */
  spawnError?: NodeJS.ErrnoException;
}

export interface RunOptions {
  input?: string;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
  /** Let the child write its stderr to the terminal (sudo password prompts). */
  inheritStderr?: boolean;
  /** Give the child this terminal entirely (stdin, stdout, stderr); nothing is captured. */
  interactive?: boolean;
}

export type CommandRunner = (
  command: string,
  args: readonly string[],
  options?: RunOptions,
) => Promise<RunResult>;

const DEFAULT_TIMEOUT_MS = 30_000;

export const runCommand: CommandRunner = (command, args, options = {}) =>
  new Promise((resolve) => {
    const child = spawn(command, [...args], {
      stdio: options.interactive
        ? 'inherit'
        : ['pipe', 'pipe', options.inheritStderr ? 'inherit' : 'pipe'],
      env: options.env ?? process.env,
    });
    const { stdin, stdout: out, stderr: err } = child;
    let stdout = '';
    let stderr = '';
    let settled = false;
    const finish = (result: RunResult) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve(result);
      }
    };
    const timer = setTimeout(
      () => {
        child.kill('SIGTERM');
      },
      options.interactive ? 2 ** 31 - 1 : (options.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    );

    out?.setEncoding('utf8');
    out?.on('data', (chunk: string) => {
      stdout += chunk;
    });
    err?.setEncoding('utf8');
    err?.on('data', (chunk: string) => {
      stderr += chunk;
    });
    child.on('error', (error: NodeJS.ErrnoException) => {
      finish({ status: -1, stdout, stderr, spawnError: error });
    });
    child.on('close', (code, signal) => {
      finish({ status: code ?? (signal ? 128 + signalNumber(signal) : 1), stdout, stderr });
    });
    stdin?.on('error', () => {
      // The child may exit before reading stdin; the exit status reports the failure.
    });
    stdin?.end(options.input ?? '');
  });

function signalNumber(signal: NodeJS.Signals): number {
  const numbers: Partial<Record<NodeJS.Signals, number>> = { SIGINT: 2, SIGKILL: 9, SIGTERM: 15 };
  return numbers[signal] ?? 0;
}
