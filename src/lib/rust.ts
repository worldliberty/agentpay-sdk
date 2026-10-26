import { type ChildProcess, spawn } from 'node:child_process';
import fs from 'node:fs';
import { constants as osConstants } from 'node:os';
import type { Writable } from 'node:stream';
import type { WlfiConfig } from '../../packages/config/src/index.js';
import * as configModule from '../../packages/config/src/index.js';
import { assertTrustedExecutablePath } from './fs-trust.js';
import { resolveValidatedPassthroughDaemonSocket } from './passthrough-security.js';
import { prepareSpawnOptions, type RunRustBinaryOptions } from './rust-spawn-options.js';

const { readConfig, resolveRustBinaryPath } =
  configModule as typeof import('../../packages/config/src/index.js');

export type RustBinaryName = 'agentpay-daemon' | 'agentpay-admin' | 'agentpay-agent';

const MAX_STDOUT_SNIPPET_CHARS = 200;
export const MAX_RUST_BINARY_OUTPUT_BYTES = 4 * 1024 * 1024;
const SIGTERM_GRACE_MS = 2_000;

export interface RustBinaryErrorOptions {
  sensitiveStdout?: boolean;
}

function summarizeRustStderr(binaryName: RustBinaryName, code: number, stderr: string): string {
  const uniqueLines: string[] = [];
  const seen = new Set<string>();

  for (const rawLine of stderr.split(/\r?\n/u)) {
    const normalized = rawLine
      .trim()
      .replace(/^(?:Error:|Caused by:)\s*/iu, '')
      .replace(/^\d+:\s*/u, '')
      .trim();
    if (!normalized) {
      continue;
    }
    const dedupeKey = normalized.replace(/\s+/gu, ' ');
    if (seen.has(dedupeKey)) {
      continue;
    }
    seen.add(dedupeKey);
    uniqueLines.push(normalized);
  }

  return uniqueLines.join('\n') || `${binaryName} exited with code ${code}`;
}

export class RustBinaryExitError extends Error {
  readonly binaryName: RustBinaryName;
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;

  constructor(
    binaryName: RustBinaryName,
    code: number,
    stdout: string,
    stderr: string,
    options: RustBinaryErrorOptions = {},
  ) {
    super(summarizeRustStderr(binaryName, code, stderr));
    this.name = 'RustBinaryExitError';
    this.binaryName = binaryName;
    this.code = code;
    // Sensitive stdout (for example a private-key export) is never retained on the error object.
    this.stdout = options.sensitiveStdout ? '' : stdout;
    this.stderr = stderr;
  }
}

export class RustBinaryJsonParseError extends Error {
  readonly binaryName: RustBinaryName;
  // `declare` keeps this off the instance unless the constructor assigns it, so a sensitive
  // payload does not even appear as an `undefined` own property.
  declare readonly stdout?: string;
  readonly cause: unknown;

  constructor(
    binaryName: RustBinaryName,
    stdout: string,
    cause: unknown,
    options: RustBinaryErrorOptions = {},
  ) {
    super(
      options.sensitiveStdout
        ? `${binaryName} returned non-JSON output`
        : RustBinaryJsonParseError.describe(binaryName, stdout, cause),
    );
    this.name = 'RustBinaryJsonParseError';
    this.binaryName = binaryName;
    this.cause = cause;
    if (!options.sensitiveStdout) {
      this.stdout = stdout;
    }
  }

  private static describe(binaryName: RustBinaryName, stdout: string, cause: unknown): string {
    const snippet =
      stdout.length > MAX_STDOUT_SNIPPET_CHARS
        ? `${stdout.slice(0, MAX_STDOUT_SNIPPET_CHARS)}...`
        : stdout;
    return cause instanceof Error
      ? `${binaryName} produced invalid JSON: ${cause.message}. stdout: ${snippet}`
      : `${binaryName} produced invalid JSON. stdout: ${snippet}`;
  }
}

export class RustBinaryAbortedError extends Error {
  readonly binaryName: RustBinaryName;
  readonly reason: 'timeout' | 'stdout-limit' | 'stderr-limit';

  constructor(
    binaryName: RustBinaryName,
    reason: RustBinaryAbortedError['reason'],
    detail: string,
  ) {
    super(`${binaryName} ${detail}`);
    this.name = 'RustBinaryAbortedError';
    this.binaryName = binaryName;
    this.reason = reason;
  }
}

function ensureBinary(binaryName: RustBinaryName, config?: WlfiConfig): string {
  /* c8 ignore next -- both provided-config and readConfig fallback paths are exercised, but c8 misattributes this nullish expression under --experimental-strip-types */
  const resolved = resolveRustBinaryPath(binaryName, config ?? readConfig());
  if (!fs.existsSync(resolved)) {
    throw new Error(
      `${binaryName} is not installed at ${resolved}. Reinstall the AgentPay SDK from source or rerun the one-click installer.`,
    );
  }
  assertTrustedExecutablePath(resolved);
  return resolved;
}

function forwardedArgsIncludeDaemonSocket(args: string[]): boolean {
  return args.some(
    (arg, _index) => arg === '--daemon-socket' || arg.startsWith('--daemon-socket='),
  );
}

function signalExitCode(signal: NodeJS.Signals | null): number {
  if (!signal) {
    return 1;
  }

  const signalNumber = osConstants.signals[signal];
  return typeof signalNumber === 'number' ? 128 + signalNumber : 128;
}

function resolveTimeoutMs(timeoutMs: number | undefined): number | undefined {
  if (timeoutMs === undefined) {
    return undefined;
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error('timeoutMs must be a positive number of milliseconds');
  }
  return timeoutMs;
}

/**
 * Accumulates raw chunks and decodes them once at exit so multibyte UTF-8 sequences split across
 * chunk boundaries are never corrupted. Reports when the configured byte budget is exceeded.
 */
class ChildOutputCollector {
  private readonly chunks: Buffer[] = [];
  private readonly limitBytes: number;
  private totalBytes = 0;
  private exceeded = false;

  constructor(limitBytes: number) {
    this.limitBytes = limitBytes;
  }

  push(chunk: Buffer | string): boolean {
    if (this.exceeded) {
      return false;
    }
    const buffer = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
    this.totalBytes += buffer.length;
    if (this.totalBytes > this.limitBytes) {
      this.exceeded = true;
      this.chunks.length = 0;
      return false;
    }
    this.chunks.push(buffer);
    return true;
  }

  decode(): string {
    return Buffer.concat(this.chunks).toString('utf8');
  }
}

/**
 * Write a secret payload to a child's stdin without letting a fast-exiting child crash the parent:
 * EPIPE / destroyed-stream errors and child close are all treated as "the child no longer wants
 * stdin" and resolve normally. Any other stream error rejects.
 */
export async function writeChildStdin(child: ChildProcess, stdin?: string | Buffer): Promise<void> {
  await writeChildInputStream(child, child.stdin, stdin);
}

/**
 * Same EPIPE-safe write-and-close as {@link writeChildStdin}, for the extra input pipe a child
 * inherits on fd 3 (used to hand over secrets without touching disk or argv).
 */
export async function writeChildExtraInputFd3(
  child: ChildProcess,
  payload: string | Buffer,
): Promise<void> {
  const stream = child.stdio[3];
  await writeChildInputStream(
    child,
    stream && 'write' in stream ? (stream as Writable) : null,
    payload,
  );
}

async function writeChildInputStream(
  child: ChildProcess,
  stream: Writable | null | undefined,
  stdin?: string | Buffer,
): Promise<void> {
  /* c8 ignore next 3 -- child.stdin is expected whenever this helper is used, but keep the guard for defensive mocked/process edge cases */
  if (!stream) {
    return;
  }

  await new Promise<void>((resolve, reject) => {
    let settled = false;

    const cleanup = () => {
      stream.off('close', handleClose);
      /* c8 ignore next 3 -- defensive re-entry guard */
      stream.off('error', handleError);
      child.off('close', handleChildClose);
    };

    const finish = () => {
      /* c8 ignore next 3 -- defensive re-entry guard */
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      resolve();
    };

    const handleError = (error: NodeJS.ErrnoException) => {
      /* c8 ignore next 3 -- defensive re-entry guard */
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
      const onEnded = () => {
        // Keep the error listener attached until the pipe or child actually closes.
      };
      if (stdin === undefined) {
        stream.end(onEnded);
      } else {
        stream.end(stdin, onEnded);
      }
    } catch (error) {
      handleError(error as NodeJS.ErrnoException);
    }
  });
}

export async function passthroughRustBinary(
  binaryName: RustBinaryName,
  args: string[],
  config?: WlfiConfig,
): Promise<number> {
  /* c8 ignore next -- both provided-config and readConfig fallback paths are exercised, but c8 misattributes this nullish expression under --experimental-strip-types */
  const resolvedConfig = config ?? readConfig();
  const resolvedDaemonSocket = resolveValidatedPassthroughDaemonSocket(
    binaryName,
    args,
    resolvedConfig,
  );
  const executable = ensureBinary(binaryName, resolvedConfig);
  const prepared = await prepareSpawnOptions(binaryName, args, {});
  const env = { ...prepared.env };
  if (
    resolvedDaemonSocket &&
    !forwardedArgsIncludeDaemonSocket(args) &&
    /* c8 ignore next -- explicit env override is exercised, but c8 misattributes this optional-chain/nullish check */
    !env.AGENTPAY_DAEMON_SOCKET?.trim()
  ) {
    env.AGENTPAY_DAEMON_SOCKET = resolvedDaemonSocket;
  }
  const child = spawn(executable, prepared.args, {
    stdio: [prepared.stdin !== undefined ? 'pipe' : 'inherit', 'inherit', 'inherit'],
    env,
  });

  const codePromise = new Promise<number>((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code, signal) => {
      if (code !== null && code !== undefined) {
        resolve(code);
        return;
      }
      resolve(signalExitCode(signal));
    });
  });
  const stdinPromise =
    prepared.stdin !== undefined ? writeChildStdin(child, prepared.stdin) : Promise.resolve();
  const [code] = await Promise.all([codePromise, stdinPromise]);
  return code;
}

export async function runRustBinary(
  binaryName: RustBinaryName,
  args: string[],
  config?: WlfiConfig,
  options: RunRustBinaryOptions = {},
): Promise<{ stdout: string; stderr: string; code: number }> {
  const resolvedConfig = config ?? readConfig();
  const timeoutMs = resolveTimeoutMs(options.timeoutMs);
  const resolvedDaemonSocket = resolveValidatedPassthroughDaemonSocket(
    binaryName,
    args,
    resolvedConfig,
  );
  const executable = ensureBinary(binaryName, resolvedConfig);
  const prepared = await prepareSpawnOptions(binaryName, args, options);
  const env = { ...prepared.env };
  if (
    resolvedDaemonSocket &&
    !forwardedArgsIncludeDaemonSocket(args) &&
    !env.AGENTPAY_DAEMON_SOCKET?.trim()
  ) {
    env.AGENTPAY_DAEMON_SOCKET = resolvedDaemonSocket;
  }
  const extraInputFd3 = options.extraInputFd3;
  const stdinMode = prepared.stdin !== undefined ? 'pipe' : 'ignore';
  const child = spawn(executable, prepared.args, {
    stdio:
      extraInputFd3 !== undefined
        ? [stdinMode, 'pipe', 'pipe', 'pipe']
        : [stdinMode, 'pipe', 'pipe'],
    env,
  });

  const stdoutCollector = new ChildOutputCollector(MAX_RUST_BINARY_OUTPUT_BYTES);
  const stderrCollector = new ChildOutputCollector(MAX_RUST_BINARY_OUTPUT_BYTES);
  let abortReason: RustBinaryAbortedError['reason'] | null = null;
  let timeoutTimer: NodeJS.Timeout | undefined;
  let graceTimer: NodeJS.Timeout | undefined;

  const forceKill = () => {
    try {
      child.kill('SIGKILL');
    } catch {
      // The child may already be gone; nothing else to do.
    }
  };
  const abort = (reason: RustBinaryAbortedError['reason'], graceful: boolean) => {
    if (abortReason !== null) {
      return;
    }
    abortReason = reason;
    // Drop our read ends so any orphaned grandchild holding the pipes dies of SIGPIPE instead of
    // keeping the close event pending, and so a runaway writer cannot keep filling memory.
    child.stdout?.destroy();
    child.stderr?.destroy();
    if (graceful) {
      try {
        child.kill('SIGTERM');
      } catch {
        // Fall through to the SIGKILL escalation below.
      }
      graceTimer = setTimeout(forceKill, SIGTERM_GRACE_MS);
      graceTimer.unref();
      return;
    }
    forceKill();
  };

  child.stdout?.on('data', (chunk: Buffer) => {
    if (!stdoutCollector.push(chunk)) {
      abort('stdout-limit', false);
    }
  });
  child.stderr?.on('data', (chunk: Buffer) => {
    if (!stderrCollector.push(chunk)) {
      abort('stderr-limit', false);
    }
  });
  if (timeoutMs !== undefined) {
    timeoutTimer = setTimeout(() => abort('timeout', true), timeoutMs);
    timeoutTimer.unref();
  }

  const codePromise = new Promise<number>((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code, signal) => {
      if (timeoutTimer) {
        clearTimeout(timeoutTimer);
      }
      if (graceTimer) {
        clearTimeout(graceTimer);
      }
      if (code !== null && code !== undefined) {
        resolve(code);
      } else {
        // Terminated by signal. Preserve the remote behavior while still waiting for stdin writes.
        resolve(signalExitCode(signal));
      }
    });
  });
  const stdinPromise =
    prepared.stdin !== undefined ? writeChildStdin(child, prepared.stdin) : Promise.resolve();
  const extraInputPromise =
    extraInputFd3 !== undefined ? writeChildExtraInputFd3(child, extraInputFd3) : Promise.resolve();
  const [code] = await Promise.all([codePromise, stdinPromise, extraInputPromise]);

  if (abortReason === 'timeout') {
    throw new RustBinaryAbortedError(
      binaryName,
      abortReason,
      `did not exit within ${timeoutMs}ms and was terminated`,
    );
  }
  if (abortReason !== null) {
    const streamName = abortReason === 'stdout-limit' ? 'stdout' : 'stderr';
    throw new RustBinaryAbortedError(
      binaryName,
      abortReason,
      `produced more than ${MAX_RUST_BINARY_OUTPUT_BYTES} bytes on ${streamName} and was terminated`,
    );
  }

  const stdout = stdoutCollector.decode();
  const stderr = stderrCollector.decode();

  if (code !== 0) {
    throw new RustBinaryExitError(binaryName, code, stdout, stderr, {
      sensitiveStdout: options.sensitiveStdout,
    });
  }

  return { stdout, stderr, code };
}

export async function runRustBinaryJson<T>(
  binaryName: RustBinaryName,
  args: string[],
  config?: WlfiConfig,
  options: RunRustBinaryOptions = {},
): Promise<T> {
  const { stdout } = await runRustBinary(binaryName, args, config, options);
  try {
    return JSON.parse(stdout) as T;
  } catch (error) {
    throw new RustBinaryJsonParseError(binaryName, stdout, error, {
      sensitiveStdout: options.sensitiveStdout,
    });
  }
}
