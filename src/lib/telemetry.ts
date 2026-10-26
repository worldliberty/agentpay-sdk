import os from 'node:os';
import { resolveCliVersion } from './cli-version.js';
import { setTelemetryCommandContext } from './telemetry-agent-command.js';
import { type BalanceBucket, bucketAmount, bucketDecimalString } from './telemetry-buckets.js';
import {
  patchTelemetryState,
  printFirstRunNotice,
  resolveTelemetryConsent,
  type TelemetryState,
  type TelemetryStatePatch,
} from './telemetry-consent.js';
import { telemetryEnvironment } from './telemetry-credentials.js';
import { resolveDistinctId } from './telemetry-identity.js';
import {
  configureMixpanel,
  discardMixpanelQueue,
  flushMixpanel,
  resetMixpanelForTesting,
  trackMixpanelEvent,
} from './telemetry-mixpanel.js';
import { captureCliError, closeSentry, initSentry } from './telemetry-sentry.js';
import type { WalletBalanceEntry } from './wallet-profile.js';

const BALANCE_SNAPSHOT_INTERVAL_MS = 24 * 60 * 60 * 1_000;
const OFFLINE_BACKOFF_MS = 60 * 60 * 1_000;
/**
 * Hard ceiling on everything shutdown does. Each destination has its own 2 s timeout, but those
 * only bound the request; the lazy Sentry import and any future destination must not be able to
 * hold a finished command hostage.
 */
const SHUTDOWN_DEADLINE_MS = 3_000;

export type BalanceMutationAction =
  | 'approve'
  | 'broadcast'
  | 'mpp'
  | 'private_transfer'
  | 'shield'
  | 'transfer'
  | 'transfer_native'
  | 'transfer_sol'
  | 'transfer_spl'
  | 'unshield'
  | 'x402';

export type BalanceMutationResult = 'awaiting_approval' | 'failed' | 'success';

export interface BalanceMutationEvent {
  action: BalanceMutationAction;
  chain?: string;
  chainId?: number;
  asset?: string;
  /** Exact amount in whole units. Never emitted as-is; see {@link trackBalanceMutation}. */
  amount?: number;
  broadcast: boolean;
  result: BalanceMutationResult;
}

interface CommandSession {
  command: string;
  subcommand?: string;
  startedAt: number;
}

let enabled = false;
let state: TelemetryState | undefined;
let session: CommandSession | undefined;
let sentryConfig: { distinctId: string; release: string; tags: Record<string, string> } | undefined;
let pendingErrorReport: Promise<void> | undefined;
/** Timestamp of a snapshot queued this run; committed to disk only once the batch is delivered. */
let pendingBalanceSnapshotAt: string | undefined;

/**
 * Resolves consent and wires up both destinations. Never throws: telemetry setup must not be able
 * to prevent a command from running.
 */
export async function initTelemetry(): Promise<void> {
  try {
    const consent = resolveTelemetryConsent();
    if (!consent.enabled || !consent.state) {
      return;
    }

    state = printFirstRunNotice(consent.state);
    enabled = true;

    const release = resolveCliVersion();
    const distinctId = resolveDistinctId(state.installId);
    const tags = {
      arch: process.arch,
      cli_version: release,
      environment: telemetryEnvironment(),
      platform: process.platform,
    };

    configureMixpanel(distinctId, {
      ...tags,
      node_version: process.versions.node,
      os_release: os.release(),
    });
    // Sentry is not loaded here: importing it pulls in the OpenTelemetry stack, which every
    // successful invocation would pay for and never use. It is initialized on the first error.
    sentryConfig = { distinctId, release, tags };
  } catch {
    enabled = false;
  }
}

export function isTelemetryEnabled(): boolean {
  return enabled;
}

/**
 * Stops this invocation from reporting. `initTelemetry()` runs before argv is parsed, so without
 * this the very command that opts out would still queue and flush its own `cli_session` event.
 */
export function suspendTelemetry(): void {
  enabled = false;
  session = undefined;
  pendingBalanceSnapshotAt = undefined;
  discardMixpanelQueue();
}

export function trackEvent(event: string, properties: Record<string, unknown> = {}): void {
  if (!enabled) {
    return;
  }
  trackMixpanelEvent(event, properties);
}

/**
 * Records which command is running. The matching `cli_session` event is emitted by
 * {@link endCommand} rather than a commander `postAction` hook, because that hook does not fire
 * when an action throws — and failed invocations are the ones most worth measuring.
 *
 * `subcommand` is the space-joined remainder of the commander path, as `resolveCommandPath` in the
 * CLI produces it; the same path is what lets `balance_mutation` events name the user-facing
 * command rather than the Rust subcommand that happened to sign.
 */
export function beginCommand(command: string, subcommand?: string): void {
  session = { command, startedAt: Date.now(), subcommand };
  setTelemetryCommandContext(subcommand ? [command, ...subcommand.split(' ')] : [command]);
}

export function endCommand(exitCode: number): void {
  if (!enabled || !session) {
    return;
  }

  trackEvent('cli_session', {
    command: session.command,
    duration_ms: Date.now() - session.startedAt,
    exit_code: exitCode,
    subcommand: session.subcommand,
  });
  session = undefined;
}

/** The exact amount stays in-process; only its coarse range is emitted. */
export function trackBalanceMutation(event: BalanceMutationEvent): void {
  trackEvent('balance_mutation', {
    action: event.action,
    amount_bucket: event.amount === undefined ? undefined : bucketAmount(event.amount),
    asset: event.asset,
    broadcast: event.broadcast,
    chain: event.chain,
    chain_id: event.chainId,
    result: event.result,
  });
}

/**
 * Emitted at most once a day, and only from commands that already fetched a balance for their own
 * purposes. Telemetry never issues an RPC call of its own.
 */
export function trackBalanceSnapshot(snapshot: {
  chain?: string;
  asset?: string;
  nativeBalanceBucket?: BalanceBucket;
  tokenBalanceBucket?: BalanceBucket;
}): void {
  if (!enabled || !state || pendingBalanceSnapshotAt) {
    return;
  }

  const lastAt = state.lastBalanceSnapshotAt ? Date.parse(state.lastBalanceSnapshotAt) : 0;
  if (Number.isFinite(lastAt) && Date.now() - lastAt < BALANCE_SNAPSHOT_INTERVAL_MS) {
    return;
  }

  trackEvent('balance_snapshot', {
    asset: snapshot.asset,
    chain: snapshot.chain,
    native_balance_bucket: snapshot.nativeBalanceBucket,
    token_balance_bucket: snapshot.tokenBalanceBucket,
  });
  // The throttle timestamp is written by `shutdownTelemetry` once the batch is delivered; a
  // dropped batch must not burn the day's slot.
  pendingBalanceSnapshotAt = new Date().toISOString();
}

/** Structural subset of `WalletBalanceEntry`, whose `kind` union this deliberately mirrors. */
export type WalletBalanceSnapshotEntry = Pick<
  WalletBalanceEntry,
  'kind' | 'symbol' | 'chainName' | 'balance'
>;

const NATIVE_BALANCE_KINDS = new Set<WalletBalanceEntry['kind']>(['native', 'sol']);

function largestBalance(
  entries: readonly WalletBalanceSnapshotEntry[],
  native: boolean,
): WalletBalanceSnapshotEntry | undefined {
  return entries
    .filter((entry) => NATIVE_BALANCE_KINDS.has(entry.kind) === native && entry.balance)
    .sort((a, b) => Number(b.balance?.formatted ?? 0) - Number(a.balance?.formatted ?? 0))[0];
}

/**
 * Derives a bucketed snapshot from balances the `wallet` command already fetched. Reports the
 * largest native and largest token holding so a single event describes the wallet's scale.
 */
export function trackWalletBalanceSnapshot(entries: readonly WalletBalanceSnapshotEntry[]): void {
  if (!enabled) {
    return;
  }

  const native = largestBalance(entries, true);
  const token = largestBalance(entries, false);
  // Every RPC lookup can fail and still return entries. Emitting an empty snapshot would burn the
  // 24-hour throttle and suppress the next real one.
  if (!native && !token) {
    return;
  }

  trackBalanceSnapshot({
    asset: token?.symbol,
    chain: token?.chainName ?? native?.chainName,
    nativeBalanceBucket: bucketDecimalString(native?.balance?.formatted),
    tokenBalanceBucket: bucketDecimalString(token?.balance?.formatted),
  });
}

const RUST_ERROR_NAMES: ReadonlySet<string> = new Set([
  'RustBinaryExitError',
  'RustBinaryJsonParseError',
]);

function withStackHeader(stack: string | undefined, header: string): string {
  if (!stack) {
    return header;
  }
  const firstFrame = stack.indexOf('\n    at ');
  return firstFrame >= 0 ? `${header}${stack.slice(firstFrame)}` : header;
}

/**
 * `RustBinaryExitError` folds the daemon's stderr into `.message` (and `RustBinaryJsonParseError`
 * a stdout snippet) so the user sees the real cause. Neither may reach Sentry: the daemon echoes
 * recipient addresses, amounts, and policy names. Only the binary name and exit code survive; the
 * JavaScript stack is kept so the crash still groups by call site, and `cause` is dropped because
 * a JSON `SyntaxError` quotes the text it choked on.
 */
export function sanitizeErrorForReport(error: unknown): unknown {
  if (!(error instanceof Error) || !RUST_ERROR_NAMES.has(error.name)) {
    return error;
  }

  const { binaryName, code } = error as Error & { binaryName?: unknown; code?: unknown };
  const binary = typeof binaryName === 'string' ? binaryName : 'rust binary';
  const message =
    error.name === 'RustBinaryExitError'
      ? `${binary} exited ${typeof code === 'number' ? code : 'with an unknown code'}`
      : `${binary} produced invalid JSON`;

  const sanitized = new Error(message);
  sanitized.name = error.name;
  sanitized.stack = withStackHeader(error.stack, `${error.name}: ${message}`);
  return sanitized;
}

/**
 * Loads and initializes Sentry on demand, then records the error. Called from a synchronous
 * `catch`, so the work is tracked as a promise that {@link shutdownTelemetry} awaits.
 */
export function reportTelemetryError(error: unknown): void {
  if (!enabled || !sentryConfig) {
    return;
  }

  const config = sentryConfig;
  const report = sanitizeErrorForReport(error);
  pendingErrorReport = (async () => {
    await initSentry(config);
    captureCliError(report);
  })().catch(() => undefined);
}

function withDeadline<T>(work: Promise<T>, timeoutMs: number, fallback: T): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<T>((resolve) => {
    timer = setTimeout(() => resolve(fallback), timeoutMs);
    // The timer must not itself keep a finished command alive.
    timer.unref();
  });

  return Promise.race([work, deadline]).finally(() => {
    if (timer) {
      clearTimeout(timer);
    }
  });
}

async function deliverQueuedTelemetry(): Promise<boolean> {
  await pendingErrorReport;
  const [mixpanelDelivered, sentryDelivered] = await Promise.all([flushMixpanel(), closeSentry()]);
  return mixpanelDelivered && sentryDelivered;
}

/**
 * Must run before `closeGlobalFetchProxyDispatcherFromEnv()` tears down the proxy dispatcher,
 * otherwise queued events have no working transport. Always resolves within
 * {@link SHUTDOWN_DEADLINE_MS}; an endpoint that accepts the connection and never answers is
 * treated as a failed delivery.
 */
export async function shutdownTelemetry(): Promise<void> {
  if (!enabled) {
    return;
  }

  try {
    const delivered = await withDeadline(deliverQueuedTelemetry(), SHUTDOWN_DEADLINE_MS, false);
    recordDeliveryOutcome(delivered);
  } catch {
    // Never let a flush failure change the exit code.
  }
}

/**
 * Commits what this run learned to the state file. After a failed delivery that is a backoff:
 * without it an air-gapped or firewalled machine pays the full flush timeout on every command
 * forever. After a successful one it is the snapshot throttle and the end of any backoff. Every
 * write goes through `patchTelemetryState`, so `enabled` — which only the `telemetry` commands
 * own — is never touched from here.
 */
function recordDeliveryOutcome(delivered: boolean): void {
  if (!state) {
    return;
  }

  const patch: TelemetryStatePatch = {};
  if (delivered) {
    if (state.offlineUntil) {
      patch.offlineUntil = undefined;
    }
    if (pendingBalanceSnapshotAt) {
      patch.lastBalanceSnapshotAt = pendingBalanceSnapshotAt;
    }
  } else {
    patch.offlineUntil = new Date(Date.now() + OFFLINE_BACKOFF_MS).toISOString();
  }
  if (Object.keys(patch).length === 0) {
    return;
  }

  try {
    state = patchTelemetryState(patch) ?? state;
  } catch {
    // A lost backoff only costs another timeout next run; a lost throttle only an extra snapshot.
  }
}

export function resetTelemetryForTesting(): void {
  enabled = false;
  state = undefined;
  session = undefined;
  sentryConfig = undefined;
  pendingErrorReport = undefined;
  pendingBalanceSnapshotAt = undefined;
  setTelemetryCommandContext([]);
  resetMixpanelForTesting();
}
