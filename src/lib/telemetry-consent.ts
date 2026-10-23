import { randomUUID } from 'node:crypto';
import {
  ensureAgentPayHome,
  readPrivateJson,
  resolveTelemetryPath,
  writePrivateJson,
} from '../../packages/config/src/index.js';
import { mixpanelToken, sentryDsn } from './telemetry-credentials.js';

const TELEMETRY_FILE_LABEL = 'telemetry file';

export type TelemetryDisabledReason =
  | 'env-opt-out'
  | 'do-not-track'
  | 'stored-opt-out'
  | 'unreadable-state'
  | 'delivery-backoff'
  | 'missing-credentials';

export interface TelemetryState {
  enabled: boolean;
  installId: string;
  noticeShownAt?: string;
  lastBalanceSnapshotAt?: string;
  /** Set after a failed delivery; suppresses sending until it elapses. */
  offlineUntil?: string;
}

/** Everything except the install id, which is fixed for the life of the file. */
export type TelemetryStatePatch = Partial<Omit<TelemetryState, 'installId'>>;

export interface TelemetryConsent {
  enabled: boolean;
  reason?: TelemetryDisabledReason;
  state?: TelemetryState;
}

const FIRST_RUN_NOTICE = [
  'AgentPay collects anonymous usage analytics and crash reports to understand adoption.',
  'It never collects private keys, passwords, wallet or recipient addresses, transaction hashes,',
  'or exact amounts; amounts and balances are reported only as coarse ranges.',
  'Opt out with `agentpay telemetry disable` or by setting AGENTPAY_TELEMETRY=0.',
].join('\n');

const FALSEY_ENV_VALUES = new Set(['', '0', 'false', 'no', 'off']);

/**
 * The Do Not Track convention treats any value other than `0` (or empty) as opting out, so a
 * `DO_NOT_TRACK=true` in someone's shell profile must be honoured.
 */
function isEnvOptOut(value: string | undefined): boolean {
  if (value === undefined) {
    return false;
  }

  return !FALSEY_ENV_VALUES.has(value.trim().toLowerCase());
}

function isEnvDisabled(value: string | undefined): boolean {
  return value !== undefined && FALSEY_ENV_VALUES.has(value.trim().toLowerCase());
}

type TelemetryStateRead =
  | { status: 'missing' }
  | { status: 'corrupt' }
  | { status: 'ok'; state: TelemetryState };

function readTelemetryStateResult(): TelemetryStateRead {
  try {
    const parsed = readPrivateJson<TelemetryState>(resolveTelemetryPath(), TELEMETRY_FILE_LABEL);
    if (parsed === null) {
      return { status: 'missing' };
    }
    if (typeof parsed.installId !== 'string' || !parsed.installId.trim()) {
      return { status: 'corrupt' };
    }
    return { state: parsed, status: 'ok' };
  } catch {
    return { status: 'corrupt' };
  }
}

export function readTelemetryState(): TelemetryState | null {
  const result = readTelemetryStateResult();
  return result.status === 'ok' ? result.state : null;
}

export function writeTelemetryState(state: TelemetryState): TelemetryState {
  ensureAgentPayHome();
  writePrivateJson(resolveTelemetryPath(), state, TELEMETRY_FILE_LABEL);
  return state;
}

/**
 * The only way to update an existing file. It re-reads immediately before writing and changes
 * nothing but the given fields, so a process that captured its state at startup cannot overwrite
 * an `agentpay telemetry disable` that ran in the meantime. Returns null, and writes nothing, when
 * the file is missing or unreadable: a patch must never resurrect a file that has gone away.
 */
export function patchTelemetryState(fields: TelemetryStatePatch): TelemetryState | null {
  const existing = readTelemetryStateResult();
  if (existing.status !== 'ok') {
    return null;
  }

  return writeTelemetryState({ ...existing.state, ...fields });
}

export function ensureTelemetryState(): TelemetryState {
  const existing = readTelemetryStateResult();
  if (existing.status === 'ok') {
    return existing.state;
  }

  return writeTelemetryState({ enabled: true, installId: randomUUID() });
}

export function resolveTelemetryConsent(env: NodeJS.ProcessEnv = process.env): TelemetryConsent {
  if (isEnvDisabled(env.AGENTPAY_TELEMETRY)) {
    return { enabled: false, reason: 'env-opt-out' };
  }
  if (isEnvOptOut(env.DO_NOT_TRACK)) {
    return { enabled: false, reason: 'do-not-track' };
  }
  if (!sentryDsn() && !mixpanelToken()) {
    return { enabled: false, reason: 'missing-credentials' };
  }

  const existing = readTelemetryStateResult();
  // A file we cannot parse may be a mangled opt-out, so fail closed rather than resurrecting
  // collection. `agentpay telemetry enable` rewrites the file and recovers.
  if (existing.status === 'corrupt') {
    return { enabled: false, reason: 'unreadable-state' };
  }
  if (existing.status === 'ok') {
    if (existing.state.enabled === false) {
      return { enabled: false, reason: 'stored-opt-out', state: existing.state };
    }
    const offlineUntil = existing.state.offlineUntil
      ? Date.parse(existing.state.offlineUntil)
      : Number.NaN;
    if (Number.isFinite(offlineUntil) && Date.now() < offlineUntil) {
      return { enabled: false, reason: 'delivery-backoff', state: existing.state };
    }
    return { enabled: true, state: existing.state };
  }

  try {
    return { enabled: true, state: ensureTelemetryState() };
  } catch {
    // Without durable state there is no install id and no way to record the notice, so stay off.
    return { enabled: false, reason: 'unreadable-state' };
  }
}

/**
 * Writes the disclosure to stderr so `--json` stdout stays machine-parseable.
 */
export function printFirstRunNotice(state: TelemetryState): TelemetryState {
  if (state.noticeShownAt) {
    return state;
  }

  console.error(FIRST_RUN_NOTICE);
  try {
    return patchTelemetryState({ noticeShownAt: new Date().toISOString() }) ?? state;
  } catch {
    return state;
  }
}

/**
 * Patches an existing file so a concurrent write of the throttle or backoff fields cannot be lost,
 * and rewrites it from scratch only when there is nothing usable to patch — which is also how a
 * corrupt file is recovered.
 */
export function setTelemetryEnabled(enabled: boolean): TelemetryState {
  return (
    patchTelemetryState({ enabled }) ?? writeTelemetryState({ enabled, installId: randomUUID() })
  );
}
