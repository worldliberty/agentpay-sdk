import { randomUUID } from 'node:crypto';
import { mixpanelToken, mixpanelTrackUrl } from './telemetry-credentials.js';
import { scrubProperties } from './telemetry-scrub.js';

const FLUSH_TIMEOUT_MS = 2_000;
const MAX_QUEUED_EVENTS = 50;
/** Timestamps are truncated to this so an event cannot be lined up with an on-chain block time. */
const TIME_GRANULARITY_MS = 60_000;

interface MixpanelEvent {
  event: string;
  properties: Record<string, unknown>;
}

const queue: MixpanelEvent[] = [];
let distinctId: string | undefined;
let baseProperties: Record<string, unknown> = {};

export function configureMixpanel(
  nextDistinctId: string,
  nextBaseProperties: Record<string, unknown>,
): void {
  distinctId = nextDistinctId;
  baseProperties = scrubProperties(nextBaseProperties);
}

export function trackMixpanelEvent(event: string, properties: Record<string, unknown>): void {
  if (!mixpanelToken() || !distinctId || queue.length >= MAX_QUEUED_EVENTS) {
    return;
  }

  queue.push({
    event,
    properties: {
      ...baseProperties,
      ...scrubProperties(properties),
      $insert_id: randomUUID(),
      distinct_id: distinctId,
      time: Math.floor(Date.now() / TIME_GRANULARITY_MS) * TIME_GRANULARITY_MS,
      token: mixpanelToken(),
    },
  });
}

/**
 * Sends everything queued during this invocation. Failures are swallowed: analytics must never
 * change the exit code or surface an error to the user. Returns whether the batch was delivered so
 * the caller can back off from an unreachable endpoint.
 */
export async function flushMixpanel(): Promise<boolean> {
  if (queue.length === 0) {
    return true;
  }

  const payload = queue.splice(0, queue.length);

  try {
    const response = await fetch(mixpanelTrackUrl(), {
      body: JSON.stringify(payload),
      headers: { 'content-type': 'application/json' },
      method: 'POST',
      signal: AbortSignal.timeout(FLUSH_TIMEOUT_MS),
    });
    return response.ok;
  } catch {
    // Offline, blocked by a proxy, or timed out. Drop the batch.
    return false;
  }
}

export function pendingMixpanelEventCount(): number {
  return queue.length;
}

export function discardMixpanelQueue(): void {
  queue.length = 0;
}

export function resetMixpanelForTesting(): void {
  queue.length = 0;
  distinctId = undefined;
  baseProperties = {};
}
