import { sentryDsn, telemetryEnvironment } from './telemetry-credentials.js';
import { scrubProperties, scrubText } from './telemetry-scrub.js';

const CLOSE_TIMEOUT_MS = 2_000;

type SentryModule = typeof import('@sentry/node');

let sentry: SentryModule | undefined;

interface SentryFrame {
  filename?: string;
  abs_path?: string;
  module?: string;
}

/** The subset of a Sentry event that `scrubEvent` inspects; everything else passes through. */
export interface SentryEventLike {
  message?: string;
  exception?: { values?: Array<{ value?: string; stacktrace?: { frames?: SentryFrame[] } }> };
  extra?: Record<string, unknown>;
  tags?: Record<string, unknown>;
  contexts?: Record<string, Record<string, unknown> | undefined>;
  user?: Record<string, unknown>;
  server_name?: string;
  breadcrumbs?: unknown;
  modules?: unknown;
  request?: unknown;
  debug_meta?: unknown;
}

/**
 * Only these `contexts` entries survive, and only their `name`/`version` fields. `device`, `app`,
 * and `culture` describe the machine and its owner (hostname, locale, timezone, memory, boot
 * time), and the full `runtime`/`os` contexts carry the same kind of detail.
 */
const ALLOWED_CONTEXTS: ReadonlySet<string> = new Set(['os', 'runtime', 'trace']);
const ALLOWED_CONTEXT_FIELDS: ReadonlySet<string> = new Set(['name', 'version']);
const FRAME_PATH_FIELDS = ['filename', 'abs_path', 'module'] as const;

function pruneContexts(
  contexts: SentryEventLike['contexts'],
): SentryEventLike['contexts'] | undefined {
  if (!contexts) {
    return undefined;
  }

  const pruned: Record<string, Record<string, unknown>> = {};
  for (const [name, context] of Object.entries(contexts)) {
    if (!context || !ALLOWED_CONTEXTS.has(name)) {
      continue;
    }
    if (name === 'trace') {
      pruned[name] = scrubProperties(context);
      continue;
    }
    const kept: Record<string, unknown> = {};
    for (const field of ALLOWED_CONTEXT_FIELDS) {
      if (typeof context[field] === 'string') {
        kept[field] = scrubText(context[field]);
      }
    }
    if (Object.keys(kept).length > 0) {
      pruned[name] = kept;
    }
  }

  return Object.keys(pruned).length > 0 ? pruned : undefined;
}

/**
 * Runs as `beforeSend`. Everything the SDK may have attached about the machine or the person is
 * removed; what remains is the error type, the scrubbed message and stack, and our own tags.
 */
export function scrubEvent(event: SentryEventLike): SentryEventLike {
  if (typeof event.message === 'string') {
    event.message = scrubText(event.message);
  }

  for (const value of event.exception?.values ?? []) {
    if (typeof value.value === 'string') {
      value.value = scrubText(value.value);
    }
    for (const frame of value.stacktrace?.frames ?? []) {
      for (const field of FRAME_PATH_FIELDS) {
        const path = frame[field];
        if (typeof path === 'string') {
          frame[field] = scrubText(path);
        }
      }
    }
  }

  if (event.extra) {
    event.extra = scrubProperties(event.extra);
  }
  if (event.tags) {
    event.tags = scrubProperties(event.tags);
  }

  const contexts = pruneContexts(event.contexts);
  if (contexts) {
    event.contexts = contexts;
  } else {
    delete event.contexts;
  }

  // The install id is the only identity analytics carries; `ip_address`, `email`, `username`,
  // and `geo` must never ride along even if a future integration tries to add them.
  const userId = event.user?.id;
  if (typeof userId === 'string' || typeof userId === 'number') {
    event.user = { id: userId };
  } else {
    delete event.user;
  }

  // `server_name` is the hostname. Breadcrumbs are already suppressed by `beforeBreadcrumb`, but an
  // event that arrives with any attached must not carry unscrubbed console or HTTP payloads.
  // `modules` lists installed packages, `request` would be a URL, and `debug_meta` holds file
  // paths for source maps we do not upload.
  delete event.server_name;
  delete event.breadcrumbs;
  delete event.modules;
  delete event.request;
  delete event.debug_meta;

  return event;
}

/**
 * Loads the SDK lazily so invocations that never report an error do not pay the import cost.
 * A missing or broken `@sentry/node` install must not break the CLI, so failures are swallowed.
 */
export async function initSentry(options: {
  release: string;
  distinctId: string;
  tags: Record<string, string>;
}): Promise<void> {
  const dsn = sentryDsn();
  if (!dsn || sentry) {
    return;
  }

  try {
    const loaded = (await import('@sentry/node')) as SentryModule;
    loaded.init({
      beforeSend: (event) => scrubEvent(event as SentryEventLike) as never,
      // The console/HTTP integrations record every `print()` line and RPC URL as a breadcrumb,
      // which would ship recipient addresses, transaction hashes, and API-key-bearing RPC URLs. A
      // short-lived CLI gains little from breadcrumbs, so drop them at the source.
      beforeBreadcrumb: () => null,
      // Nothing in the default set is wanted: console, http, nativeNodeFetch, and childProcess
      // capture output, URLs, and the argv handed to the Rust binaries; onUncaughtException and
      // onUnhandledRejection would report (and exit on) errors outside `main().catch`; nodeContext,
      // modules, and processSession describe the machine rather than the crash. linkedErrors is
      // kept so `cause` chains stay attached — every message in the chain is still scrubbed above.
      defaultIntegrations: false,
      dsn,
      environment: telemetryEnvironment(),
      includeServerName: false,
      integrations: [loaded.linkedErrorsIntegration()],
      registerEsmLoaderHooks: false,
      release: options.release,
      sendDefaultPii: false,
      // Error-only reporting needs no OpenTelemetry tracer, propagator, or context manager, and
      // not installing them keeps the SDK from touching globals the CLI's own HTTP clients use.
      skipOpenTelemetrySetup: true,
      tracesSampleRate: 0,
    });
    loaded.setUser({ id: options.distinctId });
    loaded.setTags(options.tags);
    sentry = loaded;
  } catch {
    sentry = undefined;
  }
}

export function captureCliError(error: unknown): void {
  try {
    sentry?.captureException(error);
  } catch {
    // Reporting a crash must never cause one.
  }
}

/**
 * Drains the queue and disables the client. `close()` rather than `flush()` so that once the
 * deadline passes nothing can start another request against an endpoint that accepted the socket
 * but never answered; the socket itself is only released when the process exits, which
 * `main().finally` forces.
 */
export async function closeSentry(): Promise<boolean> {
  if (!sentry) {
    return true;
  }

  try {
    return await sentry.close(CLOSE_TIMEOUT_MS);
  } catch {
    // Offline or blocked. Drop the report.
    return false;
  }
}

export function isSentryActive(): boolean {
  return sentry !== undefined;
}
