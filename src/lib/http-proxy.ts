import { Agent, ProxyAgent } from 'undici';

type FetchInput = string | URL | Request;
type ProxyDispatcher = NonNullable<RequestInit['dispatcher']>;

function readEnvValue(env: NodeJS.ProcessEnv, key: string): string | undefined {
  const value = env[key];
  if (typeof value !== 'string') {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed ? trimmed : undefined;
}

function parseNoProxyList(env: NodeJS.ProcessEnv): string[] {
  const raw = readEnvValue(env, 'NO_PROXY') ?? readEnvValue(env, 'no_proxy');
  if (!raw) {
    return [];
  }

  return raw
    .split(',')
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
}

function normalizeDefaultPort(url: URL): string {
  if (url.port) {
    return url.port;
  }
  if (url.protocol === 'https:') {
    return '443';
  }
  if (url.protocol === 'http:') {
    return '80';
  }
  return '';
}

export function shouldBypassProxy(targetUrl: URL, env: NodeJS.ProcessEnv = process.env): boolean {
  const hostname = targetUrl.hostname.toLowerCase();
  const port = normalizeDefaultPort(targetUrl);

  for (const entry of parseNoProxyList(env)) {
    if (entry === '*') {
      return true;
    }

    const hasPort = entry.includes(':');
    const [rawHost, rawPort = ''] = hasPort ? entry.split(':', 2) : [entry, ''];
    const host = rawHost.startsWith('.') ? rawHost.slice(1) : rawHost;
    if (!host) {
      continue;
    }

    const hostMatches = hostname === host || hostname.endsWith(`.${host}`);
    if (!hostMatches) {
      continue;
    }

    if (!hasPort || rawPort === port) {
      return true;
    }
  }

  return false;
}

export function resolveProxyUrlForTarget(
  targetUrl: URL,
  env: NodeJS.ProcessEnv = process.env,
): string | null {
  if (shouldBypassProxy(targetUrl, env)) {
    return null;
  }

  if (targetUrl.protocol === 'http:') {
    return (
      readEnvValue(env, 'HTTP_PROXY') ??
      readEnvValue(env, 'http_proxy') ??
      readEnvValue(env, 'ALL_PROXY') ??
      readEnvValue(env, 'all_proxy') ??
      null
    );
  }

  if (targetUrl.protocol === 'https:') {
    return (
      readEnvValue(env, 'HTTPS_PROXY') ??
      readEnvValue(env, 'https_proxy') ??
      readEnvValue(env, 'ALL_PROXY') ??
      readEnvValue(env, 'all_proxy') ??
      null
    );
  }

  return null;
}

function hasProxyEnvironment(env: NodeJS.ProcessEnv): boolean {
  return (
    resolveProxyUrlForTarget(new URL('http://example.test'), env) !== null ||
    resolveProxyUrlForTarget(new URL('https://example.test'), env) !== null
  );
}

class EnvAwareProxyAgentPool {
  private readonly defaultAgent = new Agent();
  private readonly proxyAgents = new Map<string, ProxyAgent>();
  private readonly env: NodeJS.ProcessEnv;

  constructor(env: NodeJS.ProcessEnv) {
    this.env = env;
  }

  resolveForUrl(targetUrl: URL): ProxyDispatcher {
    const proxyUrl = resolveProxyUrlForTarget(targetUrl, this.env);
    if (!proxyUrl) {
      return this.defaultAgent as ProxyDispatcher;
    }

    let proxyAgent = this.proxyAgents.get(proxyUrl);
    if (!proxyAgent) {
      proxyAgent = new ProxyAgent(proxyUrl);
      this.proxyAgents.set(proxyUrl, proxyAgent);
    }
    return proxyAgent as ProxyDispatcher;
  }

  async destroy(): Promise<void> {
    await Promise.all([
      this.defaultAgent.destroy(),
      ...Array.from(this.proxyAgents.values(), (agent) => agent.destroy()),
    ]);
  }
}

function resolveFetchTargetUrl(input: FetchInput): URL {
  if (input instanceof URL) {
    return input;
  }

  if (typeof input === 'string') {
    return new URL(input);
  }

  return new URL(input.url);
}

async function convertRequestToProxyAwareInit(
  request: Request,
  dispatcher: ProxyDispatcher,
): Promise<RequestInit & { dispatcher: ProxyDispatcher }> {
  const requestInit: RequestInit & { dispatcher: ProxyDispatcher } = {
    method: request.method,
    headers: new Headers(request.headers),
    cache: request.cache,
    credentials: request.credentials,
    dispatcher,
    integrity: request.integrity,
    keepalive: request.keepalive,
    mode: request.mode,
    redirect: request.redirect,
    referrer: request.referrer,
    referrerPolicy: request.referrerPolicy,
    signal: request.signal,
  };

  if (request.method !== 'GET' && request.method !== 'HEAD' && request.body !== null) {
    requestInit.body = Buffer.from(await request.clone().arrayBuffer());
  }

  return requestInit;
}

let installed = false;
let installedPool: EnvAwareProxyAgentPool | null = null;
let previousFetch: typeof globalThis.fetch | null = null;

export function installGlobalFetchProxyDispatcherFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): void {
  if (installed || !hasProxyEnvironment(env)) {
    return;
  }

  const pool = new EnvAwareProxyAgentPool(env);
  const fetchImpl = globalThis.fetch.bind(globalThis);
  previousFetch = fetchImpl;
  installedPool = pool;
  globalThis.fetch = (async (input: FetchInput, init?: RequestInit) => {
    const dispatcher = pool.resolveForUrl(resolveFetchTargetUrl(input));
    if (typeof input !== 'string' && !(input instanceof URL)) {
      const request = init ? new Request(input, init) : input;
      return fetchImpl(
        request.url,
        await convertRequestToProxyAwareInit(request, dispatcher),
      );
    }
    return fetchImpl(input, {
      ...init,
      dispatcher,
    } as RequestInit & { dispatcher: ProxyDispatcher });
  }) as typeof globalThis.fetch;
  installed = true;
}

export async function closeGlobalFetchProxyDispatcherFromEnv(): Promise<void> {
  const pool = installedPool;
  const fetchImpl = previousFetch;
  installedPool = null;
  previousFetch = null;
  installed = false;

  if (fetchImpl) {
    globalThis.fetch = fetchImpl;
  }
  if (pool) {
    void pool.destroy().catch(() => {});
  }
}
