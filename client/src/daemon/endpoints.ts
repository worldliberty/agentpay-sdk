/**
 * Where the two daemons listen (docs/daemon-api.md, "Transport" and "Payments service").
 *
 * - Production: fixed root-managed paths per OS. The payments socket belongs to the service
 *   account whose uid the root-owned install record (`install.json`) names.
 * - Development: `AGENTPAY_DAEMON_SOCKET` / `AGENTPAY_PAYMENTS_SOCKET` or the
 *   `--daemon-socket` / `--payments-socket` options name sockets explicitly.
 *
 * `AGENTPAY_HOME` only moves the per-user files (see `auth/home.ts`), never the sockets: the
 * previous installer exported it into shells and editors, and it must not silently point an
 * installed client at sockets that do not exist.
 */
import { readFileSync } from 'node:fs';
import { copy } from '../copy/index.js';
import { AuthError, EXIT, type ServiceName } from '../errors.js';
import { nodeTrustFs, type SocketTrust, type TrustFs } from './socket-trust.js';

export interface Endpoint {
  service: ServiceName;
  path: string;
  /** Resolved lazily: production payments trust needs the install record. */
  trust(): SocketTrust;
}

export interface Endpoints {
  signer: Endpoint;
  payments: Endpoint;
}

export interface EndpointOverrides {
  daemonSocket?: string | undefined;
  paymentsSocket?: string | undefined;
}

interface PlatformPaths {
  signer: string;
  payments: string;
  installRecord: string;
}

const PLATFORM_PATHS: Readonly<Record<string, PlatformPaths>> = {
  darwin: {
    signer: '/Library/AgentPay/run/daemon.sock',
    payments: '/Library/AgentPay/run/paymentd/paymentd.sock',
    installRecord: '/Library/AgentPay/install.json',
  },
  linux: {
    signer: '/run/agentpay/daemon.sock',
    payments: '/run/agentpay-paymentd/paymentd.sock',
    installRecord: '/opt/agentpay/install.json',
  },
};

export interface EndpointContext {
  env: NodeJS.ProcessEnv;
  platform: NodeJS.Platform;
  uid: number;
  overrides?: EndpointOverrides;
  fs?: TrustFs;
  readFile?: (path: string) => string;
}

/** Reads the payments service uid from the root-owned install record. */
export function readServiceUid(
  path: string,
  fs: TrustFs = nodeTrustFs,
  readFile: (path: string) => string = (p) => readFileSync(p, 'utf8'),
): number {
  const notInstalled = () =>
    new AuthError('not_installed', copy.errors.notInstalled, EXIT.notSetUp);
  let info: ReturnType<TrustFs['lstat']>;
  try {
    info = fs.lstat(path);
  } catch {
    throw notInstalled();
  }
  if (info.isSymbolicLink() || info.uid !== 0 || (info.mode & 0o022) !== 0) {
    throw notInstalled();
  }
  try {
    const record = JSON.parse(readFile(path)) as { service_uid?: unknown };
    if (typeof record.service_uid === 'number' && Number.isInteger(record.service_uid)) {
      return record.service_uid;
    }
  } catch {
    // fall through
  }
  throw notInstalled();
}

export function resolveEndpoints(context: EndpointContext): Endpoints {
  const { env, platform, uid } = context;
  const userTrust = (): SocketTrust => ({ kind: 'user', uid });
  const explicitSigner = context.overrides?.daemonSocket ?? env.AGENTPAY_DAEMON_SOCKET;
  const explicitPayments = context.overrides?.paymentsSocket ?? env.AGENTPAY_PAYMENTS_SOCKET;
  const production = PLATFORM_PATHS[platform];

  const signer: Endpoint = explicitSigner
    ? { service: 'signer', path: explicitSigner, trust: userTrust }
    : { service: 'signer', path: production?.signer ?? '', trust: () => ({ kind: 'root' }) };

  const payments: Endpoint = explicitPayments
    ? { service: 'payments', path: explicitPayments, trust: userTrust }
    : {
        service: 'payments',
        path: production?.payments ?? '',
        trust: () => ({
          kind: 'service',
          uid: readServiceUid(production?.installRecord ?? '', context.fs, context.readFile),
        }),
      };

  return { signer, payments };
}
