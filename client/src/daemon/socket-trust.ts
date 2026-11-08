/**
 * Socket trust checks (docs/daemon-api.md, "Security notes for integrators"): before connecting,
 * the socket must be a real Unix socket owned by the expected uid, in a directory chain other
 * users cannot rewrite. A planted socket could otherwise collect agent tokens or lease secrets.
 *
 * Node cannot read a connected peer's euid (`getpeereid` / `SO_PEERCRED`), so the client relies
 * on these path checks: a socket in a root-owned, non-writable directory can only have been
 * created by root (or by the service account, for the payments service's own directory).
 */
import { lstatSync, realpathSync, statSync } from 'node:fs';
import { dirname } from 'node:path';
import { copy } from '../copy/index.js';
import { type ServiceName, serviceLabel, TransportError } from '../errors.js';

/** Whom the socket must belong to. */
export type SocketTrust =
  /** Production signer daemon: root. */
  | { kind: 'root' }
  /** Production payments service: its service account. */
  | { kind: 'service'; uid: number }
  /** Development sockets (explicit paths): this user or root. */
  | { kind: 'user'; uid: number };

export interface StatLike {
  uid: number;
  mode: number;
  isSocket(): boolean;
  isSymbolicLink(): boolean;
  isDirectory(): boolean;
}

export interface TrustFs {
  lstat(path: string): StatLike;
  stat(path: string): StatLike;
  realpath(path: string): string;
}

export const nodeTrustFs: TrustFs = {
  lstat: (path) => lstatSync(path),
  stat: (path) => statSync(path),
  realpath: (path) => realpathSync(path),
};

const GROUP_OR_OTHER_WRITE = 0o022;
const STICKY = 0o1000;

function allowedOwners(trust: SocketTrust): number[] {
  switch (trust.kind) {
    case 'root':
      return [0];
    case 'service':
    case 'user':
      return [0, trust.uid];
  }
}

function socketOwnerOk(trust: SocketTrust, uid: number): boolean {
  switch (trust.kind) {
    case 'root':
      return uid === 0;
    case 'service':
      return uid === trust.uid;
    case 'user':
      return uid === trust.uid || uid === 0;
  }
}

/** Returns why `path` cannot be trusted, `'missing'` when it does not exist, or `null` if OK. */
export function checkSocketTrust(
  path: string,
  trust: SocketTrust,
  fs: TrustFs = nodeTrustFs,
): string | null {
  let info: StatLike;
  try {
    info = fs.lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return 'missing';
    }
    return `cannot inspect ${path}`;
  }
  if (info.isSymbolicLink()) {
    return `${path} is a symlink`;
  }
  if (!info.isSocket()) {
    return `${path} is not a socket`;
  }
  if (!socketOwnerOk(trust, info.uid)) {
    return `${path} belongs to an unexpected user (uid ${info.uid})`;
  }
  const parent = dirname(path);
  if (fs.lstat(parent).isSymbolicLink()) {
    return `${parent} is a symlink`;
  }
  const owners = allowedOwners(trust);
  // Development sockets only need a private parent; production sockets need the whole chain.
  let directory = fs.realpath(parent);
  for (let index = 0; ; index += 1) {
    const dir = fs.stat(directory);
    if (!owners.includes(dir.uid)) {
      return `${directory} belongs to an unexpected user (uid ${dir.uid})`;
    }
    const sticky = index > 0 && (dir.mode & STICKY) !== 0;
    if ((dir.mode & GROUP_OR_OTHER_WRITE) !== 0 && !sticky) {
      return `${directory} is writable by other users`;
    }
    const next = dirname(directory);
    if (trust.kind === 'user' || next === directory) {
      return null;
    }
    directory = next;
  }
}

/** Throws a `TransportError` unless the socket at `path` passes `checkSocketTrust`. */
export function assertTrustedSocket(
  path: string,
  trust: SocketTrust,
  service: ServiceName,
  fs: TrustFs = nodeTrustFs,
): void {
  const problem = checkSocketTrust(path, trust, fs);
  if (problem === 'missing') {
    throw new TransportError(
      'socket_missing',
      service,
      copy.errors.socketMissing(serviceLabel(service), path),
    );
  }
  if (problem) {
    throw new TransportError(
      'socket_untrusted',
      service,
      copy.errors.socketUntrusted(serviceLabel(service), problem),
    );
  }
}
