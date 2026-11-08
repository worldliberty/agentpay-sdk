/**
 * Where agent auth tokens live, ported from the TypeScript CLI (keychain.ts, secret-service.ts,
 * agent-auth-file.ts) and kept small:
 *
 * - macOS: the login keychain through `security`. Writes go through `security -i` with the
 *   command on stdin and the token hex-encoded (`-X`), so it never appears in a process list.
 * - Linux: Secret Service through `secret-tool` (token on stdin). Without `secret-tool`, or when
 *   no Secret Service answers (headless machines), a 0600 file under `~/.agentpay/agent-auth/`.
 *
 * Items use service `agentpay-agent-auth-token` and the agent key id as the account.
 */
import { join } from 'node:path';
import { ensurePrivateDir, readPrivateFile, removeFile, writePrivateFile } from './files.js';
import type { CommandRunner } from './process.js';

export const AGENT_TOKEN_SERVICE = 'agentpay-agent-auth-token';
const SECURITY_ITEM_NOT_FOUND = 44;
const MAX_SECRET_BYTES = 16 * 1024;

export interface SecretStore {
  /** Human-readable name, for messages ("macOS Keychain"). */
  readonly label: string;
  read(account: string): Promise<string | null>;
  write(account: string, secret: string): Promise<void>;
  remove(account: string): Promise<boolean>;
}

export class SecretStoreError extends Error {}

function hasControlCharacters(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code <= 0x1f || code === 0x7f) {
      return true;
    }
  }
  return false;
}

/** Validates a token before it is stored: non-empty, one line, at most 16 KiB. */
export function assertStorableSecret(secret: string): string {
  const trimmed = secret.trim();
  if (!trimmed || hasControlCharacters(trimmed) || Buffer.byteLength(trimmed) > MAX_SECRET_BYTES) {
    throw new SecretStoreError('the token must be one non-empty line of at most 16 KiB');
  }
  return trimmed;
}

/** Quotes one argument for `security -i`, which splits lines with shell-like rules. */
export function quoteSecurityArg(value: string): string {
  if (hasControlCharacters(value)) {
    throw new SecretStoreError('keychain arguments must not contain control characters');
  }
  return `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
}

function failure(tool: string, stderr: string): SecretStoreError {
  return new SecretStoreError(`${tool} failed${stderr.trim() ? `: ${stderr.trim()}` : ''}`);
}

export function macosKeychainStore(run: CommandRunner): SecretStore {
  return {
    label: 'macOS Keychain',
    async read(account) {
      const result = await run('security', [
        'find-generic-password',
        '-w',
        '-s',
        AGENT_TOKEN_SERVICE,
        '-a',
        account,
      ]);
      if (result.status === SECURITY_ITEM_NOT_FOUND) {
        return null;
      }
      if (result.status !== 0) {
        throw failure('security', result.stderr);
      }
      return result.stdout.replace(/\r?\n$/u, '') || null;
    },
    async write(account, secret) {
      const value = assertStorableSecret(secret);
      const line = [
        'add-generic-password',
        '-U',
        '-s',
        quoteSecurityArg(AGENT_TOKEN_SERVICE),
        '-a',
        quoteSecurityArg(account),
        '-X',
        Buffer.from(value, 'utf8').toString('hex'),
      ].join(' ');
      const result = await run('security', ['-i'], { input: `${line}\n` });
      if (result.status !== 0) {
        throw failure('security', result.stderr);
      }
    },
    async remove(account) {
      const result = await run('security', [
        'delete-generic-password',
        '-s',
        AGENT_TOKEN_SERVICE,
        '-a',
        account,
      ]);
      if (result.status === SECURITY_ITEM_NOT_FOUND) {
        return false;
      }
      if (result.status !== 0) {
        throw failure('security', result.stderr);
      }
      return true;
    },
  };
}

export function secretToolStore(run: CommandRunner): SecretStore {
  const attributes = (account: string) => ['service', AGENT_TOKEN_SERVICE, 'account', account];
  return {
    label: 'Linux Secret Service',
    async read(account) {
      const result = await run('secret-tool', ['lookup', ...attributes(account)]);
      if (result.status === 0) {
        return result.stdout.replace(/\r?\n$/u, '') || null;
      }
      // `secret-tool lookup` exits 1 without output when nothing is stored.
      if (result.status === 1 && !result.stdout.trim() && !result.stderr.trim()) {
        return null;
      }
      throw failure('secret-tool', result.stderr || result.spawnError?.message || '');
    },
    async write(account, secret) {
      const value = assertStorableSecret(secret);
      const result = await run(
        'secret-tool',
        ['store', '--label=AgentPay agent auth token', ...attributes(account)],
        { input: `${value}\n` },
      );
      if (result.status !== 0) {
        throw failure('secret-tool', result.stderr || result.spawnError?.message || '');
      }
    },
    async remove(account) {
      const existing = await this.read(account);
      if (existing === null) {
        return false;
      }
      const result = await run('secret-tool', ['clear', ...attributes(account)]);
      if (result.status !== 0) {
        throw failure('secret-tool', result.stderr);
      }
      return true;
    },
  };
}

/** 0600 token files in a 0700 directory: the fallback without a keychain. */
export function fileSecretStore(directory: string): SecretStore {
  const pathFor = (account: string) => join(directory, `${account}.token`);
  return {
    label: `local file (${directory})`,
    async read(account) {
      const text = readPrivateFile(pathFor(account));
      return text === null ? null : text.trim() || null;
    },
    async write(account, secret) {
      ensurePrivateDir(directory);
      writePrivateFile(pathFor(account), `${assertStorableSecret(secret)}\n`);
    },
    async remove(account) {
      return removeFile(pathFor(account));
    },
  };
}

/**
 * Uses `primary`, and `fallback` when `primary` fails (not when it reports "not found").
 * Reads check both, so a token stored by either is found.
 */
export function withFallback(primary: SecretStore, fallback: SecretStore): SecretStore {
  return {
    get label() {
      return primary.label;
    },
    async read(account) {
      try {
        const value = await primary.read(account);
        if (value !== null) {
          return value;
        }
      } catch {
        // fall back
      }
      return fallback.read(account);
    },
    async write(account, secret) {
      try {
        await primary.write(account, secret);
      } catch {
        await fallback.write(account, secret);
      }
    },
    async remove(account) {
      const results = await Promise.allSettled([primary.remove(account), fallback.remove(account)]);
      return results.some((result) => result.status === 'fulfilled' && result.value);
    },
  };
}

/** The store for this platform. */
export function platformSecretStore(
  platform: NodeJS.Platform,
  run: CommandRunner,
  agentAuthDir: string,
): SecretStore {
  if (platform === 'darwin') {
    return macosKeychainStore(run);
  }
  if (platform === 'linux') {
    return withFallback(secretToolStore(run), fileSecretStore(agentAuthDir));
  }
  return fileSecretStore(agentAuthDir);
}

/** In-memory store for tests. */
export function memorySecretStore(initial: Record<string, string> = {}): SecretStore {
  const secrets = new Map(Object.entries(initial));
  return {
    label: 'memory',
    read: async (account) => secrets.get(account) ?? null,
    write: async (account, secret) => {
      secrets.set(account, assertStorableSecret(secret));
    },
    remove: async (account) => secrets.delete(account),
  };
}
