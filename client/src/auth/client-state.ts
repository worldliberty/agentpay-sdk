/**
 * Non-secret client state in `~/.agentpay/client.json` (mode 0600): which agent key this user's
 * commands act as, which Touch ID credential the signer daemon enrolled for this user, and when
 * each wallet was last backed up from this client.
 * Tokens never go here; they live in the OS secret store (see `secret-store.ts`).
 */

import { readPrivateFile, writePrivateFile } from './files.js';
import { homeFiles } from './home.js';

export interface ClientState {
  agentKeyId: string | null;
  adminCredentialId: string | null;
  /** Wallet EVM address (lower case) → ISO time of its last backup written by this client. */
  backups: Record<string, string>;
}

/** Only well-formed address → ISO-time entries survive a hand-edited file. */
function backupsOrEmpty(value: unknown): Record<string, string> {
  if (typeof value !== 'object' || value === null) {
    return {};
  }
  return Object.fromEntries(
    Object.entries(value).filter(
      ([address, at]) =>
        /^0x[0-9a-f]{40}$/u.test(address) &&
        typeof at === 'string' &&
        !Number.isNaN(Date.parse(at)),
    ),
  ) as Record<string, string>;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

export function isUuid(value: string): boolean {
  return UUID.test(value.trim());
}

function uuidOrNull(value: unknown): string | null {
  return typeof value === 'string' && isUuid(value) ? value.trim().toLowerCase() : null;
}

export interface ClientStateStore {
  read(): ClientState;
  update(change: Partial<ClientState>): ClientState;
}

export function fileClientStateStore(home: string): ClientStateStore {
  const path = homeFiles.clientState(home);
  const read = (): ClientState => {
    const parsed = parseJson(readPrivateFile(path));
    const legacy = parseJson(readPrivateFile(homeFiles.legacyConfig(home)));
    return {
      agentKeyId: uuidOrNull(parsed.agentKeyId) ?? uuidOrNull(legacy.agentKeyId),
      adminCredentialId: uuidOrNull(parsed.adminCredentialId),
      backups: backupsOrEmpty(parsed.backups),
    };
  };
  return {
    read,
    update(change) {
      const next = { ...read(), ...change };
      writePrivateFile(path, `${JSON.stringify(next, null, 2)}\n`);
      return next;
    },
  };
}

function parseJson(text: string | null): Record<string, unknown> {
  if (!text) {
    return {};
  }
  try {
    const value: unknown = JSON.parse(text);
    return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/** In-memory store for tests and the root relay. */
export function memoryClientStateStore(initial: Partial<ClientState> = {}): ClientStateStore {
  let state: ClientState = { agentKeyId: null, adminCredentialId: null, backups: {}, ...initial };
  return {
    read: () => state,
    update(change) {
      state = { ...state, ...change };
      return state;
    },
  };
}
