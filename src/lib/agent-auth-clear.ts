import {
  deleteConfigKey,
  redactConfig,
  readConfig,
  type WlfiConfig
} from '../../packages/config/src/index.js';
import {
  assertValidAgentKeyId,
} from './keychain.js';
import {
  deleteStoredAgentAuthToken,
  resolveAgentAuthStorageService,
} from './agent-auth-storage.js';

export interface ClearAgentAuthTokenResult {
  agentKeyId: string;
  keychain: {
    removed: boolean;
    service: string | null;
  };
  config: Record<string, unknown>;
}

interface ClearAgentAuthTokenDeps {
  platform?: NodeJS.Platform;
  deleteAgentAuthToken?: (agentKeyId: string) => boolean;
  readConfig?: () => WlfiConfig;
  deleteConfigKey?: (key: keyof WlfiConfig) => WlfiConfig;
}

export function clearAgentAuthToken(
  agentKeyId: string,
  deps: ClearAgentAuthTokenDeps = {}
): ClearAgentAuthTokenResult {
  const platform = deps.platform ?? process.platform;
  const normalizedAgentKeyId = assertValidAgentKeyId(agentKeyId);
  const removeAgentAuthToken =
    deps.deleteAgentAuthToken ??
    ((resolvedAgentKeyId: string) => deleteStoredAgentAuthToken(resolvedAgentKeyId, platform));
  const loadConfig = deps.readConfig ?? readConfig;
  const clearConfigKey = deps.deleteConfigKey ?? deleteConfigKey;

  const existing = loadConfig();
  const removed = removeAgentAuthToken(normalizedAgentKeyId);

  let updated = existing;
  if (existing.agentKeyId === normalizedAgentKeyId) {
    updated = clearConfigKey('agentKeyId');
  }
  if (updated.agentAuthToken !== undefined) {
    updated = clearConfigKey('agentAuthToken');
  }

  return {
    agentKeyId: normalizedAgentKeyId,
    keychain: {
      removed,
      service: resolveAgentAuthStorageService(platform, normalizedAgentKeyId)
    },
    config: redactConfig(updated)
  };
}
