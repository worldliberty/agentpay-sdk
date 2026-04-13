import {
  deleteConfigKey,
  readConfig,
  redactConfig,
  writeConfig,
  type WlfiConfig
} from '../../packages/config/src/index.js';
import {
  assertValidAgentKeyId,
} from './keychain.js';
import {
  describeAgentAuthStorage,
  readStoredAgentAuthToken,
  resolveAgentAuthStorageService,
  storeStoredAgentAuthToken,
} from './agent-auth-storage.js';

export interface MigrateLegacyAgentAuthInput {
  agentKeyId?: string;
  overwriteKeychain?: boolean;
}

export interface MigrateLegacyAgentAuthResult {
  agentKeyId: string;
  source: 'config';
  keychain: {
    service: string;
    stored: boolean;
    overwritten: boolean;
    alreadyPresent: boolean;
    matchedExisting: boolean;
  };
  config: Record<string, unknown>;
}

interface MigrateLegacyAgentAuthDeps {
  platform?: NodeJS.Platform;
  readConfig?: () => WlfiConfig;
  writeConfig?: (nextConfig: WlfiConfig) => WlfiConfig;
  deleteConfigKey?: (key: keyof WlfiConfig) => WlfiConfig;
  readAgentAuthToken?: (agentKeyId: string) => string | null;
  storeAgentAuthToken?: (agentKeyId: string, token: string) => void;
}

function presentSecret(value: string | undefined): string | null {
  if (typeof value !== 'string') {
    return null;
  }

  return value.trim().length > 0 ? value : null;
}

function resolveConfiguredAgentKeyId(
  config: WlfiConfig,
  explicitAgentKeyId: string | undefined
): string | undefined {
  const configuredAgentKeyId = config.agentKeyId?.trim();
  if (!configuredAgentKeyId) {
    return undefined;
  }

  try {
    return assertValidAgentKeyId(configuredAgentKeyId);
  } catch (error) {
    if (explicitAgentKeyId) {
      return undefined;
    }
    const renderedError =
      error instanceof Error
        ? error.message
        : /* c8 ignore next -- assertValidAgentKeyId throws Error objects */ String(error);
    throw new Error(
      renderedError +
        '; pass --agent-key-id to migrate the legacy config secret explicitly'
    );
  }
}

export function migrateLegacyAgentAuthToken(
  input: MigrateLegacyAgentAuthInput = {},
  deps: MigrateLegacyAgentAuthDeps = {}
): MigrateLegacyAgentAuthResult {
  const platform = deps.platform ?? process.platform;
  if (platform !== 'darwin' && platform !== 'linux') {
    throw new Error('legacy agent auth migration requires local credential storage on macOS or Linux');
  }

  const loadConfig = deps.readConfig ?? readConfig;
  const persistConfig = deps.writeConfig ?? writeConfig;
  const clearConfigKey = deps.deleteConfigKey ?? deleteConfigKey;
  const readAgentAuthToken =
    deps.readAgentAuthToken ?? ((agentKeyId: string) => readStoredAgentAuthToken(agentKeyId, platform));
  const storeAgentAuthToken =
    deps.storeAgentAuthToken ??
    ((agentKeyId: string, token: string) => storeStoredAgentAuthToken(agentKeyId, token, platform));

  const explicitAgentKeyId = input.agentKeyId ? assertValidAgentKeyId(input.agentKeyId) : undefined;
  const config = loadConfig();
  const configuredAgentKeyId = resolveConfiguredAgentKeyId(config, explicitAgentKeyId);

  if (explicitAgentKeyId && configuredAgentKeyId && explicitAgentKeyId !== configuredAgentKeyId) {
    throw new Error(
      'explicit --agent-key-id does not match the configured agentKeyId; refuse to bind a legacy config secret to a different agent'
    );
  }

  const agentKeyId = explicitAgentKeyId ?? configuredAgentKeyId;
  if (!agentKeyId) {
    throw new Error('agentKeyId is required; pass --agent-key-id or configure agentKeyId first');
  }

  const legacyToken = presentSecret(config.agentAuthToken);
  if (!legacyToken) {
    throw new Error('config.json does not contain a legacy agentAuthToken to migrate');
  }

  const existingKeychainToken = readAgentAuthToken(agentKeyId);
  const alreadyPresent = existingKeychainToken !== null;
  let matchedExisting = false;
  let stored = false;
  let overwritten = false;

  if (existingKeychainToken === null) {
    storeAgentAuthToken(agentKeyId, legacyToken);
    stored = true;
  } else if (existingKeychainToken === legacyToken) {
    matchedExisting = true;
  } else {
    if (!input.overwriteKeychain) {
      throw new Error(
        `${describeAgentAuthStorage(platform)} already contains a different agent auth token for this agentKeyId; rerun with --overwrite-keychain after verifying the correct credential`
      );
    }

    storeAgentAuthToken(agentKeyId, legacyToken);
    stored = true;
    overwritten = true;
  }

  let updatedConfig = config;
  if (configuredAgentKeyId !== agentKeyId) {
    updatedConfig = persistConfig({ agentKeyId });
  }
  if (updatedConfig.agentAuthToken !== undefined) {
    updatedConfig = clearConfigKey('agentAuthToken');
  }

  return {
    agentKeyId,
    source: 'config',
    keychain: {
      service:
        resolveAgentAuthStorageService(platform, agentKeyId) ?? 'agentpay-agent-auth-token',
      stored,
      overwritten,
      alreadyPresent,
      matchedExisting
    },
    config: redactConfig(updatedConfig)
  };
}
