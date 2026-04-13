import {
  deleteAgentAuthTokenFromFile,
  hasAgentAuthTokenInFile,
  readAgentAuthTokenFromFile,
  resolveAgentAuthTokenFileDirectory,
  resolveAgentAuthTokenFilePath,
  storeAgentAuthTokenInFile,
} from './agent-auth-file.js';
import {
  AGENT_AUTH_TOKEN_KEYCHAIN_SERVICE,
  assertValidAgentKeyId,
  deleteAgentAuthTokenFromKeychain,
  hasAgentAuthTokenInKeychain,
  readAgentAuthTokenFromKeychain,
  storeAgentAuthTokenInKeychain,
} from './keychain.js';
import { isLinuxPlatform, isMacOsPlatform } from './platform-support.js';
import {
  AGENT_AUTH_TOKEN_SECRET_SERVICE,
  deleteAgentAuthTokenFromSecretService,
  hasAgentAuthTokenInSecretService,
  isSecretToolAvailable,
  isSecretToolUnavailableError,
  readAgentAuthTokenFromSecretService,
  storeAgentAuthTokenInSecretService,
} from './secret-service.js';

export type AgentAuthStorageBackend =
  | 'macos-keychain'
  | 'linux-secret-service'
  | 'linux-file'
  | 'unsupported';

export interface AgentAuthStorageMetadata {
  backend: AgentAuthStorageBackend;
  supported: boolean;
  label: string;
  service: string | null;
  locationType: 'service' | 'file' | null;
  directlyAccessible: boolean;
  note: string | null;
}

function normalizeOptionalAgentKeyId(agentKeyId: string | undefined): string | undefined {
  if (typeof agentKeyId !== 'string') {
    return undefined;
  }

  const normalized = agentKeyId.trim();
  if (normalized.length === 0) {
    return undefined;
  }

  try {
    return assertValidAgentKeyId(normalized);
  } catch {
    return undefined;
  }
}

function linuxFileStorageMetadata(agentKeyId?: string): AgentAuthStorageMetadata {
  return {
    backend: 'linux-file',
    supported: true,
    label: 'Linux local credential file',
    service: agentKeyId
      ? resolveAgentAuthTokenFilePath(agentKeyId)
      : resolveAgentAuthTokenFileDirectory(),
    locationType: 'file',
    directlyAccessible: true,
    note: 'secret-tool is unavailable, so the agent auth token is stored in a local file and is directly accessible to this user',
  };
}

function linuxSecretServiceMetadata(): AgentAuthStorageMetadata {
  return {
    backend: 'linux-secret-service',
    supported: true,
    label: 'Linux Secret Service',
    service: AGENT_AUTH_TOKEN_SECRET_SERVICE,
    locationType: 'service',
    directlyAccessible: false,
    note: null,
  };
}

function detectStoredLinuxBackend(agentKeyId: string): AgentAuthStorageBackend | null {
  if (isSecretToolAvailable()) {
    try {
      if (hasAgentAuthTokenInSecretService(agentKeyId)) {
        return 'linux-secret-service';
      }
    } catch (error) {
      if (!isSecretToolUnavailableError(error)) {
        try {
          if (hasAgentAuthTokenInFile(agentKeyId)) {
            return 'linux-file';
          }
        } catch {}
        return null;
      }
    }
  }

  try {
    if (hasAgentAuthTokenInFile(agentKeyId)) {
      return 'linux-file';
    }
  } catch {}

  return null;
}

export function resolveAgentAuthStorageBackend(
  platform: NodeJS.Platform = process.platform,
  agentKeyId?: string,
): AgentAuthStorageBackend {
  if (isMacOsPlatform(platform)) {
    return 'macos-keychain';
  }
  if (isLinuxPlatform(platform)) {
    const normalizedAgentKeyId = normalizeOptionalAgentKeyId(agentKeyId);
    if (normalizedAgentKeyId) {
      const detected = detectStoredLinuxBackend(normalizedAgentKeyId);
      if (detected) {
        return detected;
      }
    }
    return 'linux-secret-service';
  }
  return 'unsupported';
}

export function resolveAgentAuthStorageMetadata(
  platform: NodeJS.Platform = process.platform,
  agentKeyId?: string,
): AgentAuthStorageMetadata {
  const backend = resolveAgentAuthStorageBackend(platform, agentKeyId);
  if (backend === 'macos-keychain') {
    return {
      backend,
      supported: true,
      label: 'macOS Keychain',
      service: AGENT_AUTH_TOKEN_KEYCHAIN_SERVICE,
      locationType: 'service',
      directlyAccessible: false,
      note: null,
    };
  }
  if (backend === 'linux-secret-service') {
    return linuxSecretServiceMetadata();
  }
  if (backend === 'linux-file') {
    return linuxFileStorageMetadata(normalizeOptionalAgentKeyId(agentKeyId));
  }
  return {
    backend,
    supported: false,
    label: 'local credential storage',
    service: null,
    locationType: null,
    directlyAccessible: false,
    note: null,
  };
}

export function resolveAgentAuthStorageService(
  platform: NodeJS.Platform = process.platform,
  agentKeyId?: string,
): string | null {
  return resolveAgentAuthStorageMetadata(platform, agentKeyId).service;
}

export function describeAgentAuthStorage(
  platform: NodeJS.Platform = process.platform,
  agentKeyId?: string,
): string {
  return resolveAgentAuthStorageMetadata(platform, agentKeyId).label;
}

export function hasStoredAgentAuthToken(
  agentKeyId: string,
  platform: NodeJS.Platform = process.platform,
): boolean {
  if (isMacOsPlatform(platform)) {
    return hasAgentAuthTokenInKeychain(agentKeyId);
  }
  if (isLinuxPlatform(platform)) {
    return readStoredAgentAuthToken(agentKeyId, platform) !== null;
  }
  return false;
}

export function readStoredAgentAuthToken(
  agentKeyId: string,
  platform: NodeJS.Platform = process.platform,
): string | null {
  if (isMacOsPlatform(platform)) {
    return readAgentAuthTokenFromKeychain(agentKeyId);
  }
  if (isLinuxPlatform(platform)) {
    try {
      const secretServiceToken = readAgentAuthTokenFromSecretService(agentKeyId);
      if (secretServiceToken !== null) {
        return secretServiceToken;
      }
    } catch (error) {
      if (!isSecretToolUnavailableError(error)) {
        try {
          const fileToken = readAgentAuthTokenFromFile(agentKeyId);
          if (fileToken !== null) {
            return fileToken;
          }
        } catch {}
        throw error;
      }
    }
    return readAgentAuthTokenFromFile(agentKeyId);
  }
  return null;
}

export function storeStoredAgentAuthToken(
  agentKeyId: string,
  token: string,
  platform: NodeJS.Platform = process.platform,
): void {
  if (isMacOsPlatform(platform)) {
    storeAgentAuthTokenInKeychain(agentKeyId, token);
    return;
  }
  if (isLinuxPlatform(platform)) {
    try {
      if (isSecretToolAvailable()) {
        storeAgentAuthTokenInSecretService(agentKeyId, token);
        deleteAgentAuthTokenFromFile(agentKeyId);
        return;
      }
    } catch (error) {
      if (!isSecretToolUnavailableError(error)) {
        throw error;
      }
    }
    storeAgentAuthTokenInFile(agentKeyId, token);
    return;
  }
  throw new Error(
    `local agent auth token storage is unsupported on ${platform}; supported platforms are macOS and Linux`,
  );
}

export function deleteStoredAgentAuthToken(
  agentKeyId: string,
  platform: NodeJS.Platform = process.platform,
): boolean {
  if (isMacOsPlatform(platform)) {
    return deleteAgentAuthTokenFromKeychain(agentKeyId);
  }
  if (isLinuxPlatform(platform)) {
    let removedSecretService = false;
    if (isSecretToolAvailable()) {
      try {
        removedSecretService = deleteAgentAuthTokenFromSecretService(agentKeyId);
      } catch (error) {
        if (!isSecretToolUnavailableError(error)) {
          const removedFile = deleteAgentAuthTokenFromFile(agentKeyId);
          if (removedFile) {
            return true;
          }
          throw error;
        }
      }
    }
    const removedFile = deleteAgentAuthTokenFromFile(agentKeyId);
    return removedSecretService || removedFile;
  }
  return false;
}
