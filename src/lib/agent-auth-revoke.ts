import {
  deleteConfigKey,
  redactConfig,
  readConfig,
  type WlfiConfig,
  writeConfig
} from '../../packages/config/src/index.js';
import {
  assertValidAgentKeyId,
} from './keychain.js';
import {
  deleteStoredAgentAuthToken,
  resolveAgentAuthStorageService,
} from './agent-auth-storage.js';

export interface RevokeAgentKeyAdminArgsInput {
  agentKeyId: string;
  vaultPassword?: string;
  vaultPasswordStdin?: boolean;
  nonInteractive?: boolean;
  daemonSocket?: string;
}

export interface RevokeAgentKeyAdminOutput {
  agent_key_id: string;
  revoked: boolean;
}

export interface CompleteAgentKeyRevocationResult {
  agentKeyId: string;
  revoked: true;
  keychain: {
    removed: boolean;
    service: string | null;
  };
  config: Record<string, unknown>;
}

interface CompleteAgentKeyRevocationDeps {
  platform?: NodeJS.Platform;
  deleteAgentAuthToken?: (agentKeyId: string) => boolean;
  readConfig?: () => WlfiConfig;
  writeConfig?: (nextConfig: WlfiConfig) => WlfiConfig;
  deleteConfigKey?: (key: keyof WlfiConfig) => WlfiConfig;
}

export function buildRevokeAgentKeyAdminArgs(input: RevokeAgentKeyAdminArgsInput): string[] {
  const args = ['--json', '--quiet'];

  if (input.vaultPassword) {
    throw new Error(
      'insecure vaultPassword is disabled; use vaultPasswordStdin or an interactive prompt'
    );
  }
  if (input.vaultPasswordStdin) {
    args.push('--vault-password-stdin');
  }
  if (input.nonInteractive) {
    args.push('--non-interactive');
  }
  if (input.daemonSocket) {
    args.push('--daemon-socket', input.daemonSocket);
  }

  args.push('revoke-agent-key', '--agent-key-id', assertValidAgentKeyId(input.agentKeyId));

  return args;
}

export function completeAgentKeyRevocation(
  output: RevokeAgentKeyAdminOutput,
  deps: CompleteAgentKeyRevocationDeps = {}
): CompleteAgentKeyRevocationResult {
  const platform = deps.platform ?? process.platform;
  const agentKeyId = assertValidAgentKeyId(output.agent_key_id);
  if (!output.revoked) {
    throw new Error('revoke-agent-key did not confirm revocation');
  }

  const removeAgentAuthToken =
    deps.deleteAgentAuthToken ??
    ((resolvedAgentKeyId: string) => deleteStoredAgentAuthToken(resolvedAgentKeyId, platform));
  const loadConfig = deps.readConfig ?? readConfig;
  const persistConfig = deps.writeConfig ?? writeConfig;
  const clearLegacyConfigKey = deps.deleteConfigKey ?? deleteConfigKey;

  const existing = loadConfig();
  const removed = removeAgentAuthToken(agentKeyId);

  let updated = existing;
  if (existing.agentKeyId === agentKeyId) {
    updated = persistConfig({ agentKeyId: undefined });
    if (updated.agentAuthToken !== undefined) {
      updated = clearLegacyConfigKey('agentAuthToken');
    }
  }

  return {
    agentKeyId,
    revoked: true,
    keychain: {
      removed,
      service: resolveAgentAuthStorageService(platform, agentKeyId)
    },
    config: redactConfig(updated)
  };
}
