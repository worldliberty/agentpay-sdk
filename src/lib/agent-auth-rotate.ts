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
  resolveAgentAuthStorageService,
  storeStoredAgentAuthToken,
} from './agent-auth-storage.js';

export interface RotateAgentAuthTokenAdminArgsInput {
  agentKeyId: string;
  vaultPassword?: string;
  vaultPasswordStdin?: boolean;
  nonInteractive?: boolean;
  daemonSocket?: string;
}

export interface RotateAgentAuthTokenAdminOutput {
  agent_key_id: string;
  agent_auth_token: string;
  agent_auth_token_redacted: boolean;
}

export interface CompleteAgentAuthRotationResult {
  agentKeyId: string;
  keychain: {
    stored: true;
    service: string;
  };
  config: Record<string, unknown>;
}

interface CompleteAgentAuthRotationDeps {
  platform?: NodeJS.Platform;
  storeAgentAuthToken?: (agentKeyId: string, token: string) => void;
  readConfig?: () => WlfiConfig;
  writeConfig?: (nextConfig: WlfiConfig) => WlfiConfig;
  deleteConfigKey?: (key: keyof WlfiConfig) => WlfiConfig;
}

export function buildRotateAgentAuthTokenAdminArgs(
  input: RotateAgentAuthTokenAdminArgsInput
): string[] {
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

  args.push(
    'rotate-agent-auth-token',
    '--agent-key-id',
    assertValidAgentKeyId(input.agentKeyId),
    '--print-agent-auth-token'
  );

  return args;
}

export function completeAgentAuthRotation(
  output: RotateAgentAuthTokenAdminOutput,
  deps: CompleteAgentAuthRotationDeps = {}
): CompleteAgentAuthRotationResult {
  const platform = deps.platform ?? process.platform;
  const agentKeyId = assertValidAgentKeyId(output.agent_key_id);
  if (output.agent_auth_token_redacted) {
    throw new Error('rotate-agent-auth-token returned a redacted agent auth token');
  }
  if (!output.agent_auth_token?.trim()) {
    throw new Error('rotate-agent-auth-token returned an empty agent auth token');
  }

  const storeAgentAuthToken =
    deps.storeAgentAuthToken ??
    ((resolvedAgentKeyId: string, token: string) =>
      storeStoredAgentAuthToken(resolvedAgentKeyId, token, platform));
  const loadConfig = deps.readConfig ?? readConfig;
  const persistConfig = deps.writeConfig ?? writeConfig;
  const clearLegacyConfigKey = deps.deleteConfigKey ?? deleteConfigKey;

  loadConfig();
  storeAgentAuthToken(agentKeyId, output.agent_auth_token);

  let updated = persistConfig({ agentKeyId });
  if (updated.agentAuthToken !== undefined) {
    updated = clearLegacyConfigKey('agentAuthToken');
  }

  return {
    agentKeyId,
    keychain: {
      stored: true,
      service:
        resolveAgentAuthStorageService(platform, agentKeyId) ?? 'agentpay-agent-auth-token'
    },
    config: redactConfig(updated)
  };
}
