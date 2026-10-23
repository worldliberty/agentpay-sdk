import {
  deleteConfigKey,
  readConfig,
  redactConfig,
  type WalletProfile,
  type WlfiConfig,
  writeConfig,
} from '../../packages/config/src/index.js';
import { writeAgentAuthRecoveryFile } from './agent-auth-file.js';
import { resolveAgentAuthStorageService, storeStoredAgentAuthToken } from './agent-auth-storage.js';
import { assertValidAgentKeyId } from './keychain.js';
import { resolveWalletProfile } from './wallet-profile.js';

const AGENT_AUTH_RECOVERY_LEASE_MS = 24 * 60 * 60 * 1000;

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
  writeRecoveryFile?: (agentKeyId: string, payload: Record<string, unknown>) => string;
  readConfig?: () => WlfiConfig;
  writeConfig?: (nextConfig: WlfiConfig) => WlfiConfig;
  deleteConfigKey?: (key: keyof WlfiConfig) => WlfiConfig;
  now?: () => Date;
}

export function buildRotateAgentAuthTokenAdminArgs(
  input: RotateAgentAuthTokenAdminArgsInput,
): string[] {
  const args = ['--json', '--quiet'];

  if (input.vaultPassword) {
    throw new Error(
      'insecure vaultPassword is disabled; use vaultPasswordStdin or an interactive prompt',
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
    '--print-agent-auth-token',
  );

  return args;
}

function tryResolveWalletProfile(config: WlfiConfig): WalletProfile | null {
  try {
    return resolveWalletProfile(config);
  } catch {
    return null;
  }
}

/**
 * Shape the rotated credential as a bootstrap-credentials document so the standard
 * `agentpay config agent-auth import <path>` flow can store it. Wallet metadata is copied from the
 * current profile when available; without it the file still carries the credential itself.
 */
export function buildAgentAuthRecoveryPayload(input: {
  agentKeyId: string;
  agentAuthToken: string;
  config: WlfiConfig;
  now?: Date;
}): Record<string, unknown> {
  const now = input.now ?? new Date();
  const payload: Record<string, unknown> = {
    recovery: 'agent-auth-rotation',
    created_at: now.toISOString(),
    lease_id: `agent-auth-rotation-${now.getTime()}`,
    lease_expires_at: new Date(now.getTime() + AGENT_AUTH_RECOVERY_LEASE_MS).toISOString(),
    agent_key_id: input.agentKeyId,
    agent_auth_token: input.agentAuthToken,
    agent_auth_token_redacted: false,
  };

  const profile = tryResolveWalletProfile(input.config);
  if (profile?.vaultKeyId && profile.vaultPublicKey) {
    Object.assign(payload, {
      vault_key_id: profile.vaultKeyId,
      vault_key_algorithm: profile.algorithm ?? 'secp256k1',
      vault_public_key: profile.vaultPublicKey,
      solana_public_key: profile.solanaPublicKey ?? null,
      solana_address: profile.solanaAddress ?? null,
      policy_attachment: profile.policyAttachment ?? 'all_policies',
      attached_policy_ids: profile.attachedPolicyIds ?? [],
      policy_note: profile.policyNote ?? 'agent auth token rotation recovery',
      network_scope: profile.networkScope ?? null,
      asset_scope: profile.assetScope ?? null,
      recipient_scope: profile.recipientScope ?? null,
    });
  }

  return payload;
}

export function completeAgentAuthRotation(
  output: RotateAgentAuthTokenAdminOutput,
  deps: CompleteAgentAuthRotationDeps = {},
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
  const writeRecoveryFile = deps.writeRecoveryFile ?? writeAgentAuthRecoveryFile;
  const loadConfig = deps.readConfig ?? readConfig;
  const persistConfig = deps.writeConfig ?? writeConfig;
  const clearLegacyConfigKey = deps.deleteConfigKey ?? deleteConfigKey;

  const currentConfig = loadConfig();
  try {
    storeAgentAuthToken(agentKeyId, output.agent_auth_token);
  } catch (error) {
    // The daemon has already invalidated the previous token. Losing the new one here would lock
    // the agent out, so park it in a private recovery file before surfacing the storage failure.
    const storeMessage = error instanceof Error ? error.message : String(error);
    const recoveryPath = writeRecoveryFile(
      agentKeyId,
      buildAgentAuthRecoveryPayload({
        agentKeyId,
        agentAuthToken: output.agent_auth_token,
        config: currentConfig,
        now: deps.now?.(),
      }),
    );
    throw new Error(
      `agent auth token was rotated but could not be stored locally: ${storeMessage}. ` +
        `The new token was saved to '${recoveryPath}' (mode 0600); the previous token is no longer valid. ` +
        `Recover with \`agentpay config agent-auth import ${recoveryPath}\` (or ` +
        `\`agentpay config agent-auth set --agent-key-id ${agentKeyId} --agent-auth-token-stdin\`), ` +
        'then delete that file.',
    );
  }

  let updated = persistConfig({ agentKeyId });
  if (updated.agentAuthToken !== undefined) {
    updated = clearLegacyConfigKey('agentAuthToken');
  }

  return {
    agentKeyId,
    keychain: {
      stored: true,
      service: resolveAgentAuthStorageService(platform, agentKeyId) ?? 'agentpay-agent-auth-token',
    },
    config: redactConfig(updated),
  };
}
