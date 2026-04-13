import { resolveOptionalAgentAuthToken } from './agent-auth-token.js';

export type AgentAuthTokenSource = 'stdin' | 'argv' | 'keychain' | 'config' | 'env';

export interface ResolveAgentAuthTokenInput {
  agentKeyId?: string;
  cliToken?: string;
  cliTokenStdin?: boolean;
  keychainToken?: string | null;
  configToken?: string;
  envToken?: string;
  allowLegacySource?: boolean;
  readFromStdin: (label: string) => Promise<string>;
}

export interface ResolvedAgentAuthToken {
  token: string;
  source: AgentAuthTokenSource;
}

function migrationHint(agentKeyId?: string): string {
  const keyPart = agentKeyId ? agentKeyId : '<uuid>';
  return (
    'migrate it with `agentpay config agent-auth set --agent-key-id ' +
    keyPart +
    ' --agent-auth-token-stdin`'
  );
}

export async function resolveAgentAuthToken(
  input: ResolveAgentAuthTokenInput,
): Promise<ResolvedAgentAuthToken> {
  if (input.cliToken && input.cliTokenStdin) {
    throw new Error('--agent-auth-token conflicts with --agent-auth-token-stdin');
  }

  if (input.cliTokenStdin) {
    return {
      token: resolveOptionalAgentAuthToken(
        await input.readFromStdin('agentAuthToken'),
        'agentAuthToken',
      ) as string,
      source: 'stdin',
    };
  }

  const cliToken = resolveOptionalAgentAuthToken(input.cliToken, 'agentAuthToken');
  if (cliToken) {
    if (!input.allowLegacySource) {
      throw new Error(
        '--agent-auth-token is disabled by default for security; use local credential storage or --agent-auth-token-stdin, ' +
          migrationHint(input.agentKeyId) +
          ', or pass --allow-legacy-agent-auth-source',
      );
    }
    return { token: cliToken, source: 'argv' };
  }

  const keychainToken = resolveOptionalAgentAuthToken(input.keychainToken, 'agentAuthToken');
  if (keychainToken) {
    return { token: keychainToken, source: 'keychain' };
  }

  const configToken = resolveOptionalAgentAuthToken(input.configToken, 'agentAuthToken');
  if (configToken) {
    if (!input.allowLegacySource) {
      throw new Error(
        'agentAuthToken from config.json is disabled by default for security; use local credential storage or --agent-auth-token-stdin, ' +
          migrationHint(input.agentKeyId) +
          ', or pass --allow-legacy-agent-auth-source',
      );
    }
    return { token: configToken, source: 'config' };
  }

  const envToken = resolveOptionalAgentAuthToken(input.envToken, 'agentAuthToken');
  if (envToken) {
    if (!input.allowLegacySource) {
      throw new Error(
        'AGENTPAY_AGENT_AUTH_TOKEN is disabled by default for security; use local credential storage or --agent-auth-token-stdin, ' +
          migrationHint(input.agentKeyId) +
          ', or pass --allow-legacy-agent-auth-source',
      );
    }
    return { token: envToken, source: 'env' };
  }

  throw new Error('agentAuthToken is required; use local credential storage or --agent-auth-token-stdin');
}
