/**
 * Resolves the calling agent's credentials: the key id from `--agent-key-id`,
 * `AGENTPAY_AGENT_KEY_ID`, or client state; the token from stdin (`--agent-auth-token-stdin`)
 * or the OS secret store. Tokens are never accepted as arguments or environment variables.
 */
import { copy } from '../copy/index.js';
import { AuthError, EXIT, UsageError } from '../errors.js';
import type { AgentAuth } from '../generated/index.js';
import { type ClientStateStore, isUuid } from './client-state.js';
import { assertStorableSecret, type SecretStore } from './secret-store.js';

export interface AgentAuthFlags {
  agentKeyId?: string | undefined;
  agentAuthTokenStdin?: boolean | undefined;
}

export interface AgentAuthSources {
  env: NodeJS.ProcessEnv;
  state: ClientStateStore;
  store: SecretStore;
  readStdin: () => Promise<string>;
}

export function resolveAgentKeyId(flags: AgentAuthFlags, sources: AgentAuthSources): string {
  const explicit = flags.agentKeyId ?? sources.env.AGENTPAY_AGENT_KEY_ID;
  if (explicit !== undefined && explicit.trim() !== '') {
    if (!isUuid(explicit)) {
      throw new UsageError('--agent-key-id must be a UUID');
    }
    return explicit.trim().toLowerCase();
  }
  const saved = sources.state.read().agentKeyId;
  if (!saved) {
    throw new AuthError('not_set_up', copy.errors.notSetUp, EXIT.notSetUp);
  }
  return saved;
}

export async function resolveAgentAuth(
  flags: AgentAuthFlags,
  sources: AgentAuthSources,
): Promise<AgentAuth> {
  const agentKeyId = resolveAgentKeyId(flags, sources);
  if (flags.agentAuthTokenStdin) {
    const token = (await sources.readStdin()).trim();
    return { agent_key_id: agentKeyId, agent_auth_token: assertStorableSecret(token) };
  }
  const token = await sources.store.read(agentKeyId);
  if (!token) {
    throw new AuthError(
      'token_missing',
      copy.errors.tokenMissing(agentKeyId, sources.store.label),
      EXIT.notSetUp,
    );
  }
  return { agent_key_id: agentKeyId, agent_auth_token: token };
}
