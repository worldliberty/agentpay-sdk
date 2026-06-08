export const MAX_AGENT_AUTH_TOKEN_BYTES = 16 * 1024;

export function assertValidAgentAuthToken(token: string, label = 'agentAuthToken'): string {
  if (Buffer.byteLength(token, 'utf8') > MAX_AGENT_AUTH_TOKEN_BYTES) {
    throw new Error(`${label} must not exceed ${MAX_AGENT_AUTH_TOKEN_BYTES} bytes`);
  }

  const normalized = token.replace(/[\r\n]+$/u, '');
  if (!normalized.trim()) {
    throw new Error(`${label} is required`);
  }

  return normalized;
}

export function resolveOptionalAgentAuthToken(
  token: string | null | undefined,
  label = 'agentAuthToken',
): string | null {
  if (token === null || token === undefined) {
    return null;
  }

  return assertValidAgentAuthToken(token, label);
}
