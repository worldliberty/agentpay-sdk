/**
 * `agentpay admin privileged` (hidden): the root side of the sudo relay used by the interactive
 * screens (see src/auth/privileged.ts). Reads one `{method, params}` JSON request on stdin,
 * calls the signer daemon as the root peer, and prints `{ok, response | error}` on stdout.
 * Only the admin methods in `RELAYED_METHODS` are forwarded.
 */
import type { Command } from 'commander';
import { RELAYED_METHODS, type RelayRequest, type RelayResponse } from '../auth/privileged.js';
import { copy } from '../copy/index.js';
import { AuthError, SignerCallError, UsageError } from '../errors.js';
import { printJson } from './output.js';
import { type CommandEnv, handler } from './run.js';

const RELAY_CALL_TIMEOUT_MS = 120_000;

export function parseRelayRequest(text: string): RelayRequest {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new UsageError('the relay request is not JSON');
  }
  const request = value as Partial<RelayRequest>;
  if (
    typeof request.method !== 'string' ||
    !(RELAYED_METHODS as readonly string[]).includes(request.method) ||
    typeof request.params !== 'object' ||
    request.params === null ||
    'auth' in request.params
  ) {
    throw new UsageError('the relay request names no relayed admin method');
  }
  return request as RelayRequest;
}

export function registerPrivilegedCommand(admin: Command, env: CommandEnv): void {
  admin.command('privileged', { hidden: true }).action(
    handler(env, async () => {
      if (env.context.euid !== 0) {
        throw new AuthError('privileged_only', copy.errors.privilegedOnly);
      }
      const request = parseRelayRequest(await env.context.io.readStdin());
      const params =
        request.method === 'EnrollAdminCredential'
          ? request.params
          : { ...request.params, auth: 'peer_credentials' };
      let output: RelayResponse;
      try {
        const response = await env.context
          .signer()
          .rpc.callUntyped({ method: request.method, params }, RELAY_CALL_TIMEOUT_MS);
        output = { ok: true, response };
      } catch (error) {
        if (!(error instanceof SignerCallError)) {
          throw error;
        }
        output = { ok: false, error: error.wire };
      }
      printJson(env.context.io, output);
    }),
  );
}
