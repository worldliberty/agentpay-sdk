import { assertAdminAccessPreconditions } from './admin-guard.js';
import { prepareAgentAuthRelay } from './agent-auth-forwarding.js';
import { prepareVaultPasswordRelay } from './vault-password-forwarding.js';

export interface RunRustBinaryOptions {
  stdin?: string;
  scrubSensitiveEnv?: boolean;
  preSuppliedSecretStdin?: 'vaultPassword' | 'agentAuthToken';
}

const SENSITIVE_ENV_KEYS = ['AGENTPAY_AGENT_AUTH_TOKEN', 'AGENTPAY_VAULT_PASSWORD'] as const;

function buildChildEnv(scrubSensitiveEnv: boolean): NodeJS.ProcessEnv {
  if (!scrubSensitiveEnv) {
    return process.env;
  }

  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of SENSITIVE_ENV_KEYS) {
    delete env[key];
  }
  return env;
}

function supportsVaultPasswordRelay(binaryName: string): boolean {
  return binaryName === 'agentpay-admin' || binaryName === 'agentpay-daemon';
}

function supportsAgentAuthRelay(binaryName: string): boolean {
  return binaryName === 'agentpay-agent';
}

function hasFlag(args: string[], flag: string): boolean {
  return args.includes(flag);
}

export async function prepareSpawnOptions(
  binaryName: 'agentpay-daemon' | 'agentpay-admin' | 'agentpay-agent',
  args: string[],
  options: RunRustBinaryOptions,
): Promise<{
  args: string[];
  stdin?: string;
  env: NodeJS.ProcessEnv;
}> {
  let stdin = options.stdin;
  let scrubSensitiveEnv = options.scrubSensitiveEnv ?? false;
  let preparedArgs = [...args];
  const preSuppliedSecretStdin = options.preSuppliedSecretStdin;

  if (preSuppliedSecretStdin && stdin === undefined) {
    throw new Error('preSuppliedSecretStdin requires an explicit stdin payload');
  }

  if (supportsVaultPasswordRelay(binaryName)) {
    if (preSuppliedSecretStdin === 'vaultPassword') {
      if (!hasFlag(preparedArgs, '--vault-password-stdin')) {
        throw new Error(
          'preSuppliedSecretStdin=vaultPassword requires --vault-password-stdin in args',
        );
      }
      scrubSensitiveEnv = true;
    } else {
      const relay = await prepareVaultPasswordRelay(preparedArgs);
      if (stdin !== undefined && relay.stdin !== undefined) {
        throw new Error('vault password relay conflicts with explicit stdin payload');
      }

      preparedArgs = relay.args;
      stdin = relay.stdin ?? stdin;
      scrubSensitiveEnv = scrubSensitiveEnv || relay.scrubSensitiveEnv;
    }
  }

  if (supportsAgentAuthRelay(binaryName)) {
    if (preSuppliedSecretStdin === 'agentAuthToken') {
      if (!hasFlag(preparedArgs, '--agent-auth-token-stdin')) {
        throw new Error(
          'preSuppliedSecretStdin=agentAuthToken requires --agent-auth-token-stdin in args',
        );
      }
      scrubSensitiveEnv = true;
    } else {
      const relay = await prepareAgentAuthRelay(preparedArgs);
      if (stdin !== undefined && relay.stdin !== undefined) {
        throw new Error('agent auth token relay conflicts with explicit stdin payload');
      }

      preparedArgs = relay.args;
      stdin = relay.stdin ?? stdin;
      scrubSensitiveEnv = scrubSensitiveEnv || relay.scrubSensitiveEnv;
    }
  }

  assertAdminAccessPreconditions(binaryName, preparedArgs);

  return {
    args: preparedArgs,
    stdin,
    env: buildChildEnv(scrubSensitiveEnv),
  };
}
