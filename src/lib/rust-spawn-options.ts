import { assertAdminAccessPreconditions } from './admin-guard.js';
import { prepareAgentAuthRelay } from './agent-auth-forwarding.js';
import { prepareVaultPasswordRelay } from './vault-password-forwarding.js';

export interface RunRustBinaryOptions {
  stdin?: string;
  scrubSensitiveEnv?: boolean;
  preSuppliedSecretStdin?: 'vaultPassword' | 'agentAuthToken';
  /**
   * The child prints secret material on stdout (for example a private-key export). When set, the
   * stdout payload is never embedded in thrown error messages or exposed on error objects.
   */
  sensitiveStdout?: boolean;
  /**
   * Terminate the child if it runs longer than this many milliseconds: SIGTERM first, then SIGKILL
   * once the grace period elapses.
   */
  timeoutMs?: number;
  /**
   * Secret payload handed to the child on an extra input pipe at fd 3 (written and closed right
   * after spawn). Lets callers pass a second secret alongside stdin without a temp file or argv.
   */
  extraInputFd3?: string;
}

export interface ChildEnvAllowlistOptions {
  /** Forward `AGENTPAY_*` variables (never the secret-bearing ones). Defaults to true. */
  includeAgentPayVars?: boolean;
}

const SENSITIVE_ENV_KEYS = new Set(['AGENTPAY_AGENT_AUTH_TOKEN', 'AGENTPAY_VAULT_PASSWORD']);

const CHILD_ENV_EXACT_ALLOWLIST = new Set([
  'PATH',
  'HOME',
  'USER',
  'LOGNAME',
  'SHELL',
  'TMPDIR',
  'LANG',
  'LANGUAGE',
  'TERM',
  'COLORTERM',
  'TZ',
  'DBUS_SESSION_BUS_ADDRESS',
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'NO_PROXY',
  'http_proxy',
  'https_proxy',
  'no_proxy',
  'SSL_CERT_FILE',
  'SSL_CERT_DIR',
  'RUST_LOG',
  'RUST_BACKTRACE',
]);

const CHILD_ENV_PREFIX_ALLOWLIST = ['LC_', 'SUDO_', 'XDG_'];

// Defense in depth: these can hijack dynamic loading or the Node runtime and must never reach a
// child even if the allowlist above grows a broader prefix later.
const CHILD_ENV_DENIED_KEYS = new Set(['NODE_OPTIONS']);
const CHILD_ENV_DENIED_PREFIXES = ['DYLD_', 'LD_'];

function isAllowlistedChildEnvKey(key: string, includeAgentPayVars: boolean): boolean {
  if (CHILD_ENV_DENIED_KEYS.has(key)) {
    return false;
  }
  if (CHILD_ENV_DENIED_PREFIXES.some((prefix) => key.startsWith(prefix))) {
    return false;
  }
  if (SENSITIVE_ENV_KEYS.has(key)) {
    return false;
  }
  if (key.startsWith('AGENTPAY_')) {
    return includeAgentPayVars;
  }
  if (CHILD_ENV_EXACT_ALLOWLIST.has(key)) {
    return true;
  }
  return CHILD_ENV_PREFIX_ALLOWLIST.some((prefix) => key.startsWith(prefix));
}

/**
 * Build a child environment from an allowlist of the parent environment. Secrets relayed over
 * stdin (`AGENTPAY_VAULT_PASSWORD`, `AGENTPAY_AGENT_AUTH_TOKEN`) and loader/runtime hijack
 * variables (`DYLD_*`, `LD_*`, `NODE_OPTIONS`) are never forwarded.
 */
export function buildAllowlistedChildEnv(
  source: NodeJS.ProcessEnv = process.env,
  options: ChildEnvAllowlistOptions = {},
): NodeJS.ProcessEnv {
  const includeAgentPayVars = options.includeAgentPayVars ?? true;
  const env: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(source)) {
    if (value === undefined) {
      continue;
    }
    if (!isAllowlistedChildEnvKey(key, includeAgentPayVars)) {
      continue;
    }
    env[key] = value;
  }
  return env;
}

function buildChildEnv(_scrubSensitiveEnv: boolean): NodeJS.ProcessEnv {
  // The relay flag no longer changes the result: the allowlist drops the secret-bearing variables
  // unconditionally, so a child can only ever receive secrets over stdin.
  return buildAllowlistedChildEnv(process.env);
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
