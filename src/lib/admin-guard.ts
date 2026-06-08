import type { RustBinaryName } from './rust.js';

const HELP_FLAGS = new Set(['-h', '--help', '-V', '--version']);

export type AdminAccessMode =
  | 'not-required'
  | 'vault-password-stdin'
  | 'interactive-prompt'
  | 'blocked';

export interface AdminAccessGuardDeps {
  env?: NodeJS.ProcessEnv;
  getEffectiveUid?: () => number | null;
  stdinIsTty?: boolean;
  stderrIsTty?: boolean;
}

export interface AdminAccessResolution {
  permitted: boolean;
  mode: AdminAccessMode;
  reason: string;
  runningAsRoot: boolean;
  hasVaultPasswordSource: boolean;
  canPromptSecurely: boolean;
  nonInteractive: boolean;
}

function defaultGetEffectiveUid(): number | null {
  if (typeof process.geteuid === 'function') {
    return process.geteuid();
  }
  if (typeof process.getuid === 'function') {
    return process.getuid();
  }
  return null;
}

function forwardedArgsPrefix(args: string[]): string[] {
  const terminatorIndex = args.indexOf('--');
  return terminatorIndex >= 0 ? args.slice(0, terminatorIndex) : args;
}

function findForwardedOptionValue(args: string[], optionName: string): string | null {
  const forwarded = forwardedArgsPrefix(args);

  for (let index = 0; index < forwarded.length; index += 1) {
    const current = forwarded[index];
    if (current === optionName) {
      const next = forwarded[index + 1];
      if (next === undefined || next === '--' || next.startsWith('-')) {
        throw new Error(
          `${optionName} requires a value; use ${optionName}=<value> if the value starts with -`,
        );
      }
      return next;
    }
    if (current.startsWith(`${optionName}=`)) {
      return current.slice(optionName.length + 1);
    }
  }

  return null;
}

function hasVaultPasswordInlineArg(args: string[]): boolean {
  const value = findForwardedOptionValue(args, '--vault-password');
  return value !== null && value.trim().length > 0;
}

function hasVaultPasswordStdinFlag(args: string[]): boolean {
  return forwardedArgsPrefix(args).includes('--vault-password-stdin');
}

function hasNonInteractiveFlag(args: string[]): boolean {
  return forwardedArgsPrefix(args).includes('--non-interactive');
}

export function forwardedArgsSkipAdminAccessGuard(args: string[]): boolean {
  return args[0] === 'help' || forwardedArgsPrefix(args).some((arg) => HELP_FLAGS.has(arg));
}

export function resolveAdminAccess(
  binaryName: RustBinaryName,
  args: string[],
  deps: AdminAccessGuardDeps = {},
): AdminAccessResolution {
  if (binaryName !== 'agentpay-admin' || forwardedArgsSkipAdminAccessGuard(args)) {
    return {
      permitted: true,
      mode: 'not-required',
      reason: 'admin access guard is not required for this invocation',
      runningAsRoot: false,
      hasVaultPasswordSource: false,
      canPromptSecurely: false,
      nonInteractive: hasNonInteractiveFlag(args),
    };
  }

  const env = deps.env ?? process.env;
  const getEffectiveUid = deps.getEffectiveUid ?? defaultGetEffectiveUid;
  const stdinIsTty = deps.stdinIsTty ?? Boolean(process.stdin.isTTY);
  const stderrIsTty = deps.stderrIsTty ?? Boolean(process.stderr.isTTY);
  const runningAsRoot = getEffectiveUid() === 0;
  const inlineVaultPassword = hasVaultPasswordInlineArg(args);
  const stdinVaultPassword = hasVaultPasswordStdinFlag(args);
  const envVaultPassword = Boolean(env.AGENTPAY_VAULT_PASSWORD?.trim());
  const nonInteractive = hasNonInteractiveFlag(args);
  const hasVaultPasswordSource = inlineVaultPassword || stdinVaultPassword || envVaultPassword;
  const canPromptSecurely = !nonInteractive && stdinIsTty && stderrIsTty;

  if (inlineVaultPassword) {
    return {
      permitted: false,
      mode: 'blocked',
      reason:
        'insecure --vault-password is disabled; use --vault-password-stdin or a local TTY prompt',
      runningAsRoot,
      hasVaultPasswordSource,
      canPromptSecurely,
      nonInteractive,
    };
  }

  if (stdinVaultPassword) {
    return {
      permitted: true,
      mode: 'vault-password-stdin',
      reason: 'vault password will be read from stdin',
      runningAsRoot,
      hasVaultPasswordSource,
      canPromptSecurely,
      nonInteractive,
    };
  }

  if (envVaultPassword) {
    return {
      permitted: false,
      mode: 'blocked',
      reason:
        'AGENTPAY_VAULT_PASSWORD is disabled for security; use --vault-password-stdin or a local TTY prompt',
      runningAsRoot,
      hasVaultPasswordSource,
      canPromptSecurely,
      nonInteractive,
    };
  }

  if (canPromptSecurely) {
    return {
      permitted: true,
      mode: 'interactive-prompt',
      reason: 'a local tty is available for secure password entry',
      runningAsRoot,
      hasVaultPasswordSource,
      canPromptSecurely,
      nonInteractive,
    };
  }

  return {
    permitted: false,
    mode: 'blocked',
    reason: nonInteractive
      ? 'vault password is required in non-interactive mode; use --vault-password-stdin'
      : 'agentpay admin commands require --vault-password-stdin or a local TTY so a human can enter the vault password securely',
    runningAsRoot,
    hasVaultPasswordSource,
    canPromptSecurely,
    nonInteractive,
  };
}

export function assertAdminAccessPreconditions(
  binaryName: RustBinaryName,
  args: string[],
  deps: AdminAccessGuardDeps = {},
): void {
  const access = resolveAdminAccess(binaryName, args, deps);
  if (access.permitted) {
    return;
  }

  throw new Error(access.reason);
}
