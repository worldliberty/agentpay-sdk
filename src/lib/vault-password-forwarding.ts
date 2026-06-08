const MAX_SECRET_STDIN_BYTES = 16 * 1024;

export interface VaultPasswordRelayOptions {
  env?: NodeJS.ProcessEnv;
  readFromStdin?: (label: string) => Promise<string>;
}

export interface PreparedVaultPasswordRelay {
  args: string[];
  stdin?: string;
  scrubSensitiveEnv: boolean;
}

const HELP_FLAGS = new Set(['-h', '--help', '-V', '--version']);

function forwardedArgsPrefix(args: string[]): string[] {
  const terminatorIndex = args.indexOf('--');
  return terminatorIndex >= 0 ? args.slice(0, terminatorIndex) : args;
}

function skipEnvRelayForArgs(args: string[]): boolean {
  const forwarded = forwardedArgsPrefix(args);
  return forwarded[0] === 'help' || forwarded.some((arg) => HELP_FLAGS.has(arg));
}

function resolveInlineVaultPasswordArg(args: string[]): {
  index: number;
  value: string;
} | null {
  let match: { index: number; value: string } | null = null;

  for (let index = 0; index < forwardedArgsPrefix(args).length; index += 1) {
    const current = args[index];
    let nextMatch: { index: number; value: string } | null = null;
    if (current === '--vault-password') {
      const value = args[index + 1];
      if (value === undefined || value === '--' || value.startsWith('-')) {
        throw new Error(
          '--vault-password requires a value; use --vault-password=<value> if the value starts with -',
        );
      }
      nextMatch = { index, value };
      index += 1;
    } else if (current.startsWith('--vault-password=')) {
      nextMatch = {
        index,
        value: current.slice('--vault-password='.length),
      };
    }

    if (nextMatch) {
      if (match) {
        throw new Error('--vault-password may only be provided once');
      }
      match = nextMatch;
    }
  }

  return match;
}

function countVaultPasswordStdinFlags(args: string[]): number {
  let matches = 0;

  for (const current of forwardedArgsPrefix(args)) {
    if (current === '--vault-password-stdin') {
      matches += 1;
    }
  }

  return matches;
}

function withTrailingNewline(secret: string): string {
  return `${secret}\n`;
}

function validateSecret(secret: string, label: string): string {
  if (Buffer.byteLength(secret, 'utf8') > MAX_SECRET_STDIN_BYTES) {
    throw new Error(`${label} must not exceed ${MAX_SECRET_STDIN_BYTES} bytes`);
  }

  const trimmed = secret.replace(/[\r\n]+$/u, '');
  if (!trimmed.trim()) {
    throw new Error(`${label} is required`);
  }

  return trimmed;
}

async function readTrimmedSecretFromProcessStdin(label: string): Promise<string> {
  process.stdin.setEncoding('utf8');
  let raw = '';
  for await (const chunk of process.stdin) {
    raw += chunk;
    if (Buffer.byteLength(raw, 'utf8') > MAX_SECRET_STDIN_BYTES) {
      throw new Error(`${label} must not exceed ${MAX_SECRET_STDIN_BYTES} bytes`);
    }
  }

  return validateSecret(raw, label);
}

export async function prepareVaultPasswordRelay(
  args: string[],
  options: VaultPasswordRelayOptions = {},
): Promise<PreparedVaultPasswordRelay> {
  const env = options.env ?? process.env;
  const readFromStdin = options.readFromStdin ?? readTrimmedSecretFromProcessStdin;
  const inlineArg = resolveInlineVaultPasswordArg(args);
  const stdinFlagCount = countVaultPasswordStdinFlags(args);
  const usesStdinFlag = stdinFlagCount > 0;

  if (stdinFlagCount > 1) {
    throw new Error('--vault-password-stdin may only be provided once');
  }

  if (inlineArg && usesStdinFlag) {
    throw new Error('--vault-password conflicts with --vault-password-stdin');
  }

  if (inlineArg) {
    validateSecret(inlineArg.value, 'vaultPassword');
    throw new Error(
      'insecure --vault-password is disabled; use --vault-password-stdin or a local TTY prompt',
    );
  }

  if (usesStdinFlag) {
    return {
      args: [...args],
      stdin: withTrailingNewline(await readFromStdin('vaultPassword')),
      scrubSensitiveEnv: true,
    };
  }

  if (Object.hasOwn(env, 'AGENTPAY_VAULT_PASSWORD')) {
    if (skipEnvRelayForArgs(args)) {
      return {
        args: [...args],
        scrubSensitiveEnv: true,
      };
    }

    validateSecret(env.AGENTPAY_VAULT_PASSWORD ?? '', 'vaultPassword');
    throw new Error(
      'AGENTPAY_VAULT_PASSWORD is disabled for security; use --vault-password-stdin or a local TTY prompt',
    );
  }

  return {
    args: [...args],
    scrubSensitiveEnv: true,
  };
}
