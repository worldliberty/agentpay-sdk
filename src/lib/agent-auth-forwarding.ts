import {
  MAX_AGENT_AUTH_TOKEN_BYTES,
  assertValidAgentAuthToken
} from './agent-auth-token.js';

export interface AgentAuthRelayOptions {
  env?: NodeJS.ProcessEnv;
  readFromStdin?: (label: string) => Promise<string>;
}

export interface PreparedAgentAuthRelay {
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

function resolveInlineAgentAuthTokenArg(args: string[]): {
  index: number;
  value: string;
} | null {
  let match: { index: number; value: string } | null = null;

  for (let index = 0; index < forwardedArgsPrefix(args).length; index += 1) {
    const current = args[index];
    let nextMatch: { index: number; value: string } | null = null;

    if (current === '--agent-auth-token') {
      const value = args[index + 1];
      if (value === undefined) {
        throw new Error('--agent-auth-token requires a value');
      }
      nextMatch = { index, value };
      index += 1;
    } else if (current.startsWith('--agent-auth-token=')) {
      nextMatch = {
        index,
        value: current.slice('--agent-auth-token='.length)
      };
    }

    if (nextMatch) {
      if (match) {
        throw new Error('--agent-auth-token may only be provided once');
      }
      match = nextMatch;
    }
  }

  return match;
}

function countAgentAuthTokenStdinFlags(args: string[]): number {
  let matches = 0;

  for (const current of forwardedArgsPrefix(args)) {
    if (current === '--agent-auth-token-stdin') {
      matches += 1;
    }
  }

  return matches;
}

function validateSecret(secret: string, label: string): string {
  return assertValidAgentAuthToken(secret, label);
}

function withTrailingNewline(secret: string): string {
  return `${secret}\n`;
}

async function readTrimmedSecretFromProcessStdin(label: string): Promise<string> {
  process.stdin.setEncoding('utf8');
  let raw = '';
  for await (const chunk of process.stdin) {
    raw += chunk;
    if (Buffer.byteLength(raw, 'utf8') > MAX_AGENT_AUTH_TOKEN_BYTES) {
      throw new Error(`${label} must not exceed ${MAX_AGENT_AUTH_TOKEN_BYTES} bytes`);
    }
  }

  return validateSecret(raw, label);
}

export async function prepareAgentAuthRelay(
  args: string[],
  options: AgentAuthRelayOptions = {}
): Promise<PreparedAgentAuthRelay> {
  const env = options.env ?? process.env;
  const readFromStdin = options.readFromStdin ?? readTrimmedSecretFromProcessStdin;
  const inlineArg = resolveInlineAgentAuthTokenArg(args);
  const stdinFlagCount = countAgentAuthTokenStdinFlags(args);
  const usesStdinFlag = stdinFlagCount > 0;

  if (stdinFlagCount > 1) {
    throw new Error('--agent-auth-token-stdin may only be provided once');
  }

  if (inlineArg && usesStdinFlag) {
    throw new Error('--agent-auth-token conflicts with --agent-auth-token-stdin');
  }

  if (inlineArg) {
    validateSecret(inlineArg.value, 'agentAuthToken');
    throw new Error(
      '--agent-auth-token is disabled for security; use --agent-auth-token-stdin or local credential store-backed `agentpay` commands'
    );
  }

  if (usesStdinFlag) {
    return {
      args: [...args],
      stdin: withTrailingNewline(validateSecret(await readFromStdin('agentAuthToken'), 'agentAuthToken')),
      scrubSensitiveEnv: true
    };
  }

  if (Object.prototype.hasOwnProperty.call(env, 'AGENTPAY_AGENT_AUTH_TOKEN')) {
    if (skipEnvRelayForArgs(args)) {
      return {
        args: [...args],
        scrubSensitiveEnv: true
      };
    }

    return {
      args: ['--agent-auth-token-stdin', ...args],
      stdin: withTrailingNewline(validateSecret(env.AGENTPAY_AGENT_AUTH_TOKEN ?? '', 'agentAuthToken')),
      scrubSensitiveEnv: true
    };
  }

  return {
    args: [...args],
    scrubSensitiveEnv: true
  };
}
