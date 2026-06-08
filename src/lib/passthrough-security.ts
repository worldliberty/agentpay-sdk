import { defaultDaemonSocketPath, type WlfiConfig } from '../../packages/config/src/index.js';
import {
  resolveAdminDaemonSocketSelection,
  wrapAdminDaemonSocketTrustError,
} from './admin-daemon-socket.js';
import { assertTrustedAdminDaemonSocketPath, assertTrustedDaemonSocketPath } from './fs-trust.js';
import type { RustBinaryName } from './rust.js';

const HELP_FLAGS = new Set(['-h', '--help', '-V', '--version']);

function forwardedArgsPrefix(args: string[]): string[] {
  const terminatorIndex = args.indexOf('--');
  return terminatorIndex >= 0 ? args.slice(0, terminatorIndex) : args;
}

interface ResolvePassthroughDaemonSocketDeps {
  env?: NodeJS.ProcessEnv;
  assertTrustedDaemonSocketPath?: (targetPath: string, label?: string) => string;
}

interface ForwardedOptionValue {
  present: boolean;
  value: string | undefined;
}

type ResolvedDaemonSocketSource =
  | 'explicit'
  | 'env-daemon-socket'
  | 'config-daemon-socket'
  | 'default'
  | 'agent-default';

interface ResolvedDaemonSocketSelection {
  value: string;
  source: ResolvedDaemonSocketSource;
}

function findForwardedOptionOccurrences(
  args: string[],
  optionName: string,
): ForwardedOptionValue[] {
  const matches: ForwardedOptionValue[] = [];

  for (let index = 0; index < args.length; index += 1) {
    const current = args[index];
    if (current === '--') {
      break;
    }

    if (current === optionName) {
      const value = args[index + 1];
      if (value === undefined || value === '--' || value.startsWith('-')) {
        throw new Error(
          `${optionName} requires a path; use ${optionName}=<path> if the path starts with -`,
        );
      }
      matches.push({
        present: true,
        value,
      });
      index += 1;
      continue;
    }

    if (current.startsWith(`${optionName}=`)) {
      matches.push({
        present: true,
        value: current.slice(optionName.length + 1),
      });
    }
  }

  return matches;
}

function presentString(value: string | undefined): string | null {
  const normalized = value?.trim();
  return normalized ? normalized : null;
}

function resolvePassthroughDaemonSocketSelection(
  binaryName: RustBinaryName,
  forwardedValue: ForwardedOptionValue,
  env: NodeJS.ProcessEnv,
  config: WlfiConfig,
): ResolvedDaemonSocketSelection {
  if (binaryName === 'agentpay-admin') {
    return resolveAdminDaemonSocketSelection(
      forwardedValue.present ? forwardedValue.value : undefined,
      config,
      env,
    );
  }

  const forwardedSocket = presentString(forwardedValue.value);
  if (forwardedSocket) {
    return { value: forwardedSocket, source: 'explicit' };
  }

  const envSocket = presentString(env.AGENTPAY_DAEMON_SOCKET);
  if (envSocket) {
    return { value: envSocket, source: 'env-daemon-socket' };
  }

  const configuredSocket = presentString(config.daemonSocket);
  if (configuredSocket) {
    return { value: configuredSocket, source: 'config-daemon-socket' };
  }

  return {
    value: defaultDaemonSocketPath(),
    source: 'agent-default',
  };
}

export function forwardedArgsSkipDaemonSocketValidation(args: string[]): boolean {
  const forwarded = forwardedArgsPrefix(args);
  return forwarded[0] === 'help' || forwarded.some((arg) => HELP_FLAGS.has(arg));
}

export function readForwardedLongOptionValue(
  args: string[],
  optionName: string,
): ForwardedOptionValue {
  const matches = findForwardedOptionOccurrences(args, optionName);
  if (matches.length > 1) {
    throw new Error(`${optionName} may only be provided once`);
  }

  if (matches.length === 1) {
    return matches[0];
  }

  return {
    present: false,
    value: undefined,
  };
}

export function resolveValidatedPassthroughDaemonSocket(
  binaryName: RustBinaryName,
  args: string[],
  config: WlfiConfig,
  deps: ResolvePassthroughDaemonSocketDeps = {},
): string | null {
  if (binaryName === 'agentpay-daemon' || forwardedArgsSkipDaemonSocketValidation(args)) {
    return null;
  }

  const env = deps.env ?? process.env;
  const trustDaemonSocketPath =
    deps.assertTrustedDaemonSocketPath ??
    (binaryName === 'agentpay-admin'
      ? assertTrustedAdminDaemonSocketPath
      : assertTrustedDaemonSocketPath);
  const forwardedValue = readForwardedLongOptionValue(args, '--daemon-socket');

  if (forwardedValue.present && !presentString(forwardedValue.value)) {
    throw new Error('--daemon-socket requires a path');
  }

  const selection = resolvePassthroughDaemonSocketSelection(
    binaryName,
    forwardedValue,
    env,
    config,
  );

  try {
    return trustDaemonSocketPath(selection.value);
  } catch (error) {
    if (binaryName !== 'agentpay-admin') {
      throw error;
    }
    const message = error instanceof Error ? error.message : String(error);
    throw wrapAdminDaemonSocketTrustError(
      message,
      selection.source === 'agent-default' ? 'default' : selection.source,
      env,
    );
  }
}
