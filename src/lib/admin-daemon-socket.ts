import type { WlfiConfig } from '../../packages/config/src/index.js';
import { assertTrustedAdminDaemonSocketPath } from './fs-trust.js';
import { resolveManagedDaemonPlatformSpec } from './managed-daemon-platform.js';
import { isMacOsPlatform, supportsManagedDaemonPlatform } from './platform-support.js';

export const DEFAULT_MANAGED_ADMIN_DAEMON_SOCKET = resolveManagedDaemonPlatformSpec(
  process.platform === 'linux' ? 'linux' : 'darwin',
).daemonSocket;

export type AdminDaemonSocketSource =
  | 'explicit'
  | 'env-daemon-socket'
  | 'config-daemon-socket'
  | 'default';

export interface ResolvedAdminDaemonSocketSelection {
  value: string;
  source: AdminDaemonSocketSource;
}

interface ResolveValidatedAdminDaemonSocketDeps {
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  assertTrustedAdminDaemonSocketPath?: (targetPath: string, label?: string) => string;
}

function presentString(value: string | undefined): string | null {
  const normalized = value?.trim();
  return normalized ? normalized : null;
}

export function resolveAdminDaemonSocketSelection(
  explicitValue: string | undefined,
  config: WlfiConfig,
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): ResolvedAdminDaemonSocketSelection {
  if (explicitValue !== undefined) {
    const explicitSocket = presentString(explicitValue);
    if (!explicitSocket) {
      throw new Error('--daemon-socket requires a path');
    }
    return { value: explicitSocket, source: 'explicit' };
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
    value: resolveManagedDaemonPlatformSpec(
      supportsManagedDaemonPlatform(platform) ? platform : 'darwin',
    ).daemonSocket,
    source: 'default',
  };
}

export function wrapAdminDaemonSocketTrustError(
  message: string,
  source: AdminDaemonSocketSource,
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): Error {
  const lines = [message];
  const managedSocket = supportsManagedDaemonPlatform(platform)
    ? `\`${resolveManagedDaemonPlatformSpec(platform).daemonSocket}\``
    : '`<managed daemon socket>`';
  const nonManagedSocketHint =
    'Recovery: point the command at your existing daemon socket with `--daemon-socket`, `AGENTPAY_DAEMON_SOCKET`, or `agentpay config set daemonSocket <path>`.';

  if (source === 'explicit') {
    lines.push(
      isMacOsPlatform(platform)
        ? `Recovery: rerun without \`--daemon-socket\`, or point it at the managed root-owned socket ${managedSocket}.`
        : `Recovery: rerun without \`--daemon-socket\`, or point it at the managed root-owned socket ${managedSocket}.`,
    );
  } else if (source === 'env-daemon-socket') {
    lines.push(
      supportsManagedDaemonPlatform(platform)
        ? `Recovery: unset \`AGENTPAY_DAEMON_SOCKET\` or point it at the managed root-owned socket ${managedSocket}.`
        : 'Recovery: unset `AGENTPAY_DAEMON_SOCKET` if it is stale, or replace it with the actual daemon socket path.',
    );
  } else if (source === 'config-daemon-socket') {
    lines.push(
      supportsManagedDaemonPlatform(platform)
        ? `Recovery: if this override was not intentional, run \`agentpay config unset daemonSocket\` to fall back to ${managedSocket}.`
        : 'Recovery: if this override was not intentional, run `agentpay config unset daemonSocket`; otherwise replace it with the actual daemon socket path.',
    );
  } else if (presentString(env.AGENTPAY_HOME)) {
    lines.push(
      'Recovery: unset `AGENTPAY_HOME` before rerunning this root-managed admin command unless you intentionally want a custom local AgentPay home.',
    );
  }

  lines.push('Then verify with `agentpay status --strict`.');
  if (supportsManagedDaemonPlatform(platform)) {
    lines.push(
      'If the managed daemon/socket is missing, run `agentpay admin setup --reuse-existing-wallet` or `agentpay admin setup`.',
    );
  } else {
    lines.push(nonManagedSocketHint);
  }
  return new Error(lines.join('\n'));
}

export function resolveValidatedAdminDaemonSocket(
  explicitValue: string | undefined,
  config: WlfiConfig,
  deps: ResolveValidatedAdminDaemonSocketDeps = {},
): string {
  const env = deps.env ?? process.env;
  const platform = deps.platform ?? process.platform;
  const selection = resolveAdminDaemonSocketSelection(explicitValue, config, env, platform);
  const trustAdminDaemonSocketPath =
    deps.assertTrustedAdminDaemonSocketPath ?? assertTrustedAdminDaemonSocketPath;

  if (!supportsManagedDaemonPlatform(platform) && selection.source === 'default') {
    throw new Error(
      'No managed default daemon socket is available on this platform. Pass `--daemon-socket`, set `AGENTPAY_DAEMON_SOCKET`, or configure `daemonSocket` to the existing source-managed daemon socket path.',
    );
  }

  try {
    return trustAdminDaemonSocketPath(selection.value);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw wrapAdminDaemonSocketTrustError(message, selection.source, env, platform);
  }
}
