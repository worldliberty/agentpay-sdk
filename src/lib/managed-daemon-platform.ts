import path from 'node:path';
import { isLinuxPlatform, isMacOsPlatform } from './platform-support.js';
import { DAEMON_PASSWORD_KEYCHAIN_SERVICE } from './keychain.js';

export type ManagedDaemonServiceManager = 'launchd' | 'systemd';

export interface ManagedDaemonPlatformSpec {
  platform: 'darwin' | 'linux';
  serviceManager: ManagedDaemonServiceManager;
  label: string;
  rootDir: string;
  managedBinDir: string;
  daemonSocket: string;
  stateFile: string;
  stateDir: string;
  relayDaemonTokenFile: string;
  serviceFile: string;
  logDir: string | null;
  daemonPasswordService: string | null;
  daemonPasswordFile: string | null;
  sourceInstallScriptName: string;
  sourceUninstallScriptName: string;
  sourceRunnerScriptName: string;
  sourceCredentialHelperName: string;
}

const MACOS_SPEC: ManagedDaemonPlatformSpec = {
  platform: 'darwin',
  serviceManager: 'launchd',
  label: 'com.agentpay.daemon',
  rootDir: '/Library/AgentPay',
  managedBinDir: '/Library/AgentPay/bin',
  daemonSocket: '/Library/AgentPay/run/daemon.sock',
  stateFile: '/var/db/agentpay/daemon-state.enc',
  stateDir: '/var/db/agentpay',
  relayDaemonTokenFile: '/var/db/agentpay/relay-daemon-token',
  serviceFile: '/Library/LaunchDaemons/com.agentpay.daemon.plist',
  logDir: '/var/log/agentpay',
  daemonPasswordService: DAEMON_PASSWORD_KEYCHAIN_SERVICE,
  daemonPasswordFile: null,
  sourceInstallScriptName: 'install-user-daemon.sh',
  sourceUninstallScriptName: 'uninstall-user-daemon.sh',
  sourceRunnerScriptName: 'run-agentpay-daemon.sh',
  sourceCredentialHelperName: 'agentpay-system-keychain',
};

const LINUX_SPEC: ManagedDaemonPlatformSpec = {
  platform: 'linux',
  serviceManager: 'systemd',
  label: 'agentpay-daemon',
  rootDir: '/opt/agentpay',
  managedBinDir: '/opt/agentpay/bin',
  daemonSocket: '/run/agentpay/daemon.sock',
  stateFile: '/var/lib/agentpay/daemon-state.enc',
  stateDir: '/var/lib/agentpay',
  relayDaemonTokenFile: '/var/lib/agentpay/relay-daemon-token',
  serviceFile: '/etc/systemd/system/agentpay-daemon.service',
  logDir: null,
  daemonPasswordService: null,
  daemonPasswordFile: '/var/lib/agentpay/daemon-password',
  sourceInstallScriptName: 'install-system-daemon.sh',
  sourceUninstallScriptName: 'uninstall-system-daemon.sh',
  sourceRunnerScriptName: 'run-agentpay-daemon.sh',
  sourceCredentialHelperName: 'agentpay-daemon-password-helper.sh',
};

export function resolveManagedDaemonPlatformSpec(
  platform: NodeJS.Platform = process.platform,
): ManagedDaemonPlatformSpec {
  if (isMacOsPlatform(platform)) {
    return MACOS_SPEC;
  }
  if (isLinuxPlatform(platform)) {
    return LINUX_SPEC;
  }
  throw new Error(`managed daemon support is unavailable on ${platform}`);
}

export function resolveManagedDaemonBinaryPath(
  platform: NodeJS.Platform = process.platform,
): string {
  const spec = resolveManagedDaemonPlatformSpec(platform);
  return path.join(spec.managedBinDir, `agentpay-daemon${platform === 'win32' ? '.exe' : ''}`);
}

export function resolveManagedDaemonRunnerPath(
  platform: NodeJS.Platform = process.platform,
): string {
  const spec = resolveManagedDaemonPlatformSpec(platform);
  return path.join(spec.managedBinDir, spec.sourceRunnerScriptName);
}

export function resolveManagedDaemonCredentialHelperPath(
  platform: NodeJS.Platform = process.platform,
): string {
  const spec = resolveManagedDaemonPlatformSpec(platform);
  return path.join(spec.managedBinDir, spec.sourceCredentialHelperName);
}
