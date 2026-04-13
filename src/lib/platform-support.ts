export function isMacOsPlatform(platform: NodeJS.Platform = process.platform): boolean {
  return platform === 'darwin';
}

export function isLinuxPlatform(platform: NodeJS.Platform = process.platform): boolean {
  return platform === 'linux';
}

export function supportsManagedDaemonPlatform(
  platform: NodeJS.Platform = process.platform,
): boolean {
  return isMacOsPlatform(platform) || isLinuxPlatform(platform);
}

export function describeManagedDaemonPlatformSupport(
  platform: NodeJS.Platform = process.platform,
): string {
  if (isMacOsPlatform(platform)) {
    return 'macOS';
  }
  if (isLinuxPlatform(platform)) {
    return 'Linux';
  }
  return 'macOS or Linux';
}

export function assertMacOsOnlyFeature(
  commandLabel: string,
  detail = 'This command is available only on macOS.',
  platform: NodeJS.Platform = process.platform,
): void {
  if (isMacOsPlatform(platform)) {
    return;
  }

  throw new Error(`${commandLabel} is currently supported only on macOS. ${detail}`);
}

export function assertManagedDaemonPlatform(
  commandLabel: string,
  detail = 'Managed daemon setup is currently supported on macOS and Linux only.',
  platform: NodeJS.Platform = process.platform,
): void {
  if (supportsManagedDaemonPlatform(platform)) {
    return;
  }

  throw new Error(`${commandLabel} is currently supported only on macOS and Linux. ${detail}`);
}
