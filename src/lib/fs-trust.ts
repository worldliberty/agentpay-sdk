import fs from 'node:fs';
import path from 'node:path';

const PRIVATE_FILE_MODE_MASK = 0o077;
const GROUP_OTHER_WRITE_MODE_MASK = 0o022;
const STICKY_BIT_MODE = 0o1000;

function runningAsRoot(): boolean {
  return typeof process.geteuid === 'function' && process.geteuid() === 0;
}

function readLstat(targetPath: string): fs.Stats | null {
  try {
    return fs.lstatSync(targetPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

function isStableRootOwnedSymlink(stats: fs.Stats, targetPath: string): boolean {
  if (process.platform === 'win32' || typeof stats.uid !== 'number' || stats.uid !== 0) {
    return false;
  }

  const parentPath = path.dirname(targetPath);
  const parentStats = readLstat(parentPath);
  return Boolean(
    parentStats?.isDirectory() &&
      typeof parentStats.uid === 'number' &&
      parentStats.uid === 0 &&
      (parentStats.mode & GROUP_OTHER_WRITE_MODE_MASK) === 0,
  );
}

function assertNoSymlinkAncestorDirectories(targetPath: string, label: string): void {
  const normalizedPath = path.resolve(targetPath);
  const parentPath = path.dirname(normalizedPath);
  if (parentPath === normalizedPath) {
    return;
  }

  const { root } = path.parse(parentPath);
  const relativeParent = parentPath.slice(root.length);
  if (!relativeParent) {
    return;
  }

  let currentPath = root;
  for (const segment of relativeParent.split(path.sep).filter(Boolean)) {
    currentPath = path.join(currentPath, segment);
    const stats = readLstat(currentPath);
    if (!stats) {
      break;
    }
    if (stats.isSymbolicLink()) {
      if (isStableRootOwnedSymlink(stats, currentPath)) {
        continue;
      }
      throw new Error(
        `${label} '${normalizedPath}' must not traverse symlinked ancestor directories`,
      );
    }
  }
}

export function allowedOwnerUids(): Set<number> {
  const allowed = new Set<number>();
  const effectiveUid = typeof process.geteuid === 'function' ? process.geteuid() : null;
  if (effectiveUid !== null) {
    allowed.add(effectiveUid);
  }

  const sudoUid = process.env.SUDO_UID?.trim();
  if (effectiveUid === 0 && sudoUid && /^\d+$/u.test(sudoUid)) {
    allowed.add(Number(sudoUid));
  }

  return allowed;
}

export function assertTrustedOwner(stats: fs.Stats, targetPath: string, label: string): void {
  if (process.platform === 'win32' || typeof stats.uid !== 'number') {
    return;
  }

  if (stats.uid === 0) {
    return;
  }

  const allowed = allowedOwnerUids();
  if (!allowed.has(stats.uid)) {
    throw new Error(
      `${label} '${targetPath}' must be owned by the current user, sudo caller, or root`,
    );
  }
}

function assertTrustedDaemonSocketOwner(stats: fs.Stats, targetPath: string, label: string): void {
  if (runningAsRoot()) {
    assertRootOwned(stats, targetPath, label);
    return;
  }

  assertTrustedOwner(stats, targetPath, label);
}

export function assertRootOwned(stats: fs.Stats, targetPath: string, label: string): void {
  if (process.platform === 'win32') {
    return;
  }

  if (typeof stats.uid !== 'number') {
    throw new Error(`${label} '${targetPath}' owner could not be determined`);
  }

  if (stats.uid !== 0) {
    throw new Error(`${label} '${targetPath}' must be owned by root`);
  }
}

function isStickyDirectory(stats: fs.Stats): boolean {
  return process.platform !== 'win32' && (stats.mode & STICKY_BIT_MODE) !== 0;
}

export function assertPrivateFileStats(stats: fs.Stats, targetPath: string, label: string): void {
  assertTrustedOwner(stats, targetPath, label);

  if (process.platform === 'win32') {
    return;
  }

  if ((stats.mode & PRIVATE_FILE_MODE_MASK) !== 0) {
    throw new Error(`${label} '${targetPath}' must not grant group/other permissions`);
  }
}

function assertSecureDirectoryStats(
  stats: fs.Stats,
  targetPath: string,
  label: string,
  options: { allowStickyGroupOtherWritable?: boolean } = {},
): void {
  assertTrustedOwner(stats, targetPath, label);
  if (process.platform === 'win32') {
    return;
  }

  if ((stats.mode & GROUP_OTHER_WRITE_MODE_MASK) === 0) {
    return;
  }

  if (options.allowStickyGroupOtherWritable && isStickyDirectory(stats)) {
    return;
  }

  throw new Error(`${label} '${targetPath}' must not be writable by group/other`);
}

function ancestorDirectoryPaths(targetPath: string): string[] {
  const resolvedPath = fs.realpathSync.native(path.resolve(targetPath));
  const segments: string[] = [];
  let currentPath = resolvedPath;

  while (true) {
    segments.push(currentPath);
    const parentPath = path.dirname(currentPath);
    if (parentPath === currentPath) {
      break;
    }
    currentPath = parentPath;
  }

  return segments;
}

function findNearestExistingPath(targetPath: string): { path: string; stats: fs.Stats } {
  let currentPath = path.resolve(targetPath);

  while (true) {
    const stats = readLstat(currentPath);
    if (stats) {
      return {
        path: currentPath,
        stats,
      };
    }

    const parentPath = path.dirname(currentPath);
    if (parentPath === currentPath) {
      throw new Error(`No existing ancestor directory found for '${targetPath}'`);
    }

    currentPath = parentPath;
  }
}

export function assertTrustedDirectoryPath(targetPath: string, label: string): void {
  const normalizedPath = path.resolve(targetPath);
  assertNoSymlinkAncestorDirectories(normalizedPath, label);
  const targetStats = fs.lstatSync(normalizedPath);

  if (targetStats.isSymbolicLink()) {
    throw new Error(`${label} '${normalizedPath}' must not be a symlink`);
  }
  if (!targetStats.isDirectory()) {
    throw new Error(`${label} '${normalizedPath}' must be a directory`);
  }

  assertSecureDirectoryStats(targetStats, normalizedPath, label);

  for (const [index, currentPath] of ancestorDirectoryPaths(normalizedPath).entries()) {
    if (index === 0) {
      continue;
    }

    const stats = fs.lstatSync(currentPath);
    if (!stats.isDirectory()) {
      throw new Error(`${label} '${currentPath}' must be a directory`);
    }

    assertSecureDirectoryStats(stats, currentPath, label, {
      allowStickyGroupOtherWritable: index > 0,
    });
  }
}

export function assertTrustedDaemonSocketPath(targetPath: string, label = 'Daemon socket'): string {
  const resolvedPath = path.resolve(targetPath);
  assertTrustedDirectoryPath(path.dirname(resolvedPath), `${label} directory`);

  let stats: fs.Stats;
  try {
    stats = fs.lstatSync(resolvedPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new Error(`${label} '${resolvedPath}' does not exist`);
    }
    throw error;
  }

  if (stats.isSymbolicLink()) {
    throw new Error(`${label} '${resolvedPath}' must not be a symlink`);
  }

  if (process.platform !== 'win32' && !stats.isSocket()) {
    throw new Error(`${label} '${resolvedPath}' must be a unix socket`);
  }

  assertTrustedDaemonSocketOwner(stats, resolvedPath, label);
  return resolvedPath;
}

export function assertTrustedAdminDaemonSocketPath(
  targetPath: string,
  label = 'Daemon socket',
): string {
  const resolvedPath = path.resolve(targetPath);
  assertTrustedRootDirectoryPath(path.dirname(resolvedPath), `${label} directory`);

  let stats: fs.Stats;
  try {
    stats = fs.lstatSync(resolvedPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new Error(`${label} '${resolvedPath}' does not exist`);
    }
    throw error;
  }

  if (stats.isSymbolicLink()) {
    throw new Error(`${label} '${resolvedPath}' must not be a symlink`);
  }

  if (process.platform !== 'win32' && !stats.isSocket()) {
    throw new Error(`${label} '${resolvedPath}' must be a unix socket`);
  }

  assertRootOwned(stats, resolvedPath, label);
  return resolvedPath;
}

export function assertTrustedRootPlannedDirectoryPath(targetPath: string, label: string): string {
  const normalizedPath = path.resolve(targetPath);
  assertNoSymlinkAncestorDirectories(normalizedPath, label);
  const stats = readLstat(normalizedPath);

  if (stats) {
    if (stats.isSymbolicLink()) {
      throw new Error(`${label} '${normalizedPath}' must not be a symlink`);
    }
    if (!stats.isDirectory()) {
      throw new Error(`${label} '${normalizedPath}' must be a directory`);
    }

    assertTrustedRootDirectoryPath(normalizedPath, label);
    return normalizedPath;
  }

  const nearestExistingPath = findNearestExistingPath(normalizedPath);
  if (nearestExistingPath.stats.isSymbolicLink()) {
    throw new Error(`${label} '${nearestExistingPath.path}' must not be a symlink`);
  }
  if (!nearestExistingPath.stats.isDirectory()) {
    throw new Error(`${label} '${nearestExistingPath.path}' must be a directory`);
  }

  assertTrustedRootDirectoryPath(nearestExistingPath.path, label);
  return normalizedPath;
}

export function assertTrustedRootPlannedDaemonSocketPath(
  targetPath: string,
  label = 'Daemon socket',
): string {
  const resolvedPath = path.resolve(targetPath);
  assertTrustedRootPlannedDirectoryPath(path.dirname(resolvedPath), `${label} directory`);

  const stats = readLstat(resolvedPath);
  if (!stats) {
    return resolvedPath;
  }

  if (stats.isSymbolicLink()) {
    throw new Error(`${label} '${resolvedPath}' must not be a symlink`);
  }
  if (process.platform !== 'win32' && !stats.isSocket()) {
    throw new Error(`${label} '${resolvedPath}' must be a unix socket`);
  }

  assertRootOwned(stats, resolvedPath, label);
  return resolvedPath;
}

export function assertTrustedRootPlannedPrivateFilePath(
  targetPath: string,
  label = 'Private file',
): string {
  const resolvedPath = path.resolve(targetPath);
  assertTrustedRootPlannedDirectoryPath(path.dirname(resolvedPath), `${label} directory`);

  let stats: fs.Stats | null;
  try {
    stats = fs.lstatSync(resolvedPath);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'EACCES' || code === 'EPERM') {
      return resolvedPath;
    }
    throw error;
  }

  if (!stats) {
    return resolvedPath;
  }

  if (stats.isSymbolicLink()) {
    throw new Error(`${label} '${resolvedPath}' must not be a symlink`);
  }
  if (!stats.isFile()) {
    throw new Error(`${label} '${resolvedPath}' must be a regular file`);
  }

  assertPrivateFileStats(stats, resolvedPath, label);
  assertRootOwned(stats, resolvedPath, label);
  return resolvedPath;
}

export function assertTrustedRootDirectoryPath(targetPath: string, label: string): void {
  const normalizedPath = path.resolve(targetPath);
  assertNoSymlinkAncestorDirectories(normalizedPath, label);
  const targetStats = fs.lstatSync(normalizedPath);

  if (targetStats.isSymbolicLink()) {
    throw new Error(`${label} '${normalizedPath}' must not be a symlink`);
  }
  if (!targetStats.isDirectory()) {
    throw new Error(`${label} '${normalizedPath}' must be a directory`);
  }

  assertSecureDirectoryStats(targetStats, normalizedPath, label);
  assertRootOwned(targetStats, normalizedPath, label);

  for (const [index, currentPath] of ancestorDirectoryPaths(normalizedPath).entries()) {
    if (index === 0) {
      continue;
    }

    const stats = fs.lstatSync(currentPath);
    if (!stats.isDirectory()) {
      throw new Error(`${label} '${currentPath}' must be a directory`);
    }

    assertSecureDirectoryStats(stats, currentPath, label, {
      allowStickyGroupOtherWritable: index > 0,
    });
    assertRootOwned(stats, currentPath, label);
  }
}

export function assertTrustedRootPrivateFilePath(
  targetPath: string,
  label = 'Private file',
  options: { allowMissing?: boolean } = {},
): string {
  const resolvedPath = path.resolve(targetPath);
  assertTrustedRootDirectoryPath(path.dirname(resolvedPath), `${label} directory`);

  let stats: fs.Stats;
  try {
    stats = fs.lstatSync(resolvedPath);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' && options.allowMissing) {
      return resolvedPath;
    }
    if (code === 'ENOENT') {
      throw new Error(`${label} '${resolvedPath}' does not exist`);
    }
    if (code === 'EACCES' || code === 'EPERM') {
      throw new Error(`${label} '${resolvedPath}' is not accessible to the current process`);
    }
    throw error;
  }

  if (stats.isSymbolicLink()) {
    throw new Error(`${label} '${resolvedPath}' must not be a symlink`);
  }
  if (!stats.isFile()) {
    throw new Error(`${label} '${resolvedPath}' must be a regular file`);
  }

  assertPrivateFileStats(stats, resolvedPath, label);
  assertRootOwned(stats, resolvedPath, label);
  return resolvedPath;
}

export function assertTrustedPrivateFilePath(
  targetPath: string,
  label = 'Private file',
  options: { allowMissing?: boolean } = {},
): string {
  const resolvedPath = path.resolve(targetPath);
  assertTrustedDirectoryPath(path.dirname(resolvedPath), `${label} directory`);

  let stats: fs.Stats;
  try {
    stats = fs.lstatSync(resolvedPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT' && options.allowMissing) {
      return resolvedPath;
    }
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new Error(`${label} '${resolvedPath}' does not exist`);
    }
    throw error;
  }

  if (stats.isSymbolicLink()) {
    throw new Error(`${label} '${resolvedPath}' must not be a symlink`);
  }
  if (!stats.isFile()) {
    throw new Error(`${label} '${resolvedPath}' must be a regular file`);
  }

  assertPrivateFileStats(stats, resolvedPath, label);
  return resolvedPath;
}

export function readUtf8FileSecure(targetPath: string, label: string, maxBytes?: number): string {
  assertTrustedDirectoryPath(path.dirname(targetPath), `${label} parent directory`);
  const openFlags =
    process.platform === 'win32'
      ? fs.constants.O_RDONLY
      : fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW;
  const fd = fs.openSync(targetPath, openFlags);

  try {
    const stats = fs.fstatSync(fd);
    if (!stats.isFile()) {
      throw new Error(`${label} '${targetPath}' must be a regular file`);
    }
    assertPrivateFileStats(stats, targetPath, label);
    if (maxBytes !== undefined && stats.size > maxBytes) {
      throw new Error(`${label} '${targetPath}' must not exceed ${maxBytes} bytes`);
    }
    return fs.readFileSync(fd, 'utf8');
  } finally {
    fs.closeSync(fd);
  }
}

export function assertTrustedExecutablePath(targetPath: string): void {
  const normalizedPath = path.resolve(targetPath);
  assertNoSymlinkAncestorDirectories(normalizedPath, 'Rust binary');
  const stats = fs.lstatSync(normalizedPath);
  if (stats.isSymbolicLink()) {
    throw new Error(`Rust binary '${normalizedPath}' must not be a symlink`);
  }
  if (!stats.isFile()) {
    throw new Error(`Rust binary '${normalizedPath}' must be a regular file`);
  }

  if (runningAsRoot()) {
    assertRootOwned(stats, normalizedPath, 'Rust binary');
  } else {
    assertTrustedOwner(stats, normalizedPath, 'Rust binary');
  }
  if (process.platform !== 'win32' && (stats.mode & GROUP_OTHER_WRITE_MODE_MASK) !== 0) {
    throw new Error(`Rust binary '${normalizedPath}' must not be writable by group/other`);
  }

  const binaryDirectory = path.dirname(normalizedPath);
  if (!runningAsRoot()) {
    assertTrustedDirectoryPath(binaryDirectory, 'Rust binary directory');
    return;
  }

  for (const currentPath of ancestorDirectoryPaths(binaryDirectory)) {
    const currentStats = fs.lstatSync(currentPath);
    if (currentStats.isSymbolicLink()) {
      throw new Error(`Rust binary directory '${currentPath}' must not be a symlink`);
    }
    if (!currentStats.isDirectory()) {
      throw new Error(`Rust binary directory '${currentPath}' must be a directory`);
    }

    assertRootOwned(currentStats, currentPath, 'Rust binary directory');
    if (process.platform !== 'win32' && (currentStats.mode & GROUP_OTHER_WRITE_MODE_MASK) !== 0) {
      throw new Error(`Rust binary directory '${currentPath}' must not be writable by group/other`);
    }
  }
}
