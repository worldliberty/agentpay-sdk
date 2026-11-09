/** Small private-file helpers: 0700 directories, 0600 files, atomic replace, no symlinks. */
import { randomBytes } from 'node:crypto';
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join } from 'node:path';

export function ensurePrivateDir(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const info = lstatSync(path);
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error(`${path} must be a directory, not a symlink`);
  }
  if ((info.mode & 0o077) !== 0) {
    chmodSync(path, 0o700);
  }
}

/** Reads a file this user owns, refusing symlinks. Returns `null` when it does not exist. */
export function readPrivateFile(path: string): string | null {
  let info: ReturnType<typeof lstatSync>;
  try {
    info = lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    throw error;
  }
  if (info.isSymbolicLink() || !info.isFile()) {
    throw new Error(`${path} must be a regular file, not a symlink`);
  }
  return readFileSync(path, 'utf8');
}

/** Writes `contents` to `path` with `mode` through a temporary file and a rename. */
export function writePrivateFile(path: string, contents: string, mode = 0o600): void {
  ensurePrivateDir(dirname(path));
  const temp = join(dirname(path), `.${basename(path)}.${randomBytes(6).toString('hex')}.tmp`);
  writeFileSync(temp, contents, { mode, flag: 'wx' });
  try {
    renameSync(temp, path);
  } catch (error) {
    unlinkSync(temp);
    throw error;
  }
}

/** Writes a new file that must not exist yet (`wx`), with `mode`. */
export function writeNewFile(path: string, contents: string, mode = 0o600): void {
  writeFileSync(path, contents, { mode, flag: 'wx' });
}

export function removeFile(path: string): boolean {
  try {
    unlinkSync(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return false;
    }
    throw error;
  }
}
