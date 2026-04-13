import fs from 'node:fs';
import path from 'node:path';
import { ensureAgentPayHome, resolveAgentPayHome } from '../../packages/config/src/index.js';
import { assertValidAgentAuthToken } from './agent-auth-token.js';
import { assertTrustedDirectoryPath, assertTrustedPrivateFilePath, readUtf8FileSecure } from './fs-trust.js';
import { assertValidAgentKeyId } from './keychain.js';

const AGENT_AUTH_DIRECTORY_NAME = 'agent-auth';
const PRIVATE_DIR_MODE = 0o700;
const PRIVATE_FILE_MODE = 0o600;
const MAX_AGENT_AUTH_FILE_BYTES = 16 * 1024;

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

function tightenPermissions(targetPath: string, mode: number): void {
  try {
    fs.chmodSync(targetPath, mode);
  } catch {}
}

function ensureAgentAuthTokenDirectory(): string {
  const agentpayHome = ensureAgentPayHome();
  const directoryPath = path.join(agentpayHome, AGENT_AUTH_DIRECTORY_NAME);
  const stats = readLstat(directoryPath);
  if (stats && !stats.isDirectory()) {
    throw new Error(`agent auth token directory '${directoryPath}' must be a directory`);
  }
  if (!stats) {
    fs.mkdirSync(directoryPath, { recursive: true, mode: PRIVATE_DIR_MODE });
  }
  tightenPermissions(directoryPath, PRIVATE_DIR_MODE);
  assertTrustedDirectoryPath(directoryPath, 'agent auth token directory');
  return directoryPath;
}

export function resolveAgentAuthTokenFileDirectory(): string {
  return path.join(resolveAgentPayHome(), AGENT_AUTH_DIRECTORY_NAME);
}

export function resolveAgentAuthTokenFilePath(agentKeyId: string): string {
  return path.join(
    resolveAgentAuthTokenFileDirectory(),
    `${assertValidAgentKeyId(agentKeyId)}.token`,
  );
}

export function storeAgentAuthTokenInFile(agentKeyId: string, token: string): string {
  const normalizedAgentKeyId = assertValidAgentKeyId(agentKeyId);
  const normalizedToken = assertValidAgentAuthToken(token, 'agentAuthToken');
  const directoryPath = ensureAgentAuthTokenDirectory();
  const targetPath = path.join(directoryPath, `${normalizedAgentKeyId}.token`);
  const tempPath = `${targetPath}.${process.pid}.${Date.now()}.tmp`;

  try {
    fs.writeFileSync(tempPath, normalizedToken, {
      encoding: 'utf8',
      mode: PRIVATE_FILE_MODE,
      flag: 'wx',
    });
    tightenPermissions(tempPath, PRIVATE_FILE_MODE);
    fs.renameSync(tempPath, targetPath);
    tightenPermissions(targetPath, PRIVATE_FILE_MODE);
    assertTrustedPrivateFilePath(targetPath, 'agent auth token file');
    return targetPath;
  } catch (error) {
    fs.rmSync(tempPath, { force: true });
    throw error;
  }
}

export function readAgentAuthTokenFromFile(agentKeyId: string): string | null {
  const targetPath = resolveAgentAuthTokenFilePath(agentKeyId);
  try {
    return assertValidAgentAuthToken(
      readUtf8FileSecure(targetPath, 'agent auth token file', MAX_AGENT_AUTH_FILE_BYTES),
      'agentAuthToken',
    );
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    if (error instanceof Error && error.message.includes('does not exist')) {
      return null;
    }
    throw error;
  }
}

export function deleteAgentAuthTokenFromFile(agentKeyId: string): boolean {
  const targetPath = resolveAgentAuthTokenFilePath(agentKeyId);
  try {
    assertTrustedPrivateFilePath(targetPath, 'agent auth token file');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return false;
    }
    if (error instanceof Error && error.message.includes('does not exist')) {
      return false;
    }
    throw error;
  }

  fs.rmSync(targetPath, { force: true });
  return true;
}

export function hasAgentAuthTokenInFile(agentKeyId: string): boolean {
  return readAgentAuthTokenFromFile(agentKeyId) !== null;
}
