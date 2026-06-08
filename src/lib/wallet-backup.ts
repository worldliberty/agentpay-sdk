import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { privateKeyToAccount } from 'viem/accounts';
import { ensureAgentPayHome } from '../../packages/config/src/index.js';
import { promptHiddenTty } from './hidden-tty-prompt.js';

const MAX_SECRET_BYTES = 16 * 1024;
const MAX_BACKUP_FILE_BYTES = 256 * 1024;
const PRIVATE_FILE_MODE = 0o600;
const SCRYPT_N = 1 << 15;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_MAXMEM = 64 * 1024 * 1024;
const SCRYPT_KEYLEN = 32;
const GCM_IV_BYTES = 12;
const SCRYPT_SALT_BYTES = 16;
const BACKUP_KIND = 'agentpay-wallet-backup';
const BACKUP_VERSION = 1;

export interface WalletBackupFile {
  kind: 'agentpay-wallet-backup';
  version: 1;
  createdAt: string;
  wallet: {
    address: string;
    vaultPublicKey: string;
    sourceVaultKeyId?: string;
  };
  encryption: {
    algorithm: 'aes-256-gcm';
    kdf: 'scrypt';
    saltHex: string;
    ivHex: string;
    authTagHex: string;
    n: number;
    r: number;
    p: number;
  };
  ciphertextHex: string;
}

export interface WalletBackupMaterial {
  privateKeyHex: string;
  address: string;
  vaultPublicKey: string;
  sourceVaultKeyId?: string;
}

export interface WalletBackupSummary {
  sourcePath?: string;
  createdAt: string;
  address: string;
  vaultPublicKey: string;
  sourceVaultKeyId?: string;
}

export interface ResolveWalletBackupPasswordOptions {
  backupPassword?: string;
  backupPasswordStdin?: boolean;
  nonInteractive?: boolean;
  confirm?: boolean;
}

export interface ResolveWalletBackupPasswordDeps {
  env?: NodeJS.ProcessEnv;
  promptHidden?: (query: string, label: string, nonInteractiveError: string) => Promise<string>;
  readTrimmedStdin?: (label: string) => Promise<string>;
}

export interface TemporaryWalletImportKeyCleanupResult {
  path: string | null;
  action: 'deleted' | 'skipped' | 'failed';
  error?: string;
}

function renderError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function validateSecret(value: string, label: string): string {
  if (Buffer.byteLength(value, 'utf8') > MAX_SECRET_BYTES) {
    throw new Error(`${label} must not exceed ${MAX_SECRET_BYTES} bytes`);
  }
  if (!value.trim()) {
    throw new Error(`${label} must not be empty or whitespace`);
  }
  return value;
}

function normalizePrivateKeyHex(value: string, label = 'private key'): `0x${string}` {
  const normalized = value.trim().toLowerCase();
  const stripped = normalized.startsWith('0x') ? normalized.slice(2) : normalized;
  if (!/^[0-9a-f]{64}$/u.test(stripped)) {
    throw new Error(`${label} must be a 32-byte hex string`);
  }
  return `0x${stripped}`;
}

function resolveMaterialFromPrivateKey(
  privateKeyHex: string,
  sourceVaultKeyId?: string,
): WalletBackupMaterial {
  const normalizedPrivateKey = normalizePrivateKeyHex(privateKeyHex);
  const account = privateKeyToAccount(normalizedPrivateKey);
  return {
    privateKeyHex: normalizedPrivateKey.slice(2),
    address: account.address,
    vaultPublicKey: account.publicKey,
    sourceVaultKeyId: sourceVaultKeyId?.trim() || undefined,
  };
}

function deriveKey(
  password: string,
  salt: Buffer,
  params: { n: number; r: number; p: number },
): Buffer {
  return crypto.scryptSync(password, salt, SCRYPT_KEYLEN, {
    N: params.n,
    r: params.r,
    p: params.p,
    maxmem: SCRYPT_MAXMEM,
  });
}

function readHexField(
  record: Record<string, unknown>,
  fieldName: string,
  label: string,
  expectedBytes?: number,
): string {
  const value = record[fieldName];
  if (typeof value !== 'string' || !/^[0-9a-f]+$/iu.test(value)) {
    throw new Error(`${label} must be a hex string in wallet backup`);
  }
  const normalized = value.toLowerCase();
  if (normalized.length % 2 !== 0) {
    throw new Error(`${label} must contain an even number of hex characters in wallet backup`);
  }
  if (expectedBytes !== undefined && normalized.length !== expectedBytes * 2) {
    throw new Error(`${label} must be ${expectedBytes} bytes in wallet backup`);
  }
  return normalized;
}

function assertRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function readOptionalString(
  record: Record<string, unknown>,
  fieldName: string,
): string | undefined {
  const value = record[fieldName];
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== 'string') {
    throw new Error(`${fieldName} must be a string in wallet backup`);
  }
  const normalized = value.trim();
  return normalized || undefined;
}

function parseWalletBackupFileContents(raw: string, sourcePath?: string): WalletBackupFile {
  const payload = assertRecord(JSON.parse(raw), 'wallet backup');
  if (payload.kind !== BACKUP_KIND) {
    throw new Error('wallet backup kind is invalid');
  }
  if (payload.version !== BACKUP_VERSION) {
    throw new Error(`wallet backup version must be ${BACKUP_VERSION}`);
  }
  if (typeof payload.createdAt !== 'string' || Number.isNaN(Date.parse(payload.createdAt))) {
    throw new Error('wallet backup createdAt must be a valid ISO-8601 string');
  }

  const wallet = assertRecord(payload.wallet, 'wallet backup wallet');
  const address = readOptionalString(wallet, 'address');
  const vaultPublicKey = readOptionalString(wallet, 'vaultPublicKey');
  if (!address) {
    throw new Error('wallet backup wallet.address is required');
  }
  if (!vaultPublicKey) {
    throw new Error('wallet backup wallet.vaultPublicKey is required');
  }

  const encryption = assertRecord(payload.encryption, 'wallet backup encryption');
  if (encryption.algorithm !== 'aes-256-gcm') {
    throw new Error('wallet backup encryption.algorithm must be aes-256-gcm');
  }
  if (encryption.kdf !== 'scrypt') {
    throw new Error('wallet backup encryption.kdf must be scrypt');
  }

  const n = encryption.n;
  const r = encryption.r;
  const p = encryption.p;
  if (n !== SCRYPT_N || r !== SCRYPT_R || p !== SCRYPT_P) {
    throw new Error('wallet backup encryption parameters are unsupported');
  }

  const backup: WalletBackupFile = {
    kind: BACKUP_KIND,
    version: BACKUP_VERSION,
    createdAt: payload.createdAt,
    wallet: {
      address,
      vaultPublicKey,
      sourceVaultKeyId: readOptionalString(wallet, 'sourceVaultKeyId'),
    },
    encryption: {
      algorithm: 'aes-256-gcm',
      kdf: 'scrypt',
      saltHex: readHexField(
        encryption,
        'saltHex',
        'wallet backup encryption.saltHex',
        SCRYPT_SALT_BYTES,
      ),
      ivHex: readHexField(encryption, 'ivHex', 'wallet backup encryption.ivHex', GCM_IV_BYTES),
      authTagHex: readHexField(encryption, 'authTagHex', 'wallet backup encryption.authTagHex', 16),
      n: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P,
    },
    ciphertextHex: readHexField(payload, 'ciphertextHex', 'wallet backup ciphertextHex'),
  };

  if (sourcePath) {
    return { ...backup };
  }
  return backup;
}

function parseBackupPlaintext(raw: string): WalletBackupMaterial & { createdAt: string } {
  const payload = assertRecord(JSON.parse(raw), 'wallet backup plaintext');
  const privateKeyHex = readOptionalString(payload, 'privateKeyHex');
  const address = readOptionalString(payload, 'address');
  const vaultPublicKey = readOptionalString(payload, 'vaultPublicKey');
  const createdAt = readOptionalString(payload, 'createdAt');
  if (!privateKeyHex) {
    throw new Error('wallet backup privateKeyHex is required');
  }
  if (!address) {
    throw new Error('wallet backup address is required');
  }
  if (!vaultPublicKey) {
    throw new Error('wallet backup vaultPublicKey is required');
  }
  if (!createdAt || Number.isNaN(Date.parse(createdAt))) {
    throw new Error('wallet backup createdAt is required');
  }

  const resolved = resolveMaterialFromPrivateKey(
    privateKeyHex,
    readOptionalString(payload, 'sourceVaultKeyId'),
  );
  if (resolved.address.toLowerCase() !== address.toLowerCase()) {
    throw new Error('wallet backup address does not match the encrypted private key');
  }
  if (resolved.vaultPublicKey.toLowerCase() !== vaultPublicKey.toLowerCase()) {
    throw new Error('wallet backup vaultPublicKey does not match the encrypted private key');
  }

  return {
    ...resolved,
    createdAt,
  };
}

function writeBackupFile(targetPath: string, contents: string, overwrite = false): string {
  const resolvedPath = path.resolve(targetPath.trim());
  if (!path.basename(resolvedPath).trim()) {
    throw new Error('wallet backup output path is required');
  }

  const parent = path.dirname(resolvedPath);
  fs.mkdirSync(parent, { recursive: true });

  const existing = safeLstat(resolvedPath);
  if (existing?.isSymbolicLink()) {
    throw new Error(`wallet backup output '${resolvedPath}' must not be a symlink`);
  }
  if (existing && !existing.isFile()) {
    throw new Error(`wallet backup output '${resolvedPath}' must be a regular file`);
  }
  if (existing && !overwrite) {
    throw new Error(`wallet backup output '${resolvedPath}' already exists; choose a new path`);
  }

  const tempPath = path.join(
    parent,
    `.${path.basename(resolvedPath)}.tmp-${process.pid}-${Date.now()}`,
  );
  try {
    fs.writeFileSync(tempPath, contents, { encoding: 'utf8', mode: PRIVATE_FILE_MODE, flag: 'wx' });
    try {
      fs.chmodSync(tempPath, PRIVATE_FILE_MODE);
    } catch {}
    fs.renameSync(tempPath, resolvedPath);
    try {
      fs.chmodSync(resolvedPath, PRIVATE_FILE_MODE);
    } catch {}
  } finally {
    try {
      if (fs.existsSync(tempPath)) {
        fs.rmSync(tempPath, { force: true });
      }
    } catch {}
  }

  return resolvedPath;
}

function safeLstat(targetPath: string): fs.Stats | null {
  try {
    return fs.lstatSync(targetPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

async function readTrimmedStdin(label: string): Promise<string> {
  process.stdin.setEncoding('utf8');
  let raw = '';
  for await (const chunk of process.stdin) {
    raw += chunk;
    if (Buffer.byteLength(raw, 'utf8') > MAX_SECRET_BYTES) {
      throw new Error(`${label} must not exceed ${MAX_SECRET_BYTES} bytes`);
    }
  }
  return validateSecret(raw.replace(/[\r\n]+$/u, ''), label);
}

async function promptHidden(
  query: string,
  label: string,
  nonInteractiveError: string,
): Promise<string> {
  const answer = await promptHiddenTty(query, nonInteractiveError);
  return validateSecret(answer, label);
}

export function defaultWalletBackupOutputPath(address: string): string {
  const compactAddress = address.trim().toLowerCase().replace(/^0x/u, '');
  return path.join(
    os.homedir(),
    'agentpay-backups',
    `agentpay-wallet-backup-${compactAddress.slice(0, 12)}.json`,
  );
}

export function createEncryptedWalletBackup(input: {
  privateKeyHex: string;
  sourceVaultKeyId?: string;
  password: string;
}): WalletBackupFile {
  const material = resolveMaterialFromPrivateKey(input.privateKeyHex, input.sourceVaultKeyId);
  const createdAt = new Date().toISOString();
  const salt = crypto.randomBytes(SCRYPT_SALT_BYTES);
  const iv = crypto.randomBytes(GCM_IV_BYTES);
  const key = deriveKey(validateSecret(input.password, 'wallet backup password'), salt, {
    n: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = JSON.stringify({
    createdAt,
    privateKeyHex: material.privateKeyHex,
    address: material.address,
    vaultPublicKey: material.vaultPublicKey,
    ...(material.sourceVaultKeyId ? { sourceVaultKeyId: material.sourceVaultKeyId } : {}),
  });
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    kind: BACKUP_KIND,
    version: BACKUP_VERSION,
    createdAt,
    wallet: {
      address: material.address,
      vaultPublicKey: material.vaultPublicKey,
      ...(material.sourceVaultKeyId ? { sourceVaultKeyId: material.sourceVaultKeyId } : {}),
    },
    encryption: {
      algorithm: 'aes-256-gcm',
      kdf: 'scrypt',
      saltHex: salt.toString('hex'),
      ivHex: iv.toString('hex'),
      authTagHex: authTag.toString('hex'),
      n: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P,
    },
    ciphertextHex: ciphertext.toString('hex'),
  };
}

export function decryptWalletBackup(
  backup: WalletBackupFile,
  password: string,
): WalletBackupMaterial & { createdAt: string } {
  const key = deriveKey(
    validateSecret(password, 'wallet backup password'),
    Buffer.from(backup.encryption.saltHex, 'hex'),
    {
      n: backup.encryption.n,
      r: backup.encryption.r,
      p: backup.encryption.p,
    },
  );
  try {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(backup.encryption.ivHex, 'hex'),
    );
    decipher.setAuthTag(Buffer.from(backup.encryption.authTagHex, 'hex'));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(backup.ciphertextHex, 'hex')),
      decipher.final(),
    ]).toString('utf8');
    const decrypted = parseBackupPlaintext(plaintext);
    if (decrypted.address.toLowerCase() !== backup.wallet.address.toLowerCase()) {
      throw new Error('wallet backup metadata address does not match the encrypted payload');
    }
    if (decrypted.vaultPublicKey.toLowerCase() !== backup.wallet.vaultPublicKey.toLowerCase()) {
      throw new Error('wallet backup metadata vaultPublicKey does not match the encrypted payload');
    }
    if ((decrypted.sourceVaultKeyId ?? '') !== (backup.wallet.sourceVaultKeyId ?? '')) {
      throw new Error(
        'wallet backup metadata sourceVaultKeyId does not match the encrypted payload',
      );
    }
    return decrypted;
  } catch (error) {
    if (error instanceof Error && error.message.includes('wallet backup')) {
      throw error;
    }
    throw new Error('wallet backup password is incorrect or the backup file is corrupted');
  }
}

export function writeEncryptedWalletBackupFile(
  targetPath: string,
  backup: WalletBackupFile,
  options: { overwrite?: boolean } = {},
): string {
  return writeBackupFile(
    targetPath,
    `${JSON.stringify(backup, null, 2)}\n`,
    options.overwrite ?? false,
  );
}

export function readWalletBackupFile(inputPath: string): WalletBackupFile & { sourcePath: string } {
  const resolvedPath = path.resolve(inputPath.trim());
  const stats = safeLstat(resolvedPath);
  if (!stats) {
    throw new Error(`wallet backup '${resolvedPath}' does not exist`);
  }
  if (stats.isSymbolicLink()) {
    throw new Error(`wallet backup '${resolvedPath}' must not be a symlink`);
  }
  if (!stats.isFile()) {
    throw new Error(`wallet backup '${resolvedPath}' must be a regular file`);
  }
  if (stats.size > MAX_BACKUP_FILE_BYTES) {
    throw new Error(
      `wallet backup '${resolvedPath}' must not exceed ${MAX_BACKUP_FILE_BYTES} bytes`,
    );
  }
  const raw = fs.readFileSync(resolvedPath, 'utf8');
  return {
    ...parseWalletBackupFileContents(raw, resolvedPath),
    sourcePath: resolvedPath,
  };
}

export function verifyWalletBackupFile(inputPath: string, password: string): WalletBackupSummary {
  const backup = readWalletBackupFile(inputPath);
  const decrypted = decryptWalletBackup(backup, password);
  return {
    sourcePath: backup.sourcePath,
    createdAt: decrypted.createdAt,
    address: decrypted.address,
    vaultPublicKey: decrypted.vaultPublicKey,
    sourceVaultKeyId: decrypted.sourceVaultKeyId,
  };
}

export async function resolveWalletBackupPassword(
  options: ResolveWalletBackupPasswordOptions,
  deps: ResolveWalletBackupPasswordDeps = {},
): Promise<string> {
  const env = deps.env ?? process.env;
  const prompt = deps.promptHidden ?? promptHidden;
  const readFromStdin = deps.readTrimmedStdin ?? readTrimmedStdin;
  if (options.backupPassword && options.backupPasswordStdin) {
    throw new Error('--backup-password conflicts with --backup-password-stdin');
  }
  if (options.backupPassword) {
    validateSecret(options.backupPassword, 'wallet backup password');
    throw new Error(
      'insecure --backup-password is disabled; use --backup-password-stdin or a local TTY prompt',
    );
  }
  if (Object.hasOwn(env, 'AGENTPAY_WALLET_BACKUP_PASSWORD')) {
    validateSecret(env.AGENTPAY_WALLET_BACKUP_PASSWORD ?? '', 'wallet backup password');
    throw new Error(
      'AGENTPAY_WALLET_BACKUP_PASSWORD is disabled for security; use --backup-password-stdin or a local TTY prompt',
    );
  }
  if (options.backupPasswordStdin) {
    return readFromStdin('wallet backup password');
  }
  if (options.nonInteractive) {
    throw new Error(
      'wallet backup password is required in non-interactive mode; use --backup-password-stdin',
    );
  }

  const first = await prompt(
    'Wallet backup password (input hidden; this encrypts the offline recovery file): ',
    'wallet backup password',
    'wallet backup password is required; rerun on a local TTY or use --backup-password-stdin',
  );
  if (options.confirm === false) {
    return first;
  }
  const second = await prompt(
    'Confirm wallet backup password: ',
    'wallet backup password confirmation',
    'wallet backup password confirmation is required; rerun on a local TTY or use --backup-password-stdin',
  );
  if (first !== second) {
    throw new Error('wallet backup passwords did not match');
  }
  return first;
}

export function writeTemporaryWalletImportKeyFile(privateKeyHex: string): string {
  const agentpayHome = ensureAgentPayHome();
  const resolvedPath = path.join(
    agentpayHome,
    `wallet-import-key-${process.pid}-${Date.now()}.key`,
  );
  fs.writeFileSync(
    resolvedPath,
    `${resolveMaterialFromPrivateKey(privateKeyHex).privateKeyHex}\n`,
    {
      encoding: 'utf8',
      mode: PRIVATE_FILE_MODE,
      flag: 'wx',
    },
  );
  try {
    fs.chmodSync(resolvedPath, PRIVATE_FILE_MODE);
  } catch {}
  return resolvedPath;
}

export function cleanupTemporaryWalletImportKeyFile(
  inputPath: string | null | undefined,
): TemporaryWalletImportKeyCleanupResult {
  if (!inputPath) {
    return {
      path: null,
      action: 'skipped',
    };
  }
  const resolvedPath = path.resolve(inputPath);
  try {
    fs.rmSync(resolvedPath, { force: true });
    return {
      path: resolvedPath,
      action: 'deleted',
    };
  } catch (error) {
    return {
      path: resolvedPath,
      action: 'failed',
      error: `temporary wallet import key file '${resolvedPath}' cleanup failed: ${renderError(error)}`,
    };
  }
}
