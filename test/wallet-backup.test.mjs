import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const walletBackupModulePath = new URL('../src/lib/wallet-backup.ts', import.meta.url);
const walletBackupAdminModulePath = new URL('../src/lib/wallet-backup-admin.ts', import.meta.url);

const TEST_PRIVATE_KEY = '11'.repeat(32);
const TEST_VAULT_KEY_ID = '00000000-0000-0000-0000-000000000001';

function tempPath(prefix, suffix = '') {
  return path.join(
    os.tmpdir(),
    `${prefix}-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}${suffix}`,
  );
}

test('wallet backup encrypts and decrypts software wallet material', async () => {
  const walletBackup = await import(walletBackupModulePath.href + `?case=${Date.now()}-roundtrip`);

  const backup = walletBackup.createEncryptedWalletBackup({
    privateKeyHex: TEST_PRIVATE_KEY,
    sourceVaultKeyId: TEST_VAULT_KEY_ID,
    password: 'backup-secret',
  });
  const decrypted = walletBackup.decryptWalletBackup(backup, 'backup-secret');

  assert.equal(decrypted.privateKeyHex, TEST_PRIVATE_KEY);
  assert.equal(decrypted.sourceVaultKeyId, TEST_VAULT_KEY_ID);
  assert.match(decrypted.address, /^0x[0-9a-fA-F]{40}$/u);
  assert.match(decrypted.vaultPublicKey, /^0x[0-9a-fA-F]+$/u);
});

test('wallet backup rejects an incorrect password', async () => {
  const walletBackup = await import(
    walletBackupModulePath.href + `?case=${Date.now()}-wrong-password`
  );

  const backup = walletBackup.createEncryptedWalletBackup({
    privateKeyHex: TEST_PRIVATE_KEY,
    password: 'backup-secret',
  });

  assert.throws(
    () => walletBackup.decryptWalletBackup(backup, 'wrong-password'),
    /wallet backup password is incorrect or the backup file is corrupted/,
  );
});

test('wallet backup file verify round-trips encrypted metadata', async () => {
  const walletBackup = await import(
    walletBackupModulePath.href + `?case=${Date.now()}-verify-file`
  );

  const outputPath = tempPath('agentpay-wallet-backup', '.json');
  try {
    const backup = walletBackup.createEncryptedWalletBackup({
      privateKeyHex: TEST_PRIVATE_KEY,
      sourceVaultKeyId: TEST_VAULT_KEY_ID,
      password: 'backup-secret',
    });
    walletBackup.writeEncryptedWalletBackupFile(outputPath, backup);

    const verified = walletBackup.verifyWalletBackupFile(outputPath, 'backup-secret');
    assert.equal(verified.sourcePath, path.resolve(outputPath));
    assert.equal(verified.sourceVaultKeyId, TEST_VAULT_KEY_ID);
    assert.match(verified.address, /^0x[0-9a-fA-F]{40}$/u);
  } finally {
    fs.rmSync(outputPath, { force: true });
  }
});

test('defaultWalletBackupOutputPath uses the dedicated agentpay-backups directory', async () => {
  const walletBackup = await import(
    walletBackupModulePath.href + `?case=${Date.now()}-default-output-path`
  );

  const outputPath = walletBackup.defaultWalletBackupOutputPath(
    '0x1234567890abcdef1234567890abcdef12345678',
  );
  assert.match(outputPath, /agentpay-backups/u);
  assert.match(outputPath, /agentpay-wallet-backup-1234567890ab\.json$/u);
});

function writeLegacyWalletImportKeyFile(agentpayHome) {
  fs.mkdirSync(agentpayHome, { recursive: true, mode: 0o700 });
  const writtenPath = path.join(agentpayHome, `wallet-import-key-${process.pid}-${Date.now()}.key`);
  fs.writeFileSync(writtenPath, `${TEST_PRIVATE_KEY}\n`, { mode: 0o600, flag: 'wx' });
  return writtenPath;
}

test('legacy temporary wallet import key files under AGENTPAY_HOME are cleaned up', async () => {
  const walletBackup = await import(
    walletBackupModulePath.href + `?case=${Date.now()}-temporary-import-file`
  );
  const agentpayHome = tempPath('agentpay-home');
  const originalAgentPayHome = process.env.AGENTPAY_HOME;

  process.env.AGENTPAY_HOME = agentpayHome;
  try {
    const writtenPath = writeLegacyWalletImportKeyFile(agentpayHome);
    assert.equal(fs.readFileSync(writtenPath, 'utf8').trim(), TEST_PRIVATE_KEY);

    assert.deepEqual(walletBackup.cleanupTemporaryWalletImportKeyFile(writtenPath), {
      path: path.resolve(writtenPath),
      action: 'deleted',
    });
    assert.equal(fs.existsSync(writtenPath), false);
  } finally {
    if (originalAgentPayHome === undefined) {
      delete process.env.AGENTPAY_HOME;
    } else {
      process.env.AGENTPAY_HOME = originalAgentPayHome;
    }
    fs.rmSync(agentpayHome, { recursive: true, force: true });
  }
});

test('temporary wallet import key cleanup reports failures without throwing', async () => {
  const walletBackup = await import(
    walletBackupModulePath.href + `?case=${Date.now()}-temporary-import-file-cleanup-failure`
  );
  const agentpayHome = tempPath('agentpay-home');
  const originalAgentPayHome = process.env.AGENTPAY_HOME;

  process.env.AGENTPAY_HOME = agentpayHome;
  try {
    const writtenPath = writeLegacyWalletImportKeyFile(agentpayHome);
    const originalRmSync = fs.rmSync;
    fs.rmSync = (targetPath, ...args) => {
      if (path.resolve(String(targetPath)) === path.resolve(writtenPath)) {
        throw new Error('delete failed');
      }
      return originalRmSync.call(fs, targetPath, ...args);
    };

    try {
      const result = walletBackup.cleanupTemporaryWalletImportKeyFile(writtenPath);
      assert.equal(result.path, path.resolve(writtenPath));
      assert.equal(result.action, 'failed');
      assert.match(result.error ?? '', /delete failed/u);
    } finally {
      fs.rmSync = originalRmSync;
    }

    assert.equal(fs.existsSync(writtenPath), true);
  } finally {
    if (originalAgentPayHome === undefined) {
      delete process.env.AGENTPAY_HOME;
    } else {
      process.env.AGENTPAY_HOME = originalAgentPayHome;
    }
    fs.rmSync(agentpayHome, { recursive: true, force: true });
  }
});

test('exportEncryptedWalletBackup pulls the private key from rust admin JSON and writes an encrypted backup', async () => {
  const walletBackup = await import(
    walletBackupModulePath.href + `?case=${Date.now()}-export-admin-verify`
  );
  const walletBackupAdmin = await import(
    walletBackupAdminModulePath.href + `?case=${Date.now()}-export-admin`
  );

  const outputPath = tempPath('agentpay-wallet-export', '.json');
  try {
    const exported = await walletBackupAdmin.exportEncryptedWalletBackup(
      {
        daemonSocket: '/Library/AgentPay/run/daemon.sock',
        vaultPassword: 'vault-secret',
        backupPassword: 'backup-secret',
        outputPath,
      },
      {
        readConfig: () => ({ wallet: { vaultKeyId: TEST_VAULT_KEY_ID } }),
        resolveWalletProfile: () => ({ vaultKeyId: TEST_VAULT_KEY_ID }),
        runRustBinaryJson: async (_binary, args, _config, options) => {
          const nonce = args.indexOf('--vault-key-id');
          assert.ok(nonce >= 0);
          assert.equal(args[nonce + 1], TEST_VAULT_KEY_ID);
          assert.equal(options?.stdin, 'vault-secret\n');
          assert.equal(options?.preSuppliedSecretStdin, 'vaultPassword');
          assert.equal(
            options?.sensitiveStdout,
            true,
            'private-key export stdout must never reach error messages',
          );
          return {
            vault_key_id: TEST_VAULT_KEY_ID,
            vault_private_key: TEST_PRIVATE_KEY,
          };
        },
      },
    );

    assert.equal(exported.outputPath, path.resolve(outputPath));
    const verified = walletBackup.verifyWalletBackupFile(outputPath, 'backup-secret');
    assert.equal(verified.address, exported.address);
    assert.equal(verified.sourceVaultKeyId, TEST_VAULT_KEY_ID);
  } finally {
    fs.rmSync(outputPath, { force: true });
  }
});

function writeBackupJson(backup) {
  const backupPath = tempPath('agentpay-wallet-backup', '.json');
  fs.writeFileSync(backupPath, `${JSON.stringify(backup, null, 2)}\n`, { mode: 0o600 });
  return backupPath;
}

function createLegacyV1Backup(wallet, password) {
  // Mirrors the format written by CLIs before v2: scrypt N=2^15 and no GCM AAD.
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const n = 1 << 15;
  const key = crypto.scryptSync(password, salt, 32, { N: n, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  const createdAt = '2025-01-01T00:00:00.000Z';
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = JSON.stringify({
    createdAt,
    privateKeyHex: TEST_PRIVATE_KEY,
    address: wallet.address,
    vaultPublicKey: wallet.vaultPublicKey,
    sourceVaultKeyId: wallet.sourceVaultKeyId,
  });
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    kind: 'agentpay-wallet-backup',
    version: 1,
    createdAt,
    wallet,
    encryption: {
      algorithm: 'aes-256-gcm',
      kdf: 'scrypt',
      saltHex: salt.toString('hex'),
      ivHex: iv.toString('hex'),
      authTagHex: cipher.getAuthTag().toString('hex'),
      n,
      r: 8,
      p: 1,
    },
    ciphertextHex: ciphertext.toString('hex'),
  };
}

test('wallet backup v2 uses scrypt N=2^18 and binds header metadata as GCM AAD', async () => {
  const walletBackup = await import(walletBackupModulePath.href + `?case=${Date.now()}-v2-aad`);

  const backup = walletBackup.createEncryptedWalletBackup({
    privateKeyHex: TEST_PRIVATE_KEY,
    sourceVaultKeyId: TEST_VAULT_KEY_ID,
    password: 'backup-secret',
  });
  assert.equal(backup.version, 2);
  assert.equal(backup.encryption.n, 1 << 18);
  assert.equal(backup.encryption.r, 8);
  assert.equal(backup.encryption.p, 1);

  // Editing header-only metadata (not covered by the plaintext address checks) must break the tag.
  const tampered = structuredClone(backup);
  tampered.createdAt = '2001-01-01T00:00:00.000Z';
  assert.throws(
    () => walletBackup.decryptWalletBackup(tampered, 'backup-secret'),
    /wallet backup password is incorrect or the backup file is corrupted/u,
  );

  // Downgrading the version label to skip AAD verification must also fail.
  const downgraded = structuredClone(backup);
  downgraded.version = 1;
  assert.throws(
    () => walletBackup.decryptWalletBackup(downgraded, 'backup-secret'),
    /wallet backup password is incorrect or the backup file is corrupted/u,
  );
});

test('wallet backup still reads and verifies legacy v1 files', async () => {
  const walletBackup = await import(walletBackupModulePath.href + `?case=${Date.now()}-v1-compat`);
  const current = walletBackup.createEncryptedWalletBackup({
    privateKeyHex: TEST_PRIVATE_KEY,
    sourceVaultKeyId: TEST_VAULT_KEY_ID,
    password: 'backup-secret',
  });
  const backupPath = writeBackupJson(createLegacyV1Backup(current.wallet, 'backup-secret'));

  try {
    const parsed = walletBackup.readWalletBackupFile(backupPath);
    assert.equal(parsed.version, 1);
    assert.equal(parsed.encryption.n, 1 << 15);
    const summary = walletBackup.verifyWalletBackupFile(backupPath, 'backup-secret');
    assert.equal(summary.address, current.wallet.address);
    assert.equal(
      walletBackup.decryptWalletBackup(parsed, 'backup-secret').privateKeyHex,
      TEST_PRIVATE_KEY,
    );
  } finally {
    fs.rmSync(backupPath, { force: true });
  }
});

test('wallet backup rejects unsupported versions and out-of-range scrypt parameters on read', async () => {
  const walletBackup = await import(
    walletBackupModulePath.href + `?case=${Date.now()}-param-bounds`
  );
  const backup = walletBackup.createEncryptedWalletBackup({
    privateKeyHex: TEST_PRIVATE_KEY,
    password: 'backup-secret',
  });

  const cases = [
    [{ version: 3 }, /wallet backup version must be 1 or 2/u],
    [
      { encryption: { ...backup.encryption, n: 1 << 21 } },
      /encryption parameters are unsupported/u,
    ],
    [
      { encryption: { ...backup.encryption, n: 1 << 14 } },
      /encryption parameters are unsupported/u,
    ],
    [
      { encryption: { ...backup.encryption, n: (1 << 18) + 1 } },
      /encryption parameters are unsupported/u,
    ],
    [{ encryption: { ...backup.encryption, r: 16 } }, /encryption parameters are unsupported/u],
    [{ encryption: { ...backup.encryption, p: 4 } }, /encryption parameters are unsupported/u],
  ];
  for (const [overrides, pattern] of cases) {
    const backupPath = writeBackupJson({ ...backup, ...overrides });
    try {
      assert.throws(() => walletBackup.readWalletBackupFile(backupPath), pattern);
    } finally {
      fs.rmSync(backupPath, { force: true });
    }
  }
});

test('wallet backup module no longer writes plaintext import key files', async () => {
  const walletBackup = await import(walletBackupModulePath.href + `?case=${Date.now()}-no-writer`);
  // Restores hand the decrypted key to the Rust admin over an fd 3 pipe; only the legacy
  // cleanup/sweep helpers remain for files left behind by older releases.
  assert.equal(walletBackup.writeTemporaryWalletImportKeyFile, undefined);
  assert.equal(walletBackup.registerTemporaryWalletImportKeyCleanup, undefined);
  assert.equal(typeof walletBackup.cleanupTemporaryWalletImportKeyFile, 'function');
  assert.equal(typeof walletBackup.sweepStaleTemporaryWalletImportKeyFiles, 'function');
});

test('sweepStaleTemporaryWalletImportKeyFiles removes keys from dead setup runs only', async () => {
  const walletBackup = await import(
    walletBackupModulePath.href + `?case=${Date.now()}-sweep-stale`
  );
  const agentpayHome = tempPath('agentpay-home-sweep');
  fs.mkdirSync(agentpayHome, { recursive: true, mode: 0o700 });

  try {
    const stalePath = path.join(agentpayHome, 'wallet-import-key-111-1700000000000.key');
    const livePath = path.join(agentpayHome, 'wallet-import-key-222-1700000000000.key');
    const ownPath = path.join(agentpayHome, 'wallet-import-key-333-1700000000000.key');
    const unrelatedPath = path.join(agentpayHome, 'bootstrap-1-2.json');
    for (const target of [stalePath, livePath, ownPath, unrelatedPath]) {
      fs.writeFileSync(target, 'secret', { mode: 0o600 });
    }

    const results = walletBackup.sweepStaleTemporaryWalletImportKeyFiles({
      resolveAgentPayHome: () => agentpayHome,
      isProcessAlive: (pid) => pid === 222,
      currentPid: 333,
    });

    const byName = Object.fromEntries(
      results.map((result) => [path.basename(result.path), result.action]),
    );
    assert.deepEqual(byName, {
      'wallet-import-key-111-1700000000000.key': 'deleted',
      'wallet-import-key-222-1700000000000.key': 'skipped',
      'wallet-import-key-333-1700000000000.key': 'skipped',
    });
    assert.equal(fs.existsSync(stalePath), false);
    assert.equal(fs.existsSync(livePath), true);
    assert.equal(fs.existsSync(ownPath), true);
    assert.equal(fs.existsSync(unrelatedPath), true);

    assert.deepEqual(
      walletBackup.sweepStaleTemporaryWalletImportKeyFiles({
        resolveAgentPayHome: () => path.join(agentpayHome, 'missing'),
      }),
      [],
    );
  } finally {
    fs.rmSync(agentpayHome, { recursive: true, force: true });
  }
});
