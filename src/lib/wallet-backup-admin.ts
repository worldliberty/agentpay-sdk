import type { WlfiConfig } from '../../packages/config/src/index.js';
import { readConfig } from '../../packages/config/src/index.js';
import { type RustBinaryName, runRustBinaryJson } from './rust.js';
import {
  createEncryptedWalletBackup,
  type WalletBackupSummary,
  writeEncryptedWalletBackupFile,
} from './wallet-backup.js';
import { resolveWalletProfile } from './wallet-profile.js';

interface ExportVaultPrivateKeyAdminOutput {
  vault_key_id: string;
  vault_private_key: string;
}

export interface ExportEncryptedWalletBackupOptions {
  daemonSocket: string;
  vaultPassword: string;
  backupPassword: string;
  outputPath: string;
  overwrite?: boolean;
  config?: WlfiConfig;
}

export interface ExportEncryptedWalletBackupDeps {
  readConfig?: () => WlfiConfig;
  runRustBinaryJson?: typeof runRustBinaryJson;
  resolveWalletProfile?: typeof resolveWalletProfile;
}

export function buildExportVaultPrivateKeyAdminArgs(input: { daemonSocket: string }): string[] {
  return [
    '--json',
    '--quiet',
    '--vault-password-stdin',
    '--daemon-socket',
    input.daemonSocket,
    'export-vault-private-key',
    '--vault-key-id',
  ];
}

export async function exportEncryptedWalletBackup(
  options: ExportEncryptedWalletBackupOptions,
  deps: ExportEncryptedWalletBackupDeps = {},
): Promise<WalletBackupSummary & { outputPath: string }> {
  const config = options.config ?? (deps.readConfig ?? readConfig)();
  const walletProfile = (deps.resolveWalletProfile ?? resolveWalletProfile)(config);
  const vaultKeyId = walletProfile.vaultKeyId?.trim();
  if (!vaultKeyId) {
    throw new Error('wallet.vaultKeyId is required before exporting a wallet backup');
  }

  const runJson = deps.runRustBinaryJson ?? runRustBinaryJson;
  const exported = await runJson<ExportVaultPrivateKeyAdminOutput>(
    'agentpay-admin' as RustBinaryName,
    [
      ...buildExportVaultPrivateKeyAdminArgs({
        daemonSocket: options.daemonSocket,
      }),
      vaultKeyId,
    ],
    config,
    {
      stdin: `${options.vaultPassword}\n`,
      preSuppliedSecretStdin: 'vaultPassword',
      scrubSensitiveEnv: true,
    },
  );

  const backup = createEncryptedWalletBackup({
    privateKeyHex: exported.vault_private_key,
    sourceVaultKeyId: exported.vault_key_id,
    password: options.backupPassword,
  });
  const outputPath = writeEncryptedWalletBackupFile(options.outputPath, backup, {
    overwrite: options.overwrite ?? false,
  });

  return {
    outputPath,
    createdAt: backup.createdAt,
    address: backup.wallet.address,
    vaultPublicKey: backup.wallet.vaultPublicKey,
    sourceVaultKeyId: backup.wallet.sourceVaultKeyId,
  };
}
