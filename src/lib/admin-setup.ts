import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { Command } from 'commander';
import type { Hex } from 'viem';
import { publicKeyToAddress } from 'viem/accounts';
import {
  defaultRustBinDir,
  readConfig,
  redactConfig,
  type WlfiConfig,
  writeConfig,
} from '../../packages/config/src/index.js';
import { cleanupBootstrapAgentCredentialsFile } from './bootstrap-credentials.js';
import {
  assertTrustedAdminDaemonSocketPath,
  assertTrustedExecutablePath,
  assertTrustedRootPlannedDaemonSocketPath,
  assertTrustedRootPlannedPrivateFilePath,
} from './fs-trust.js';
import { resolveAgentAuthStorageMetadata } from './agent-auth-storage.js';
import { DAEMON_PASSWORD_KEYCHAIN_SERVICE } from './keychain.js';
import {
  LAUNCHD_INSTALL_SCRIPT_NAME,
  LAUNCHD_RUNNER_SCRIPT_NAME,
  resolveLaunchDaemonHelperScriptPath,
} from './launchd-assets.js';
import {
  resolveManagedDaemonCredentialHelperPath,
  resolveManagedDaemonPlatformSpec,
} from './managed-daemon-platform.js';
import { resolveCliNetworkProfile } from './network-selection.js';
import { passthroughRustBinary, RustBinaryExitError, runRustBinary } from './rust.js';
import { createSudoSession } from './sudo.js';
import {
  resolveSystemdHelperScriptPath,
  SYSTEMD_INSTALL_SCRIPT_NAME,
  SYSTEMD_RUNNER_SCRIPT_NAME,
} from './systemd-assets.js';
import { resolveWalletProfile } from './wallet-profile.js';
import { exportEncryptedWalletBackup } from './wallet-backup-admin.js';
import {
  assertWalletSetupExecutionPreconditions,
  buildWalletSetupAdminArgs,
  type CompleteWalletSetupResult,
  completeWalletSetup,
  createWalletSetupPlan,
  formatWalletSetupPlanText,
  resolveWalletSetupBootstrapOutputPath,
  resolveWalletSetupCleanupAction,
  type WalletSetupPlan,
} from './wallet-setup.js';
import { promptHiddenTty } from './hidden-tty-prompt.js';
import {
  cleanupTemporaryWalletImportKeyFile,
  defaultWalletBackupOutputPath,
  decryptWalletBackup,
  readWalletBackupFile,
  resolveWalletBackupPassword,
  writeTemporaryWalletImportKeyFile,
} from './wallet-backup.js';
import { assertManagedDaemonPlatform } from './platform-support.js';

const MANAGED_DAEMON_SPEC = resolveManagedDaemonPlatformSpec(
  process.platform === 'linux' ? 'linux' : 'darwin',
);
const DEFAULT_LAUNCH_DAEMON_LABEL = MANAGED_DAEMON_SPEC.label;
const DEFAULT_SIGNER_BACKEND = 'software';
const DEFAULT_MANAGED_BIN_DIR = MANAGED_DAEMON_SPEC.managedBinDir;
const DEFAULT_MANAGED_DAEMON_SOCKET = MANAGED_DAEMON_SPEC.daemonSocket;
const DEFAULT_MANAGED_STATE_FILE = MANAGED_DAEMON_SPEC.stateFile;
const DEFAULT_MANAGED_KEYCHAIN_HELPER = path.join(
  DEFAULT_MANAGED_BIN_DIR,
  MANAGED_DAEMON_SPEC.sourceCredentialHelperName,
);
const MAX_SECRET_STDIN_BYTES = 16 * 1024;
const DEFAULT_LAUNCH_DAEMON_PLIST = MANAGED_DAEMON_SPEC.serviceFile;
const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const REDACTED_SECRET_PLACEHOLDER = '<redacted>';
interface ProgressHandle {
  succeed(message?: string): void;
  fail(message?: string): void;
  info(message?: string): void;
}

interface AdminSetupOptions {
  vaultPassword?: string;
  vaultPasswordStdin?: boolean;
  backupPassword?: string;
  backupPasswordStdin?: boolean;
  nonInteractive?: boolean;
  plan?: boolean;
  yes?: boolean;
  reuseExistingWallet?: boolean;
  restoreWalletFrom?: string;
  backupOutput?: string;
  backupOverwrite?: boolean;
  printAgentAuthToken?: boolean;
  daemonSocket?: string;
  perTxMaxWei?: string;
  dailyMaxWei?: string;
  weeklyMaxWei?: string;
  maxGasPerChainWei?: string;
  dailyMaxTxCount?: string;
  perTxMaxFeePerGasWei?: string;
  perTxMaxPriorityFeePerGasWei?: string;
  perTxMaxCalldataBytes?: string;
  token: string[];
  allowNativeEth?: boolean;
  network?: string;
  rpcUrl?: string;
  chainName?: string;
  recipient?: string;
  attachPolicyId: string[];
  attachBootstrapPolicies?: boolean;
  bootstrapOutput?: string;
  deleteBootstrapOutput?: boolean;
  json?: boolean;
}

interface AdminTuiOptions {
  daemonSocket?: string;
  bootstrapOutput?: string;
  deleteBootstrapOutput?: boolean;
  json?: boolean;
  printAgentAuthToken?: boolean;
}

interface WalletBackupExportResult {
  status: 'created' | 'failed' | 'not-created';
  outputPath?: string;
  createdAt?: string;
  address?: string;
  sourceVaultKeyId?: string;
  reminderCommand?: string;
  error?: string;
}

export interface AdminSetupPlan {
  command: 'setup';
  mode: 'plan';
  daemon: {
    launchdLabel: string;
    socket: string;
    stateFile: string;
    installReady: boolean;
    installError: string | null;
    sourceRunnerPath: string;
    sourceDaemonBin: string;
    sourceKeychainHelperBin: string;
    managedRunnerPath: string;
    managedDaemonBin: string;
    managedKeychainHelperBin: string;
  };
  existingWallet: ExistingWalletSetupTarget | null;
  overwrite: {
    required: boolean;
    requiresYesInNonInteractive: boolean;
  };
  walletSetup: WalletSetupPlan;
}

interface LaunchDaemonAssetPaths {
  runnerPath: string;
  daemonBin: string;
  keychainHelperBin: string;
}

interface ManagedDaemonInstallPreconditionDeps {
  existsSync?: (targetPath: string) => boolean;
  assertTrustedExecutablePath?: (targetPath: string) => void;
  assertTrustedRootPlannedDaemonSocketPath?: (targetPath: string, label?: string) => string;
  assertTrustedRootPlannedPrivateFilePath?: (targetPath: string, label?: string) => string;
  resolveInstallScriptPath?: () => string;
}

interface ManagedDaemonInstallPreconditions extends LaunchDaemonAssetPaths {
  installScript: string;
  managedRunnerPath: string;
  managedDaemonBin: string;
  managedKeychainHelperBin: string;
}

interface ManagedDaemonInstallResult {
  label: string;
  runnerPath: string;
  daemonBin: string;
  stateFile: string;
  serviceManager: 'launchd' | 'systemd';
  keychainAccount?: string;
  keychainService?: string;
  passwordFile?: string;
}

interface ManagedLaunchDaemonAssetMatchDeps {
  filesHaveIdenticalContents?: (leftPath: string, rightPath: string) => boolean;
  resolveManagedPaths?: () => LaunchDaemonAssetPaths;
}

interface CreateAdminSetupPlanDeps {
  readConfig?: () => WlfiConfig;
  assertManagedDaemonInstallPreconditions?: typeof assertManagedDaemonInstallPreconditions;
}

export interface ExistingWalletSetupTarget {
  address?: string;
  agentKeyId?: string;
  hasLegacyAgentAuthToken: boolean;
}

interface ReusableWalletSetupTarget {
  address?: string;
  existingVaultKeyId: string;
  existingVaultPublicKey: string;
}

interface ConfirmAdminSetupOverwriteDeps {
  prompt?: (query: string) => Promise<string>;
  stderr?: Pick<NodeJS.WriteStream, 'write'>;
}

interface ResolveAdminSetupVaultPasswordDeps {
  env?: NodeJS.ProcessEnv;
  readTrimmedStdin?: (label: string) => Promise<string>;
  promptHidden?: (query: string) => Promise<string>;
}

interface PostSetupWalletBackupRequest {
  outputPath: string;
  overwrite: boolean;
}

function validateSecret(value: string, label: string): string {
  if (Buffer.byteLength(value, 'utf8') > MAX_SECRET_STDIN_BYTES) {
    throw new Error(`${label} must not exceed ${MAX_SECRET_STDIN_BYTES} bytes`);
  }
  if (!value.trim()) {
    throw new Error(`${label} must not be empty or whitespace`);
  }
  return value;
}

async function readTrimmedStdin(label: string): Promise<string> {
  process.stdin.setEncoding('utf8');
  let raw = '';
  for await (const chunk of process.stdin) {
    raw += chunk;
    if (Buffer.byteLength(raw, 'utf8') > MAX_SECRET_STDIN_BYTES) {
      throw new Error(`${label} must not exceed ${MAX_SECRET_STDIN_BYTES} bytes`);
    }
  }
  return validateSecret(raw.replace(/[\r\n]+$/u, ''), label);
}

async function promptHidden(
  query: string,
  label = 'vault password',
  nonInteractiveError = 'vault password is required; use --vault-password-stdin or a local TTY prompt',
): Promise<string> {
  const answer = await promptHiddenTty(query, nonInteractiveError);
  return validateSecret(answer, label);
}

async function promptVisible(query: string, nonInteractiveError: string): Promise<string> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error(nonInteractiveError);
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: true,
  });

  const answer = await new Promise<string>((resolve) => {
    rl.question(query, resolve);
  });
  rl.close();
  return answer.trim();
}

async function promptConfirmedVaultPassword(
  prompt: (query: string) => Promise<string>,
): Promise<string> {
  const first = await prompt('Vault password (input hidden; this unlocks the wallet, not sudo): ');
  const second = await prompt('Confirm vault password: ');
  if (first !== second) {
    throw new Error('vault passwords did not match');
  }
  return first;
}

function deriveWalletAddress(vaultPublicKey: string | undefined): string | undefined {
  const normalized = vaultPublicKey?.trim();
  if (!normalized) {
    return undefined;
  }
  try {
    return publicKeyToAddress(
      (normalized.startsWith('0x') ? normalized : `0x${normalized}`) as Hex,
    );
    /* c8 ignore next 2 -- viem currently normalizes malformed public-key strings instead of throwing; catch is defensive */
  } catch {
    return undefined;
  }
}

export function resolveExistingWalletSetupTarget(
  config: WlfiConfig,
): ExistingWalletSetupTarget | null {
  const address =
    config.wallet?.address?.trim() || deriveWalletAddress(config.wallet?.vaultPublicKey);
  const agentKeyId = config.agentKeyId?.trim() || config.wallet?.agentKeyId?.trim();
  const hasLegacyAgentAuthToken = Boolean(config.agentAuthToken?.trim());

  if (!address && !agentKeyId && !hasLegacyAgentAuthToken) {
    return null;
  }

  return {
    address: address || undefined,
    agentKeyId: agentKeyId || undefined,
    hasLegacyAgentAuthToken,
  };
}

function resolveReusableWalletSetupTarget(
  config: WlfiConfig,
  optionLabel = '--reuse-existing-wallet',
): ReusableWalletSetupTarget {
  let walletProfile: ReturnType<typeof resolveWalletProfile>;
  try {
    walletProfile = resolveWalletProfile(config);
  } catch (error) {
    throw new Error(
      `${optionLabel} requires a local wallet to reuse; ${renderError(error)}`,
    );
  }

  const existingVaultKeyId = walletProfile.vaultKeyId?.trim();
  const existingVaultPublicKey = walletProfile.vaultPublicKey?.trim();
  if (!existingVaultKeyId || !existingVaultPublicKey) {
    throw new Error(
      `${optionLabel} requires wallet.vaultKeyId and wallet.vaultPublicKey in the local wallet profile`,
    );
  }

  return {
    address: walletProfile.address?.trim() || deriveWalletAddress(existingVaultPublicKey),
    existingVaultKeyId,
    existingVaultPublicKey,
  };
}

function resolveRequestedReusableWalletSetupTarget(
  options: Pick<AdminSetupOptions, 'reuseExistingWallet' | 'restoreWalletFrom' | 'attachBootstrapPolicies'>,
  config: WlfiConfig,
): ReusableWalletSetupTarget | null {
  if (options.restoreWalletFrom) {
    return null;
  }
  if (options.reuseExistingWallet) {
    return resolveReusableWalletSetupTarget(config, '--reuse-existing-wallet');
  }
  if (options.attachBootstrapPolicies) {
    return resolveReusableWalletSetupTarget(config, '--attach-bootstrap-policies');
  }
  return null;
}

export async function confirmAdminSetupOverwrite(
  options: Pick<AdminSetupOptions, 'yes' | 'nonInteractive' | 'reuseExistingWallet'>,
  config: WlfiConfig,
  deps: ConfirmAdminSetupOverwriteDeps = {},
): Promise<void> {
  const existing = resolveExistingWalletSetupTarget(config);
  if (!existing || options.yes) {
    return;
  }
  if (options.nonInteractive) {
    throw new Error(
      options.reuseExistingWallet
        ? '`agentpay admin setup --reuse-existing-wallet` would refresh the existing local wallet metadata and agent credentials; rerun with --yes in non-interactive mode'
        : '`agentpay admin setup` would overwrite the existing wallet; rerun with --yes in non-interactive mode',
    );
  }

  const stderr = deps.stderr ?? process.stderr;
  stderr.write(
    options.reuseExistingWallet
      ? 'warning: admin setup will reuse the current vault and refresh the local wallet metadata and agent credentials.\n'
      : 'warning: admin setup will overwrite the current local wallet metadata and agent credentials.\n',
  );
  if (existing.address) {
    stderr.write(`current address: ${existing.address}\n`);
  }
  if (existing.agentKeyId) {
    stderr.write(`current agent key id: ${existing.agentKeyId}\n`);
  }
  if (existing.hasLegacyAgentAuthToken) {
    stderr.write('legacy agent auth token is still present in config.json\n');
  }

  const confirmationToken = options.reuseExistingWallet ? 'REUSE' : 'OVERWRITE';
  const confirmationPrompt = options.reuseExistingWallet
    ? 'Type REUSE to reattach the current local vault: '
    : 'Type OVERWRITE to replace the current local wallet: ';
  const confirmation = await (
    deps.prompt ??
    ((query: string) =>
      promptVisible(
        query,
        options.reuseExistingWallet
          ? '`agentpay admin setup --reuse-existing-wallet` requires --yes in non-interactive environments when reusing an existing wallet'
          : '`agentpay admin setup` requires --yes in non-interactive environments when overwriting an existing wallet',
      ))
  )(confirmationPrompt);
  if (confirmation !== confirmationToken) {
    throw new Error('admin setup aborted');
  }
}

export async function resolveAdminSetupVaultPassword(
  options: Pick<AdminSetupOptions, 'vaultPassword' | 'vaultPasswordStdin' | 'nonInteractive'>,
  deps: ResolveAdminSetupVaultPasswordDeps = {},
): Promise<string> {
  const env = deps.env ?? process.env;
  const readVaultPasswordFromStdin = deps.readTrimmedStdin ?? readTrimmedStdin;
  const promptForVaultPassword = deps.promptHidden ?? promptHidden;

  if (options.vaultPassword && options.vaultPasswordStdin) {
    throw new Error('--vault-password conflicts with --vault-password-stdin');
  }
  if (options.vaultPassword) {
    validateSecret(options.vaultPassword, 'vault password');
    throw new Error(
      'insecure --vault-password is disabled; use --vault-password-stdin or a local TTY prompt',
    );
  }
  if (options.vaultPasswordStdin) {
    return readVaultPasswordFromStdin('vault password');
  }
  if (Object.hasOwn(env, 'AGENTPAY_VAULT_PASSWORD')) {
    validateSecret(env.AGENTPAY_VAULT_PASSWORD ?? '', 'vault password');
    throw new Error(
      'AGENTPAY_VAULT_PASSWORD is disabled for security; use --vault-password-stdin or a local TTY prompt',
    );
  }
  if (options.nonInteractive) {
    throw new Error(
      'vault password is required in non-interactive mode; use --vault-password-stdin',
    );
  }
  return await promptConfirmedVaultPassword(promptForVaultPassword);
}

async function resolveAdminSetupBackupPassword(
  options: Pick<
    AdminSetupOptions,
    'backupPassword' | 'backupPasswordStdin' | 'nonInteractive'
  >,
  confirm = true,
): Promise<string> {
  return resolveWalletBackupPassword(
    {
      backupPassword: options.backupPassword,
      backupPasswordStdin: options.backupPasswordStdin,
      nonInteractive: options.nonInteractive,
      confirm,
    },
  );
}

function resolveAdminSetupRestoreConflictErrors(options: AdminSetupOptions): void {
  if (options.reuseExistingWallet && options.restoreWalletFrom) {
    throw new Error('--restore-wallet-from conflicts with --reuse-existing-wallet');
  }
  if (options.vaultPasswordStdin && options.backupPasswordStdin) {
    throw new Error(
      '--vault-password-stdin conflicts with --backup-password-stdin; provide one secret via a local TTY prompt',
    );
  }
  if ((options.backupPassword || options.backupPasswordStdin) && !options.restoreWalletFrom && !options.backupOutput) {
    throw new Error(
      '--backup-password-stdin requires --restore-wallet-from or --backup-output',
    );
  }
}

function renderWalletBackupCommand(outputPath: string): string {
  return `agentpay admin wallet-backup export --output ${JSON.stringify(path.resolve(outputPath))}`;
}

async function resolvePostSetupWalletBackupRequest(input: {
  options: Pick<
    AdminSetupOptions,
    'backupOutput' | 'backupOverwrite' | 'nonInteractive' | 'restoreWalletFrom'
  >;
  createdFreshWallet: boolean;
}): Promise<PostSetupWalletBackupRequest | null> {
  if (input.options.backupOutput) {
    return {
      outputPath: path.resolve(input.options.backupOutput),
      overwrite: Boolean(input.options.backupOverwrite),
    };
  }

  if (!input.createdFreshWallet || input.options.nonInteractive) {
    return null;
  }
  return null;
}

function resolveDaemonSocket(optionValue: string | undefined): string {
  return path.resolve(optionValue?.trim() || DEFAULT_MANAGED_DAEMON_SOCKET);
}

function resolveStateFile(): string {
  return path.resolve(DEFAULT_MANAGED_STATE_FILE);
}

function resolveDefaultActiveChainForFreshSetup(
  config: WlfiConfig,
): { chainId: number; chainName: string; rpcUrl?: string } | null {
  try {
    const profile = resolveCliNetworkProfile('bsc', config);
    return {
      chainId: profile.chainId,
      chainName: profile.key?.trim() || profile.name.trim().toLowerCase() || 'bsc',
      ...(profile.rpcUrl?.trim() ? { rpcUrl: profile.rpcUrl.trim() } : {}),
    };
  } catch {
    return null;
  }
}

function shouldSeedDefaultActiveChain(
  options: Pick<AdminSetupOptions, 'network' | 'rpcUrl' | 'chainName'>,
  config: WlfiConfig,
): boolean {
  return (
    !options.network &&
    !options.rpcUrl &&
    !options.chainName &&
    config.chainId === undefined &&
    !config.chainName?.trim() &&
    !config.rpcUrl?.trim()
  );
}

export function createAdminSetupPlan(
  options: AdminSetupOptions,
  deps: CreateAdminSetupPlanDeps = {},
): AdminSetupPlan {
  resolveAdminSetupRestoreConflictErrors(options);
  if (options.rpcUrl && !options.network) {
    throw new Error('--rpc-url requires --network');
  }
  if (options.chainName && !options.network) {
    throw new Error('--chain-name requires --network');
  }

  const loadConfig = deps.readConfig ?? readConfig;
  const checkManagedDaemonInstallPreconditions =
    deps.assertManagedDaemonInstallPreconditions ?? assertManagedDaemonInstallPreconditions;
  const config = loadConfig();
  const daemonSocket = resolveDaemonSocket(options.daemonSocket);
  const stateFile = resolveStateFile();
  const sourcePaths = resolveSourceLaunchDaemonPaths(config);
  const managedPaths = resolveManagedLaunchDaemonPaths();
  let installReady = true;
  let installError: string | null = null;

  try {
    checkManagedDaemonInstallPreconditions(config, daemonSocket, stateFile);
  } catch (error) {
    installReady = false;
    installError = renderError(error);
  }

  const existingWallet = resolveExistingWalletSetupTarget(config);
  const reusableWallet = resolveRequestedReusableWalletSetupTarget(options, config);

  return {
    command: 'setup',
    mode: 'plan',
    daemon: {
      launchdLabel: DEFAULT_LAUNCH_DAEMON_LABEL,
      socket: daemonSocket,
      stateFile,
      installReady,
      installError,
      sourceRunnerPath: sourcePaths.runnerPath,
      sourceDaemonBin: sourcePaths.daemonBin,
      sourceKeychainHelperBin: sourcePaths.keychainHelperBin,
      managedRunnerPath: managedPaths.runnerPath,
      managedDaemonBin: managedPaths.daemonBin,
      managedKeychainHelperBin: managedPaths.keychainHelperBin,
    },
    existingWallet,
    overwrite: {
      required: existingWallet !== null,
      requiresYesInNonInteractive:
        existingWallet !== null && Boolean(options.nonInteractive) && !options.yes,
    },
    walletSetup: createWalletSetupPlan(
      {
        vaultPasswordStdin: options.vaultPasswordStdin,
        nonInteractive: options.nonInteractive,
        daemonSocket,
        perTxMaxWei: options.perTxMaxWei,
        dailyMaxWei: options.dailyMaxWei,
        weeklyMaxWei: options.weeklyMaxWei,
        maxGasPerChainWei: options.maxGasPerChainWei,
        dailyMaxTxCount: options.dailyMaxTxCount,
        perTxMaxFeePerGasWei: options.perTxMaxFeePerGasWei,
        perTxMaxPriorityFeePerGasWei: options.perTxMaxPriorityFeePerGasWei,
        perTxMaxCalldataBytes: options.perTxMaxCalldataBytes,
        token: options.token,
        allowNativeEth: options.allowNativeEth,
        network: options.network,
        rpcUrl: options.rpcUrl,
        chainName: options.chainName,
        recipient: options.recipient,
        attachPolicyId: options.attachPolicyId,
        attachBootstrapPolicies: options.attachBootstrapPolicies,
        existingVaultKeyId: reusableWallet?.existingVaultKeyId,
        existingVaultPublicKey: reusableWallet?.existingVaultPublicKey,
        importVaultPrivateKeyFile: options.restoreWalletFrom
          ? '<decrypted from backup at runtime>'
          : undefined,
        bootstrapOutputPath: options.bootstrapOutput,
        deleteBootstrapOutput: options.deleteBootstrapOutput,
      },
      {
        readConfig: () => config,
      },
    ),
  };
}

function formatAdminSetupExistingWallet(plan: AdminSetupPlan): string[] {
  if (!plan.existingWallet) {
    return ['Existing Wallet', '- none'];
  }

  return [
    'Existing Wallet',
    `- Address: ${plan.existingWallet.address ?? 'unknown'}`,
    `- Agent Key ID: ${plan.existingWallet.agentKeyId ?? 'unknown'}`,
    `- Legacy Config Token Present: ${plan.existingWallet.hasLegacyAgentAuthToken ? 'yes' : 'no'}`,
  ];
}

export function formatAdminSetupPlanText(plan: AdminSetupPlan): string {
  const lines = [
    'Admin Setup Preview',
    `Managed Service Install: ${plan.daemon.installReady ? 'ready' : 'blocked'}`,
    plan.daemon.installError ? `Install Error: ${plan.daemon.installError}` : null,
    `Managed Socket: ${plan.daemon.socket}`,
    `Managed State File: ${plan.daemon.stateFile}`,
    `Managed Service Label: ${plan.daemon.launchdLabel}`,
    '',
    ...formatAdminSetupExistingWallet(plan),
    `Overwrite Confirmation Required: ${plan.overwrite.required ? 'yes' : 'no'}`,
    `Non-interactive Requires --yes: ${plan.overwrite.requiresYesInNonInteractive ? 'yes' : 'no'}`,
    '',
    formatWalletSetupPlanText(plan.walletSetup),
  ];

  return lines.filter((line): line is string => line !== null).join('\n');
}

function backfillPersistedWalletProfileForTui(config: WlfiConfig): WlfiConfig {
  if (!config.wallet || config.wallet.vaultKeyId) {
    return config;
  }

  let resolvedWallet: ReturnType<typeof resolveWalletProfile>;
  try {
    resolvedWallet = resolveWalletProfile(config);
  } catch {
    return config;
  }

  if (!resolvedWallet.vaultKeyId) {
    return config;
  }

  return writeConfig({
    agentKeyId: config.agentKeyId ?? resolvedWallet.agentKeyId,
    wallet: resolvedWallet,
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function asOptionalRecord(value: unknown): Record<string, unknown> {
  return isRecord(value) ? value : {};
}

function isFinalAdminCommandPayload(payload: unknown): payload is Record<string, unknown> {
  return (
    isRecord(payload) &&
    (payload.command === 'setup' || payload.command === 'tui') &&
    payload.mode !== 'plan'
  );
}

export function prepareAdminCommandOutputPayload(
  payload: unknown,
  includeSecrets = false,
): unknown {
  if (!isRecord(payload)) {
    return payload;
  }

  const prepared = { ...payload };
  for (const [fieldName, redactedFieldName] of [['vaultPrivateKey', 'vaultPrivateKeyRedacted']] as const) {
    const value = prepared[fieldName];
    if (typeof value === 'string' && value.trim()) {
      prepared[fieldName] = REDACTED_SECRET_PLACEHOLDER;
      prepared[redactedFieldName] = true;
    }
  }

  if (!includeSecrets) {
    for (const [fieldName, redactedFieldName] of [['agentAuthToken', 'agentAuthTokenRedacted']] as const) {
      const value = prepared[fieldName];
      if (typeof value === 'string' && value.trim()) {
        prepared[fieldName] = REDACTED_SECRET_PLACEHOLDER;
        prepared[redactedFieldName] = true;
      }
    }
  }

  return prepared;
}

export function formatAdminCommandOutput(
  payload: unknown,
  options: { includeSecrets?: boolean } = {},
): string {
  if (typeof payload === 'string') {
    return payload;
  }

  const prepared = prepareAdminCommandOutputPayload(payload, options.includeSecrets ?? false);
  if (!isRecord(prepared)) {
    return JSON.stringify(prepared, null, 2);
  }

  if (prepared.command === 'tui' && prepared.canceled === true) {
    return 'tui canceled';
  }

  const keychain = asOptionalRecord(prepared.keychain);
  const config = asOptionalRecord(prepared.config);
  const daemon = asOptionalRecord(prepared.daemon);
  const walletBackup = asOptionalRecord(prepared.walletBackup);
  const vaultPublicKey = String(prepared.vaultPublicKey ?? '').trim();
  const agentAuthToken = String(prepared.agentAuthToken ?? '').trim();
  const renderedAgentKeyId = String(prepared.agentKeyId ?? '').trim();
  const storageMetadata = resolveAgentAuthStorageMetadata(
    process.platform,
    renderedAgentKeyId || undefined,
  );
  const includeSecrets = options.includeSecrets ?? false;

  let addressLine: string | null = null;
  if (vaultPublicKey) {
    const normalizedPublicKey = (
      vaultPublicKey.startsWith('0x') ? vaultPublicKey : `0x${vaultPublicKey}`
    ) as Hex;
    addressLine = `address: ${publicKeyToAddress(normalizedPublicKey)}`;
  }

  const daemonSocket = String(daemon.daemonSocket ?? config.daemonSocket ?? '').trim();
  const stateFile = String(daemon.stateFile ?? config.stateFile ?? '').trim();
  const chainName = String(config.chainName ?? prepared.networkScope ?? 'unconfigured').trim();
  const keychainService = String(keychain.service ?? '').trim();
  const keychainLocationType =
    keychain.locationType === 'file' || keychain.locationType === 'service'
      ? keychain.locationType
      : storageMetadata.locationType;
  const keychainLocationLabel =
    keychainLocationType === 'file' || keychainService.includes(path.sep)
      ? 'credential file'
      : 'credential service';
  const keychainLabel = String(keychain.label ?? storageMetadata.label).trim();
  const keychainNote = String(keychain.note ?? storageMetadata.note ?? '').trim();
  const storedAgentAuthTokenSummary = keychainNote
    ? `stored in ${keychainLabel} (${keychainNote})`
    : `stored in ${keychainLabel}`;
  const title = prepared.command === 'tui' ? 'tui complete' : 'setup complete';
  const walletBackupStatus =
    walletBackup.status === 'not-created' ? 'skipped by default' : walletBackup.status;

  const lines = [
    title,
    addressLine,
    typeof prepared.vaultKeyId === 'string' && prepared.vaultKeyId.trim()
      ? `vault key id: ${prepared.vaultKeyId}`
      : null,
    typeof prepared.agentKeyId === 'string' && prepared.agentKeyId.trim()
      ? `agent key id: ${prepared.agentKeyId}`
      : null,
    daemonSocket ? `daemon socket: ${daemonSocket}` : null,
    stateFile ? `state file: ${stateFile}` : null,
    `chain: ${chainName || 'unconfigured'}`,
    includeSecrets
      ? agentAuthToken
        ? `agent auth token: ${agentAuthToken}`
        : null
      : `agent auth token: ${storedAgentAuthTokenSummary}`,
    keychainService ? `${keychainLocationLabel}: ${keychainService}` : null,
    typeof prepared.sourceCleanupWarning === 'string' && prepared.sourceCleanupWarning.trim()
      ? `source cleanup warning: ${prepared.sourceCleanupWarning}`
      : null,
    keychainNote ? `note: ${keychainNote}` : null,
    typeof walletBackupStatus === 'string' ? `wallet backup: ${walletBackupStatus}` : null,
    walletBackup.status !== 'not-created' &&
    typeof walletBackup.outputPath === 'string' && walletBackup.outputPath.trim()
      ? `wallet backup path: ${walletBackup.outputPath}`
      : null,
    typeof walletBackup.createdAt === 'string' && walletBackup.createdAt.trim()
      ? `wallet backup created at: ${walletBackup.createdAt}`
      : null,
    typeof walletBackup.error === 'string' && walletBackup.error.trim()
      ? `wallet backup error: ${walletBackup.error}`
      : null,
    typeof walletBackup.reminderCommand === 'string' && walletBackup.reminderCommand.trim()
      ? `wallet backup command: ${walletBackup.reminderCommand}`
      : null,
  ].filter((line): line is string => Boolean(line && !line.endsWith(': ')));

  if (includeSecrets && agentAuthToken) {
    lines.push('warning: keep the agent auth token carefully.');
  }

  return lines.join('\n');
}

function printCliPayload(payload: unknown, asJson: boolean, includeSecrets = false): void {
  const prepared = isFinalAdminCommandPayload(payload)
    ? prepareAdminCommandOutputPayload(payload, includeSecrets)
    : payload;

  if (asJson) {
    process.stdout.write(`${JSON.stringify(prepared, null, 2)}\n`);
    return;
  }
  if (typeof prepared === 'string') {
    process.stdout.write(`${prepared}\n`);
    return;
  }
  if (isFinalAdminCommandPayload(prepared)) {
    process.stdout.write(`${formatAdminCommandOutput(prepared, { includeSecrets })}\n`);
    return;
  }
  process.stdout.write(`${JSON.stringify(prepared, null, 2)}\n`);
}

function resolveRustBinDir(config: WlfiConfig): string {
  return path.resolve(config.rustBinDir || defaultRustBinDir());
}

function resolveSourceLaunchDaemonPaths(config: WlfiConfig): LaunchDaemonAssetPaths {
  const rustBinDir = resolveRustBinDir(config);
  const isLinux = process.platform === 'linux';
  return {
    runnerPath: path.join(
      rustBinDir,
      isLinux ? SYSTEMD_RUNNER_SCRIPT_NAME : LAUNCHD_RUNNER_SCRIPT_NAME,
    ),
    daemonBin: path.join(
      rustBinDir,
      `agentpay-daemon${process.platform === 'win32' ? '.exe' : ''}`,
    ),
    keychainHelperBin: path.join(rustBinDir, MANAGED_DAEMON_SPEC.sourceCredentialHelperName),
  };
}

export function resolveManagedLaunchDaemonPaths(): LaunchDaemonAssetPaths {
  return {
    runnerPath: path.join(DEFAULT_MANAGED_BIN_DIR, MANAGED_DAEMON_SPEC.sourceRunnerScriptName),
    daemonBin: path.join(
      DEFAULT_MANAGED_BIN_DIR,
      `agentpay-daemon${process.platform === 'win32' ? '.exe' : ''}`,
    ),
    keychainHelperBin: resolveManagedDaemonCredentialHelperPath(
      process.platform === 'linux' ? 'linux' : 'darwin',
    ),
  };
}

function resolveLaunchDaemonInstallScriptPath(config: WlfiConfig): string {
  if (process.platform === 'linux') {
    return resolveSystemdHelperScriptPath(SYSTEMD_INSTALL_SCRIPT_NAME, config);
  }
  return resolveLaunchDaemonHelperScriptPath(LAUNCHD_INSTALL_SCRIPT_NAME, config);
}

function filesHaveIdenticalContents(leftPath: string, rightPath: string): boolean {
  try {
    const leftStats = fs.statSync(leftPath);
    const rightStats = fs.statSync(rightPath);
    if (!leftStats.isFile() || !rightStats.isFile() || leftStats.size !== rightStats.size) {
      return false;
    }

    return fs.readFileSync(leftPath).equals(fs.readFileSync(rightPath));
  } catch {
    return false;
  }
}

export function managedLaunchDaemonAssetsMatchSource(
  config: WlfiConfig,
  deps: ManagedLaunchDaemonAssetMatchDeps = {},
): boolean {
  const sourcePaths = resolveSourceLaunchDaemonPaths(config);
  const managedPaths = (deps.resolveManagedPaths ?? resolveManagedLaunchDaemonPaths)();
  const compareFileContents = deps.filesHaveIdenticalContents ?? filesHaveIdenticalContents;
  return (
    compareFileContents(sourcePaths.runnerPath, managedPaths.runnerPath) &&
    compareFileContents(sourcePaths.daemonBin, managedPaths.daemonBin) &&
    compareFileContents(sourcePaths.keychainHelperBin, managedPaths.keychainHelperBin)
  );
}

export function assertManagedDaemonInstallPreconditions(
  config: WlfiConfig,
  daemonSocket: string,
  stateFile: string,
  deps: ManagedDaemonInstallPreconditionDeps = {},
): ManagedDaemonInstallPreconditions {
  const existsSync = deps.existsSync ?? fs.existsSync;
  const trustExecutablePath = deps.assertTrustedExecutablePath ?? assertTrustedExecutablePath;
  const trustDaemonSocketPath =
    deps.assertTrustedRootPlannedDaemonSocketPath ?? assertTrustedRootPlannedDaemonSocketPath;
  const trustStateFilePath =
    deps.assertTrustedRootPlannedPrivateFilePath ?? assertTrustedRootPlannedPrivateFilePath;
  const installScript =
    (deps.resolveInstallScriptPath ?? (() => resolveLaunchDaemonInstallScriptPath(config)))();
  const sourcePaths = resolveSourceLaunchDaemonPaths(config);
  const managedPaths = resolveManagedLaunchDaemonPaths();

  if (!existsSync(sourcePaths.runnerPath)) {
    throw new Error(
      `daemon runner is not installed at ${sourcePaths.runnerPath}; reinstall the AgentPay SDK from source or rerun the one-click installer`,
    );
  }
  if (!existsSync(sourcePaths.daemonBin)) {
    throw new Error(
      `daemon binary is not installed at ${sourcePaths.daemonBin}; reinstall the AgentPay SDK from source or rerun the one-click installer`,
    );
  }
  if (!existsSync(sourcePaths.keychainHelperBin)) {
    throw new Error(
      `daemon credential helper is not installed at ${sourcePaths.keychainHelperBin}; reinstall the AgentPay SDK from source or rerun the one-click installer`,
    );
  }
  if (!existsSync(installScript)) {
    throw new Error(`managed daemon install helper is not installed at ${installScript}`);
  }

  trustExecutablePath(sourcePaths.runnerPath);
  trustExecutablePath(sourcePaths.daemonBin);
  trustExecutablePath(sourcePaths.keychainHelperBin);
  trustExecutablePath(installScript);
  trustDaemonSocketPath(daemonSocket, 'Managed daemon socket');
  trustStateFilePath(stateFile, 'Managed daemon state file');

  return {
    ...sourcePaths,
    installScript,
    managedRunnerPath: managedPaths.runnerPath,
    managedDaemonBin: managedPaths.daemonBin,
    managedKeychainHelperBin: managedPaths.keychainHelperBin,
  };
}

function renderError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function createProgress(message: string, enabled = true): ProgressHandle {
  if (!enabled) {
    return {
      succeed() {},
      fail() {},
      info() {},
    };
  }

  if (!process.stderr.isTTY) {
    process.stderr.write(`==> ${message}
`);
    return {
      succeed(finalMessage = message) {
        process.stderr.write(`✓ ${finalMessage}
`);
      },
      fail(finalMessage = `${message} failed`) {
        process.stderr.write(`✗ ${finalMessage}
`);
      },
      info(finalMessage = message) {
        process.stderr.write(`• ${finalMessage}
`);
      },
    };
  }

  let frameIndex = 0;
  const render = (prefix: string, currentMessage: string) => {
    process.stderr.write(`\r\u001b[2K${prefix} ${currentMessage}`);
  };

  render(SPINNER_FRAMES[frameIndex], message);
  const timer = setInterval(() => {
    frameIndex = (frameIndex + 1) % SPINNER_FRAMES.length;
    render(SPINNER_FRAMES[frameIndex], message);
  }, 80);

  const stop = (prefix: string, finalMessage: string) => {
    clearInterval(timer);
    render(prefix, finalMessage);
    process.stderr.write('\n');
  };

  return {
    succeed(finalMessage = message) {
      stop('✓', finalMessage);
    },
    fail(finalMessage = `${message} failed`) {
      stop('✗', finalMessage);
    },
    info(finalMessage = message) {
      stop('•', finalMessage);
    },
  };
}

async function daemonAcceptsVaultPassword(
  config: WlfiConfig,
  daemonSocket: string,
  vaultPassword: string,
): Promise<boolean> {
  try {
    await runRustBinary(
      'agentpay-admin',
      [
        '--json',
        '--non-interactive',
        '--vault-password-stdin',
        '--daemon-socket',
        daemonSocket,
        'list-policies',
      ],
      config,
      {
        stdin: `${vaultPassword}\n`,
        preSuppliedSecretStdin: 'vaultPassword',
        scrubSensitiveEnv: true,
      },
    );
    return true;
  } catch (error) {
    if (error instanceof RustBinaryExitError) {
      const output = `${error.stderr}\n${error.stdout}`;
      if (/authentication failed/iu.test(output)) {
        return false;
      }
    }
    throw error;
  }
}

const sudoSession = createSudoSession({
  promptPassword: async () =>
    await promptHidden(
      'System admin password for sudo (input hidden; required to install or recover the root-managed daemon): ',
      'System admin password for sudo',
      'System admin password for sudo is required; rerun on a local TTY',
    ),
});

async function managedStateFileExists(stateFile: string): Promise<boolean> {
  const result = await sudoSession.run(['/bin/test', '-e', stateFile]);
  if (result.code === 0) {
    return true;
  }
  if (
    result.code === 1 &&
    !/password is required|try again|authentication failed|sorry/iu.test(result.stderr)
  ) {
    return false;
  }
  throw new Error(
    result.stderr.trim() ||
      result.stdout.trim() ||
      `failed to inspect managed daemon state file '${stateFile}' (exit code ${result.code})`,
  );
}

async function inspectManagedState(
  stateFile: string,
  showProgress: boolean,
  message = 'Inspecting managed daemon state',
): Promise<boolean> {
  await sudoSession.prime();
  const stateProbeProgress = createProgress(message, showProgress);
  let stateExists: boolean;
  try {
    stateExists = await managedStateFileExists(stateFile);
    stateProbeProgress.succeed(
      stateExists ? 'Managed daemon state already exists' : 'No managed daemon state found',
    );
  } catch (error) {
    stateProbeProgress.fail();
    throw error;
  }
  return stateExists;
}

function createManagedStatePasswordMismatchError(stateFile: string): Error {
  return new Error(
    `managed daemon state already exists at ${stateFile} and is encrypted with a different vault password. Re-run setup with the original vault password, or remove/reset the managed daemon state before initializing a fresh wallet.`,
  );
}

function isManagedStatePasswordMismatch(output: string): boolean {
  return /failed to decrypt state|wrong password or tampered file|authentication failed/iu.test(
    output,
  );
}

async function managedStateAcceptsRequestedVaultPassword(
  config: WlfiConfig,
  daemonSocket: string,
  stateFile: string,
  vaultPassword: string,
): Promise<boolean> {
  const installPreconditions = assertManagedDaemonInstallPreconditions(
    config,
    daemonSocket,
    stateFile,
  );
  const allowedUid = String(process.getuid?.() ?? process.geteuid?.() ?? 0);
  const probeScript = [
    'set -euo pipefail',
    'vault_password="$(cat)"',
    'daemon_bin="$1"',
    'state_file="$2"',
    'admin_uid="$3"',
    'agent_uid="$4"',
    'signer_backend="$5"',
    'temp_root="$(mktemp -d "${TMPDIR:-/tmp}/agentpay-managed-state-probe-XXXXXX")"',
    'trap \'rm -rf "$temp_root"\' EXIT',
    'daemon_socket="$temp_root/daemon.sock"',
    '"$daemon_bin" \\',
    '  --non-interactive \\',
    '  --vault-password-stdin \\',
    '  --state-file "$state_file" \\',
    '  --daemon-socket "$daemon_socket" \\',
    '  --signer-backend "$signer_backend" \\',
    '  --allow-admin-euid "$admin_uid" \\',
    '  --allow-agent-euid "$agent_uid" <<<"$vault_password" &',
    'child="$!"',
    'for _ in $(seq 1 20); do',
    '  if ! kill -0 "$child" 2>/dev/null; then',
    '    wait "$child"',
    '    exit $?',
    '  fi',
    '  sleep 0.25',
    'done',
    'kill "$child" >/dev/null 2>&1 || true',
    'wait "$child" >/dev/null 2>&1 || true',
    'exit 0',
  ].join('\n');

  const result = await sudoSession.run(
    [
      '/bin/bash',
      '-lc',
      probeScript,
      '--',
      installPreconditions.daemonBin,
      stateFile,
      allowedUid,
      allowedUid,
      DEFAULT_SIGNER_BACKEND,
    ],
    {
      stdin: `${vaultPassword}\n`,
    },
  );
  if (result.code === 0) {
    return true;
  }

  const combinedOutput = `${result.stderr}\n${result.stdout}`.trim();
  if (isManagedStatePasswordMismatch(combinedOutput)) {
    return false;
  }
  throw new Error(
    combinedOutput ||
      `failed to validate the managed daemon state with the requested vault password (exit code ${result.code})`,
  );
}

async function assertManagedStateMatchesRequestedVaultPasswordBeforeInstall(
  config: WlfiConfig,
  daemonSocket: string,
  stateFile: string,
  vaultPassword: string,
  showProgress: boolean,
): Promise<void> {
  const stateExists = await inspectManagedState(
    stateFile,
    showProgress,
    'Inspecting managed daemon state before install',
  );
  if (!stateExists) {
    return;
  }

  const verifyProgress = createProgress(
    'Verifying the requested vault password against the managed daemon state',
    showProgress,
  );
  let accepted: boolean;
  try {
    accepted = await managedStateAcceptsRequestedVaultPassword(
      config,
      daemonSocket,
      stateFile,
      vaultPassword,
    );
  } catch (error) {
    verifyProgress.fail();
    throw error;
  }

  if (!accepted) {
    verifyProgress.fail('Existing daemon password does not unlock the stored daemon state');
    throw createManagedStatePasswordMismatchError(stateFile);
  }

  verifyProgress.succeed('Requested vault password unlocks the existing managed daemon state');
}

async function waitForTrustedDaemonSocket(targetPath: string, timeoutMs = 15_000): Promise<void> {
  async function canConnect(socketPath: string): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      const socket = net.createConnection(socketPath);
      let settled = false;

      const finish = (result: boolean) => {
        if (settled) {
          return;
        }
        settled = true;
        socket.destroy();
        resolve(result);
      };

      socket.once('connect', () => finish(true));
      socket.once('error', (error: NodeJS.ErrnoException) => {
        if (error.code === 'ECONNREFUSED' || error.code === 'ENOENT') {
          finish(false);
          return;
        }
        finish(false);
      });
      socket.setTimeout(500, () => finish(false));
    });
  }

  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const resolvedPath = assertTrustedAdminDaemonSocketPath(targetPath);
      if (await canConnect(resolvedPath)) {
        return;
      }
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 250));
  }

  const resolvedPath = assertTrustedAdminDaemonSocketPath(targetPath);
  if (!(await canConnect(resolvedPath))) {
    throw new Error(`daemon socket '${resolvedPath}' is present but not accepting connections yet`);
  }
}

function plistContainsValue(plistContents: string, value: string): boolean {
  return plistContents.includes(`<string>${value}</string>`);
}

export function launchDaemonPlistValue(
  plistContents: string,
  key: string,
): string | null {
  const escapedKey = key.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const match = plistContents.match(
    new RegExp(`<key>${escapedKey}</key>\\s*<string>([^<]+)</string>`, 'u'),
  );
  return match?.[1] ?? null;
}

function resolveInstalledLaunchDaemonPaths(
  config: WlfiConfig,
  plistContents: string,
): LaunchDaemonAssetPaths | null {
  const sourcePaths = resolveSourceLaunchDaemonPaths(config);
  const managedPaths = resolveManagedLaunchDaemonPaths();

  if (
    plistContainsValue(plistContents, sourcePaths.runnerPath) &&
    plistContainsValue(plistContents, sourcePaths.daemonBin) &&
    plistContainsValue(plistContents, sourcePaths.keychainHelperBin)
  ) {
    return sourcePaths;
  }

  if (
    plistContainsValue(plistContents, managedPaths.runnerPath) &&
    plistContainsValue(plistContents, managedPaths.daemonBin) &&
    plistContainsValue(plistContents, managedPaths.keychainHelperBin)
  ) {
    return managedPaths;
  }

  return null;
}

function isManagedDaemonInstallCurrent(
  config: WlfiConfig,
  daemonSocket: string,
  stateFile: string,
): boolean {
  const sourcePaths = resolveSourceLaunchDaemonPaths(config);
  const keychainAccount = os.userInfo().username;
  const expectedAdminUid = String(process.getuid?.() ?? process.geteuid?.() ?? 0);
  const expectedAgentUid = String(process.getuid?.() ?? process.geteuid?.() ?? 0);

  if (!fs.existsSync(DEFAULT_LAUNCH_DAEMON_PLIST)) {
    return false;
  }
  if (
    !fs.existsSync(sourcePaths.runnerPath) ||
    !fs.existsSync(sourcePaths.daemonBin) ||
    !fs.existsSync(sourcePaths.keychainHelperBin)
  ) {
    return false;
  }

  let plistContents: string;
  try {
    plistContents = fs.readFileSync(DEFAULT_LAUNCH_DAEMON_PLIST, 'utf8');
  } catch {
    return false;
  }

  const installedPaths = resolveInstalledLaunchDaemonPaths(config, plistContents);
  if (!installedPaths) {
    return false;
  }
  if (
    !fs.existsSync(installedPaths.runnerPath) ||
    !fs.existsSync(installedPaths.daemonBin) ||
    !fs.existsSync(installedPaths.keychainHelperBin)
  ) {
    return false;
  }
  if (!filesHaveIdenticalContents(sourcePaths.runnerPath, installedPaths.runnerPath)) {
    return false;
  }
  if (!filesHaveIdenticalContents(sourcePaths.daemonBin, installedPaths.daemonBin)) {
    return false;
  }
  if (
    !filesHaveIdenticalContents(sourcePaths.keychainHelperBin, installedPaths.keychainHelperBin)
  ) {
    return false;
  }

  if (
    launchDaemonPlistValue(plistContents, 'AGENTPAY_ALLOW_ADMIN_EUID') !== expectedAdminUid ||
    launchDaemonPlistValue(plistContents, 'AGENTPAY_ALLOW_AGENT_EUID') !== expectedAgentUid
  ) {
    return false;
  }

  return [
    DEFAULT_LAUNCH_DAEMON_LABEL,
    installedPaths.runnerPath,
    installedPaths.daemonBin,
    installedPaths.keychainHelperBin,
    daemonSocket,
    stateFile,
    DAEMON_PASSWORD_KEYCHAIN_SERVICE,
    keychainAccount,
    DEFAULT_SIGNER_BACKEND,
  ].every((value) => plistContainsValue(plistContents, value));
}

async function installLaunchDaemon(
  config: WlfiConfig,
  daemonSocket: string,
  stateFile: string,
  vaultPassword: string,
): Promise<ManagedDaemonInstallResult> {
  const installPreconditions = assertManagedDaemonInstallPreconditions(
    config,
    daemonSocket,
    stateFile,
  );
  const relayDaemonToken = process.env.AGENTPAY_RELAY_DAEMON_TOKEN?.trim();
  const installArgs =
    process.platform === 'linux'
      ? [
          installPreconditions.installScript,
          '--label',
          DEFAULT_LAUNCH_DAEMON_LABEL,
          '--runner',
          installPreconditions.runnerPath,
          '--daemon-bin',
          installPreconditions.daemonBin,
          '--password-helper',
          installPreconditions.keychainHelperBin,
          '--state-file',
          stateFile,
          '--daemon-socket',
          daemonSocket,
          '--password-file',
          MANAGED_DAEMON_SPEC.daemonPasswordFile ?? '/var/lib/agentpay/daemon-password',
          '--signer-backend',
          DEFAULT_SIGNER_BACKEND,
          '--allow-admin-euid',
          String(process.getuid?.() ?? process.geteuid?.() ?? 0),
          '--allow-agent-euid',
          String(process.getuid?.() ?? process.geteuid?.() ?? 0),
          '--vault-password-stdin',
        ]
      : [
          installPreconditions.installScript,
          '--label',
          DEFAULT_LAUNCH_DAEMON_LABEL,
          '--runner',
          installPreconditions.runnerPath,
          '--daemon-bin',
          installPreconditions.daemonBin,
          '--keychain-helper',
          installPreconditions.keychainHelperBin,
          '--state-file',
          stateFile,
          '--daemon-socket',
          daemonSocket,
          '--keychain-service',
          DAEMON_PASSWORD_KEYCHAIN_SERVICE,
          '--keychain-account',
          os.userInfo().username,
          '--signer-backend',
          DEFAULT_SIGNER_BACKEND,
          '--allow-admin-euid',
          String(process.getuid?.() ?? process.geteuid?.() ?? 0),
          '--allow-agent-euid',
          String(process.getuid?.() ?? process.geteuid?.() ?? 0),
          '--vault-password-stdin',
        ];

  const installResult = await sudoSession.run(installArgs, {
    env: relayDaemonToken
      ? {
          AGENTPAY_RELAY_DAEMON_TOKEN: relayDaemonToken,
        }
      : undefined,
    stdin: `${vaultPassword}\n`,
    inheritOutput: true,
  });
  if (installResult.code !== 0) {
    throw new Error(
      installResult.stderr.trim() ||
        installResult.stdout.trim() ||
        `sudo exited with code ${installResult.code}`,
    );
  }

  return {
    label: DEFAULT_LAUNCH_DAEMON_LABEL,
    runnerPath: installPreconditions.managedRunnerPath,
    daemonBin: installPreconditions.managedDaemonBin,
    stateFile,
    serviceManager: MANAGED_DAEMON_SPEC.serviceManager,
    ...(process.platform === 'linux'
      ? {
          passwordFile: MANAGED_DAEMON_SPEC.daemonPasswordFile ?? '/var/lib/agentpay/daemon-password',
        }
      : {
          keychainAccount: os.userInfo().username,
          keychainService: DAEMON_PASSWORD_KEYCHAIN_SERVICE,
        }),
  };
}

async function runAdminSetup(options: AdminSetupOptions): Promise<void> {
  assertManagedDaemonPlatform(
    '`agentpay admin setup`',
    'The current setup flow installs a root-managed daemon and imports credentials into local credential storage.',
  );

  if (options.plan) {
    const plan = createAdminSetupPlan(options);
    printCliPayload(options.json ? plan : formatAdminSetupPlanText(plan), options.json ?? false);
    return;
  }

  resolveAdminSetupRestoreConflictErrors(options);
  if (options.rpcUrl && !options.network) {
    throw new Error('--rpc-url requires --network');
  }
  if (options.chainName && !options.network) {
    throw new Error('--chain-name requires --network');
  }

  const config = readConfig();
  const daemonSocket = resolveDaemonSocket(options.daemonSocket);
  const stateFile = resolveStateFile();
  const defaultActiveChain = shouldSeedDefaultActiveChain(options, config)
    ? resolveDefaultActiveChainForFreshSetup(config)
    : null;
  const reusableWallet = resolveRequestedReusableWalletSetupTarget(options, config);
  const effectiveReuseExistingWallet = reusableWallet !== null;
  const createdFreshWallet = !effectiveReuseExistingWallet && !options.restoreWalletFrom;
  assertManagedDaemonInstallPreconditions(config, daemonSocket, stateFile);
  await confirmAdminSetupOverwrite(
    {
      yes: options.yes,
      nonInteractive: options.nonInteractive,
      reuseExistingWallet: effectiveReuseExistingWallet,
    },
    config,
  );
  const vaultPassword = await resolveAdminSetupVaultPassword(options);
  const restoredBackupMaterial = options.restoreWalletFrom
    ? decryptWalletBackup(
        readWalletBackupFile(options.restoreWalletFrom),
        await resolveAdminSetupBackupPassword(options, false),
      )
    : null;
  const showProgress = !options.json;
  let temporaryImportKeyFile: string | null = null;

  const existingDaemonProgress = createProgress('Checking existing daemon', showProgress);
  const plistContents = process.platform === 'darwin' && fs.existsSync(DEFAULT_LAUNCH_DAEMON_PLIST)
    ? fs.readFileSync(DEFAULT_LAUNCH_DAEMON_PLIST, 'utf8')
    : null;
  const installedPaths = plistContents
    ? resolveInstalledLaunchDaemonPaths(config, plistContents)
    : null;

  let daemon: ManagedDaemonInstallResult | null = null;
  let installIsCurrent =
    process.platform === 'darwin' && isManagedDaemonInstallCurrent(config, daemonSocket, stateFile);
  let existingDaemonRejectedPassword = false;
  let existingDaemonResponding = false;

  try {
    await waitForTrustedDaemonSocket(daemonSocket, 1_500);
    existingDaemonResponding = true;
    const accepted = await daemonAcceptsVaultPassword(config, daemonSocket, vaultPassword);
    if (accepted) {
      installIsCurrent = true;
      daemon = {
        label: DEFAULT_LAUNCH_DAEMON_LABEL,
        runnerPath: installedPaths?.runnerPath ?? resolveManagedLaunchDaemonPaths().runnerPath,
        daemonBin: installedPaths?.daemonBin ?? resolveManagedLaunchDaemonPaths().daemonBin,
        stateFile,
        serviceManager: MANAGED_DAEMON_SPEC.serviceManager,
        ...(process.platform === 'linux'
          ? {
              passwordFile:
                MANAGED_DAEMON_SPEC.daemonPasswordFile ?? '/var/lib/agentpay/daemon-password',
            }
          : {
              keychainAccount: os.userInfo().username,
              keychainService: DAEMON_PASSWORD_KEYCHAIN_SERVICE,
            }),
      };
      existingDaemonProgress.succeed('Existing daemon is ready and accepted the vault password');
    } else {
      existingDaemonRejectedPassword = true;
      existingDaemonProgress.succeed(
        'Existing daemon is running but needs password recovery or reinstall',
      );
    }
  } catch {
    existingDaemonProgress.succeed('No ready daemon detected; checking installation state');
  }

  if (!daemon) {
    if (installIsCurrent && existingDaemonResponding) {
      const currentPlistContents = fs.readFileSync(DEFAULT_LAUNCH_DAEMON_PLIST, 'utf8');
      const currentInstalledPaths =
        resolveInstalledLaunchDaemonPaths(config, currentPlistContents) ??
        resolveManagedLaunchDaemonPaths();
      daemon = {
        label: DEFAULT_LAUNCH_DAEMON_LABEL,
        runnerPath: currentInstalledPaths.runnerPath,
        daemonBin: currentInstalledPaths.daemonBin,
        stateFile,
        serviceManager: MANAGED_DAEMON_SPEC.serviceManager,
        ...(process.platform === 'linux'
          ? {
              passwordFile:
                MANAGED_DAEMON_SPEC.daemonPasswordFile ?? '/var/lib/agentpay/daemon-password',
            }
          : {
              keychainAccount: os.userInfo().username,
              keychainService: DAEMON_PASSWORD_KEYCHAIN_SERVICE,
            }),
      };
      const installProgress = createProgress('Checking existing daemon installation', showProgress);
      installProgress.succeed('Existing daemon install looks current');
    } else {
      if (installIsCurrent && !existingDaemonResponding && !options.json) {
        process.stderr.write(
          'Existing daemon install metadata looks current, but the daemon is not responding; setup will recover it now.\n',
        );
      }
      if (!options.json && typeof process.geteuid === 'function' && process.geteuid() !== 0) {
        process.stderr.write(
          'System admin password required: setup uses sudo to install or recover the root-managed daemon.\n',
        );
      }
      await sudoSession.prime();
      await assertManagedStateMatchesRequestedVaultPasswordBeforeInstall(
        config,
        daemonSocket,
        stateFile,
        vaultPassword,
        showProgress,
      );
      const installProgress = createProgress('Installing and restarting daemon', showProgress);
      try {
        daemon = await installLaunchDaemon(config, daemonSocket, stateFile, vaultPassword);
        installProgress.succeed('Daemon installed and restarted');
      } catch (error) {
        installProgress.fail();
        throw error;
      }
    }
  }

  const readyProgress = createProgress('Waiting for daemon to become ready', showProgress);
  try {
    await waitForTrustedDaemonSocket(daemonSocket);
    readyProgress.succeed('Daemon is ready');
  } catch (error) {
    readyProgress.fail();
    throw error;
  }

  const authProgress = createProgress('Verifying daemon vault password', showProgress);
  let daemonAcceptedPassword: boolean;
  try {
    daemonAcceptedPassword = await daemonAcceptsVaultPassword(config, daemonSocket, vaultPassword);
  } catch (error) {
    authProgress.fail();
    throw error;
  }

  if (!daemonAcceptedPassword) {
    if (existingDaemonRejectedPassword) {
      authProgress.fail('Existing daemon password does not unlock the stored daemon state');
      throw createManagedStatePasswordMismatchError(stateFile);
    }

    authProgress.info('Daemon rejected the requested vault password; inspecting managed state');
    const stateExists = await inspectManagedState(stateFile, showProgress);

    if (stateExists) {
      authProgress.fail('Existing daemon password does not unlock the stored daemon state');
      throw createManagedStatePasswordMismatchError(stateFile);
    }

    authProgress.fail(
      'Existing daemon password differs; reinstalling with the requested vault password',
    );

    if (!options.json && typeof process.geteuid === 'function' && process.geteuid() !== 0) {
      process.stderr.write(
        'System admin password required: setup uses sudo to reinstall the root-managed daemon and rotate the managed daemon password.\n',
      );
    }
    await sudoSession.prime();
    const reinstallProgress = createProgress(
      'Reinstalling daemon with the requested vault password',
      showProgress,
    );
    try {
      daemon = await installLaunchDaemon(config, daemonSocket, stateFile, vaultPassword);
      reinstallProgress.succeed('Daemon reinstalled and restarted');
    } catch (error) {
      reinstallProgress.fail();
      throw error;
    }

    const restartedReadyProgress = createProgress(
      'Waiting for restarted daemon to become ready',
      showProgress,
    );
    try {
      await waitForTrustedDaemonSocket(daemonSocket);
      restartedReadyProgress.succeed('Restarted daemon is ready');
    } catch (error) {
      restartedReadyProgress.fail();
      throw error;
    }

    const retryAuthProgress = createProgress('Re-checking daemon vault password', showProgress);
    let retryAcceptedPassword: boolean;
    try {
      retryAcceptedPassword = await daemonAcceptsVaultPassword(config, daemonSocket, vaultPassword);
    } catch (error) {
      retryAuthProgress.fail();
      throw error;
    }

    if (!retryAcceptedPassword) {
      retryAuthProgress.fail();
      throw new Error(
        'the managed daemon still rejects the requested vault password. Re-run setup with the original vault password, or clear the managed daemon state before initializing a fresh wallet.',
      );
    }

    retryAuthProgress.succeed('Daemon accepted the requested vault password');
  } else {
    authProgress.succeed('Daemon accepted the requested vault password');
  }

  writeConfig({
    daemonSocket,
    stateFile,
  });

  const resolvedNetwork = options.network
    ? resolveCliNetworkProfile(options.network, config)
    : null;
  const resolvedNetworkId = resolvedNetwork?.chainId;
  const resolvedChainName = options.chainName?.trim() || resolvedNetwork?.name;

  assertWalletSetupExecutionPreconditions(
    {
      daemonSocket,
      network: resolvedNetworkId,
      rpcUrl: options.rpcUrl,
    },
    config,
    {
      assertTrustedDaemonSocketPath: assertTrustedAdminDaemonSocketPath,
    },
  );

  const bootstrapOutput = resolveWalletSetupBootstrapOutputPath(options.bootstrapOutput);
  try {
    if (restoredBackupMaterial) {
      temporaryImportKeyFile = writeTemporaryWalletImportKeyFile(
        restoredBackupMaterial.privateKeyHex,
      );
    }

    const bootstrapInvocation = buildAdminSetupBootstrapInvocation({
      vaultPassword,
      daemonSocket,
      perTxMaxWei: options.perTxMaxWei,
      dailyMaxWei: options.dailyMaxWei,
      weeklyMaxWei: options.weeklyMaxWei,
      maxGasPerChainWei: options.maxGasPerChainWei,
      dailyMaxTxCount: options.dailyMaxTxCount,
      perTxMaxFeePerGasWei: options.perTxMaxFeePerGasWei,
      perTxMaxPriorityFeePerGasWei: options.perTxMaxPriorityFeePerGasWei,
      perTxMaxCalldataBytes: options.perTxMaxCalldataBytes,
      token: options.token,
      allowNativeEth: options.allowNativeEth,
      network: resolvedNetworkId !== undefined ? String(resolvedNetworkId) : undefined,
      recipient: options.recipient,
      attachPolicyId: options.attachPolicyId,
      attachBootstrapPolicies: options.attachBootstrapPolicies,
      existingVaultKeyId: reusableWallet?.existingVaultKeyId,
      existingVaultPublicKey: reusableWallet?.existingVaultPublicKey,
      importVaultPrivateKeyFile: temporaryImportKeyFile ?? undefined,
      bootstrapOutputPath: bootstrapOutput.path,
    });

    const bootstrapProgress = createProgress('Setting up wallet access', showProgress);
    try {
      await runRustBinary('agentpay-admin', bootstrapInvocation.args, config, {
        stdin: bootstrapInvocation.stdin,
        preSuppliedSecretStdin: 'vaultPassword',
        scrubSensitiveEnv: true,
      });
    } catch (error) {
      bootstrapProgress.fail();
      try {
        const cleanup = cleanupBootstrapAgentCredentialsFile(
          bootstrapOutput.path,
          resolveWalletSetupCleanupAction(
            bootstrapOutput.autoGenerated,
            options.deleteBootstrapOutput ?? false,
          ),
        );
        if (cleanup.action === 'failed') {
          console.error(
            `warning: failed to scrub bootstrap output after setup failure: ${cleanup.error}`,
          );
        }
      } catch (error) {
        console.error(
          `warning: failed to scrub bootstrap output after setup failure: ${renderError(error)}`,
        );
      }
      if (error instanceof RustBinaryExitError) {
        const output = error.stderr || error.stdout;
        if (output) {
          process.stderr.write(output.endsWith('\n') ? output : `${output}\n`);
        }
        process.exitCode = error.code;
        return;
      }
      throw error;
    }
    bootstrapProgress.succeed('Bootstrap completed');

    const finalizeProgress = createProgress('Importing agent token and saving config', showProgress);
    let summary: CompleteWalletSetupResult;
    try {
      summary = completeWalletSetup({
        bootstrapOutputPath: bootstrapOutput.path,
        cleanupAction: resolveWalletSetupCleanupAction(
          bootstrapOutput.autoGenerated,
          options.deleteBootstrapOutput ?? false,
        ),
        daemonSocket,
        perTxMaxWei: options.perTxMaxWei,
        dailyMaxWei: options.dailyMaxWei,
        weeklyMaxWei: options.weeklyMaxWei,
        maxGasPerChainWei: options.maxGasPerChainWei,
        dailyMaxTxCount: options.dailyMaxTxCount,
        perTxMaxFeePerGasWei: options.perTxMaxFeePerGasWei,
        perTxMaxPriorityFeePerGasWei: options.perTxMaxPriorityFeePerGasWei,
        perTxMaxCalldataBytes: options.perTxMaxCalldataBytes,
        token: options.token,
        allowNativeEth: options.allowNativeEth,
        network: resolvedNetworkId,
        recipient: options.recipient,
        attachPolicyId: options.attachPolicyId,
        attachBootstrapPolicies: options.attachBootstrapPolicies,
        rpcUrl: options.rpcUrl,
        chainName: resolvedChainName,
      });
      finalizeProgress.succeed('Agent token imported and config saved');
    } catch (error) {
      finalizeProgress.fail();
      throw error;
    }

    const persistedConfig = writeConfig({
      daemonSocket,
      stateFile,
      ...(defaultActiveChain
        ? {
            chainId: defaultActiveChain.chainId,
            chainName: defaultActiveChain.chainName,
            ...(defaultActiveChain.rpcUrl ? { rpcUrl: defaultActiveChain.rpcUrl } : {}),
          }
        : {}),
    });

    const walletAddress = deriveWalletAddress(summary.vaultPublicKey);
    let walletBackup: WalletBackupExportResult | undefined;
    const walletBackupRequest = walletAddress
      ? await resolvePostSetupWalletBackupRequest({
          options,
          createdFreshWallet,
        })
      : options.backupOutput
        ? {
            outputPath: path.resolve(options.backupOutput),
            overwrite: Boolean(options.backupOverwrite),
          }
        : null;

    if (walletBackupRequest) {
      try {
        const backupPassword = await resolveAdminSetupBackupPassword(options, true);
        const exported = await exportEncryptedWalletBackup({
          daemonSocket,
          vaultPassword,
          backupPassword,
          outputPath: walletBackupRequest.outputPath,
          overwrite: walletBackupRequest.overwrite,
          config: persistedConfig,
        });
        walletBackup = {
          status: 'created',
          outputPath: exported.outputPath,
          createdAt: exported.createdAt,
          address: exported.address,
          sourceVaultKeyId: exported.sourceVaultKeyId,
          reminderCommand: renderWalletBackupCommand(exported.outputPath),
        };
      } catch (error) {
        process.exitCode = 1;
        walletBackup = {
          status: 'failed',
          outputPath: walletBackupRequest.outputPath,
          address: walletAddress,
          error: renderError(error),
          reminderCommand: renderWalletBackupCommand(walletBackupRequest.outputPath),
        };
      }
    } else if (createdFreshWallet && walletAddress) {
      const suggestedOutputPath = defaultWalletBackupOutputPath(walletAddress);
      walletBackup = {
        status: 'not-created',
        address: walletAddress,
        outputPath: suggestedOutputPath,
        reminderCommand: renderWalletBackupCommand(suggestedOutputPath),
      };
    }

    printCliPayload(
      {
        command: 'setup',
        daemon: {
          autostart: true,
          label: daemon.label,
          serviceManager: daemon.serviceManager,
          daemonSocket,
          stateFile: daemon.stateFile,
          runnerPath: daemon.runnerPath,
          daemonBinary: daemon.daemonBin,
          signerBackend: DEFAULT_SIGNER_BACKEND,
          keychainService: daemon.keychainService,
          keychainAccount: daemon.keychainAccount,
          passwordFile: daemon.passwordFile,
        },
        ...summary,
        ...(walletBackup ? { walletBackup } : {}),
        config: redactConfig(persistedConfig),
      },
      options.json ?? false,
      options.printAgentAuthToken ?? false,
    );
  } finally {
    const cleanup = cleanupTemporaryWalletImportKeyFile(temporaryImportKeyFile);
    if (cleanup.action === 'failed') {
      console.error(`warning: failed to delete temporary wallet import key file: ${cleanup.error}`);
    }
  }
}

export function buildAdminTuiPassthroughArgs(input: {
  daemonSocket?: string;
  bootstrapOutputPath: string;
}): string[] {
  const args = ['--json', '--quiet', '--output', input.bootstrapOutputPath];
  if (input.daemonSocket) {
    args.push('--daemon-socket', input.daemonSocket);
  }
  args.push('tui', '--print-agent-auth-token');
  return args;
}

export function buildAdminSetupBootstrapInvocation(input: {
  vaultPassword: string;
  daemonSocket: string;
  perTxMaxWei?: string;
  dailyMaxWei?: string;
  weeklyMaxWei?: string;
  maxGasPerChainWei?: string;
  dailyMaxTxCount?: string;
  perTxMaxFeePerGasWei?: string;
  perTxMaxPriorityFeePerGasWei?: string;
  perTxMaxCalldataBytes?: string;
  token?: string[];
  allowNativeEth?: boolean;
  network?: string;
  recipient?: string;
  attachPolicyId?: string[];
  attachBootstrapPolicies?: boolean;
  existingVaultKeyId?: string;
  existingVaultPublicKey?: string;
  importVaultPrivateKeyFile?: string;
  bootstrapOutputPath: string;
}): { args: string[]; stdin: string } {
  return {
    args: buildWalletSetupAdminArgs({
      vaultPasswordStdin: true,
      nonInteractive: true,
      daemonSocket: input.daemonSocket,
      perTxMaxWei: input.perTxMaxWei,
      dailyMaxWei: input.dailyMaxWei,
      weeklyMaxWei: input.weeklyMaxWei,
      maxGasPerChainWei: input.maxGasPerChainWei,
      dailyMaxTxCount: input.dailyMaxTxCount,
      perTxMaxFeePerGasWei: input.perTxMaxFeePerGasWei,
      perTxMaxPriorityFeePerGasWei: input.perTxMaxPriorityFeePerGasWei,
      perTxMaxCalldataBytes: input.perTxMaxCalldataBytes,
      token: input.token,
      allowNativeEth: input.allowNativeEth,
      network: input.network,
      recipient: input.recipient,
      attachPolicyId: input.attachPolicyId,
      attachBootstrapPolicies: input.attachBootstrapPolicies,
      existingVaultKeyId: input.existingVaultKeyId,
      existingVaultPublicKey: input.existingVaultPublicKey,
      importVaultPrivateKeyFile: input.importVaultPrivateKeyFile,
      bootstrapOutputPath: input.bootstrapOutputPath,
    }),
    stdin: `${validateSecret(input.vaultPassword, 'vault password')}\n`,
  };
}

async function runAdminTui(options: AdminTuiOptions): Promise<void> {
  assertManagedDaemonPlatform(
    '`agentpay admin tui`',
    'The current TUI flow refreshes local wallet credentials through managed daemon setup helpers.',
  );

  const config = backfillPersistedWalletProfileForTui(readConfig());

  const daemonSocket = options.daemonSocket ? resolveDaemonSocket(options.daemonSocket) : undefined;
  const bootstrapOutput = resolveWalletSetupBootstrapOutputPath(options.bootstrapOutput);
  const cleanupAction = resolveWalletSetupCleanupAction(
    bootstrapOutput.autoGenerated,
    options.deleteBootstrapOutput ?? false,
  );

  const code = await passthroughRustBinary(
    'agentpay-admin',
    buildAdminTuiPassthroughArgs({
      daemonSocket,
      bootstrapOutputPath: bootstrapOutput.path,
    }),
    config,
  );
  if (code !== 0) {
    try {
      const cleanup = cleanupBootstrapAgentCredentialsFile(bootstrapOutput.path, cleanupAction);
      if (cleanup.action === 'failed') {
        console.error(
          `warning: failed to scrub bootstrap output after tui failure: ${cleanup.error}`,
        );
      }
    } catch (error) {
      console.error(
        `warning: failed to scrub bootstrap output after tui failure: ${renderError(error)}`,
      );
    }
    process.exitCode = code;
    return;
  }

  if (!fs.existsSync(bootstrapOutput.path)) {
    printCliPayload(
      options.json ? { command: 'tui', canceled: true } : 'tui canceled',
      options.json ?? false,
    );
    return;
  }

  const summary = completeWalletSetup({
    bootstrapOutputPath: bootstrapOutput.path,
    cleanupAction,
    daemonSocket,
  });

  printCliPayload(
    {
      command: 'tui',
      ...summary,
    },
    options.json ?? false,
    options.printAgentAuthToken ?? false,
  );
}

export async function runAdminSetupCli(argv: string[]): Promise<void> {
  const program = new Command();
  program
    .name('agentpay admin setup')
    .description(
      'Store the vault password, install the root daemon autostart, set up wallet access, and print the wallet address',
    )
    .option('--plan', 'Print a sanitized setup preview without prompting or mutating state', false)
    .option('--vault-password-stdin', 'Read vault password from stdin', false)
    .option('--backup-password-stdin', 'Read wallet backup password from stdin', false)
    .option('--non-interactive', 'Disable password prompts', false)
    .option('-y, --yes', 'Skip the overwrite confirmation prompt', false)
    .option(
      '--reuse-existing-wallet',
      'Reuse the current local vault instead of generating a fresh wallet',
      false,
    )
    .option('--restore-wallet-from <path>', 'Restore the wallet from an encrypted offline backup')
    .option(
      '--backup-output <path>',
      'Create an encrypted offline wallet backup at this path after setup',
    )
    .option('--backup-overwrite', 'Allow replacing an existing wallet backup file', false)
    .option('--daemon-socket <path>', 'Daemon unix socket path')
    .option('--per-tx-max-wei <wei>', 'Per-transaction max spend in wei')
    .option('--daily-max-wei <wei>', 'Daily max spend in wei')
    .option('--weekly-max-wei <wei>', 'Weekly max spend in wei')
    .option('--max-gas-per-chain-wei <wei>', 'Per-chain gas-spend ceiling in wei')
    .option('--daily-max-tx-count <count>', 'Optional daily tx-count cap')
    .option('--per-tx-max-fee-per-gas-wei <wei>', 'Optional max fee-per-gas cap')
    .option('--per-tx-max-priority-fee-per-gas-wei <wei>', 'Optional max priority fee-per-gas cap')
    .option('--per-tx-max-calldata-bytes <bytes>', 'Optional calldata size cap')
    .option(
      '--token <address>',
      'Allowed ERC-20 token address',
      (value, acc: string[]) => {
        acc.push(value);
        return acc;
      },
      [],
    )
    .option('--allow-native-eth', 'Allow native ETH transfers', false)
    .option('--network <name>', 'Network name for policy scope and active config')
    .option('--rpc-url <url>', 'Persist RPC URL for the configured active chain')
    .option('--chain-name <name>', 'Persist chain display name for the active chain')
    .option('--recipient <address>', 'Optional allowed recipient scope')
    .option(
      '--attach-policy-id <uuid>',
      'Attach the new agent key to an existing policy id',
      (value, acc: string[]) => {
        acc.push(value);
        return acc;
      },
      [],
    )
    .option(
      '--attach-bootstrap-policies',
      'Attach the refreshed agent key to the current enabled daemon policies',
      false,
    )
    .option('--bootstrap-output <path>', 'Write temporary bootstrap JSON to this private path')
    .option('--delete-bootstrap-output', 'Delete the bootstrap JSON after local credential import', false)
    .option(
      '--print-agent-auth-token',
      'Print the freshly issued agent auth token after importing it into local credential storage',
      false,
    )
    .option('--json', 'Print JSON output', false)
    .action(runAdminSetup);

  await program.parseAsync(argv, { from: 'user' });
}

export async function runAdminTuiCli(argv: string[]): Promise<void> {
  const program = new Command();
  program
    .name('agentpay admin tui')
    .description(
      'Launch the interactive terminal UI, then import the new agent token and activate the new wallet locally',
    )
    .option('--daemon-socket <path>', 'Daemon unix socket path')
    .option('--bootstrap-output <path>', 'Write temporary bootstrap JSON to this private path')
    .option('--delete-bootstrap-output', 'Delete the bootstrap JSON after local credential import', false)
    .option(
      '--print-agent-auth-token',
      'Print the freshly issued agent auth token after importing it into local credential storage',
      false,
    )
    .option('--json', 'Print JSON output', false)
    .action(runAdminTui);

  await program.parseAsync(argv, { from: 'user' });
}
