import fs from 'node:fs';
import path from 'node:path';
import type { WalletKeyAlgorithm } from '../../packages/config/src/index.js';
import { assertValidAgentAuthToken } from './agent-auth-token.js';
import {
  assertPrivateFileStats,
  assertTrustedDirectoryPath,
  readUtf8FileSecure,
} from './fs-trust.js';
import { assertValidAgentKeyId } from './keychain.js';

const PRIVATE_FILE_MODE = 0o600;
const REDACTED_SECRET_PLACEHOLDER = '<redacted>';
const MAX_BOOTSTRAP_FILE_BYTES = 256 * 1024;

export interface BootstrapAgentCredentials {
  agentKeyId: string;
  agentAuthToken: string;
  sourcePath: string;
}

export interface BootstrapCredentialsCleanupResult {
  sourcePath: string;
}

export interface BootstrapCredentialsCleanupFailureResult
  extends BootstrapCredentialsCleanupResult {
  action: 'failed';
  error: string;
}

export type BootstrapCredentialsBestEffortCleanupResult =
  | (BootstrapCredentialsCleanupResult & {
      action: 'deleted' | 'redacted' | 'missing';
    })
  | BootstrapCredentialsCleanupFailureResult;

export interface BootstrapSetupFileContents {
  summary: BootstrapSetupSummary;
  credentials: BootstrapAgentCredentials;
}

export interface BootstrapDestinationOverrideSummary {
  recipient: string;
  perTxPolicyId: string;
  dailyPolicyId: string;
  weeklyPolicyId: string;
  gasPolicyId: string | null;
  perTxMaxWei: string;
  dailyMaxWei: string;
  weeklyMaxWei: string;
  maxGasPerChainWei: string | null;
  dailyMaxTxCount: string | null;
  dailyTxCountPolicyId: string | null;
  perTxMaxFeePerGasWei: string | null;
  perTxMaxFeePerGasPolicyId: string | null;
  perTxMaxPriorityFeePerGasWei: string | null;
  perTxMaxPriorityFeePerGasPolicyId: string | null;
  perTxMaxCalldataBytes: string | null;
  perTxMaxCalldataBytesPolicyId: string | null;
}

export interface BootstrapTokenPolicySummary {
  tokenKey: string;
  symbol: string;
  chainKey: string;
  chainId: number;
  assetScope: string;
  recipientScope: string;
  perTxPolicyId: string;
  dailyPolicyId: string;
  weeklyPolicyId: string;
  gasPolicyId: string | null;
  perTxMaxWei: string;
  dailyMaxWei: string;
  weeklyMaxWei: string;
  maxGasPerChainWei: string | null;
  dailyMaxTxCount: string | null;
  dailyTxCountPolicyId: string | null;
  perTxMaxFeePerGasWei: string | null;
  perTxMaxFeePerGasPolicyId: string | null;
  perTxMaxPriorityFeePerGasWei: string | null;
  perTxMaxPriorityFeePerGasPolicyId: string | null;
  perTxMaxCalldataBytes: string | null;
  perTxMaxCalldataBytesPolicyId: string | null;
}

export interface BootstrapTokenDestinationOverrideSummary {
  tokenKey: string;
  symbol: string;
  chainKey: string;
  chainId: number;
  recipient: string;
  assetScope: string;
  perTxPolicyId: string;
  dailyPolicyId: string;
  weeklyPolicyId: string;
  gasPolicyId: string | null;
  perTxMaxWei: string;
  dailyMaxWei: string;
  weeklyMaxWei: string;
  maxGasPerChainWei: string | null;
  dailyMaxTxCount: string | null;
  dailyTxCountPolicyId: string | null;
  perTxMaxFeePerGasWei: string | null;
  perTxMaxFeePerGasPolicyId: string | null;
  perTxMaxPriorityFeePerGasWei: string | null;
  perTxMaxPriorityFeePerGasPolicyId: string | null;
  perTxMaxCalldataBytes: string | null;
  perTxMaxCalldataBytesPolicyId: string | null;
}

export interface BootstrapTokenManualApprovalPolicySummary {
  tokenKey: string;
  symbol: string;
  chainKey: string;
  chainId: number;
  priority: number;
  minAmountWei: string;
  maxAmountWei: string;
  assetScope: string;
  recipientScope: string;
  policyId: string;
}

export interface BootstrapSetupSummary {
  sourcePath: string;
  leaseId: string;
  leaseExpiresAt: string;
  perTxPolicyId: string | null;
  dailyPolicyId: string | null;
  weeklyPolicyId: string | null;
  gasPolicyId: string | null;
  perTxMaxWei: string | null;
  dailyMaxWei: string | null;
  weeklyMaxWei: string | null;
  maxGasPerChainWei: string | null;
  dailyMaxTxCount: string | null;
  dailyTxCountPolicyId: string | null;
  perTxMaxFeePerGasWei: string | null;
  perTxMaxFeePerGasPolicyId: string | null;
  perTxMaxPriorityFeePerGasWei: string | null;
  perTxMaxPriorityFeePerGasPolicyId: string | null;
  perTxMaxCalldataBytes: string | null;
  perTxMaxCalldataBytesPolicyId: string | null;
  vaultKeyId: string;
  vaultKeyAlgorithm: WalletKeyAlgorithm;
  vaultPublicKey: string;
  solanaPublicKey: string | null;
  solanaAddress: string | null;
  vaultPrivateKey: string | null;
  agentKeyId: string;
  networkScope: string | null;
  assetScope: string | null;
  recipientScope: string | null;
  destinationOverrideCount: number;
  destinationOverrides: BootstrapDestinationOverrideSummary[];
  tokenPolicies: BootstrapTokenPolicySummary[];
  tokenDestinationOverrides: BootstrapTokenDestinationOverrideSummary[];
  tokenManualApprovalPolicies: BootstrapTokenManualApprovalPolicySummary[];
  policyAttachment: string;
  attachedPolicyIds: string[];
  policyNote: string;
}

export interface BootstrapLeaseValidationDeps {
  now?: () => number;
}

function renderError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function resolveInputPath(inputPath: string): string {
  const normalized = inputPath.trim();
  if (!normalized) {
    throw new Error('bootstrap credentials file path is required');
  }
  return path.resolve(normalized);
}

function assertJsonRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must contain a JSON object`);
  }
  return value as Record<string, unknown>;
}

function readRequiredString(
  payload: Record<string, unknown>,
  fieldNames: string[],
  label: string,
  options: { trim?: boolean } = {},
): string {
  for (const fieldName of fieldNames) {
    const value = payload[fieldName];
    if (typeof value !== 'string') {
      continue;
    }

    const normalized = options.trim === false ? value : value.trim();
    if (normalized.length > 0) {
      return normalized;
    }
    break;
  }

  throw new Error(`${label} is required in bootstrap credentials file`);
}

function readOptionalBoolean(
  payload: Record<string, unknown>,
  fieldNames: string[],
): boolean | null {
  for (const fieldName of fieldNames) {
    const value = payload[fieldName];
    if (value === undefined) {
      continue;
    }
    if (typeof value !== 'boolean') {
      throw new Error(`${fieldName} must be a boolean in bootstrap credentials file`);
    }
    return value;
  }
  return null;
}

function readOptionalString(payload: Record<string, unknown>, fieldNames: string[]): string | null {
  for (const fieldName of fieldNames) {
    const value = payload[fieldName];
    if (value === undefined || value === null) {
      continue;
    }
    if (typeof value !== 'string') {
      throw new Error(`${fieldName} must be a string in bootstrap credentials file`);
    }

    const normalized = value.trim();
    return normalized.length > 0 ? normalized : null;
  }

  return null;
}

function readOptionalStringArray(payload: Record<string, unknown>, fieldNames: string[]): string[] {
  for (const fieldName of fieldNames) {
    const value = payload[fieldName];
    if (value === undefined || value === null) {
      continue;
    }
    if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
      throw new Error(`${fieldName} must be an array of strings in bootstrap credentials file`);
    }

    return value.map((entry) => entry.trim()).filter((entry) => entry.length > 0);
  }

  return [];
}

function readOptionalNumber(payload: Record<string, unknown>, fieldNames: string[]): number | null {
  for (const fieldName of fieldNames) {
    const value = payload[fieldName];
    if (value === undefined || value === null) {
      continue;
    }
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      throw new Error(`${fieldName} must be a number in bootstrap credentials file`);
    }
    return value;
  }
  return null;
}

function readRequiredNumber(
  payload: Record<string, unknown>,
  fieldNames: string[],
  label: string,
): number {
  const value = readOptionalNumber(payload, fieldNames);
  if (value === null) {
    throw new Error(`${label} is required in bootstrap credentials file`);
  }
  return value;
}

function readOptionalRecordArray(
  payload: Record<string, unknown>,
  fieldNames: string[],
): Record<string, unknown>[] {
  for (const fieldName of fieldNames) {
    const value = payload[fieldName];
    if (value === undefined || value === null) {
      continue;
    }
    if (!Array.isArray(value)) {
      throw new Error(`${fieldName} must be an array in bootstrap credentials file`);
    }
    return value.map((entry, index) => assertJsonRecord(entry, `${fieldName}[${index}]`));
  }
  return [];
}

function readDestinationOverrideSummary(
  payload: Record<string, unknown>,
  label: string,
): BootstrapDestinationOverrideSummary {
  return {
    recipient: readRequiredString(payload, ['recipient'], `${label}.recipient`),
    perTxPolicyId: readRequiredString(
      payload,
      ['per_tx_policy_id', 'perTxPolicyId'],
      `${label}.per_tx_policy_id`,
    ),
    dailyPolicyId: readRequiredString(
      payload,
      ['daily_policy_id', 'dailyPolicyId'],
      `${label}.daily_policy_id`,
    ),
    weeklyPolicyId: readRequiredString(
      payload,
      ['weekly_policy_id', 'weeklyPolicyId'],
      `${label}.weekly_policy_id`,
    ),
    gasPolicyId: readOptionalString(payload, ['gas_policy_id', 'gasPolicyId']),
    perTxMaxWei: readRequiredString(
      payload,
      ['per_tx_max_wei', 'perTxMaxWei'],
      `${label}.per_tx_max_wei`,
    ),
    dailyMaxWei: readRequiredString(
      payload,
      ['daily_max_wei', 'dailyMaxWei'],
      `${label}.daily_max_wei`,
    ),
    weeklyMaxWei: readRequiredString(
      payload,
      ['weekly_max_wei', 'weeklyMaxWei'],
      `${label}.weekly_max_wei`,
    ),
    maxGasPerChainWei: readOptionalString(payload, ['max_gas_per_chain_wei', 'maxGasPerChainWei']),
    dailyMaxTxCount: readOptionalString(payload, ['daily_max_tx_count', 'dailyMaxTxCount']),
    dailyTxCountPolicyId: readOptionalString(payload, [
      'daily_tx_count_policy_id',
      'dailyTxCountPolicyId',
    ]),
    perTxMaxFeePerGasWei: readOptionalString(payload, [
      'per_tx_max_fee_per_gas_wei',
      'perTxMaxFeePerGasWei',
    ]),
    perTxMaxFeePerGasPolicyId: readOptionalString(payload, [
      'per_tx_max_fee_per_gas_policy_id',
      'perTxMaxFeePerGasPolicyId',
    ]),
    perTxMaxPriorityFeePerGasWei: readOptionalString(payload, [
      'per_tx_max_priority_fee_per_gas_wei',
      'perTxMaxPriorityFeePerGasWei',
    ]),
    perTxMaxPriorityFeePerGasPolicyId: readOptionalString(payload, [
      'per_tx_max_priority_fee_per_gas_policy_id',
      'perTxMaxPriorityFeePerGasPolicyId',
    ]),
    perTxMaxCalldataBytes: readOptionalString(payload, [
      'per_tx_max_calldata_bytes',
      'perTxMaxCalldataBytes',
    ]),
    perTxMaxCalldataBytesPolicyId: readOptionalString(payload, [
      'per_tx_max_calldata_bytes_policy_id',
      'perTxMaxCalldataBytesPolicyId',
    ]),
  };
}

function readTokenPolicySummary(
  payload: Record<string, unknown>,
  label: string,
): BootstrapTokenPolicySummary {
  return {
    tokenKey: readRequiredString(payload, ['token_key', 'tokenKey'], `${label}.token_key`),
    symbol: readRequiredString(payload, ['symbol'], `${label}.symbol`),
    chainKey: readRequiredString(payload, ['chain_key', 'chainKey'], `${label}.chain_key`),
    chainId: readRequiredNumber(payload, ['chain_id', 'chainId'], `${label}.chain_id`),
    assetScope: readRequiredString(payload, ['asset_scope', 'assetScope'], `${label}.asset_scope`),
    recipientScope: readRequiredString(
      payload,
      ['recipient_scope', 'recipientScope'],
      `${label}.recipient_scope`,
    ),
    perTxPolicyId: readRequiredString(
      payload,
      ['per_tx_policy_id', 'perTxPolicyId'],
      `${label}.per_tx_policy_id`,
    ),
    dailyPolicyId: readRequiredString(
      payload,
      ['daily_policy_id', 'dailyPolicyId'],
      `${label}.daily_policy_id`,
    ),
    weeklyPolicyId: readRequiredString(
      payload,
      ['weekly_policy_id', 'weeklyPolicyId'],
      `${label}.weekly_policy_id`,
    ),
    gasPolicyId: readOptionalString(payload, ['gas_policy_id', 'gasPolicyId']),
    perTxMaxWei: readRequiredString(
      payload,
      ['per_tx_max_wei', 'perTxMaxWei'],
      `${label}.per_tx_max_wei`,
    ),
    dailyMaxWei: readRequiredString(
      payload,
      ['daily_max_wei', 'dailyMaxWei'],
      `${label}.daily_max_wei`,
    ),
    weeklyMaxWei: readRequiredString(
      payload,
      ['weekly_max_wei', 'weeklyMaxWei'],
      `${label}.weekly_max_wei`,
    ),
    maxGasPerChainWei: readOptionalString(payload, ['max_gas_per_chain_wei', 'maxGasPerChainWei']),
    dailyMaxTxCount: readOptionalString(payload, ['daily_max_tx_count', 'dailyMaxTxCount']),
    dailyTxCountPolicyId: readOptionalString(payload, [
      'daily_tx_count_policy_id',
      'dailyTxCountPolicyId',
    ]),
    perTxMaxFeePerGasWei: readOptionalString(payload, [
      'per_tx_max_fee_per_gas_wei',
      'perTxMaxFeePerGasWei',
    ]),
    perTxMaxFeePerGasPolicyId: readOptionalString(payload, [
      'per_tx_max_fee_per_gas_policy_id',
      'perTxMaxFeePerGasPolicyId',
    ]),
    perTxMaxPriorityFeePerGasWei: readOptionalString(payload, [
      'per_tx_max_priority_fee_per_gas_wei',
      'perTxMaxPriorityFeePerGasWei',
    ]),
    perTxMaxPriorityFeePerGasPolicyId: readOptionalString(payload, [
      'per_tx_max_priority_fee_per_gas_policy_id',
      'perTxMaxPriorityFeePerGasPolicyId',
    ]),
    perTxMaxCalldataBytes: readOptionalString(payload, [
      'per_tx_max_calldata_bytes',
      'perTxMaxCalldataBytes',
    ]),
    perTxMaxCalldataBytesPolicyId: readOptionalString(payload, [
      'per_tx_max_calldata_bytes_policy_id',
      'perTxMaxCalldataBytesPolicyId',
    ]),
  };
}

function readTokenDestinationOverrideSummary(
  payload: Record<string, unknown>,
  label: string,
): BootstrapTokenDestinationOverrideSummary {
  return {
    tokenKey: readRequiredString(payload, ['token_key', 'tokenKey'], `${label}.token_key`),
    symbol: readRequiredString(payload, ['symbol'], `${label}.symbol`),
    chainKey: readRequiredString(payload, ['chain_key', 'chainKey'], `${label}.chain_key`),
    chainId: readRequiredNumber(payload, ['chain_id', 'chainId'], `${label}.chain_id`),
    recipient: readRequiredString(payload, ['recipient'], `${label}.recipient`),
    assetScope: readRequiredString(payload, ['asset_scope', 'assetScope'], `${label}.asset_scope`),
    perTxPolicyId: readRequiredString(
      payload,
      ['per_tx_policy_id', 'perTxPolicyId'],
      `${label}.per_tx_policy_id`,
    ),
    dailyPolicyId: readRequiredString(
      payload,
      ['daily_policy_id', 'dailyPolicyId'],
      `${label}.daily_policy_id`,
    ),
    weeklyPolicyId: readRequiredString(
      payload,
      ['weekly_policy_id', 'weeklyPolicyId'],
      `${label}.weekly_policy_id`,
    ),
    gasPolicyId: readOptionalString(payload, ['gas_policy_id', 'gasPolicyId']),
    perTxMaxWei: readRequiredString(
      payload,
      ['per_tx_max_wei', 'perTxMaxWei'],
      `${label}.per_tx_max_wei`,
    ),
    dailyMaxWei: readRequiredString(
      payload,
      ['daily_max_wei', 'dailyMaxWei'],
      `${label}.daily_max_wei`,
    ),
    weeklyMaxWei: readRequiredString(
      payload,
      ['weekly_max_wei', 'weeklyMaxWei'],
      `${label}.weekly_max_wei`,
    ),
    maxGasPerChainWei: readOptionalString(payload, ['max_gas_per_chain_wei', 'maxGasPerChainWei']),
    dailyMaxTxCount: readOptionalString(payload, ['daily_max_tx_count', 'dailyMaxTxCount']),
    dailyTxCountPolicyId: readOptionalString(payload, [
      'daily_tx_count_policy_id',
      'dailyTxCountPolicyId',
    ]),
    perTxMaxFeePerGasWei: readOptionalString(payload, [
      'per_tx_max_fee_per_gas_wei',
      'perTxMaxFeePerGasWei',
    ]),
    perTxMaxFeePerGasPolicyId: readOptionalString(payload, [
      'per_tx_max_fee_per_gas_policy_id',
      'perTxMaxFeePerGasPolicyId',
    ]),
    perTxMaxPriorityFeePerGasWei: readOptionalString(payload, [
      'per_tx_max_priority_fee_per_gas_wei',
      'perTxMaxPriorityFeePerGasWei',
    ]),
    perTxMaxPriorityFeePerGasPolicyId: readOptionalString(payload, [
      'per_tx_max_priority_fee_per_gas_policy_id',
      'perTxMaxPriorityFeePerGasPolicyId',
    ]),
    perTxMaxCalldataBytes: readOptionalString(payload, [
      'per_tx_max_calldata_bytes',
      'perTxMaxCalldataBytes',
    ]),
    perTxMaxCalldataBytesPolicyId: readOptionalString(payload, [
      'per_tx_max_calldata_bytes_policy_id',
      'perTxMaxCalldataBytesPolicyId',
    ]),
  };
}

function readTokenManualApprovalPolicySummary(
  payload: Record<string, unknown>,
  label: string,
): BootstrapTokenManualApprovalPolicySummary {
  return {
    tokenKey: readRequiredString(payload, ['token_key', 'tokenKey'], `${label}.token_key`),
    symbol: readRequiredString(payload, ['symbol'], `${label}.symbol`),
    chainKey: readRequiredString(payload, ['chain_key', 'chainKey'], `${label}.chain_key`),
    chainId: readRequiredNumber(payload, ['chain_id', 'chainId'], `${label}.chain_id`),
    priority: readRequiredNumber(payload, ['priority'], `${label}.priority`),
    minAmountWei: readRequiredString(
      payload,
      ['min_amount_wei', 'minAmountWei'],
      `${label}.min_amount_wei`,
    ),
    maxAmountWei: readRequiredString(
      payload,
      ['max_amount_wei', 'maxAmountWei'],
      `${label}.max_amount_wei`,
    ),
    assetScope: readRequiredString(payload, ['asset_scope', 'assetScope'], `${label}.asset_scope`),
    recipientScope: readRequiredString(
      payload,
      ['recipient_scope', 'recipientScope'],
      `${label}.recipient_scope`,
    ),
    policyId: readRequiredString(payload, ['policy_id', 'policyId'], `${label}.policy_id`),
  };
}

function assertPrivateFile(stats: fs.Stats, resolvedPath: string): void {
  assertPrivateFileStats(stats, resolvedPath, 'bootstrap credentials file');
}

function readBootstrapPayload(resolvedPath: string): Record<string, unknown> {
  return assertJsonRecord(
    JSON.parse(
      readUtf8FileSecure(
        resolvedPath,
        `bootstrap credentials file '${resolvedPath}'`,
        MAX_BOOTSTRAP_FILE_BYTES,
      ),
    ),
    `bootstrap credentials file '${resolvedPath}'`,
  );
}

function assertWritableBootstrapFile(resolvedPath: string): void {
  const stats = fs.lstatSync(resolvedPath);
  if (stats.isSymbolicLink()) {
    throw new Error(`bootstrap credentials file '${resolvedPath}' must not be a symlink`);
  }
  if (!stats.isFile()) {
    throw new Error(`bootstrap credentials file '${resolvedPath}' must be a regular file`);
  }
  assertPrivateFile(stats, resolvedPath);
  assertTrustedDirectoryPath(path.dirname(resolvedPath), 'bootstrap credentials directory');
}

function writePrivateBootstrapFile(resolvedPath: string, payload: Record<string, unknown>): void {
  const directoryPath = path.dirname(resolvedPath);
  const tempPath = path.join(
    directoryPath,
    `.${path.basename(resolvedPath)}.tmp-${process.pid}-${Date.now()}`,
  );

  try {
    fs.writeFileSync(tempPath, JSON.stringify(payload, null, 2) + '\n', {
      encoding: 'utf8',
      mode: PRIVATE_FILE_MODE,
      flag: 'wx',
    });
    fs.chmodSync(tempPath, PRIVATE_FILE_MODE);
    fs.renameSync(tempPath, resolvedPath);
    fs.chmodSync(resolvedPath, PRIVATE_FILE_MODE);
  } finally {
    try {
      if (fs.existsSync(tempPath)) {
        fs.rmSync(tempPath);
      }
    } catch {}
  }
}

function applyRedactedSecretFields(payload: Record<string, unknown>): Record<string, unknown> {
  const nextPayload = { ...payload };
  let wroteTokenField = false;
  for (const fieldName of ['agent_auth_token', 'agentAuthToken']) {
    if (fieldName in nextPayload) {
      nextPayload[fieldName] = REDACTED_SECRET_PLACEHOLDER;
      wroteTokenField = true;
    }
  }

  if (!wroteTokenField) {
    nextPayload.agent_auth_token = REDACTED_SECRET_PLACEHOLDER;
  }

  let wroteRedactedField = false;
  for (const fieldName of ['agent_auth_token_redacted', 'agentAuthTokenRedacted']) {
    if (fieldName in nextPayload) {
      nextPayload[fieldName] = true;
      wroteRedactedField = true;
    }
  }

  if (!wroteRedactedField) {
    nextPayload.agent_auth_token_redacted = true;
  }

  let wrotePrivateKeyField = false;
  for (const fieldName of ['vault_private_key', 'vaultPrivateKey']) {
    if (fieldName in nextPayload) {
      nextPayload[fieldName] = REDACTED_SECRET_PLACEHOLDER;
      wrotePrivateKeyField = true;
    }
  }

  if (wrotePrivateKeyField) {
    let wrotePrivateKeyRedactedField = false;
    for (const fieldName of ['vault_private_key_redacted', 'vaultPrivateKeyRedacted']) {
      if (fieldName in nextPayload) {
        nextPayload[fieldName] = true;
        wrotePrivateKeyRedactedField = true;
      }
    }

    if (!wrotePrivateKeyRedactedField) {
      nextPayload.vault_private_key_redacted = true;
    }
  }

  return nextPayload;
}

function parseBootstrapAgentCredentialsPayload(
  payload: Record<string, unknown>,
  sourcePath: string,
): BootstrapAgentCredentials {
  const redacted = readOptionalBoolean(payload, [
    'agent_auth_token_redacted',
    'agentAuthTokenRedacted',
  ]);
  if (redacted === true) {
    throw new Error(
      'bootstrap credentials file contains a redacted agent auth token; rerun `agentpay admin setup --print-agent-auth-token`',
    );
  }

  const agentKeyId = assertValidAgentKeyId(
    readRequiredString(payload, ['agent_key_id', 'agentKeyId'], 'agent_key_id'),
  );
  const rawAgentAuthToken = readRequiredString(
    payload,
    ['agent_auth_token', 'agentAuthToken'],
    'agent_auth_token',
    { trim: false },
  );

  if (rawAgentAuthToken === '<redacted>') {
    throw new Error(
      'bootstrap credentials file contains a redacted agent auth token; rerun `agentpay admin setup --print-agent-auth-token`',
    );
  }
  const agentAuthToken = assertValidAgentAuthToken(rawAgentAuthToken, 'agent_auth_token');

  return {
    agentKeyId,
    agentAuthToken,
    sourcePath,
  };
}

function parseBootstrapSetupSummaryPayload(
  payload: Record<string, unknown>,
  sourcePath: string,
): BootstrapSetupSummary {
  const vaultPrivateKey = readOptionalString(payload, ['vault_private_key', 'vaultPrivateKey']);
  const tokenPolicies = readOptionalRecordArray(payload, ['token_policies', 'tokenPolicies']).map(
    (entry, index) => readTokenPolicySummary(entry, `token_policies[${index}]`),
  );
  const tokenDestinationOverrides = readOptionalRecordArray(payload, [
    'token_destination_overrides',
    'tokenDestinationOverrides',
  ]).map((entry, index) =>
    readTokenDestinationOverrideSummary(entry, `token_destination_overrides[${index}]`),
  );
  const tokenManualApprovalPolicies = readOptionalRecordArray(payload, [
    'token_manual_approval_policies',
    'tokenManualApprovalPolicies',
  ]).map((entry, index) =>
    readTokenManualApprovalPolicySummary(entry, `token_manual_approval_policies[${index}]`),
  );
  const perTxPolicyId = readOptionalString(payload, ['per_tx_policy_id', 'perTxPolicyId']);
  const dailyPolicyId = readOptionalString(payload, ['daily_policy_id', 'dailyPolicyId']);
  const weeklyPolicyId = readOptionalString(payload, ['weekly_policy_id', 'weeklyPolicyId']);
  const networkScope = readOptionalString(payload, ['network_scope', 'networkScope']);
  const assetScope = readOptionalString(payload, ['asset_scope', 'assetScope']);
  const recipientScope = readOptionalString(payload, ['recipient_scope', 'recipientScope']);
  const policyAttachment = readRequiredString(
    payload,
    ['policy_attachment', 'policyAttachment'],
    'policy_attachment',
  );
  const attachedPolicyIds = readOptionalStringArray(payload, [
    'attached_policy_ids',
    'attachedPolicyIds',
  ]);
  const hasLegacyPolicyIds = Boolean(perTxPolicyId || dailyPolicyId || weeklyPolicyId);

  if (tokenPolicies.length === 0) {
    if (hasLegacyPolicyIds) {
      if (!perTxPolicyId || !dailyPolicyId || !weeklyPolicyId) {
        throw new Error(
          'per-token bootstrap summary is missing token_policies and legacy policy ids',
        );
      }
      if (!networkScope || !assetScope || !recipientScope) {
        throw new Error('legacy bootstrap summary is missing policy scope fields');
      }
    } else if (policyAttachment !== 'all_policies' && attachedPolicyIds.length === 0) {
      throw new Error(
        'per-token bootstrap summary is missing token_policies and legacy policy ids',
      );
    }
  }

  return {
    sourcePath,
    leaseId: readRequiredString(payload, ['lease_id', 'leaseId'], 'lease_id'),
    leaseExpiresAt: readRequiredString(
      payload,
      ['lease_expires_at', 'leaseExpiresAt'],
      'lease_expires_at',
    ),
    perTxPolicyId,
    dailyPolicyId,
    weeklyPolicyId,
    gasPolicyId: readOptionalString(payload, ['gas_policy_id', 'gasPolicyId']),
    perTxMaxWei: readOptionalString(payload, ['per_tx_max_wei', 'perTxMaxWei']),
    dailyMaxWei: readOptionalString(payload, ['daily_max_wei', 'dailyMaxWei']),
    weeklyMaxWei: readOptionalString(payload, ['weekly_max_wei', 'weeklyMaxWei']),
    maxGasPerChainWei: readOptionalString(payload, ['max_gas_per_chain_wei', 'maxGasPerChainWei']),
    dailyMaxTxCount: readOptionalString(payload, ['daily_max_tx_count', 'dailyMaxTxCount']),
    dailyTxCountPolicyId: readOptionalString(payload, [
      'daily_tx_count_policy_id',
      'dailyTxCountPolicyId',
    ]),
    perTxMaxFeePerGasWei: readOptionalString(payload, [
      'per_tx_max_fee_per_gas_wei',
      'perTxMaxFeePerGasWei',
    ]),
    perTxMaxFeePerGasPolicyId: readOptionalString(payload, [
      'per_tx_max_fee_per_gas_policy_id',
      'perTxMaxFeePerGasPolicyId',
    ]),
    perTxMaxPriorityFeePerGasWei: readOptionalString(payload, [
      'per_tx_max_priority_fee_per_gas_wei',
      'perTxMaxPriorityFeePerGasWei',
    ]),
    perTxMaxPriorityFeePerGasPolicyId: readOptionalString(payload, [
      'per_tx_max_priority_fee_per_gas_policy_id',
      'perTxMaxPriorityFeePerGasPolicyId',
    ]),
    perTxMaxCalldataBytes: readOptionalString(payload, [
      'per_tx_max_calldata_bytes',
      'perTxMaxCalldataBytes',
    ]),
    perTxMaxCalldataBytesPolicyId: readOptionalString(payload, [
      'per_tx_max_calldata_bytes_policy_id',
      'perTxMaxCalldataBytesPolicyId',
    ]),
    vaultKeyId: readRequiredString(payload, ['vault_key_id', 'vaultKeyId'], 'vault_key_id'),
    vaultKeyAlgorithm: readWalletKeyAlgorithm(
      payload,
      ['vault_key_algorithm', 'vaultKeyAlgorithm'],
      'vault_key_algorithm',
    ),
    vaultPublicKey: readRequiredString(
      payload,
      ['vault_public_key', 'vaultPublicKey'],
      'vault_public_key',
    ),
    solanaPublicKey: readOptionalString(payload, ['solana_public_key', 'solanaPublicKey']),
    solanaAddress: readOptionalString(payload, ['solana_address', 'solanaAddress']),
    vaultPrivateKey: vaultPrivateKey === REDACTED_SECRET_PLACEHOLDER ? null : vaultPrivateKey,
    agentKeyId: readRequiredString(payload, ['agent_key_id', 'agentKeyId'], 'agent_key_id'),
    networkScope,
    assetScope,
    recipientScope,
    destinationOverrideCount:
      readOptionalNumber(payload, ['destination_override_count', 'destinationOverrideCount']) ?? 0,
    destinationOverrides: readOptionalRecordArray(payload, [
      'destination_overrides',
      'destinationOverrides',
    ]).map((entry, index) =>
      readDestinationOverrideSummary(entry, `destination_overrides[${index}]`),
    ),
    tokenPolicies,
    tokenDestinationOverrides,
    tokenManualApprovalPolicies,
    policyAttachment,
    attachedPolicyIds,
    policyNote: readRequiredString(payload, ['policy_note', 'policyNote'], 'policy_note'),
  };
}

function readWalletKeyAlgorithm(
  payload: Record<string, unknown>,
  fieldNames: string[],
  label: string,
): WalletKeyAlgorithm {
  const value = readOptionalString(payload, fieldNames);
  if (value == null) {
    return 'secp256k1';
  }
  if (value === 'secp256k1' || value === 'ed25519') {
    return value;
  }
  throw new Error(`${label} must be secp256k1 or ed25519 in bootstrap credentials file`);
}

export function readBootstrapSetupFile(inputPath: string): BootstrapSetupFileContents {
  const resolvedPath = resolveInputPath(inputPath);
  assertWritableBootstrapFile(resolvedPath);
  const payload = readBootstrapPayload(resolvedPath);

  return {
    summary: parseBootstrapSetupSummaryPayload(payload, resolvedPath),
    credentials: parseBootstrapAgentCredentialsPayload(payload, resolvedPath),
  };
}

export function readBootstrapAgentCredentialsFile(inputPath: string): BootstrapAgentCredentials {
  const resolvedPath = resolveInputPath(inputPath);
  assertWritableBootstrapFile(resolvedPath);
  return parseBootstrapAgentCredentialsPayload(readBootstrapPayload(resolvedPath), resolvedPath);
}

export function readBootstrapSetupSummaryFile(inputPath: string): BootstrapSetupSummary {
  const resolvedPath = resolveInputPath(inputPath);
  assertWritableBootstrapFile(resolvedPath);
  return parseBootstrapSetupSummaryPayload(readBootstrapPayload(resolvedPath), resolvedPath);
}

export function assertBootstrapSetupSummaryLeaseIsActive(
  summary: Pick<BootstrapSetupSummary, 'leaseExpiresAt'>,
  deps: BootstrapLeaseValidationDeps = {},
): void {
  const now = deps.now ?? (() => Date.now());
  const leaseExpiry = Date.parse(summary.leaseExpiresAt);

  if (!Number.isFinite(leaseExpiry)) {
    throw new Error('bootstrap summary lease_expires_at is not a valid ISO-8601 timestamp');
  }

  if (leaseExpiry <= now()) {
    throw new Error(
      'bootstrap summary lease has expired; rerun `agentpay admin setup --print-agent-auth-token`',
    );
  }
}

export function redactBootstrapAgentCredentialsFile(
  inputPath: string,
): BootstrapCredentialsCleanupResult {
  const resolvedPath = resolveInputPath(inputPath);
  assertWritableBootstrapFile(resolvedPath);
  const payload = readBootstrapPayload(resolvedPath);
  writePrivateBootstrapFile(resolvedPath, applyRedactedSecretFields(payload));
  return { sourcePath: resolvedPath };
}

export function deleteBootstrapAgentCredentialsFile(
  inputPath: string,
): BootstrapCredentialsCleanupResult {
  const resolvedPath = resolveInputPath(inputPath);
  assertWritableBootstrapFile(resolvedPath);
  fs.rmSync(resolvedPath);
  return { sourcePath: resolvedPath };
}

export function cleanupBootstrapAgentCredentialsFile(
  inputPath: string,
  action: 'deleted' | 'redacted',
): BootstrapCredentialsBestEffortCleanupResult {
  const resolvedPath = resolveInputPath(inputPath);

  try {
    fs.lstatSync(resolvedPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return {
        sourcePath: resolvedPath,
        action: 'missing',
      };
    }
    throw error;
  }

  if (action === 'deleted') {
    deleteBootstrapAgentCredentialsFile(resolvedPath);
    return {
      sourcePath: resolvedPath,
      action: 'deleted',
    };
  }

  try {
    redactBootstrapAgentCredentialsFile(resolvedPath);
    return {
      sourcePath: resolvedPath,
      action: 'redacted',
    };
  } catch (redactError) {
    try {
      deleteBootstrapAgentCredentialsFile(resolvedPath);
      return {
        sourcePath: resolvedPath,
        action: 'deleted',
      };
    } catch (deleteError) {
      return {
        sourcePath: resolvedPath,
        action: 'failed',
        error:
          `bootstrap credentials file '${resolvedPath}' redaction failed: ${renderError(redactError)}; ` +
          `fallback delete also failed: ${renderError(deleteError)}`,
      };
    }
  }
}
