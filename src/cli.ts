import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { type ClientEvmSigner, ExactEvmScheme } from '@x402/evm';
import { ExactEvmSchemeV1, NETWORKS as X402_EVM_V1_NETWORKS } from '@x402/evm/v1';
import {
  decodePaymentResponseHeader,
  type PaymentRequirements,
  wrapFetchWithPayment,
  x402Client,
} from '@x402/fetch';
import { Command, Option } from 'commander';
import {
  type Address,
  createPublicClient,
  encodeAbiParameters,
  encodeFunctionData,
  type Hex,
  hashTypedData,
  http,
  isAddress,
  isHex,
  keccak256,
  parseSignature,
  toHex,
} from 'viem';
import { prepareTransactionRequest } from 'viem/actions';
import { tempo as tempoChain, tempoModerato } from 'viem/chains';
import {
  Abis as TempoAbis,
  Actions as TempoActions,
  Transaction as TempoTransaction,
} from 'viem/tempo';
import type { ChainProfile, TokenChainProfile, WlfiConfig } from '../packages/config/src/index.js';
import * as configPackage from '../packages/config/src/index.js';
import { assertSafeRpcUrl } from '../packages/config/src/index.js';
import * as rpcPackage from '../packages/rpc/src/index.js';
import { resolveValidatedAdminDaemonSocket } from './lib/admin-daemon-socket.js';
import {
  blockedRawAdminPassthroughMessage,
  rewriteAdminHelpText,
} from './lib/admin-passthrough.js';
import { runAdminResetCli, runAdminUninstallCli } from './lib/admin-reset.js';
import {
  resolveAdminSetupVaultPassword,
  runAdminSetupCli,
  runAdminTuiCli,
} from './lib/admin-setup.js';
import { resolveAgentAuthToken } from './lib/agent-auth.js';
import { clearAgentAuthToken } from './lib/agent-auth-clear.js';
import { migrateLegacyAgentAuthToken } from './lib/agent-auth-migrate.js';
import {
  buildRevokeAgentKeyAdminArgs,
  completeAgentKeyRevocation,
  type RevokeAgentKeyAdminOutput,
} from './lib/agent-auth-revoke.js';
import {
  buildRotateAgentAuthTokenAdminArgs,
  completeAgentAuthRotation,
  type RotateAgentAuthTokenAdminOutput,
} from './lib/agent-auth-rotate.js';
import { assertValidAgentAuthToken } from './lib/agent-auth-token.js';
import {
  completeAssetBroadcast,
  encodeErc20ApproveData,
  encodeErc20TransferData,
  formatBroadcastedAssetOutput,
  resolveAssetBroadcastPlan,
  resolveEstimatedPriorityFeePerGasWei,
  waitForOnchainReceipt,
} from './lib/asset-broadcast.js';
import {
  assertBootstrapSetupSummaryLeaseIsActive,
  deleteBootstrapAgentCredentialsFile,
  readBootstrapAgentCredentialsFile,
  readBootstrapSetupSummaryFile,
  redactBootstrapAgentCredentialsFile,
} from './lib/bootstrap-credentials.js';
import { resolveCliVersion } from './lib/cli-version.js';
import {
  formatConfiguredAmount,
  normalizeAgentAmountOutput,
  normalizePositiveDecimalInput,
  parseConfiguredAmount,
  resolveConfiguredErc20Asset,
  resolveConfiguredNativeAsset,
  resolveErc20AssetWithRpcFallback,
  rewriteAmountPolicyErrorMessage,
} from './lib/config-amounts.js';
import {
  assertWritableConfigKey,
  resolveConfigMutationCommandLabel,
  type WritableConfigKey,
} from './lib/config-mutation.js';
import { assertTrustedDaemonSocketPath } from './lib/fs-trust.js';
import {
  AGENT_AUTH_TOKEN_KEYCHAIN_SERVICE,
  hasAgentAuthTokenInKeychain,
  readAgentAuthTokenFromKeychain,
  storeAgentAuthTokenInKeychain,
} from './lib/keychain.js';
import {
  withDynamicLocalAdminMutationAccess,
  withLocalAdminMutationAccess,
} from './lib/local-admin-access.js';
import {
  encodeMppAttributionMemo,
  type MppReceipt,
  parseMppChallengeFromHeaders,
  parseMppReceiptFromHeaders,
  isTempoChain,
  resolveMppChainId,
  resolveMppEscrowContract,
  serializeMppCredentialHeader,
} from './lib/mpp.js';
import { resolveCliNetworkProfile, resolveCliRpcUrl } from './lib/network-selection.js';
import { assertRpcChainIdMatches } from './lib/rpc-guard.js';
import {
  passthroughRustBinary,
  RustBinaryExitError,
  runRustBinary,
  runRustBinaryJson,
} from './lib/rust.js';
import { assertSignedBroadcastTransactionMatchesRequest } from './lib/signed-tx.js';
import { registerRepairCommand, registerStatusCommand } from './lib/status-repair-cli.js';
import {
  closeGlobalFetchProxyDispatcherFromEnv,
  installGlobalFetchProxyDispatcherFromEnv,
} from './lib/http-proxy.js';
import { resolveWalletBackupPassword, verifyWalletBackupFile } from './lib/wallet-backup.js';
import { exportEncryptedWalletBackup } from './lib/wallet-backup-admin.js';
import {
  formatWalletProfileText,
  resolveWalletAddress,
  resolveWalletProfileWithBalances,
  walletProfileFromBootstrapSummary,
} from './lib/wallet-profile.js';
import { registerBuiltinCliPlugins } from './plugins/index.js';

const configExports = (
  'default' in configPackage ? configPackage.default : configPackage
) as typeof import('../packages/config/src/index.js');
const {
  defaultDaemonSocketPath,
  deleteConfigKey,
  ensureAgentPayHome,
  listBuiltinChains,
  listBuiltinTokens,
  listConfiguredChains,
  listConfiguredTokens,
  readConfig,
  redactConfig,
  removeChainProfile,
  removeTokenChainProfile,
  removeTokenProfile,
  resolveChainProfile,
  resolveConfigPath,
  resolveTokenProfile,
  saveChainProfile,
  saveTokenChainProfile,
  switchActiveChain,
  writeConfig,
} = configExports;

const rpcExports = (
  'default' in rpcPackage ? rpcPackage.default : rpcPackage
) as typeof import('../packages/rpc/src/index.ts');
const {
  broadcastRawTransaction,
  estimateFees,
  estimateGas,
  getAccountSnapshot,
  getChainInfo,
  getCodeAtAddress,
  getLatestBlockNumber,
  getNativeBalance,
  getNonce,
  getTokenBalance,
  getTokenMetadata,
  getTransactionByHash,
  getTransactionReceiptByHash,
} = rpcExports;

const CLI_VERSION = resolveCliVersion();

interface RustBroadcastOutput {
  command: string;
  network: string;
  asset: string;
  counterparty: string;
  amount_wei: string;
  estimated_max_gas_spend_wei?: string;
  tx_type?: string;
  delegation_enabled?: boolean;
  signature_hex: string;
  r_hex?: string;
  s_hex?: string;
  v?: number;
  raw_tx_hex?: string;
  tx_hash_hex?: string;
}

interface RustManualApprovalRequiredOutput {
  command: string;
  approval_request_id: string;
  cli_approval_command: string;
}

interface RustManualApprovalBroadcastTx {
  chain_id: number;
  nonce: number;
  to: string;
  value_wei: string;
  data_hex: string;
  gas_limit: number;
  max_fee_per_gas_wei: string;
  max_priority_fee_per_gas_wei: string;
  tx_type: number;
  delegation_enabled: boolean;
}

interface RustManualApprovalBroadcastAction {
  kind: 'BroadcastTx';
  tx: RustManualApprovalBroadcastTx;
}

interface RustManualApprovalRequestOutput {
  id: string;
  agent_key_id: string;
  status: 'pending' | 'approved' | 'rejected' | 'completed';
  action: {
    kind: string;
    tx?: Partial<RustManualApprovalBroadcastTx>;
  };
  chain_id: number;
  asset: string;
  recipient: string;
  amount_wei: string;
}

type AgentCommandAttemptResult<T> =
  | { type: 'success'; value: T }
  | {
      type: 'manualApproval';
      output: RustManualApprovalRequiredOutput;
      exitCode: number;
    };

function rewriteAgentAmountError(
  error: unknown,
  symbolAwareAsset: { decimals: number; symbol: string; assetId: string },
): Error {
  if (!(error instanceof Error)) {
    return new Error(String(error));
  }

  const rewritten = rewriteAmountPolicyErrorMessage(error.message, symbolAwareAsset);
  if (rewritten === error.message) {
    return error;
  }

  return new Error(rewritten);
}

function isManualApprovalRequiredOutput(value: unknown): value is RustManualApprovalRequiredOutput {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const candidate = value as Partial<RustManualApprovalRequiredOutput>;
  return (
    typeof candidate.command === 'string' &&
    typeof candidate.approval_request_id === 'string' &&
    typeof candidate.cli_approval_command === 'string'
  );
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function isRustManualApprovalBroadcastTx(value: unknown): value is RustManualApprovalBroadcastTx {
  if (!isPlainObject(value)) {
    return false;
  }
  return (
    typeof value.chain_id === 'number' &&
    Number.isSafeInteger(value.chain_id) &&
    value.chain_id > 0 &&
    typeof value.nonce === 'number' &&
    Number.isSafeInteger(value.nonce) &&
    value.nonce >= 0 &&
    typeof value.to === 'string' &&
    typeof value.value_wei === 'string' &&
    typeof value.data_hex === 'string' &&
    typeof value.gas_limit === 'number' &&
    Number.isSafeInteger(value.gas_limit) &&
    value.gas_limit > 0 &&
    typeof value.max_fee_per_gas_wei === 'string' &&
    typeof value.max_priority_fee_per_gas_wei === 'string' &&
    typeof value.tx_type === 'number' &&
    Number.isSafeInteger(value.tx_type) &&
    value.tx_type >= 0 &&
    value.tx_type <= 0xff &&
    typeof value.delegation_enabled === 'boolean'
  );
}

function isRustManualApprovalRequestOutput(
  value: unknown,
): value is RustManualApprovalRequestOutput {
  if (!isPlainObject(value) || !isPlainObject(value.action)) {
    return false;
  }
  return (
    typeof value.id === 'string' &&
    typeof value.agent_key_id === 'string' &&
    (value.status === 'pending' ||
      value.status === 'approved' ||
      value.status === 'rejected' ||
      value.status === 'completed') &&
    typeof value.action.kind === 'string' &&
    typeof value.chain_id === 'number' &&
    Number.isSafeInteger(value.chain_id) &&
    value.chain_id > 0 &&
    typeof value.asset === 'string' &&
    typeof value.recipient === 'string' &&
    typeof value.amount_wei === 'string'
  );
}

function formatBroadcastTxType(txType: number): string {
  return `0x${txType.toString(16).padStart(2, '0')}`;
}

function buildListManualApprovalRequestsAdminArgs(input: {
  vaultPasswordStdin?: boolean;
  nonInteractive?: boolean;
  daemonSocket?: string;
}): string[] {
  const args = ['--json', '--quiet'];
  if (input.vaultPasswordStdin) {
    args.push('--vault-password-stdin');
  }
  if (input.nonInteractive) {
    args.push('--non-interactive');
  }
  if (input.daemonSocket) {
    args.push('--daemon-socket', input.daemonSocket);
  }
  args.push('list-manual-approval-requests');
  return args;
}

function resolveManualApprovalRequestById(
  requests: unknown,
  approvalRequestId: string,
): RustManualApprovalRequestOutput {
  if (!Array.isArray(requests)) {
    throw new Error('agentpay-admin returned invalid manual approval request output');
  }

  const request = requests
    .filter(isRustManualApprovalRequestOutput)
    .find((candidate) => candidate.id === approvalRequestId);

  if (!request) {
    throw new Error(`manual approval request '${approvalRequestId}' was not found`);
  }

  return request;
}

function resolveApprovedBroadcastManualApprovalRequest(request: RustManualApprovalRequestOutput): {
  request: RustManualApprovalRequestOutput;
  action: RustManualApprovalBroadcastAction;
} {
  if (request.status === 'pending') {
    throw new Error(
      `manual approval request '${request.id}' is still pending; approve it before resuming`,
    );
  }
  if (request.status === 'rejected') {
    throw new Error(`manual approval request '${request.id}' was rejected and cannot be resumed`);
  }
  if (request.status === 'completed') {
    throw new Error(
      `manual approval request '${request.id}' is already completed; nothing needs to be resumed`,
    );
  }
  if (
    request.action.kind !== 'BroadcastTx' ||
    !isRustManualApprovalBroadcastTx(request.action.tx)
  ) {
    throw new Error(
      `manual approval request '${request.id}' is not a resumable broadcast transaction`,
    );
  }
  return {
    request,
    action: {
      kind: 'BroadcastTx',
      tx: request.action.tx,
    },
  };
}

function resolveResumeManualApprovalRpcUrl(
  config: WlfiConfig,
  chainId: number,
  explicitRpcUrl: string | undefined,
): string {
  if (explicitRpcUrl?.trim()) {
    return assertSafeRpcUrl(explicitRpcUrl, 'rpcUrl');
  }

  const chainProfile = resolveChainProfile(String(chainId), config);
  const resolvedRpcUrl = chainProfile?.rpcUrl?.trim();
  if (resolvedRpcUrl) {
    return assertSafeRpcUrl(resolvedRpcUrl, 'rpcUrl');
  }

  throw new Error(
    `rpcUrl is required to resume manual approval request for chain ${chainId}; configure that chain or pass --rpc-url`,
  );
}

function renderManualApprovalRequired(
  output: RustManualApprovalRequiredOutput,
  asJson: boolean,
): string {
  if (asJson) {
    return formatJson(output);
  }

  const lines = [
    `Command: ${output.command}`,
    `Approval Request ID: ${output.approval_request_id}`,
  ];
  lines.push(`CLI Approval Command: ${output.cli_approval_command}`);
  return lines.join('\n');
}

function printManualApprovalRequired(
  output: RustManualApprovalRequiredOutput,
  asJson: boolean,
  useStderr = false,
) {
  const rendered = renderManualApprovalRequired(output, asJson);
  if (useStderr) {
    console.error(rendered);
    return;
  }
  console.log(rendered);
}

function printManualApprovalWaiting(output: RustManualApprovalRequiredOutput, asJson: boolean) {
  if (asJson) {
    console.error(
      formatJson({
        event: 'manualApprovalPending',
        approvalRequestId: output.approval_request_id,
      }),
    );
    return;
  }

  console.error(`Waiting for manual approval decision: ${output.approval_request_id}`);
}

const MAX_SECRET_STDIN_BYTES = 16 * 1024;
const AGENT_KEY_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

function requiredString(value: string | undefined, label: string): string {
  if (!value?.trim()) {
    throw new Error(`${label} is required`);
  }
  return value;
}

function assertAgentKeyId(value: string | undefined, label = 'agentKeyId'): string {
  const normalized = requiredString(value, label).trim();
  if (!AGENT_KEY_ID_PATTERN.test(normalized)) {
    throw new Error(`${label} must be a valid UUID`);
  }
  return normalized;
}

function hasStoredAgentAuthToken(agentKeyId: string | undefined): boolean {
  if (!agentKeyId) {
    return false;
  }

  try {
    return hasAgentAuthTokenInKeychain(agentKeyId);
  } catch {
    return false;
  }
}

function resolveRpcUrl(value: string | undefined, config: WlfiConfig): string {
  return assertSafeRpcUrl(requiredString(value ?? config.rpcUrl, 'rpcUrl'), 'rpcUrl');
}

function resolveDaemonSocket(value: string | undefined, config: WlfiConfig): string {
  if (value !== undefined) {
    return requiredString(value, 'daemonSocket').trim();
  }
  if (config.daemonSocket !== undefined) {
    return requiredString(config.daemonSocket, 'configured daemonSocket').trim();
  }
  return defaultDaemonSocketPath();
}

function assertAddress(value: string, label: string): Address {
  if (!isAddress(value)) {
    throw new Error(`${label} must be a valid EVM address`);
  }
  return value as Address;
}

function assertHex(value: string, label: string): Hex {
  if (!isHex(value)) {
    throw new Error(`${label} must be valid hex`);
  }
  return value as Hex;
}

function parseBigIntString(value: string, label: string): bigint {
  const normalized = value.trim();
  if (!/^(0|[1-9][0-9]*)$/u.test(normalized)) {
    throw new Error(`${label} must be a non-negative integer string`);
  }
  try {
    return BigInt(normalized);
  } catch {
    throw new Error(`${label} must be a non-negative integer string`);
  }
}

function parseIntegerString(value: string, label: string): number {
  const normalized = value.trim();
  if (!/^(0|[1-9][0-9]*)$/u.test(normalized)) {
    throw new Error(`${label} must be a non-negative integer`);
  }
  const parsed = Number(normalized);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`${label} must be a safe integer`);
  }
  return parsed;
}

function parsePositiveBigIntString(value: string, label: string): bigint {
  const parsed = parseBigIntString(value, label);
  if (parsed <= 0n) {
    throw new Error(`${label} must be greater than zero`);
  }
  return parsed;
}

function parsePositiveIntegerString(value: string, label: string): number {
  const parsed = parseIntegerString(value, label);
  if (parsed <= 0) {
    throw new Error(`${label} must be greater than zero`);
  }
  return parsed;
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
  return requiredString(raw.replace(/[\r\n]+$/u, ''), label);
}

function formatJson(payload: unknown) {
  return JSON.stringify(
    payload,
    (_key, value) => (typeof value === 'bigint' ? value.toString() : value),
    2,
  );
}

function formatJsonLine(payload: unknown) {
  return JSON.stringify(payload, (_key, value) =>
    typeof value === 'bigint' ? value.toString() : value,
  );
}

function stringifyOptionalValue(value: { toString(): string } | null | undefined): string | null {
  return value === null || value === undefined ? null : value.toString();
}

function print(payload: unknown, asJson: boolean) {
  if (asJson) {
    console.log(formatJson(payload));
    return;
  }
  if (typeof payload === 'string') {
    console.log(payload);
    return;
  }
  console.log(formatJson(payload));
}

function headersToObject(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  headers.forEach((value, key) => {
    result[key] = value;
  });
  return result;
}

function parseResponseBody(text: string, contentType: string | null): unknown {
  if (!text) {
    return null;
  }
  if (contentType?.toLowerCase().includes('json')) {
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }
  return text;
}

async function printHttpCommandResponse(input: {
  protocol: 'x402' | 'mpp';
  response: Response;
  asJson: boolean;
  payment?: unknown;
  summaryLines?: string[];
}) {
  const bodyText = await input.response.text();
  if (input.asJson) {
    print(
      {
        protocol: input.protocol,
        url: input.response.url,
        status: input.response.status,
        ok: input.response.ok,
        headers: headersToObject(input.response.headers),
        body: parseResponseBody(bodyText, input.response.headers.get('content-type')),
        payment: input.payment ?? null,
      },
      true,
    );
    return;
  }
  if (bodyText) {
    process.stdout.write(bodyText.endsWith('\n') ? bodyText : `${bodyText}\n`);
  }
  for (const line of input.summaryLines ?? []) {
    console.error(line);
  }
}

function collectRepeatedOptionValue(value: string, previous: string[] = []): string[] {
  return [...previous, value];
}

function parseHttpHeaderOption(value: string): [string, string] {
  const separatorIndex = value.indexOf(':');
  if (separatorIndex <= 0) {
    throw new Error('--header must use the format "Name: value"');
  }

  const name = value.slice(0, separatorIndex).trim();
  if (!name) {
    throw new Error('--header must include a header name');
  }

  return [name, value.slice(separatorIndex + 1).trimStart()];
}

function hasHeaderName(headers: Headers, target: string): boolean {
  for (const [name] of headers.entries()) {
    if (name.toLowerCase() === target.toLowerCase()) {
      return true;
    }
  }
  return false;
}

function normalizeHttpMethod(value: string | undefined, hasBody: boolean): string {
  const normalized = value?.trim();
  if (!normalized) {
    return hasBody ? 'POST' : 'GET';
  }

  const method = normalized.toUpperCase();
  if (!/^[!#$%&'*+.^_`|~0-9A-Z-]+$/u.test(method)) {
    throw new Error('method must be a valid HTTP method token');
  }
  return method;
}

function buildHttpRequestInit(input: {
  method?: string;
  header?: string[];
  data?: string;
  jsonBody?: string;
}): RequestInit {
  if (input.data !== undefined && input.jsonBody !== undefined) {
    throw new Error('Pass either --data or --json-body, not both');
  }

  let body: string | undefined;
  if (input.jsonBody !== undefined) {
    try {
      JSON.parse(input.jsonBody);
    } catch {
      throw new Error('jsonBody must be valid JSON');
    }
    body = input.jsonBody;
  } else if (input.data !== undefined) {
    body = input.data;
  }

  const method = normalizeHttpMethod(input.method, body !== undefined);
  if ((method === 'GET' || method === 'HEAD') && body !== undefined) {
    throw new Error(`${method} requests cannot include a request body`);
  }

  const headers = new Headers();
  for (const header of input.header ?? []) {
    const [name, value] = parseHttpHeaderOption(header);
    headers.append(name, value);
  }
  if (input.jsonBody !== undefined && !hasHeaderName(headers, 'content-type')) {
    headers.set('content-type', 'application/json');
  }
  const hasHeaders = Array.from(headers.keys()).length > 0;

  return {
    method,
    ...(hasHeaders ? { headers } : {}),
    ...(body !== undefined ? { body } : {}),
  };
}

function withAuthorizationHeader(
  headers: RequestInit['headers'] | undefined,
  authorization: string,
): Headers {
  const next = new Headers(headers);
  next.set('Authorization', authorization);
  return next;
}

function buildMppPaymentSummaryLines(payment: {
  txHash?: string;
  receipt?: MppReceipt | null;
  channelId?: string;
  closeReceipt?: MppReceipt | null;
}): string[] {
  const lines: string[] = [];
  if (payment.txHash) {
    lines.push(`MPP payment tx hash: ${payment.txHash}`);
  }
  if (payment.channelId) {
    lines.push(`MPP channel id: ${payment.channelId}`);
  }
  if (payment.receipt) {
    const label = payment.receipt.intent
      ? `${payment.receipt.method}/${payment.receipt.intent}`
      : payment.receipt.method;
    const details = [`reference=${payment.receipt.reference}`];
    if (typeof payment.receipt.txHash === 'string' && payment.receipt.txHash.trim()) {
      details.push(`txHash=${payment.receipt.txHash}`);
    }
    lines.push(`MPP receipt (${label}): ${details.join(' ')}`);
  }
  if (payment.closeReceipt) {
    const label = payment.closeReceipt.intent
      ? `${payment.closeReceipt.method}/${payment.closeReceipt.intent}`
      : payment.closeReceipt.method;
    lines.push(`MPP close receipt (${label}): reference=${payment.closeReceipt.reference}`);
  }
  return lines;
}

function isLikelyInsufficientFundsError(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }

  const message = error.message.toLowerCase();
  return (
    message.includes('insufficient funds') ||
    message.includes('exceeds the balance of the account') ||
    message.includes('sender account balance')
  );
}

function formatMppSessionTokenAmount(
  amountWei: bigint,
  decimals: number,
  tokenLabel: string,
): string {
  return `${formatConfiguredAmount(amountWei, decimals)} ${tokenLabel} (${amountWei.toString()} raw units)`;
}

async function rewriteMppSessionInsufficientFundsError(input: {
  error: unknown;
  stage: 'open' | 'topUp';
  rpcUrl: string;
  token: Address;
  walletAddress: Address;
  decimals: number;
  requestAmountWei?: bigint;
  depositWei?: bigint;
  additionalDepositWei?: bigint;
  targetDepositWei?: bigint;
  requiredCumulativeAmountWei?: bigint;
}): Promise<Error> {
  if (!isLikelyInsufficientFundsError(input.error)) {
    return input.error instanceof Error ? input.error : new Error(String(input.error));
  }

  let tokenLabel: string = input.token;
  let balance: {
    raw: bigint;
    formatted: string;
  } | null = null;

  try {
    const tokenBalance = await getTokenBalance(
      input.rpcUrl,
      input.token,
      input.walletAddress,
      input.decimals,
    );
    tokenLabel = tokenBalance.symbol?.trim() || tokenLabel;
    balance = {
      raw: tokenBalance.raw,
      formatted: tokenBalance.formatted,
    };
  } catch {
    // Best-effort enrichment only. Preserve the original balance error if RPC metadata reads fail.
  }

  const lines = [
    `tempo/session ${input.stage} could not be prepared because the wallet balance is insufficient.`,
  ];
  if (input.requestAmountWei !== undefined) {
    lines.push(
      `required payment amount: ${formatMppSessionTokenAmount(
        input.requestAmountWei,
        input.decimals,
        tokenLabel,
      )}`,
    );
  }
  if (input.depositWei !== undefined) {
    lines.push(
      `required session deposit: ${formatMppSessionTokenAmount(
        input.depositWei,
        input.decimals,
        tokenLabel,
      )}`,
    );
  }
  if (input.additionalDepositWei !== undefined) {
    lines.push(
      `required additional session deposit: ${formatMppSessionTokenAmount(
        input.additionalDepositWei,
        input.decimals,
        tokenLabel,
      )}`,
    );
  }
  if (input.targetDepositWei !== undefined) {
    lines.push(
      `target session deposit: ${formatMppSessionTokenAmount(
        input.targetDepositWei,
        input.decimals,
        tokenLabel,
      )}`,
    );
  }
  if (input.requiredCumulativeAmountWei !== undefined) {
    lines.push(
      `required cumulative paid amount: ${formatMppSessionTokenAmount(
        input.requiredCumulativeAmountWei,
        input.decimals,
        tokenLabel,
      )}`,
    );
  }
  if (balance) {
    lines.push(
      `wallet token balance: ${balance.formatted} ${tokenLabel} (${balance.raw.toString()} raw units)`,
    );
    const depositRequirement = input.additionalDepositWei ?? input.depositWei;
    if (depositRequirement !== undefined && balance.raw < depositRequirement) {
      lines.push(
        `minimum deposit shortfall (fees excluded): ${formatMppSessionTokenAmount(
          depositRequirement - balance.raw,
          input.decimals,
          tokenLabel,
        )}`,
      );
    }
  } else {
    lines.push(`payment token: ${tokenLabel}`);
  }
  lines.push(
    `underlying error: ${input.error instanceof Error ? input.error.message : String(input.error)}`,
  );
  return new Error(lines.join('\n'));
}

interface TempoSessionState {
  version: 1;
  kind: 'tempo_session';
  chainId: number;
  rpcUrl: string;
  escrowContract: Address;
  token: Address;
  recipient: Address;
  walletAddress: Address;
  channelId: Hex;
  depositWei: string;
  cumulativeAmountWei: string;
}

const PRIVATE_FILE_MODE = 0o600;
const MAX_SESSION_STATE_FILE_BYTES = 64 * 1024;

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

function resolveOptionalSessionStatePath(value: string | undefined): string | undefined {
  if (!value?.trim()) {
    return undefined;
  }
  const resolvedPath = path.resolve(value.trim());
  if (!path.basename(resolvedPath).trim()) {
    throw new Error('sessionStateFile path is required');
  }
  return resolvedPath;
}

function parseTempoSessionState(value: unknown): TempoSessionState {
  if (!isPlainObject(value)) {
    throw new Error('tempo session state must be an object');
  }
  if (value.version !== 1 || value.kind !== 'tempo_session') {
    throw new Error('tempo session state file has an unsupported format');
  }

  return {
    version: 1,
    kind: 'tempo_session',
    chainId: parsePositiveIntegerString(String(value.chainId), 'tempo session state.chainId'),
    rpcUrl: assertSafeRpcUrl(
      requiredString(String(value.rpcUrl ?? ''), 'tempo session state.rpcUrl'),
      'tempo session state.rpcUrl',
    ),
    escrowContract: assertAddress(
      requiredString(String(value.escrowContract ?? ''), 'tempo session state.escrowContract'),
      'tempo session state.escrowContract',
    ),
    token: assertAddress(
      requiredString(String(value.token ?? ''), 'tempo session state.token'),
      'tempo session state.token',
    ),
    recipient: assertAddress(
      requiredString(String(value.recipient ?? ''), 'tempo session state.recipient'),
      'tempo session state.recipient',
    ),
    walletAddress: assertAddress(
      requiredString(String(value.walletAddress ?? ''), 'tempo session state.walletAddress'),
      'tempo session state.walletAddress',
    ),
    channelId: assertHex(
      requiredString(String(value.channelId ?? ''), 'tempo session state.channelId'),
      'tempo session state.channelId',
    ),
    depositWei: normalizeUnsignedIntegerValue(value.depositWei, 'tempo session state.depositWei'),
    cumulativeAmountWei: normalizeUnsignedIntegerValue(
      value.cumulativeAmountWei,
      'tempo session state.cumulativeAmountWei',
      { allowZero: true },
    ),
  };
}

function readTempoSessionStateFile(sessionStatePath: string | undefined): TempoSessionState | null {
  if (!sessionStatePath) {
    return null;
  }

  const stats = safeLstat(sessionStatePath);
  if (!stats) {
    return null;
  }
  if (stats.isSymbolicLink()) {
    throw new Error(`session state file '${sessionStatePath}' must not be a symlink`);
  }
  if (!stats.isFile()) {
    throw new Error(`session state file '${sessionStatePath}' must be a regular file`);
  }
  if (stats.size > MAX_SESSION_STATE_FILE_BYTES) {
    throw new Error(
      `session state file '${sessionStatePath}' must not exceed ${MAX_SESSION_STATE_FILE_BYTES} bytes`,
    );
  }

  const raw = fs.readFileSync(sessionStatePath, 'utf8');
  return parseTempoSessionState(JSON.parse(raw));
}

function writeTempoSessionStateFile(
  sessionStatePath: string | undefined,
  state: TempoSessionState,
): void {
  if (!sessionStatePath) {
    return;
  }

  const parent = path.dirname(sessionStatePath);
  fs.mkdirSync(parent, { recursive: true });

  const existing = safeLstat(sessionStatePath);
  if (existing?.isSymbolicLink()) {
    throw new Error(`session state file '${sessionStatePath}' must not be a symlink`);
  }
  if (existing && !existing.isFile()) {
    throw new Error(`session state file '${sessionStatePath}' must be a regular file`);
  }

  const tempPath = path.join(
    parent,
    `.${path.basename(sessionStatePath)}.tmp-${process.pid}-${Date.now()}`,
  );
  try {
    fs.writeFileSync(tempPath, `${JSON.stringify(state, null, 2)}\n`, {
      encoding: 'utf8',
      mode: PRIVATE_FILE_MODE,
      flag: 'wx',
    });
    try {
      fs.chmodSync(tempPath, PRIVATE_FILE_MODE);
    } catch {}
    fs.renameSync(tempPath, sessionStatePath);
    try {
      fs.chmodSync(sessionStatePath, PRIVATE_FILE_MODE);
    } catch {}
  } finally {
    try {
      if (fs.existsSync(tempPath)) {
        fs.rmSync(tempPath, { force: true });
      }
    } catch {}
  }
}

function deleteTempoSessionStateFile(sessionStatePath: string | undefined): void {
  if (!sessionStatePath) {
    return;
  }
  try {
    fs.rmSync(sessionStatePath, { force: true });
  } catch {}
}

function createTempoSessionState(input: {
  chainId: number;
  rpcUrl: string;
  escrowContract: Address;
  token: Address;
  recipient: Address;
  walletAddress: Address;
  channelId: Hex;
  depositWei: bigint;
  cumulativeAmountWei: bigint;
}): TempoSessionState {
  return {
    version: 1,
    kind: 'tempo_session',
    chainId: input.chainId,
    rpcUrl: input.rpcUrl,
    escrowContract: input.escrowContract,
    token: input.token,
    recipient: input.recipient,
    walletAddress: input.walletAddress,
    channelId: input.channelId,
    depositWei: input.depositWei.toString(),
    cumulativeAmountWei: input.cumulativeAmountWei.toString(),
  };
}

function resolveTempoSessionCumulativeAmountWei(
  receipt: MppReceipt | null | undefined,
  fallback: bigint,
): bigint {
  if (typeof receipt?.acceptedCumulative === 'string' && receipt.acceptedCumulative.trim()) {
    return parseBigIntString(receipt.acceptedCumulative, 'payment.receipt.acceptedCumulative');
  }
  if (typeof receipt?.spent === 'string' && receipt.spent.trim()) {
    return parseBigIntString(receipt.spent, 'payment.receipt.spent');
  }
  return fallback;
}

interface TempoSessionNeedVoucherEvent {
  channelId: Hex;
  requiredCumulative: string;
  acceptedCumulative: string;
  deposit: string;
}

function parseTempoSessionSseEvent(
  chunk: string,
):
  | { type: 'message'; data: string }
  | { type: 'payment-need-voucher'; data: TempoSessionNeedVoucherEvent }
  | { type: 'payment-receipt'; data: MppReceipt }
  | null {
  const lines = chunk
    .split(/\r?\n/u)
    .map((line) => line.trimEnd())
    .filter((line) => line.length > 0 && !line.startsWith(':'));
  if (lines.length === 0) {
    return null;
  }

  let eventType = 'message';
  const dataLines: string[] = [];
  for (const line of lines) {
    if (line.startsWith('event:')) {
      eventType = line.slice(6).trim();
      continue;
    }
    if (line.startsWith('data:')) {
      dataLines.push(line.slice(5).trimStart());
    }
  }
  const data = dataLines.join('\n');

  if (eventType === 'message') {
    return { type: 'message', data };
  }
  if (eventType === 'payment-need-voucher') {
    const parsed = JSON.parse(data) as Record<string, unknown>;
    return {
      type: 'payment-need-voucher',
      data: {
        channelId: assertHex(
          requiredString(String(parsed.channelId ?? ''), 'payment-need-voucher.channelId'),
          'payment-need-voucher.channelId',
        ),
        requiredCumulative: requiredString(
          String(parsed.requiredCumulative ?? ''),
          'payment-need-voucher.requiredCumulative',
        ),
        acceptedCumulative: requiredString(
          String(parsed.acceptedCumulative ?? ''),
          'payment-need-voucher.acceptedCumulative',
        ),
        deposit: requiredString(String(parsed.deposit ?? ''), 'payment-need-voucher.deposit'),
      },
    };
  }
  if (eventType === 'payment-receipt') {
    return {
      type: 'payment-receipt',
      data:
        parseMppReceiptFromHeaders(
          new Headers({
            'Payment-Receipt': Buffer.from(data, 'utf8').toString('base64url'),
          }),
        ) ??
        (() => {
          throw new Error('invalid payment-receipt event');
        })(),
    };
  }
  return null;
}

const TEMPO_VOUCHER_DOMAIN_NAME = 'Tempo Stream Channel';
const TEMPO_VOUCHER_DOMAIN_VERSION = '1';
const tempoEscrowAbi = [
  {
    type: 'function',
    name: 'open',
    inputs: [
      { name: 'payee', type: 'address' },
      { name: 'token', type: 'address' },
      { name: 'deposit', type: 'uint128' },
      { name: 'salt', type: 'bytes32' },
      { name: 'authorizedSigner', type: 'address' },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'topUp',
    inputs: [
      { name: 'channelId', type: 'bytes32' },
      { name: 'additionalDeposit', type: 'uint256' },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
] as const;

function resolveTempoChainDefinition(chainId: number) {
  if (chainId === tempoChain.id) {
    return tempoChain;
  }
  if (chainId === tempoModerato.id) {
    return tempoModerato;
  }
  throw new Error(`agentpay mpp tempo support requires a known Tempo chain, received ${chainId}`);
}

function randomHex(size: number, label: string): Hex {
  return assertHex(toHex(globalThis.crypto.getRandomValues(new Uint8Array(size))), label);
}

function computeTempoSessionChannelId(input: {
  payer: Address;
  recipient: Address;
  token: Address;
  salt: Hex;
  authorizedSigner: Address;
  escrowContract: Address;
  chainId: number;
}): Hex {
  return assertHex(
    keccak256(
      encodeAbiParameters(
        [
          { name: 'payer', type: 'address' },
          { name: 'payee', type: 'address' },
          { name: 'token', type: 'address' },
          { name: 'salt', type: 'bytes32' },
          { name: 'authorizedSigner', type: 'address' },
          { name: 'escrowContract', type: 'address' },
          { name: 'chainId', type: 'uint256' },
        ],
        [
          input.payer,
          input.recipient,
          input.token,
          input.salt,
          input.authorizedSigner,
          input.escrowContract,
          BigInt(input.chainId),
        ],
      ),
    ),
    'tempo session channelId',
  );
}

function computeTempoSessionVoucherSigningHash(input: {
  chainId: number;
  escrowContract: Address;
  channelId: Hex;
  cumulativeAmountWei: bigint;
}): Hex {
  return assertHex(
    hashTypedData({
      domain: {
        name: TEMPO_VOUCHER_DOMAIN_NAME,
        version: TEMPO_VOUCHER_DOMAIN_VERSION,
        chainId: input.chainId,
        verifyingContract: input.escrowContract,
      },
      types: {
        Voucher: [
          { name: 'channelId', type: 'bytes32' },
          { name: 'cumulativeAmount', type: 'uint128' },
        ],
      },
      primaryType: 'Voucher',
      message: {
        channelId: input.channelId,
        cumulativeAmount: input.cumulativeAmountWei,
      },
    }),
    'tempo session voucher signing hash',
  );
}

function normalizeUnsignedIntegerValue(
  value: unknown,
  label: string,
  options: { allowZero?: boolean } = {},
): string {
  let normalized: string;
  if (typeof value === 'bigint') {
    normalized = value.toString();
  } else if (typeof value === 'number') {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value)) {
      throw new Error(`${label} must be a safe integer`);
    }
    normalized = String(value);
  } else if (typeof value === 'string') {
    normalized = value.trim();
  } else {
    throw new Error(`${label} must be an unsigned integer`);
  }

  const parsed = parseBigIntString(normalized, label);
  if (!options.allowZero && parsed <= 0n) {
    throw new Error(`${label} must be greater than zero`);
  }
  return parsed.toString();
}

function buildBroadcastCommandArgs(plan: {
  chainId: number;
  nonce: number;
  to: Address;
  valueWei: bigint;
  dataHex: Hex;
  gasLimit: bigint;
  maxFeePerGasWei: bigint;
  maxPriorityFeePerGasWei: bigint;
  txType: string;
}): string[] {
  return [
    'broadcast',
    '--network',
    String(plan.chainId),
    '--nonce',
    String(plan.nonce),
    '--to',
    plan.to,
    '--value-wei',
    plan.valueWei.toString(),
    '--data-hex',
    plan.dataHex,
    '--gas-limit',
    plan.gasLimit.toString(),
    '--max-fee-per-gas-wei',
    plan.maxFeePerGasWei.toString(),
    '--max-priority-fee-per-gas-wei',
    plan.maxPriorityFeePerGasWei.toString(),
    '--tx-type',
    plan.txType,
  ];
}

function resolveRpcUrlForChainId(
  config: WlfiConfig,
  chainId: number,
  explicitRpcUrl: string | undefined,
  fallbackRpcUrl?: string | null,
): string {
  if (explicitRpcUrl?.trim()) {
    return assertSafeRpcUrl(explicitRpcUrl, 'rpcUrl');
  }

  const chainProfile = resolveChainProfile(String(chainId), config);
  const configuredRpcUrl = chainProfile?.rpcUrl?.trim();
  if (configuredRpcUrl) {
    return assertSafeRpcUrl(configuredRpcUrl, 'rpcUrl');
  }

  if (fallbackRpcUrl?.trim()) {
    return assertSafeRpcUrl(fallbackRpcUrl, 'rpcUrl');
  }

  throw new Error(
    `rpcUrl is required for chain ${chainId}; configure that chain or pass --rpc-url`,
  );
}

function hexDataByteLength(value: Hex, label: string): number {
  if ((value.length - 2) % 2 !== 0) {
    throw new Error(`${label} must have an even number of hex digits`);
  }
  return (value.length - 2) / 2;
}

function normalizeRecoverableSignatureHex(
  output: Pick<RustBroadcastOutput, 'signature_hex' | 'r_hex' | 's_hex' | 'v'>,
  label: string,
): Hex {
  if (output.r_hex && output.s_hex && output.v !== undefined) {
    const rHex = assertHex(output.r_hex, `${label}.r`);
    const sHex = assertHex(output.s_hex, `${label}.s`);
    if (hexDataByteLength(rHex, `${label}.r`) !== 32) {
      throw new Error(`${label}.r must be 32 bytes`);
    }
    if (hexDataByteLength(sHex, `${label}.s`) !== 32) {
      throw new Error(`${label}.s must be 32 bytes`);
    }

    const recoveryByte =
      output.v === 0 || output.v === 1
        ? output.v + 27
        : output.v === 27 || output.v === 28
          ? output.v
          : (() => {
              throw new Error(`${label}.v must be 0, 1, 27, or 28`);
            })();

    return assertHex(
      `0x${rHex.slice(2)}${sHex.slice(2)}${recoveryByte.toString(16).padStart(2, '0')}`,
      label,
    );
  }

  return assertHex(output.signature_hex, label);
}

async function signAgentEip3009TransferWithAuthorization(input: {
  auth: AgentCommandAuthOptions;
  config: WlfiConfig;
  chainId: number;
  token: Address;
  tokenName: string;
  tokenVersion?: string;
  from: Address;
  to: Address;
  amountWei: bigint;
  validAfter: string;
  validBefore: string;
  nonceHex: Hex;
}): Promise<Hex> {
  const commandArgs = [
    'eip3009-transfer-with-authorization',
    '--network',
    String(input.chainId),
    '--token',
    input.token,
    '--token-name',
    input.tokenName,
    ...(input.tokenVersion ? ['--token-version', input.tokenVersion] : []),
    '--from',
    input.from,
    '--to',
    input.to,
    '--amount-wei',
    input.amountWei.toString(),
    '--valid-after',
    input.validAfter,
    '--valid-before',
    input.validBefore,
    '--nonce-hex',
    input.nonceHex,
  ];

  const result = await runAgentCommandJson<RustBroadcastOutput>({
    commandArgs,
    auth: input.auth,
    config: input.config,
    asJson: false,
    waitForManualApproval: true,
  });
  if (!result) {
    throw new Error('agentpay-agent did not return an EIP-3009 signature');
  }
  return normalizeRecoverableSignatureHex(result, 'signatureHex');
}

async function signAgentTempoSessionOpenTransaction(input: {
  auth: AgentCommandAuthOptions;
  config: WlfiConfig;
  chainId: number;
  token: Address;
  recipient: Address;
  depositWei: bigint;
  initialAmountWei: bigint;
  signingHashHex: Hex;
}): Promise<Hex> {
  const result = await runAgentCommandJson<RustBroadcastOutput>({
    commandArgs: [
      'tempo-session-open-transaction',
      '--network',
      String(input.chainId),
      '--token',
      input.token,
      '--recipient',
      input.recipient,
      '--deposit-wei',
      input.depositWei.toString(),
      '--initial-amount-wei',
      input.initialAmountWei.toString(),
      '--signing-hash-hex',
      input.signingHashHex,
    ],
    auth: input.auth,
    config: input.config,
    asJson: false,
    waitForManualApproval: true,
  });
  if (!result) {
    throw new Error('agentpay-agent did not return a Tempo session open transaction signature');
  }
  return normalizeRecoverableSignatureHex(result, 'signatureHex');
}

async function signAgentTempoSessionVoucher(input: {
  auth: AgentCommandAuthOptions;
  config: WlfiConfig;
  chainId: number;
  escrowContract: Address;
  token: Address;
  recipient: Address;
  channelId: Hex;
  amountWei: bigint;
  cumulativeAmountWei: bigint;
  signingHashHex: Hex;
}): Promise<Hex> {
  const result = await runAgentCommandJson<RustBroadcastOutput>({
    commandArgs: [
      'tempo-session-voucher',
      '--network',
      String(input.chainId),
      '--escrow-contract',
      input.escrowContract,
      '--token',
      input.token,
      '--recipient',
      input.recipient,
      '--channel-id-hex',
      input.channelId,
      '--amount-wei',
      input.amountWei.toString(),
      '--cumulative-amount-wei',
      input.cumulativeAmountWei.toString(),
      '--signing-hash-hex',
      input.signingHashHex,
    ],
    auth: input.auth,
    config: input.config,
    asJson: false,
    waitForManualApproval: true,
  });
  if (!result) {
    throw new Error('agentpay-agent did not return a Tempo session voucher signature');
  }
  return normalizeRecoverableSignatureHex(result, 'signatureHex');
}

async function signAgentTempoSessionTopUpTransaction(input: {
  auth: AgentCommandAuthOptions;
  config: WlfiConfig;
  chainId: number;
  token: Address;
  recipient: Address;
  channelId: Hex;
  additionalDepositWei: bigint;
  signingHashHex: Hex;
}): Promise<Hex> {
  const result = await runAgentCommandJson<RustBroadcastOutput>({
    commandArgs: [
      'tempo-session-top-up-transaction',
      '--network',
      String(input.chainId),
      '--token',
      input.token,
      '--recipient',
      input.recipient,
      '--channel-id-hex',
      input.channelId,
      '--additional-deposit-wei',
      input.additionalDepositWei.toString(),
      '--signing-hash-hex',
      input.signingHashHex,
    ],
    auth: input.auth,
    config: input.config,
    asJson: false,
    waitForManualApproval: true,
  });
  if (!result) {
    throw new Error('agentpay-agent did not return a Tempo session topUp transaction signature');
  }
  return normalizeRecoverableSignatureHex(result, 'signatureHex');
}

async function buildTempoSessionOpenPayload(input: {
  auth: AgentCommandAuthOptions;
  config: WlfiConfig;
  rpcUrl: string;
  chainId: number;
  token: Address;
  recipient: Address;
  escrowContract: Address;
  walletAddress: Address;
  decimals: number;
  amountWei: bigint;
  depositWei: bigint;
  feePayer: boolean;
}): Promise<{
  channelId: Hex;
  payload: {
    action: 'open';
    type: 'transaction';
    channelId: Hex;
    transaction: Hex;
    cumulativeAmount: string;
    signature: Hex;
    authorizedSigner: Address;
  };
}> {
  const authorizedSigner = input.walletAddress;
  const salt = randomHex(32, 'tempo session salt');
  const channelId = computeTempoSessionChannelId({
    payer: input.walletAddress,
    recipient: input.recipient,
    token: input.token,
    salt,
    authorizedSigner,
    escrowContract: input.escrowContract,
    chainId: input.chainId,
  });

  const client = createPublicClient({
    chain: resolveTempoChainDefinition(input.chainId),
    transport: http(input.rpcUrl),
  });
  const approveData = encodeFunctionData({
    abi: TempoAbis.tip20,
    functionName: 'approve',
    args: [input.escrowContract, input.depositWei],
  });
  const openData = encodeFunctionData({
    abi: tempoEscrowAbi,
    functionName: 'open',
    args: [input.recipient, input.token, input.depositWei, salt, authorizedSigner],
  });
  const prepared = await (async () => {
    try {
      return await prepareTransactionRequest(
        client as never,
        {
          account: input.walletAddress,
          calls: [
            { to: input.token, data: approveData },
            { to: input.escrowContract, data: openData },
          ],
          feeToken: input.token,
          ...(input.feePayer ? { feePayer: true } : {}),
        } as never,
      );
    } catch (error) {
      throw await rewriteMppSessionInsufficientFundsError({
        error,
        stage: 'open',
        rpcUrl: input.rpcUrl,
        token: input.token,
        walletAddress: input.walletAddress,
        decimals: input.decimals,
        requestAmountWei: input.amountWei,
        depositWei: input.depositWei,
      });
    }
  })();
  const unsignedTransaction = {
    ...prepared,
    from: input.walletAddress,
    type: 'tempo' as const,
  };
  const envelope = TempoTransaction.z_TxEnvelopeTempo.from(unsignedTransaction as never);
  const signingHashHex = assertHex(
    TempoTransaction.z_TxEnvelopeTempo.getSignPayload(envelope, {
      from: input.walletAddress,
    }) as Hex,
    'tempo session open signing hash',
  );
  const transactionSignatureHex = await signAgentTempoSessionOpenTransaction({
    auth: input.auth,
    config: input.config,
    chainId: input.chainId,
    token: input.token,
    recipient: input.recipient,
    depositWei: input.depositWei,
    initialAmountWei: input.amountWei,
    signingHashHex,
  });
  const transaction = assertHex(
    await TempoTransaction.serialize(
      unsignedTransaction as never,
      parseSignature(transactionSignatureHex) as never,
    ),
    'tempo session serialized transaction',
  );
  const voucherSigningHashHex = computeTempoSessionVoucherSigningHash({
    chainId: input.chainId,
    escrowContract: input.escrowContract,
    channelId,
    cumulativeAmountWei: input.amountWei,
  });
  const voucherSignatureHex = await signAgentTempoSessionVoucher({
    auth: input.auth,
    config: input.config,
    chainId: input.chainId,
    escrowContract: input.escrowContract,
    token: input.token,
    recipient: input.recipient,
    channelId,
    amountWei: input.amountWei,
    cumulativeAmountWei: input.amountWei,
    signingHashHex: voucherSigningHashHex,
  });

  return {
    channelId,
    payload: {
      action: 'open',
      type: 'transaction',
      channelId,
      transaction,
      cumulativeAmount: input.amountWei.toString(),
      signature: voucherSignatureHex,
      authorizedSigner,
    },
  };
}

async function buildTempoSessionClosePayload(input: {
  auth: AgentCommandAuthOptions;
  config: WlfiConfig;
  chainId: number;
  escrowContract: Address;
  token: Address;
  recipient: Address;
  channelId: Hex;
  cumulativeAmountWei: bigint;
}): Promise<{
  action: 'voucher' | 'close';
  channelId: Hex;
  cumulativeAmount: string;
  signature: Hex;
}> {
  return buildTempoSessionVoucherPayload({
    ...input,
    amountWei: input.cumulativeAmountWei,
    action: 'close',
  });
}

async function buildTempoSessionVoucherPayload(input: {
  auth: AgentCommandAuthOptions;
  config: WlfiConfig;
  chainId: number;
  escrowContract: Address;
  token: Address;
  recipient: Address;
  channelId: Hex;
  amountWei: bigint;
  cumulativeAmountWei: bigint;
  action: 'voucher' | 'close';
}): Promise<{
  action: 'voucher' | 'close';
  channelId: Hex;
  cumulativeAmount: string;
  signature: Hex;
}> {
  const signingHashHex = computeTempoSessionVoucherSigningHash({
    chainId: input.chainId,
    escrowContract: input.escrowContract,
    channelId: input.channelId,
    cumulativeAmountWei: input.cumulativeAmountWei,
  });
  const signatureHex = await signAgentTempoSessionVoucher({
    auth: input.auth,
    config: input.config,
    chainId: input.chainId,
    escrowContract: input.escrowContract,
    token: input.token,
    recipient: input.recipient,
    channelId: input.channelId,
    amountWei: input.amountWei,
    cumulativeAmountWei: input.cumulativeAmountWei,
    signingHashHex,
  });

  return {
    action: input.action,
    channelId: input.channelId,
    cumulativeAmount: input.cumulativeAmountWei.toString(),
    signature: signatureHex,
  };
}

async function buildTempoSessionTopUpPayload(input: {
  auth: AgentCommandAuthOptions;
  config: WlfiConfig;
  rpcUrl: string;
  chainId: number;
  token: Address;
  recipient: Address;
  escrowContract: Address;
  walletAddress: Address;
  decimals: number;
  channelId: Hex;
  requestAmountWei?: bigint;
  additionalDepositWei: bigint;
  targetDepositWei?: bigint;
  requiredCumulativeAmountWei?: bigint;
  feePayer: boolean;
}): Promise<{
  payload: {
    action: 'topUp';
    type: 'transaction';
    channelId: Hex;
    transaction: Hex;
    additionalDeposit: string;
  };
}> {
  const client = createPublicClient({
    chain: resolveTempoChainDefinition(input.chainId),
    transport: http(input.rpcUrl),
  });
  const approveData = encodeFunctionData({
    abi: TempoAbis.tip20,
    functionName: 'approve',
    args: [input.escrowContract, input.additionalDepositWei],
  });
  const topUpData = encodeFunctionData({
    abi: tempoEscrowAbi,
    functionName: 'topUp',
    args: [input.channelId, input.additionalDepositWei],
  });
  const prepared = await (async () => {
    try {
      return await prepareTransactionRequest(
        client as never,
        {
          account: input.walletAddress,
          calls: [
            { to: input.token, data: approveData },
            { to: input.escrowContract, data: topUpData },
          ],
          feeToken: input.token,
          ...(input.feePayer ? { feePayer: true } : {}),
        } as never,
      );
    } catch (error) {
      throw await rewriteMppSessionInsufficientFundsError({
        error,
        stage: 'topUp',
        rpcUrl: input.rpcUrl,
        token: input.token,
        walletAddress: input.walletAddress,
        decimals: input.decimals,
        requestAmountWei: input.requestAmountWei,
        additionalDepositWei: input.additionalDepositWei,
        targetDepositWei: input.targetDepositWei,
        requiredCumulativeAmountWei: input.requiredCumulativeAmountWei,
      });
    }
  })();
  const unsignedTransaction = {
    ...prepared,
    from: input.walletAddress,
    type: 'tempo' as const,
  };
  const envelope = TempoTransaction.z_TxEnvelopeTempo.from(unsignedTransaction as never);
  const signingHashHex = assertHex(
    TempoTransaction.z_TxEnvelopeTempo.getSignPayload(envelope, {
      from: input.walletAddress,
    }) as Hex,
    'tempo session topUp signing hash',
  );
  const transactionSignatureHex = await signAgentTempoSessionTopUpTransaction({
    auth: input.auth,
    config: input.config,
    chainId: input.chainId,
    token: input.token,
    recipient: input.recipient,
    channelId: input.channelId,
    additionalDepositWei: input.additionalDepositWei,
    signingHashHex,
  });
  const transaction = assertHex(
    await TempoTransaction.serialize(
      unsignedTransaction as never,
      parseSignature(transactionSignatureHex) as never,
    ),
    'tempo session topUp serialized transaction',
  );

  return {
    payload: {
      action: 'topUp',
      type: 'transaction',
      channelId: input.channelId,
      transaction,
      additionalDeposit: input.additionalDepositWei.toString(),
    },
  };
}

async function handleTempoSessionStreamResponse(input: {
  response: Response;
  asJson: boolean;
  challenge: ReturnType<typeof parseMppChallengeFromHeaders>;
  auth: AgentCommandAuthOptions;
  config: WlfiConfig;
  targetUrl: string;
  chainId: number;
  rpcUrl: string;
  token: Address;
  recipient: Address;
  escrowContract: Address;
  walletAddress: Address;
  decimals: number;
  sessionStatePath?: string;
  closeSession: boolean;
  defaultDepositWei: bigint;
  activeChannelId: Hex;
  activeDepositWei: bigint;
  activeCumulativeAmountWei: bigint;
  source: string;
}) {
  if (!input.response.body) {
    throw new Error('tempo/session event stream response has no body');
  }

  const reader = input.response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let latestReceipt: MppReceipt | null = parseMppReceiptFromHeaders(input.response.headers);
  let activeChannelId = input.activeChannelId;
  let activeDepositWei = input.activeDepositWei;
  let activeCumulativeAmountWei = input.activeCumulativeAmountWei;
  let spentWei = resolveTempoSessionCumulativeAmountWei(latestReceipt, activeCumulativeAmountWei);
  const emitJsonEvent = (event: string, payload: Record<string, unknown> = {}) => {
    if (!input.asJson) {
      return;
    }
    process.stdout.write(
      `${formatJsonLine({
        event,
        protocol: 'mpp',
        ...payload,
      })}\n`,
    );
  };

  emitJsonEvent('mppStreamStart', {
    url: input.response.url || input.targetUrl,
    status: input.response.status,
    ok: input.response.ok,
    headers: headersToObject(input.response.headers),
    payment: {
      challengeId: input.challenge.id,
      method: input.challenge.method,
      intent: input.challenge.intent,
      channelId: activeChannelId,
      receipt: latestReceipt,
    },
  });

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split('\n\n');
      buffer = parts.pop() ?? '';

      for (const part of parts) {
        const event = parseTempoSessionSseEvent(part);
        if (!event) {
          continue;
        }

        if (event.type === 'message') {
          if (input.asJson) {
            emitJsonEvent('mppStreamMessage', { data: event.data });
          } else if (event.data) {
            process.stdout.write(event.data.endsWith('\n') ? event.data : `${event.data}\n`);
          }
          continue;
        }

        if (event.type === 'payment-receipt') {
          latestReceipt = event.data;
          emitJsonEvent('mppStreamReceipt', { receipt: event.data });
          if (typeof event.data.channelId === 'string' && event.data.channelId.trim()) {
            activeChannelId = assertHex(event.data.channelId, 'payment.receipt.channelId');
          }
          activeCumulativeAmountWei = resolveTempoSessionCumulativeAmountWei(
            event.data,
            activeCumulativeAmountWei,
          );
          spentWei =
            typeof event.data.spent === 'string' && event.data.spent.trim()
              ? parseBigIntString(event.data.spent, 'payment.receipt.spent')
              : activeCumulativeAmountWei;
          if (input.sessionStatePath && !input.closeSession) {
            writeTempoSessionStateFile(
              input.sessionStatePath,
              createTempoSessionState({
                chainId: input.chainId,
                rpcUrl: input.rpcUrl,
                escrowContract: input.escrowContract,
                token: input.token,
                recipient: input.recipient,
                walletAddress: input.walletAddress,
                channelId: activeChannelId,
                depositWei: activeDepositWei,
                cumulativeAmountWei: activeCumulativeAmountWei,
              }),
            );
          }
          continue;
        }

        const acceptedCumulativeWei = parseBigIntString(
          event.data.acceptedCumulative,
          'payment-need-voucher.acceptedCumulative',
        );
        if (acceptedCumulativeWei > activeCumulativeAmountWei) {
          activeCumulativeAmountWei = acceptedCumulativeWei;
        }
        const requiredCumulativeWei = parseBigIntString(
          event.data.requiredCumulative,
          'payment-need-voucher.requiredCumulative',
        );
        emitJsonEvent('mppStreamNeedVoucher', {
          needVoucher: event.data,
        });
        if (requiredCumulativeWei > activeDepositWei) {
          const targetDepositWei =
            input.defaultDepositWei > requiredCumulativeWei
              ? input.defaultDepositWei
              : requiredCumulativeWei;
          const additionalDepositWei = targetDepositWei - activeDepositWei;
          const topUp = await buildTempoSessionTopUpPayload({
            auth: input.auth,
            config: input.config,
            rpcUrl: input.rpcUrl,
            chainId: input.chainId,
            token: input.token,
            recipient: input.recipient,
            escrowContract: input.escrowContract,
            walletAddress: input.walletAddress,
            decimals: input.decimals,
            channelId: activeChannelId,
            requestAmountWei:
              requiredCumulativeWei > acceptedCumulativeWei
                ? requiredCumulativeWei - acceptedCumulativeWei
                : undefined,
            additionalDepositWei,
            targetDepositWei,
            requiredCumulativeAmountWei: requiredCumulativeWei,
            feePayer: input.challenge.request.methodDetails?.feePayer === true,
          });
          const topUpResponse = await globalThis.fetch(input.targetUrl, {
            method: 'POST',
            headers: withAuthorizationHeader(
              undefined,
              serializeMppCredentialHeader({
                challenge: input.challenge,
                payload: topUp.payload,
                source: input.source,
              }),
            ),
          });
          if (!topUpResponse.ok) {
            const topUpErrorBody = await topUpResponse.text();
            throw new Error(
              `tempo/session topUp failed with status ${topUpResponse.status}${topUpErrorBody ? `: ${topUpErrorBody}` : ''}`,
            );
          }
          activeDepositWei = targetDepositWei;
          emitJsonEvent('mppStreamTopUp', {
            channelId: activeChannelId,
            additionalDepositWei,
            depositWei: activeDepositWei,
          });
        }

        if (requiredCumulativeWei > activeCumulativeAmountWei) {
          const voucherPayload = await buildTempoSessionVoucherPayload({
            auth: input.auth,
            config: input.config,
            chainId: input.chainId,
            escrowContract: input.escrowContract,
            token: input.token,
            recipient: input.recipient,
            channelId: activeChannelId,
            amountWei: requiredCumulativeWei - activeCumulativeAmountWei,
            cumulativeAmountWei: requiredCumulativeWei,
            action: 'voucher',
          });
          const voucherResponse = await globalThis.fetch(input.targetUrl, {
            method: 'POST',
            headers: withAuthorizationHeader(
              undefined,
              serializeMppCredentialHeader({
                challenge: input.challenge,
                payload: voucherPayload,
                source: input.source,
              }),
            ),
          });
          if (!voucherResponse.ok) {
            const voucherErrorBody = await voucherResponse.text();
            throw new Error(
              `tempo/session voucher failed with status ${voucherResponse.status}${voucherErrorBody ? `: ${voucherErrorBody}` : ''}`,
            );
          }
          activeCumulativeAmountWei = requiredCumulativeWei;
          emitJsonEvent('mppStreamVoucher', {
            channelId: activeChannelId,
            amountWei: requiredCumulativeWei - acceptedCumulativeWei,
            cumulativeAmountWei: activeCumulativeAmountWei,
          });
        }
      }
    }
  } finally {
    reader.releaseLock();
  }

  let closeReceipt: MppReceipt | null = null;
  const shouldCloseSession = !input.sessionStatePath || input.closeSession;
  if (shouldCloseSession) {
    const closePayload = await buildTempoSessionClosePayload({
      auth: input.auth,
      config: input.config,
      chainId: input.chainId,
      escrowContract: input.escrowContract,
      token: input.token,
      recipient: input.recipient,
      channelId: activeChannelId,
      cumulativeAmountWei: spentWei > 0n ? spentWei : activeCumulativeAmountWei,
    });
    const closeResponse = await globalThis.fetch(input.targetUrl, {
      method: 'POST',
      headers: withAuthorizationHeader(
        undefined,
        serializeMppCredentialHeader({
          challenge: input.challenge,
          payload: closePayload,
          source: input.source,
        }),
      ),
    });
    if (!closeResponse.ok) {
      const closeErrorBody = await closeResponse.text();
      throw new Error(
        `tempo/session close failed with status ${closeResponse.status}${closeErrorBody ? `: ${closeErrorBody}` : ''}`,
      );
    }
    closeReceipt = parseMppReceiptFromHeaders(closeResponse.headers);
    deleteTempoSessionStateFile(input.sessionStatePath);
  } else if (input.sessionStatePath) {
    writeTempoSessionStateFile(
      input.sessionStatePath,
      createTempoSessionState({
        chainId: input.chainId,
        rpcUrl: input.rpcUrl,
        escrowContract: input.escrowContract,
        token: input.token,
        recipient: input.recipient,
        walletAddress: input.walletAddress,
        channelId: activeChannelId,
        depositWei: activeDepositWei,
        cumulativeAmountWei: activeCumulativeAmountWei,
      }),
    );
  }

  const summaryLines = buildMppPaymentSummaryLines({
    channelId: activeChannelId,
    receipt: latestReceipt,
    closeReceipt,
  });
  if (input.asJson) {
    emitJsonEvent('mppStreamEnd', {
      channelId: activeChannelId,
      receipt: latestReceipt,
      closeReceipt,
    });
  } else {
    for (const line of summaryLines) {
      console.error(line);
    }
  }
}

function createAgentPayX402Signer(input: {
  auth: AgentCommandAuthOptions;
  config: WlfiConfig;
}): ClientEvmSigner {
  const walletAddress = resolveWalletAddress(input.config);

  return {
    address: walletAddress,
    async signTypedData(message) {
      if (message.primaryType !== 'TransferWithAuthorization') {
        throw new Error(`Unsupported x402 typed-data primary type: ${message.primaryType}`);
      }
      if (!isPlainObject(message.domain) || !isPlainObject(message.message)) {
        throw new Error('x402 typed-data payload must include object domain and message fields');
      }

      const domainName = requiredString(
        typeof message.domain.name === 'string' ? message.domain.name : undefined,
        'x402 domain.name',
      );
      const domainVersion =
        typeof message.domain.version === 'string' ? message.domain.version : undefined;
      const chainId = parsePositiveIntegerString(
        normalizeUnsignedIntegerValue(message.domain.chainId, 'x402 domain.chainId', {
          allowZero: false,
        }),
        'x402 domain.chainId',
      );
      const token = assertAddress(
        requiredString(
          typeof message.domain.verifyingContract === 'string'
            ? message.domain.verifyingContract
            : undefined,
          'x402 domain.verifyingContract',
        ),
        'x402 domain.verifyingContract',
      );
      const from = assertAddress(
        requiredString(
          typeof message.message.from === 'string' ? message.message.from : undefined,
          'x402 message.from',
        ),
        'x402 message.from',
      );
      if (from.toLowerCase() !== walletAddress.toLowerCase()) {
        throw new Error(
          `x402 payment requires signature from configured wallet ${walletAddress}, received ${from}`,
        );
      }

      const to = assertAddress(
        requiredString(
          typeof message.message.to === 'string' ? message.message.to : undefined,
          'x402 message.to',
        ),
        'x402 message.to',
      );
      const amountWei = parseBigIntString(
        normalizeUnsignedIntegerValue(message.message.value, 'x402 message.value', {
          allowZero: false,
        }),
        'x402 message.value',
      );
      const validAfter = normalizeUnsignedIntegerValue(
        message.message.validAfter,
        'x402 message.validAfter',
      );
      const validBefore = normalizeUnsignedIntegerValue(
        message.message.validBefore,
        'x402 message.validBefore',
        { allowZero: false },
      );
      const nonceHex = assertHex(
        requiredString(
          typeof message.message.nonce === 'string' ? message.message.nonce : undefined,
          'x402 message.nonce',
        ),
        'x402 message.nonce',
      );

      return await signAgentEip3009TransferWithAuthorization({
        auth: input.auth,
        config: input.config,
        chainId,
        token,
        tokenName: domainName,
        tokenVersion: domainVersion,
        from,
        to,
        amountWei,
        validAfter,
        validBefore,
        nonceHex,
      });
    },
  };
}

function selectPreferredX402Requirement(_x402Version: number, accepts: PaymentRequirements[]) {
  const selected = accepts.find((candidate) => {
    if (candidate.scheme !== 'exact') {
      return false;
    }
    if (!isPlainObject(candidate.extra)) {
      return true;
    }
    const assetTransferMethod = candidate.extra.assetTransferMethod;
    return assetTransferMethod === undefined || assetTransferMethod === 'eip3009';
  });

  if (!selected) {
    throw new Error('agentpay x402 currently supports only exact/eip3009 payment requirements');
  }

  return selected;
}

function formatWalletBackupExportOutput(input: {
  outputPath: string;
  address: string;
  sourceVaultKeyId?: string;
  createdAt: string;
}): string {
  return [
    'wallet backup exported',
    `path: ${input.outputPath}`,
    `address: ${input.address}`,
    input.sourceVaultKeyId ? `source vault key id: ${input.sourceVaultKeyId}` : null,
    `created at: ${input.createdAt}`,
    `restore with: agentpay admin setup --restore-wallet-from ${input.outputPath}`,
  ]
    .filter((line): line is string => Boolean(line))
    .join('\n');
}

function formatWalletBackupVerifyOutput(input: {
  sourcePath: string;
  address: string;
  sourceVaultKeyId?: string;
  createdAt: string;
}): string {
  return [
    'wallet backup verified',
    `path: ${input.sourcePath}`,
    `address: ${input.address}`,
    input.sourceVaultKeyId ? `source vault key id: ${input.sourceVaultKeyId}` : null,
    `created at: ${input.createdAt}`,
  ]
    .filter((line): line is string => Boolean(line))
    .join('\n');
}

const ONCHAIN_RECEIPT_TIMEOUT_MS = 30_000;
const ONCHAIN_RECEIPT_POLL_INTERVAL_MS = 2_000;
const MANUAL_APPROVAL_POLL_INTERVAL_MS = 2_000;
const BITREFILL_CHALLENGE_EXIT_CODE = 4;
const BITREFILL_WAIT_TIMEOUT_EXIT_CODE = 5;
const MANUAL_APPROVAL_WAIT_TIMEOUT_MS = (() => {
  const raw = process.env.AGENTPAY_TEST_MANUAL_APPROVAL_TIMEOUT_MS;
  if (!raw) {
    return 5 * 60_000;
  }
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 5 * 60_000;
})();

async function reportOnchainReceiptStatus(input: {
  rpcUrl: string;
  txHash: Hex;
  asJson: boolean;
}): Promise<void> {
  if (input.asJson) {
    console.error(
      formatJson({
        event: 'onchainReceiptPending',
        txHash: input.txHash,
        timeoutMs: ONCHAIN_RECEIPT_TIMEOUT_MS,
      }),
    );
  } else {
    console.error(
      `Waiting up to ${ONCHAIN_RECEIPT_TIMEOUT_MS / 1000}s for on-chain receipt: ${input.txHash}`,
    );
  }

  try {
    const result = await waitForOnchainReceipt(
      {
        rpcUrl: input.rpcUrl,
        txHash: input.txHash,
        timeoutMs: ONCHAIN_RECEIPT_TIMEOUT_MS,
        intervalMs: ONCHAIN_RECEIPT_POLL_INTERVAL_MS,
      },
      {
        getTransactionReceiptByHash,
      },
    );

    if (result.receipt) {
      const summary = {
        event: 'onchainReceipt',
        txHash: input.txHash,
        blockNumber: stringifyOptionalValue(result.receipt.blockNumber),
        transactionIndex: result.receipt.transactionIndex,
        status: result.receipt.status,
      };
      if (input.asJson) {
        console.error(formatJson(summary));
      } else {
        console.error(
          `On-chain receipt: ${result.receipt.status} block ${result.receipt.blockNumber} txIndex ${result.receipt.transactionIndex}`,
        );
      }
      return;
    }

    if (input.asJson) {
      console.error(
        formatJson({
          event: 'onchainReceiptTimeout',
          txHash: input.txHash,
          timeoutMs: ONCHAIN_RECEIPT_TIMEOUT_MS,
        }),
      );
    } else {
      console.error(
        `Timed out after ${ONCHAIN_RECEIPT_TIMEOUT_MS / 1000}s waiting for on-chain receipt`,
      );
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (input.asJson) {
      console.error(
        formatJson({
          event: 'onchainReceiptPollingError',
          txHash: input.txHash,
          error: message,
        }),
      );
    } else {
      console.error(`On-chain receipt polling failed: ${message}`);
    }
  }
}

function parseConfigValue(key: WritableConfigKey, value: string): WlfiConfig {
  if (key === 'chainId') {
    return { [key]: parsePositiveIntegerString(value, key) };
  }
  if (key === 'agentKeyId') {
    return { [key]: assertAgentKeyId(value, key) };
  }
  if (key === 'rpcUrl') {
    return { [key]: assertSafeRpcUrl(value, key) };
  }
  return { [key]: value } as WlfiConfig;
}

function activeChainSummary(config: WlfiConfig) {
  return {
    chainId: config.chainId ?? null,
    chainName: config.chainName ?? null,
    rpcUrl: config.rpcUrl ?? null,
  };
}

function normalizeChainProfile(
  key: string,
  options: { chainId: string; name?: string; rpcUrl?: string },
): ChainProfile {
  const rpcUrl = options.rpcUrl?.trim();
  return {
    chainId: parsePositiveIntegerString(options.chainId, 'chainId'),
    name: options.name?.trim() || key.trim().toLowerCase(),
    rpcUrl: rpcUrl ? assertSafeRpcUrl(rpcUrl, 'rpcUrl') : undefined,
  };
}

interface AgentCommandAuthOptions {
  agentKeyId?: string;
  agentAuthToken?: string;
  agentAuthTokenStdin?: boolean;
  allowLegacyAgentAuthSource?: boolean;
  daemonSocket?: string;
}

function warnForAgentAuthTokenSource(source: string, agentKeyId: string) {
  if (source === 'argv') {
    console.error(
      'warning: --agent-auth-token exposes secrets in shell history and process listings; prefer --agent-auth-token-stdin',
    );
    return;
  }

  if (source === 'config') {
    console.error(
      'warning: agentAuthToken is being loaded from config.json; migrate it with `agentpay config agent-auth set --agent-key-id ' +
        agentKeyId +
        ' --agent-auth-token-stdin`',
    );
    return;
  }

  if (source === 'env') {
    console.error(
      'warning: AGENTPAY_AGENT_AUTH_TOKEN exposes secrets to child processes and shell sessions; prefer macOS Keychain or --agent-auth-token-stdin',
    );
  }
}

async function resolveAgentCommandContext(
  options: AgentCommandAuthOptions,
  config: WlfiConfig,
): Promise<{ agentKeyId: string; agentAuthToken: string; daemonSocket: string }> {
  const agentKeyId = assertAgentKeyId(
    options.agentKeyId ?? config.agentKeyId ?? process.env.AGENTPAY_AGENT_KEY_ID,
    'agentKeyId',
  );
  const keychainAgentAuthToken = readAgentAuthTokenFromKeychain(agentKeyId);
  const { token: agentAuthToken, source: agentAuthTokenSource } = await resolveAgentAuthToken({
    agentKeyId,
    cliToken: options.agentAuthToken,
    cliTokenStdin: options.agentAuthTokenStdin,
    keychainToken: keychainAgentAuthToken,
    configToken: config.agentAuthToken,
    envToken: process.env.AGENTPAY_AGENT_AUTH_TOKEN,
    allowLegacySource: options.allowLegacyAgentAuthSource,
    readFromStdin: readTrimmedStdin,
  });
  const daemonSocket = resolveDaemonSocket(
    options.daemonSocket ?? process.env.AGENTPAY_DAEMON_SOCKET,
    config,
  );
  assertTrustedDaemonSocketPath(daemonSocket);

  warnForAgentAuthTokenSource(agentAuthTokenSource, agentKeyId);

  return { agentKeyId, agentAuthToken, daemonSocket };
}

async function runAgentCommandJsonOnce<T>(input: {
  commandArgs: string[];
  config: WlfiConfig;
  agentKeyId: string;
  agentAuthToken: string;
  daemonSocket: string;
}): Promise<AgentCommandAttemptResult<T>> {
  try {
    return {
      type: 'success',
      value: await runRustBinaryJson<T>(
        'agentpay-agent',
        [
          '--json',
          '--agent-key-id',
          input.agentKeyId,
          '--agent-auth-token-stdin',
          '--daemon-socket',
          input.daemonSocket,
          ...input.commandArgs,
        ],
        input.config,
        {
          stdin: `${input.agentAuthToken}\n`,
          preSuppliedSecretStdin: 'agentAuthToken',
          scrubSensitiveEnv: true,
        },
      ),
    };
  } catch (error) {
    if (error instanceof RustBinaryExitError && error.stdout.trim()) {
      try {
        const parsed = JSON.parse(error.stdout) as unknown;
        if (isManualApprovalRequiredOutput(parsed)) {
          return {
            type: 'manualApproval',
            output: parsed,
            exitCode: error.code,
          };
        }
      } catch {
        // fall through to the original error
      }
    }
    throw error;
  }
}

async function runAgentCommandJson<T>(input: {
  commandArgs: string[];
  auth: AgentCommandAuthOptions;
  config: WlfiConfig;
  asJson: boolean;
  waitForManualApproval?: boolean;
}): Promise<T | null> {
  const { agentKeyId, agentAuthToken, daemonSocket } = await resolveAgentCommandContext(
    input.auth,
    input.config,
  );

  const runOnce = () =>
    runAgentCommandJsonOnce<T>({
      commandArgs: input.commandArgs,
      config: input.config,
      agentKeyId,
      agentAuthToken,
      daemonSocket,
    });

  const firstAttempt = await runOnce();
  if (firstAttempt.type === 'success') {
    return firstAttempt.value;
  }

  if (!input.waitForManualApproval) {
    printManualApprovalRequired(firstAttempt.output, input.asJson);
    process.exitCode = firstAttempt.exitCode;
    return null;
  }

  printManualApprovalRequired(firstAttempt.output, input.asJson, true);
  printManualApprovalWaiting(firstAttempt.output, input.asJson);
  const pendingApprovalRequestId = firstAttempt.output.approval_request_id;
  const startedWaitingAt = Date.now();

  for (;;) {
    await sleep(MANUAL_APPROVAL_POLL_INTERVAL_MS);
    const nextAttempt = await runOnce();
    if (nextAttempt.type === 'success') {
      return nextAttempt.value;
    }

    if (nextAttempt.output.approval_request_id !== pendingApprovalRequestId) {
      throw new Error(
        `manual approval request changed while waiting for a decision (${pendingApprovalRequestId} -> ${nextAttempt.output.approval_request_id}); stop and rerun the command after checking the approval status.`,
      );
    }

    if (Date.now() - startedWaitingAt >= MANUAL_APPROVAL_WAIT_TIMEOUT_MS) {
      throw new Error(
        `Timed out after ${Math.ceil(MANUAL_APPROVAL_WAIT_TIMEOUT_MS / 1000)}s waiting for manual approval decision: ${pendingApprovalRequestId}`,
      );
    }
  }
}

function legacyAmountToDecimalString(value: number | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  return value.toString();
}

function describeResolvedToken(token: NonNullable<ReturnType<typeof resolveTokenProfile>>) {
  return {
    key: token.key,
    source: token.source,
    symbol: token.symbol,
    chains: Object.entries(token.chains ?? {})
      .map(([key, value]) => ({ key, ...value }))
      .sort((left, right) => left.chainId - right.chainId || left.key.localeCompare(right.key)),
  };
}

function normalizeTokenChainConfig(
  tokenKey: string,
  chainKey: string,
  options: {
    symbol?: string;
    chainId?: string;
    native?: boolean;
    address?: string;
    decimals?: string;
    perTx?: string;
    daily?: string;
    weekly?: string;
  },
  config: WlfiConfig,
): { symbol: string; profile: TokenChainProfile } {
  const normalizedTokenKey = tokenKey.trim().toLowerCase();
  const normalizedChainKey = chainKey.trim().toLowerCase();
  if (!normalizedTokenKey) {
    throw new Error('token key is required');
  }
  if (!normalizedChainKey) {
    throw new Error('chain key is required');
  }
  if (options.native && options.address) {
    throw new Error('--native conflicts with --address');
  }

  const existingToken = resolveTokenProfile(normalizedTokenKey, config);
  const existingChain = existingToken?.chains?.[normalizedChainKey];
  const resolvedChain = resolveChainProfile(normalizedChainKey, config);
  const symbol =
    options.symbol?.trim() || existingToken?.symbol || normalizedTokenKey.toUpperCase();
  const chainId = options.chainId
    ? parsePositiveIntegerString(options.chainId, 'chainId')
    : (existingChain?.chainId ?? resolvedChain?.chainId);
  if (chainId === undefined) {
    throw new Error(
      `chainId is required; pass --chain-id or configure chain '${normalizedChainKey}' first`,
    );
  }

  const isNative = options.native ? true : options.address ? false : existingChain?.isNative;
  if (isNative === undefined) {
    throw new Error('pass --native or --address for a new token chain');
  }

  const decimals =
    options.decimals !== undefined
      ? parseIntegerString(options.decimals, 'decimals')
      : existingChain?.decimals;
  if (decimals === undefined) {
    throw new Error('decimals is required; pass --decimals or edit an existing token chain');
  }

  const address = isNative
    ? undefined
    : options.address
      ? assertAddress(options.address, 'address')
      : existingChain?.address;
  if (!isNative && !address) {
    throw new Error('address is required for a non-native token chain');
  }

  const hasPolicyOverride =
    options.perTx !== undefined || options.daily !== undefined || options.weekly !== undefined;
  const defaultPolicy =
    hasPolicyOverride || existingChain?.defaultPolicy
      ? {
          perTxAmountDecimal:
            options.perTx !== undefined
              ? normalizePositiveDecimalInput(options.perTx, 'perTx')
              : (existingChain?.defaultPolicy?.perTxAmountDecimal ??
                legacyAmountToDecimalString(existingChain?.defaultPolicy?.perTxAmount)),
          dailyAmountDecimal:
            options.daily !== undefined
              ? normalizePositiveDecimalInput(options.daily, 'daily')
              : (existingChain?.defaultPolicy?.dailyAmountDecimal ??
                legacyAmountToDecimalString(existingChain?.defaultPolicy?.dailyAmount)),
          weeklyAmountDecimal:
            options.weekly !== undefined
              ? normalizePositiveDecimalInput(options.weekly, 'weekly')
              : (existingChain?.defaultPolicy?.weeklyAmountDecimal ??
                legacyAmountToDecimalString(existingChain?.defaultPolicy?.weeklyAmount)),
        }
      : undefined;

  return {
    symbol,
    profile: {
      chainId,
      isNative,
      decimals,
      ...(address ? { address } : {}),
      ...(defaultPolicy && Object.values(defaultPolicy).some((value) => value !== undefined)
        ? { defaultPolicy }
        : {}),
    },
  };
}

function buildAdminChainCommand(): Command {
  const command = new Command('chain')
    .description(
      'Manage active chain selection and chain profiles (mutations require verified root access)',
    )
    .showHelpAfterError();

  command
    .command('list')
    .option('--json', 'Print JSON output', false)
    .action((options) => {
      const config = readConfig();
      print(
        {
          active: activeChainSummary(config),
          configured: listConfiguredChains(config),
          builtin: listBuiltinChains(),
        },
        options.json,
      );
    });

  command
    .command('current')
    .option('--json', 'Print JSON output', false)
    .action(async (options) => {
      const config = readConfig();
      let rpc = null;
      if (config.rpcUrl) {
        try {
          rpc = await getChainInfo(config.rpcUrl);
        } catch {
          rpc = null;
        }
      }
      print(
        {
          active: activeChainSummary(config),
          rpc,
        },
        options.json,
      );
    });

  command
    .command('add')
    .argument('<key>')
    .requiredOption('--chain-id <id>', 'Chain ID')
    .option('--name <name>', 'Display name')
    .option('--rpc-url <url>', 'Default RPC URL for this chain profile')
    .option('--activate', 'Activate this profile immediately', false)
    .option('--json', 'Print JSON output', false)
    .action(
      withLocalAdminMutationAccess('agentpay admin chain add', (key: string, options) => {
        const profile = normalizeChainProfile(key, options);
        let updated = saveChainProfile(key, profile);
        if (options.activate) {
          updated = switchActiveChain(key, { rpcUrl: profile.rpcUrl });
        }
        print(
          {
            saved: { key: key.trim().toLowerCase(), ...profile },
            active: activeChainSummary(updated),
          },
          options.json,
        );
      }),
    );

  command
    .command('remove')
    .argument('<key>')
    .option('--json', 'Print JSON output', false)
    .action(
      withLocalAdminMutationAccess('agentpay admin chain remove', (key: string, options) => {
        const updated = removeChainProfile(key);
        print(
          {
            removed: key.trim().toLowerCase(),
            configured: listConfiguredChains(updated),
          },
          options.json,
        );
      }),
    );

  command
    .command('switch')
    .argument('<selector>')
    .option('--rpc-url <url>', 'RPC URL to save as the active endpoint')
    .option('--save', 'Persist the active selection as a named profile', false)
    .option('--json', 'Print JSON output', false)
    .action(
      withLocalAdminMutationAccess('agentpay admin chain switch', (selector: string, options) => {
        const updated = switchActiveChain(selector, {
          rpcUrl: options.rpcUrl,
          persistProfile: options.save,
        });
        const profile = resolveChainProfile(selector, updated);
        print(
          {
            selected: selector,
            resolved: profile,
            active: activeChainSummary(updated),
          },
          options.json,
        );
      }),
    );

  return command;
}

function buildAdminTokenCommand(): Command {
  const command = new Command('token')
    .description(
      'Manage shared token definitions and default policies (mutations require verified root access)',
    )
    .showHelpAfterError();

  command
    .command('list')
    .option('--json', 'Print JSON output', false)
    .action((options) => {
      const config = readConfig();
      print(
        {
          builtin: listBuiltinTokens(),
          configured: listConfiguredTokens(config),
        },
        options.json,
      );
    });

  command
    .command('show')
    .argument('<selector>')
    .option('--json', 'Print JSON output', false)
    .action((selector: string, options) => {
      const config = readConfig();
      const resolved = resolveTokenProfile(selector, config);
      if (!resolved) {
        throw new Error(`unknown token selector: ${selector}`);
      }
      print(describeResolvedToken(resolved), options.json);
    });

  command
    .command('set-chain')
    .argument('<tokenKey>')
    .argument('<chainKey>')
    .option('--symbol <symbol>', 'Token symbol')
    .option('--chain-id <id>', 'Chain ID (defaults from the existing token or configured chain)')
    .option('--native', 'Mark the token as the native asset on this chain', false)
    .option('--address <address>', 'ERC-20 token contract address')
    .option('--decimals <count>', 'Token decimals')
    .option('--per-tx <amount>', 'Default per-transaction policy amount in token units')
    .option('--daily <amount>', 'Default daily policy amount in token units')
    .option('--weekly <amount>', 'Default weekly policy amount in token units')
    .option('--json', 'Print JSON output', false)
    .action(
      withLocalAdminMutationAccess(
        'agentpay admin token set-chain',
        (tokenKey: string, chainKey: string, options) => {
          const config = readConfig();
          const { symbol, profile } = normalizeTokenChainConfig(
            tokenKey,
            chainKey,
            options,
            config,
          );
          const updated = saveTokenChainProfile(tokenKey, chainKey, profile, { symbol });
          const resolved = resolveTokenProfile(tokenKey, updated);
          if (!resolved) {
            throw new Error(`failed to save token '${tokenKey}'`);
          }
          print(
            {
              saved: describeResolvedToken(resolved),
            },
            options.json,
          );
        },
      ),
    );

  command
    .command('remove')
    .argument('<tokenKey>')
    .option('--json', 'Print JSON output', false)
    .action(
      withLocalAdminMutationAccess('agentpay admin token remove', (tokenKey: string, options) => {
        const updated = removeTokenProfile(tokenKey);
        print(
          {
            removed: tokenKey.trim().toLowerCase(),
            configured: listConfiguredTokens(updated),
          },
          options.json,
        );
      }),
    );

  command
    .command('remove-chain')
    .argument('<tokenKey>')
    .argument('<chainKey>')
    .option('--json', 'Print JSON output', false)
    .action(
      withLocalAdminMutationAccess(
        'agentpay admin token remove-chain',
        (tokenKey: string, chainKey: string, options) => {
          const updated = removeTokenChainProfile(tokenKey, chainKey);
          const resolved = resolveTokenProfile(tokenKey, updated);
          print(
            {
              removed: {
                token: tokenKey.trim().toLowerCase(),
                chain: chainKey.trim().toLowerCase(),
              },
              remaining: resolved ? describeResolvedToken(resolved) : null,
            },
            options.json,
          );
        },
      ),
    );

  return command;
}

async function runLocalAdminCommand(forwarded: string[]): Promise<boolean> {
  const target = forwarded[0] === 'help' ? forwarded[1] : forwarded[0];
  if (target !== 'chain' && target !== 'token' && target !== 'daemon') {
    return false;
  }

  const command =
    target === 'chain'
      ? buildAdminChainCommand()
      : target === 'token'
        ? buildAdminTokenCommand()
        : buildAdminDaemonCommand();
  const args = forwarded[0] === 'help' ? ['--help'] : forwarded.slice(1);
  command.exitOverride();

  try {
    await command.parseAsync(args, { from: 'user' });
    return true;
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error) {
      const code = String((error as { code?: unknown }).code ?? '');
      if (code === 'commander.helpDisplayed') {
        return true;
      }
    }
    throw error;
  }
}

function normalizeAdminPassthroughArgs(forwarded: string[]): string[] {
  const lifted: string[] = [];
  const remaining: string[] = [];

  for (const arg of forwarded) {
    if (arg === '--json') {
      if (!lifted.includes(arg)) {
        lifted.push(arg);
      }
      continue;
    }
    remaining.push(arg);
  }

  return [...lifted, ...remaining];
}

function buildAdminDaemonCommand(): Command {
  return new Command()
    .name('daemon')
    .description('Daemon launch is managed by agentpay admin setup')
    .action(() => {
      throw new Error(
        'Direct daemon execution is disabled. Use `agentpay admin setup` to install and manage the daemon.',
      );
    });
}

async function runAdminWalletBackupCli(argv: string[]): Promise<void> {
  const command = new Command()
    .name('wallet-backup')
    .description('Export and verify encrypted offline wallet backups');

  command
    .command('export')
    .description('Export the current software wallet into an encrypted offline backup file')
    .requiredOption('--output <path>', 'Output path for the encrypted wallet backup file')
    .option('--overwrite', 'Replace an existing backup file at the target path', false)
    .option('--daemon-socket <path>', 'Daemon unix socket path')
    .option('--vault-password-stdin', 'Read vault password from stdin', false)
    .option('--backup-password-stdin', 'Read wallet backup password from stdin', false)
    .option('--non-interactive', 'Disable password prompts', false)
    .option('--json', 'Print JSON output', false)
    .action(async (options) => {
      if (options.vaultPasswordStdin && options.backupPasswordStdin) {
        throw new Error(
          '--vault-password-stdin conflicts with --backup-password-stdin; provide one secret via a local TTY prompt',
        );
      }

      const config = readConfig();
      const daemonSocket = resolveValidatedAdminDaemonSocket(options.daemonSocket, config);

      const vaultPassword = await resolveAdminSetupVaultPassword({
        vaultPasswordStdin: options.vaultPasswordStdin,
        nonInteractive: options.nonInteractive,
      });
      const backupPassword = await resolveWalletBackupPassword({
        backupPasswordStdin: options.backupPasswordStdin,
        nonInteractive: options.nonInteractive,
        confirm: !options.backupPasswordStdin,
      });

      const exported = await exportEncryptedWalletBackup({
        daemonSocket,
        vaultPassword,
        backupPassword,
        outputPath: options.output,
        overwrite: options.overwrite,
        config,
      });
      print(
        options.json
          ? {
              command: 'wallet-backup-export',
              ...exported,
            }
          : formatWalletBackupExportOutput(exported),
        options.json,
      );
    });

  command
    .command('verify')
    .description('Verify that an encrypted wallet backup can be decrypted and matches its metadata')
    .argument('<path>', 'Path to the encrypted wallet backup file')
    .option('--backup-password-stdin', 'Read wallet backup password from stdin', false)
    .option('--non-interactive', 'Disable password prompts', false)
    .option('--json', 'Print JSON output', false)
    .action(async (inputPath: string, options) => {
      const verified = verifyWalletBackupFile(
        inputPath,
        await resolveWalletBackupPassword({
          backupPasswordStdin: options.backupPasswordStdin,
          nonInteractive: options.nonInteractive,
          confirm: false,
        }),
      );
      print(
        options.json
          ? {
              command: 'wallet-backup-verify',
              ...verified,
            }
          : formatWalletBackupVerifyOutput({
              sourcePath: verified.sourcePath ?? inputPath,
              address: verified.address,
              sourceVaultKeyId: verified.sourceVaultKeyId,
              createdAt: verified.createdAt,
            }),
        options.json,
      );
    });

  await command.parseAsync(argv, { from: 'user' });
}

async function runAdminResumeManualApprovalCli(argv: string[]): Promise<void> {
  const command = new Command()
    .name('resume-manual-approval-request')
    .description('Resume an approved broadcast-backed manual approval request on this machine')
    .requiredOption('--approval-request-id <uuid>', 'Manual approval request id to resume')
    .option('--rpc-url <url>', 'Ethereum RPC URL override used only for the resumed broadcast')
    .option('--vault-password-stdin', 'Read vault password from stdin', false)
    .option('--non-interactive', 'Disable password prompts', false)
    .option('--daemon-socket <path>', 'Daemon unix socket path')
    .option('--no-wait', 'Do not wait up to 30s for an on-chain receipt after broadcast')
    .option('--json', 'Print JSON output', false)
    .action(async (options) => {
      const config = readConfig();
      const approvalRequestId = assertAgentKeyId(options.approvalRequestId, 'approvalRequestId');
      const daemonSocket = resolveValidatedAdminDaemonSocket(options.daemonSocket, config);

      const requests = await runRustBinaryJson<unknown[]>(
        'agentpay-admin',
        buildListManualApprovalRequestsAdminArgs({
          vaultPasswordStdin: options.vaultPasswordStdin,
          nonInteractive: options.nonInteractive,
          daemonSocket,
        }),
        config,
      );
      const resolved = resolveApprovedBroadcastManualApprovalRequest(
        resolveManualApprovalRequestById(requests, approvalRequestId),
      );
      const tx = resolved.action.tx;
      const rpcUrl = resolveResumeManualApprovalRpcUrl(config, tx.chain_id, options.rpcUrl);
      const chainInfo = await getChainInfo(rpcUrl);
      assertRpcChainIdMatches(tx.chain_id, chainInfo.chainId);

      const agentContext = await resolveAgentCommandContext(
        {
          agentKeyId: resolved.request.agent_key_id,
          daemonSocket,
        },
        config,
      );
      const txType = formatBroadcastTxType(tx.tx_type);
      const valueWei = parseBigIntString(tx.value_wei, 'valueWei');
      const dataHex = assertHex(tx.data_hex, 'dataHex');
      const gasLimit = BigInt(tx.gas_limit);
      const maxFeePerGasWei = parsePositiveBigIntString(tx.max_fee_per_gas_wei, 'maxFeePerGasWei');
      const maxPriorityFeePerGasWei = parseBigIntString(
        tx.max_priority_fee_per_gas_wei,
        'maxPriorityFeePerGasWei',
      );
      const to = assertAddress(tx.to, 'to');

      const signedAttempt = await runAgentCommandJsonOnce<RustBroadcastOutput>({
        commandArgs: [
          'broadcast',
          '--network',
          String(tx.chain_id),
          '--nonce',
          String(tx.nonce),
          '--to',
          to,
          '--value-wei',
          valueWei.toString(),
          '--data-hex',
          dataHex,
          '--gas-limit',
          gasLimit.toString(),
          '--max-fee-per-gas-wei',
          maxFeePerGasWei.toString(),
          '--max-priority-fee-per-gas-wei',
          maxPriorityFeePerGasWei.toString(),
          '--tx-type',
          txType,
          ...(tx.delegation_enabled ? ['--delegation-enabled'] : []),
        ],
        config,
        agentKeyId: agentContext.agentKeyId,
        agentAuthToken: agentContext.agentAuthToken,
        daemonSocket: agentContext.daemonSocket,
      });

      if (signedAttempt.type !== 'success') {
        if (signedAttempt.output.approval_request_id === approvalRequestId) {
          throw new Error(
            `manual approval request '${approvalRequestId}' is still waiting for approval; approve it before resuming`,
          );
        }
        throw new Error(
          `manual approval request '${approvalRequestId}' could not be resumed because daemon returned a different approval request (${signedAttempt.output.approval_request_id})`,
        );
      }

      const signed = signedAttempt.value;
      if (!signed.raw_tx_hex) {
        throw new Error(
          `manual approval request '${approvalRequestId}' did not produce raw_tx_hex during resume`,
        );
      }

      const from = resolveWalletAddress(config);
      await assertSignedBroadcastTransactionMatchesRequest({
        rawTxHex: signed.raw_tx_hex as Hex,
        from,
        to,
        chainId: tx.chain_id,
        nonce: tx.nonce,
        allowHigherNonce: false,
        value: valueWei,
        data: dataHex,
        gasLimit,
        maxFeePerGas: maxFeePerGasWei,
        maxPriorityFeePerGas: maxPriorityFeePerGasWei,
        txType,
      });

      const networkTxHash = await broadcastRawTransaction(rpcUrl, signed.raw_tx_hex as Hex);
      print(
        {
          command: 'resume-manual-approval-request',
          approvalRequestId,
          agentKeyId: resolved.request.agent_key_id,
          chainId: tx.chain_id,
          nonce: tx.nonce,
          counterparty: resolved.request.recipient,
          asset: resolved.request.asset,
          amountWei: resolved.request.amount_wei,
          txType,
          networkTxHash,
          txHashHex: signed.tx_hash_hex ?? networkTxHash,
        },
        options.json,
      );

      if (options.wait) {
        await reportOnchainReceiptStatus({
          rpcUrl,
          txHash: networkTxHash,
          asJson: options.json,
        });
      }
    });

  command.exitOverride();

  try {
    await command.parseAsync(argv, { from: 'user' });
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error) {
      const code = String((error as { code?: unknown }).code ?? '');
      if (code === 'commander.helpDisplayed') {
        return;
      }
    }
    throw error;
  }
}

async function main() {
  installGlobalFetchProxyDispatcherFromEnv();

  if (process.argv.length === 3 && (process.argv[2] === '--version' || process.argv[2] === '-V')) {
    console.log(CLI_VERSION);
    return;
  }

  ensureAgentPayHome();
  const program = new Command();
  program
    .name('agentpay')
    .description('Single entrypoint for AgentPay admin and signing operations')
    .version(CLI_VERSION, '-V, --version', 'Print CLI version')
    .showHelpAfterError();

  const configCommand = program.command('config').description('Manage ~/.agentpay configuration');
  configCommand
    .command('show')
    .option('--json', 'Print JSON output', false)
    .action((options) => {
      const config = readConfig();
      print(
        {
          ...redactConfig(config),
          keychain: {
            agentAuthTokenStored: hasStoredAgentAuthToken(config.agentKeyId),
            service: process.platform === 'darwin' ? AGENT_AUTH_TOKEN_KEYCHAIN_SERVICE : null,
          },
        },
        options.json,
      );
    });
  configCommand.command('path').action(() => {
    console.log(resolveConfigPath());
  });
  configCommand
    .command('set')
    .argument('<key>')
    .argument('<value>')
    .action(
      withDynamicLocalAdminMutationAccess(
        (key: string, _value: string) => resolveConfigMutationCommandLabel('set', key),
        (key: string, value: string) => {
          const writableKey = assertWritableConfigKey(key);
          const updated = writeConfig(parseConfigValue(writableKey, value));
          print(redactConfig(updated), true);
        },
      ),
    );
  configCommand
    .command('unset')
    .argument('<key>')
    .action(
      withDynamicLocalAdminMutationAccess(
        (key: string) => resolveConfigMutationCommandLabel('unset', key),
        (key: string) => {
          const writableKey = assertWritableConfigKey(key);
          const updated = deleteConfigKey(writableKey);
          print(redactConfig(updated), true);
        },
      ),
    );

  const agentAuthCommand = configCommand
    .command('agent-auth')
    .description('Manage the agent auth token in macOS Keychain');

  agentAuthCommand
    .command('set')
    .requiredOption('--agent-key-id <uuid>', 'Agent key id')
    .option('--agent-auth-token <token>', 'Agent auth token')
    .option('--agent-auth-token-stdin', 'Read agent auth token from stdin', false)
    .option('--json', 'Print JSON output', false)
    .action(
      withLocalAdminMutationAccess('agentpay config agent-auth set', async (options) => {
        if (options.agentAuthToken && options.agentAuthTokenStdin) {
          throw new Error('--agent-auth-token conflicts with --agent-auth-token-stdin');
        }

        const agentKeyId = assertAgentKeyId(options.agentKeyId);
        const agentAuthToken = options.agentAuthTokenStdin
          ? assertValidAgentAuthToken(await readTrimmedStdin('agentAuthToken'), 'agentAuthToken')
          : assertValidAgentAuthToken(
              requiredString(options.agentAuthToken, 'agentAuthToken'),
              'agentAuthToken',
            );

        if (options.agentAuthToken) {
          console.error(
            'warning: --agent-auth-token exposes secrets in shell history and process listings; prefer --agent-auth-token-stdin',
          );
        }

        storeAgentAuthTokenInKeychain(agentKeyId, agentAuthToken);

        let updated = writeConfig({ agentKeyId });
        if (updated.agentAuthToken !== undefined) {
          updated = deleteConfigKey('agentAuthToken');
        }

        print(
          {
            agentKeyId: updated.agentKeyId ?? agentKeyId,
            keychain: {
              stored: true,
              service: AGENT_AUTH_TOKEN_KEYCHAIN_SERVICE,
            },
            config: redactConfig(updated),
          },
          options.json,
        );
      }),
    );

  agentAuthCommand
    .command('import')
    .description('Import agent credentials from a private admin bootstrap JSON file')
    .argument('<path>', 'Path to bootstrap JSON output with an unredacted agent auth token')
    .option('--keep-source', 'Keep the imported bootstrap file unchanged after import', false)
    .option('--delete-source', 'Delete the imported bootstrap file after import', false)
    .option('--json', 'Print JSON output', false)
    .action(
      withLocalAdminMutationAccess(
        'agentpay config agent-auth import',
        (inputPath: string, options) => {
          if (options.keepSource && options.deleteSource) {
            throw new Error('--keep-source conflicts with --delete-source');
          }

          const summary = readBootstrapSetupSummaryFile(inputPath);
          assertBootstrapSetupSummaryLeaseIsActive(summary);
          const imported = readBootstrapAgentCredentialsFile(inputPath);
          const agentKeyId = assertAgentKeyId(imported.agentKeyId);
          if (summary.agentKeyId !== agentKeyId) {
            throw new Error(
              'bootstrap credentials file agent_key_id does not match setup summary agent_key_id',
            );
          }

          storeAgentAuthTokenInKeychain(agentKeyId, imported.agentAuthToken);

          let sourceCleanup: 'redacted' | 'deleted' | 'kept' = 'kept';
          if (options.deleteSource) {
            deleteBootstrapAgentCredentialsFile(imported.sourcePath);
            sourceCleanup = 'deleted';
          } else if (!options.keepSource) {
            redactBootstrapAgentCredentialsFile(imported.sourcePath);
            sourceCleanup = 'redacted';
          } else {
            console.error(
              'warning: imported bootstrap file still contains a plaintext agent auth token; prefer the default redaction or --delete-source',
            );
          }

          let updated = writeConfig({
            agentKeyId,
            wallet: walletProfileFromBootstrapSummary(summary),
          });
          if (updated.agentAuthToken !== undefined) {
            updated = deleteConfigKey('agentAuthToken');
          }

          print(
            {
              sourcePath: imported.sourcePath,
              sourceCleanup,
              agentKeyId,
              keychain: {
                stored: true,
                service: AGENT_AUTH_TOKEN_KEYCHAIN_SERVICE,
              },
              config: redactConfig(updated),
            },
            options.json,
          );
        },
      ),
    );

  agentAuthCommand
    .command('migrate')
    .description(
      'Move a legacy config.json agentAuthToken into macOS Keychain and scrub plaintext storage',
    )
    .option('--agent-key-id <uuid>', 'Agent key id (defaults to configured agentKeyId)')
    .option(
      '--overwrite-keychain',
      'Replace a different existing Keychain token for this agent',
      false,
    )
    .option('--json', 'Print JSON output', false)
    .action(
      withLocalAdminMutationAccess('agentpay config agent-auth migrate', (options) => {
        print(
          migrateLegacyAgentAuthToken({
            agentKeyId: options.agentKeyId,
            overwriteKeychain: options.overwriteKeychain,
          }),
          options.json,
        );
      }),
    );

  agentAuthCommand
    .command('rotate')
    .description('Rotate the agent auth token via Rust admin flow, then store it in macOS Keychain')
    .option('--agent-key-id <uuid>', 'Agent key id (defaults to configured agentKeyId)')
    .option('--vault-password-stdin', 'Read vault password from stdin', false)
    .option('--non-interactive', 'Disable password prompts', false)
    .option('--daemon-socket <path>', 'Daemon unix socket path')
    .option('--json', 'Print JSON output', false)
    .action(async (options) => {
      const config = readConfig();
      const agentKeyId = options.agentKeyId
        ? assertAgentKeyId(options.agentKeyId)
        : config.agentKeyId
          ? assertAgentKeyId(config.agentKeyId, 'configured agentKeyId')
          : undefined;
      if (!agentKeyId) {
        throw new Error(
          'agentKeyId is required; pass --agent-key-id or configure agentKeyId first',
        );
      }

      const daemonSocket = resolveValidatedAdminDaemonSocket(options.daemonSocket, config);

      const rotated = await runRustBinaryJson<RotateAgentAuthTokenAdminOutput>(
        'agentpay-admin',
        buildRotateAgentAuthTokenAdminArgs({
          agentKeyId,
          vaultPasswordStdin: options.vaultPasswordStdin,
          nonInteractive: options.nonInteractive,
          daemonSocket,
        }),
        config,
      );

      print(completeAgentAuthRotation(rotated), options.json);
    });

  agentAuthCommand
    .command('revoke')
    .description('Revoke the agent key via Rust admin flow, then remove local credentials')
    .option('--agent-key-id <uuid>', 'Agent key id (defaults to configured agentKeyId)')
    .option('--vault-password-stdin', 'Read vault password from stdin', false)
    .option('--non-interactive', 'Disable password prompts', false)
    .option('--daemon-socket <path>', 'Daemon unix socket path')
    .option('--json', 'Print JSON output', false)
    .action(async (options) => {
      const config = readConfig();
      const agentKeyId = options.agentKeyId
        ? assertAgentKeyId(options.agentKeyId)
        : config.agentKeyId
          ? assertAgentKeyId(config.agentKeyId, 'configured agentKeyId')
          : undefined;
      if (!agentKeyId) {
        throw new Error(
          'agentKeyId is required; pass --agent-key-id or configure agentKeyId first',
        );
      }

      const daemonSocket = resolveValidatedAdminDaemonSocket(options.daemonSocket, config);

      const revoked = await runRustBinaryJson<RevokeAgentKeyAdminOutput>(
        'agentpay-admin',
        buildRevokeAgentKeyAdminArgs({
          agentKeyId,
          vaultPasswordStdin: options.vaultPasswordStdin,
          nonInteractive: options.nonInteractive,
          daemonSocket,
        }),
        config,
      );

      print(completeAgentKeyRevocation(revoked), options.json);
    });

  agentAuthCommand
    .command('status')
    .option('--agent-key-id <uuid>', 'Agent key id (defaults to configured agentKeyId)')
    .option('--json', 'Print JSON output', false)
    .action((options) => {
      const config = readConfig();
      const agentKeyId = options.agentKeyId
        ? assertAgentKeyId(options.agentKeyId)
        : config.agentKeyId && AGENT_KEY_ID_PATTERN.test(config.agentKeyId.trim())
          ? config.agentKeyId.trim()
          : null;
      print(
        {
          agentKeyId,
          keychain: {
            supported: process.platform === 'darwin',
            service: process.platform === 'darwin' ? AGENT_AUTH_TOKEN_KEYCHAIN_SERVICE : null,
            stored: hasStoredAgentAuthToken(agentKeyId ?? undefined),
          },
        },
        options.json,
      );
    });

  agentAuthCommand
    .command('clear')
    .option('--agent-key-id <uuid>', 'Agent key id (defaults to configured agentKeyId)')
    .option('--json', 'Print JSON output', false)
    .action(
      withLocalAdminMutationAccess('agentpay config agent-auth clear', (options) => {
        const config = readConfig();
        const agentKeyId = options.agentKeyId
          ? assertAgentKeyId(options.agentKeyId)
          : config.agentKeyId
            ? assertAgentKeyId(config.agentKeyId, 'configured agentKeyId')
            : undefined;
        if (!agentKeyId) {
          throw new Error(
            'agentKeyId is required; pass --agent-key-id or configure agentKeyId first',
          );
        }

        print(clearAgentAuthToken(agentKeyId), options.json);
      }),
    );

  program
    .command('wallet')
    .description('Show the configured wallet public key and associated policy summary')
    .option('--json', 'Print JSON output', false)
    .action(async (options) => {
      const config = readConfig();
      const profile = await resolveWalletProfileWithBalances(config, {
        getNativeBalance,
        getTokenBalance,
      });
      print(options.json ? profile : formatWalletProfileText(profile), options.json);
    });

  registerStatusCommand(program, {
    print: (payload, options) => {
      print(payload, options.asJson);
    },
    setExitCode: (code) => {
      process.exitCode = code;
    },
  });

  registerRepairCommand(program, {
    print: (payload, options) => {
      print(payload, options.asJson);
    },
    setExitCode: (code) => {
      process.exitCode = code;
    },
  });

  program
    .command('admin')
    .helpOption(false)
    .allowUnknownOption(true)
    .allowExcessArguments(true)
    .argument('[args...]')
    .description('Admin commands and setup passthrough')
    .action(async () => {
      const index = process.argv.indexOf('admin');
      const forwarded = index >= 0 ? process.argv.slice(index + 1) : [];
      const passthroughTarget = forwarded[0] === 'help' ? forwarded[1] : forwarded[0];
      const blockedPassthroughMessage = blockedRawAdminPassthroughMessage(passthroughTarget);
      if (forwarded[0] === 'setup') {
        await runAdminSetupCli(forwarded.slice(1));
        return;
      }
      if (forwarded[0] === 'tui') {
        await runAdminTuiCli(forwarded.slice(1));
        return;
      }
      if (forwarded[0] === 'reset') {
        await runAdminResetCli(forwarded.slice(1));
        return;
      }
      if (forwarded[0] === 'uninstall') {
        await runAdminUninstallCli(forwarded.slice(1));
        return;
      }
      if (forwarded[0] === 'resume-manual-approval-request') {
        await runAdminResumeManualApprovalCli(forwarded.slice(1));
        return;
      }
      if (forwarded[0] === 'wallet-backup') {
        await runAdminWalletBackupCli(forwarded.slice(1));
        return;
      }
      if (forwarded[0] === 'help' && forwarded[1] === 'tui') {
        await runAdminTuiCli(['--help']);
        return;
      }
      if (forwarded[0] === 'help' && forwarded[1] === 'setup') {
        await runAdminSetupCli(['--help']);
        return;
      }
      if (forwarded[0] === 'help' && forwarded[1] === 'reset') {
        await runAdminResetCli(['--help']);
        return;
      }
      if (forwarded[0] === 'help' && forwarded[1] === 'uninstall') {
        await runAdminUninstallCli(['--help']);
        return;
      }
      if (forwarded[0] === 'help' && forwarded[1] === 'resume-manual-approval-request') {
        await runAdminResumeManualApprovalCli(['--help']);
        return;
      }
      if (forwarded[0] === 'help' && forwarded[1] === 'wallet-backup') {
        await runAdminWalletBackupCli(['--help']);
        return;
      }
      if (blockedPassthroughMessage) {
        if (forwarded[0] === 'help') {
          print(blockedPassthroughMessage, false);
          return;
        }
        throw new Error(blockedPassthroughMessage);
      }
      if (forwarded[0] === 'bootstrap') {
        throw new Error('`agentpay admin bootstrap` has been removed; use `agentpay admin setup`');
      }
      if (await runLocalAdminCommand(forwarded)) {
        return;
      }
      const config = readConfig();
      const wantsHelp =
        forwarded.length === 0 ||
        forwarded[0] === 'help' ||
        forwarded.includes('--help') ||
        forwarded.includes('-h');
      const normalizedForwarded = wantsHelp ? forwarded : normalizeAdminPassthroughArgs(forwarded);
      if (wantsHelp) {
        const rendered = await runRustBinary(
          'agentpay-admin',
          normalizedForwarded.length === 0 ? ['--help'] : normalizedForwarded,
          config,
        );
        if (rendered.stdout) {
          process.stdout.write(rewriteAdminHelpText(rendered.stdout));
        }
        if (rendered.stderr) {
          process.stderr.write(rewriteAdminHelpText(rendered.stderr));
        }
        return;
      }
      const code = await passthroughRustBinary('agentpay-admin', normalizedForwarded, config);
      process.exitCode = code;
    });

  const addAgentCommandAuthOptions = (command: Command) =>
    command
      .option('--daemon-socket <path>', 'Daemon socket path')
      .option('--agent-key-id <uuid>', 'Agent key id')
      .option('--agent-auth-token <token>', 'Agent auth token')
      .option('--agent-auth-token-stdin', 'Read agent auth token from stdin', false)
      .option(
        '--allow-legacy-agent-auth-source',
        'Allow deprecated argv/config/env fallback for agent auth token',
        false,
      )
      .option('--json', 'Print JSON output', false);

  addAgentCommandAuthOptions(
    program
      .command('transfer')
      .description('Submit an ERC-20 transfer request through policy checks')
      .requiredOption('--network <name>', 'Network name')
      .requiredOption('--token <address>', 'ERC-20 token contract')
      .requiredOption('--to <address>', 'Recipient address')
      .requiredOption('--amount <amount>', 'Transfer amount in token units')
      .option('--broadcast', 'Broadcast the signed transaction through RPC', false)
      .option('--rpc-url <url>', 'Ethereum RPC URL override used only for broadcast')
      .option(
        '--from <address>',
        'Sender address override for broadcast; defaults to configured wallet address',
      )
      .option('--nonce <nonce>', 'Explicit nonce override for broadcast')
      .option('--gas-limit <gas>', 'Gas limit override for broadcast')
      .option('--max-fee-per-gas-wei <wei>', 'Max fee per gas override for broadcast')
      .option('--max-priority-fee-per-gas-wei <wei>', 'Priority fee per gas override for broadcast')
      .option('--tx-type <type>', 'Typed tx value for broadcast', '0x02')
      .option('--no-wait', 'Do not wait up to 30s for an on-chain receipt after broadcast')
      .option(
        '--reveal-raw-tx',
        'Include the signed raw transaction bytes in broadcast output',
        false,
      )
      .option('--reveal-signature', 'Include signer r/s/v fields in broadcast output', false)
      .addOption(new Option('--amount-wei <wei>').hideHelp()),
  ).action(async (options) => {
    const config = readConfig();
    const network = resolveCliNetworkProfile(options.network, config).chainId;
    const token = assertAddress(options.token, 'token');
    const recipient = assertAddress(options.to, 'to');
    const rpcUrl = resolveCliRpcUrl(options.rpcUrl, options.network, config);
    const asset = await resolveErc20AssetWithRpcFallback(
      config, network, token, rpcUrl, getTokenMetadata,
    );
    const amountWei = options.amount
      ? parseConfiguredAmount(options.amount, asset.decimals, 'amount')
      : parseBigIntString(options.amountWei, 'amountWei');
    try {
      if (options.broadcast) {
        const plan = await resolveAssetBroadcastPlan(
          {
            rpcUrl,
            chainId: network,
            from: options.from ? assertAddress(options.from, 'from') : resolveWalletAddress(config),
            to: token,
            valueWei: 0n,
            dataHex: encodeErc20TransferData(recipient, amountWei),
            nonce: options.nonce ? parseIntegerString(options.nonce, 'nonce') : undefined,
            gasLimit: options.gasLimit
              ? parsePositiveBigIntString(options.gasLimit, 'gasLimit')
              : undefined,
            maxFeePerGasWei: options.maxFeePerGasWei
              ? parsePositiveBigIntString(options.maxFeePerGasWei, 'maxFeePerGasWei')
              : undefined,
            maxPriorityFeePerGasWei: options.maxPriorityFeePerGasWei
              ? parseBigIntString(options.maxPriorityFeePerGasWei, 'maxPriorityFeePerGasWei')
              : undefined,
            txType: options.txType,
          },
          {
            getChainInfo,
            assertRpcChainIdMatches,
            getNonce,
            estimateGas,
            estimateFees,
          },
        );
        const signed = await runAgentCommandJson<RustBroadcastOutput>({
          commandArgs: [
            'broadcast',
            '--network',
            String(plan.chainId),
            '--nonce',
            String(plan.nonce),
            '--to',
            token,
            '--value-wei',
            '0',
            '--data-hex',
            plan.dataHex,
            '--gas-limit',
            plan.gasLimit.toString(),
            '--max-fee-per-gas-wei',
            plan.maxFeePerGasWei.toString(),
            '--max-priority-fee-per-gas-wei',
            plan.maxPriorityFeePerGasWei.toString(),
            '--tx-type',
            plan.txType,
          ],
          auth: options,
          config,
          asJson: options.json,
          waitForManualApproval: true,
        });
        if (!signed) {
          return;
        }
        const completed = await completeAssetBroadcast(plan, signed, {
          assertSignedBroadcastTransactionMatchesRequest,
          broadcastRawTransaction,
        });
        print(
          formatBroadcastedAssetOutput({
            command: 'transfer',
            counterparty: recipient,
            asset,
            signed,
            plan,
            signedNonce: completed.signedNonce,
            networkTxHash: completed.networkTxHash,
            revealRawTx: options.revealRawTx,
            revealSignature: options.revealSignature,
          }),
          options.json,
        );
        if (options.wait) {
          await reportOnchainReceiptStatus({
            rpcUrl: plan.rpcUrl,
            txHash: completed.networkTxHash,
            asJson: options.json,
          });
        }
        return;
      }

      const result = await runAgentCommandJson<RustBroadcastOutput>({
        commandArgs: [
          'transfer',
          '--network',
          String(network),
          '--token',
          token,
          '--to',
          recipient,
          '--amount-wei',
          amountWei.toString(),
        ],
        auth: options,
        config,
        asJson: options.json,
      });
      if (result) {
        print(normalizeAgentAmountOutput(result, asset), options.json);
      }
    } catch (error) {
      throw rewriteAgentAmountError(error, asset);
    }
  });

  addAgentCommandAuthOptions(
    program
      .command('transfer-native')
      .description('Submit a native ETH transfer request through policy checks')
      .requiredOption('--network <name>', 'Network name')
      .requiredOption('--to <address>', 'Recipient address')
      .requiredOption('--amount <amount>', 'Transfer amount in configured native token units')
      .option('--broadcast', 'Broadcast the signed transaction through RPC', false)
      .option('--rpc-url <url>', 'Ethereum RPC URL override used only for broadcast')
      .option(
        '--from <address>',
        'Sender address override for broadcast; defaults to configured wallet address',
      )
      .option('--nonce <nonce>', 'Explicit nonce override for broadcast')
      .option('--gas-limit <gas>', 'Gas limit override for broadcast')
      .option('--max-fee-per-gas-wei <wei>', 'Max fee per gas override for broadcast')
      .option('--max-priority-fee-per-gas-wei <wei>', 'Priority fee per gas override for broadcast')
      .option('--tx-type <type>', 'Typed tx value for broadcast', '0x02')
      .option('--no-wait', 'Do not wait up to 30s for an on-chain receipt after broadcast')
      .option(
        '--reveal-raw-tx',
        'Include the signed raw transaction bytes in broadcast output',
        false,
      )
      .option('--reveal-signature', 'Include signer r/s/v fields in broadcast output', false)
      .addOption(new Option('--amount-wei <wei>').hideHelp()),
  ).action(async (options) => {
    const config = readConfig();
    const network = resolveCliNetworkProfile(options.network, config).chainId;
    const asset = resolveConfiguredNativeAsset(config, network);
    const recipient = assertAddress(options.to, 'to');
    const amountWei = options.amount
      ? parseConfiguredAmount(options.amount, asset.decimals, 'amount')
      : parseBigIntString(options.amountWei, 'amountWei');
    try {
      if (options.broadcast) {
        const plan = await resolveAssetBroadcastPlan(
          {
            rpcUrl: resolveCliRpcUrl(options.rpcUrl, options.network, config),
            chainId: network,
            from: options.from ? assertAddress(options.from, 'from') : resolveWalletAddress(config),
            to: recipient,
            valueWei: amountWei,
            dataHex: '0x',
            nonce: options.nonce ? parseIntegerString(options.nonce, 'nonce') : undefined,
            gasLimit: options.gasLimit
              ? parsePositiveBigIntString(options.gasLimit, 'gasLimit')
              : undefined,
            maxFeePerGasWei: options.maxFeePerGasWei
              ? parsePositiveBigIntString(options.maxFeePerGasWei, 'maxFeePerGasWei')
              : undefined,
            maxPriorityFeePerGasWei: options.maxPriorityFeePerGasWei
              ? parseBigIntString(options.maxPriorityFeePerGasWei, 'maxPriorityFeePerGasWei')
              : undefined,
            txType: options.txType,
          },
          {
            getChainInfo,
            assertRpcChainIdMatches,
            getNonce,
            estimateGas,
            estimateFees,
          },
        );
        const signed = await runAgentCommandJson<RustBroadcastOutput>({
          commandArgs: [
            'broadcast',
            '--network',
            String(plan.chainId),
            '--nonce',
            String(plan.nonce),
            '--to',
            recipient,
            '--value-wei',
            amountWei.toString(),
            '--data-hex',
            '0x',
            '--gas-limit',
            plan.gasLimit.toString(),
            '--max-fee-per-gas-wei',
            plan.maxFeePerGasWei.toString(),
            '--max-priority-fee-per-gas-wei',
            plan.maxPriorityFeePerGasWei.toString(),
            '--tx-type',
            plan.txType,
          ],
          auth: options,
          config,
          asJson: options.json,
          waitForManualApproval: true,
        });
        if (!signed) {
          return;
        }
        const completed = await completeAssetBroadcast(plan, signed, {
          assertSignedBroadcastTransactionMatchesRequest,
          broadcastRawTransaction,
        });
        print(
          formatBroadcastedAssetOutput({
            command: 'transfer-native',
            counterparty: recipient,
            asset,
            signed,
            plan,
            signedNonce: completed.signedNonce,
            networkTxHash: completed.networkTxHash,
            revealRawTx: options.revealRawTx,
            revealSignature: options.revealSignature,
          }),
          options.json,
        );
        if (options.wait) {
          await reportOnchainReceiptStatus({
            rpcUrl: plan.rpcUrl,
            txHash: completed.networkTxHash,
            asJson: options.json,
          });
        }
        return;
      }

      const result = await runAgentCommandJson<RustBroadcastOutput>({
        commandArgs: [
          'transfer-native',
          '--network',
          String(network),
          '--to',
          recipient,
          '--amount-wei',
          amountWei.toString(),
        ],
        auth: options,
        config,
        asJson: options.json,
      });
      if (result) {
        print(normalizeAgentAmountOutput(result, asset), options.json);
      }
    } catch (error) {
      throw rewriteAgentAmountError(error, asset);
    }
  });

  addAgentCommandAuthOptions(
    program
      .command('approve')
      .description('Submit an ERC-20 approve request through policy checks')
      .requiredOption('--network <name>', 'Network name')
      .requiredOption('--token <address>', 'ERC-20 token contract')
      .requiredOption('--spender <address>', 'Spender address')
      .requiredOption('--amount <amount>', 'Approval amount in token units')
      .option('--broadcast', 'Broadcast the signed transaction through RPC', false)
      .option('--rpc-url <url>', 'Ethereum RPC URL override used only for broadcast')
      .option(
        '--from <address>',
        'Sender address override for broadcast; defaults to configured wallet address',
      )
      .option('--nonce <nonce>', 'Explicit nonce override for broadcast')
      .option('--gas-limit <gas>', 'Gas limit override for broadcast')
      .option('--max-fee-per-gas-wei <wei>', 'Max fee per gas override for broadcast')
      .option('--max-priority-fee-per-gas-wei <wei>', 'Priority fee per gas override for broadcast')
      .option('--tx-type <type>', 'Typed tx value for broadcast', '0x02')
      .option('--no-wait', 'Do not wait up to 30s for an on-chain receipt after broadcast')
      .option(
        '--reveal-raw-tx',
        'Include the signed raw transaction bytes in broadcast output',
        false,
      )
      .option('--reveal-signature', 'Include signer r/s/v fields in broadcast output', false)
      .addOption(new Option('--amount-wei <wei>').hideHelp()),
  ).action(async (options) => {
    const config = readConfig();
    const network = resolveCliNetworkProfile(options.network, config).chainId;
    const token = assertAddress(options.token, 'token');
    const spender = assertAddress(options.spender, 'spender');
    const rpcUrl = resolveCliRpcUrl(options.rpcUrl, options.network, config);
    const asset = await resolveErc20AssetWithRpcFallback(
      config, network, token, rpcUrl, getTokenMetadata,
    );
    const amountWei = options.amount
      ? parseConfiguredAmount(options.amount, asset.decimals, 'amount')
      : parseBigIntString(options.amountWei, 'amountWei');
    try {
      if (options.broadcast) {
        const plan = await resolveAssetBroadcastPlan(
          {
            rpcUrl,
            chainId: network,
            from: options.from ? assertAddress(options.from, 'from') : resolveWalletAddress(config),
            to: token,
            valueWei: 0n,
            dataHex: encodeErc20ApproveData(spender, amountWei),
            nonce: options.nonce ? parseIntegerString(options.nonce, 'nonce') : undefined,
            gasLimit: options.gasLimit
              ? parsePositiveBigIntString(options.gasLimit, 'gasLimit')
              : undefined,
            maxFeePerGasWei: options.maxFeePerGasWei
              ? parsePositiveBigIntString(options.maxFeePerGasWei, 'maxFeePerGasWei')
              : undefined,
            maxPriorityFeePerGasWei: options.maxPriorityFeePerGasWei
              ? parseBigIntString(options.maxPriorityFeePerGasWei, 'maxPriorityFeePerGasWei')
              : undefined,
            txType: options.txType,
          },
          {
            getChainInfo,
            assertRpcChainIdMatches,
            getNonce,
            estimateGas,
            estimateFees,
          },
        );
        const signed = await runAgentCommandJson<RustBroadcastOutput>({
          commandArgs: [
            'broadcast',
            '--network',
            String(plan.chainId),
            '--nonce',
            String(plan.nonce),
            '--to',
            token,
            '--value-wei',
            '0',
            '--data-hex',
            plan.dataHex,
            '--gas-limit',
            plan.gasLimit.toString(),
            '--max-fee-per-gas-wei',
            plan.maxFeePerGasWei.toString(),
            '--max-priority-fee-per-gas-wei',
            plan.maxPriorityFeePerGasWei.toString(),
            '--tx-type',
            plan.txType,
          ],
          auth: options,
          config,
          asJson: options.json,
          waitForManualApproval: true,
        });
        if (!signed) {
          return;
        }
        const completed = await completeAssetBroadcast(plan, signed, {
          assertSignedBroadcastTransactionMatchesRequest,
          broadcastRawTransaction,
        });
        print(
          formatBroadcastedAssetOutput({
            command: 'approve',
            counterparty: spender,
            asset,
            signed,
            plan,
            signedNonce: completed.signedNonce,
            networkTxHash: completed.networkTxHash,
            revealRawTx: options.revealRawTx,
            revealSignature: options.revealSignature,
          }),
          options.json,
        );
        if (options.wait) {
          await reportOnchainReceiptStatus({
            rpcUrl: plan.rpcUrl,
            txHash: completed.networkTxHash,
            asJson: options.json,
          });
        }
        return;
      }

      const result = await runAgentCommandJson<RustBroadcastOutput>({
        commandArgs: [
          'approve',
          '--network',
          String(network),
          '--token',
          token,
          '--spender',
          spender,
          '--amount-wei',
          amountWei.toString(),
        ],
        auth: options,
        config,
        asJson: options.json,
      });
      if (result) {
        print(normalizeAgentAmountOutput(result, asset), options.json);
      }
    } catch (error) {
      throw rewriteAgentAmountError(error, asset);
    }
  });

  addAgentCommandAuthOptions(
    program
      .command('broadcast')
      .description('Submit a raw transaction broadcast request through policy checks')
      .requiredOption('--network <name>', 'Network name')
      .requiredOption('--to <address>', 'Recipient or target contract')
      .requiredOption('--gas-limit <gas>', 'Gas limit')
      .requiredOption('--max-fee-per-gas-wei <wei>', 'Max fee per gas in wei')
      .option('--nonce <nonce>', 'Explicit nonce override')
      .option('--value-wei <wei>', 'Value in wei', '0')
      .option('--data-hex <hex>', 'Calldata hex', '0x')
      .option('--max-priority-fee-per-gas-wei <wei>', 'Priority fee per gas in wei')
      .option('--tx-type <type>', 'Typed tx value', '0x02')
      .option('--delegation-enabled', 'Forward delegation flag to Rust signing request', false),
  ).action(async (options) => {
    const config = readConfig();
    const network = resolveCliNetworkProfile(options.network, config);
    const to = assertAddress(options.to, 'to');
    const valueWei = parseBigIntString(options.valueWei, 'valueWei');
    const dataHex = assertHex(options.dataHex, 'dataHex');
    const gasLimit = parsePositiveBigIntString(options.gasLimit, 'gasLimit');
    const maxFeePerGasWei = parsePositiveBigIntString(options.maxFeePerGasWei, 'maxFeePerGasWei');
    const explicitNonce = options.nonce ? parseIntegerString(options.nonce, 'nonce') : undefined;
    const rpcUrl = resolveCliRpcUrl(undefined, options.network, config);
    const from = resolveWalletAddress(config);
    const chainInfo = await getChainInfo(rpcUrl);
    assertRpcChainIdMatches(network.chainId, chainInfo.chainId);
    const nonce = explicitNonce ?? (await getNonce(rpcUrl, from));
    const fees = options.maxPriorityFeePerGasWei ? null : await estimateFees(rpcUrl);
    const maxPriorityFeePerGasWei = options.maxPriorityFeePerGasWei
      ? parseBigIntString(options.maxPriorityFeePerGasWei, 'maxPriorityFeePerGasWei')
      : resolveEstimatedPriorityFeePerGasWei({
          gasPrice: fees?.gasPrice ?? null,
          maxFeePerGas: fees?.maxFeePerGas ?? null,
          maxPriorityFeePerGas: fees?.maxPriorityFeePerGas ?? null,
        });
    const signed = await runAgentCommandJson<RustBroadcastOutput>({
      commandArgs: [
        'broadcast',
        '--network',
        String(network.chainId),
        '--nonce',
        String(nonce),
        '--to',
        to,
        '--value-wei',
        valueWei.toString(),
        '--data-hex',
        dataHex,
        '--gas-limit',
        gasLimit.toString(),
        '--max-fee-per-gas-wei',
        maxFeePerGasWei.toString(),
        '--max-priority-fee-per-gas-wei',
        maxPriorityFeePerGasWei.toString(),
        '--tx-type',
        options.txType,
        ...(options.delegationEnabled ? ['--delegation-enabled'] : []),
      ],
      auth: options,
      config,
      asJson: options.json,
    });
    if (!signed) {
      return;
    }

    if (!signed.raw_tx_hex) {
      throw new Error('Rust agent did not return raw_tx_hex for broadcast signing');
    }

    await assertSignedBroadcastTransactionMatchesRequest({
      rawTxHex: signed.raw_tx_hex as Hex,
      from,
      to,
      chainId: network.chainId,
      nonce,
      allowHigherNonce: false,
      value: valueWei,
      data: dataHex,
      gasLimit,
      maxFeePerGas: maxFeePerGasWei,
      maxPriorityFeePerGas: maxPriorityFeePerGasWei,
      txType: options.txType,
    });

    await broadcastRawTransaction(rpcUrl, signed.raw_tx_hex as Hex);
    print(signed, options.json);
  });

  registerBuiltinCliPlugins(program, {
    cli: {
      print,
      setExitCode: (code) => {
        process.exitCode = code;
      },
      addAgentCommandAuthOptions,
    },
    config: {
      readConfig,
      resolveCliRpcUrl,
      resolveWalletAddress,
    },
    values: {
      assertAddress,
      parseIntegerString,
      parsePositiveIntegerString,
      parsePositiveBigIntString,
      parseBigIntString,
    },
    agent: {
      runJson: (input) =>
        runAgentCommandJson({
          ...input,
          auth: input.auth as AgentCommandAuthOptions,
        }),
      rewriteAmountError: rewriteAgentAmountError,
    },
    broadcast: {
      resolvePlan: resolveAssetBroadcastPlan,
      resolvePlanDeps: {
        getChainInfo,
        assertRpcChainIdMatches,
        getNonce,
        estimateGas,
        estimateFees,
      },
      complete: completeAssetBroadcast,
      completeDeps: {
        assertSignedBroadcastTransactionMatchesRequest,
        broadcastRawTransaction,
      },
      formatOutput: formatBroadcastedAssetOutput,
      reportOnchainReceiptStatus,
    },
    exitCodes: {
      challengeRequired: BITREFILL_CHALLENGE_EXIT_CODE,
      waitTimeout: BITREFILL_WAIT_TIMEOUT_EXIT_CODE,
    },
  });

  addAgentCommandAuthOptions(
    program
      .command('x402')
      .description('Fetch an x402-protected URL using EIP-3009 signing')
      .argument('<url>', 'Absolute x402-protected URL')
      .option('--method <method>', 'HTTP method to use for the unpaid request and paid retry')
      .option(
        '--header <header>',
        'HTTP header to include with the request; repeat for multiple headers',
        collectRepeatedOptionValue,
        [],
      )
      .option('--data <text>', 'Raw HTTP request body to send')
      .option('--json-body <json>', 'JSON HTTP request body to send'),
  ).action(async (url, options) => {
    const config = readConfig();
    const requestInit = buildHttpRequestInit({
      method: options.method,
      header: options.header as string[] | undefined,
      data: options.data,
      jsonBody: options.jsonBody,
    });
    const signer = createAgentPayX402Signer({ auth: options, config });
    const x402 = new x402Client(selectPreferredX402Requirement).register(
      'eip155:*',
      new ExactEvmScheme(signer),
    );
    for (const network of X402_EVM_V1_NETWORKS) {
      x402.registerV1(network, new ExactEvmSchemeV1(signer));
    }
    const paidFetch = wrapFetchWithPayment(globalThis.fetch, x402);

    const response = await paidFetch(requiredString(url, 'url'), requestInit);
    const paymentResponseHeader =
      response.headers.get('PAYMENT-RESPONSE') ?? response.headers.get('X-PAYMENT-RESPONSE');
    let paymentResponse: unknown = null;
    if (paymentResponseHeader) {
      try {
        paymentResponse = decodePaymentResponseHeader(paymentResponseHeader);
      } catch {
        paymentResponse = paymentResponseHeader;
      }
    }

    await printHttpCommandResponse({
      protocol: 'x402',
      response,
      asJson: options.json,
      payment: paymentResponse,
    });
  });

  addAgentCommandAuthOptions(
    program
      .command('mpp')
      .description('Fetch an MPP-protected URL using Tempo charge/session payment flows')
      .argument('<url>', 'Absolute MPP-protected URL')
      .option('--amount <amount>', 'Expected payment amount in token units; omit to accept the server challenge amount')
      .option(
        '--deposit <amount>',
        'Tempo session deposit amount in token units; defaults to the challenge amount',
      )
      .option(
        '--session-state-file <path>',
        'Persist and reuse a tempo/session channel in this private JSON file',
      )
      .option(
        '--close-session',
        'Close a persisted tempo/session channel after the paid response',
        false,
      )
      .option('--method <method>', 'HTTP method to use for the unpaid request and paid retry')
      .option(
        '--header <header>',
        'HTTP header to include with the request; repeat for multiple headers',
        collectRepeatedOptionValue,
        [],
      )
      .option('--data <text>', 'Raw HTTP request body to send')
      .option('--json-body <json>', 'JSON HTTP request body to send')
      .option('--rpc-url <url>', 'RPC URL override used only for payment broadcast'),
  ).action(async (url, options) => {
    const config = readConfig();
    const targetUrl = requiredString(url, 'url');
    const sessionStatePath = resolveOptionalSessionStatePath(options.sessionStateFile);
    const requestInit = buildHttpRequestInit({
      method: options.method,
      header: options.header as string[] | undefined,
      data: options.data,
      jsonBody: options.jsonBody,
    });
    const initialResponse = await globalThis.fetch(targetUrl, requestInit);
    if (initialResponse.status !== 402) {
      const initialReceipt = parseMppReceiptFromHeaders(initialResponse.headers);
      await printHttpCommandResponse({
        protocol: 'mpp',
        response: initialResponse,
        asJson: options.json,
        payment: initialReceipt ? { receipt: initialReceipt } : undefined,
        summaryLines: buildMppPaymentSummaryLines({ receipt: initialReceipt }),
      });
      return;
    }

    const challenge = parseMppChallengeFromHeaders(initialResponse.headers);
    if (challenge.intent !== 'charge' && challenge.intent !== 'session') {
      throw new Error(
        `agentpay mpp supports charge and session intents (received ${challenge.method}/${challenge.intent})`,
      );
    }
    if (challenge.intent === 'session' && challenge.method !== 'tempo') {
      throw new Error(
        `agentpay mpp session requires the tempo method (received ${challenge.method}/session)`,
      );
    }

    const chainId = resolveMppChainId(challenge);
    const decimals =
      challenge.request.decimals !== undefined && Number.isSafeInteger(challenge.request.decimals)
        ? challenge.request.decimals
        : 6;
    const challengeAmountWei = parseBigIntString(challenge.request.amount, 'challenge.amount');
    if (options.amount) {
      const expectedAmountWei = parseConfiguredAmount(options.amount, decimals, 'amount');
      if (expectedAmountWei !== challengeAmountWei) {
        throw new Error(
          `challenge amount ${challenge.request.amount} does not match requested amount ${expectedAmountWei.toString()}`,
        );
      }
    }

    const walletAddress = resolveWalletAddress(config);
    const token = assertAddress(challenge.request.currency, 'challenge.currency');
    const recipient = assertAddress(challenge.request.recipient, 'challenge.recipient');
    const rpcUrl = resolveRpcUrlForChainId(config, chainId, options.rpcUrl);

    if (challenge.intent === 'session') {
      const escrowContract = assertAddress(
        requiredString(
          resolveMppEscrowContract(challenge) ?? undefined,
          'challenge.methodDetails.escrowContract',
        ),
        'challenge.methodDetails.escrowContract',
      );
      const suggestedDepositWei =
        typeof challenge.request.suggestedDeposit === 'string' && challenge.request.suggestedDeposit
          ? parseBigIntString(challenge.request.suggestedDeposit, 'challenge.suggestedDeposit')
          : undefined;
      const depositWei = options.deposit
        ? parseConfiguredAmount(options.deposit, decimals, 'deposit')
        : (suggestedDepositWei ?? challengeAmountWei);
      if (depositWei < challengeAmountWei) {
        throw new Error(
          `session deposit ${depositWei.toString()} must cover the requested amount ${challengeAmountWei.toString()}`,
        );
      }

      const source = `did:pkh:eip155:${chainId}:${walletAddress}`;
      const persistedSession = readTempoSessionStateFile(sessionStatePath);
      let activeChannelId: Hex;
      let activeDepositWei: bigint;
      let activeCumulativeAmountWei: bigint;
      let paidResponse: Response;

      if (persistedSession) {
        if (persistedSession.kind !== 'tempo_session' || persistedSession.version !== 1) {
          throw new Error('tempo session state file has an unsupported format');
        }
        if (persistedSession.chainId !== chainId) {
          throw new Error(
            `tempo session state chain ${persistedSession.chainId} does not match challenge chain ${chainId}`,
          );
        }
        if (persistedSession.walletAddress.toLowerCase() !== walletAddress.toLowerCase()) {
          throw new Error(
            `tempo session state wallet ${persistedSession.walletAddress} does not match configured wallet ${walletAddress}`,
          );
        }
        if (persistedSession.token.toLowerCase() !== token.toLowerCase()) {
          throw new Error(
            `tempo session state token ${persistedSession.token} does not match challenge currency ${token}`,
          );
        }
        if (persistedSession.recipient.toLowerCase() !== recipient.toLowerCase()) {
          throw new Error(
            `tempo session state recipient ${persistedSession.recipient} does not match challenge recipient ${recipient}`,
          );
        }
        if (persistedSession.escrowContract.toLowerCase() !== escrowContract.toLowerCase()) {
          throw new Error(
            `tempo session state escrow ${persistedSession.escrowContract} does not match challenge escrow ${escrowContract}`,
          );
        }
        if (
          typeof challenge.request.methodDetails?.channelId === 'string' &&
          challenge.request.methodDetails.channelId.trim() &&
          assertHex(
            challenge.request.methodDetails.channelId,
            'challenge.methodDetails.channelId',
          ).toLowerCase() !== persistedSession.channelId.toLowerCase()
        ) {
          throw new Error(
            `tempo session state channel ${persistedSession.channelId} does not match challenge channel ${challenge.request.methodDetails.channelId}`,
          );
        }

        activeChannelId = persistedSession.channelId;
        activeDepositWei = parseBigIntString(
          persistedSession.depositWei,
          'tempo session state.depositWei',
        );
        const persistedCumulativeAmountWei = parseBigIntString(
          persistedSession.cumulativeAmountWei,
          'tempo session state.cumulativeAmountWei',
        );
        let nextCumulativeAmountWei = persistedCumulativeAmountWei + challengeAmountWei;
        if (nextCumulativeAmountWei > activeDepositWei) {
          const targetDepositWei =
            depositWei > nextCumulativeAmountWei ? depositWei : nextCumulativeAmountWei;
          const additionalDepositWei = targetDepositWei - activeDepositWei;
          const topUp = await buildTempoSessionTopUpPayload({
            auth: options,
            config,
            rpcUrl,
            chainId,
            token,
            recipient,
            escrowContract,
            walletAddress,
            decimals,
            channelId: activeChannelId,
            requestAmountWei: challengeAmountWei,
            additionalDepositWei,
            targetDepositWei,
            requiredCumulativeAmountWei: nextCumulativeAmountWei,
            feePayer: challenge.request.methodDetails?.feePayer === true,
          });
          const topUpResponse = await globalThis.fetch(targetUrl, {
            method: 'POST',
            headers: withAuthorizationHeader(
              undefined,
              serializeMppCredentialHeader({
                challenge,
                payload: topUp.payload,
                source,
              }),
            ),
          });
          if (!topUpResponse.ok) {
            const topUpErrorBody = await topUpResponse.text();
            throw new Error(
              `tempo/session topUp failed with status ${topUpResponse.status}${topUpErrorBody ? `: ${topUpErrorBody}` : ''}`,
            );
          }
          activeDepositWei = targetDepositWei;
          if (sessionStatePath) {
            writeTempoSessionStateFile(
              sessionStatePath,
              createTempoSessionState({
                chainId,
                rpcUrl,
                escrowContract,
                token,
                recipient,
                walletAddress,
                channelId: activeChannelId,
                depositWei: activeDepositWei,
                cumulativeAmountWei: persistedCumulativeAmountWei,
              }),
            );
          }
          nextCumulativeAmountWei = persistedCumulativeAmountWei + challengeAmountWei;
        }

        const voucherPayload = await buildTempoSessionVoucherPayload({
          auth: options,
          config,
          chainId,
          escrowContract,
          token,
          recipient,
          channelId: activeChannelId,
          amountWei: challengeAmountWei,
          cumulativeAmountWei: nextCumulativeAmountWei,
          action: 'voucher',
        });
        paidResponse = await globalThis.fetch(targetUrl, {
          ...requestInit,
          headers: withAuthorizationHeader(
            requestInit.headers,
            serializeMppCredentialHeader({
              challenge,
              payload: voucherPayload,
              source,
            }),
          ),
        });
        activeCumulativeAmountWei = nextCumulativeAmountWei;
      } else {
        const open = await buildTempoSessionOpenPayload({
          auth: options,
          config,
          rpcUrl,
          chainId,
          token,
          recipient,
          escrowContract,
          walletAddress,
          decimals,
          amountWei: challengeAmountWei,
          depositWei,
          feePayer: challenge.request.methodDetails?.feePayer === true,
        });
        activeChannelId = open.channelId;
        activeDepositWei = depositWei;
        activeCumulativeAmountWei = challengeAmountWei;
        paidResponse = await globalThis.fetch(targetUrl, {
          ...requestInit,
          headers: withAuthorizationHeader(
            requestInit.headers,
            serializeMppCredentialHeader({
              challenge,
              payload: open.payload,
              source,
            }),
          ),
        });
      }

      const paymentReceipt = parseMppReceiptFromHeaders(paidResponse.headers);
      if (!paidResponse.ok && !paymentReceipt) {
        const paidErrorBody = await paidResponse.text();
        throw new Error(
          `tempo/session request failed with status ${paidResponse.status}${paidErrorBody ? `: ${paidErrorBody}` : ''}`,
        );
      }
      const isEventStream = paidResponse.headers
        .get('content-type')
        ?.toLowerCase()
        .includes('text/event-stream');
      if (paymentReceipt?.channelId) {
        activeChannelId = assertHex(paymentReceipt.channelId, 'payment.receipt.channelId');
      }
      activeCumulativeAmountWei = resolveTempoSessionCumulativeAmountWei(
        paymentReceipt,
        activeCumulativeAmountWei,
      );

      if (isEventStream) {
        await handleTempoSessionStreamResponse({
          response: paidResponse,
          asJson: options.json,
          challenge,
          auth: options,
          config,
          targetUrl,
          chainId,
          rpcUrl,
          token,
          recipient,
          escrowContract,
          walletAddress,
          decimals,
          sessionStatePath,
          closeSession: Boolean(options.closeSession),
          defaultDepositWei: depositWei,
          activeChannelId,
          activeDepositWei,
          activeCumulativeAmountWei,
          source,
        });
        return;
      }

      let closeReceipt: MppReceipt | null = null;
      const shouldCloseSession = !sessionStatePath || Boolean(options.closeSession);
      if (shouldCloseSession) {
        const closePayload = await buildTempoSessionClosePayload({
          auth: options,
          config,
          chainId,
          escrowContract,
          token,
          recipient,
          channelId: activeChannelId,
          cumulativeAmountWei: activeCumulativeAmountWei,
        });
        const closeResponse = await globalThis.fetch(targetUrl, {
          method: 'POST',
          headers: withAuthorizationHeader(
            undefined,
            serializeMppCredentialHeader({
              challenge,
              payload: closePayload,
              source,
            }),
          ),
        });
        let closeErrorBody = '';
        if (!closeResponse.ok) {
          closeErrorBody = await closeResponse.text();
          throw new Error(
            `tempo/session close failed with status ${closeResponse.status}${closeErrorBody ? `: ${closeErrorBody}` : ''}`,
          );
        }
        closeReceipt = parseMppReceiptFromHeaders(closeResponse.headers);
        deleteTempoSessionStateFile(sessionStatePath);
      } else {
        writeTempoSessionStateFile(
          sessionStatePath,
          createTempoSessionState({
            chainId,
            rpcUrl,
            escrowContract,
            token,
            recipient,
            walletAddress,
            channelId: activeChannelId,
            depositWei: activeDepositWei,
            cumulativeAmountWei: activeCumulativeAmountWei,
          }),
        );
      }

      await printHttpCommandResponse({
        protocol: 'mpp',
        response: paidResponse,
        asJson: options.json,
        payment: {
          challengeId: challenge.id,
          method: challenge.method,
          intent: challenge.intent,
          channelId: activeChannelId,
          depositWei: activeDepositWei.toString(),
          receipt: paymentReceipt,
          closeReceipt,
        },
        summaryLines: buildMppPaymentSummaryLines({
          channelId: activeChannelId,
          receipt: paymentReceipt,
          closeReceipt,
        }),
      });
      return;
    }

    let chargeTo: Address;
    let chargeData: Hex;
    if (isTempoChain(chainId)) {
      const memo = challenge.request.methodDetails?.memo
        ? assertHex(challenge.request.methodDetails.memo, 'challenge.methodDetails.memo')
        : encodeMppAttributionMemo({ serverId: challenge.realm });
      const call = TempoActions.token.transfer.call({
        token,
        to: recipient,
        amount: challengeAmountWei,
        ...(memo ? { memo } : {}),
      });
      chargeTo = assertAddress(call.to, 'mpp transfer target');
      chargeData = assertHex(call.data, 'mpp transfer calldata');
    } else {
      chargeTo = token;
      chargeData = encodeErc20TransferData(recipient, challengeAmountWei);
    }

    const plan = await resolveAssetBroadcastPlan(
      {
        rpcUrl,
        chainId,
        from: walletAddress,
        to: chargeTo,
        valueWei: 0n,
        dataHex: chargeData,
        txType: '0x02',
      },
      {
        getChainInfo,
        assertRpcChainIdMatches,
        getNonce,
        estimateGas,
        estimateFees,
      },
    );
    const signed = await runAgentCommandJson<RustBroadcastOutput>({
      commandArgs: buildBroadcastCommandArgs(plan),
      auth: options,
      config,
      asJson: options.json,
      waitForManualApproval: true,
    });
    if (!signed) {
      return;
    }

    const completed = await completeAssetBroadcast(plan, signed, {
      assertSignedBroadcastTransactionMatchesRequest,
      broadcastRawTransaction,
    });
    const networkTxHash = completed.networkTxHash;

    const receiptResult = await waitForOnchainReceipt(
      {
        rpcUrl,
        txHash: networkTxHash,
        timeoutMs: ONCHAIN_RECEIPT_TIMEOUT_MS,
        intervalMs: ONCHAIN_RECEIPT_POLL_INTERVAL_MS,
      },
      {
        getTransactionReceiptByHash,
      },
    );
    if (!receiptResult.receipt) {
      throw new Error(
        `Timed out after ${ONCHAIN_RECEIPT_TIMEOUT_MS / 1000}s waiting for Tempo payment receipt ${networkTxHash}`,
      );
    }

    const authorization = serializeMppCredentialHeader({
      challenge,
      payload: {
        type: 'hash',
        hash: networkTxHash,
      },
      source: `did:pkh:eip155:${chainId}:${walletAddress}`,
    });
    const paidResponse = await globalThis.fetch(targetUrl, {
      ...requestInit,
      headers: withAuthorizationHeader(requestInit.headers, authorization),
    });
    const paymentReceipt = parseMppReceiptFromHeaders(paidResponse.headers);

    await printHttpCommandResponse({
      protocol: 'mpp',
      response: paidResponse,
      asJson: options.json,
      payment: {
        challengeId: challenge.id,
        method: challenge.method,
        intent: challenge.intent,
        txHash: networkTxHash,
        receipt: paymentReceipt,
      },
      summaryLines: buildMppPaymentSummaryLines({
        txHash: networkTxHash,
        receipt: paymentReceipt,
      }),
    });
  });

  const rpc = program.command('rpc').description('RPC methods implemented in TypeScript');
  rpc
    .command('chain')
    .option('--rpc-url <url>', 'Ethereum RPC URL')
    .option('--json', 'Print JSON output', false)
    .action(async (options) => {
      const config = readConfig();
      const rpcUrl = resolveRpcUrl(options.rpcUrl, config);
      const result = await getChainInfo(rpcUrl);
      print(
        {
          rpcUrl,
          ...result,
          configured: activeChainSummary(config),
        },
        options.json,
      );
    });
  rpc
    .command('block-number')
    .option('--rpc-url <url>', 'Ethereum RPC URL')
    .option('--json', 'Print JSON output', false)
    .action(async (options) => {
      const config = readConfig();
      const rpcUrl = resolveRpcUrl(options.rpcUrl, config);
      const blockNumber = await getLatestBlockNumber(rpcUrl);
      print({ rpcUrl, blockNumber: blockNumber.toString() }, options.json);
    });
  rpc
    .command('account')
    .requiredOption('--address <address>', 'Account address')
    .option('--rpc-url <url>', 'Ethereum RPC URL')
    .option('--json', 'Print JSON output', false)
    .action(async (options) => {
      const config = readConfig();
      const rpcUrl = resolveRpcUrl(options.rpcUrl, config);
      const address = assertAddress(options.address, 'address');
      const snapshot = await getAccountSnapshot(rpcUrl, address);
      print(
        {
          ...snapshot,
          latestBlockNumber: snapshot.latestBlockNumber.toString(),
          balance: {
            raw: snapshot.balance.raw.toString(),
            formatted: snapshot.balance.formatted,
          },
        },
        options.json,
      );
    });
  rpc
    .command('balance')
    .requiredOption('--address <address>', 'Account address')
    .option('--token <address>', 'Optional ERC-20 token address')
    .option('--rpc-url <url>', 'Ethereum RPC URL')
    .option('--decimals <decimals>', 'ERC-20 decimals override')
    .option('--json', 'Print JSON output', false)
    .action(async (options) => {
      const config = readConfig();
      const rpcUrl = resolveRpcUrl(options.rpcUrl, config);
      const owner = assertAddress(options.address, 'address');
      if (options.token) {
        const token = assertAddress(options.token, 'token');
        const result = await getTokenBalance(
          rpcUrl,
          token,
          owner,
          options.decimals ? parseIntegerString(options.decimals, 'decimals') : undefined,
        );
        print(
          {
            kind: 'erc20',
            token,
            owner,
            balanceWei: result.raw.toString(),
            decimals: result.decimals,
            name: result.name,
            symbol: result.symbol,
            formatted: result.formatted,
          },
          options.json,
        );
        return;
      }

      const result = await getNativeBalance(rpcUrl, owner);
      print(
        {
          kind: 'native',
          owner,
          balanceWei: result.raw.toString(),
          formatted: result.formatted,
        },
        options.json,
      );
    });
  rpc
    .command('nonce')
    .requiredOption('--address <address>', 'Account address')
    .option('--rpc-url <url>', 'Ethereum RPC URL')
    .option('--json', 'Print JSON output', false)
    .action(async (options) => {
      const config = readConfig();
      const rpcUrl = resolveRpcUrl(options.rpcUrl, config);
      const address = assertAddress(options.address, 'address');
      const nonce = await getNonce(rpcUrl, address);
      print({ address, nonce }, options.json);
    });
  rpc
    .command('fees')
    .option('--rpc-url <url>', 'Ethereum RPC URL')
    .option('--json', 'Print JSON output', false)
    .action(async (options) => {
      const config = readConfig();
      const rpcUrl = resolveRpcUrl(options.rpcUrl, config);
      const fees = await estimateFees(rpcUrl);
      print(
        {
          rpcUrl,
          gasPrice: stringifyOptionalValue(fees.gasPrice),
          maxFeePerGas: stringifyOptionalValue(fees.maxFeePerGas),
          maxPriorityFeePerGas: stringifyOptionalValue(fees.maxPriorityFeePerGas),
        },
        options.json,
      );
    });
  rpc
    .command('gas-estimate')
    .requiredOption('--from <address>', 'Sender address')
    .requiredOption('--to <address>', 'Recipient or target contract')
    .option('--value-wei <wei>', 'Value in wei', '0')
    .option('--data-hex <hex>', 'Calldata hex', '0x')
    .option('--rpc-url <url>', 'Ethereum RPC URL')
    .option('--json', 'Print JSON output', false)
    .action(async (options) => {
      const config = readConfig();
      const rpcUrl = resolveRpcUrl(options.rpcUrl, config);
      const gas = await estimateGas({
        rpcUrl,
        from: assertAddress(options.from, 'from'),
        to: assertAddress(options.to, 'to'),
        value: parseBigIntString(options.valueWei, 'valueWei'),
        data: assertHex(options.dataHex, 'dataHex'),
      });
      print({ rpcUrl, gas: gas.toString() }, options.json);
    });
  rpc
    .command('tx')
    .requiredOption('--hash <hash>', 'Transaction hash')
    .option('--rpc-url <url>', 'Ethereum RPC URL')
    .option('--json', 'Print JSON output', false)
    .action(async (options) => {
      const config = readConfig();
      const rpcUrl = resolveRpcUrl(options.rpcUrl, config);
      const tx = await getTransactionByHash(rpcUrl, assertHex(options.hash, 'hash'));
      print(tx, options.json);
    });
  rpc
    .command('receipt')
    .requiredOption('--hash <hash>', 'Transaction hash')
    .option('--rpc-url <url>', 'Ethereum RPC URL')
    .option('--json', 'Print JSON output', false)
    .action(async (options) => {
      const config = readConfig();
      const rpcUrl = resolveRpcUrl(options.rpcUrl, config);
      const receipt = await getTransactionReceiptByHash(rpcUrl, assertHex(options.hash, 'hash'));
      print(receipt, options.json);
    });
  rpc
    .command('code')
    .requiredOption('--address <address>', 'Contract address')
    .option('--rpc-url <url>', 'Ethereum RPC URL')
    .option('--json', 'Print JSON output', false)
    .action(async (options) => {
      const config = readConfig();
      const rpcUrl = resolveRpcUrl(options.rpcUrl, config);
      const bytecode = await getCodeAtAddress(rpcUrl, assertAddress(options.address, 'address'));
      print(
        {
          address: options.address,
          rpcUrl,
          bytecode: bytecode ?? '0x',
          hasCode: bytecode !== undefined && bytecode !== '0x',
        },
        options.json,
      );
    });
  rpc
    .command('broadcast-raw')
    .requiredOption('--raw-tx-hex <hex>', 'Signed raw transaction hex')
    .option('--rpc-url <url>', 'Ethereum RPC URL')
    .option('--no-wait', 'Do not wait up to 30s for an on-chain receipt after broadcast')
    .option('--json', 'Print JSON output', false)
    .action(async (options) => {
      const config = readConfig();
      const rpcUrl = resolveRpcUrl(options.rpcUrl, config);
      const txHash = await broadcastRawTransaction(rpcUrl, assertHex(options.rawTxHex, 'rawTxHex'));
      print({ txHash }, options.json);
      if (options.wait) {
        await reportOnchainReceiptStatus({
          rpcUrl,
          txHash,
          asJson: options.json,
        });
      }
    });

  const tx = program
    .command('tx')
    .description('Sign with Rust, then perform network RPC in TypeScript');
  tx.command('broadcast')
    .requiredOption('--from <address>', 'Sender address for nonce/gas estimation')
    .requiredOption('--to <address>', 'Recipient or target contract')
    .option('--network <name>', 'Network name')
    .option('--rpc-url <url>', 'Ethereum RPC URL')
    .option('--daemon-socket <path>', 'Daemon socket path')
    .option('--agent-key-id <uuid>', 'Agent key id')
    .option('--agent-auth-token <token>', 'Agent auth token')
    .option('--agent-auth-token-stdin', 'Read agent auth token from stdin', false)
    .option(
      '--allow-legacy-agent-auth-source',
      'Allow deprecated argv/config/env fallback for agent auth token',
      false,
    )
    .option('--nonce <nonce>', 'Explicit nonce override')
    .option('--value-wei <wei>', 'Value in wei', '0')
    .option('--data-hex <hex>', 'Calldata hex', '0x')
    .option('--gas-limit <gas>', 'Gas limit override')
    .option('--max-fee-per-gas-wei <wei>', 'Max fee per gas override')
    .option('--max-priority-fee-per-gas-wei <wei>', 'Priority fee per gas override')
    .option('--tx-type <type>', 'Typed tx value', '0x02')
    .option('--delegation-enabled', 'Forward delegation flag to Rust signing request', false)
    .option('--no-wait', 'Do not wait up to 30s for an on-chain receipt after broadcast')
    .option('--reveal-raw-tx', 'Include the signed raw transaction bytes in output', false)
    .option('--reveal-signature', 'Include signer r/s/v fields in output', false)
    .option('--json', 'Print JSON output', false)
    .action(async (options) => {
      const config = readConfig();
      const network = resolveCliNetworkProfile(options.network, config);
      const rpcUrl = resolveCliRpcUrl(options.rpcUrl, options.network, config);
      const chainId = network.chainId;
      const chainInfo = await getChainInfo(rpcUrl);
      assertRpcChainIdMatches(chainId, chainInfo.chainId);
      const from = assertAddress(options.from, 'from');
      const to = assertAddress(options.to, 'to');
      const valueWei = parseBigIntString(options.valueWei, 'valueWei');
      const dataHex = assertHex(options.dataHex, 'dataHex');
      const nonce = options.nonce
        ? parseIntegerString(options.nonce, 'nonce')
        : await getNonce(rpcUrl, from);
      const gasLimit = options.gasLimit
        ? parsePositiveBigIntString(options.gasLimit, 'gasLimit')
        : await estimateGas({ rpcUrl, from, to, value: valueWei, data: dataHex });
      const fees = await estimateFees(rpcUrl);
      const maxFeePerGasWei = options.maxFeePerGasWei
        ? parsePositiveBigIntString(options.maxFeePerGasWei, 'maxFeePerGasWei')
        : (fees.maxFeePerGas ?? fees.gasPrice);
      const maxPriorityFeePerGasWei = options.maxPriorityFeePerGasWei
        ? parseBigIntString(options.maxPriorityFeePerGasWei, 'maxPriorityFeePerGasWei')
        : (fees.maxPriorityFeePerGas ?? fees.gasPrice ?? 0n);

      if (maxFeePerGasWei === null || maxFeePerGasWei <= 0n) {
        throw new Error('Could not determine maxFeePerGas; pass --max-fee-per-gas-wei');
      }

      const signed = await runAgentCommandJson<RustBroadcastOutput>({
        commandArgs: [
          'broadcast',
          '--network',
          String(chainId),
          '--nonce',
          String(nonce),
          '--to',
          to,
          '--value-wei',
          valueWei.toString(),
          '--data-hex',
          dataHex,
          '--gas-limit',
          gasLimit.toString(),
          '--max-fee-per-gas-wei',
          maxFeePerGasWei.toString(),
          '--max-priority-fee-per-gas-wei',
          maxPriorityFeePerGasWei.toString(),
          '--tx-type',
          options.txType,
          ...(options.delegationEnabled ? ['--delegation-enabled'] : []),
        ],
        auth: options,
        config,
        asJson: options.json,
      });
      if (!signed) {
        return;
      }

      if (!signed.raw_tx_hex) {
        throw new Error('Rust agent did not return raw_tx_hex for broadcast signing');
      }

      const inspected = await assertSignedBroadcastTransactionMatchesRequest({
        rawTxHex: signed.raw_tx_hex as Hex,
        from,
        to,
        chainId,
        nonce,
        allowHigherNonce: false,
        value: valueWei,
        data: dataHex,
        gasLimit,
        maxFeePerGas: maxFeePerGasWei,
        maxPriorityFeePerGas: maxPriorityFeePerGasWei,
        txType: options.txType,
      });

      const networkTxHash = await broadcastRawTransaction(rpcUrl, signed.raw_tx_hex as Hex);
      print(
        {
          command: 'broadcast',
          rpcUrl,
          chainId,
          nonce: inspected.nonce,
          gasLimit: gasLimit.toString(),
          maxFeePerGasWei: maxFeePerGasWei.toString(),
          maxPriorityFeePerGasWei: maxPriorityFeePerGasWei.toString(),
          signedTxHash: signed.tx_hash_hex,
          networkTxHash,
          rawTxHex: options.revealRawTx ? signed.raw_tx_hex : '<redacted>',
          signer: options.revealSignature
            ? {
                r: signed.r_hex,
                s: signed.s_hex,
                v: signed.v,
              }
            : '<redacted>',
        },
        options.json,
      );
      if (options.wait) {
        await reportOnchainReceiptStatus({
          rpcUrl,
          txHash: networkTxHash,
          asJson: options.json,
        });
      }
    });

  await program.parseAsync(process.argv);
}

void main()
  .catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  })
  .finally(async () => {
    await closeGlobalFetchProxyDispatcherFromEnv();
  });
