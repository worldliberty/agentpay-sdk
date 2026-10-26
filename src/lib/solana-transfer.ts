import {
  calculateEpochFee,
  decodeTransferCheckedInstruction,
  decodeTransferCheckedWithFeeInstruction,
  getAssociatedTokenAddressSync,
  getMint,
  getTransferFeeConfig,
  getTransferHook,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  TokenInstruction,
  TransferFeeInstruction,
} from '@solana/spl-token';
import {
  ComputeBudgetInstruction,
  ComputeBudgetProgram,
  Connection,
  NONCE_ACCOUNT_LENGTH,
  NonceAccount,
  PublicKey,
  SystemInstruction,
  SystemProgram,
  type TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from '@solana/web3.js';
import type { WlfiConfig } from '../../packages/config/src/index.js';
import { assertSafeRpcUrl } from '../../packages/config/src/index.js';
import { deriveSolanaWalletAddress, resolveWalletProfile } from './wallet-profile.js';

export interface SolanaAssetMetadata {
  assetId: string;
  decimals: number;
  symbol: string;
}

export interface SolanaTransferContext {
  asset: SolanaAssetMetadata;
  feePayer: string;
  mint: string;
  recipientOwner: string;
  recentBlockhash: string;
  sourceAta: string;
  destinationAta: string;
  tokenProgram: SolanaTokenProgram;
}

export interface SolanaSolTransferContext {
  asset: SolanaAssetMetadata;
  feePayer: string;
  recipient: string;
  recentBlockhash: string;
}

export interface SolanaComputeBudget {
  computeUnitLimit: string | null;
  computeUnitPriceMicroLamports: string | null;
}

export interface SolanaDurableNonceContext {
  nonceAccount: string;
  nonceAuthority: string;
  nonce: string;
}

export interface SolanaManagedNonceAccount {
  nonceAccount: string;
  seed: string;
}

export type SolanaTokenProgram = 'token' | 'token_2022';

/** Caps applied to the priority fee of every Solana transaction we build or broadcast. */
export interface SolanaPriorityFeeLimits {
  /** Defaults to {@link DEFAULT_SOLANA_MAX_COMPUTE_UNIT_PRICE_MICRO_LAMPORTS}. */
  maxComputeUnitPriceMicroLamports?: bigint | string;
  /** Defaults to {@link DEFAULT_SOLANA_MAX_PRIORITY_FEE_LAMPORTS} (0.01 SOL). */
  maxPriorityFeeLamports?: bigint | string;
}

export interface SolanaExpectedSolTransfer {
  kind: 'sol';
  recipient: string;
  lamports: bigint;
}

export interface SolanaExpectedSplTransfer {
  kind: 'spl';
  mint: string;
  sourceAta: string;
  destinationAta: string;
  amountWei: bigint;
  decimals: number;
  tokenProgram: SolanaTokenProgram;
  /** Present when the Rust signer was asked for `transfer_checked_with_fee`. */
  transferFeeWei?: bigint | string | null;
}

/** What the Rust agent was asked to sign; the broadcast path refuses anything else. */
export interface SolanaSignedTransactionExpectation extends SolanaPriorityFeeLimits {
  feePayer: string;
  /** The recent blockhash, or the durable nonce value when a nonce account is used. */
  recentBlockhash: string;
  durableNonceAccount?: string | null;
  transfer: SolanaExpectedSolTransfer | SolanaExpectedSplTransfer;
}

export interface DecodedSignedSolanaTransaction {
  feePayer: string;
  recentBlockhash: string;
  instructions: TransactionInstruction[];
  computeUnitLimit: bigint | null;
  computeUnitPriceMicroLamports: bigint | null;
  priorityFeeLamports: bigint;
}

export const DEFAULT_SOLANA_MAX_COMPUTE_UNIT_PRICE_MICRO_LAMPORTS = 10_000_000n;
export const DEFAULT_SOLANA_MAX_PRIORITY_FEE_LAMPORTS = 10_000_000n;
const SOLANA_MAX_COMPUTE_UNIT_LIMIT = 1_400_000n;
const MICRO_LAMPORTS_PER_LAMPORT = 1_000_000n;

export interface SolanaSignatureStatusResult {
  confirmationStatus: string | null;
  err: unknown;
  slot: number;
  timedOut: boolean;
}

function createConnection(rpcUrl: string): Connection {
  return new Connection(assertSafeRpcUrl(rpcUrl, 'rpcUrl'), 'confirmed');
}

function parsePublicKey(value: string, label: string): PublicKey {
  try {
    return new PublicKey(value.trim());
  } catch {
    throw new Error(`${label} must be a valid Solana address`);
  }
}

function solanaManagedNonceSeed(chainId: string | number): string {
  const normalizedChainId = String(chainId).trim();
  const seed = `agentpay-${normalizedChainId}-nonce`;
  // biome-ignore lint/suspicious/noControlCharactersInRegex: intentional ASCII-range check for the nonce seed
  if (!normalizedChainId || seed.length > 32 || !/^[\x00-\x7F]+$/u.test(seed)) {
    throw new Error('managed Solana nonce seed is invalid for this network');
  }
  return seed;
}

function parseSolanaNonceAccount(
  accountInfo: { owner: PublicKey; data: Buffer | Uint8Array },
  nonceAccount: PublicKey,
  expectedAuthority: PublicKey,
): SolanaDurableNonceContext {
  if (!accountInfo.owner.equals(SystemProgram.programId)) {
    throw new Error(
      `durableNonceAccount must be owned by the Solana system program; got ${accountInfo.owner.toBase58()}`,
    );
  }

  let parsed: NonceAccount;
  try {
    parsed = NonceAccount.fromAccountData(accountInfo.data);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`durableNonceAccount must be a valid Solana nonce account: ${message}`);
  }

  if (!parsed.authorizedPubkey.equals(expectedAuthority)) {
    throw new Error(
      `durable nonce authority must match the fee payer ${expectedAuthority.toBase58()}; got ${parsed.authorizedPubkey.toBase58()}`,
    );
  }

  return {
    nonceAccount: nonceAccount.toBase58(),
    nonceAuthority: parsed.authorizedPubkey.toBase58(),
    nonce: parsed.nonce,
  };
}

function parseHexBytes(value: string, label: string): Uint8Array {
  const normalized = value.trim().replace(/^0x/iu, '');
  if (!/^[0-9a-fA-F]+$/u.test(normalized) || normalized.length % 2 !== 0) {
    throw new Error(`${label} must be valid hex`);
  }
  return Uint8Array.from(Buffer.from(normalized, 'hex'));
}

function resolveTokenProgramForMintOwner(owner: PublicKey): SolanaTokenProgram {
  if (owner.equals(TOKEN_PROGRAM_ID)) {
    return 'token';
  }
  if (owner.equals(TOKEN_2022_PROGRAM_ID)) {
    return 'token_2022';
  }
  throw new Error(
    `mint must be owned by the SPL Token or Token-2022 program; got ${owner.toBase58()}`,
  );
}

function tokenProgramId(tokenProgram: SolanaTokenProgram): PublicKey {
  return tokenProgram === 'token_2022' ? TOKEN_2022_PROGRAM_ID : TOKEN_PROGRAM_ID;
}

function parseOptionalPositiveBigInt(value: string | undefined, label: string): bigint | null {
  const normalized = value?.trim();
  if (!normalized) {
    return null;
  }
  if (!/^[0-9]+$/u.test(normalized)) {
    throw new Error(`${label} must be a positive integer`);
  }
  const parsed = BigInt(normalized);
  if (parsed <= 0n) {
    throw new Error(`${label} must be greater than zero`);
  }
  return parsed;
}

function percentile(values: bigint[], percent: number): bigint | null {
  if (values.length === 0) {
    return null;
  }
  const sorted = [...values].sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
  const index = Math.min(sorted.length - 1, Math.max(0, Math.floor((sorted.length - 1) * percent)));
  return sorted[index] ?? null;
}

export function resolveSolanaWalletAddress(config: WlfiConfig): string {
  const profile = resolveWalletProfile(config);
  if (profile.solanaAddress) {
    return parsePublicKey(profile.solanaAddress, 'wallet.solanaAddress').toBase58();
  }
  const derivedFromSolanaPublicKey = profile.solanaPublicKey
    ? deriveSolanaWalletAddress(profile.solanaPublicKey)
    : undefined;
  if (derivedFromSolanaPublicKey) {
    return derivedFromSolanaPublicKey;
  }
  const legacyEd25519PublicKey =
    profile.algorithm === 'ed25519' ? profile.vaultPublicKey : undefined;
  if (!legacyEd25519PublicKey) {
    throw new Error(
      'wallet.solanaAddress is unavailable; rerun `agentpay admin setup --reuse-existing-wallet` to add Solana wallet metadata',
    );
  }
  const publicKeyBytes = parseHexBytes(legacyEd25519PublicKey, 'wallet.vaultPublicKey');
  if (publicKeyBytes.length !== 32) {
    throw new Error('wallet.vaultPublicKey must be a 32-byte ed25519 public key for Solana');
  }
  return new PublicKey(publicKeyBytes).toBase58();
}

export async function resolveSolanaTransferContext(input: {
  rpcUrl: string;
  feePayer: string;
  mint: string;
  recipientOwner: string;
}): Promise<SolanaTransferContext> {
  const connection = createConnection(input.rpcUrl);
  const feePayer = parsePublicKey(input.feePayer, 'feePayer');
  const mint = parsePublicKey(input.mint, 'mint');
  const recipientOwner = parsePublicKey(input.recipientOwner, 'to');

  const mintInfo = await connection.getAccountInfo(mint, 'confirmed');
  if (!mintInfo) {
    throw new Error(`mint account does not exist: ${mint.toBase58()}`);
  }
  const tokenProgram = resolveTokenProgramForMintOwner(mintInfo.owner);
  const programId = tokenProgramId(tokenProgram);
  const resolvedMint = await getMint(connection, mint, undefined, programId).catch(
    (error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`mint must be a valid SPL Token or Token-2022 mint: ${message}`);
    },
  );
  const transferHook = tokenProgram === 'token_2022' ? getTransferHook(resolvedMint) : null;
  if (transferHook) {
    throw new Error(
      `Token-2022 transfer hooks are not supported by this constrained transfer route: ${transferHook.programId.toBase58()}`,
    );
  }

  const sourceAta = getAssociatedTokenAddressSync(mint, feePayer, false, programId);
  const destinationAta = getAssociatedTokenAddressSync(mint, recipientOwner, false, programId);
  const [sourceInfo, destinationInfo, latestBlockhash] = await Promise.all([
    connection.getAccountInfo(sourceAta, 'confirmed'),
    connection.getAccountInfo(destinationAta, 'confirmed'),
    connection.getLatestBlockhash('finalized'),
  ]);

  if (!sourceInfo) {
    throw new Error(
      `sender associated token account does not exist: ${sourceAta.toBase58()}; create it before signing`,
    );
  }
  if (!destinationInfo) {
    throw new Error(
      `recipient associated token account does not exist: ${destinationAta.toBase58()}; create it before signing`,
    );
  }

  const normalizedMint = mint.toBase58();
  return {
    asset: {
      assetId: `spl:${normalizedMint}`,
      decimals: resolvedMint.decimals,
      symbol: normalizedMint,
    },
    feePayer: feePayer.toBase58(),
    mint: normalizedMint,
    recipientOwner: recipientOwner.toBase58(),
    recentBlockhash: latestBlockhash.blockhash,
    sourceAta: sourceAta.toBase58(),
    destinationAta: destinationAta.toBase58(),
    tokenProgram,
  };
}

export async function resolveSolanaTransferFee(input: {
  rpcUrl: string;
  mint: string;
  tokenProgram: SolanaTokenProgram;
  amountWei: bigint;
}): Promise<{
  transferInstruction: 'transfer_checked' | 'transfer_checked_with_fee';
  transferFeeWei: string | null;
}> {
  if (input.tokenProgram !== 'token_2022') {
    return { transferInstruction: 'transfer_checked', transferFeeWei: null };
  }
  const connection = createConnection(input.rpcUrl);
  const mint = parsePublicKey(input.mint, 'mint');
  const resolvedMint = await getMint(connection, mint, undefined, TOKEN_2022_PROGRAM_ID);
  const transferFeeConfig = getTransferFeeConfig(resolvedMint);
  if (!transferFeeConfig) {
    return { transferInstruction: 'transfer_checked', transferFeeWei: null };
  }
  const epochInfo = await connection.getEpochInfo('confirmed');
  const fee = calculateEpochFee(transferFeeConfig, BigInt(epochInfo.epoch), input.amountWei);
  return {
    transferInstruction: 'transfer_checked_with_fee',
    transferFeeWei: fee.toString(),
  };
}

export async function resolveSolanaSolTransferContext(input: {
  rpcUrl: string;
  feePayer: string;
  recipient: string;
}): Promise<SolanaSolTransferContext> {
  const connection = createConnection(input.rpcUrl);
  const feePayer = parsePublicKey(input.feePayer, 'feePayer');
  const recipient = parsePublicKey(input.recipient, 'to');
  const latestBlockhash = await connection.getLatestBlockhash('finalized');

  return {
    asset: {
      assetId: 'native_sol',
      decimals: 9,
      symbol: 'SOL',
    },
    feePayer: feePayer.toBase58(),
    recipient: recipient.toBase58(),
    recentBlockhash: latestBlockhash.blockhash,
  };
}

export async function resolveSolanaDurableNonceContext(input: {
  rpcUrl: string;
  nonceAccount: string;
  expectedAuthority: string;
}): Promise<SolanaDurableNonceContext> {
  const connection = createConnection(input.rpcUrl);
  const nonceAccount = parsePublicKey(input.nonceAccount, 'durableNonceAccount');
  const expectedAuthority = parsePublicKey(input.expectedAuthority, 'nonceAuthority');
  const accountInfo = await connection.getAccountInfo(nonceAccount, 'confirmed');
  if (!accountInfo) {
    throw new Error(`durable nonce account does not exist: ${nonceAccount.toBase58()}`);
  }
  return parseSolanaNonceAccount(accountInfo, nonceAccount, expectedAuthority);
}

export async function resolveSolanaDurableNonceContextIfExists(input: {
  rpcUrl: string;
  nonceAccount: string;
  expectedAuthority: string;
}): Promise<SolanaDurableNonceContext | null> {
  const connection = createConnection(input.rpcUrl);
  const nonceAccount = parsePublicKey(input.nonceAccount, 'durableNonceAccount');
  const expectedAuthority = parsePublicKey(input.expectedAuthority, 'nonceAuthority');
  const accountInfo = await connection.getAccountInfo(nonceAccount, 'confirmed');
  if (!accountInfo) {
    return null;
  }
  return parseSolanaNonceAccount(accountInfo, nonceAccount, expectedAuthority);
}

export async function deriveSolanaManagedNonceAccount(input: {
  chainId: string | number;
  feePayer: string;
}): Promise<SolanaManagedNonceAccount> {
  const feePayer = parsePublicKey(input.feePayer, 'feePayer');
  const seed = solanaManagedNonceSeed(input.chainId);
  const nonceAccount = await PublicKey.createWithSeed(feePayer, seed, SystemProgram.programId);
  return {
    nonceAccount: nonceAccount.toBase58(),
    seed,
  };
}

export async function getSolanaNonceAccountRentLamports(rpcUrl: string): Promise<string> {
  const connection = createConnection(rpcUrl);
  const lamports = await connection.getMinimumBalanceForRentExemption(
    NONCE_ACCOUNT_LENGTH,
    'confirmed',
  );
  return String(lamports);
}

function resolveFeeLimit(
  value: bigint | string | undefined,
  label: string,
  fallback: bigint,
): bigint {
  if (value === undefined) {
    return fallback;
  }
  if (typeof value === 'bigint') {
    if (value <= 0n) {
      throw new Error(`${label} must be greater than zero`);
    }
    return value;
  }
  return parseOptionalPositiveBigInt(value, label) ?? fallback;
}

function resolvePriorityFeeLimits(limits: SolanaPriorityFeeLimits): {
  maxComputeUnitPriceMicroLamports: bigint;
  maxPriorityFeeLamports: bigint;
} {
  return {
    maxComputeUnitPriceMicroLamports: resolveFeeLimit(
      limits.maxComputeUnitPriceMicroLamports,
      'maxComputeUnitPriceMicroLamports',
      DEFAULT_SOLANA_MAX_COMPUTE_UNIT_PRICE_MICRO_LAMPORTS,
    ),
    maxPriorityFeeLamports: resolveFeeLimit(
      limits.maxPriorityFeeLamports,
      'maxPriorityFeeLamports',
      DEFAULT_SOLANA_MAX_PRIORITY_FEE_LAMPORTS,
    ),
  };
}

/**
 * Worst-case priority fee in lamports. Without an explicit compute unit limit the runtime may
 * grant up to the per-transaction maximum, so that is what the estimate assumes.
 */
export function estimateSolanaPriorityFeeLamports(
  computeUnitLimit: bigint | null,
  computeUnitPriceMicroLamports: bigint | null,
): bigint {
  if (computeUnitPriceMicroLamports === null || computeUnitPriceMicroLamports <= 0n) {
    return 0n;
  }
  const units = computeUnitLimit ?? SOLANA_MAX_COMPUTE_UNIT_LIMIT;
  const microLamports = units * computeUnitPriceMicroLamports;
  return (microLamports + MICRO_LAMPORTS_PER_LAMPORT - 1n) / MICRO_LAMPORTS_PER_LAMPORT;
}

function assertSolanaPriorityFeeWithinLimits(
  budget: { computeUnitLimit: bigint | null; computeUnitPriceMicroLamports: bigint | null },
  limits: SolanaPriorityFeeLimits,
): bigint {
  const resolved = resolvePriorityFeeLimits(limits);
  const price = budget.computeUnitPriceMicroLamports ?? 0n;
  if (price > resolved.maxComputeUnitPriceMicroLamports) {
    throw new Error(
      `Solana compute unit price ${price.toString()} microlamports exceeds the maximum ${resolved.maxComputeUnitPriceMicroLamports.toString()}`,
    );
  }
  const priorityFeeLamports = estimateSolanaPriorityFeeLamports(budget.computeUnitLimit, price);
  if (priorityFeeLamports > resolved.maxPriorityFeeLamports) {
    const units = (budget.computeUnitLimit ?? SOLANA_MAX_COMPUTE_UNIT_LIMIT).toString();
    throw new Error(
      `Solana priority fee ${priorityFeeLamports.toString()} lamports (${units} compute units x ${price.toString()} microlamports) exceeds the maximum ${resolved.maxPriorityFeeLamports.toString()} lamports`,
    );
  }
  return priorityFeeLamports;
}

function capSolanaComputeUnitPrice(
  price: bigint,
  computeUnitLimit: bigint,
  limits: SolanaPriorityFeeLimits,
): bigint {
  const resolved = resolvePriorityFeeLimits(limits);
  const priceForMaxFee =
    (resolved.maxPriorityFeeLamports * MICRO_LAMPORTS_PER_LAMPORT) / computeUnitLimit;
  let capped = price;
  if (capped > resolved.maxComputeUnitPriceMicroLamports) {
    capped = resolved.maxComputeUnitPriceMicroLamports;
  }
  if (capped > priceForMaxFee) {
    capped = priceForMaxFee;
  }
  return capped;
}

export async function resolveSolanaComputeBudget(
  input: {
    rpcUrl: string;
    defaultComputeUnitLimit: number;
    computeUnitLimit?: string;
    computeUnitPriceMicroLamports?: string;
  } & SolanaPriorityFeeLimits,
): Promise<SolanaComputeBudget> {
  const explicitLimit = parseOptionalPositiveBigInt(input.computeUnitLimit, 'computeUnitLimit');
  const explicitPrice = parseOptionalPositiveBigInt(
    input.computeUnitPriceMicroLamports,
    'computeUnitPriceMicroLamports',
  );
  const computeUnitLimit = explicitLimit ?? BigInt(input.defaultComputeUnitLimit);
  if (computeUnitLimit <= 0n || computeUnitLimit > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error('computeUnitLimit must be a positive safe integer');
  }
  if (explicitPrice !== null) {
    // An operator-supplied price is honoured verbatim, but never past the fee caps.
    assertSolanaPriorityFeeWithinLimits(
      { computeUnitLimit, computeUnitPriceMicroLamports: explicitPrice },
      input,
    );
    return {
      computeUnitLimit: computeUnitLimit.toString(),
      computeUnitPriceMicroLamports: explicitPrice.toString(),
    };
  }

  try {
    const connection = createConnection(input.rpcUrl);
    const fees = await connection.getRecentPrioritizationFees();
    const price = percentile(
      fees.map((fee) => BigInt(fee.prioritizationFee)).filter((fee) => fee > 0n),
      0.5,
    );
    // RPC-suggested prices are advisory (and attacker-influenceable on a hostile RPC), so clamp
    // them to the caps instead of failing the transfer.
    const cappedPrice =
      price === null ? null : capSolanaComputeUnitPrice(price, computeUnitLimit, input);
    return {
      computeUnitLimit: computeUnitLimit.toString(),
      computeUnitPriceMicroLamports:
        cappedPrice === null || cappedPrice <= 0n ? null : cappedPrice.toString(),
    };
  } catch {
    return {
      computeUnitLimit: computeUnitLimit.toString(),
      computeUnitPriceMicroLamports: null,
    };
  }
}

/**
 * Deserialize a signed transaction and pull out the fields every later check relies on. Rejects
 * shapes the Rust signer never produces (multiple signers, address lookup tables, unknown compute
 * budget instructions) before any per-instruction comparison happens.
 */
export function decodeSignedSolanaTransaction(rawTxBase64: string): DecodedSignedSolanaTransaction {
  let transaction: VersionedTransaction;
  try {
    transaction = VersionedTransaction.deserialize(
      Uint8Array.from(Buffer.from(rawTxBase64.trim(), 'base64')),
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`signed Solana transaction could not be decoded: ${message}`);
  }

  const message = transaction.message;
  if (message.addressTableLookups.length > 0) {
    throw new Error('signed Solana transaction must not use address lookup tables');
  }
  if (message.header.numRequiredSignatures !== 1 || transaction.signatures.length !== 1) {
    throw new Error(
      `signed Solana transaction must have exactly one signer; got ${message.header.numRequiredSignatures} required signature(s) and ${transaction.signatures.length} signature(s)`,
    );
  }

  const decompiled = TransactionMessage.decompile(message);
  let computeUnitLimit: bigint | null = null;
  let computeUnitPriceMicroLamports: bigint | null = null;
  for (const instruction of decompiled.instructions) {
    if (!instruction.programId.equals(ComputeBudgetProgram.programId)) {
      continue;
    }
    const type = ComputeBudgetInstruction.decodeInstructionType(instruction);
    if (type === 'SetComputeUnitLimit') {
      if (computeUnitLimit !== null) {
        throw new Error('signed Solana transaction sets the compute unit limit more than once');
      }
      computeUnitLimit = BigInt(
        ComputeBudgetInstruction.decodeSetComputeUnitLimit(instruction).units,
      );
      continue;
    }
    if (type === 'SetComputeUnitPrice') {
      if (computeUnitPriceMicroLamports !== null) {
        throw new Error('signed Solana transaction sets the compute unit price more than once');
      }
      computeUnitPriceMicroLamports = BigInt(
        ComputeBudgetInstruction.decodeSetComputeUnitPrice(instruction).microLamports,
      );
      continue;
    }
    throw new Error(
      `signed Solana transaction contains an unsupported compute budget instruction: ${type}`,
    );
  }

  return {
    feePayer: decompiled.payerKey.toBase58(),
    recentBlockhash: decompiled.recentBlockhash,
    instructions: decompiled.instructions,
    computeUnitLimit,
    computeUnitPriceMicroLamports,
    priorityFeeLamports: estimateSolanaPriorityFeeLamports(
      computeUnitLimit,
      computeUnitPriceMicroLamports,
    ),
  };
}

function assertSamePublicKey(actual: PublicKey, expected: PublicKey, label: string): void {
  if (!actual.equals(expected)) {
    throw new Error(
      `signed Solana transaction ${label} ${actual.toBase58()} does not match expected ${expected.toBase58()}`,
    );
  }
}

function verifySplTransferInstruction(
  instruction: TransactionInstruction,
  expected: SolanaExpectedSplTransfer,
  feePayer: PublicKey,
): void {
  const programId = tokenProgramId(expected.tokenProgram);
  if (!instruction.programId.equals(programId)) {
    throw new Error(
      `signed Solana transaction token program ${instruction.programId.toBase58()} does not match expected ${programId.toBase58()}`,
    );
  }
  const expectedMint = parsePublicKey(expected.mint, 'mint');
  const expectedSource = parsePublicKey(expected.sourceAta, 'sourceAta');
  const expectedDestination = parsePublicKey(expected.destinationAta, 'destinationAta');
  const expectedFee =
    expected.transferFeeWei === undefined || expected.transferFeeWei === null
      ? null
      : typeof expected.transferFeeWei === 'bigint'
        ? expected.transferFeeWei
        : BigInt(expected.transferFeeWei.trim());

  let source: PublicKey;
  let mint: PublicKey;
  let destination: PublicKey;
  let owner: PublicKey;
  let extraSigners: number;
  let amount: bigint;
  let decimals: number;
  let fee: bigint | null;

  const discriminator = instruction.data[0];
  if (discriminator === TokenInstruction.TransferChecked) {
    const decoded = decodeTransferCheckedInstruction(instruction, programId);
    source = decoded.keys.source.pubkey;
    mint = decoded.keys.mint.pubkey;
    destination = decoded.keys.destination.pubkey;
    owner = decoded.keys.owner.pubkey;
    extraSigners = decoded.keys.multiSigners.length;
    amount = BigInt(decoded.data.amount);
    decimals = decoded.data.decimals;
    fee = null;
  } else if (
    discriminator === TokenInstruction.TransferFeeExtension &&
    instruction.data[1] === TransferFeeInstruction.TransferCheckedWithFee
  ) {
    const decoded = decodeTransferCheckedWithFeeInstruction(instruction, programId);
    source = decoded.keys.source.pubkey;
    mint = decoded.keys.mint.pubkey;
    destination = decoded.keys.destination.pubkey;
    owner = decoded.keys.authority.pubkey;
    extraSigners = decoded.keys.signers?.length ?? 0;
    amount = BigInt(decoded.data.amount);
    decimals = decoded.data.decimals;
    fee = BigInt(decoded.data.fee);
  } else {
    throw new Error(
      'signed Solana transaction contains an unsupported token instruction; only transfer_checked and transfer_checked_with_fee are allowed',
    );
  }

  assertSamePublicKey(source, expectedSource, 'source token account');
  assertSamePublicKey(mint, expectedMint, 'mint');
  assertSamePublicKey(destination, expectedDestination, 'destination token account');
  assertSamePublicKey(owner, feePayer, 'token transfer authority');
  if (extraSigners !== 0) {
    throw new Error('signed Solana transaction token transfer must not include extra signers');
  }
  if (amount !== expected.amountWei) {
    throw new Error(
      `signed Solana transaction token amount ${amount.toString()} does not match expected ${expected.amountWei.toString()}`,
    );
  }
  if (decimals !== expected.decimals) {
    throw new Error(
      `signed Solana transaction token decimals ${decimals} do not match expected ${expected.decimals}`,
    );
  }
  if (expectedFee === null && fee !== null) {
    throw new Error('signed Solana transaction includes a transfer fee but none was expected');
  }
  if (expectedFee !== null && fee !== expectedFee) {
    throw new Error(
      `signed Solana transaction transfer fee ${fee === null ? 'none' : fee.toString()} does not match expected ${expectedFee.toString()}`,
    );
  }
}

/**
 * Compare a Rust-signed transaction against what this process asked for: fee payer, recent
 * blockhash / nonce, optional durable-nonce advance, exactly one transfer to the intended
 * destination for the intended amount, and priority fees within the caps.
 */
export function verifySignedSolanaTransaction(
  rawTxBase64: string,
  expected: SolanaSignedTransactionExpectation,
): DecodedSignedSolanaTransaction {
  const decoded = decodeSignedSolanaTransaction(rawTxBase64);
  const feePayer = parsePublicKey(expected.feePayer, 'feePayer');
  assertSamePublicKey(new PublicKey(decoded.feePayer), feePayer, 'fee payer');

  const expectedBlockhash = expected.recentBlockhash.trim();
  if (decoded.recentBlockhash !== expectedBlockhash) {
    throw new Error(
      `signed Solana transaction recent blockhash ${decoded.recentBlockhash} does not match expected ${expectedBlockhash}`,
    );
  }

  const expectedNonceAccount = expected.durableNonceAccount?.trim()
    ? parsePublicKey(expected.durableNonceAccount, 'durableNonceAccount')
    : null;
  let transferCount = 0;
  let nonceAdvanceCount = 0;

  decoded.instructions.forEach((instruction, index) => {
    if (instruction.programId.equals(ComputeBudgetProgram.programId)) {
      return;
    }

    if (instruction.programId.equals(SystemProgram.programId)) {
      const type = SystemInstruction.decodeInstructionType(instruction);
      if (type === 'AdvanceNonceAccount') {
        if (!expectedNonceAccount) {
          throw new Error(
            'signed Solana transaction advances a durable nonce but no nonce account was requested',
          );
        }
        if (index !== 0) {
          throw new Error(
            'signed Solana transaction durable nonce advance must be the first instruction',
          );
        }
        const advance = SystemInstruction.decodeNonceAdvance(instruction);
        assertSamePublicKey(advance.noncePubkey, expectedNonceAccount, 'durable nonce account');
        assertSamePublicKey(advance.authorizedPubkey, feePayer, 'durable nonce authority');
        nonceAdvanceCount += 1;
        return;
      }
      if (type === 'Transfer') {
        if (expected.transfer.kind !== 'sol') {
          throw new Error(
            'signed Solana transaction contains a SOL transfer but an SPL token transfer was expected',
          );
        }
        const transfer = SystemInstruction.decodeTransfer(instruction);
        assertSamePublicKey(transfer.fromPubkey, feePayer, 'SOL transfer source');
        assertSamePublicKey(
          transfer.toPubkey,
          parsePublicKey(expected.transfer.recipient, 'to'),
          'SOL transfer recipient',
        );
        const lamports = BigInt(transfer.lamports);
        if (lamports !== expected.transfer.lamports) {
          throw new Error(
            `signed Solana transaction SOL amount ${lamports.toString()} lamports does not match expected ${expected.transfer.lamports.toString()}`,
          );
        }
        transferCount += 1;
        return;
      }
      throw new Error(
        `signed Solana transaction contains an unsupported system instruction: ${type}`,
      );
    }

    if (
      instruction.programId.equals(TOKEN_PROGRAM_ID) ||
      instruction.programId.equals(TOKEN_2022_PROGRAM_ID)
    ) {
      if (expected.transfer.kind !== 'spl') {
        throw new Error(
          'signed Solana transaction contains an SPL token transfer but a SOL transfer was expected',
        );
      }
      verifySplTransferInstruction(instruction, expected.transfer, feePayer);
      transferCount += 1;
      return;
    }

    throw new Error(
      `signed Solana transaction invokes an unexpected program: ${instruction.programId.toBase58()}`,
    );
  });

  if (transferCount !== 1) {
    throw new Error(
      `signed Solana transaction must contain exactly one transfer instruction; found ${transferCount}`,
    );
  }
  if (expectedNonceAccount && nonceAdvanceCount !== 1) {
    throw new Error('signed Solana transaction is missing the expected durable nonce advance');
  }

  assertSolanaPriorityFeeWithinLimits(decoded, expected);
  return decoded;
}

/**
 * Broadcast a Rust-signed transaction. When the caller supplies what it asked the signer for, the
 * transaction is verified against it first; fee caps are enforced either way.
 */
export async function broadcastSignedSolanaTransaction(
  rpcUrl: string,
  rawTxBase64: string,
  expected?: SolanaSignedTransactionExpectation,
): Promise<string> {
  if (expected) {
    verifySignedSolanaTransaction(rawTxBase64, expected);
  } else {
    assertSolanaPriorityFeeWithinLimits(decodeSignedSolanaTransaction(rawTxBase64), {});
  }
  const connection = createConnection(rpcUrl);
  return connection.sendRawTransaction(Buffer.from(rawTxBase64, 'base64'));
}

export async function waitForSolanaSignatureStatus(
  input: {
    rpcUrl: string;
    signature: string;
    timeoutMs?: number;
    intervalMs?: number;
  },
  deps: {
    now?: () => number;
    sleep?: (ms: number) => Promise<void>;
  } = {},
): Promise<SolanaSignatureStatusResult> {
  const connection = createConnection(input.rpcUrl);
  const timeoutMs = input.timeoutMs ?? 30_000;
  const intervalMs = input.intervalMs ?? 2_000;
  const now = deps.now ?? Date.now;
  const sleep = deps.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
  const started = now();

  while (true) {
    const status = (await connection.getSignatureStatuses([input.signature])).value[0];
    if (status) {
      if (
        status.err ||
        status.confirmationStatus === 'confirmed' ||
        status.confirmationStatus === 'finalized'
      ) {
        return {
          confirmationStatus: status.confirmationStatus ?? null,
          err: status.err,
          slot: status.slot,
          timedOut: false,
        };
      }
    }

    if (now() - started >= timeoutMs) {
      return {
        confirmationStatus: status?.confirmationStatus ?? null,
        err: status?.err ?? null,
        slot: status?.slot ?? 0,
        timedOut: true,
      };
    }

    await sleep(intervalMs);
  }
}
