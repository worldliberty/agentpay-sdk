import {
  calculateEpochFee,
  getAssociatedTokenAddressSync,
  getMint,
  getTransferFeeConfig,
  getTransferHook,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
} from '@solana/spl-token';
import {
  Connection,
  NONCE_ACCOUNT_LENGTH,
  NonceAccount,
  PublicKey,
  SystemProgram,
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

export async function resolveSolanaComputeBudget(input: {
  rpcUrl: string;
  defaultComputeUnitLimit: number;
  computeUnitLimit?: string;
  computeUnitPriceMicroLamports?: string;
}): Promise<SolanaComputeBudget> {
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
    return {
      computeUnitLimit: computeUnitLimit.toString(),
      computeUnitPriceMicroLamports: price === null ? null : price.toString(),
    };
  } catch {
    return {
      computeUnitLimit: computeUnitLimit.toString(),
      computeUnitPriceMicroLamports: null,
    };
  }
}

export async function broadcastSignedSolanaTransaction(
  rpcUrl: string,
  rawTxBase64: string,
): Promise<string> {
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
