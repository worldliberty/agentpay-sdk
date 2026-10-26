import { assertSafeRpcUrl } from '@worldlibertyfinancial/agent-config';
import type { Address, Hex, TransactionReceipt } from 'viem';
import * as viem from 'viem';

export const DEFAULT_NATIVE_DECIMALS = 18;
/**
 * Broadcasts must never be replayed by the transport layer: viem's default
 * `retryCount: 3` re-sends `eth_sendRawTransaction` after a timeout, which
 * surfaces as spurious "already known" failures for a transaction that was
 * actually accepted. The broadcast client therefore disables retries and uses
 * an explicit, generous timeout instead.
 */
export const BROADCAST_RPC_TIMEOUT_MS = 30_000;
export const BROADCAST_RPC_TRANSPORT_CONFIG = {
  retryCount: 0,
  timeout: BROADCAST_RPC_TIMEOUT_MS,
} as const;

const ALREADY_KNOWN_TRANSACTION_PATTERN =
  /already known|already_exists|known transaction|transaction already imported|already in (?:the )?mempool/iu;
const MAX_ERROR_CAUSE_DEPTH = 10;

export interface RpcTransportConfig {
  retryCount?: number;
  timeout?: number;
}

export interface RpcClientOptions {
  rpcUrl: string;
  transport?: RpcTransportConfig;
}

export interface RpcClientDeps {
  createPublicClient: typeof viem.createPublicClient;
  http: typeof viem.http;
}

const DEFAULT_RPC_CLIENT_DEPS: RpcClientDeps = {
  createPublicClient: viem.createPublicClient,
  http: viem.http,
};

export interface ChainInfo {
  chainId: number;
  latestBlockNumber: bigint;
}

export interface TokenMetadata {
  name: string | null;
  symbol: string | null;
  decimals: number;
}

export interface AccountSnapshot {
  address: Address;
  chainId: number;
  latestBlockNumber: bigint;
  nonce: number;
  balance: {
    raw: bigint;
    formatted: string;
  };
}

export interface EstimateGasArgs {
  rpcUrl: string;
  from: Address;
  to: Address;
  value?: bigint;
  data?: Hex;
}

function assertNativeDecimals(value: number): number {
  if (!Number.isInteger(value) || value < 0 || value > 255) {
    throw new Error('native decimals must be an integer between 0 and 255');
  }
  return value;
}

export function createRpcClient(
  options: RpcClientOptions,
  deps: RpcClientDeps = DEFAULT_RPC_CLIENT_DEPS,
) {
  const rpcUrl = assertSafeRpcUrl(options.rpcUrl, 'rpcUrl');
  const transport = options.transport ? deps.http(rpcUrl, options.transport) : deps.http(rpcUrl);
  return deps.createPublicClient({ transport });
}

export function createBroadcastRpcClient(
  options: Omit<RpcClientOptions, 'transport'>,
  deps: RpcClientDeps = DEFAULT_RPC_CLIENT_DEPS,
) {
  return createRpcClient({ ...options, transport: BROADCAST_RPC_TRANSPORT_CONFIG }, deps);
}

export async function getChainInfo(rpcUrl: string): Promise<ChainInfo> {
  const client = createRpcClient({ rpcUrl });
  const [chainId, latestBlockNumber] = await Promise.all([
    client.getChainId(),
    client.getBlockNumber(),
  ]);
  return {
    chainId,
    latestBlockNumber,
  };
}

export async function getLatestBlockNumber(rpcUrl: string) {
  const client = createRpcClient({ rpcUrl });
  return client.getBlockNumber();
}

export async function getNativeBalance(
  rpcUrl: string,
  address: Address,
  decimals: number = DEFAULT_NATIVE_DECIMALS,
) {
  const nativeDecimals = assertNativeDecimals(decimals);
  const client = createRpcClient({ rpcUrl });
  const balance = await client.getBalance({ address });
  return {
    raw: balance,
    formatted: viem.formatUnits(balance, nativeDecimals),
  };
}

interface SolanaJsonRpcResponse<T> {
  jsonrpc?: string;
  id?: number;
  result?: T;
  error?: { code?: number; message?: string };
}

async function callSolanaRpc<T>(rpcUrl: string, method: string, params: unknown[]): Promise<T> {
  const url = assertSafeRpcUrl(rpcUrl, 'rpcUrl');
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method,
      params,
    }),
  });
  if (!response.ok) {
    throw new Error(`Solana RPC HTTP ${response.status} ${response.statusText}`);
  }
  const payload = (await response.json()) as SolanaJsonRpcResponse<T>;
  if (payload.error) {
    throw new Error(`Solana RPC error: ${payload.error.message ?? 'unknown error'}`);
  }
  if (payload.result === undefined) {
    throw new Error(`Solana RPC ${method} returned no result`);
  }
  return payload.result;
}

export async function getSolanaNativeBalance(rpcUrl: string, owner: string) {
  const result = await callSolanaRpc<{ value?: number }>(rpcUrl, 'getBalance', [
    owner,
    { commitment: 'confirmed' },
  ]);
  const raw = BigInt(result.value ?? 0);
  return {
    raw,
    formatted: viem.formatUnits(raw, 9),
  };
}

async function readOptionalTokenString(
  rpcUrl: string,
  token: Address,
  functionName: 'name' | 'symbol',
): Promise<string | null> {
  const client = createRpcClient({ rpcUrl });
  try {
    return await client.readContract({
      address: token,
      abi: viem.erc20Abi,
      functionName,
    });
  } catch {
    return null;
  }
}

export async function getTokenMetadata(
  rpcUrl: string,
  token: Address,
  decimals?: number,
): Promise<TokenMetadata> {
  const client = createRpcClient({ rpcUrl });
  const [name, symbol, resolvedDecimals] = await Promise.all([
    readOptionalTokenString(rpcUrl, token, 'name'),
    readOptionalTokenString(rpcUrl, token, 'symbol'),
    decimals !== undefined
      ? Promise.resolve(decimals)
      : client.readContract({
          address: token,
          abi: viem.erc20Abi,
          functionName: 'decimals',
        }),
  ]);

  return {
    name,
    symbol,
    decimals: resolvedDecimals,
  };
}

export async function getTokenBalance(
  rpcUrl: string,
  token: Address,
  owner: Address,
  decimals?: number,
) {
  const client = createRpcClient({ rpcUrl });
  const [balance, metadata] = await Promise.all([
    client.readContract({
      address: token,
      abi: viem.erc20Abi,
      functionName: 'balanceOf',
      args: [owner],
    }),
    getTokenMetadata(rpcUrl, token, decimals),
  ]);

  return {
    raw: balance,
    decimals: metadata.decimals,
    name: metadata.name,
    symbol: metadata.symbol,
    formatted: viem.formatUnits(balance, metadata.decimals),
  };
}

interface SolanaTokenAccountsByOwnerResult {
  value?: Array<{
    account?: {
      data?: {
        parsed?: {
          info?: {
            tokenAmount?: {
              amount?: string;
              decimals?: number;
            };
          };
        };
      };
    };
  }>;
}

export async function getSplTokenBalance(
  rpcUrl: string,
  mint: string,
  owner: string,
  decimals: number,
): Promise<{ raw: bigint; decimals: number; formatted: string }> {
  const result = await callSolanaRpc<SolanaTokenAccountsByOwnerResult>(
    rpcUrl,
    'getTokenAccountsByOwner',
    [owner, { mint }, { encoding: 'jsonParsed', commitment: 'confirmed' }],
  );

  let raw = 0n;
  let resolvedDecimals = decimals;
  for (const entry of result.value ?? []) {
    const tokenAmount = entry.account?.data?.parsed?.info?.tokenAmount;
    if (!tokenAmount?.amount) {
      continue;
    }
    raw += BigInt(tokenAmount.amount);
    if (typeof tokenAmount.decimals === 'number') {
      resolvedDecimals = tokenAmount.decimals;
    }
  }

  return {
    raw,
    decimals: resolvedDecimals,
    formatted: viem.formatUnits(raw, resolvedDecimals),
  };
}

export async function getNonce(rpcUrl: string, address: Address) {
  const client = createRpcClient({ rpcUrl });
  return client.getTransactionCount({ address, blockTag: 'pending' });
}

export async function getAccountSnapshot(
  rpcUrl: string,
  address: Address,
  nativeDecimals: number = DEFAULT_NATIVE_DECIMALS,
): Promise<AccountSnapshot> {
  const [chain, balance, nonce] = await Promise.all([
    getChainInfo(rpcUrl),
    getNativeBalance(rpcUrl, address, nativeDecimals),
    getNonce(rpcUrl, address),
  ]);

  return {
    address,
    chainId: chain.chainId,
    latestBlockNumber: chain.latestBlockNumber,
    nonce,
    balance,
  };
}

export async function estimateFees(rpcUrl: string) {
  const client = createRpcClient({ rpcUrl });
  const fees = await client.estimateFeesPerGas();
  return {
    gasPrice: fees.gasPrice ?? null,
    maxFeePerGas: fees.maxFeePerGas ?? null,
    maxPriorityFeePerGas: fees.maxPriorityFeePerGas ?? null,
  };
}

export async function estimateGas(args: EstimateGasArgs) {
  const client = createRpcClient({ rpcUrl: args.rpcUrl });
  return client.estimateGas({
    account: args.from,
    to: args.to,
    value: args.value ?? 0n,
    data: args.data,
  });
}

export async function getTransactionByHash(rpcUrl: string, hash: Hex) {
  const client = createRpcClient({ rpcUrl });
  return client.getTransaction({ hash });
}

export async function getTransactionReceiptByHash(
  rpcUrl: string,
  hash: Hex,
): Promise<TransactionReceipt> {
  const client = createRpcClient({ rpcUrl });
  return client.getTransactionReceipt({ hash });
}

export async function getCodeAtAddress(rpcUrl: string, address: Address) {
  const client = createRpcClient({ rpcUrl });
  return client.getBytecode({ address });
}

/**
 * Detects node responses that mean "this exact signed transaction is already
 * in the mempool". viem wraps RPC errors in a cause chain, so every level of
 * `message`, `shortMessage`, and `details` is inspected.
 */
export function isAlreadyKnownTransactionError(error: unknown): boolean {
  let current: unknown = error;
  for (let depth = 0; depth < MAX_ERROR_CAUSE_DEPTH && current; depth += 1) {
    if (typeof current !== 'object') {
      return false;
    }
    const candidate = current as {
      cause?: unknown;
      details?: unknown;
      message?: unknown;
      shortMessage?: unknown;
    };
    for (const text of [candidate.details, candidate.shortMessage, candidate.message]) {
      if (typeof text === 'string' && ALREADY_KNOWN_TRANSACTION_PATTERN.test(text)) {
        return true;
      }
    }
    current = candidate.cause;
  }
  return false;
}

export function computeRawTransactionHash(rawTransaction: Hex): Hex {
  return viem.keccak256(rawTransaction);
}

export async function broadcastRawTransaction(rpcUrl: string, rawTransaction: Hex): Promise<Hex> {
  const client = createBroadcastRpcClient({ rpcUrl });
  try {
    return await client.sendRawTransaction({ serializedTransaction: rawTransaction });
  } catch (error) {
    if (isAlreadyKnownTransactionError(error)) {
      return computeRawTransactionHash(rawTransaction);
    }
    throw error;
  }
}

export const TRANSFER_EVENT = viem.parseAbiItem(
  'event Transfer(address indexed from, address indexed to, uint256 value)',
);
