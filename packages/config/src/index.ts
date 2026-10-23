import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export interface WlfiConfig {
  rpcUrl?: string;
  chainId?: number;
  chainName?: string;
  daemonSocket?: string;
  stateFile?: string;
  rustBinDir?: string;
  agentKeyId?: string;
  agentAuthToken?: string;
  wallet?: WalletProfile;
  chains?: Record<string, ChainProfile>;
  tokens?: Record<string, TokenProfile>;
  /// Tombstones for builtin chain/token seeds the user explicitly removed.
  /// `readConfig` re-merges the builtin defaults on every read, so without
  /// these markers `removeChainProfile`/`removeTokenProfile` would silently
  /// resurrect the removed entries. Token entries use `<token>` for a whole
  /// token or `<token>:<chain>` for a single chain of a builtin token.
  removedBuiltins?: RemovedBuiltinProfiles;
}

export interface RemovedBuiltinProfiles {
  chains?: string[];
  tokens?: string[];
}

export type WalletKeyAlgorithm = 'secp256k1' | 'ed25519';
export type ChainFamily = 'evm' | 'solana';

export interface WalletProfile {
  vaultKeyId?: string;
  algorithm?: WalletKeyAlgorithm;
  vaultPublicKey: string;
  address?: string;
  solanaPublicKey?: string;
  solanaAddress?: string;
  /// Railgun shielded address (`0zk1…`) derived deterministically from the
  /// wallet's secp256k1 vault key. Surfaced by `agentpay config show` and the
  /// `agentpay wallet --json` summary. Populated after a successful
  /// `agentpay admin setup` call; absent until the Phase B derivation lands.
  railgunAddress?: string;
  agentKeyId?: string;
  policyAttachment: string;
  attachedPolicyIds?: string[];
  policyNote?: string;
  networkScope?: string;
  assetScope?: string;
  recipientScope?: string;
}

export interface ChainProfile {
  chainId: number;
  name: string;
  family?: ChainFamily;
  rpcUrl?: string;
}

export interface TokenPolicyProfile {
  perTxAmount?: number;
  dailyAmount?: number;
  weeklyAmount?: number;
  perTxAmountDecimal?: string;
  dailyAmountDecimal?: string;
  weeklyAmountDecimal?: string;
  perTxLimit?: string;
  dailyLimit?: string;
  weeklyLimit?: string;
  maxGasPerChainWei?: string;
  dailyMaxTxCount?: string;
  perTxMaxFeePerGasGwei?: string;
  perTxMaxFeePerGasWei?: string;
  perTxMaxPriorityFeePerGasWei?: string;
  perTxMaxCalldataBytes?: string;
}

export interface TokenDestinationOverrideProfile {
  recipient: string;
  limits: TokenPolicyProfile;
}

export interface TokenManualApprovalProfile {
  priority?: number;
  recipient?: string;
  minAmount?: number;
  maxAmount?: number;
  minAmountDecimal?: string;
  maxAmountDecimal?: string;
  minAmountWei?: string;
  maxAmountWei?: string;
}

export interface TokenChainProfile {
  chainId: number;
  isNative: boolean;
  address?: string;
  decimals: number;
  defaultPolicy?: TokenPolicyProfile;
}

export interface TokenProfile {
  name?: string;
  symbol: string;
  defaultPolicy?: TokenPolicyProfile;
  destinationOverrides?: TokenDestinationOverrideProfile[];
  manualApprovalPolicies?: TokenManualApprovalProfile[];
  chains: Record<string, TokenChainProfile>;
}

export interface TokenChainProfileEntry extends TokenChainProfile {
  key: string;
}

export interface TokenProfileEntry {
  key: string;
  name?: string;
  symbol: string;
  chains: TokenChainProfileEntry[];
}

export const AGENTPAY_DIRNAME = '.agentpay';
export const CONFIG_FILENAME = 'config.json';
export const TELEMETRY_FILENAME = 'telemetry.json';

const PRIVATE_DIR_MODE = 0o700;
const PRIVATE_FILE_MODE = 0o600;
const GROUP_OTHER_WRITE_MODE_MASK = 0o022;
const PRIVATE_FILE_MODE_MASK = 0o077;
const STICKY_BIT_MODE = 0o1000;
const MAX_CONFIG_FILE_BYTES = 256 * 1024;
const DEFAULT_ETH_RPC_URL = 'https://eth.llamarpc.com';
const DEFAULT_BSC_RPC_URL = 'https://bsc.drpc.org';
const DEFAULT_SOLANA_MAINNET_RPC_URL = 'https://api.mainnet-beta.solana.com';
const DEFAULT_SOLANA_DEVNET_RPC_URL = 'https://api.devnet.solana.com';
const DEFAULT_SOLANA_TESTNET_RPC_URL = 'https://api.testnet.solana.com';
const DEFAULT_TEMPO_RPC_URL = 'https://rpc.presto.tempo.xyz';
const DEFAULT_TEMPO_TESTNET_RPC_URL = 'https://rpc.moderato.tempo.xyz';
const DEFAULT_USD1_ADDRESS = '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d';
const DEFAULT_PATHUSD_ADDRESS = '0x20c0000000000000000000000000000000000000';
const DEFAULT_TEMPO_USDCE_ADDRESS = '0x20c000000000000000000000b9537d11c60e8b50';
const DEFAULT_TEMPO_TESTNET_USDCE_ADDRESS = '0x20c0000000000000000000009e8d7eb59b783726';
const DEFAULT_SOLANA_USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const DEFAULT_SOLANA_DEVNET_USDC_MINT = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';

export const BUILTIN_CHAINS: Record<string, ChainProfile> = {
  eth: { chainId: 1, name: 'eth', family: 'evm', rpcUrl: DEFAULT_ETH_RPC_URL },
  ethereum: { chainId: 1, name: 'ethereum', family: 'evm', rpcUrl: DEFAULT_ETH_RPC_URL },
  mainnet: { chainId: 1, name: 'mainnet', family: 'evm', rpcUrl: DEFAULT_ETH_RPC_URL },
  sepolia: { chainId: 11155111, name: 'sepolia', family: 'evm' },
  base: { chainId: 8453, name: 'base', family: 'evm' },
  'base-sepolia': { chainId: 84532, name: 'base-sepolia', family: 'evm' },
  optimism: { chainId: 10, name: 'optimism', family: 'evm' },
  arbitrum: { chainId: 42161, name: 'arbitrum', family: 'evm' },
  polygon: { chainId: 137, name: 'polygon', family: 'evm' },
  bsc: { chainId: 56, name: 'bsc', family: 'evm', rpcUrl: DEFAULT_BSC_RPC_URL },
  solana: {
    chainId: 900000001,
    name: 'solana',
    family: 'solana',
    rpcUrl: DEFAULT_SOLANA_MAINNET_RPC_URL,
  },
  'solana-mainnet': {
    chainId: 900000001,
    name: 'solana-mainnet',
    family: 'solana',
    rpcUrl: DEFAULT_SOLANA_MAINNET_RPC_URL,
  },
  'solana-devnet': {
    chainId: 900000002,
    name: 'solana-devnet',
    family: 'solana',
    rpcUrl: DEFAULT_SOLANA_DEVNET_RPC_URL,
  },
  'solana-testnet': {
    chainId: 900000003,
    name: 'solana-testnet',
    family: 'solana',
    rpcUrl: DEFAULT_SOLANA_TESTNET_RPC_URL,
  },
  tempo: { chainId: 4217, name: 'tempo', family: 'evm', rpcUrl: DEFAULT_TEMPO_RPC_URL },
  'tempo-mainnet': {
    chainId: 4217,
    name: 'tempo-mainnet',
    family: 'evm',
    rpcUrl: DEFAULT_TEMPO_RPC_URL,
  },
  'tempo-testnet': {
    chainId: 42431,
    name: 'tempo-testnet',
    family: 'evm',
    rpcUrl: DEFAULT_TEMPO_TESTNET_RPC_URL,
  },
  moderato: {
    chainId: 42431,
    name: 'moderato',
    family: 'evm',
    rpcUrl: DEFAULT_TEMPO_TESTNET_RPC_URL,
  },
  'tempo-moderato': {
    chainId: 42431,
    name: 'tempo-moderato',
    family: 'evm',
    rpcUrl: DEFAULT_TEMPO_TESTNET_RPC_URL,
  },
};

export const BUILTIN_TOKENS: Record<string, TokenProfile> = {
  bnb: {
    name: 'BNB',
    symbol: 'BNB',
    defaultPolicy: defaultTokenPolicy('0.01', '0.2', '1.4'),
    chains: {
      bsc: {
        chainId: 56,
        isNative: true,
        decimals: 18,
        defaultPolicy: defaultTokenPolicy('0.01', '0.2', '1.4'),
      },
    },
  },
  eth: {
    symbol: 'ETH',
    chains: {
      ethereum: { chainId: 1, isNative: true, decimals: 18 },
      sepolia: { chainId: 11155111, isNative: true, decimals: 18 },
      base: { chainId: 8453, isNative: true, decimals: 18 },
      'base-sepolia': { chainId: 84532, isNative: true, decimals: 18 },
      optimism: { chainId: 10, isNative: true, decimals: 18 },
      arbitrum: { chainId: 42161, isNative: true, decimals: 18 },
    },
  },
  sol: {
    name: 'Solana',
    symbol: 'SOL',
    defaultPolicy: defaultTokenPolicy('0.05', '1', '7'),
    chains: {
      'solana-mainnet': {
        chainId: 900000001,
        isNative: true,
        decimals: 9,
        defaultPolicy: defaultTokenPolicy('0.05', '1', '7'),
      },
      'solana-devnet': {
        chainId: 900000002,
        isNative: true,
        decimals: 9,
        defaultPolicy: defaultTokenPolicy('0.05', '1', '7'),
      },
      'solana-testnet': {
        chainId: 900000003,
        isNative: true,
        decimals: 9,
        defaultPolicy: defaultTokenPolicy('0.05', '1', '7'),
      },
    },
  },
  usd: {
    name: 'USD',
    symbol: 'USD',
    defaultPolicy: defaultTokenPolicy('10', '100', '700'),
    chains: {
      tempo: {
        chainId: 4217,
        isNative: true,
        decimals: 6,
        defaultPolicy: defaultTokenPolicy('10', '100', '700'),
      },
    },
  },
  usd1: {
    name: 'USD1',
    symbol: 'USD1',
    defaultPolicy: defaultTokenPolicy('10', '100', '700'),
    chains: {
      eth: {
        chainId: 1,
        isNative: false,
        address: DEFAULT_USD1_ADDRESS,
        decimals: 18,
        defaultPolicy: defaultTokenPolicy('10', '100', '700'),
      },
      bsc: {
        chainId: 56,
        isNative: false,
        address: DEFAULT_USD1_ADDRESS,
        decimals: 18,
        defaultPolicy: defaultTokenPolicy('10', '100', '700'),
      },
      tempo: {
        chainId: 4217,
        isNative: false,
        address: '0x111111d2bf19e43C34263401e0CAd979eD1cdb61',
        decimals: 18,
        defaultPolicy: defaultTokenPolicy('10', '100', '700'),
      },
    },
  },
  pathusd: {
    name: 'PATH/USD',
    symbol: 'PATH/USD',
    defaultPolicy: defaultTokenPolicy('10', '100', '700'),
    chains: {
      tempo: {
        chainId: 4217,
        isNative: false,
        address: DEFAULT_PATHUSD_ADDRESS,
        decimals: 6,
        defaultPolicy: defaultTokenPolicy('10', '100', '700'),
      },
      'tempo-testnet': {
        chainId: 42431,
        isNative: false,
        address: DEFAULT_PATHUSD_ADDRESS,
        decimals: 6,
        defaultPolicy: defaultTokenPolicy('10', '100', '700'),
      },
    },
  },
  'usdc.e': {
    name: 'Bridged USDC (Stargate)',
    symbol: 'USDC.e',
    defaultPolicy: defaultTokenPolicy('10', '100', '700'),
    chains: {
      tempo: {
        chainId: 4217,
        isNative: false,
        address: DEFAULT_TEMPO_USDCE_ADDRESS,
        decimals: 6,
        defaultPolicy: defaultTokenPolicy('10', '100', '700'),
      },
      'tempo-testnet': {
        chainId: 42431,
        isNative: false,
        address: DEFAULT_TEMPO_TESTNET_USDCE_ADDRESS,
        decimals: 6,
        defaultPolicy: defaultTokenPolicy('10', '100', '700'),
      },
    },
  },
  usdc: {
    name: 'USDC',
    symbol: 'USDC',
    defaultPolicy: defaultTokenPolicy('10', '100', '700'),
    chains: {
      'solana-mainnet': {
        chainId: 900000001,
        isNative: false,
        address: DEFAULT_SOLANA_USDC_MINT,
        decimals: 6,
        defaultPolicy: defaultTokenPolicy('10', '100', '700'),
      },
      'solana-devnet': {
        chainId: 900000002,
        isNative: false,
        address: DEFAULT_SOLANA_DEVNET_USDC_MINT,
        decimals: 6,
        defaultPolicy: defaultTokenPolicy('10', '100', '700'),
      },
    },
  },
};

function defaultTokenPolicy(
  perTxAmountDecimal: string,
  dailyAmountDecimal: string,
  weeklyAmountDecimal: string,
): TokenPolicyProfile {
  return {
    perTxAmountDecimal,
    dailyAmountDecimal,
    weeklyAmountDecimal,
  };
}

/**
 * Builtin chains that are seeded into every config, keyed by their `BUILTIN_CHAINS`
 * key with the operator-facing display name. Everything else about the seeded
 * profile (chainId, family, rpcUrl) is derived from `BUILTIN_CHAINS` so the two
 * tables cannot drift apart.
 */
const DEFAULT_SEEDED_CHAIN_NAMES: Record<string, string> = {
  eth: 'ETH',
  bsc: 'BSC',
  tempo: 'Tempo',
  'tempo-testnet': 'Tempo Testnet (Moderato)',
  'solana-mainnet': 'Solana',
  'solana-devnet': 'Solana Devnet',
  'solana-testnet': 'Solana Testnet',
};

function defaultChainProfiles(): Record<string, ChainProfile> {
  const profiles: Record<string, ChainProfile> = {};
  for (const [key, name] of Object.entries(DEFAULT_SEEDED_CHAIN_NAMES)) {
    const builtin = BUILTIN_CHAINS[key];
    if (!builtin) {
      throw new Error(
        `builtin chain '${key}' is missing; seeded chains must exist in BUILTIN_CHAINS`,
      );
    }
    profiles[key] = {
      chainId: builtin.chainId,
      name,
      family: builtin.family,
      rpcUrl: builtin.rpcUrl,
    };
  }
  return profiles;
}

function seededChainKeyForChainId(chainId: number): string | undefined {
  return Object.keys(DEFAULT_SEEDED_CHAIN_NAMES).find(
    (key) => BUILTIN_CHAINS[key]?.chainId === chainId,
  );
}

/**
 * Seeded token profiles are derived from `BUILTIN_TOKENS`: every builtin token
 * chain whose chainId belongs to a seeded chain is included, keyed by the seeded
 * chain key (so the builtin `ethereum` entry seeds as `eth`). Builtin spending
 * policies are intentionally dropped so seeded assets start unrestricted.
 */
function defaultTokenProfiles(): Record<string, TokenProfile> {
  const profiles: Record<string, TokenProfile> = {};
  for (const [tokenKey, builtin] of Object.entries(BUILTIN_TOKENS)) {
    const chains: Record<string, TokenChainProfile> = {};
    for (const chainProfile of Object.values(builtin.chains ?? {})) {
      const seededChainKey = seededChainKeyForChainId(chainProfile.chainId);
      if (!seededChainKey || chains[seededChainKey]) {
        continue;
      }
      chains[seededChainKey] = {
        chainId: chainProfile.chainId,
        isNative: chainProfile.isNative,
        ...(chainProfile.address ? { address: chainProfile.address } : {}),
        decimals: chainProfile.decimals,
      };
    }
    if (Object.keys(chains).length === 0) {
      continue;
    }
    profiles[tokenKey] = {
      name: builtin.name ?? builtin.symbol,
      symbol: builtin.symbol,
      destinationOverrides: [],
      manualApprovalPolicies: [],
      chains,
    };
  }
  return profiles;
}

const REMOVED_BUILTIN_TOKEN_CHAIN_SEPARATOR = ':';

interface NormalizedRemovedBuiltinProfiles {
  chains: string[];
  tokens: string[];
}

function normalizeRemovedBuiltinList(value: unknown, label: string): string[] {
  if (value == null) {
    return [];
  }
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
    throw new Error(`config field ${label} must be an array of strings`);
  }
  return [
    ...new Set(
      (value as string[]).map((entry) => entry.trim().toLowerCase()).filter((entry) => entry),
    ),
  ].sort();
}

function normalizeRemovedBuiltins(
  value: RemovedBuiltinProfiles | null | undefined,
): NormalizedRemovedBuiltinProfiles {
  if (value == null) {
    return { chains: [], tokens: [] };
  }
  if (!isPlainObject(value)) {
    throw new Error('config field removedBuiltins must be an object');
  }
  return {
    chains: normalizeRemovedBuiltinList(value.chains, 'removedBuiltins.chains'),
    tokens: normalizeRemovedBuiltinList(value.tokens, 'removedBuiltins.tokens'),
  };
}

function compactRemovedBuiltins(
  value: RemovedBuiltinProfiles | null | undefined,
): RemovedBuiltinProfiles | undefined {
  const normalized = normalizeRemovedBuiltins(value);
  if (normalized.chains.length === 0 && normalized.tokens.length === 0) {
    return undefined;
  }
  return {
    ...(normalized.chains.length > 0 ? { chains: normalized.chains } : {}),
    ...(normalized.tokens.length > 0 ? { tokens: normalized.tokens } : {}),
  };
}

function removedBuiltinTokenChainEntry(tokenKey: string, chainKey: string): string {
  return `${tokenKey}${REMOVED_BUILTIN_TOKEN_CHAIN_SEPARATOR}${chainKey}`;
}

function withRemovedBuiltins(
  existing: RemovedBuiltinProfiles | undefined,
  additions: Partial<NormalizedRemovedBuiltinProfiles>,
): RemovedBuiltinProfiles | undefined {
  const normalized = normalizeRemovedBuiltins(existing);
  return compactRemovedBuiltins({
    chains: [...normalized.chains, ...(additions.chains ?? [])],
    tokens: [...normalized.tokens, ...(additions.tokens ?? [])],
  });
}

function withoutRemovedBuiltins(
  existing: RemovedBuiltinProfiles | undefined,
  removals: { chains?: (entry: string) => boolean; tokens?: (entry: string) => boolean },
): RemovedBuiltinProfiles | undefined {
  const normalized = normalizeRemovedBuiltins(existing);
  return compactRemovedBuiltins({
    chains: normalized.chains.filter((entry) => !removals.chains?.(entry)),
    tokens: normalized.tokens.filter((entry) => !removals.tokens?.(entry)),
  });
}

function seededChainRemovals(chainKey: string): Partial<NormalizedRemovedBuiltinProfiles> {
  return Object.hasOwn(defaultChainProfiles(), chainKey) ? { chains: [chainKey] } : {};
}

function seededTokenRemovals(
  tokenKey: string,
  chainKey?: string,
): Partial<NormalizedRemovedBuiltinProfiles> {
  const seeded = defaultTokenProfiles()[tokenKey];
  if (!seeded) {
    return {};
  }
  if (chainKey === undefined) {
    return { tokens: [tokenKey] };
  }
  return Object.hasOwn(seeded.chains ?? {}, chainKey)
    ? { tokens: [removedBuiltinTokenChainEntry(tokenKey, chainKey)] }
    : {};
}

function mergeDefaultChainProfiles(
  profiles: Record<string, ChainProfile> | undefined,
  removed: NormalizedRemovedBuiltinProfiles = { chains: [], tokens: [] },
): Record<string, ChainProfile> {
  const seeded = Object.fromEntries(
    Object.entries(defaultChainProfiles()).filter(([key]) => !removed.chains.includes(key)),
  );
  return {
    ...seeded,
    ...(profiles ?? {}),
  };
}

function mergeDefaultTokenProfiles(
  profiles: Record<string, TokenProfile> | undefined,
  removed: NormalizedRemovedBuiltinProfiles = { chains: [], tokens: [] },
): Record<string, TokenProfile> {
  const merged: Record<string, TokenProfile> = {};
  for (const [key, profile] of Object.entries(defaultTokenProfiles())) {
    if (removed.tokens.includes(key)) {
      continue;
    }
    const chains = Object.fromEntries(
      Object.entries(profile.chains ?? {}).filter(
        ([chainKey]) => !removed.tokens.includes(removedBuiltinTokenChainEntry(key, chainKey)),
      ),
    );
    if (Object.keys(chains).length === 0) {
      continue;
    }
    merged[key] = {
      ...profile,
      destinationOverrides: [...(profile.destinationOverrides ?? [])],
      manualApprovalPolicies: [...(profile.manualApprovalPolicies ?? [])],
      chains,
    };
  }

  for (const [key, profile] of Object.entries(profiles ?? {})) {
    const existing = merged[key];
    if (!existing) {
      merged[key] = profile;
      continue;
    }

    merged[key] = {
      name: profile.name ?? existing.name,
      symbol: profile.symbol,
      defaultPolicy: profile.defaultPolicy ?? existing.defaultPolicy,
      destinationOverrides: profile.destinationOverrides ?? existing.destinationOverrides,
      manualApprovalPolicies: profile.manualApprovalPolicies ?? existing.manualApprovalPolicies,
      chains: {
        ...(existing.chains ?? {}),
        ...(profile.chains ?? {}),
      },
    };
  }

  return merged;
}

function normalizeLoopbackHostname(hostname: string): string {
  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    return hostname.slice(1, -1).toLowerCase();
  }

  return hostname.toLowerCase();
}

function isIpv4Loopback(hostname: string): boolean {
  const parts = hostname.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^\d+$/u.test(part))) {
    return false;
  }

  const octets = parts.map((part) => Number(part));
  if (octets.some((octet) => octet < 0 || octet > 255)) {
    return false;
  }

  return octets[0] === 127;
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = normalizeLoopbackHostname(hostname);
  return (
    normalized === 'localhost' ||
    normalized.endsWith('.localhost') ||
    normalized === '::1' ||
    isIpv4Loopback(normalized)
  );
}

export function assertSafeRpcUrl(value: string, label = 'rpcUrl'): string {
  const normalized = value.trim();
  if (!normalized) {
    throw new Error(`${label} is required`);
  }

  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error(`${label} must be a valid http(s) URL`);
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error(`${label} must use https or localhost http`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`${label} must not include embedded credentials`);
  }
  if (!parsed.hostname) {
    throw new Error(`${label} must include a hostname`);
  }
  if (parsed.protocol === 'http:' && !isLoopbackHostname(parsed.hostname)) {
    throw new Error(`${label} must use https unless it targets localhost or a loopback address`);
  }

  return normalized;
}

function normalizeOptionalRpcUrl(
  value: string | null | undefined,
  label = 'rpcUrl',
  options: { validate?: boolean } = {},
): string | undefined {
  const normalized = value?.trim();
  if (!normalized) {
    return undefined;
  }
  return options.validate ? assertSafeRpcUrl(normalized, label) : normalized;
}

const ADDRESS_PATTERN = /^0x[a-f0-9]{40}$/iu;
const SOLANA_ADDRESS_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/u;
const SOLANA_PUBLIC_KEY_HEX_PATTERN = /^(?:0x)?[0-9a-f]{64}$/iu;
const SOLANA_CHAIN_IDS = new Set([900000001, 900000002, 900000003]);

function assertValidEvmAddress(value: string, label: string): string {
  const normalized = assertString(value, label).trim();
  if (!ADDRESS_PATTERN.test(normalized)) {
    throw new Error(`${label} must be a valid EVM address`);
  }
  return normalized;
}

function assertOptionalSolanaPublicKeyHex(
  value: string | null | undefined,
  label: string,
): string | undefined {
  const normalized = assertOptionalTrimmedString(value, label);
  if (!normalized) {
    return undefined;
  }
  if (!SOLANA_PUBLIC_KEY_HEX_PATTERN.test(normalized)) {
    throw new Error(`${label} must be a 32-byte hex public key`);
  }
  return normalized;
}

function assertOptionalSolanaAddress(
  value: string | null | undefined,
  label: string,
): string | undefined {
  const normalized = assertOptionalTrimmedString(value, label);
  if (!normalized) {
    return undefined;
  }
  if (!SOLANA_ADDRESS_PATTERN.test(normalized)) {
    throw new Error(`${label} must be a valid Solana address`);
  }
  return normalized;
}

// Bounds chosen to match `RailgunAddress::from_str` in vault-domain — keep
// the two sides in lockstep when the encoding evolves.
const RAILGUN_ADDRESS_PREFIX = '0zk1';
const RAILGUN_ADDRESS_MIN_LENGTH = 32;
const RAILGUN_ADDRESS_MAX_LENGTH = 256;
const RAILGUN_ADDRESS_CHAR_PATTERN = /^[A-Za-z0-9_]+$/u;

function assertOptionalRailgunAddress(
  value: string | null | undefined,
  label: string,
): string | undefined {
  const normalized = assertOptionalTrimmedString(value, label);
  if (!normalized) {
    return undefined;
  }
  if (!normalized.startsWith(RAILGUN_ADDRESS_PREFIX)) {
    throw new Error(`${label} must start with "${RAILGUN_ADDRESS_PREFIX}"`);
  }
  if (
    normalized.length < RAILGUN_ADDRESS_MIN_LENGTH ||
    normalized.length > RAILGUN_ADDRESS_MAX_LENGTH
  ) {
    throw new Error(
      `${label} length ${normalized.length} is outside the supported range (${RAILGUN_ADDRESS_MIN_LENGTH}-${RAILGUN_ADDRESS_MAX_LENGTH})`,
    );
  }
  if (!RAILGUN_ADDRESS_CHAR_PATTERN.test(normalized)) {
    throw new Error(`${label} contains characters outside the supported alphanumeric/_ set`);
  }
  return normalized;
}

function assertValidSolanaAddress(value: string, label: string): string {
  const normalized = assertString(value, label).trim();
  if (!SOLANA_ADDRESS_PATTERN.test(normalized)) {
    throw new Error(`${label} must be a valid Solana address`);
  }
  return normalized;
}

function assertValidEvmOrSolanaAddress(value: string, label: string): string {
  const normalized = assertString(value, label).trim();
  if (ADDRESS_PATTERN.test(normalized) || SOLANA_ADDRESS_PATTERN.test(normalized)) {
    return normalized;
  }
  throw new Error(`${label} must be a valid EVM or Solana address`);
}

function normalizeChainFamily(
  value: ChainProfile['family'] | undefined,
  chainId: number,
): ChainFamily {
  if (value === 'evm' || value === 'solana') {
    return value;
  }
  if (value !== undefined) {
    throw new Error(`chain family must be one of: evm, solana`);
  }
  return SOLANA_CHAIN_IDS.has(chainId) ? 'solana' : 'evm';
}

function assertPositiveSafeInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return value;
}

function assertTokenDecimals(value: number, label: string): number {
  if (!Number.isInteger(value) || value < 0 || value > 255) {
    throw new Error(`${label} must be an integer between 0 and 255`);
  }
  return value;
}

function assertOptionalTokenAmount(
  value: number | null | undefined,
  label: string,
): number | undefined {
  if (value == null) {
    return undefined;
  }
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new Error(`${label} must be a positive finite number`);
  }
  return value;
}

function assertString(value: unknown, label: string): string {
  if (typeof value !== 'string') {
    throw new Error(`${label} must be a string`);
  }
  return value;
}

function assertOptionalArray<T>(value: T[] | null | undefined, label: string): T[] {
  if (value == null) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array`);
  }
  return value;
}

function assertOptionalTrimmedString(
  value: string | null | undefined,
  label: string,
): string | undefined {
  if (value == null) {
    return undefined;
  }
  const normalized = assertString(value, label).trim();
  if (!normalized) {
    return undefined;
  }
  return normalized;
}

function assertRequiredTrimmedString(value: string | null | undefined, label: string): string {
  const normalized = assertOptionalTrimmedString(value, label);
  if (!normalized) {
    throw new Error(`${label} is required`);
  }
  return normalized;
}

function assertOptionalStringArray(
  value: string[] | null | undefined,
  label: string,
): string[] | undefined {
  if (value == null) {
    return undefined;
  }
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
    throw new Error(`${label} must be an array of strings`);
  }
  const normalized = value.map((entry) => entry.trim()).filter((entry) => entry.length > 0);
  return normalized.length > 0 ? normalized : undefined;
}

function normalizeWalletProfile(
  profile: WalletProfile | null | undefined,
): WalletProfile | undefined {
  if (profile == null) {
    return undefined;
  }

  const algorithm = normalizeWalletKeyAlgorithm(profile.algorithm);

  return {
    vaultKeyId: assertOptionalTrimmedString(profile.vaultKeyId, 'wallet.vaultKeyId'),
    algorithm,
    vaultPublicKey: assertRequiredTrimmedString(profile.vaultPublicKey, 'wallet.vaultPublicKey'),
    address: profile.address
      ? algorithm === 'ed25519'
        ? assertRequiredTrimmedString(profile.address, 'wallet.address')
        : assertValidEvmAddress(profile.address, 'wallet.address')
      : undefined,
    solanaPublicKey: assertOptionalSolanaPublicKeyHex(
      profile.solanaPublicKey,
      'wallet.solanaPublicKey',
    ),
    solanaAddress: assertOptionalSolanaAddress(profile.solanaAddress, 'wallet.solanaAddress'),
    railgunAddress: assertOptionalRailgunAddress(profile.railgunAddress, 'wallet.railgunAddress'),
    agentKeyId: assertOptionalTrimmedString(profile.agentKeyId, 'wallet.agentKeyId'),
    policyAttachment: assertRequiredTrimmedString(
      profile.policyAttachment,
      'wallet.policyAttachment',
    ),
    attachedPolicyIds: assertOptionalStringArray(
      profile.attachedPolicyIds,
      'wallet.attachedPolicyIds',
    ),
    policyNote: assertOptionalTrimmedString(profile.policyNote, 'wallet.policyNote'),
    networkScope: assertOptionalTrimmedString(profile.networkScope, 'wallet.networkScope'),
    assetScope: assertOptionalTrimmedString(profile.assetScope, 'wallet.assetScope'),
    recipientScope: assertOptionalTrimmedString(profile.recipientScope, 'wallet.recipientScope'),
  };
}

function normalizeWalletKeyAlgorithm(
  value: WalletProfile['algorithm'] | undefined,
): WalletKeyAlgorithm {
  if (value === undefined) {
    return 'secp256k1';
  }
  if (value === 'secp256k1' || value === 'ed25519') {
    return value;
  }
  throw new Error(`wallet.algorithm must be one of: secp256k1, ed25519`);
}

function normalizeTokenPolicyProfile(
  tokenKey: string,
  chainKey: string,
  policy: TokenPolicyProfile | undefined,
) {
  if (!policy) {
    return undefined;
  }
  return {
    perTxAmount: assertOptionalTokenAmount(
      policy.perTxAmount,
      `token '${tokenKey}' chain '${chainKey}' perTxAmount`,
    ),
    dailyAmount: assertOptionalTokenAmount(
      policy.dailyAmount,
      `token '${tokenKey}' chain '${chainKey}' dailyAmount`,
    ),
    weeklyAmount: assertOptionalTokenAmount(
      policy.weeklyAmount,
      `token '${tokenKey}' chain '${chainKey}' weeklyAmount`,
    ),
    perTxAmountDecimal: assertOptionalTrimmedString(
      policy.perTxAmountDecimal,
      `token '${tokenKey}' chain '${chainKey}' perTxAmountDecimal`,
    ),
    dailyAmountDecimal: assertOptionalTrimmedString(
      policy.dailyAmountDecimal,
      `token '${tokenKey}' chain '${chainKey}' dailyAmountDecimal`,
    ),
    weeklyAmountDecimal: assertOptionalTrimmedString(
      policy.weeklyAmountDecimal,
      `token '${tokenKey}' chain '${chainKey}' weeklyAmountDecimal`,
    ),
    perTxLimit: assertOptionalTrimmedString(
      policy.perTxLimit,
      `token '${tokenKey}' chain '${chainKey}' perTxLimit`,
    ),
    dailyLimit: assertOptionalTrimmedString(
      policy.dailyLimit,
      `token '${tokenKey}' chain '${chainKey}' dailyLimit`,
    ),
    weeklyLimit: assertOptionalTrimmedString(
      policy.weeklyLimit,
      `token '${tokenKey}' chain '${chainKey}' weeklyLimit`,
    ),
    maxGasPerChainWei: assertOptionalTrimmedString(
      policy.maxGasPerChainWei,
      `token '${tokenKey}' chain '${chainKey}' maxGasPerChainWei`,
    ),
    dailyMaxTxCount: assertOptionalTrimmedString(
      policy.dailyMaxTxCount,
      `token '${tokenKey}' chain '${chainKey}' dailyMaxTxCount`,
    ),
    perTxMaxFeePerGasGwei: assertOptionalTrimmedString(
      policy.perTxMaxFeePerGasGwei,
      `token '${tokenKey}' chain '${chainKey}' perTxMaxFeePerGasGwei`,
    ),
    perTxMaxFeePerGasWei: assertOptionalTrimmedString(
      policy.perTxMaxFeePerGasWei,
      `token '${tokenKey}' chain '${chainKey}' perTxMaxFeePerGasWei`,
    ),
    perTxMaxPriorityFeePerGasWei: assertOptionalTrimmedString(
      policy.perTxMaxPriorityFeePerGasWei,
      `token '${tokenKey}' chain '${chainKey}' perTxMaxPriorityFeePerGasWei`,
    ),
    perTxMaxCalldataBytes: assertOptionalTrimmedString(
      policy.perTxMaxCalldataBytes,
      `token '${tokenKey}' chain '${chainKey}' perTxMaxCalldataBytes`,
    ),
  } satisfies TokenPolicyProfile;
}

function normalizeTokenDestinationOverrideProfile(
  tokenKey: string,
  profile: TokenDestinationOverrideProfile,
): TokenDestinationOverrideProfile {
  const recipient = assertValidEvmAddress(
    profile.recipient,
    `token '${tokenKey}' destination override recipient`,
  );
  return {
    recipient,
    limits: normalizeTokenPolicyProfile(tokenKey, 'override', profile.limits) ?? {},
  };
}

function normalizeTokenManualApprovalProfile(
  tokenKey: string,
  profile: TokenManualApprovalProfile,
): TokenManualApprovalProfile {
  return {
    priority:
      profile.priority === undefined
        ? undefined
        : assertPositiveSafeInteger(
            profile.priority,
            `token '${tokenKey}' manual approval priority`,
          ),
    recipient: profile.recipient
      ? assertValidEvmOrSolanaAddress(
          profile.recipient,
          `token '${tokenKey}' manual approval recipient`,
        )
      : undefined,
    minAmount: assertOptionalTokenAmount(
      profile.minAmount,
      `token '${tokenKey}' manual approval minAmount`,
    ),
    maxAmount: assertOptionalTokenAmount(
      profile.maxAmount,
      `token '${tokenKey}' manual approval maxAmount`,
    ),
    minAmountDecimal: assertOptionalTrimmedString(
      profile.minAmountDecimal,
      `token '${tokenKey}' manual approval minAmountDecimal`,
    ),
    maxAmountDecimal: assertOptionalTrimmedString(
      profile.maxAmountDecimal,
      `token '${tokenKey}' manual approval maxAmountDecimal`,
    ),
    minAmountWei: assertOptionalTrimmedString(
      profile.minAmountWei,
      `token '${tokenKey}' manual approval minAmountWei`,
    ),
    maxAmountWei: assertOptionalTrimmedString(
      profile.maxAmountWei,
      `token '${tokenKey}' manual approval maxAmountWei`,
    ),
  };
}

function normalizeTokenChainProfile(
  tokenKey: string,
  chainKey: string,
  profile: TokenChainProfile,
): TokenChainProfile {
  const normalizedChainKey = chainKey.trim().toLowerCase();
  if (!normalizedChainKey) {
    throw new Error(`token '${tokenKey}' chain key is required`);
  }

  const normalized: TokenChainProfile = {
    chainId: assertPositiveSafeInteger(
      profile.chainId,
      `token '${tokenKey}' chain '${normalizedChainKey}' chainId`,
    ),
    isNative: Boolean(profile.isNative),
    decimals: assertTokenDecimals(
      profile.decimals,
      `token '${tokenKey}' chain '${normalizedChainKey}' decimals`,
    ),
    defaultPolicy: normalizeTokenPolicyProfile(tokenKey, normalizedChainKey, profile.defaultPolicy),
  };

  if (normalized.isNative) {
    if (profile.address?.trim()) {
      throw new Error(
        `token '${tokenKey}' chain '${normalizedChainKey}' must not set address when isNative=true`,
      );
    }
  } else {
    const addressLabel = `token '${tokenKey}' chain '${normalizedChainKey}' address`;
    normalized.address = SOLANA_CHAIN_IDS.has(normalized.chainId)
      ? assertValidSolanaAddress(profile.address ?? '', addressLabel)
      : assertValidEvmAddress(profile.address ?? '', addressLabel);
  }

  return normalized;
}

function normalizeTokenProfile(key: string, profile: TokenProfile): TokenProfile {
  const normalizedKey = key.trim().toLowerCase();
  if (!normalizedKey) {
    throw new Error('token profile key is required');
  }

  if (!isPlainObject(profile)) {
    throw new Error(`token profile '${normalizedKey}' must be an object`);
  }
  const symbol = assertRequiredTrimmedString(
    profile.symbol,
    `token profile '${normalizedKey}' symbol`,
  );
  const name = assertOptionalTrimmedString(profile.name, `token profile '${normalizedKey}' name`);
  if (profile.chains != null && !isPlainObject(profile.chains)) {
    throw new Error(`token profile '${normalizedKey}' chains must be an object`);
  }

  const normalizedChains: Record<string, TokenChainProfile> = {};
  for (const [chainKey, chainProfile] of Object.entries(profile.chains ?? {})) {
    const normalizedChainKey = chainKey.trim().toLowerCase();
    if (!normalizedChainKey) {
      throw new Error(`token profile '${normalizedKey}' contains an empty chain key`);
    }
    if (!isPlainObject(chainProfile)) {
      throw new Error(
        `token profile '${normalizedKey}' chain '${normalizedChainKey}' must be an object`,
      );
    }
    normalizedChains[normalizedChainKey] = normalizeTokenChainProfile(
      normalizedKey,
      normalizedChainKey,
      chainProfile,
    );
  }

  return {
    name,
    symbol,
    defaultPolicy: normalizeTokenPolicyProfile(normalizedKey, 'default', profile.defaultPolicy),
    destinationOverrides: assertOptionalArray(
      profile.destinationOverrides,
      `token profile '${normalizedKey}' destinationOverrides`,
    ).map((item) => normalizeTokenDestinationOverrideProfile(normalizedKey, item)),
    manualApprovalPolicies: assertOptionalArray(
      profile.manualApprovalPolicies,
      `token profile '${normalizedKey}' manualApprovalPolicies`,
    ).map((item) => normalizeTokenManualApprovalProfile(normalizedKey, item)),
    chains: normalizedChains,
  };
}

function normalizeChainProfileEntry(
  key: string,
  profile: ChainProfile,
  options: { validateRpcUrl?: boolean } = {},
): ChainProfile {
  const normalizedKey = key.trim().toLowerCase();
  if (!normalizedKey) {
    throw new Error('chain profile key is required');
  }

  const name = profile.name?.trim() || normalizedKey;
  const chainId = assertPositiveSafeInteger(
    profile.chainId,
    `chain profile '${normalizedKey}' chainId`,
  );
  return {
    chainId,
    name,
    family: normalizeChainFamily(profile.family, chainId),
    rpcUrl: normalizeOptionalRpcUrl(profile.rpcUrl, `chain profile '${normalizedKey}' rpcUrl`, {
      validate: options.validateRpcUrl,
    }),
  };
}

function normalizeChainProfiles(
  profiles: Record<string, ChainProfile> | undefined,
): Record<string, ChainProfile> {
  const normalized: Record<string, ChainProfile> = {};
  for (const [key, profile] of Object.entries(profiles ?? {})) {
    const normalizedKey = key.trim().toLowerCase();
    if (!normalizedKey) {
      throw new Error('chain profile key is required');
    }
    normalized[normalizedKey] = normalizeChainProfileEntry(normalizedKey, profile);
  }
  return normalized;
}

function normalizeTokenProfiles(
  profiles: Record<string, TokenProfile> | undefined,
): Record<string, TokenProfile> {
  const normalized: Record<string, TokenProfile> = {};
  for (const [key, profile] of Object.entries(profiles ?? {})) {
    const normalizedKey = key.trim().toLowerCase();
    if (!normalizedKey) {
      throw new Error('token profile key is required');
    }
    normalized[normalizedKey] = normalizeTokenProfile(normalizedKey, profile);
  }
  return normalized;
}

function normalizePath(targetPath: string): string {
  return path.resolve(targetPath);
}

function requirePathValue(targetPath: string, label: string): string {
  const normalized = targetPath.trim();
  if (!normalized) {
    throw new Error(`${label} is required`);
  }

  return normalizePath(normalized);
}

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

function readLstatAllowInaccessible(targetPath: string): fs.Stats | 'inaccessible' | null {
  try {
    return fs.lstatSync(targetPath);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      return null;
    }
    if (code === 'EACCES' || code === 'EPERM') {
      return 'inaccessible';
    }
    throw error;
  }
}

function isStableRootOwnedSymlink(stats: fs.Stats, targetPath: string): boolean {
  if (process.platform === 'win32' || typeof stats.uid !== 'number' || stats.uid !== 0) {
    return false;
  }

  const parentPath = path.dirname(targetPath);
  const parentStats = readLstat(parentPath);
  return Boolean(
    parentStats?.isDirectory() &&
      typeof parentStats.uid === 'number' &&
      parentStats.uid === 0 &&
      (parentStats.mode & GROUP_OTHER_WRITE_MODE_MASK) === 0,
  );
}

function assertNoSymlinkAncestorDirectories(targetPath: string, label: string): void {
  const normalized = normalizePath(targetPath);
  const parent = path.dirname(normalized);
  if (parent === normalized) {
    return;
  }

  const { root } = path.parse(parent);
  const relativeParent = parent.slice(root.length);
  if (!relativeParent) {
    return;
  }

  let currentPath = root;
  for (const segment of relativeParent.split(path.sep).filter(Boolean)) {
    currentPath = path.join(currentPath, segment);
    const stats = readLstat(currentPath);
    if (!stats) {
      break;
    }
    if (stats.isSymbolicLink()) {
      if (isStableRootOwnedSymlink(stats, currentPath)) {
        continue;
      }
      throw new Error(`${label} '${normalized}' must not traverse symlinked ancestor directories`);
    }
  }
}

function findNearestExistingPath(targetPath: string): { path: string; stats: fs.Stats } {
  let currentPath = normalizePath(targetPath);

  while (true) {
    const stats = readLstat(currentPath);
    if (stats) {
      return {
        path: currentPath,
        stats,
      };
    }

    const parentPath = path.dirname(currentPath);
    if (parentPath === currentPath) {
      throw new Error(`No existing ancestor directory found for '${targetPath}'`);
    }

    currentPath = parentPath;
  }
}

export function allowedOwnerUids(): Set<number> {
  const allowed = new Set<number>();
  const effectiveUid = typeof process.geteuid === 'function' ? process.geteuid() : null;
  if (effectiveUid !== null) {
    allowed.add(effectiveUid);
  }

  const sudoUid = process.env.SUDO_UID?.trim();
  if (effectiveUid === 0 && sudoUid && /^\d+$/u.test(sudoUid)) {
    allowed.add(Number(sudoUid));
  }

  return allowed;
}

function assertTrustedOwner(stats: fs.Stats, targetPath: string, label: string): void {
  if (process.platform === 'win32' || typeof stats.uid !== 'number') {
    return;
  }

  if (stats.uid === 0) {
    return;
  }

  const allowed = allowedOwnerUids();
  if (!allowed.has(stats.uid)) {
    throw new Error(
      `${label} '${targetPath}' must be owned by the current user, sudo caller, or root`,
    );
  }
}

function assertSecureDirectory(stats: fs.Stats, targetPath: string, label: string): void {
  assertTrustedOwner(stats, targetPath, label);
  if (process.platform === 'win32') {
    return;
  }

  if ((stats.mode & GROUP_OTHER_WRITE_MODE_MASK) !== 0) {
    throw new Error(`${label} '${targetPath}' must not be writable by group/other`);
  }
}

function isStickyDirectory(stats: fs.Stats): boolean {
  return process.platform !== 'win32' && (stats.mode & STICKY_BIT_MODE) !== 0;
}

function assertSecureDirectoryPath(targetPath: string, label: string): void {
  const normalized = normalizePath(targetPath);
  assertNoSymlinkAncestorDirectories(normalized, label);
  const targetStats = fs.lstatSync(normalized);
  if (targetStats.isSymbolicLink()) {
    throw new Error(`${label} '${normalized}' must not be a symlink`);
  }
  if (!targetStats.isDirectory()) {
    throw new Error(`${label} '${normalized}' must be a directory`);
  }

  assertSecureDirectory(targetStats, normalized, label);

  const ancestors: string[] = [];
  let currentPath = fs.realpathSync.native(normalized);

  while (true) {
    ancestors.push(currentPath);
    const parentPath = path.dirname(currentPath);
    if (parentPath === currentPath) {
      break;
    }
    currentPath = parentPath;
  }

  for (const [index, currentDirectory] of ancestors.entries()) {
    if (index === 0) {
      continue;
    }

    const stats = fs.lstatSync(currentDirectory);
    if (!stats.isDirectory()) {
      throw new Error(`${label} '${currentDirectory}' must be a directory`);
    }

    assertTrustedOwner(stats, currentDirectory, label);
    if (process.platform !== 'win32' && (stats.mode & GROUP_OTHER_WRITE_MODE_MASK) !== 0) {
      const allowStickyAncestor = index > 0 && isStickyDirectory(stats);
      if (!allowStickyAncestor) {
        throw new Error(`${label} '${currentDirectory}' must not be writable by group/other`);
      }
    }
  }
}

function assertSecureFile(stats: fs.Stats, targetPath: string, label: string): void {
  assertTrustedOwner(stats, targetPath, label);
  if (process.platform === 'win32') {
    return;
  }

  if ((stats.mode & PRIVATE_FILE_MODE_MASK) !== 0) {
    throw new Error(`${label} '${targetPath}' must not grant group/other permissions`);
  }
}

function assertNotSymlink(targetPath: string, label: string): fs.Stats | null {
  const stats = readLstat(targetPath);
  if (stats?.isSymbolicLink()) {
    throw new Error(`${label} '${targetPath}' must not be a symlink`);
  }
  return stats;
}

function tightenPermissions(targetPath: string, mode: number) {
  try {
    fs.chmodSync(targetPath, mode);
  } catch {}
}

function ensurePrivateDirectory(targetPath: string, label: string): string {
  const normalized = normalizePath(targetPath);
  assertNoSymlinkAncestorDirectories(normalized, label);
  const stats = assertNotSymlink(normalized, label);
  if (stats && !stats.isDirectory()) {
    throw new Error(`${label} '${normalized}' must be a directory`);
  }
  if (!stats) {
    fs.mkdirSync(normalized, { recursive: true, mode: PRIVATE_DIR_MODE });
  }
  tightenPermissions(normalized, PRIVATE_DIR_MODE);
  assertSecureDirectoryPath(normalized, label);
  return normalized;
}

function readUtf8FileSecure(targetPath: string, label: string, maxBytes?: number): string {
  const normalized = normalizePath(targetPath);
  assertSecureDirectoryPath(path.dirname(normalized), `${label} parent directory`);
  const openFlags =
    process.platform === 'win32'
      ? fs.constants.O_RDONLY
      : fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW;
  const fd = fs.openSync(normalized, openFlags);

  try {
    const stats = fs.fstatSync(fd);
    if (!stats.isFile()) {
      throw new Error(`${label} '${normalized}' must be a regular file`);
    }
    assertSecureFile(stats, normalized, label);
    if (maxBytes !== undefined && stats.size > maxBytes) {
      throw new Error(`${label} '${normalized}' must not exceed ${maxBytes} bytes`);
    }
    return fs.readFileSync(fd, 'utf8');
  } finally {
    fs.closeSync(fd);
  }
}

function readPrivateJsonFile<T>(targetPath: string, label: string): T | null {
  const normalized = normalizePath(targetPath);
  const stats = assertNotSymlink(normalized, label);
  if (!stats) {
    return null;
  }
  if (!stats.isFile()) {
    throw new Error(`${label} '${normalized}' must be a regular file`);
  }
  tightenPermissions(normalized, PRIVATE_FILE_MODE);
  return JSON.parse(readUtf8FileSecure(normalized, label, MAX_CONFIG_FILE_BYTES)) as T;
}

function assertSecurePlannedDirectoryPath(targetPath: string, label: string): string {
  const normalized = requirePathValue(targetPath, label);
  assertNoSymlinkAncestorDirectories(normalized, label);
  const stats = readLstat(normalized);

  if (stats) {
    if (stats.isSymbolicLink()) {
      throw new Error(`${label} '${normalized}' must not be a symlink`);
    }
    if (!stats.isDirectory()) {
      throw new Error(`${label} '${normalized}' must be a directory`);
    }

    assertSecureDirectoryPath(normalized, label);
    return normalized;
  }

  const nearestExistingPath = findNearestExistingPath(normalized);
  if (nearestExistingPath.stats.isSymbolicLink()) {
    throw new Error(`${label} '${nearestExistingPath.path}' must not be a symlink`);
  }
  if (!nearestExistingPath.stats.isDirectory()) {
    throw new Error(`${label} '${nearestExistingPath.path}' must be a directory`);
  }

  assertSecureDirectoryPath(nearestExistingPath.path, label);
  return normalized;
}

function assertSecurePlannedDaemonSocketPath(targetPath: string, label: string): string {
  const normalized = requirePathValue(targetPath, label);
  assertSecurePlannedDirectoryPath(path.dirname(normalized), `${label} directory`);

  const stats = readLstat(normalized);
  if (!stats) {
    return normalized;
  }

  if (stats.isSymbolicLink()) {
    throw new Error(`${label} '${normalized}' must not be a symlink`);
  }
  if (process.platform !== 'win32' && !stats.isSocket()) {
    throw new Error(`${label} '${normalized}' must be a unix socket`);
  }

  assertTrustedOwner(stats, normalized, label);
  return normalized;
}

function assertSecurePlannedPrivateFilePath(targetPath: string, label: string): string {
  const normalized = requirePathValue(targetPath, label);
  assertSecurePlannedDirectoryPath(path.dirname(normalized), `${label} directory`);

  const stats = readLstatAllowInaccessible(normalized);
  if (!stats || stats === 'inaccessible') {
    return normalized;
  }

  if (stats.isSymbolicLink()) {
    throw new Error(`${label} '${normalized}' must not be a symlink`);
  }
  if (!stats.isFile()) {
    throw new Error(`${label} '${normalized}' must be a regular file`);
  }

  assertSecureFile(stats, normalized, label);
  return normalized;
}

function writePrivateFile(targetPath: string, contents: string, label: string) {
  const normalized = normalizePath(targetPath);
  const parent = ensurePrivateDirectory(path.dirname(normalized), `${label} parent`);
  assertNotSymlink(normalized, label);

  const tempPath = path.join(
    parent,
    `.${path.basename(normalized)}.tmp-${process.pid}-${Date.now()}`,
  );

  try {
    fs.writeFileSync(tempPath, contents, {
      encoding: 'utf8',
      mode: PRIVATE_FILE_MODE,
      flag: 'wx',
    });
    tightenPermissions(tempPath, PRIVATE_FILE_MODE);
    fs.renameSync(tempPath, normalized);
    tightenPermissions(normalized, PRIVATE_FILE_MODE);
  } finally {
    try {
      if (fs.existsSync(tempPath)) {
        fs.rmSync(tempPath);
      }
    } catch {}
  }
}

function normalizedDefaultConfig(): WlfiConfig {
  return {
    daemonSocket: defaultDaemonSocketPath(),
    stateFile: defaultStateFilePath(),
    rustBinDir: defaultRustBinDir(),
    chains: defaultChainProfiles(),
    tokens: defaultTokenProfiles(),
  };
}

function mergeSeedDefaults(config: WlfiConfig): WlfiConfig {
  const removed = normalizeRemovedBuiltins(config.removedBuiltins);
  return {
    ...config,
    removedBuiltins: compactRemovedBuiltins(removed),
    chains: mergeDefaultChainProfiles(config.chains, removed),
    tokens: mergeDefaultTokenProfiles(config.tokens, removed),
  };
}

const CONFIG_STRING_FIELDS = [
  'rpcUrl',
  'chainName',
  'daemonSocket',
  'stateFile',
  'rustBinDir',
  'agentKeyId',
  'agentAuthToken',
] as const;
const CONFIG_OBJECT_FIELDS = ['wallet', 'chains', 'tokens', 'removedBuiltins'] as const;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assertConfigEntriesAreObjects(
  entries: Record<string, unknown> | undefined,
  label: string,
): void {
  for (const [key, value] of Object.entries(entries ?? {})) {
    if (!isPlainObject(value)) {
      throw new Error(`config field ${label}.${key} must be an object`);
    }
  }
}

/**
 * Structural guard for the on-disk config. Field-level normalizers assume the
 * declared TypeScript shapes, so wrong-typed JSON (e.g. `wallet.vaultPublicKey: 123`)
 * would otherwise surface as an opaque `TypeError`.
 */
function assertConfigFieldTypes(parsed: unknown, label: string): WlfiConfig {
  if (parsed == null) {
    return {};
  }
  if (!isPlainObject(parsed)) {
    throw new Error(`${label} must contain a JSON object`);
  }
  for (const field of CONFIG_STRING_FIELDS) {
    const value = parsed[field];
    if (value != null && typeof value !== 'string') {
      throw new Error(`config field ${field} must be a string`);
    }
  }
  if (parsed.chainId != null && typeof parsed.chainId !== 'number') {
    throw new Error('config field chainId must be a number');
  }
  for (const field of CONFIG_OBJECT_FIELDS) {
    const value = parsed[field];
    if (value != null && !isPlainObject(value)) {
      throw new Error(`config field ${field} must be an object`);
    }
  }
  assertConfigEntriesAreObjects(parsed.chains as Record<string, unknown> | undefined, 'chains');
  assertConfigEntriesAreObjects(parsed.tokens as Record<string, unknown> | undefined, 'tokens');
  for (const [tokenKey, token] of Object.entries(
    (parsed.tokens as Record<string, Record<string, unknown>> | undefined) ?? {},
  )) {
    if (token.chains != null && !isPlainObject(token.chains)) {
      throw new Error(`config field tokens.${tokenKey}.chains must be an object`);
    }
    assertConfigEntriesAreObjects(
      token.chains as Record<string, unknown> | undefined,
      `tokens.${tokenKey}.chains`,
    );
  }
  return parsed as WlfiConfig;
}

export function resolveAgentPayHome(): string {
  const explicit = process.env.AGENTPAY_HOME?.trim();
  if (explicit) {
    return normalizePath(explicit);
  }
  return path.join(os.homedir(), AGENTPAY_DIRNAME);
}

export function resolveConfigPath(): string {
  return path.join(resolveAgentPayHome(), CONFIG_FILENAME);
}

export function resolveTelemetryPath(): string {
  return path.join(resolveAgentPayHome(), TELEMETRY_FILENAME);
}

export function defaultDaemonSocketPath(): string {
  return path.join(resolveAgentPayHome(), 'daemon.sock');
}

export function defaultStateFilePath(): string {
  return path.join(resolveAgentPayHome(), 'daemon-state.enc');
}

export function defaultRustBinDir(): string {
  return path.join(resolveAgentPayHome(), 'bin');
}

export function defaultConfig(): WlfiConfig {
  return normalizedDefaultConfig();
}

export function ensureAgentPayHome(): string {
  return ensurePrivateDirectory(resolveAgentPayHome(), 'AgentPay home');
}

export function readPrivateJson<T>(targetPath: string, label: string): T | null {
  return readPrivateJsonFile<T>(targetPath, label);
}

export function writePrivateJson(targetPath: string, value: unknown, label: string): void {
  writePrivateFile(targetPath, JSON.stringify(value, null, 2) + '\n', label);
}

export function readConfig(): WlfiConfig {
  ensureAgentPayHome();
  const parsed = assertConfigFieldTypes(
    readPrivateJsonFile<unknown>(resolveConfigPath(), 'config file'),
    'config file',
  );
  const merged = mergeSeedDefaults({
    ...normalizedDefaultConfig(),
    ...parsed,
  } satisfies WlfiConfig);

  return {
    ...merged,
    rpcUrl: normalizeOptionalRpcUrl(merged.rpcUrl, 'rpcUrl'),
    wallet: normalizeWalletProfile(merged.wallet),
    chains: normalizeChainProfiles(merged.chains),
    tokens: normalizeTokenProfiles(merged.tokens),
  };
}

export function writeConfig(nextConfig: WlfiConfig): WlfiConfig {
  ensureAgentPayHome();
  const merged: WlfiConfig = {
    ...normalizedDefaultConfig(),
    ...readConfig(),
    ...nextConfig,
  };

  if (Object.hasOwn(nextConfig, 'rpcUrl')) {
    merged.rpcUrl = normalizeOptionalRpcUrl(merged.rpcUrl, 'rpcUrl', { validate: true });
  }
  if (Object.hasOwn(nextConfig, 'daemonSocket') && merged.daemonSocket !== undefined) {
    merged.daemonSocket = assertSecurePlannedDaemonSocketPath(merged.daemonSocket, 'daemonSocket');
  }
  if (Object.hasOwn(nextConfig, 'stateFile') && merged.stateFile !== undefined) {
    merged.stateFile = assertSecurePlannedPrivateFilePath(merged.stateFile, 'stateFile');
  }
  if (Object.hasOwn(nextConfig, 'rustBinDir') && merged.rustBinDir !== undefined) {
    merged.rustBinDir = assertSecurePlannedDirectoryPath(merged.rustBinDir, 'rustBinDir');
  }

  merged.wallet = normalizeWalletProfile(merged.wallet);
  merged.chains = normalizeChainProfiles(merged.chains);
  merged.tokens = normalizeTokenProfiles(merged.tokens);
  merged.removedBuiltins = compactRemovedBuiltins(merged.removedBuiltins);

  writePrivateFile(resolveConfigPath(), JSON.stringify(merged, null, 2) + '\n', 'config file');
  return merged;
}

export function deleteConfigKey(key: keyof WlfiConfig): WlfiConfig {
  ensureAgentPayHome();
  const current = {
    ...normalizedDefaultConfig(),
    ...readConfig(),
  };
  delete current[key];

  const normalized = {
    ...normalizedDefaultConfig(),
    ...current,
    chains: current.chains ?? {},
    tokens: current.tokens ?? {},
  };

  writePrivateFile(resolveConfigPath(), JSON.stringify(normalized, null, 2) + '\n', 'config file');
  return normalized;
}

export function listBuiltinChains(): ChainProfile[] {
  return Object.entries(BUILTIN_CHAINS)
    .map(([key, value]) => ({ ...value, name: key }))
    .sort((left, right) => left.chainId - right.chainId || left.name.localeCompare(right.name));
}

export function listBuiltinTokens(): TokenProfileEntry[] {
  return Object.entries(BUILTIN_TOKENS)
    .map(([key, value]) => ({
      key,
      name: value.name,
      symbol: value.symbol,
      chains: Object.entries(value.chains ?? {})
        .map(([chainKey, chainValue]) => ({ key: chainKey, ...chainValue }))
        .sort((left, right) => left.chainId - right.chainId || left.key.localeCompare(right.key)),
    }))
    .sort((left, right) => left.key.localeCompare(right.key));
}

export function listConfiguredTokens(config: WlfiConfig = readConfig()): TokenProfileEntry[] {
  return Object.entries(config.tokens ?? {})
    .map(([key, value]) => ({
      key,
      name: value.name,
      symbol: value.symbol,
      chains: Object.entries(value.chains ?? {})
        .map(([chainKey, chainValue]) => ({ key: chainKey, ...chainValue }))
        .sort((left, right) => left.chainId - right.chainId || left.key.localeCompare(right.key)),
    }))
    .sort((left, right) => left.key.localeCompare(right.key));
}

export function resolveTokenProfile(
  selector: string,
  config: WlfiConfig = readConfig(),
): (TokenProfile & { key: string; source: 'configured' | 'builtin' }) | null {
  const normalized = selector.trim().toLowerCase();
  if (!normalized) {
    return null;
  }

  for (const [key, value] of Object.entries(config.tokens ?? {})) {
    if (key.toLowerCase() === normalized || value.symbol.toLowerCase() === normalized) {
      return { key, source: 'configured', ...value };
    }
  }

  for (const [key, value] of Object.entries(BUILTIN_TOKENS)) {
    if (key.toLowerCase() === normalized || value.symbol.toLowerCase() === normalized) {
      return { key, source: 'builtin', ...value };
    }
  }

  return null;
}

export function listConfiguredChains(
  config: WlfiConfig = readConfig(),
): Array<ChainProfile & { key: string }> {
  return Object.entries(config.chains ?? {})
    .map(([key, value]) => ({ key, ...value }))
    .sort((left, right) => left.chainId - right.chainId || left.key.localeCompare(right.key));
}

export function resolveChainProfile(
  selector: string,
  config: WlfiConfig = readConfig(),
): (ChainProfile & { key?: string; source: 'configured' | 'builtin' | 'active' }) | null {
  const normalized = selector.trim().toLowerCase();
  if (!normalized) {
    return null;
  }

  for (const [key, value] of Object.entries(config.chains ?? {})) {
    if (
      key.toLowerCase() === normalized ||
      value.name.toLowerCase() === normalized ||
      String(value.chainId) === selector
    ) {
      return { ...value, key, source: 'configured' };
    }
  }

  for (const [key, value] of Object.entries(BUILTIN_CHAINS)) {
    if (
      key.toLowerCase() === normalized ||
      value.name.toLowerCase() === normalized ||
      String(value.chainId) === selector
    ) {
      return { ...value, key, source: 'builtin' };
    }
  }

  if (config.chainId !== undefined && String(config.chainId) === selector) {
    return {
      chainId: config.chainId,
      name: config.chainName ?? normalized,
      family: normalizeChainFamily(undefined, config.chainId),
      rpcUrl: config.rpcUrl,
      source: 'active',
    };
  }

  return null;
}

export function saveChainProfile(key: string, profile: ChainProfile): WlfiConfig {
  const normalizedKey = key.trim().toLowerCase();
  if (!normalizedKey) {
    throw new Error('chain profile key is required');
  }

  const normalizedProfile = normalizeChainProfileEntry(normalizedKey, profile, {
    validateRpcUrl: true,
  });
  const current = readConfig();

  return writeConfig({
    chains: {
      ...(current.chains ?? {}),
      [normalizedKey]: normalizedProfile,
    },
    removedBuiltins: withoutRemovedBuiltins(current.removedBuiltins, {
      chains: (entry) => entry === normalizedKey,
    }),
  });
}

export function removeChainProfile(key: string): WlfiConfig {
  const normalizedKey = key.trim().toLowerCase();
  const current = readConfig();
  const nextChains = { ...(current.chains ?? {}) };
  if (!Object.hasOwn(nextChains, normalizedKey)) {
    throw new Error(`network '${normalizedKey}' does not exist`);
  }
  delete nextChains[normalizedKey];
  return writeConfig({
    chains: nextChains,
    removedBuiltins: withRemovedBuiltins(
      current.removedBuiltins,
      seededChainRemovals(normalizedKey),
    ),
  });
}

function isRemovedBuiltinTokenEntry(entry: string, tokenKey: string, chainKey?: string): boolean {
  if (entry === tokenKey) {
    return true;
  }
  return chainKey === undefined
    ? entry.startsWith(`${tokenKey}${REMOVED_BUILTIN_TOKEN_CHAIN_SEPARATOR}`)
    : entry === removedBuiltinTokenChainEntry(tokenKey, chainKey);
}

export function saveTokenProfile(key: string, profile: TokenProfile): WlfiConfig {
  const normalizedKey = key.trim().toLowerCase();
  const current = readConfig();
  return writeConfig({
    tokens: {
      ...(current.tokens ?? {}),
      [normalizedKey]: normalizeTokenProfile(normalizedKey, profile),
    },
    removedBuiltins: withoutRemovedBuiltins(current.removedBuiltins, {
      tokens: (entry) => isRemovedBuiltinTokenEntry(entry, normalizedKey),
    }),
  });
}

export function saveTokenChainProfile(
  tokenKey: string,
  chainKey: string,
  profile: TokenChainProfile,
  options: { symbol?: string } = {},
): WlfiConfig {
  const normalizedTokenKey = tokenKey.trim().toLowerCase();
  const normalizedChainKey = chainKey.trim().toLowerCase();
  const current = readConfig();
  const existing = current.tokens?.[normalizedTokenKey];
  const symbol = options.symbol?.trim() || existing?.symbol;
  if (!symbol) {
    throw new Error(`token '${normalizedTokenKey}' symbol is required`);
  }

  return writeConfig({
    tokens: {
      ...(current.tokens ?? {}),
      [normalizedTokenKey]: normalizeTokenProfile(normalizedTokenKey, {
        name: existing?.name,
        symbol,
        defaultPolicy: existing?.defaultPolicy,
        destinationOverrides: existing?.destinationOverrides,
        manualApprovalPolicies: existing?.manualApprovalPolicies,
        chains: {
          ...(existing?.chains ?? {}),
          [normalizedChainKey]: normalizeTokenChainProfile(
            normalizedTokenKey,
            normalizedChainKey,
            profile,
          ),
        },
      }),
    },
    removedBuiltins: withoutRemovedBuiltins(current.removedBuiltins, {
      tokens: (entry) =>
        entry === normalizedTokenKey ||
        isRemovedBuiltinTokenEntry(entry, normalizedTokenKey, normalizedChainKey),
    }),
  });
}

export function removeTokenProfile(key: string): WlfiConfig {
  const normalizedKey = key.trim().toLowerCase();
  const current = readConfig();
  const nextTokens = { ...(current.tokens ?? {}) };
  delete nextTokens[normalizedKey];
  return writeConfig({
    tokens: nextTokens,
    removedBuiltins: withRemovedBuiltins(
      current.removedBuiltins,
      seededTokenRemovals(normalizedKey),
    ),
  });
}

export function removeTokenChainProfile(tokenKey: string, chainKey: string): WlfiConfig {
  const normalizedTokenKey = tokenKey.trim().toLowerCase();
  const normalizedChainKey = chainKey.trim().toLowerCase();
  const current = readConfig();
  const token = current.tokens?.[normalizedTokenKey];
  if (!token) {
    return current;
  }

  const nextChains = { ...(token.chains ?? {}) };
  delete nextChains[normalizedChainKey];
  const nextTokens = { ...(current.tokens ?? {}) };
  const removedBuiltins = withRemovedBuiltins(current.removedBuiltins, {
    tokens: [
      ...(seededTokenRemovals(normalizedTokenKey, normalizedChainKey).tokens ?? []),
      ...(Object.keys(nextChains).length === 0
        ? (seededTokenRemovals(normalizedTokenKey).tokens ?? [])
        : []),
    ],
  });
  if (Object.keys(nextChains).length === 0) {
    delete nextTokens[normalizedTokenKey];
  } else {
    nextTokens[normalizedTokenKey] = normalizeTokenProfile(normalizedTokenKey, {
      name: token.name,
      symbol: token.symbol,
      defaultPolicy: token.defaultPolicy,
      destinationOverrides: token.destinationOverrides,
      manualApprovalPolicies: token.manualApprovalPolicies,
      chains: nextChains,
    });
  }
  return writeConfig({ tokens: nextTokens, removedBuiltins });
}

export function switchActiveChain(
  selector: string,
  options: { rpcUrl?: string; persistProfile?: boolean } = {},
): WlfiConfig {
  const config = readConfig();
  const profile = resolveChainProfile(selector, config);
  if (!profile) {
    throw new Error(`Unknown chain selector: ${selector}`);
  }

  // A blank `--rpc-url` means "not provided": fall back to the profile endpoint
  // instead of clearing the active RPC URL.
  const explicitRpcUrl = options.rpcUrl?.trim();
  const nextRpcUrl = explicitRpcUrl ? explicitRpcUrl : profile.rpcUrl;
  const normalizedRpcUrl = normalizeOptionalRpcUrl(nextRpcUrl, 'rpcUrl', { validate: true });
  let next = writeConfig({
    chainId: profile.chainId,
    chainName: profile.name,
    rpcUrl: normalizedRpcUrl,
    chains: config.chains ?? {},
  });

  if (options.persistProfile) {
    next = saveChainProfile(profile.key ?? profile.name, {
      chainId: profile.chainId,
      name: profile.name,
      rpcUrl: normalizedRpcUrl,
    });
  }

  return next;
}

export function redactConfig(config: WlfiConfig): Record<string, unknown> {
  return {
    ...config,
    agentAuthToken: config.agentAuthToken ? '<redacted>' : undefined,
    paths: {
      agentpayHome: resolveAgentPayHome(),
      configPath: resolveConfigPath(),
      daemonSocket: config.daemonSocket ?? defaultDaemonSocketPath(),
      stateFile: config.stateFile ?? defaultStateFilePath(),
      rustBinDir: config.rustBinDir ?? defaultRustBinDir(),
    },
  };
}

export function resolveRustBinaryPath(
  binaryName: string,
  config: WlfiConfig = readConfig(),
): string {
  return path.join(
    config.rustBinDir ?? defaultRustBinDir(),
    binaryName + (process.platform === 'win32' ? '.exe' : ''),
  );
}
