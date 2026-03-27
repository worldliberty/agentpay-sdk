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
}

export interface WalletProfile {
  vaultKeyId?: string;
  vaultPublicKey: string;
  address?: string;
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

const PRIVATE_DIR_MODE = 0o700;
const PRIVATE_FILE_MODE = 0o600;
const GROUP_OTHER_WRITE_MODE_MASK = 0o022;
const PRIVATE_FILE_MODE_MASK = 0o077;
const STICKY_BIT_MODE = 0o1000;
const MAX_CONFIG_FILE_BYTES = 256 * 1024;
const DEFAULT_ETH_RPC_URL = 'https://eth.llamarpc.com';
const DEFAULT_BSC_RPC_URL = 'https://bsc.drpc.org';
const DEFAULT_TEMPO_RPC_URL = 'https://rpc.presto.tempo.xyz';
const DEFAULT_TEMPO_TESTNET_RPC_URL = 'https://rpc.moderato.tempo.xyz';
const DEFAULT_USD1_ADDRESS = '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d';
const DEFAULT_PATHUSD_ADDRESS = '0x20c0000000000000000000000000000000000000';
const DEFAULT_TEMPO_USDCE_ADDRESS = '0x20c000000000000000000000b9537d11c60e8b50';
const DEFAULT_TEMPO_TESTNET_USDCE_ADDRESS = '0x20c0000000000000000000009e8d7eb59b783726';

export const BUILTIN_CHAINS: Record<string, ChainProfile> = {
  eth: { chainId: 1, name: 'eth', rpcUrl: DEFAULT_ETH_RPC_URL },
  ethereum: { chainId: 1, name: 'ethereum', rpcUrl: DEFAULT_ETH_RPC_URL },
  mainnet: { chainId: 1, name: 'mainnet', rpcUrl: DEFAULT_ETH_RPC_URL },
  sepolia: { chainId: 11155111, name: 'sepolia' },
  base: { chainId: 8453, name: 'base' },
  'base-sepolia': { chainId: 84532, name: 'base-sepolia' },
  optimism: { chainId: 10, name: 'optimism' },
  arbitrum: { chainId: 42161, name: 'arbitrum' },
  polygon: { chainId: 137, name: 'polygon' },
  bsc: { chainId: 56, name: 'bsc', rpcUrl: DEFAULT_BSC_RPC_URL },
  tempo: { chainId: 4217, name: 'tempo', rpcUrl: DEFAULT_TEMPO_RPC_URL },
  'tempo-mainnet': { chainId: 4217, name: 'tempo-mainnet', rpcUrl: DEFAULT_TEMPO_RPC_URL },
  'tempo-testnet': {
    chainId: 42431,
    name: 'tempo-testnet',
    rpcUrl: DEFAULT_TEMPO_TESTNET_RPC_URL,
  },
  moderato: { chainId: 42431, name: 'moderato', rpcUrl: DEFAULT_TEMPO_TESTNET_RPC_URL },
  'tempo-moderato': {
    chainId: 42431,
    name: 'tempo-moderato',
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

function defaultChainProfiles(): Record<string, ChainProfile> {
  return {
    eth: {
      chainId: 1,
      name: 'ETH',
      rpcUrl: DEFAULT_ETH_RPC_URL,
    },
    bsc: {
      chainId: 56,
      name: 'BSC',
      rpcUrl: DEFAULT_BSC_RPC_URL,
    },
    tempo: {
      chainId: 4217,
      name: 'Tempo',
      rpcUrl: DEFAULT_TEMPO_RPC_URL,
    },
    'tempo-testnet': {
      chainId: 42431,
      name: 'Tempo Testnet (Moderato)',
      rpcUrl: DEFAULT_TEMPO_TESTNET_RPC_URL,
    },
  };
}

function defaultTokenProfiles(): Record<string, TokenProfile> {
  return {
    bnb: {
      name: 'BNB',
      symbol: 'BNB',
      destinationOverrides: [],
      manualApprovalPolicies: [],
      chains: {
        bsc: {
          chainId: 56,
          isNative: true,
          decimals: 18,
        },
      },
    },
    eth: {
      name: 'ETH',
      symbol: 'ETH',
      destinationOverrides: [],
      manualApprovalPolicies: [],
      chains: {
        eth: {
          chainId: 1,
          isNative: true,
          decimals: 18,
        },
      },
    },
    usd: {
      name: 'USD',
      symbol: 'USD',
      destinationOverrides: [],
      manualApprovalPolicies: [],
      chains: {
        tempo: {
          chainId: 4217,
          isNative: true,
          decimals: 6,
        },
      },
    },
    usd1: {
      name: 'USD1',
      symbol: 'USD1',
      destinationOverrides: [],
      manualApprovalPolicies: [],
      chains: {
        eth: {
          chainId: 1,
          isNative: false,
          address: DEFAULT_USD1_ADDRESS,
          decimals: 18,
        },
        bsc: {
          chainId: 56,
          isNative: false,
          address: DEFAULT_USD1_ADDRESS,
          decimals: 18,
        },
      },
    },
    pathusd: {
      name: 'PATH/USD',
      symbol: 'PATH/USD',
      destinationOverrides: [],
      manualApprovalPolicies: [],
      chains: {
        tempo: {
          chainId: 4217,
          isNative: false,
          address: DEFAULT_PATHUSD_ADDRESS,
          decimals: 6,
        },
        'tempo-testnet': {
          chainId: 42431,
          isNative: false,
          address: DEFAULT_PATHUSD_ADDRESS,
          decimals: 6,
        },
      },
    },
    'usdc.e': {
      name: 'Bridged USDC (Stargate)',
      symbol: 'USDC.e',
      destinationOverrides: [],
      manualApprovalPolicies: [],
      chains: {
        tempo: {
          chainId: 4217,
          isNative: false,
          address: DEFAULT_TEMPO_USDCE_ADDRESS,
          decimals: 6,
        },
        'tempo-testnet': {
          chainId: 42431,
          isNative: false,
          address: DEFAULT_TEMPO_TESTNET_USDCE_ADDRESS,
          decimals: 6,
        },
      },
    },
  };
}

function mergeDefaultChainProfiles(
  profiles: Record<string, ChainProfile> | undefined,
): Record<string, ChainProfile> {
  return {
    ...defaultChainProfiles(),
    ...(profiles ?? {}),
  };
}

function mergeDefaultTokenProfiles(
  profiles: Record<string, TokenProfile> | undefined,
): Record<string, TokenProfile> {
  const merged = Object.fromEntries(
    Object.entries(defaultTokenProfiles()).map(([key, profile]) => [
      key,
      {
        ...profile,
        destinationOverrides: [...(profile.destinationOverrides ?? [])],
        manualApprovalPolicies: [...(profile.manualApprovalPolicies ?? [])],
        chains: { ...(profile.chains ?? {}) },
      },
    ]),
  ) as Record<string, TokenProfile>;

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

function assertValidEvmAddress(value: string, label: string): string {
  const normalized = value.trim();
  if (!ADDRESS_PATTERN.test(normalized)) {
    throw new Error(`${label} must be a valid EVM address`);
  }
  return normalized;
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

function assertOptionalTrimmedString(
  value: string | null | undefined,
  label: string,
): string | undefined {
  if (value == null) {
    return undefined;
  }
  const normalized = value.trim();
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

  return {
    vaultKeyId: assertOptionalTrimmedString(profile.vaultKeyId, 'wallet.vaultKeyId'),
    vaultPublicKey: assertRequiredTrimmedString(profile.vaultPublicKey, 'wallet.vaultPublicKey'),
    address: profile.address ? assertValidEvmAddress(profile.address, 'wallet.address') : undefined,
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
      ? assertValidEvmAddress(profile.recipient, `token '${tokenKey}' manual approval recipient`)
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
    normalized.address = assertValidEvmAddress(
      profile.address ?? '',
      `token '${tokenKey}' chain '${normalizedChainKey}' address`,
    );
  }

  return normalized;
}

function normalizeTokenProfile(key: string, profile: TokenProfile): TokenProfile {
  const normalizedKey = key.trim().toLowerCase();
  if (!normalizedKey) {
    throw new Error('token profile key is required');
  }

  const symbol = profile.symbol?.trim();
  if (!symbol) {
    throw new Error(`token profile '${normalizedKey}' symbol is required`);
  }
  const name = assertOptionalTrimmedString(profile.name, `token profile '${normalizedKey}' name`);

  const normalizedChains: Record<string, TokenChainProfile> = {};
  for (const [chainKey, chainProfile] of Object.entries(profile.chains ?? {})) {
    const normalizedChainKey = chainKey.trim().toLowerCase();
    if (!normalizedChainKey) {
      throw new Error(`token profile '${normalizedKey}' contains an empty chain key`);
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
    destinationOverrides: (profile.destinationOverrides ?? []).map((item) =>
      normalizeTokenDestinationOverrideProfile(normalizedKey, item),
    ),
    manualApprovalPolicies: (profile.manualApprovalPolicies ?? []).map((item) =>
      normalizeTokenManualApprovalProfile(normalizedKey, item),
    ),
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
  return {
    chainId: assertPositiveSafeInteger(profile.chainId, `chain profile '${normalizedKey}' chainId`),
    name,
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
    parentStats &&
      parentStats.isDirectory() &&
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
  return {
    ...config,
    chains: mergeDefaultChainProfiles(config.chains),
    tokens: mergeDefaultTokenProfiles(config.tokens),
  };
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

export function readConfig(): WlfiConfig {
  ensureAgentPayHome();
  const parsed = readPrivateJsonFile<WlfiConfig>(resolveConfigPath(), 'config file');
  const merged = mergeSeedDefaults({
    ...normalizedDefaultConfig(),
    ...(parsed ?? {}),
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

  return writeConfig({
    chains: {
      ...(readConfig().chains ?? {}),
      [normalizedKey]: normalizedProfile,
    },
  });
}

export function removeChainProfile(key: string): WlfiConfig {
  const normalizedKey = key.trim().toLowerCase();
  const nextChains = { ...(readConfig().chains ?? {}) };
  if (!Object.hasOwn(nextChains, normalizedKey)) {
    throw new Error(`network '${normalizedKey}' does not exist`);
  }
  delete nextChains[normalizedKey];
  return writeConfig({ chains: nextChains });
}

export function saveTokenProfile(key: string, profile: TokenProfile): WlfiConfig {
  const normalizedKey = key.trim().toLowerCase();
  return writeConfig({
    tokens: {
      ...(readConfig().tokens ?? {}),
      [normalizedKey]: normalizeTokenProfile(normalizedKey, profile),
    },
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
  });
}

export function removeTokenProfile(key: string): WlfiConfig {
  const normalizedKey = key.trim().toLowerCase();
  const nextTokens = { ...(readConfig().tokens ?? {}) };
  delete nextTokens[normalizedKey];
  return writeConfig({ tokens: nextTokens });
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
  return writeConfig({ tokens: nextTokens });
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

  const nextRpcUrl = options.rpcUrl ?? profile.rpcUrl;
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
