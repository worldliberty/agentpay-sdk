import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { createCuimpHttp } from 'cuimp';
import { chromium } from 'playwright-core';
import { type Address, type Hex, isAddress } from 'viem';
import { assertSafeRpcUrl, ensureAgentPayHome } from '../../packages/config/src/index.js';
import { encodeErc20TransferData } from './asset-broadcast.js';
import {
  formatConfiguredAmount,
  normalizePositiveDecimalInput,
  parseConfiguredAmount,
  type ResolvedAssetMetadata,
} from './config-amounts.js';

const DEFAULT_BITREFILL_BASE_URL = 'https://www.bitrefill.com';
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_WAIT_TIMEOUT_MS = 60_000;
const DEFAULT_WAIT_INTERVAL_MS = 3_000;
const DEFAULT_BOOTSTRAP_TIMEOUT_MS = 90_000;
const DEFAULT_BOOTSTRAP_POLL_INTERVAL_MS = 1_000;
const BITREFILL_INVOICE_ACCESS_TOKEN_STORE_FILE = 'invoice-access-tokens.json';
const BITREFILL_CHALLENGE_HEADER = 'cf-mitigated';
const BITREFILL_CHALLENGE_HEADER_VALUE = 'challenge';
const BITREFILL_INVOICE_SUCCESS_STATUSES = new Set([
  'complete',
  'completed',
  'delivered',
  'fulfilled',
  'paid',
  'success',
]);
const BITREFILL_INVOICE_FAILURE_STATUSES = new Set([
  'cancelled',
  'canceled',
  'expired',
  'failed',
  'invalid',
  'refunded',
  'rejected',
]);

interface BitrefillMethodConfig {
  method: string;
  requestMethod?: string;
  networkSelector: string;
  chainId: number;
  paymentCurrency: string;
  assetKind: 'native' | 'erc20';
  asset: ResolvedAssetMetadata;
  tokenAddress?: Address;
}

const BITREFILL_SUPPORTED_EVM_METHODS = [
  'usdt_bnb',
  'usdt_eth',
  'eth_base',
  'ethereum',
  'usdc_arbitrum',
  'usdc_base',
  'usdc_erc20',
  'usdc_polygon',
  'usdt_arbitrum',
  'usdt_polygon',
] as const;

const BITREFILL_METHOD_ALIASES: Record<string, string> = {
  'usdt-bnb': 'usdt_bnb',
  usdt_bep20: 'usdt_bnb',
  'usdt-bep20': 'usdt_bnb',
  usdt_bsc: 'usdt_bnb',
  'usdt-bsc': 'usdt_bnb',
  'usdt-eth': 'usdt_eth',
  usdt_erc20: 'usdt_eth',
  'usdt-erc20': 'usdt_eth',
};

const BITREFILL_METHOD_CONFIGS: Record<string, BitrefillMethodConfig> = {
  ethereum: {
    method: 'ethereum',
    networkSelector: 'ethereum',
    chainId: 1,
    paymentCurrency: 'ETH',
    assetKind: 'native',
    asset: {
      assetId: 'native_eth',
      decimals: 18,
      symbol: 'ETH',
    },
  },
  eth_base: {
    method: 'eth_base',
    networkSelector: 'base',
    chainId: 8453,
    paymentCurrency: 'ETH',
    assetKind: 'native',
    asset: {
      assetId: 'native_eth',
      decimals: 18,
      symbol: 'ETH',
    },
  },
  usdc_base: {
    method: 'usdc_base',
    networkSelector: 'base',
    chainId: 8453,
    paymentCurrency: 'USDC',
    assetKind: 'erc20',
    tokenAddress: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    asset: {
      assetId: 'erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      decimals: 6,
      symbol: 'USDC',
    },
  },
  usdc_erc20: {
    method: 'usdc_erc20',
    networkSelector: 'ethereum',
    chainId: 1,
    paymentCurrency: 'USDC',
    assetKind: 'erc20',
    tokenAddress: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
    asset: {
      assetId: 'erc20:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
      decimals: 6,
      symbol: 'USDC',
    },
  },
  usdc_polygon: {
    method: 'usdc_polygon',
    networkSelector: 'polygon',
    chainId: 137,
    paymentCurrency: 'USDC',
    assetKind: 'erc20',
    tokenAddress: '0x3c499c542cEF5E3811e1192CE70d8cC03d5c3359',
    asset: {
      assetId: 'erc20:0x3c499c542cEF5E3811e1192CE70d8cC03d5c3359',
      decimals: 6,
      symbol: 'USDC',
    },
  },
  usdc_arbitrum: {
    method: 'usdc_arbitrum',
    networkSelector: 'arbitrum',
    chainId: 42161,
    paymentCurrency: 'USDC',
    assetKind: 'erc20',
    tokenAddress: '0xaf88d065e77c8cC2239327C5EDb3A432268e5831',
    asset: {
      assetId: 'erc20:0xaf88d065e77c8cC2239327C5EDb3A432268e5831',
      decimals: 6,
      symbol: 'USDC',
    },
  },
  usdt_bnb: {
    method: 'usdt_bnb',
    requestMethod: 'usdt_bsc',
    networkSelector: 'bsc',
    chainId: 56,
    paymentCurrency: 'USDT',
    assetKind: 'erc20',
    tokenAddress: '0x55d398326f99059fF775485246999027B3197955',
    asset: {
      assetId: 'erc20:0x55d398326f99059fF775485246999027B3197955',
      decimals: 18,
      symbol: 'USDT',
    },
  },
  usdt_eth: {
    method: 'usdt_eth',
    requestMethod: 'usdt_erc20',
    networkSelector: 'ethereum',
    chainId: 1,
    paymentCurrency: 'USDT',
    assetKind: 'erc20',
    tokenAddress: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
    asset: {
      assetId: 'erc20:0xdAC17F958D2ee523a2206206994597C13D831ec7',
      decimals: 6,
      symbol: 'USDT',
    },
  },
  usdt_polygon: {
    method: 'usdt_polygon',
    networkSelector: 'polygon',
    chainId: 137,
    paymentCurrency: 'USDT',
    assetKind: 'erc20',
    tokenAddress: '0xc2132D05D31c914a87C6611C10748AaCbC532Db',
    asset: {
      assetId: 'erc20:0xc2132D05D31c914a87C6611C10748AaCbC532Db',
      decimals: 6,
      symbol: 'USDT',
    },
  },
  usdt_arbitrum: {
    method: 'usdt_arbitrum',
    networkSelector: 'arbitrum',
    chainId: 42161,
    paymentCurrency: 'USDT',
    assetKind: 'erc20',
    tokenAddress: '0xFd086bC7CD5C481DCC9C85ebe478A1C0b69FCbb9',
    asset: {
      assetId: 'erc20:0xFd086bC7CD5C481DCC9C85ebe478A1C0b69FCbb9',
      decimals: 6,
      symbol: 'USDT',
    },
  },
};

const BITREFILL_METHOD_PRIORITY = new Map<string, number>(
  BITREFILL_SUPPORTED_EVM_METHODS.map((method, index) => [method, index] as const),
);

function canonicalizeBitrefillPaymentMethod(method: string): string {
  const normalized = method.trim().toLowerCase();
  return BITREFILL_METHOD_ALIASES[normalized] ?? normalized;
}

function compareBitrefillMethodPriority(left: string, right: string): number {
  const leftPriority = BITREFILL_METHOD_PRIORITY.get(left) ?? Number.MAX_SAFE_INTEGER;
  const rightPriority = BITREFILL_METHOD_PRIORITY.get(right) ?? Number.MAX_SAFE_INTEGER;
  if (leftPriority !== rightPriority) {
    return leftPriority - rightPriority;
  }
  return left.localeCompare(right);
}

export { BITREFILL_SUPPORTED_EVM_METHODS };

export interface BitrefillHttpRequest {
  method: 'GET' | 'POST';
  pathname: string;
  query?: Record<string, string | number | boolean | undefined>;
  headers?: Record<string, string>;
  body?: unknown | string | URLSearchParams;
  timeoutMs?: number;
}

export interface BitrefillHttpResponse<T = unknown> {
  status: number;
  headers: Record<string, string>;
  data: T;
}

export interface BitrefillHttpTransport {
  request<T = unknown>(input: BitrefillHttpRequest): Promise<BitrefillHttpResponse<T>>;
  destroy?(): void;
}

export interface BitrefillBrowserCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  expires: number;
  secure: boolean;
}

interface StoredBitrefillInvoiceAccessTokenEntry {
  accessToken: string;
  updatedAt: string;
}

export interface StoredBitrefillInvoiceSummary {
  invoiceId: string;
  accessTokenStored: true;
  updatedAt: string;
}

export interface BitrefillAmountRange {
  min: string;
  max: string;
  step?: string;
}

export interface BitrefillProductPackage {
  id: string | null;
  label: string;
  value: string;
}

export interface BitrefillProductSummary {
  slug: string;
  name: string;
  country: string | null;
  categories: string[];
  amountMode: 'fixed' | 'range' | 'unknown';
}

export interface BitrefillProductDetails extends BitrefillProductSummary {
  currency: string | null;
  description: string | null;
  instructions: string | null;
  termsAndConditions: string | null;
  reviews: BitrefillProductReview[];
  packages: BitrefillProductPackage[];
  range: BitrefillAmountRange | null;
  raw: unknown;
}

export interface BitrefillProductReview {
  author: string | null;
  rating: number | null;
  maxRating: number | null;
  date: string | null;
  content: string;
}

export interface BitrefillPaymentMethodQuote {
  method: string;
  supported: boolean;
  network: string | null;
  chainId: number | null;
  assetKind: 'native' | 'erc20' | 'unsupported';
  assetSymbol: string | null;
  tokenAddress: string | null;
  amount: string | null;
  amountBaseUnits: string | null;
  fiatAmount: string | null;
  raw: unknown;
}

export interface BitrefillCartItem {
  operatorSlug: string | null;
  valuePackage: string | null;
  count: number;
  isGift: boolean;
  raw: Record<string, unknown>;
}

export interface BitrefillCart {
  id: string;
  items: BitrefillCartItem[];
  paymentMethodQuotes: BitrefillPaymentMethodQuote[];
  raw: unknown;
}

export interface BitrefillInvoicePayment {
  address: string | null;
  paymentUri: string | null;
  altcoinPrice: string | null;
  altBasePrice: string | null;
  contractAddress: string | null;
}

export interface BitrefillOrderSummary {
  id: string | null;
  status: string | null;
  raw: unknown;
}

export interface BitrefillInvoice {
  id: string;
  accessToken: string | null;
  cartId: string | null;
  status: string;
  paymentMethod: string | null;
  paymentCurrency: string | null;
  price: string | null;
  subtotal: string | null;
  expirationTime: string | null;
  invoiceTimeLeft: number | null;
  paymentReceived: string | null;
  orders: BitrefillOrderSummary[];
  payment: BitrefillInvoicePayment;
  raw: unknown;
}

export interface BitrefillInvoiceWaitResult {
  invoice: BitrefillInvoice;
  timedOut: boolean;
}

export interface BitrefillBuyPreview {
  mode: 'preview';
  product: {
    slug: string;
    name: string;
    amount: string;
  };
  invoice: {
    id: string;
    accessToken: string | null;
    status: string;
    cartId: string | null;
    expirationTime: string | null;
  };
  payment: {
    method: string;
    network: string;
    chainId: number;
    assetKind: 'native' | 'erc20';
    asset: string;
    assetId: string;
    decimals: number;
    tokenAddress: string | null;
    recipient: string;
    amount: string;
    amountBaseUnits: string;
    paymentUri: string | null;
  };
  availablePaymentMethods: BitrefillPaymentMethodQuote[];
  broadcastRequested: boolean;
}

export interface ResolvedBitrefillInvoicePayment {
  method: string;
  networkSelector: string;
  chainId: number;
  assetKind: 'native' | 'erc20';
  asset: ResolvedAssetMetadata;
  recipient: Address;
  tokenAddress: Address | null;
  amountBaseUnits: bigint;
  amount: string;
  paymentUri: string | null;
  broadcastTo: Address;
  valueWei: bigint;
  dataHex: Hex;
}

export interface BitrefillChallengeRequiredOutput {
  status: 'challenge_required';
  message: string;
  invoiceId: string | null;
  accessToken: string | null;
  details: unknown;
}

export class BitrefillChallengeRequiredError extends Error {
  readonly output: BitrefillChallengeRequiredOutput;

  constructor(output: BitrefillChallengeRequiredOutput) {
    super(output.message);
    this.name = 'BitrefillChallengeRequiredError';
    this.output = output;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function normalizeWhitespace(value: string | null | undefined): string | null {
  const normalized = value?.trim();
  return normalized ? normalized : null;
}

function normalizeStringValue(value: unknown): string | null {
  if (typeof value === 'string') {
    return normalizeWhitespace(value);
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value);
  }
  return null;
}

function normalizeNumberValue(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

function normalizeIntegerValue(value: unknown): number | null {
  if (typeof value === 'number' && Number.isSafeInteger(value)) {
    return value;
  }
  if (typeof value === 'string' && /^(0|[1-9][0-9]*)$/u.test(value.trim())) {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : null;
  }
  return null;
}

function normalizeBooleanValue(value: unknown): boolean {
  return value === true || value === 'true' || value === 1 || value === '1';
}

function collectArrays(value: unknown): unknown[] {
  if (Array.isArray(value)) {
    return value;
  }
  if (!isPlainObject(value)) {
    return [];
  }
  for (const key of ['items', 'results', 'products', 'data', 'hits']) {
    if (Array.isArray(value[key])) {
      return value[key] as unknown[];
    }
  }
  return [];
}

function normalizeDecimalDisplay(value: string): string {
  const normalized = normalizePositiveDecimalInput(value, 'amount');
  const [whole, fraction = ''] = normalized.split('.');
  const trimmedFraction = fraction.replace(/0+$/u, '');
  return trimmedFraction ? `${whole}.${trimmedFraction}` : whole;
}

function decimalScale(value: string): number {
  const [_whole, fraction = ''] = value.split('.');
  return fraction.length;
}

function compareDecimalStrings(left: string, right: string): number {
  const normalizedLeft = normalizeDecimalDisplay(left);
  const normalizedRight = normalizeDecimalDisplay(right);
  const scale = Math.max(decimalScale(normalizedLeft), decimalScale(normalizedRight));
  const leftValue = parseConfiguredAmount(normalizedLeft, scale, 'amount');
  const rightValue = parseConfiguredAmount(normalizedRight, scale, 'amount');
  if (leftValue === rightValue) {
    return 0;
  }
  return leftValue < rightValue ? -1 : 1;
}

function decimalEquals(left: string, right: string): boolean {
  return compareDecimalStrings(left, right) === 0;
}

function normalizeCategories(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map((entry) => {
      if (typeof entry === 'string') {
        return normalizeWhitespace(entry);
      }
      if (isPlainObject(entry)) {
        return normalizeStringValue(entry.slug ?? entry.name ?? entry.label);
      }
      return null;
    })
    .filter((entry): entry is string => Boolean(entry));
}

function normalizeSlug(value: unknown): string | null {
  const direct = normalizeStringValue(value);
  if (direct) {
    return direct;
  }
  if (typeof value !== 'string') {
    return null;
  }
  try {
    const parsed = new URL(value, DEFAULT_BITREFILL_BASE_URL);
    const segments = parsed.pathname.split('/').filter(Boolean);
    return segments.length > 0 ? segments[segments.length - 1] : null;
  } catch {
    return null;
  }
}

function normalizePackages(value: unknown): BitrefillProductPackage[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const packages: BitrefillProductPackage[] = [];
  for (const entry of value) {
    if (typeof entry === 'number' || typeof entry === 'string') {
      const normalizedValue = normalizeStringValue(entry);
      if (normalizedValue) {
        packages.push({
          id: normalizedValue,
          label: normalizeDecimalDisplay(normalizedValue),
          value: normalizeDecimalDisplay(normalizedValue),
        });
      }
      continue;
    }
    if (!isPlainObject(entry)) {
      continue;
    }
    const rawValue = normalizeStringValue(
      entry.valuePackage ?? entry.value ?? entry.amount ?? entry.price ?? entry.label,
    );
    if (!rawValue) {
      continue;
    }
    packages.push({
      id: normalizeStringValue(entry.id ?? entry._id ?? entry.packageId),
      label: normalizeStringValue(entry.label ?? entry.name ?? rawValue) ?? rawValue,
      value: normalizeDecimalDisplay(rawValue),
    });
  }
  return packages;
}

function decodeHtmlEntities(value: string): string {
  const namedEntities: Record<string, string> = {
    '&nbsp;': ' ',
    '&amp;': '&',
    '&lt;': '<',
    '&gt;': '>',
    '&quot;': '"',
    '&#39;': "'",
    '&apos;': "'",
    '&rsquo;': "'",
    '&lsquo;': "'",
    '&rdquo;': '"',
    '&ldquo;': '"',
    '&ndash;': '-',
    '&mdash;': '-',
    '&hellip;': '...',
  };
  let decoded = value.replace(
    /&(nbsp|amp|lt|gt|quot|apos|rsquo|lsquo|rdquo|ldquo|ndash|mdash|hellip|#39);/giu,
    (entity) => namedEntities[entity] ?? entity,
  );
  decoded = decoded.replace(/&#([0-9]+);/gu, (_match, code) =>
    String.fromCodePoint(Number.parseInt(code, 10)),
  );
  decoded = decoded.replace(/&#x([0-9a-f]+);/giu, (_match, code) =>
    String.fromCodePoint(Number.parseInt(code, 16)),
  );
  return decoded;
}

function htmlToPlainText(value: string): string | null {
  let normalized = value.trim();
  if (!normalized) {
    return null;
  }
  normalized = normalized
    .replace(/<\s*br\s*\/?>/giu, '\n')
    .replace(/<\s*li[^>]*>/giu, '\n- ')
    .replace(/<\s*\/\s*li\s*>/giu, '')
    .replace(/<\s*\/\s*(p|div|section|article|h[1-6]|ul|ol)\s*>/giu, '\n\n')
    .replace(/<[^>]+>/gu, '');
  normalized = decodeHtmlEntities(normalized)
    .replace(/\r\n?/gu, '\n')
    .replace(/[ \t]+\n/gu, '\n')
    .replace(/\n{3,}/gu, '\n\n');
  const lines = normalized
    .split('\n')
    .map((line) => line.replace(/[ \t]{2,}/gu, ' ').trim())
    .filter((line, index, entries) => line.length > 0 || (index > 0 && entries[index - 1] !== ''));
  return normalizeWhitespace(lines.join('\n'));
}

function firstLocalizedString(value: unknown): string | null {
  if (typeof value === 'string') {
    return htmlToPlainText(value);
  }
  if (!isPlainObject(value)) {
    return null;
  }
  for (const key of ['en', 'en-US', 'default', 'text', 'content']) {
    const candidate = value[key];
    if (typeof candidate === 'string') {
      const normalized = htmlToPlainText(candidate);
      if (normalized) {
        return normalized;
      }
    }
  }
  for (const candidate of Object.values(value)) {
    if (typeof candidate === 'string') {
      const normalized = htmlToPlainText(candidate);
      if (normalized) {
        return normalized;
      }
    }
  }
  return null;
}

function normalizeReviewDate(value: unknown): string | null {
  const normalized = normalizeStringValue(value);
  if (!normalized) {
    return null;
  }
  return normalized.includes('T') ? normalized.slice(0, 10) : normalized;
}

function normalizeProductReviews(value: unknown): BitrefillProductReview[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map((entry) => {
      if (!isPlainObject(entry)) {
        return null;
      }
      const content = firstLocalizedString(
        entry.content ?? entry.extract ?? entry.review ?? entry.comment ?? entry.text,
      );
      if (!content) {
        return null;
      }
      return {
        author: normalizeStringValue(entry.authorName ?? entry.author ?? entry.user),
        rating: normalizeNumberValue(entry.score ?? entry.rating ?? entry.ratingValue),
        maxRating: normalizeNumberValue(entry.scoreMax ?? entry.maxRating ?? entry.ratingMax),
        date: normalizeReviewDate(entry.date ?? entry.createdTime ?? entry.created_at),
        content,
      } satisfies BitrefillProductReview;
    })
    .filter((entry): entry is BitrefillProductReview => Boolean(entry));
}

function normalizeRange(value: unknown): BitrefillAmountRange | null {
  if (!isPlainObject(value)) {
    return null;
  }
  const min = normalizeStringValue(value.min ?? value.minimum ?? value.from);
  const max = normalizeStringValue(value.max ?? value.maximum ?? value.to);
  if (!min || !max) {
    return null;
  }
  const step = normalizeStringValue(value.step ?? value.increment);
  return {
    min: normalizeDecimalDisplay(min),
    max: normalizeDecimalDisplay(max),
    step: step ? normalizeDecimalDisplay(step) : undefined,
  };
}

function normalizeProductSummary(
  candidate: Record<string, unknown>,
): BitrefillProductSummary | null {
  const slug = normalizeSlug(candidate.slug ?? candidate.url ?? candidate.path ?? candidate.href);
  const name = normalizeStringValue(candidate.name ?? candidate.title ?? candidate.label);
  if (!slug || !name) {
    return null;
  }
  const packages = normalizePackages(
    candidate.packages ?? candidate.denominations ?? candidate.options,
  );
  const range = normalizeRange(candidate.range ?? candidate.valueRange ?? candidate.customAmount);
  return {
    slug,
    name,
    country: normalizeStringValue(candidate.country ?? candidate.countryCode),
    categories: normalizeCategories(candidate.categories),
    amountMode: range ? 'range' : packages.length > 0 ? 'fixed' : 'unknown',
  };
}

export function normalizeBitrefillSearchResults(payload: unknown): BitrefillProductSummary[] {
  return collectArrays(payload)
    .map((entry) => (isPlainObject(entry) ? normalizeProductSummary(entry) : null))
    .filter((entry): entry is BitrefillProductSummary => Boolean(entry));
}

export function normalizeBitrefillProductDetails(payload: unknown): BitrefillProductDetails {
  if (!isPlainObject(payload)) {
    throw new Error('Bitrefill product response was not an object');
  }
  const summary = normalizeProductSummary(payload);
  if (!summary) {
    throw new Error('Bitrefill product response did not include slug and name');
  }
  return {
    ...summary,
    currency: normalizeStringValue(payload.currency ?? payload.localFiatCurrency),
    description: firstLocalizedString(payload.descriptions ?? payload.description),
    instructions: firstLocalizedString(payload.instructions ?? payload.redeemInstructions),
    termsAndConditions: firstLocalizedString(payload.terms ?? payload.termsAndConditions),
    reviews: normalizeProductReviews(
      isPlainObject(payload.ratings) ? payload.ratings.reviews : payload.reviews,
    ),
    packages: normalizePackages(payload.packages ?? payload.denominations ?? payload.options),
    range: normalizeRange(payload.range ?? payload.valueRange ?? payload.customAmount),
    raw: payload,
  };
}

function normalizePaymentQuoteEntry(
  method: string,
  payload: unknown,
): BitrefillPaymentMethodQuote | null {
  const normalizedMethod = canonicalizeBitrefillPaymentMethod(method);
  const methodConfig = BITREFILL_METHOD_CONFIGS[normalizedMethod];
  if (payload === null || payload === undefined) {
    return null;
  }
  const candidate = isPlainObject(payload) ? payload : { amount: payload };
  return {
    method: methodConfig?.method ?? normalizedMethod,
    supported: Boolean(methodConfig),
    network: methodConfig?.networkSelector ?? null,
    chainId: methodConfig?.chainId ?? null,
    assetKind: methodConfig?.assetKind ?? 'unsupported',
    assetSymbol: methodConfig?.asset.symbol ?? null,
    tokenAddress: methodConfig?.tokenAddress ?? null,
    amount: normalizeStringValue(
      candidate.amount ??
        candidate.altcoinPrice ??
        candidate.total ??
        candidate.price ??
        candidate.payment_amount,
    ),
    amountBaseUnits: normalizeStringValue(
      candidate.amountBaseUnits ??
        candidate.altBasePrice ??
        candidate.base_amount ??
        candidate.raw_amount,
    ),
    fiatAmount: normalizeStringValue(
      candidate.fiatAmount ?? candidate.fiat_amount ?? candidate.usd,
    ),
    raw: payload,
  };
}

export function normalizeBitrefillCart(payload: unknown): BitrefillCart {
  if (!isPlainObject(payload)) {
    throw new Error('Bitrefill cart response was not an object');
  }
  const id = normalizeStringValue(payload.id ?? payload.cart_id);
  if (!id) {
    throw new Error('Bitrefill cart response did not include id');
  }

  const itemPayload = Array.isArray(payload.cart_items)
    ? payload.cart_items
    : Array.isArray(payload.items)
      ? payload.items
      : [];
  const items = itemPayload
    .map((entry) => {
      if (!isPlainObject(entry)) {
        return null;
      }
      return {
        operatorSlug: normalizeStringValue(
          entry.operator_slug ??
            entry.operatorSlug ??
            (isPlainObject(entry.operator) ? entry.operator._id : undefined),
        ),
        valuePackage: normalizeStringValue(
          entry.valuePackage ?? entry.value_package ?? entry.value ?? entry.amount,
        ),
        count: normalizeIntegerValue(entry.count ?? entry.qty ?? entry.quantity) ?? 1,
        isGift: normalizeBooleanValue(entry.isGift ?? entry.is_gift),
        raw: { ...entry },
      } satisfies BitrefillCartItem;
    })
    .filter((entry): entry is BitrefillCartItem => Boolean(entry));

  const paymentMethodInfo = payload.payment_methods_info;
  const paymentMethodQuotes = (
    Array.isArray(paymentMethodInfo)
      ? paymentMethodInfo.flatMap((entry) => {
          if (!isPlainObject(entry)) {
            return [];
          }
          const method = normalizeStringValue(entry.method ?? entry.name);
          return method ? [normalizePaymentQuoteEntry(method, entry)] : [];
        })
      : isPlainObject(paymentMethodInfo)
        ? Object.entries(paymentMethodInfo).map(([method, value]) =>
            normalizePaymentQuoteEntry(method, value),
          )
        : []
  ).filter((entry): entry is BitrefillPaymentMethodQuote => Boolean(entry));
  const dedupedPaymentMethodQuotes: BitrefillPaymentMethodQuote[] = [];
  const seenPaymentMethods = new Set<string>();
  for (const entry of paymentMethodQuotes) {
    if (seenPaymentMethods.has(entry.method)) {
      continue;
    }
    seenPaymentMethods.add(entry.method);
    dedupedPaymentMethodQuotes.push(entry);
  }

  return {
    id,
    items,
    paymentMethodQuotes: dedupedPaymentMethodQuotes,
    raw: payload,
  };
}

function normalizeOrderSummary(value: unknown): BitrefillOrderSummary | null {
  if (!isPlainObject(value)) {
    return null;
  }
  return {
    id: normalizeStringValue(value.id ?? value._id ?? value.orderId),
    status: normalizeStringValue(value.status ?? value.state),
    raw: value,
  };
}

function extractAccessToken(payload: Record<string, unknown>): string | null {
  return normalizeStringValue(
    payload.accessToken ??
      payload.access_token ??
      payload.invoiceAccessToken ??
      payload.invoice_access_token ??
      payload.token,
  );
}

function normalizeInvoiceStatus(value: unknown): string {
  return normalizeStringValue(value)?.toLowerCase() ?? 'unknown';
}

export function normalizeBitrefillInvoice(
  payload: unknown,
  input: { accessToken?: string | null } = {},
): BitrefillInvoice {
  if (!isPlainObject(payload)) {
    throw new Error('Bitrefill invoice response was not an object');
  }
  const id = normalizeStringValue(payload.id ?? payload.invoice_id);
  if (!id) {
    throw new Error('Bitrefill invoice response did not include id');
  }
  const payment = isPlainObject(payload.payment) ? payload.payment : {};
  return {
    id,
    accessToken: extractAccessToken(payload) ?? normalizeWhitespace(input.accessToken ?? null),
    cartId: normalizeStringValue(payload.cart_id ?? payload.cartId),
    status: normalizeInvoiceStatus(payload.status),
    paymentMethod: (() => {
      const method = normalizeStringValue(payload.paymentMethod ?? payload.payment_method);
      return method ? canonicalizeBitrefillPaymentMethod(method) : null;
    })(),
    paymentCurrency: normalizeStringValue(payload.payment_currency ?? payload.paymentCurrency),
    price: normalizeStringValue(payload.price),
    subtotal: normalizeStringValue(payload.subtotal),
    expirationTime: normalizeStringValue(payload.expirationTime ?? payload.expires_at),
    invoiceTimeLeft: normalizeIntegerValue(payload.invoiceTimeLeft ?? payload.invoice_time_left),
    paymentReceived: normalizeStringValue(payload.paymentReceived ?? payload.payment_received),
    orders: Array.isArray(payload.orders)
      ? payload.orders
          .map((entry) => normalizeOrderSummary(entry))
          .filter((entry): entry is BitrefillOrderSummary => Boolean(entry))
      : [],
    payment: {
      address: normalizeStringValue(payment.address ?? payment.paymentAddress),
      paymentUri: normalizeStringValue(payment.paymentUri ?? payment.payment_uri ?? payment.uri),
      altcoinPrice: normalizeStringValue(
        payment.altcoinPrice ?? payment.altcoin_price ?? payment.amount,
      ),
      altBasePrice: normalizeStringValue(
        payment.altBasePrice ?? payment.alt_base_price ?? payment.amountBaseUnits,
      ),
      contractAddress: normalizeStringValue(
        payment.contractAddress ?? payment.contract_address ?? payment.tokenAddress,
      ),
    },
    raw: payload,
  };
}

function normalizeHeaders(headers: Record<string, string>): Record<string, string> {
  const normalized: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    normalized[key.toLowerCase()] = value;
  }
  return normalized;
}

function resolveBitrefillBaseUrl(value: string | undefined): string {
  return assertSafeRpcUrl(value?.trim() || DEFAULT_BITREFILL_BASE_URL, 'bitrefillBaseUrl');
}

function resolveBitrefillPluginStateDir(): string {
  const pluginDir = path.join(ensureAgentPayHome(), 'plugins', 'bitrefill');
  fs.mkdirSync(pluginDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(pluginDir, 0o700);
  return pluginDir;
}

export function resolveBitrefillCookieJarPath(): string {
  const pluginDir = resolveBitrefillPluginStateDir();
  const cookieJarPath = path.join(pluginDir, 'cookies.txt');
  if (!fs.existsSync(cookieJarPath)) {
    fs.writeFileSync(cookieJarPath, '', { mode: 0o600 });
  }
  fs.chmodSync(cookieJarPath, 0o600);
  return cookieJarPath;
}

export function resolveBitrefillInvoiceAccessTokenStorePath(): string {
  const pluginDir = resolveBitrefillPluginStateDir();
  const storePath = path.join(pluginDir, BITREFILL_INVOICE_ACCESS_TOKEN_STORE_FILE);
  if (!fs.existsSync(storePath)) {
    fs.writeFileSync(storePath, '{}\n', { mode: 0o600 });
  }
  fs.chmodSync(storePath, 0o600);
  return storePath;
}

function normalizeBitrefillInvoiceAccessTokenStore(
  value: unknown,
): Record<string, StoredBitrefillInvoiceAccessTokenEntry> {
  if (!isPlainObject(value)) {
    return {};
  }
  const output: Record<string, StoredBitrefillInvoiceAccessTokenEntry> = {};
  for (const [invoiceId, entry] of Object.entries(value)) {
    if (!isPlainObject(entry)) {
      continue;
    }
    const accessToken = normalizeStringValue(entry.accessToken);
    if (!accessToken) {
      continue;
    }
    output[invoiceId] = {
      accessToken,
      updatedAt: normalizeStringValue(entry.updatedAt) ?? new Date(0).toISOString(),
    };
  }
  return output;
}

function readBitrefillInvoiceAccessTokenStoreEntries(): Record<
  string,
  StoredBitrefillInvoiceAccessTokenEntry
> {
  const storePath = resolveBitrefillInvoiceAccessTokenStorePath();
  try {
    const raw = fs.readFileSync(storePath, 'utf8');
    const parsed = raw.trim() ? JSON.parse(raw) : {};
    return normalizeBitrefillInvoiceAccessTokenStore(parsed);
  } catch {
    return {};
  }
}

function writeBitrefillInvoiceAccessTokenStoreEntries(
  entries: Record<string, StoredBitrefillInvoiceAccessTokenEntry>,
): void {
  const storePath = resolveBitrefillInvoiceAccessTokenStorePath();
  fs.writeFileSync(storePath, `${JSON.stringify(entries, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(storePath, 0o600);
}

export function rememberBitrefillInvoiceAccessToken(input: {
  invoiceId: string;
  accessToken: string;
}): void {
  const invoiceId = normalizeStringValue(input.invoiceId);
  const accessToken = normalizeStringValue(input.accessToken);
  if (!invoiceId || !accessToken) {
    return;
  }
  const entries = readBitrefillInvoiceAccessTokenStoreEntries();
  entries[invoiceId] = {
    accessToken,
    updatedAt: new Date().toISOString(),
  };
  writeBitrefillInvoiceAccessTokenStoreEntries(entries);
}

export function findBitrefillInvoiceAccessToken(invoiceId: string): string | null {
  const normalizedInvoiceId = normalizeStringValue(invoiceId);
  if (!normalizedInvoiceId) {
    return null;
  }
  const entry = readBitrefillInvoiceAccessTokenStoreEntries()[normalizedInvoiceId];
  return entry?.accessToken ?? null;
}

export function listStoredBitrefillInvoices(): StoredBitrefillInvoiceSummary[] {
  return Object.entries(readBitrefillInvoiceAccessTokenStoreEntries())
    .map(([invoiceId, entry]) => ({
      invoiceId,
      accessTokenStored: true as const,
      updatedAt: entry.updatedAt,
    }))
    .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
}

function resolveBitrefillBrowserExecutablePath(): string {
  const explicitPath = process.env.AGENTPAY_BITREFILL_BROWSER_EXECUTABLE_PATH?.trim();
  const candidates = explicitPath
    ? [explicitPath]
    : process.platform === 'darwin'
      ? [
          '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
          '/Applications/Chromium.app/Contents/MacOS/Chromium',
          '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',
          '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
        ]
      : process.platform === 'win32'
        ? [
            ...(process.env.PROGRAMFILES
              ? [
                  path.join(
                    process.env.PROGRAMFILES,
                    'Google',
                    'Chrome',
                    'Application',
                    'chrome.exe',
                  ),
                ]
              : []),
            ...(process.env['PROGRAMFILES(X86)']
              ? [
                  path.join(
                    process.env['PROGRAMFILES(X86)'],
                    'Google',
                    'Chrome',
                    'Application',
                    'chrome.exe',
                  ),
                ]
              : []),
            ...(process.env.LOCALAPPDATA
              ? [
                  path.join(
                    process.env.LOCALAPPDATA,
                    'Google',
                    'Chrome',
                    'Application',
                    'chrome.exe',
                  ),
                ]
              : []),
          ]
        : [
            '/usr/bin/google-chrome',
            '/usr/bin/google-chrome-stable',
            '/usr/bin/chromium-browser',
            '/usr/bin/chromium',
            '/usr/bin/brave-browser',
            '/usr/bin/microsoft-edge',
          ];

  for (const candidate of candidates) {
    if (candidate && fs.existsSync(candidate)) {
      return candidate;
    }
  }

  throw new Error(
    'Could not find a Chrome/Chromium browser for Bitrefill bootstrap; set AGENTPAY_BITREFILL_BROWSER_EXECUTABLE_PATH',
  );
}

export function shouldAutoBootstrapBitrefillSession(baseUrl: string): boolean {
  if (process.env.AGENTPAY_BITREFILL_SKIP_BOOTSTRAP === '1') {
    return false;
  }

  try {
    const parsed = new URL(baseUrl);
    return parsed.hostname === 'bitrefill.com' || parsed.hostname.endsWith('.bitrefill.com');
  } catch {
    return false;
  }
}

export function writeBitrefillCookiesToCookieJar(
  cookies: BitrefillBrowserCookie[],
  cookieJarPath: string,
): void {
  fs.mkdirSync(path.dirname(cookieJarPath), { recursive: true, mode: 0o700 });
  const lines = ['# Netscape HTTP Cookie File'];
  for (const cookie of cookies) {
    lines.push(
      [
        cookie.domain,
        cookie.domain.startsWith('.') ? 'TRUE' : 'FALSE',
        cookie.path || '/',
        cookie.secure ? 'TRUE' : 'FALSE',
        String(cookie.expires > 0 ? Math.floor(cookie.expires) : 0),
        cookie.name,
        cookie.value,
      ].join('\t'),
    );
  }
  fs.writeFileSync(cookieJarPath, `${lines.join('\n')}\n`, { mode: 0o600 });
  fs.chmodSync(cookieJarPath, 0o600);
}

export function readBitrefillCookiesFromCookieJar(cookieJarPath: string): BitrefillBrowserCookie[] {
  if (!fs.existsSync(cookieJarPath)) {
    return [];
  }

  return fs
    .readFileSync(cookieJarPath, 'utf8')
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .flatMap((line) => {
      const fields = line.split('\t');
      if (fields.length < 7) {
        return [];
      }
      const [domain, _includeSubdomains, rawPath, rawSecure, rawExpires, name, value] = fields;
      const expires = Number(rawExpires);
      return [
        {
          domain,
          path: rawPath || '/',
          secure: rawSecure.toUpperCase() === 'TRUE',
          expires: Number.isFinite(expires) ? expires : 0,
          name,
          value,
        } satisfies BitrefillBrowserCookie,
      ];
    });
}

async function bootstrapBitrefillBrowserSession(input: {
  baseUrl: string;
  cookieJarPath: string;
}): Promise<void> {
  const executablePath = resolveBitrefillBrowserExecutablePath();
  const bootstrapUrl = new URL('/', input.baseUrl).toString();
  const headless = process.env.AGENTPAY_BITREFILL_BOOTSTRAP_HEADLESS === '1';
  const timeoutMs = Number(process.env.AGENTPAY_BITREFILL_BOOTSTRAP_TIMEOUT_MS ?? '');
  const resolvedTimeoutMs =
    Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : DEFAULT_BOOTSTRAP_TIMEOUT_MS;

  console.error(`Bootstrapping Bitrefill browser session via ${executablePath}`);
  if (!headless) {
    console.error(
      `A browser window may open for Bitrefill. Complete any challenge there; waiting up to ${Math.ceil(resolvedTimeoutMs / 1000)}s.`,
    );
  }

  const browser = await chromium.launch({
    executablePath,
    headless,
  });

  try {
    const context = await browser.newContext();
    try {
      const existingCookies = readBitrefillCookiesFromCookieJar(input.cookieJarPath);
      if (existingCookies.length > 0) {
        await context.addCookies(
          existingCookies.map((cookie) => ({
            name: cookie.name,
            value: cookie.value,
            domain: cookie.domain,
            path: cookie.path,
            secure: cookie.secure,
            ...(cookie.expires > 0 ? { expires: cookie.expires } : {}),
          })),
        );
      }

      const page = await context.newPage();
      await page.goto(bootstrapUrl, {
        waitUntil: 'domcontentloaded',
        timeout: DEFAULT_REQUEST_TIMEOUT_MS,
      });

      const started = Date.now();
      for (;;) {
        const cookies = (await context.cookies())
          .filter((cookie) => cookie.domain.includes('bitrefill.com'))
          .map((cookie) => ({
            name: cookie.name,
            value: cookie.value,
            domain: cookie.domain,
            path: cookie.path,
            expires: cookie.expires,
            secure: cookie.secure,
          }));
        const title = (await page.title()).toLowerCase();
        if (cookies.length > 0 && !title.includes('just a moment')) {
          writeBitrefillCookiesToCookieJar(cookies, input.cookieJarPath);
          console.error(`Bitrefill browser session saved to ${input.cookieJarPath}`);
          return;
        }

        if (Date.now() - started >= resolvedTimeoutMs) {
          throw new Error(
            `Timed out after ${Math.ceil(resolvedTimeoutMs / 1000)}s waiting for Bitrefill browser bootstrap`,
          );
        }

        await page.waitForTimeout(DEFAULT_BOOTSTRAP_POLL_INTERVAL_MS);
      }
    } finally {
      await context.close();
    }
  } finally {
    await browser.close();
  }
}

function shouldTreatAsChallenge(response: BitrefillHttpResponse<unknown>): boolean {
  const headerValue = response.headers[BITREFILL_CHALLENGE_HEADER];
  if (headerValue?.toLowerCase() === BITREFILL_CHALLENGE_HEADER_VALUE) {
    return true;
  }
  if (typeof response.data !== 'string') {
    return false;
  }
  const lower = response.data.toLowerCase();
  return lower.includes('just a moment') || lower.includes('_cf_chl_opt');
}

function extractInvoiceIdFromUnknown(payload: unknown): string | null {
  if (!isPlainObject(payload)) {
    return null;
  }
  return normalizeStringValue(payload.invoiceId ?? payload.invoice_id ?? payload.id);
}

function extractAccessTokenFromUnknown(payload: unknown): string | null {
  if (!isPlainObject(payload)) {
    return null;
  }
  return extractAccessToken(payload);
}

function isChallengePayload(payload: unknown): boolean {
  if (typeof payload === 'string') {
    const lower = payload.toLowerCase();
    return lower.includes('challenge') || lower.includes('captcha');
  }
  if (!isPlainObject(payload)) {
    return false;
  }
  const joined = JSON.stringify(payload).toLowerCase();
  return (
    joined.includes('invoice_creation_challenge') ||
    joined.includes('captcha') ||
    joined.includes('challenge')
  );
}

export function createCuimpBitrefillTransport(
  input: { baseUrl?: string; cookieJarPath?: string } = {},
): BitrefillHttpTransport {
  const client = createCuimpHttp({
    descriptor: { browser: 'chrome' },
    cookieJar: input.cookieJarPath ?? resolveBitrefillCookieJarPath(),
  });
  const baseUrl = resolveBitrefillBaseUrl(input.baseUrl);
  return {
    async request<T>(request: BitrefillHttpRequest): Promise<BitrefillHttpResponse<T>> {
      try {
        const response = await client.request<T>({
          baseURL: baseUrl,
          url: request.pathname,
          method: request.method,
          params: request.query,
          headers: {
            Accept: 'application/json',
            Referer: `${baseUrl}/`,
            ...request.headers,
          },
          data: request.body as never,
          timeout: request.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
          maxRedirects: 5,
        });
        const normalized = {
          status: response.status,
          headers: normalizeHeaders(response.headers),
          data: response.data,
        };
        if (shouldTreatAsChallenge(normalized)) {
          throw new BitrefillChallengeRequiredError({
            status: 'challenge_required',
            message: 'Bitrefill requested a Cloudflare or captcha challenge',
            invoiceId: extractInvoiceIdFromUnknown(normalized.data),
            accessToken: extractAccessTokenFromUnknown(normalized.data),
            details: normalized.data,
          });
        }
        return normalized;
      } catch (error) {
        if (error instanceof BitrefillChallengeRequiredError) {
          throw error;
        }
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(`Bitrefill cuimp transport failed: ${message}`);
      }
    },
    destroy() {
      client.destroy();
    },
  };
}

export function createFetchBitrefillTransport(
  input: { baseUrl?: string } = {},
): BitrefillHttpTransport {
  const baseUrl = resolveBitrefillBaseUrl(input.baseUrl);
  return {
    async request<T>(request: BitrefillHttpRequest): Promise<BitrefillHttpResponse<T>> {
      const url = new URL(request.pathname, baseUrl);
      for (const [key, value] of Object.entries(request.query ?? {})) {
        if (value !== undefined) {
          url.searchParams.set(key, String(value));
        }
      }
      const response = await fetch(url, {
        method: request.method,
        headers: {
          Accept: 'application/json',
          ...(request.body ? { 'Content-Type': 'application/json' } : {}),
          ...request.headers,
        },
        body:
          request.body === undefined
            ? undefined
            : request.body instanceof URLSearchParams
              ? request.body
              : typeof request.body === 'string'
                ? request.body
                : JSON.stringify(request.body),
      });
      const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
      const rawBody = await response.text();
      const data = contentType.includes('application/json') ? JSON.parse(rawBody) : rawBody;
      const headers: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        headers[key] = value;
      });
      const normalized = {
        status: response.status,
        headers: normalizeHeaders(headers),
        data: data as T,
      };
      if (shouldTreatAsChallenge(normalized)) {
        throw new BitrefillChallengeRequiredError({
          status: 'challenge_required',
          message: 'Bitrefill requested a Cloudflare or captcha challenge',
          invoiceId: extractInvoiceIdFromUnknown(normalized.data),
          accessToken: extractAccessTokenFromUnknown(normalized.data),
          details: normalized.data,
        });
      }
      return normalized;
    },
  };
}

function createDefaultTransport(): BitrefillHttpTransport {
  const transportKind = (process.env.AGENTPAY_BITREFILL_TRANSPORT ?? 'cuimp').trim().toLowerCase();
  if (transportKind === 'fetch') {
    return createFetchBitrefillTransport({
      baseUrl: process.env.AGENTPAY_BITREFILL_BASE_URL,
    });
  }
  if (transportKind !== 'cuimp') {
    throw new Error(`Unsupported Bitrefill transport '${transportKind}'`);
  }
  return createCuimpBitrefillTransport({
    baseUrl: process.env.AGENTPAY_BITREFILL_BASE_URL,
    cookieJarPath: process.env.AGENTPAY_BITREFILL_COOKIE_JAR_PATH ?? undefined,
  });
}

function assertSuccessfulResponse(response: BitrefillHttpResponse<unknown>, label: string): void {
  if (response.status >= 200 && response.status < 300) {
    return;
  }
  if (isChallengePayload(response.data)) {
    throw new BitrefillChallengeRequiredError({
      status: 'challenge_required',
      message: `Bitrefill blocked ${label} with a challenge`,
      invoiceId: extractInvoiceIdFromUnknown(response.data),
      accessToken: extractAccessTokenFromUnknown(response.data),
      details: response.data,
    });
  }
  throw new Error(`${label} failed with HTTP ${response.status}`);
}

export function assertSupportedBitrefillPaymentMethod(method: string): string {
  const normalized = canonicalizeBitrefillPaymentMethod(method);
  if (!BITREFILL_METHOD_CONFIGS[normalized]) {
    throw new Error(
      `payment method '${method}' is not supported; choose one of ${BITREFILL_SUPPORTED_EVM_METHODS.join(', ')}`,
    );
  }
  return normalized;
}

export function resolveBitrefillMethodConfig(method: string): BitrefillMethodConfig {
  const normalized = assertSupportedBitrefillPaymentMethod(method);
  return BITREFILL_METHOD_CONFIGS[normalized];
}

export function validateBitrefillProductAmount(
  product: BitrefillProductDetails,
  amount: string,
): string {
  const normalizedAmount = normalizeDecimalDisplay(amount);
  if (product.range) {
    if (
      compareDecimalStrings(normalizedAmount, product.range.min) < 0 ||
      compareDecimalStrings(normalizedAmount, product.range.max) > 0
    ) {
      throw new Error(
        `amount ${normalizedAmount} is outside the allowed range ${product.range.min}..${product.range.max}`,
      );
    }
    return normalizedAmount;
  }

  if (product.packages.length > 0) {
    const matches = product.packages.some((entry) => decimalEquals(entry.value, normalizedAmount));
    if (!matches) {
      throw new Error(
        `amount ${normalizedAmount} is not available for '${product.slug}'; choose one of ${product.packages.map((entry) => entry.value).join(', ')}`,
      );
    }
    return normalizedAmount;
  }

  return normalizedAmount;
}

function buildInvoiceItemsFromCart(cart: BitrefillCart): Array<Record<string, unknown>> {
  return cart.items.map((entry) => ({
    operatorSlug: entry.operatorSlug,
    valuePackage: entry.valuePackage,
    count: entry.count,
    isGift: entry.isGift,
  }));
}

function buildInvoiceCartItemsFromCart(cart: BitrefillCart): Array<Record<string, unknown>> {
  return cart.items.map((entry) => ({
    ...entry.raw,
    operator_slug:
      normalizeStringValue(entry.raw.operator_slug ?? entry.raw.operatorSlug) ?? entry.operatorSlug,
    valuePackage:
      normalizeStringValue(entry.raw.valuePackage ?? entry.raw.value_package ?? entry.raw.value) ??
      entry.valuePackage,
    count:
      normalizeIntegerValue(entry.raw.count ?? entry.raw.qty ?? entry.raw.quantity) ?? entry.count,
    isGift: normalizeBooleanValue(entry.raw.isGift ?? entry.raw.is_gift) || entry.isGift,
    operator: undefined,
  }));
}

export class BitrefillClient {
  private readonly transport: BitrefillHttpTransport;
  private readonly baseUrl: string;
  private readonly cookieJarPath: string;
  private bootstrapPromise: Promise<void> | null = null;

  constructor(transport: BitrefillHttpTransport = createDefaultTransport()) {
    this.transport = transport;
    this.baseUrl = resolveBitrefillBaseUrl(process.env.AGENTPAY_BITREFILL_BASE_URL);
    this.cookieJarPath =
      process.env.AGENTPAY_BITREFILL_COOKIE_JAR_PATH ?? resolveBitrefillCookieJarPath();
  }

  destroy(): void {
    this.transport.destroy?.();
  }

  private async bootstrapAfterChallenge(): Promise<boolean> {
    if (!shouldAutoBootstrapBitrefillSession(this.baseUrl)) {
      return false;
    }
    if (!this.bootstrapPromise) {
      this.bootstrapPromise = (async () => {
        await bootstrapBitrefillBrowserSession({
          baseUrl: this.baseUrl,
          cookieJarPath: this.cookieJarPath,
        });
      })().finally(() => {
        this.bootstrapPromise = null;
      });
    }
    await this.bootstrapPromise;
    return true;
  }

  private async request<T = unknown>(
    input: BitrefillHttpRequest,
  ): Promise<BitrefillHttpResponse<T>> {
    try {
      return await this.transport.request<T>(input);
    } catch (error) {
      if (!(error instanceof BitrefillChallengeRequiredError)) {
        throw error;
      }
      const bootstrapped = await this.bootstrapAfterChallenge();
      if (!bootstrapped) {
        throw error;
      }
      return this.transport.request<T>(input);
    }
  }

  async search(query: string): Promise<BitrefillProductSummary[]> {
    const normalizedQuery = query.trim();
    if (!normalizedQuery) {
      throw new Error('query is required');
    }
    const response = await this.request<unknown>({
      method: 'GET',
      pathname: '/api/omni',
      query: {
        q: normalizedQuery,
        country: 'US',
        hl: 'en',
        s_oos_last: 1,
        limit: 40,
        hardlimit: 40,
        skip: 0,
        src: 'browse',
        rec: 1,
        prefcc: 1,
        do_recommend: 1,
      },
    });
    assertSuccessfulResponse(response, 'Bitrefill search');
    const results = normalizeBitrefillSearchResults(response.data);
    if (results.length > 0) {
      return results;
    }
    const fallback = await this.request<unknown>({
      method: 'GET',
      pathname: '/api/omni',
      query: {
        q: normalizedQuery,
        cart: '',
        col: 1,
        country: 'US',
        do_recommend: 1,
        hl: 'en',
        limit: 6,
        prefcc: 1,
        rec: 1,
        sec: 1,
        skip: 0,
        src: 'omni',
      },
    });
    assertSuccessfulResponse(fallback, 'Bitrefill omni search');
    return normalizeBitrefillSearchResults(fallback.data);
  }

  async getProduct(slug: string): Promise<BitrefillProductDetails> {
    const normalizedSlug = slug.trim();
    if (!normalizedSlug) {
      throw new Error('slug is required');
    }
    const response = await this.request<unknown>({
      method: 'GET',
      pathname: `/api/product/${normalizedSlug}`,
    });
    assertSuccessfulResponse(response, 'Bitrefill product lookup');
    return normalizeBitrefillProductDetails(response.data);
  }

  async getPrice(input: {
    slug: string;
    amount: string;
    paymentCurrency?: string;
  }): Promise<BitrefillCart> {
    return this.createCart(input);
  }

  async createCart(input: {
    slug: string;
    amount: string;
    paymentCurrency?: string;
    localFiatCurrency?: string;
  }): Promise<BitrefillCart> {
    const amount = normalizeDecimalDisplay(input.amount);
    const currency = normalizeWhitespace(input.paymentCurrency) ?? 'USD';
    const localFiatCurrency = normalizeWhitespace(input.localFiatCurrency) ?? currency;
    const response = await this.request<unknown>({
      method: 'POST',
      pathname: '/api/accounts/cart',
      query: {
        currency,
        localFiatCurrency,
      },
      body: {
        cart_id: randomUUID(),
        slug: input.slug.trim(),
        count: 1,
        value: amount,
        is_gift: false,
      },
    });
    assertSuccessfulResponse(response, 'Bitrefill cart creation');
    return normalizeBitrefillCart(response.data);
  }

  async getCart(input: {
    cartId: string;
    paymentCurrency?: string;
    localFiatCurrency?: string;
  }): Promise<BitrefillCart> {
    const currency = normalizeWhitespace(input.paymentCurrency) ?? 'USD';
    const localFiatCurrency = normalizeWhitespace(input.localFiatCurrency) ?? currency;
    const response = await this.request<unknown>({
      method: 'GET',
      pathname: `/api/accounts/cart/${input.cartId}`,
      query: {
        currency,
        localFiatCurrency,
      },
    });
    assertSuccessfulResponse(response, 'Bitrefill cart lookup');
    return normalizeBitrefillCart(response.data);
  }

  async createInvoice(input: {
    cart: BitrefillCart;
    email: string;
    paymentMethod: string;
  }): Promise<BitrefillInvoice> {
    const methodConfig = resolveBitrefillMethodConfig(input.paymentMethod);
    const email = normalizeWhitespace(input.email);
    if (!email) {
      throw new Error('email is required');
    }

    const response = await this.request<unknown>({
      method: 'POST',
      pathname: '/api/accounts/invoice',
      body: {
        captchaResponse: '',
        cart_id: input.cart.id,
        cart_items: buildInvoiceCartItemsFromCart(input.cart),
        items: buildInvoiceItemsFromCart(input.cart),
        email,
        paymentMethod: methodConfig.requestMethod ?? methodConfig.method,
        paymentCurrency: methodConfig.paymentCurrency,
        couponCode: '',
        isSubscribing: false,
        unsealAll: false,
        isQuickBuy: true,
        user_source: 'agentpay',
        user_source_platform: 'cli',
        userTimezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      },
    });
    assertSuccessfulResponse(response, 'Bitrefill invoice creation');
    if (isChallengePayload(response.data)) {
      throw new BitrefillChallengeRequiredError({
        status: 'challenge_required',
        message: 'Bitrefill invoice creation requires a challenge to be completed first',
        invoiceId: extractInvoiceIdFromUnknown(response.data),
        accessToken: extractAccessTokenFromUnknown(response.data),
        details: response.data,
      });
    }
    const invoice = normalizeBitrefillInvoice(response.data);
    if (invoice.accessToken) {
      rememberBitrefillInvoiceAccessToken({
        invoiceId: invoice.id,
        accessToken: invoice.accessToken,
      });
    }
    return invoice;
  }

  async getInvoice(input: {
    invoiceId: string;
    accessToken: string;
    source?: string;
  }): Promise<BitrefillInvoice> {
    const response = await this.request<unknown>({
      method: 'GET',
      pathname: `/api/accounts/invoice/${input.invoiceId}`,
      query: {
        accessToken: input.accessToken,
        source: input.source ?? 'action',
      },
    });
    assertSuccessfulResponse(response, 'Bitrefill invoice lookup');
    const invoice = normalizeBitrefillInvoice(response.data, { accessToken: input.accessToken });
    if (invoice.accessToken) {
      rememberBitrefillInvoiceAccessToken({
        invoiceId: invoice.id,
        accessToken: invoice.accessToken,
      });
    }
    return invoice;
  }

  async waitForInvoice(input: {
    invoiceId: string;
    accessToken: string;
    timeoutMs?: number;
    intervalMs?: number;
  }): Promise<BitrefillInvoiceWaitResult> {
    const timeoutMs = input.timeoutMs ?? DEFAULT_WAIT_TIMEOUT_MS;
    const intervalMs = input.intervalMs ?? DEFAULT_WAIT_INTERVAL_MS;
    const started = Date.now();
    let latest = await this.getInvoice({
      invoiceId: input.invoiceId,
      accessToken: input.accessToken,
      source: 'action',
    });

    while (!isBitrefillInvoiceTerminal(latest.status)) {
      if (Date.now() - started >= timeoutMs) {
        return { invoice: latest, timedOut: true };
      }
      await sleep(intervalMs);
      latest = await this.getInvoice({
        invoiceId: input.invoiceId,
        accessToken: input.accessToken,
        source: 'action',
      });
    }

    return { invoice: latest, timedOut: false };
  }
}

export function createBitrefillClient(transport?: BitrefillHttpTransport): BitrefillClient {
  return new BitrefillClient(transport);
}

export function listSupportedBitrefillPaymentQuotes(
  cart: BitrefillCart,
): BitrefillPaymentMethodQuote[] {
  return [...cart.paymentMethodQuotes]
    .filter((entry) => entry.supported)
    .sort((left, right) => compareBitrefillMethodPriority(left.method, right.method));
}

export function resolveBitrefillPaymentQuote(
  cart: BitrefillCart,
  paymentMethod: string,
): BitrefillPaymentMethodQuote {
  const normalizedMethod = assertSupportedBitrefillPaymentMethod(paymentMethod);
  const quote = cart.paymentMethodQuotes.find((entry) => entry.method === normalizedMethod);
  if (!quote) {
    throw new Error(
      `payment method '${normalizedMethod}' is not available for this cart; available EVM methods: ${
        listSupportedBitrefillPaymentQuotes(cart)
          .map((entry) => entry.method)
          .join(', ') || 'none'
      }`,
    );
  }
  return quote;
}

function normalizeEvmAddress(value: string, label: string): Address {
  if (!isAddress(value)) {
    throw new Error(`${label} must be a valid EVM address`);
  }
  return value as Address;
}

function parseAmountBaseUnits(invoice: BitrefillInvoice, config: BitrefillMethodConfig): bigint {
  const altBasePrice = normalizeStringValue(invoice.payment.altBasePrice);
  if (altBasePrice && /^(0|[1-9][0-9]*)$/u.test(altBasePrice)) {
    return BigInt(altBasePrice);
  }

  const altcoinPrice = normalizeStringValue(invoice.payment.altcoinPrice);
  if (!altcoinPrice) {
    throw new Error(`Bitrefill invoice '${invoice.id}' did not include payment amount`);
  }
  return parseConfiguredAmount(altcoinPrice, config.asset.decimals, 'invoice payment amount');
}

export function resolveBitrefillInvoicePayment(
  invoice: BitrefillInvoice,
): ResolvedBitrefillInvoicePayment {
  const paymentMethod = invoice.paymentMethod
    ? assertSupportedBitrefillPaymentMethod(invoice.paymentMethod)
    : null;
  if (!paymentMethod) {
    throw new Error(`Bitrefill invoice '${invoice.id}' did not include paymentMethod`);
  }

  const methodConfig = resolveBitrefillMethodConfig(paymentMethod);
  const recipient = normalizeStringValue(invoice.payment.address);
  if (!recipient) {
    throw new Error(`Bitrefill invoice '${invoice.id}' did not include payment recipient address`);
  }
  const recipientAddress = normalizeEvmAddress(recipient, 'Bitrefill invoice payment address');
  const amountBaseUnits = parseAmountBaseUnits(invoice, methodConfig);

  if (methodConfig.assetKind === 'native') {
    return {
      method: methodConfig.method,
      networkSelector: methodConfig.networkSelector,
      chainId: methodConfig.chainId,
      assetKind: 'native',
      asset: methodConfig.asset,
      recipient: recipientAddress,
      tokenAddress: null,
      amountBaseUnits,
      amount: formatConfiguredAmount(amountBaseUnits, methodConfig.asset.decimals),
      paymentUri: normalizeStringValue(invoice.payment.paymentUri),
      broadcastTo: recipientAddress,
      valueWei: amountBaseUnits,
      dataHex: '0x',
    };
  }

  const contractAddress = normalizeStringValue(invoice.payment.contractAddress);
  if (!contractAddress) {
    throw new Error(`Bitrefill invoice '${invoice.id}' did not include token contract address`);
  }
  const tokenAddress = normalizeEvmAddress(contractAddress, 'Bitrefill invoice token contract');
  if (
    methodConfig.tokenAddress &&
    tokenAddress.toLowerCase() !== methodConfig.tokenAddress.toLowerCase()
  ) {
    throw new Error(
      `Bitrefill invoice '${invoice.id}' contract mismatch for ${methodConfig.method}: expected ${methodConfig.tokenAddress}, got ${tokenAddress}`,
    );
  }

  return {
    method: methodConfig.method,
    networkSelector: methodConfig.networkSelector,
    chainId: methodConfig.chainId,
    assetKind: 'erc20',
    asset: methodConfig.asset,
    recipient: recipientAddress,
    tokenAddress,
    amountBaseUnits,
    amount: formatConfiguredAmount(amountBaseUnits, methodConfig.asset.decimals),
    paymentUri: normalizeStringValue(invoice.payment.paymentUri),
    broadcastTo: tokenAddress,
    valueWei: 0n,
    dataHex: encodeErc20TransferData(recipientAddress, amountBaseUnits),
  };
}

export function buildBitrefillBuyPreview(input: {
  product: Pick<BitrefillProductDetails, 'slug' | 'name'>;
  amount: string;
  invoice: BitrefillInvoice;
  cart: BitrefillCart;
}): BitrefillBuyPreview {
  const resolvedPayment = resolveBitrefillInvoicePayment(input.invoice);
  return {
    mode: 'preview',
    product: {
      slug: input.product.slug,
      name: input.product.name,
      amount: normalizeDecimalDisplay(input.amount),
    },
    invoice: {
      id: input.invoice.id,
      accessToken: input.invoice.accessToken,
      status: input.invoice.status,
      cartId: input.invoice.cartId,
      expirationTime: input.invoice.expirationTime,
    },
    payment: {
      method: resolvedPayment.method,
      network: resolvedPayment.networkSelector,
      chainId: resolvedPayment.chainId,
      assetKind: resolvedPayment.assetKind,
      asset: resolvedPayment.asset.symbol,
      assetId: resolvedPayment.asset.assetId,
      decimals: resolvedPayment.asset.decimals,
      tokenAddress: resolvedPayment.tokenAddress,
      recipient: resolvedPayment.recipient,
      amount: resolvedPayment.amount,
      amountBaseUnits: resolvedPayment.amountBaseUnits.toString(),
      paymentUri: resolvedPayment.paymentUri,
    },
    availablePaymentMethods: listSupportedBitrefillPaymentQuotes(input.cart),
    broadcastRequested: false,
  };
}

export function isBitrefillInvoiceSuccessStatus(status: string): boolean {
  return BITREFILL_INVOICE_SUCCESS_STATUSES.has(status.trim().toLowerCase());
}

export function isBitrefillInvoiceFailureStatus(status: string): boolean {
  return BITREFILL_INVOICE_FAILURE_STATUSES.has(status.trim().toLowerCase());
}

export function isBitrefillInvoiceTerminal(status: string): boolean {
  const normalized = status.trim().toLowerCase();
  return isBitrefillInvoiceSuccessStatus(normalized) || isBitrefillInvoiceFailureStatus(normalized);
}
