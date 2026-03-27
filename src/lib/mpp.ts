import { type Hex, hexToBytes, keccak256, stringToHex, toHex } from 'viem';

export interface MppChallengeRequest {
  amount: string;
  currency: string;
  recipient: string;
  decimals?: number;
  suggestedDeposit?: string;
  unitType?: string;
  methodDetails?: {
    chainId?: number;
    memo?: string;
    feePayer?: boolean;
    escrowContract?: string;
    channelId?: string;
    minVoucherDelta?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface MppChallenge {
  id: string;
  realm: string;
  method: string;
  intent: string;
  request: MppChallengeRequest;
  description?: string;
  digest?: string;
  expires?: string;
  opaque?: Record<string, string>;
}

export type MppCredentialPayload =
  | {
      type: 'hash';
      hash: string;
    }
  | {
      action: 'open';
      type: 'transaction';
      channelId: string;
      transaction: string;
      cumulativeAmount: string;
      signature: string;
      authorizedSigner?: string;
    }
  | {
      action: 'topUp';
      type: 'transaction';
      channelId: string;
      transaction: string;
      additionalDeposit: string;
    }
  | {
      action: 'close';
      channelId: string;
      cumulativeAmount: string;
      signature: string;
    }
  | {
      action: 'voucher';
      channelId: string;
      cumulativeAmount: string;
      signature: string;
    };

export interface MppReceipt {
  method: string;
  reference: string;
  status: 'success';
  timestamp: string;
  externalId?: string;
  intent?: string;
  challengeId?: string;
  channelId?: string;
  acceptedCumulative?: string;
  spent?: string;
  units?: number;
  txHash?: string;
  [key: string]: unknown;
}

interface RawMppCredential {
  challenge: Omit<MppChallenge, 'request'> & { request: string };
  payload: unknown;
  source?: string;
}

const MPP_ATTRIBUTION_TAG = keccak256(stringToHex('mpp')).slice(0, 10) as Hex;
const MPP_ATTRIBUTION_VERSION = 0x01;

function decodeBase64UrlJson<T>(value: string): T {
  return JSON.parse(Buffer.from(value, 'base64url').toString('utf8')) as T;
}

function encodeBase64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function extractPaymentAuthParams(header: string): string | null {
  const token = 'Payment';
  let inQuotes = false;
  let escaped = false;

  for (let index = 0; index < header.length; index += 1) {
    const char = header[index];

    if (inQuotes) {
      if (escaped) {
        escaped = false;
      } else if (char === '\\') {
        escaped = true;
      } else if (char === '"') {
        inQuotes = false;
      }
      continue;
    }

    if (char === '"') {
      inQuotes = true;
      continue;
    }

    if (!startsWithSchemeToken(header, index, token)) {
      continue;
    }

    const prefix = header.slice(0, index);
    if (prefix.trim() && !prefix.trimEnd().endsWith(',')) {
      continue;
    }

    let paramsStart = index + token.length;
    while (paramsStart < header.length && /\s/u.test(header[paramsStart] ?? '')) {
      paramsStart += 1;
    }
    return header.slice(paramsStart);
  }

  return null;
}

function startsWithSchemeToken(value: string, index: number, token: string): boolean {
  if (!value.slice(index).toLowerCase().startsWith(token.toLowerCase())) {
    return false;
  }

  const next = value[index + token.length];
  return Boolean(next && /\s/u.test(next));
}

function readAuthParamValue(input: string, start: number): [string, number] {
  if (input[start] === '"') {
    return readQuotedAuthParamValue(input, start + 1);
  }

  let index = start;
  while (index < input.length && input[index] !== ',') {
    index += 1;
  }
  return [input.slice(start, index).trim(), index];
}

function readQuotedAuthParamValue(input: string, start: number): [string, number] {
  let index = start;
  let value = '';
  let escaped = false;

  while (index < input.length) {
    const char = input[index];
    index += 1;

    if (escaped) {
      value += char;
      escaped = false;
      continue;
    }

    if (char === '\\') {
      escaped = true;
      continue;
    }

    if (char === '"') {
      return [value, index];
    }

    value += char;
  }

  throw new Error('MPP challenge contains an unterminated quoted-string');
}

function parseAuthParams(input: string): Record<string, string> {
  const result: Record<string, string> = {};
  let index = 0;

  while (index < input.length) {
    while (index < input.length && /[\s,]/u.test(input[index] ?? '')) {
      index += 1;
    }
    if (index >= input.length) {
      break;
    }

    const keyStart = index;
    while (index < input.length && /[A-Za-z0-9_-]/u.test(input[index] ?? '')) {
      index += 1;
    }
    const key = input.slice(keyStart, index);
    if (!key) {
      throw new Error('MPP challenge contains a malformed auth-param');
    }

    while (index < input.length && /\s/u.test(input[index] ?? '')) {
      index += 1;
    }

    if (input[index] !== '=') {
      break;
    }
    index += 1;

    while (index < input.length && /\s/u.test(input[index] ?? '')) {
      index += 1;
    }

    const [value, nextIndex] = readAuthParamValue(input, index);
    index = nextIndex;

    if (key in result) {
      throw new Error(`MPP challenge contains a duplicate parameter: ${key}`);
    }
    result[key] = value;
  }

  return result;
}

function assertStringRecord(value: unknown, label: string): Record<string, string> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }

  const record = value as Record<string, unknown>;
  const result: Record<string, string> = {};
  for (const [key, entry] of Object.entries(record)) {
    if (typeof entry !== 'string') {
      throw new Error(`${label}.${key} must be a string`);
    }
    result[key] = entry;
  }
  return result;
}

function assertOptionalReceiptString(
  record: Record<string, unknown>,
  key: keyof MppReceipt,
  label: string,
): string | undefined {
  const value = record[key];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'string') {
    throw new Error(`${label}.${key} must be a string when present`);
  }
  return value;
}

function assertOptionalReceiptNumber(
  record: Record<string, unknown>,
  key: keyof MppReceipt,
  label: string,
): number | undefined {
  const value = record[key];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`${label}.${key} must be a number when present`);
  }
  return value;
}

function parseChallengeRequest(value: unknown): MppChallengeRequest {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('MPP challenge request must be an object');
  }

  const request = value as Record<string, unknown>;
  if (typeof request.amount !== 'string' || !request.amount.trim()) {
    throw new Error('MPP challenge request.amount must be a non-empty string');
  }
  if (typeof request.currency !== 'string' || !request.currency.trim()) {
    throw new Error('MPP challenge request.currency must be a non-empty string');
  }
  if (typeof request.recipient !== 'string' || !request.recipient.trim()) {
    throw new Error('MPP challenge request.recipient must be a non-empty string');
  }
  if (request.decimals !== undefined && typeof request.decimals !== 'number') {
    throw new Error('MPP challenge request.decimals must be a number when present');
  }
  if (request.suggestedDeposit !== undefined && typeof request.suggestedDeposit !== 'string') {
    throw new Error('MPP challenge request.suggestedDeposit must be a string when present');
  }
  if (request.unitType !== undefined && typeof request.unitType !== 'string') {
    throw new Error('MPP challenge request.unitType must be a string when present');
  }

  let methodDetails: MppChallengeRequest['methodDetails'];
  if (request.methodDetails !== undefined) {
    if (
      !request.methodDetails ||
      typeof request.methodDetails !== 'object' ||
      Array.isArray(request.methodDetails)
    ) {
      throw new Error('MPP challenge request.methodDetails must be an object when present');
    }
    const details = request.methodDetails as Record<string, unknown>;
    if (details.chainId !== undefined && typeof details.chainId !== 'number') {
      throw new Error('MPP challenge request.methodDetails.chainId must be a number');
    }
    if (details.memo !== undefined && typeof details.memo !== 'string') {
      throw new Error('MPP challenge request.methodDetails.memo must be a string');
    }
    if (details.feePayer !== undefined && typeof details.feePayer !== 'boolean') {
      throw new Error('MPP challenge request.methodDetails.feePayer must be a boolean');
    }
    if (details.escrowContract !== undefined && typeof details.escrowContract !== 'string') {
      throw new Error('MPP challenge request.methodDetails.escrowContract must be a string');
    }
    if (details.channelId !== undefined && typeof details.channelId !== 'string') {
      throw new Error('MPP challenge request.methodDetails.channelId must be a string');
    }
    if (details.minVoucherDelta !== undefined && typeof details.minVoucherDelta !== 'string') {
      throw new Error('MPP challenge request.methodDetails.minVoucherDelta must be a string');
    }
    methodDetails = details as MppChallengeRequest['methodDetails'];
  }

  return {
    ...request,
    amount: request.amount,
    currency: request.currency,
    recipient: request.recipient,
    decimals: request.decimals as number | undefined,
    suggestedDeposit: request.suggestedDeposit as string | undefined,
    unitType: request.unitType as string | undefined,
    methodDetails,
  };
}

function parseReceipt(value: unknown): MppReceipt {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('MPP receipt must be an object');
  }

  const receipt = value as Record<string, unknown>;
  if (typeof receipt.method !== 'string' || !receipt.method.trim()) {
    throw new Error('MPP receipt.method must be a non-empty string');
  }
  if (typeof receipt.reference !== 'string' || !receipt.reference.trim()) {
    throw new Error('MPP receipt.reference must be a non-empty string');
  }
  if (receipt.status !== 'success') {
    throw new Error('MPP receipt.status must be "success"');
  }
  if (typeof receipt.timestamp !== 'string' || !receipt.timestamp.trim()) {
    throw new Error('MPP receipt.timestamp must be a non-empty string');
  }

  return {
    ...receipt,
    method: receipt.method,
    reference: receipt.reference,
    status: 'success',
    timestamp: receipt.timestamp,
    externalId: assertOptionalReceiptString(receipt, 'externalId', 'MPP receipt'),
    intent: assertOptionalReceiptString(receipt, 'intent', 'MPP receipt'),
    challengeId: assertOptionalReceiptString(receipt, 'challengeId', 'MPP receipt'),
    channelId: assertOptionalReceiptString(receipt, 'channelId', 'MPP receipt'),
    acceptedCumulative: assertOptionalReceiptString(receipt, 'acceptedCumulative', 'MPP receipt'),
    spent: assertOptionalReceiptString(receipt, 'spent', 'MPP receipt'),
    units: assertOptionalReceiptNumber(receipt, 'units', 'MPP receipt'),
    txHash: assertOptionalReceiptString(receipt, 'txHash', 'MPP receipt'),
  };
}

export function parseMppChallengeHeader(header: string): MppChallenge {
  const params = extractPaymentAuthParams(header);
  if (!params) {
    throw new Error('Missing Payment scheme in MPP challenge');
  }

  const raw = parseAuthParams(params);
  const requestEncoded = raw.request;
  if (!requestEncoded) {
    throw new Error('MPP challenge is missing the request parameter');
  }
  if (raw.method && !/^[a-z][a-z0-9:_-]*$/u.test(raw.method)) {
    throw new Error(`MPP challenge method must be lowercase: ${raw.method}`);
  }

  const request = parseChallengeRequest(decodeBase64UrlJson<unknown>(requestEncoded));

  return {
    id: requireHeaderField(raw.id, 'id'),
    realm: requireHeaderField(raw.realm, 'realm'),
    method: requireHeaderField(raw.method, 'method'),
    intent: requireHeaderField(raw.intent, 'intent'),
    request,
    description: raw.description,
    digest: raw.digest,
    expires: raw.expires,
    opaque: raw.opaque
      ? assertStringRecord(decodeBase64UrlJson<unknown>(raw.opaque), 'opaque')
      : undefined,
  };
}

function requireHeaderField(value: string | undefined, label: string): string {
  if (!value?.trim()) {
    throw new Error(`MPP challenge is missing the ${label} parameter`);
  }
  return value;
}

export function parseMppChallengeFromHeaders(headers: Headers): MppChallenge {
  const header = headers.get('WWW-Authenticate');
  if (!header) {
    throw new Error('MPP response is missing the WWW-Authenticate header');
  }
  return parseMppChallengeHeader(header);
}

export function deserializeMppReceiptHeader(header: string): MppReceipt {
  return parseReceipt(decodeBase64UrlJson<unknown>(header));
}

export function parseMppReceiptFromHeaders(headers: Headers): MppReceipt | null {
  const header = headers.get('Payment-Receipt');
  return header ? deserializeMppReceiptHeader(header) : null;
}

export function serializeMppCredentialHeader(input: {
  challenge: MppChallenge;
  payload: MppCredentialPayload;
  source?: string;
}): string {
  const wire: RawMppCredential = {
    challenge: {
      ...input.challenge,
      request: encodeBase64UrlJson(input.challenge.request),
    },
    payload: input.payload,
    source: input.source,
  };
  return `Payment ${encodeBase64UrlJson(wire)}`;
}

function fingerprintAttributionValue(value: string): Uint8Array {
  const hash = keccak256(stringToHex(value));
  return hexToBytes(`${hash.slice(0, 22)}` as Hex);
}

export function encodeMppAttributionMemo(input: { serverId: string; clientId?: string }): Hex {
  const output = new Uint8Array(32);
  output.set(hexToBytes(MPP_ATTRIBUTION_TAG), 0);
  output[4] = MPP_ATTRIBUTION_VERSION;
  output.set(fingerprintAttributionValue(input.serverId), 5);
  if (input.clientId) {
    output.set(fingerprintAttributionValue(input.clientId), 15);
  }
  output.set(globalThis.crypto.getRandomValues(new Uint8Array(7)), 25);
  return toHex(output);
}

export function resolveMppChainId(challenge: MppChallenge): number {
  return challenge.request.methodDetails?.chainId ?? 4217;
}

export function isTempoChain(chainId: number): boolean {
  return chainId === 4217 || chainId === 42431;
}

export function resolveMppEscrowContract(challenge: MppChallenge): string | null {
  const explicit = challenge.request.methodDetails?.escrowContract;
  if (typeof explicit === 'string' && explicit.trim()) {
    return explicit;
  }

  const chainId = resolveMppChainId(challenge);
  if (chainId === 4217) {
    return '0x33b901018174DDabE4841042ab76ba85D4e24f25';
  }
  if (chainId === 42431) {
    return '0xe1c4d3dce17bc111181ddf716f75bae49e61a336';
  }
  return null;
}
