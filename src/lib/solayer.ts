import { Buffer } from 'node:buffer';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { assertSafeRpcUrl, ensureAgentPayHome } from '../../packages/config/src/index.js';

const DEFAULT_SOLAYER_BASE_URL = 'https://app.solayer.org/api';
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const SOLAYER_PLUGIN_DIR = 'solayer';
const SOLAYER_SESSION_FILE = 'session.json';
const MAX_GRPC_WEB_MESSAGE_BYTES = 8 * 1024 * 1024;

export enum SolayerNetwork {
  Unspecified = 0,
  SolanaMainnet = 1,
  SolanaTestnet = 2,
}

export enum SolayerSignatureMessageType {
  WalletMessage = 0,
  WalletTransaction = 1,
}

export enum SolayerEmailType {
  Notification = 0,
  Kyc = 1,
  Student = 2,
  Login = 3,
  Delete = 4,
  SetPin = 5,
}

export enum SolayerCardType {
  Virtual = 0,
  Physical = 1,
}

export enum SolayerCardLimitPeriod {
  Unspecified = 0,
  Day = 1,
  Week = 2,
  Month = 3,
  Year = 4,
  Total = 5,
}

export interface SolayerHttpTransport {
  request(method: string, body: Uint8Array, headers: Record<string, string>): Promise<Uint8Array>;
}

export interface SolayerClientOptions {
  baseUrl?: string;
  token?: string | null;
  deviceId?: string;
  timeoutMs?: number;
  transport?: SolayerHttpTransport;
}

export interface SolayerSession {
  token: string;
  deviceId: string;
  updatedAt: string;
}

export interface SolayerDevice {
  name: string;
  mode?: string;
  browser?: string;
  os: string;
  osVersion: string;
}

export interface SolayerCardCondition {
  period?: SolayerCardLimitPeriod;
  valueInUsd?: string;
}

export interface SolayerBilling {
  line1?: string | null;
  line2?: string | null;
  city?: string | null;
  region?: string | null;
  postalCode?: string | null;
  countryCode?: string | null;
  country?: string | null;
}

export interface SolayerShipping extends SolayerBilling {
  phoneNumber?: string | null;
  method?: number;
  firstName?: string | null;
  lastName?: string | null;
  dialCode?: string | null;
}

export interface SolayerCard {
  uuid: string;
  last4: string | null;
  expirationData: string | null;
  status: number;
  tokenWallets: string[];
  limit: SolayerCardCondition | null;
  name: string | null;
  billing: SolayerBilling | null;
  shipping: SolayerShipping | null;
  timestamp: string | null;
  type: number;
}

export interface SolayerCardTransaction {
  uuid: string;
  type: number;
  card: SolayerCard | null;
  amount: string | null;
  currency: string | null;
  timestamp: string | null;
  status: number;
  notes: string | null;
  merchant: Record<string, string | null> | null;
  failedReason: number;
  failedMessage: string | null;
}

export interface SolayerApplication {
  uuid: string;
  applicationStatus: number;
  msg: string | null;
  completionLink: string | null;
  handle: number;
  operation: number;
  link: string | null;
}

export interface SolayerKycInfo {
  kycStatus: number;
  kyc: {
    applicantId: string | null;
    email: string | null;
    country: string | null;
  } | null;
  msg: string | null;
  operation: number;
  itemKyc: boolean;
  needKycMetadata: boolean;
}

export interface SolayerGrpcStatus {
  code?: number;
  message?: string | null;
  raw?: Record<number, ProtoValue[]>;
}

type ProtoPrimitive = bigint | string | Uint8Array | boolean;

interface ProtoValue {
  wireType: number;
  value: ProtoPrimitive;
}

function normalizeString(value: unknown): string | null {
  if (typeof value !== 'string') {
    return null;
  }
  const normalized = value.trim();
  return normalized ? normalized : null;
}

function ensureSolayerPluginDir(): string {
  const pluginDir = path.join(ensureAgentPayHome(), 'plugins', SOLAYER_PLUGIN_DIR);
  fs.mkdirSync(pluginDir, { recursive: true, mode: 0o700 });
  return pluginDir;
}

function solayerSessionPath(): string {
  return path.join(ensureSolayerPluginDir(), SOLAYER_SESSION_FILE);
}

export function readStoredSolayerSession(): SolayerSession | null {
  const filePath = solayerSessionPath();
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    throw error;
  }
  const parsed = JSON.parse(raw) as Partial<SolayerSession>;
  const token = normalizeString(parsed.token);
  const deviceId = normalizeString(parsed.deviceId);
  const updatedAt = normalizeString(parsed.updatedAt);
  if (!token || !deviceId || !updatedAt) {
    return null;
  }
  return { token, deviceId, updatedAt };
}

export function storeSolayerSession(input: { token: string; deviceId: string }): SolayerSession {
  const token = normalizeString(input.token);
  const deviceId = normalizeString(input.deviceId);
  if (!token) {
    throw new Error('Solayer session token is required');
  }
  if (!deviceId) {
    throw new Error('Solayer device id is required');
  }
  const session = {
    token,
    deviceId,
    updatedAt: new Date().toISOString(),
  };
  const filePath = solayerSessionPath();
  fs.writeFileSync(filePath, `${JSON.stringify(session, null, 2)}\n`, { mode: 0o600 });
  try {
    fs.chmodSync(filePath, 0o600);
  } catch {}
  return session;
}

export function deleteStoredSolayerSession(): boolean {
  const filePath = solayerSessionPath();
  try {
    fs.unlinkSync(filePath);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return false;
    }
    throw error;
  }
}

export function resolveSolayerBaseUrl(value = process.env.AGENTPAY_SOLAYER_BASE_URL): string {
  return assertSafeRpcUrl(value?.trim() || DEFAULT_SOLAYER_BASE_URL, 'solayerBaseUrl');
}

export function resolveSolayerNetwork(network: string | undefined): SolayerNetwork {
  const normalized = (network ?? 'solana-mainnet').trim().toLowerCase();
  switch (normalized) {
    case 'solana':
    case 'solana-mainnet':
    case 'mainnet':
      return SolayerNetwork.SolanaMainnet;
    case 'solana-testnet':
    case 'testnet':
      return SolayerNetwork.SolanaTestnet;
    default:
      throw new Error(`network '${network}' is not supported by Solayer`);
  }
}

export function createSolayerDevice(): SolayerDevice {
  return {
    name: 'AgentPay CLI',
    mode: 'cli',
    browser: 'AgentPay',
    os: process.platform,
    osVersion: process.version,
  };
}

function normalizeDeviceId(value: string | undefined): string {
  const normalized = normalizeString(value);
  if (normalized) {
    return normalized;
  }
  return randomUUID();
}

function writeVarint(value: bigint): Uint8Array {
  if (value < 0n) {
    throw new Error('protobuf varint must be non-negative');
  }
  const bytes: number[] = [];
  let remaining = value;
  while (remaining >= 0x80n) {
    bytes.push(Number((remaining & 0x7fn) | 0x80n));
    remaining >>= 7n;
  }
  bytes.push(Number(remaining));
  return Uint8Array.from(bytes);
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  const length = chunks.reduce((total, chunk) => total + chunk.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

function protoKey(fieldNumber: number, wireType: number): Uint8Array {
  return writeVarint(BigInt((fieldNumber << 3) | wireType));
}

function protoVarint(
  fieldNumber: number,
  value: number | bigint | boolean | undefined | null,
): Uint8Array[] {
  if (value === undefined || value === null) {
    return [];
  }
  const normalized =
    typeof value === 'boolean'
      ? value
        ? 1n
        : 0n
      : typeof value === 'number'
        ? BigInt(value)
        : value;
  return [protoKey(fieldNumber, 0), writeVarint(normalized)];
}

function protoString(fieldNumber: number, value: string | undefined | null): Uint8Array[] {
  if (value === undefined || value === null || value === '') {
    return [];
  }
  const bytes = Buffer.from(value, 'utf8');
  return [protoKey(fieldNumber, 2), writeVarint(BigInt(bytes.length)), bytes];
}

function protoBytes(fieldNumber: number, value: Uint8Array | undefined | null): Uint8Array[] {
  if (!value || value.length === 0) {
    return [];
  }
  return [protoKey(fieldNumber, 2), writeVarint(BigInt(value.length)), value];
}

function protoMessage(fieldNumber: number, value: Uint8Array | undefined | null): Uint8Array[] {
  if (!value) {
    return [];
  }
  return [protoKey(fieldNumber, 2), writeVarint(BigInt(value.length)), value];
}

function encodeMessage(chunks: Uint8Array[][]): Uint8Array {
  return concatBytes(chunks.flat());
}

function readVarint(bytes: Uint8Array, offset: number): { value: bigint; offset: number } {
  let result = 0n;
  let shift = 0n;
  let cursor = offset;
  while (cursor < bytes.length) {
    const byte = bytes[cursor++];
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      return { value: result, offset: cursor };
    }
    shift += 7n;
    if (shift > 70n) {
      throw new Error('protobuf varint is too long');
    }
  }
  throw new Error('protobuf varint is truncated');
}

function decodeMessage(bytes: Uint8Array): Record<number, ProtoValue[]> {
  const fields: Record<number, ProtoValue[]> = {};
  let offset = 0;
  while (offset < bytes.length) {
    const key = readVarint(bytes, offset);
    offset = key.offset;
    const fieldNumber = Number(key.value >> 3n);
    const wireType = Number(key.value & 7n);
    let value: ProtoPrimitive;
    if (wireType === 0) {
      const decoded = readVarint(bytes, offset);
      offset = decoded.offset;
      value = decoded.value;
    } else if (wireType === 2) {
      const length = readVarint(bytes, offset);
      offset = length.offset;
      const size = Number(length.value);
      if (!Number.isSafeInteger(size) || size < 0 || offset + size > bytes.length) {
        throw new Error('protobuf length-delimited field is invalid');
      }
      value = bytes.slice(offset, offset + size);
      offset += size;
    } else {
      throw new Error(`unsupported protobuf wire type ${wireType}`);
    }
    const entries = fields[fieldNumber] ?? [];
    entries.push({ wireType, value });
    fields[fieldNumber] = entries;
  }
  return fields;
}

function field(fields: Record<number, ProtoValue[]>, no: number): ProtoValue | undefined {
  return fields[no]?.[0];
}

function fields(fields: Record<number, ProtoValue[]>, no: number): ProtoValue[] {
  return fields[no] ?? [];
}

function fieldString(fields: Record<number, ProtoValue[]>, no: number): string | null {
  const value = field(fields, no)?.value;
  if (!(value instanceof Uint8Array)) {
    return null;
  }
  const decoded = Buffer.from(value).toString('utf8');
  return decoded.length ? decoded : null;
}

function fieldBool(fields: Record<number, ProtoValue[]>, no: number): boolean {
  const value = field(fields, no)?.value;
  return typeof value === 'bigint' ? value !== 0n : false;
}

function fieldNumber(fields: Record<number, ProtoValue[]>, no: number): number {
  const value = field(fields, no)?.value;
  return typeof value === 'bigint' ? Number(value) : 0;
}

function fieldUint64String(fields: Record<number, ProtoValue[]>, no: number): string | null {
  const value = field(fields, no)?.value;
  return typeof value === 'bigint' ? value.toString() : null;
}

function fieldMessage(
  fieldsMap: Record<number, ProtoValue[]>,
  no: number,
): Record<number, ProtoValue[]> | null {
  const value = field(fieldsMap, no)?.value;
  if (!(value instanceof Uint8Array)) {
    return null;
  }
  return decodeMessage(value);
}

function fieldMessages(
  fieldsMap: Record<number, ProtoValue[]>,
  no: number,
): Record<number, ProtoValue[]>[] {
  return fields(fieldsMap, no).flatMap((entry) =>
    entry.value instanceof Uint8Array ? [decodeMessage(entry.value)] : [],
  );
}

function encodeGrpcWebMessage(message: Uint8Array): Uint8Array {
  if (message.length > MAX_GRPC_WEB_MESSAGE_BYTES) {
    throw new Error('Solayer gRPC message is too large');
  }
  const output = new Uint8Array(5 + message.length);
  output[0] = 0;
  new DataView(output.buffer).setUint32(1, message.length, false);
  output.set(message, 5);
  return output;
}

function decodeGrpcWebMessage(body: Uint8Array): Uint8Array {
  let offset = 0;
  while (offset + 5 <= body.length) {
    const frameType = body[offset];
    const length = new DataView(body.buffer, body.byteOffset + offset + 1, 4).getUint32(0, false);
    offset += 5;
    if (offset + length > body.length) {
      throw new Error('Solayer gRPC-web response frame is truncated');
    }
    const frame = body.slice(offset, offset + length);
    offset += length;
    if ((frameType & 0x80) === 0) {
      return frame;
    }
  }
  throw new Error('Solayer gRPC-web response did not include a data frame');
}

function encodeDevice(device: SolayerDevice): Uint8Array {
  return encodeMessage([
    protoString(1, device.name),
    protoString(2, device.mode),
    protoString(3, device.browser),
    protoString(4, device.os),
    protoString(5, device.osVersion),
  ]);
}

function encodeCardCondition(condition: SolayerCardCondition | undefined): Uint8Array | undefined {
  if (!condition) {
    return undefined;
  }
  return encodeMessage([
    protoVarint(1, condition.period ?? SolayerCardLimitPeriod.Unspecified),
    protoString(2, condition.valueInUsd),
  ]);
}

function decodeStatus(message: Record<number, ProtoValue[]> | null): SolayerGrpcStatus | null {
  if (!message) {
    return null;
  }
  return {
    code: fieldNumber(message, 1),
    message: fieldString(message, 2),
    raw: message,
  };
}

function decodeCondition(
  message: Record<number, ProtoValue[]> | null,
): SolayerCardCondition | null {
  if (!message) {
    return null;
  }
  return {
    period: fieldNumber(message, 1),
    valueInUsd: fieldString(message, 2) ?? undefined,
  };
}

function decodeBilling(message: Record<number, ProtoValue[]> | null): SolayerBilling | null {
  if (!message) {
    return null;
  }
  return {
    line1: fieldString(message, 1),
    line2: fieldString(message, 2),
    city: fieldString(message, 3),
    region: fieldString(message, 4),
    postalCode: fieldString(message, 5),
    countryCode: fieldString(message, 6),
    country: fieldString(message, 7),
  };
}

function decodeShipping(message: Record<number, ProtoValue[]> | null): SolayerShipping | null {
  if (!message) {
    return null;
  }
  return {
    ...decodeBilling(message),
    phoneNumber: fieldString(message, 8),
    method: fieldNumber(message, 9),
    firstName: fieldString(message, 10),
    lastName: fieldString(message, 11),
    dialCode: fieldString(message, 12),
  };
}

function decodeCard(message: Record<number, ProtoValue[]> | null): SolayerCard | null {
  if (!message) {
    return null;
  }
  return {
    uuid: fieldString(message, 1) ?? '',
    last4: fieldString(message, 2),
    expirationData: fieldString(message, 3),
    status: fieldNumber(message, 4),
    tokenWallets: fields(message, 5).flatMap((entry) =>
      entry.value instanceof Uint8Array ? [Buffer.from(entry.value).toString('utf8')] : [],
    ),
    limit: decodeCondition(fieldMessage(message, 6)),
    name: fieldString(message, 7),
    billing: decodeBilling(fieldMessage(message, 8)),
    shipping: decodeShipping(fieldMessage(message, 9)),
    timestamp: fieldUint64String(message, 10),
    type: fieldNumber(message, 11),
  };
}

function decodeMerchant(
  message: Record<number, ProtoValue[]> | null,
): Record<string, string | null> | null {
  if (!message) {
    return null;
  }
  return {
    name: fieldString(message, 1),
    city: fieldString(message, 2),
    country: fieldString(message, 3),
    category: fieldString(message, 4),
    categoryCode: fieldString(message, 5),
    enrichedName: fieldString(message, 6),
    enrichedCategory: fieldString(message, 7),
    enrichedIcon: fieldString(message, 8),
    contact: fieldString(message, 9),
  };
}

function decodeCardTransaction(message: Record<number, ProtoValue[]>): SolayerCardTransaction {
  return {
    uuid: fieldString(message, 1) ?? '',
    type: fieldNumber(message, 2),
    card: decodeCard(fieldMessage(message, 3)),
    amount: fieldString(message, 4),
    currency: fieldString(message, 5),
    timestamp: fieldUint64String(message, 6),
    status: fieldNumber(message, 7),
    notes: fieldString(message, 8),
    merchant: decodeMerchant(fieldMessage(message, 9)),
    failedReason: fieldNumber(message, 10),
    failedMessage: fieldString(message, 11),
  };
}

function decodeApplication(
  message: Record<number, ProtoValue[]> | null,
): SolayerApplication | null {
  if (!message) {
    return null;
  }
  return {
    uuid: fieldString(message, 1) ?? '',
    applicationStatus: fieldNumber(message, 2),
    msg: fieldString(message, 3),
    completionLink: fieldString(message, 4),
    handle: fieldNumber(message, 5),
    operation: fieldNumber(message, 6),
    link: fieldString(message, 7),
  };
}

function decodeKycInfo(message: Record<number, ProtoValue[]> | null): SolayerKycInfo | null {
  if (!message) {
    return null;
  }
  const kyc = fieldMessage(message, 2);
  return {
    kycStatus: fieldNumber(message, 1),
    kyc: kyc
      ? {
          applicantId: fieldString(kyc, 1),
          email: fieldString(kyc, 2),
          country: fieldString(kyc, 3),
        }
      : null,
    msg: fieldString(message, 3),
    operation: fieldNumber(message, 4),
    itemKyc: fieldBool(message, 5),
    needKycMetadata: fieldBool(message, 6),
  };
}

function decodeCardEncrypted(
  message: Record<number, ProtoValue[]> | null,
): { pan: string | null; cvc: string | null } | null {
  if (!message) {
    return null;
  }
  return {
    pan: fieldString(message, 1),
    cvc: fieldString(message, 2),
  };
}

export function redactSolayerSensitiveFields<T>(value: T, revealSensitive = false): T {
  if (revealSensitive) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((entry) => redactSolayerSensitiveFields(entry, false)) as T;
  }
  if (!value || typeof value !== 'object') {
    return value;
  }
  const output: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    if (['pan', 'cvc', 'pin', 'token'].includes(key)) {
      continue;
    }
    output[key] = redactSolayerSensitiveFields(entry, false);
  }
  return output as T;
}

class FetchSolayerTransport implements SolayerHttpTransport {
  readonly baseUrl: string;
  readonly timeoutMs: number;

  constructor(baseUrl: string, timeoutMs = DEFAULT_REQUEST_TIMEOUT_MS) {
    this.baseUrl = assertSafeRpcUrl(baseUrl, 'solayerBaseUrl').replace(/\/+$/u, '');
    this.timeoutMs = timeoutMs;
  }

  async request(
    method: string,
    body: Uint8Array,
    headers: Record<string, string>,
  ): Promise<Uint8Array> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await fetch(`${this.baseUrl}/solayerservice.v1.SolayerService/${method}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/grpc-web+proto',
          'x-grpc-web': '1',
          ...headers,
        },
        body: encodeGrpcWebMessage(body),
        signal: controller.signal,
      });
      const responseBody = new Uint8Array(await response.arrayBuffer());
      if (!response.ok) {
        throw new Error(`Solayer ${method} failed with HTTP ${response.status}`);
      }
      return decodeGrpcWebMessage(responseBody);
    } finally {
      clearTimeout(timer);
    }
  }
}

export class SolayerClient {
  readonly token: string | null;
  readonly deviceId: string;
  readonly transport: SolayerHttpTransport;

  constructor(options: SolayerClientOptions = {}) {
    this.token = normalizeString(options.token);
    this.deviceId = normalizeDeviceId(options.deviceId);
    this.transport =
      options.transport ??
      new FetchSolayerTransport(
        resolveSolayerBaseUrl(options.baseUrl),
        options.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
      );
  }

  headers(authenticated: boolean): Record<string, string> {
    const headers: Record<string, string> = {
      platform: 'WEB',
      'browser-id': this.deviceId,
      'user-agent': 'AgentPay CLI',
    };
    if (authenticated) {
      if (!this.token) {
        throw new Error('Solayer login is required; run `agentpay solayer login ...` first');
      }
      headers.authorization = this.token;
    }
    return headers;
  }

  async call(
    method: string,
    body: Uint8Array,
    authenticated: boolean,
  ): Promise<Record<number, ProtoValue[]>> {
    return decodeMessage(await this.transport.request(method, body, this.headers(authenticated)));
  }

  async getSignatureMessage(input: {
    network: SolayerNetwork;
    address: string;
    messageType?: SolayerSignatureMessageType;
  }) {
    const response = await this.call(
      'GetSignatureMessage',
      encodeMessage([
        protoVarint(1, input.network),
        protoString(2, input.address),
        protoVarint(3, input.messageType ?? SolayerSignatureMessageType.WalletMessage),
      ]),
      false,
    );
    return {
      message: fieldString(response, 1) ?? '',
      messageId: fieldString(response, 2) ?? '',
    };
  }

  async verifySignature(input: {
    network: SolayerNetwork;
    address: string;
    signature: Uint8Array;
    messageId: string;
    walletName: string;
    txB64?: string;
  }) {
    const response = await this.call(
      'VerifySignature',
      encodeMessage([
        protoVarint(1, input.network),
        protoString(2, input.address),
        protoBytes(3, input.signature),
        protoString(4, input.messageId),
        protoString(5, input.walletName),
        protoString(6, input.txB64),
      ]),
      false,
    );
    return { token: fieldString(response, 1) ?? '' };
  }

  async sendEmail(input: { network: SolayerNetwork; email: string; emailType: SolayerEmailType }) {
    const response = await this.call(
      'SendEmail',
      encodeMessage([
        protoVarint(1, input.network),
        protoString(2, input.email),
        protoVarint(3, input.emailType),
      ]),
      false,
    );
    return {
      sessionId: fieldString(response, 1) ?? '',
      error: decodeStatus(fieldMessage(response, 2)),
    };
  }

  async verifyEmailOtp(input: {
    network: SolayerNetwork;
    sessionId: string;
    otp: string;
    emailType: SolayerEmailType;
  }) {
    const response = await this.call(
      'VerifyEmailOTP',
      encodeMessage([
        protoVarint(1, input.network),
        protoString(2, input.sessionId),
        protoString(3, input.otp),
        protoVarint(4, input.emailType),
      ]),
      false,
    );
    return {
      sessionId: fieldString(response, 1) ?? '',
      error: decodeStatus(fieldMessage(response, 2)),
    };
  }

  async checkAccount(input: { emailToken?: string; googleToken?: string; appleToken?: string }) {
    const response = await this.call(
      'CheckAccount',
      encodeMessage([
        protoString(1, input.googleToken),
        protoString(2, input.appleToken),
        protoString(3, input.emailToken),
      ]),
      false,
    );
    return {
      exists: fieldBool(response, 1),
      sessionId: fieldString(response, 2) ?? '',
    };
  }

  async signIn(sessionId: string, device = createSolayerDevice()) {
    const response = await this.call(
      'SignIn',
      encodeMessage([protoString(1, sessionId), protoMessage(2, encodeDevice(device))]),
      false,
    );
    return {
      token: fieldString(response, 1) ?? '',
      tfaSessionId: fieldString(response, 3),
    };
  }

  async signUp(sessionId: string, device = createSolayerDevice()) {
    const response = await this.call(
      'SignUp',
      encodeMessage([protoString(1, sessionId), protoMessage(2, encodeDevice(device))]),
      false,
    );
    return {
      token: fieldString(response, 1) ?? '',
      error: decodeStatus(fieldMessage(response, 3)),
      tfaSessionId: fieldString(response, 4),
    };
  }

  async logout() {
    await this.call('Logout', new Uint8Array(), true);
  }

  async getAccountInfo() {
    const response = await this.call('GetAccountInfo', new Uint8Array(), true);
    const account = fieldMessage(response, 1);
    return {
      address: account ? fieldString(account, 1) : null,
      subscribeEmail: account ? fieldString(account, 2) : null,
      uuid: account ? fieldString(account, 16) : null,
      name: account ? fieldString(account, 17) : null,
      tester: account ? fieldBool(account, 18) : false,
    };
  }

  async getDepositAddress(network: SolayerNetwork) {
    const response = await this.call(
      'GetDepositAddress',
      encodeMessage([protoVarint(1, network)]),
      true,
    );
    return { depositAddress: fieldString(response, 1) ?? '' };
  }

  async getKycInfo(network: SolayerNetwork) {
    const response = await this.call('GetKYCInfo', encodeMessage([protoVarint(1, network)]), true);
    return { kycInfo: decodeKycInfo(fieldMessage(response, 1)) };
  }

  async getKycAuth(network: SolayerNetwork) {
    const response = await this.call('GetKYCAuth', encodeMessage([protoVarint(1, network)]), true);
    return { link: fieldString(response, 1) ?? '' };
  }

  async acceptProtocol(input: { kyc?: boolean; card?: boolean }) {
    await this.call('AcceptProtocol', encodeMessage([protoVarint(input.kyc ? 1 : 2, true)]), true);
  }

  async getApplication(network: SolayerNetwork) {
    const response = await this.call(
      'GetApplication',
      encodeMessage([protoVarint(1, network)]),
      true,
    );
    return { application: decodeApplication(fieldMessage(response, 1)) };
  }

  async createApplication(network: SolayerNetwork) {
    const response = await this.call(
      'CreateApplication',
      encodeMessage([protoVarint(1, network)]),
      true,
    );
    return { application: decodeApplication(fieldMessage(response, 1)) };
  }

  async updateApplication(network: SolayerNetwork) {
    const response = await this.call(
      'UpdateApplication',
      encodeMessage([protoVarint(1, network)]),
      true,
    );
    return { application: decodeApplication(fieldMessage(response, 1)) };
  }

  async getCards(input: { network: SolayerNetwork; limit?: SolayerCardCondition }) {
    const response = await this.call(
      'GetCards',
      encodeMessage([
        protoVarint(1, input.network),
        protoMessage(2, encodeCardCondition(input.limit)),
      ]),
      true,
    );
    return {
      balance: fieldString(response, 1),
      pendingBalance: fieldString(response, 2),
      cards: fieldMessages(response, 3)
        .map(decodeCard)
        .filter((entry): entry is SolayerCard => Boolean(entry)),
      itemCard: fieldBool(response, 4),
    };
  }

  async createCard(input: {
    network: SolayerNetwork;
    name?: string;
    type: SolayerCardType;
    limit?: SolayerCardCondition;
  }) {
    const response = await this.call(
      'CreateCard',
      encodeMessage([
        protoVarint(1, input.network),
        protoMessage(2, encodeCardCondition(input.limit)),
        protoString(3, input.name),
        protoVarint(4, input.type),
      ]),
      true,
    );
    return {
      card: decodeCard(fieldMessage(response, 1)),
      pan: fieldString(response, 2),
      cvc: fieldString(response, 3),
      error: decodeStatus(fieldMessage(response, 4)),
    };
  }

  async getCardEncryptedInfo(input: {
    network: SolayerNetwork;
    cardId: string;
    tfaSessionId?: string;
  }) {
    const response = await this.call(
      'GetCardEncryptedInfo',
      encodeMessage([
        protoVarint(1, input.network),
        protoString(2, input.cardId),
        protoString(3, input.tfaSessionId),
      ]),
      true,
    );
    return { cardEncryptedInfo: decodeCardEncrypted(fieldMessage(response, 1)) };
  }

  async getCardDetails(input: { network: SolayerNetwork; cardId: string }) {
    const response = await this.call(
      'GetCardDetails',
      encodeMessage([protoVarint(1, input.network), protoString(2, input.cardId)]),
      true,
    );
    return {
      card: decodeCard(fieldMessage(response, 1)),
      usedAmount: fieldString(response, 2),
      resetTimestamp: fieldUint64String(response, 3),
    };
  }

  async getCardPin(cardId: string) {
    const response = await this.call('GetCardPin', encodeMessage([protoString(1, cardId)]), true);
    return { pin: fieldString(response, 1) };
  }

  async getCardTransactions(input: {
    network: SolayerNetwork;
    startTimestamp?: string;
    endTimestamp?: string;
    pageSize?: string;
    page?: string;
    cardId?: string;
  }) {
    const response = await this.call(
      'GetCardTransactions',
      encodeMessage([
        protoVarint(1, input.network),
        protoVarint(2, input.startTimestamp ? BigInt(input.startTimestamp) : undefined),
        protoVarint(3, input.endTimestamp ? BigInt(input.endTimestamp) : undefined),
        protoVarint(4, input.pageSize ? BigInt(input.pageSize) : undefined),
        protoVarint(5, input.page ? BigInt(input.page) : undefined),
        protoString(6, input.cardId),
      ]),
      true,
    );
    return {
      cardTransactions: fieldMessages(response, 1).map(decodeCardTransaction),
      rewardPoints: fieldUint64String(response, 2),
      totalSize: fieldUint64String(response, 3),
    };
  }
}

export function createSolayerClient(options: SolayerClientOptions = {}): SolayerClient {
  const stored = readStoredSolayerSession();
  return new SolayerClient({
    token: options.token ?? stored?.token ?? null,
    deviceId: options.deviceId ?? stored?.deviceId,
    baseUrl: options.baseUrl ?? resolveSolayerBaseUrl(),
    timeoutMs: options.timeoutMs,
    transport: options.transport,
  });
}

export function parseSolayerSignature(value: string): Uint8Array {
  const normalized = value.trim();
  if (!normalized) {
    throw new Error('signature is required');
  }
  if (/^(0x)?[0-9a-f]+$/iu.test(normalized) && normalized.replace(/^0x/iu, '').length % 2 === 0) {
    return Uint8Array.from(Buffer.from(normalized.replace(/^0x/iu, ''), 'hex'));
  }
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let num = 0n;
  for (const character of normalized) {
    const index = alphabet.indexOf(character);
    if (index === -1) {
      throw new Error('signature must be hex or base58');
    }
    num = num * 58n + BigInt(index);
  }
  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num & 0xffn));
    num >>= 8n;
  }
  for (const character of normalized) {
    if (character !== '1') {
      break;
    }
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}
