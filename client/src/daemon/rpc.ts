/**
 * Typed request/response over the framed transport, shared by both daemons: handshake with
 * `Hello`, response-variant checks, and typed errors.
 *
 * Compatibility is the major `api_version`: a daemon with the same major version as the
 * generated `API_VERSION` serves every method in `src/generated`, so calls need no per-method
 * capability check.
 */

import {
  IncompatibleApiError,
  PaymentsCallError,
  ProtocolError,
  SignerCallError,
} from '../errors.js';
import { API_VERSION, type HelloResponse } from '../generated/index.js';
import type { Endpoint } from './endpoints.js';
import { assertTrustedSocket, type TrustFs } from './socket-trust.js';
import { DEFAULT_TIMEOUT_MS, exchange as defaultExchange, type Exchange } from './transport.js';

/** A tagged response: `{"type": ..., "data": ...}`. */
export interface Tagged {
  type: string;
}

/** The member of response union `R` whose `type` is `T`. */
export type Variant<R extends Tagged, T extends R['type']> = Extract<R, { type: T }>;

export interface RpcClientOptions {
  endpoint: Endpoint;
  exchange?: Exchange;
  trustFs?: TrustFs;
}

/** The major component of a semver string. */
export function majorVersion(version: string): string {
  return version.split('.')[0] ?? version;
}

export class RpcClient<Req extends { method: string }, Res extends Tagged> {
  private readonly endpoint: Endpoint;
  private readonly exchangeFn: Exchange;
  private readonly trustFs: TrustFs | undefined;
  private helloResponse: Promise<HelloResponse> | null = null;

  constructor(options: RpcClientOptions) {
    this.endpoint = options.endpoint;
    this.exchangeFn = options.exchange ?? defaultExchange;
    this.trustFs = options.trustFs;
  }

  get service() {
    return this.endpoint.service;
  }

  /** Calls `Hello` once per client and checks its major API version against `API_VERSION`. */
  hello(): Promise<HelloResponse> {
    this.helloResponse ??= this.send({ method: 'Hello' }, DEFAULT_TIMEOUT_MS).then((body) => {
      const response = this.expect(body, 'Hello', ['Hello']) as unknown as { data: HelloResponse };
      const theirs = response.data.api_version;
      if (majorVersion(theirs) !== majorVersion(API_VERSION)) {
        throw new IncompatibleApiError(this.service, theirs, API_VERSION);
      }
      return response.data;
    });
    this.helloResponse.catch(() => {
      this.helloResponse = null;
    });
    return this.helloResponse;
  }

  /**
   * Sends `request` after the handshake and returns the response, which must be one of the
   * `expected` variants.
   */
  async call<T extends Res['type']>(
    request: Req,
    expected: readonly T[],
    timeoutMs: number = DEFAULT_TIMEOUT_MS,
  ): Promise<Variant<Res, T>> {
    await this.hello();
    const body = await this.send(request, timeoutMs);
    return this.expect(body, request.method, expected) as Variant<Res, T>;
  }

  /**
   * For the sudo relay, which forwards an admin request it does not interpret: sends `request`
   * after the handshake and returns whatever response variant the daemon sent.
   */
  async callUntyped(
    request: { method: string; params?: unknown },
    timeoutMs: number = DEFAULT_TIMEOUT_MS,
  ): Promise<{ type: string; data?: unknown }> {
    await this.hello();
    const body = await this.send(request, timeoutMs);
    return this.expect(body, request.method, 'any') as { type: string; data?: unknown };
  }

  private async send(request: unknown, timeoutMs: number): Promise<unknown> {
    assertTrustedSocket(this.endpoint.path, this.endpoint.trust(), this.service, this.trustFs);
    const raw = await this.exchangeFn(this.endpoint.path, request, {
      service: this.service,
      timeoutMs,
    });
    if (!raw.ok) {
      throw this.toError(raw.body);
    }
    return raw.body;
  }

  private expect(body: unknown, method: string, expected: readonly string[] | 'any'): Tagged {
    const type =
      typeof body === 'object' && body !== null && typeof (body as Tagged).type === 'string'
        ? (body as Tagged).type
        : 'malformed';
    if (type === 'malformed' || (expected !== 'any' && !expected.includes(type))) {
      throw new ProtocolError(this.service, method, type);
    }
    return body as Tagged;
  }

  private toError(body: unknown): Error {
    if (
      typeof body !== 'object' ||
      body === null ||
      typeof (body as { kind?: unknown }).kind !== 'string'
    ) {
      return new ProtocolError(this.service, 'error', 'malformed');
    }
    return this.service === 'signer'
      ? new SignerCallError(body as ConstructorParameters<typeof SignerCallError>[0])
      : new PaymentsCallError(body as ConstructorParameters<typeof PaymentsCallError>[0]);
  }
}
