/** Paid HTTP: `x402 <url>` and `mpp <url>`. The payments service makes the requests. */
import { createHash } from 'node:crypto';
import { basename } from 'node:path';
import { type Command, InvalidArgumentError } from 'commander';
import { expandPath } from '../app/services.js';
import { copy } from '../copy/index.js';
import { UsageError } from '../errors.js';
import { isIntegerString } from '../format/amount.js';
import type {
  HttpResponse,
  MppFetchResult,
  MppPayment,
  X402FetchResult,
} from '../generated/index.js';
import {
  type AgentOptions,
  baseUnits,
  collect,
  type HttpOptions,
  httpRequest,
  nonNegativeInt,
  opt,
  withAgentOptions,
} from './options.js';
import { printJson } from './output.js';
import { type CommandEnv, handler } from './run.js';

const SESSION_KEY = /^[A-Za-z0-9._:-]{1,64}$/u;

/**
 * Maps the old `--session-state-file <path>` to a paymentd session key: a readable name from the
 * file name plus a hash of the absolute path, so different files never share a channel.
 */
export function sessionKeyFromFile(path: string): string {
  const absolute = expandPath(path);
  const name =
    basename(absolute)
      .replace(/\.json$/iu, '')
      .replace(/[^A-Za-z0-9._-]/gu, '-')
      .slice(0, 40) || 'session';
  const digest = createHash('sha256').update(absolute).digest('hex').slice(0, 12);
  return `file:${name}:${digest}`;
}

function mppAmount(flag: string) {
  return (value: string) => {
    if (!isIntegerString(value)) {
      throw new InvalidArgumentError(copy.commands.http.baseUnitsOnly(flag));
    }
    return baseUnits(value);
  };
}

function headerObject(response: HttpResponse): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const { name, value } of response.headers) {
    const key = name.toLowerCase();
    headers[key] = headers[key] === undefined ? value : `${headers[key]}, ${value}`;
  }
  return headers;
}

function bodyValue(response: HttpResponse): unknown {
  if (response.body.type === 'base64') {
    return { base64: response.body.data };
  }
  const contentType = response.headers.find((h) => h.name.toLowerCase() === 'content-type')?.value;
  if (contentType && /\bjson\b/iu.test(contentType)) {
    try {
      return JSON.parse(response.body.data);
    } catch {
      // not JSON after all
    }
  }
  return response.body.data;
}

/** The `--json` shape of the TypeScript CLI: protocol, url, status, ok, headers, body, payment. */
export function httpJson(protocol: 'x402' | 'mpp', result: X402FetchResult | MppFetchResult) {
  const response = result.response;
  let payment: unknown = result.payment;
  if (protocol === 'mpp' && result.payment && 'session' in result.payment) {
    // Older agents read `payment.sessionProtocol` and `payment.closeReceipt`.
    payment = {
      ...result.payment,
      sessionProtocol: result.payment.session_protocol,
      closeReceipt: result.payment.session?.close_receipt ?? null,
    };
  }
  return {
    protocol,
    url: response.url,
    status: response.status,
    ok: response.status >= 200 && response.status < 300,
    headers: headerObject(response),
    body: bodyValue(response),
    body_truncated: response.body_truncated,
    payment,
  };
}

function paidLine(protocol: 'x402' | 'mpp', result: X402FetchResult | MppFetchResult): string {
  const h = copy.commands.http;
  const payment = result.payment;
  if (!payment) {
    return h.notPaid;
  }
  if (protocol === 'mpp' && 'session_protocol' in payment) {
    const mpp = payment as MppPayment;
    return h.paidOn(mpp.amount, mpp.method, mpp.network, mpp.charge?.credential_type ?? null);
  }
  return h.paid(payment.amount, protocol);
}

function emitHttp(
  env: CommandEnv,
  protocol: 'x402' | 'mpp',
  json: boolean | undefined,
  result: X402FetchResult | MppFetchResult,
): number {
  const io = env.context.io;
  const h = copy.commands.http;
  if (json) {
    printJson(io, httpJson(protocol, result));
  } else {
    const { body } = result.response;
    io.stdout(body.type === 'base64' ? Buffer.from(body.data, 'base64') : body.data);
    if (body.type === 'text' && body.data && !body.data.endsWith('\n')) {
      io.stdout('\n');
    }
    io.stderr(`${paidLine(protocol, result)}\n`);
    if (result.response.body_truncated) {
      io.stderr(`${h.truncated}\n`);
    }
  }
  return result.response.status >= 400 ? 1 : 0;
}

interface X402Options extends AgentOptions, HttpOptions {
  maxAmount?: string;
  expectedAmount?: string;
  approvalWait?: number;
}

interface MppOptions extends AgentOptions, HttpOptions {
  amount?: string;
  deposit?: string;
  maxDeposit?: string;
  currency?: string;
  network?: string;
  sessionStateFile?: string;
  sessionKey?: string;
  closeSession?: boolean;
  approvalWait?: number;
}

function withHttpOptions(command: Command): Command {
  const h = copy.commands.http;
  return withAgentOptions(
    command
      .argument('<url>', h.url)
      .option('--method <method>', h.method)
      .option('--header <header>', h.header, collect)
      .option('--data <text>', h.data)
      .option('--json-body <json>', h.jsonBody)
      .option('--approval-wait <secs>', copy.commands.evm.approvalWait, nonNegativeInt),
  );
}

export function registerHttpCommands(program: Command, env: CommandEnv): void {
  const h = copy.commands.http;
  withHttpOptions(
    program
      .command('x402')
      .description(h.x402)
      .option('--max-amount <units>', h.maxAmount, baseUnits)
      .option('--expected-amount <units>', h.expectedAmount, baseUnits),
  ).action(
    handler(env, async (url: string, options: X402Options) => {
      const request = httpRequest(options);
      const payments = await env.context.payments(options);
      const result = await payments.x402({
        url,
        ...request,
        ...opt('max_amount', options.maxAmount),
        ...opt('expected_amount', options.expectedAmount),
        ...opt('approval_wait_secs', options.approvalWait),
      });
      return emitHttp(env, 'x402', options.json, result);
    }),
  );

  withHttpOptions(
    program
      .command('mpp')
      .description(h.mpp)
      .option('--amount <units>', h.amount, mppAmount('--amount'))
      .option('--deposit <units>', h.deposit, mppAmount('--deposit'))
      .option('--max-deposit <units>', h.maxDeposit, mppAmount('--max-deposit'))
      .option('--currency <address>', h.currency)
      .option('--network <network>', h.network)
      .option('--session-state-file <path>', h.sessionStateFile)
      .option('--session-key <name>', h.sessionKey)
      .option('--close-session', h.closeSession),
  ).action(
    handler(env, async (url: string, options: MppOptions) => {
      if (options.sessionKey !== undefined && options.sessionStateFile !== undefined) {
        throw new UsageError('use either --session-key or --session-state-file, not both');
      }
      const sessionKey =
        options.sessionKey ??
        (options.sessionStateFile ? sessionKeyFromFile(options.sessionStateFile) : undefined);
      if (sessionKey !== undefined && !SESSION_KEY.test(sessionKey)) {
        throw new UsageError('--session-key must be 1 to 64 of A-Z a-z 0-9 . _ : -');
      }
      const request = httpRequest(options);
      const payments = await env.context.payments(options);
      const result = await payments.mpp({
        url,
        ...request,
        close_session: options.closeSession === true,
        ...opt('amount', options.amount),
        ...opt('deposit', options.deposit),
        ...opt('max_deposit', options.maxDeposit),
        ...opt('currency', options.currency),
        ...opt('network', options.network),
        ...opt('session_key', sessionKey),
        ...opt('approval_wait_secs', options.approvalWait),
      });
      return emitHttp(env, 'mpp', options.json, result);
    }),
  );
}
