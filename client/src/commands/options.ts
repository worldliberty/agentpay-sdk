/** Option parsing shared by the commands. */
import { type Command, InvalidArgumentError } from 'commander';
import { copy } from '../copy/index.js';
import { UsageError } from '../errors.js';
import { isDecimalString, isIntegerString } from '../format/amount.js';
import type { HttpBody, HttpHeader } from '../generated/index.js';

export interface JsonOption {
  json?: boolean;
}

export interface AgentOptions extends JsonOption {
  agentKeyId?: string;
  agentAuthTokenStdin?: boolean;
}

/** `--agent-key-id`, `--agent-auth-token-stdin`, `--json`. */
export function withAgentOptions(command: Command): Command {
  const p = copy.commands.program;
  return command
    .option('--agent-key-id <uuid>', p.agentKeyId)
    .option('--agent-auth-token-stdin', p.agentAuthTokenStdin)
    .option('--json', p.json);
}

export function positiveInt(value: string): number {
  if (!/^\d+$/u.test(value) || Number(value) <= 0 || !Number.isSafeInteger(Number(value))) {
    throw new InvalidArgumentError('expected a positive whole number');
  }
  return Number(value);
}

export function nonNegativeInt(value: string): number {
  if (!/^\d+$/u.test(value) || !Number.isSafeInteger(Number(value))) {
    throw new InvalidArgumentError('expected a whole number');
  }
  return Number(value);
}

export function decimalAmount(value: string): string {
  if (!isDecimalString(value) || /^0*(\.0*)?$/u.test(value.trim())) {
    throw new InvalidArgumentError('expected a positive decimal amount, for example 1.5');
  }
  return value.trim();
}

export function baseUnits(value: string): string {
  if (!isIntegerString(value)) {
    throw new InvalidArgumentError(
      copy.errors.usage('expected base units: a whole number').message,
    );
  }
  return value.trim().replace(/^0+(?=\d)/u, '');
}

export function collect(value: string, previous: string[] = []): string[] {
  return [...previous, value];
}

/** `{key: value}` when `value` is defined, else `{}` (for exact optional properties). */
export function opt<K extends string, V>(key: K, value: V | undefined): { [P in K]?: V } {
  return (value === undefined ? {} : { [key]: value }) as { [P in K]?: V };
}

export function parseHeader(value: string): HttpHeader {
  const separator = value.indexOf(':');
  if (separator <= 0) {
    throw new UsageError('--header must look like "Name: value"');
  }
  return { name: value.slice(0, separator).trim(), value: value.slice(separator + 1).trimStart() };
}

export interface HttpOptions {
  method?: string;
  header?: string[];
  data?: string;
  jsonBody?: string;
}

/** The `method`, `headers`, and `body` of an `X402Fetch` / `MppFetch` request. */
export function httpRequest(options: HttpOptions): {
  method?: string;
  headers?: HttpHeader[];
  body?: HttpBody;
} {
  if (options.data !== undefined && options.jsonBody !== undefined) {
    throw new UsageError('use either --data or --json-body, not both');
  }
  const headers = (options.header ?? []).map(parseHeader);
  let body: HttpBody | undefined;
  if (options.jsonBody !== undefined) {
    try {
      JSON.parse(options.jsonBody);
    } catch {
      throw new UsageError('--json-body is not valid JSON');
    }
    if (!headers.some((h) => h.name.toLowerCase() === 'content-type')) {
      headers.push({ name: 'Content-Type', value: 'application/json' });
    }
    body = { type: 'text', data: options.jsonBody };
  } else if (options.data !== undefined) {
    body = { type: 'text', data: options.data };
  }
  return {
    ...opt('method', options.method?.toUpperCase()),
    ...(headers.length > 0 ? { headers } : {}),
    ...opt('body', body),
  };
}
