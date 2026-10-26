/**
 * Railgun prover sidecar entrypoint.
 *
 * Reads newline-delimited JSON-RPC 2.0 requests from stdin, writes
 * newline-delimited JSON-RPC responses to stdout. The parent process
 * (`vault-cli-agent`) spawns this binary on demand for proof generation,
 * Waku broadcasting, and balance scanning.
 *
 * On startup we emit a single `{ "type": "ready", "version": ... }` line so
 * the parent can detect readiness before sending the first request.
 */

import { createInterface } from 'node:readline';
import { dispatch, type MethodResult } from './methods';

export const SIDECAR_VERSION = '0.0.0-track4-scaffold';
export const READY_MESSAGE = { type: 'ready', version: SIDECAR_VERSION } as const;

const PARSE_ERROR_CODE = -32700;
const INVALID_REQUEST_CODE = -32600;
const INTERNAL_ERROR_CODE = -32603;

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: string | number | null;
  method: string;
  params?: unknown;
}

interface JsonRpcResponseEnvelope {
  jsonrpc: '2.0';
  id: string | number | null;
}

type JsonRpcResponse = JsonRpcResponseEnvelope &
  ({ result: unknown } | { error: { code: number; message: string; data?: unknown } });

export function emitReady(write: (line: string) => void = writeLine): void {
  write(JSON.stringify(READY_MESSAGE));
}

function writeLine(line: string): void {
  process.stdout.write(`${line}\n`);
}

function buildResponse(id: string | number | null, result: MethodResult): JsonRpcResponse {
  if ('error' in result) {
    return { jsonrpc: '2.0', id, error: result.error };
  }
  return { jsonrpc: '2.0', id, result: result.result };
}

function parseRequest(raw: string): JsonRpcRequest | { parseError: true } {
  try {
    const value = JSON.parse(raw);
    if (
      value === null ||
      typeof value !== 'object' ||
      (value as { jsonrpc?: unknown }).jsonrpc !== '2.0' ||
      typeof (value as { method?: unknown }).method !== 'string'
    ) {
      return { parseError: true };
    }
    return value as JsonRpcRequest;
  } catch {
    return { parseError: true };
  }
}

export async function handleLine(line: string): Promise<JsonRpcResponse | null> {
  const trimmed = line.trim();
  if (trimmed.length === 0) {
    return null;
  }
  const parsed = parseRequest(trimmed);
  if ('parseError' in parsed) {
    return {
      jsonrpc: '2.0',
      id: null,
      error: { code: PARSE_ERROR_CODE, message: 'Failed to parse JSON-RPC request' },
    };
  }
  if (typeof parsed.method !== 'string' || parsed.method.length === 0) {
    return {
      jsonrpc: '2.0',
      id: parsed.id ?? null,
      error: { code: INVALID_REQUEST_CODE, message: 'Request is missing a method name' },
    };
  }
  try {
    const result = await dispatch(parsed.method, parsed.params);
    return buildResponse(parsed.id ?? null, result);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unhandled sidecar error';
    return {
      jsonrpc: '2.0',
      id: parsed.id ?? null,
      error: { code: INTERNAL_ERROR_CODE, message, data: { kind: 'unhandled-exception' } },
    };
  }
}

export async function runStdinLoop(): Promise<void> {
  emitReady();
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of rl) {
    const response = await handleLine(line);
    if (response !== null) {
      writeLine(JSON.stringify(response));
    }
  }
}

// Re-export for parent processes / tests that want the dispatcher directly.
export { dispatch, METHOD_NOT_FOUND_CODE, methods } from './methods';

const isDirectInvocation = typeof require !== 'undefined' && require.main === module;

if (isDirectInvocation) {
  runStdinLoop().catch((err) => {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`railgun-prover fatal: ${message}\n`);
    process.exit(1);
  });
}
