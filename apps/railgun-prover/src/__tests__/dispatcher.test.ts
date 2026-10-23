import { describe, expect, it } from 'vitest';
import { emitReady, handleLine, READY_MESSAGE, SIDECAR_VERSION } from '../index';
import { dispatch, methods, NOT_IMPLEMENTED_CODE } from '../methods';

const EXPECTED_METHOD_NAMES = [
  'shield.populate',
  'unshield.generateProof',
  'unshield.populate',
  'transfer.generateProof',
  'transfer.populate',
  'balance.scan',
] as const;

describe('railgun-prover method registry', () => {
  it('registers exactly the Track 4 method set', () => {
    expect(Object.keys(methods).sort()).toEqual([...EXPECTED_METHOD_NAMES].sort());
  });

  for (const method of EXPECTED_METHOD_NAMES) {
    it(`returns the pending-track error for ${method}`, async () => {
      const result = await dispatch(method, {});
      expect(result).toEqual({
        error: {
          code: NOT_IMPLEMENTED_CODE,
          message: `${method} is not yet implemented (Track 3 + Track 2 Phase B pending)`,
        },
      });
    });
  }

  it('returns method-not-found for unknown methods', async () => {
    const result = await dispatch('mystery.method', {});
    expect(result).toEqual({
      error: {
        code: -32601,
        message: 'Unknown method: mystery.method',
      },
    });
  });
});

describe('railgun-prover ready signal', () => {
  it('emits a single ready line with the scaffold version', () => {
    const emitted: string[] = [];
    emitReady((line) => emitted.push(line));
    expect(emitted).toHaveLength(1);
    const parsed = JSON.parse(emitted[0] ?? '{}');
    expect(parsed).toEqual({ type: 'ready', version: SIDECAR_VERSION });
    expect(READY_MESSAGE).toEqual(parsed);
  });

  it('emits ready before any request can be handled', async () => {
    // The contract: parents wait for the ready line, then send requests.
    // Simulate that ordering: emit ready, then dispatch a request, and assert
    // the ready line came out first.
    const transcript: string[] = [];
    emitReady((line) => transcript.push(`ready:${line}`));
    const response = await handleLine(
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'shield.populate', params: {} }),
    );
    transcript.push(`response:${JSON.stringify(response)}`);
    expect(transcript[0]?.startsWith('ready:')).toBe(true);
    expect(transcript[1]?.startsWith('response:')).toBe(true);
    expect(response).toMatchObject({
      jsonrpc: '2.0',
      id: 1,
      error: { code: NOT_IMPLEMENTED_CODE },
    });
  });
});

describe('railgun-prover line handler', () => {
  it('ignores blank lines', async () => {
    const response = await handleLine('   ');
    expect(response).toBeNull();
  });

  it('surfaces parse errors as JSON-RPC parse-error responses', async () => {
    const response = await handleLine('{not json');
    expect(response).toMatchObject({
      jsonrpc: '2.0',
      id: null,
      error: { code: -32700 },
    });
  });

  it('rejects requests that are missing the jsonrpc envelope', async () => {
    const response = await handleLine(JSON.stringify({ id: 1, method: 'shield.populate' }));
    expect(response).toMatchObject({
      jsonrpc: '2.0',
      id: null,
      error: { code: -32700 },
    });
  });

  it('preserves the request id on the response', async () => {
    const response = await handleLine(
      JSON.stringify({ jsonrpc: '2.0', id: 'req-42', method: 'balance.scan' }),
    );
    expect(response).toMatchObject({
      jsonrpc: '2.0',
      id: 'req-42',
      error: { code: NOT_IMPLEMENTED_CODE },
    });
  });
});
