/**
 * Railgun prover sidecar method registry.
 *
 * Track 4 scaffold: every method returns a JSON-RPC error indicating the
 * implementation is pending Track 3 (engine fork) + Track 2 Phase B
 * (Baby Jubjub / viewing-key signer). The shell exists so `vault-cli-agent`
 * can wire the spawn + stdio protocol without blocking on the engine fork.
 */

export type JsonRpcParams = unknown;

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

export interface JsonRpcSuccess {
  result: unknown;
}

export interface JsonRpcFailure {
  error: JsonRpcError;
}

export type MethodResult = JsonRpcSuccess | JsonRpcFailure;

export type MethodHandler = (params: JsonRpcParams) => Promise<MethodResult>;

export const NOT_IMPLEMENTED_CODE = -32000;
export const METHOD_NOT_FOUND_CODE = -32601;

const PENDING_TRACKS = '(Track 3 + Track 2 Phase B pending)';

function notImplemented(method: string): MethodHandler {
  return async () => ({
    error: {
      code: NOT_IMPLEMENTED_CODE,
      message: `${method} is not yet implemented ${PENDING_TRACKS}`,
    },
  });
}

export const methods: Record<string, MethodHandler> = {
  'shield.populate': notImplemented('shield.populate'),
  'unshield.generateProof': notImplemented('unshield.generateProof'),
  'unshield.populate': notImplemented('unshield.populate'),
  'transfer.generateProof': notImplemented('transfer.generateProof'),
  'transfer.populate': notImplemented('transfer.populate'),
  'balance.scan': notImplemented('balance.scan'),
};

export async function dispatch(method: string, params: JsonRpcParams): Promise<MethodResult> {
  const handler = methods[method];
  if (!handler) {
    return {
      error: {
        code: METHOD_NOT_FOUND_CODE,
        message: `Unknown method: ${method}`,
      },
    };
  }
  return handler(params);
}
