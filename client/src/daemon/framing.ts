/**
 * Wire framing shared by both daemons (docs/daemon-api.md, "Transport"): each connection
 * carries one frame each way, `[u32 big-endian length][UTF-8 JSON]`, at most 256 KiB of JSON.
 * The JSON is a `WireRequest` / `WireResponse` whose `body_json` holds the request or response
 * serialized again as a string.
 */
import { MAX_WIRE_BODY_BYTES, type WireResponse } from '../generated/index.js';

export const MAX_FRAME_BYTES = MAX_WIRE_BODY_BYTES;
const HEADER_BYTES = 4;

export class FrameTooLargeError extends Error {
  readonly size: number;

  constructor(size: number) {
    super(`frame of ${size} bytes exceeds the ${MAX_FRAME_BYTES}-byte limit`);
    this.size = size;
  }
}

export class MalformedFrameError extends Error {}

/** Prefixes `payload` with its big-endian u32 length. */
export function encodeFrame(payload: Uint8Array): Buffer {
  if (payload.byteLength > MAX_FRAME_BYTES) {
    throw new FrameTooLargeError(payload.byteLength);
  }
  const header = Buffer.alloc(HEADER_BYTES);
  header.writeUInt32BE(payload.byteLength, 0);
  return Buffer.concat([header, payload]);
}

/** Encodes `request` (a `DaemonRpcRequest` or `PaymentsRpcRequest`) as a framed `WireRequest`. */
export function encodeRequest(request: unknown): Buffer {
  const envelope = JSON.stringify({ body_json: JSON.stringify(request) });
  return encodeFrame(Buffer.from(envelope, 'utf8'));
}

/**
 * Accumulates socket chunks until one complete frame has arrived. Rejects an announced length
 * over the limit before buffering it.
 */
export class FrameDecoder {
  private chunks: Buffer[] = [];
  private received = 0;
  private expected: number | null = null;

  /** Adds `chunk`; returns the frame payload once complete, else `null`. */
  push(chunk: Buffer): Buffer | null {
    this.chunks.push(chunk);
    this.received += chunk.byteLength;
    if (this.expected === null && this.received >= HEADER_BYTES) {
      const buffered = Buffer.concat(this.chunks);
      this.chunks = [buffered];
      this.expected = buffered.readUInt32BE(0);
      if (this.expected > MAX_FRAME_BYTES) {
        throw new FrameTooLargeError(this.expected);
      }
    }
    if (this.expected === null || this.received < HEADER_BYTES + this.expected) {
      return null;
    }
    const all = Buffer.concat(this.chunks);
    if (all.byteLength > HEADER_BYTES + this.expected) {
      throw new MalformedFrameError('received bytes after the response frame');
    }
    return all.subarray(HEADER_BYTES, HEADER_BYTES + this.expected);
  }
}

/** Parses a frame payload as a `WireResponse` and the JSON inside `body_json`. */
export function decodeResponse(payload: Buffer): { ok: boolean; body: unknown } {
  let envelope: unknown;
  try {
    envelope = JSON.parse(payload.toString('utf8'));
  } catch {
    throw new MalformedFrameError('response frame is not JSON');
  }
  if (!isWireResponse(envelope)) {
    throw new MalformedFrameError('response frame is not a WireResponse');
  }
  try {
    return { ok: envelope.ok, body: JSON.parse(envelope.body_json) };
  } catch {
    throw new MalformedFrameError('body_json is not JSON');
  }
}

function isWireResponse(value: unknown): value is WireResponse {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as WireResponse).ok === 'boolean' &&
    typeof (value as WireResponse).body_json === 'string'
  );
}
