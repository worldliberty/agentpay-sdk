/**
 * One request/response exchange over a Unix socket: connect, write one frame, read one frame,
 * close. A new connection is opened for every call (docs/daemon-api.md, "Connection lifecycle").
 */
import { createConnection } from 'node:net';
import { copy } from '../copy/index.js';
import { type ServiceName, serviceLabel, TransportError } from '../errors.js';
import { decodeResponse, encodeRequest, FrameDecoder, FrameTooLargeError } from './framing.js';

/** Default client timeout: the daemons use 10 s per frame read or write. */
export const DEFAULT_TIMEOUT_MS = 15_000;

export interface ExchangeOptions {
  service: ServiceName;
  timeoutMs: number;
}

/** A decoded response: `ok` and the parsed `body_json`. */
export interface RawResponse {
  ok: boolean;
  body: unknown;
}

/** Sends `request` to the socket at `path` and resolves with the decoded response. */
export type Exchange = (
  path: string,
  request: unknown,
  options: ExchangeOptions,
) => Promise<RawResponse>;

export const exchange: Exchange = (path, request, { service, timeoutMs }) => {
  const label = serviceLabel(service);
  let frame: Buffer;
  try {
    frame = encodeRequest(request);
  } catch (error) {
    if (error instanceof FrameTooLargeError) {
      return Promise.reject(
        new TransportError('frame_too_large', service, copy.errors.frameTooLarge),
      );
    }
    return Promise.reject(error);
  }

  return new Promise<RawResponse>((resolve, reject) => {
    const decoder = new FrameDecoder();
    let settled = false;
    const socket = createConnection({ path });

    const finish = (outcome: { value: RawResponse } | { error: TransportError }) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if ('value' in outcome) {
        resolve(outcome.value);
      } else {
        reject(outcome.error);
      }
    };

    const timer = setTimeout(() => {
      finish({
        error: new TransportError(
          'timeout',
          service,
          copy.errors.timeout(label, Math.round(timeoutMs / 1000)),
        ),
      });
    }, timeoutMs);

    socket.on('connect', () => {
      socket.write(frame);
    });

    socket.on('data', (chunk: Buffer) => {
      try {
        const payload = decoder.push(chunk);
        if (payload) {
          finish({ value: decodeResponse(payload) });
        }
      } catch (error) {
        const tooLarge = error instanceof FrameTooLargeError;
        finish({
          error: new TransportError(
            tooLarge ? 'frame_too_large' : 'malformed_response',
            service,
            tooLarge ? copy.errors.frameTooLarge : copy.errors.malformedResponse(label),
          ),
        });
      }
    });

    socket.on('end', () => {
      finish({
        error: new TransportError(
          'closed_without_response',
          service,
          copy.errors.rejectedByTransport(label),
        ),
      });
    });

    socket.on('error', (error: NodeJS.ErrnoException) => {
      finish({ error: socketError(error, service, path) });
    });
  });
};

function socketError(error: NodeJS.ErrnoException, service: ServiceName, path: string) {
  const label = serviceLabel(service);
  if (error.code === 'ENOENT') {
    return new TransportError('socket_missing', service, copy.errors.socketMissing(label, path));
  }
  if (error.code === 'EPIPE' || error.code === 'ECONNRESET') {
    return new TransportError(
      'closed_without_response',
      service,
      copy.errors.rejectedByTransport(label),
    );
  }
  return new TransportError(
    'connect_failed',
    service,
    copy.errors.connectFailed(label, error.code ?? error.message),
  );
}
