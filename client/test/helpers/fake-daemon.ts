/**
 * A fake daemon on a real Unix socket, speaking the documented framing independently of the
 * client's own framing code: `[u32 BE length][{"body_json": "<request JSON>"}]` in, the same
 * envelope with `ok` out, then close.
 */
import { mkdtempSync } from 'node:fs';
import { createServer, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { API_VERSION, type HelloResponse } from '../../src/generated/index.js';
import { fixtureData } from './fixtures.js';

export interface WireCall {
  method: string;
  params?: Record<string, unknown>;
}

export type Reply =
  | { ok: boolean; body: unknown }
  | { close: true }
  | { raw: Buffer }
  | { hang: true };

export type Handler = (call: WireCall) => Reply | Promise<Reply>;

export interface FakeDaemon {
  path: string;
  calls: WireCall[];
  close(): Promise<void>;
}

export const ok = (type: string, data?: unknown): Reply => ({
  ok: true,
  body: data === undefined ? { type } : { type, data },
});

export const fail = (kind: string, data?: unknown): Reply => ({
  ok: false,
  body: data === undefined ? { kind } : { kind, data },
});

export function frame(value: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(value), 'utf8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

/** The API fixture's `Hello`, reporting the API version of the generated bindings. */
export const HELLO: HelloResponse = {
  ...fixtureData<HelloResponse>('rpc/Hello.response.json'),
  api_version: API_VERSION,
};

/** Answers `Hello` like a daemon of this API version; everything else goes to `handler`. */
export function withHello(handler: Handler): Handler {
  return (call) => (call.method === 'Hello' ? ok('Hello', HELLO) : handler(call));
}

export async function startFakeDaemon(handler: Handler): Promise<FakeDaemon> {
  const dir = mkdtempSync(join(tmpdir(), 'apd-'));
  const path = join(dir, 's.sock');
  const calls: WireCall[] = [];
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    let buffer = Buffer.alloc(0);
    socket.on('data', async (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length < 4 || buffer.length < 4 + buffer.readUInt32BE(0)) {
        return;
      }
      const envelope = JSON.parse(
        buffer.subarray(4, 4 + buffer.readUInt32BE(0)).toString('utf8'),
      ) as {
        body_json: string;
      };
      const call = JSON.parse(envelope.body_json) as WireCall;
      calls.push(call);
      const reply = await handler(call);
      if ('hang' in reply) {
        return;
      }
      if ('close' in reply) {
        socket.destroy();
        return;
      }
      socket.end(
        'raw' in reply ? reply.raw : frame({ ok: reply.ok, body_json: JSON.stringify(reply.body) }),
      );
    });
  });
  await new Promise<void>((resolve) => server.listen(path, resolve));
  return {
    path,
    calls,
    close: () =>
      new Promise<void>((resolve) => {
        for (const socket of sockets) {
          socket.destroy();
        }
        server.close(() => resolve());
      }),
  };
}

/** A successful reply carrying a whole response body (for example an API fixture). */
export const body = (response: unknown): Reply => ({ ok: true, body: response });
