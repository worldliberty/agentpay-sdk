import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { exchange } from '../src/daemon/transport.js';
import { TransportError } from '../src/errors.js';
import { type FakeDaemon, frame, ok, startFakeDaemon } from './helpers/fake-daemon.js';

const options = { service: 'signer' as const, timeoutMs: 2000 };
let daemon: FakeDaemon | null = null;

afterEach(async () => {
  await daemon?.close();
  daemon = null;
});

async function expectTransportError(promise: Promise<unknown>, code: string) {
  const error = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(TransportError);
  expect((error as TransportError).code).toBe(code);
  expect((error as TransportError).guidance.next).toMatch(/\S/u);
}

describe('exchange over a Unix socket', () => {
  it('sends one framed request and decodes the framed response', async () => {
    daemon = await startFakeDaemon(() => ok('Hello', { api_version: '1.1.0' }));
    const response = await exchange(daemon.path, { method: 'Hello' }, options);
    expect(response).toEqual({ ok: true, body: { type: 'Hello', data: { api_version: '1.1.0' } } });
    expect(daemon.calls).toEqual([{ method: 'Hello' }]);
  });

  it('reads a response delivered in small chunks', async () => {
    const bytes = frame({ ok: true, body_json: JSON.stringify({ type: 'Unit' }) });
    daemon = await startFakeDaemon(() => ({ raw: bytes }));
    await expect(exchange(daemon.path, { method: 'X' }, options)).resolves.toEqual({
      ok: true,
      body: { type: 'Unit' },
    });
  });

  it('reports a connection closed without a response (transport rejection)', async () => {
    daemon = await startFakeDaemon(() => ({ close: true }));
    await expectTransportError(
      exchange(daemon.path, { method: 'Hello' }, options),
      'closed_without_response',
    );
  });

  it('reports a missing socket', async () => {
    const path = join(mkdtempSync(join(tmpdir(), 'apd-')), 'missing.sock');
    await expectTransportError(exchange(path, { method: 'Hello' }, options), 'socket_missing');
  });

  it('times out when the daemon never answers', async () => {
    daemon = await startFakeDaemon(() => ({ hang: true }));
    await expectTransportError(
      exchange(daemon.path, { method: 'Hello' }, { ...options, timeoutMs: 100 }),
      'timeout',
    );
  });

  it('rejects an oversized response frame', async () => {
    const header = Buffer.alloc(4);
    header.writeUInt32BE(300_000, 0);
    daemon = await startFakeDaemon(() => ({ raw: header }));
    await expectTransportError(
      exchange(daemon.path, { method: 'Hello' }, options),
      'frame_too_large',
    );
  });

  it('rejects a malformed response', async () => {
    const payload = Buffer.from('not json');
    const header = Buffer.alloc(4);
    header.writeUInt32BE(payload.length, 0);
    daemon = await startFakeDaemon(() => ({ raw: Buffer.concat([header, payload]) }));
    await expectTransportError(
      exchange(daemon.path, { method: 'Hello' }, options),
      'malformed_response',
    );
  });

  it('refuses to send a request over 256 KiB', async () => {
    daemon = await startFakeDaemon(() => ok('Unit'));
    await expectTransportError(
      exchange(daemon.path, { method: 'X', params: { blob: 'x'.repeat(300_000) } }, options),
      'frame_too_large',
    );
    expect(daemon.calls).toEqual([]);
  });
});
