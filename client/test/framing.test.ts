import { describe, expect, it } from 'vitest';
import {
  decodeResponse,
  encodeFrame,
  encodeRequest,
  FrameDecoder,
  FrameTooLargeError,
  MAX_FRAME_BYTES,
  MalformedFrameError,
} from '../src/daemon/framing.js';

describe('framing', () => {
  it('encodes the documented Hello frame byte for byte', () => {
    const frame = encodeRequest({ method: 'Hello' });
    // docs/daemon-api.md: `00 00 00 26 {"body_json":"{\"method\":\"Hello\"}"}`
    expect(frame.subarray(0, 4).toString('hex')).toBe('00000026');
    expect(frame.subarray(4).toString('utf8')).toBe('{"body_json":"{\\"method\\":\\"Hello\\"}"}');
  });

  it('double-encodes the request inside body_json', () => {
    const frame = encodeRequest({ method: 'GetConfig', params: { auth: { agent_key_id: 'a' } } });
    const envelope = JSON.parse(frame.subarray(4).toString('utf8')) as { body_json: string };
    expect(typeof envelope.body_json).toBe('string');
    expect(JSON.parse(envelope.body_json)).toEqual({
      method: 'GetConfig',
      params: { auth: { agent_key_id: 'a' } },
    });
  });

  it('refuses to write more than 256 KiB', () => {
    expect(MAX_FRAME_BYTES).toBe(262_144);
    expect(() => encodeFrame(new Uint8Array(MAX_FRAME_BYTES + 1))).toThrow(FrameTooLargeError);
    expect(encodeFrame(new Uint8Array(MAX_FRAME_BYTES)).length).toBe(MAX_FRAME_BYTES + 4);
  });

  it('reassembles a frame split across chunks, including inside the header', () => {
    const frame = encodeFrame(Buffer.from('{"ok":true,"body_json":"{}"}'));
    const decoder = new FrameDecoder();
    expect(decoder.push(frame.subarray(0, 2))).toBeNull();
    expect(decoder.push(frame.subarray(2, 9))).toBeNull();
    const payload = decoder.push(frame.subarray(9));
    expect(payload?.toString('utf8')).toBe('{"ok":true,"body_json":"{}"}');
  });

  it('rejects an announced length over the limit before buffering it', () => {
    const header = Buffer.alloc(4);
    header.writeUInt32BE(MAX_FRAME_BYTES + 1, 0);
    expect(() => new FrameDecoder().push(header)).toThrow(FrameTooLargeError);
  });

  it('rejects trailing bytes after the response frame', () => {
    const frame = Buffer.concat([encodeFrame(Buffer.from('{}')), Buffer.from('x')]);
    expect(() => new FrameDecoder().push(frame)).toThrow(MalformedFrameError);
  });

  it('decodes ok and error responses and rejects malformed ones', () => {
    expect(
      decodeResponse(Buffer.from('{"ok":true,"body_json":"{\\"type\\":\\"Unit\\"}"}')),
    ).toEqual({
      ok: true,
      body: { type: 'Unit' },
    });
    expect(
      decodeResponse(Buffer.from('{"ok":false,"body_json":"{\\"kind\\":\\"UnknownLease\\"}"}')),
    ).toEqual({
      ok: false,
      body: { kind: 'UnknownLease' },
    });
    expect(() => decodeResponse(Buffer.from('nope'))).toThrow(MalformedFrameError);
    expect(() => decodeResponse(Buffer.from('{"ok":"yes"}'))).toThrow(MalformedFrameError);
    expect(() => decodeResponse(Buffer.from('{"ok":true,"body_json":"{"}'))).toThrow(
      MalformedFrameError,
    );
  });
});
