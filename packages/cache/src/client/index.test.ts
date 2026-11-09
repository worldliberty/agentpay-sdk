import { describe, expect, it } from 'vitest';
import { parseCachePort } from './index.js';

describe('parseCachePort', () => {
  it('uses the default Redis port when unset or blank', () => {
    expect(parseCachePort(undefined)).toBe(6379);
    expect(parseCachePort('  ')).toBe(6379);
  });

  it('accepts explicit valid ports', () => {
    expect(parseCachePort('6380')).toBe(6380);
    expect(parseCachePort(' 65535 ')).toBe(65535);
  });

  it('rejects malformed and out of range ports', () => {
    for (const value of ['0', '65536', '-1', '12.5', '6379abc', 'Infinity']) {
      expect(() => parseCachePort(value)).toThrow(
        /CACHE_PORT must be an integer between 1 and 65535/,
      );
    }
  });
});
