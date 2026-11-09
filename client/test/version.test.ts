import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { API_VERSION } from '../src/generated/index.js';
import { VERSION } from '../src/program.js';

describe('version', () => {
  it('matches the package version', () => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
      version: string;
    };
    expect(VERSION).toBe(pkg.version);
  });

  it('is released together with the matching API major version', () => {
    expect(VERSION.split('.')[0]).toBe(API_VERSION.split('.')[0]);
  });
});
