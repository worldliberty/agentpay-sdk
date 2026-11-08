/** The API contract's own examples (crates/agentpay-api/fixtures), used as daemon responses. */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = new URL('../../../crates/agentpay-api/fixtures/', import.meta.url);

export function fixture<T = { type: string; data: unknown }>(path: string): T {
  return JSON.parse(readFileSync(fileURLToPath(new URL(path, ROOT)), 'utf8')) as T;
}

/** `data` of a response fixture. */
export function fixtureData<T>(path: string): T {
  return fixture<{ data: T }>(path).data;
}
