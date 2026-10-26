import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const modulePath = new URL('../src/lib/secret-service.ts', import.meta.url);
const TEST_AGENT_KEY_ID = '00000000-0000-0000-0000-000000000001';

async function withFakeSecretTool(scriptBody, fn) {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-secret-tool-'));
  const originalPath = process.env.PATH;
  const platformDescriptor = Object.getOwnPropertyDescriptor(process, 'platform');

  fs.writeFileSync(path.join(tempRoot, 'secret-tool'), `#!/bin/sh\n${scriptBody}\n`, {
    mode: 0o755,
  });
  Object.defineProperty(process, 'platform', { value: 'linux', configurable: true });
  process.env.PATH = `${tempRoot}${path.delimiter}${originalPath ?? ''}`;

  try {
    await fn();
  } finally {
    if (platformDescriptor) {
      Object.defineProperty(process, 'platform', platformDescriptor);
    }
    if (originalPath === undefined) {
      delete process.env.PATH;
    } else {
      process.env.PATH = originalPath;
    }
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

test('readAgentAuthTokenFromSecretService strips exactly one trailing newline and keeps edge whitespace', async () => {
  const service = await import(`${modulePath.href}?case=${Date.now()}-single-newline`);

  await withFakeSecretTool(`printf ' token-with-edges \\n'`, async () => {
    assert.equal(
      service.readAgentAuthTokenFromSecretService(TEST_AGENT_KEY_ID),
      ' token-with-edges ',
    );
  });
});

test('readAgentAuthTokenFromSecretService preserves embedded and doubled newlines', async () => {
  const service = await import(`${modulePath.href}?case=${Date.now()}-embedded-newline`);

  await withFakeSecretTool(`printf 'line-one\\nline-two\\n\\n'`, async () => {
    assert.equal(
      service.readAgentAuthTokenFromSecretService(TEST_AGENT_KEY_ID),
      'line-one\nline-two\n',
    );
  });
});

test('readAgentAuthTokenFromSecretService returns secrets without a trailing newline unchanged', async () => {
  const service = await import(`${modulePath.href}?case=${Date.now()}-no-newline`);

  await withFakeSecretTool(`printf 'bare-token'`, async () => {
    assert.equal(service.readAgentAuthTokenFromSecretService(TEST_AGENT_KEY_ID), 'bare-token');
  });
});

test('readAgentAuthTokenFromSecretService treats a missing secret as null', async () => {
  const service = await import(`${modulePath.href}?case=${Date.now()}-missing`);

  await withFakeSecretTool('exit 1', async () => {
    assert.equal(service.readAgentAuthTokenFromSecretService(TEST_AGENT_KEY_ID), null);
  });
});
