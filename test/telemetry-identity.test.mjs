import assert from 'node:assert/strict';
import test from 'node:test';

const modulePath = new URL('../src/lib/telemetry-identity.ts', import.meta.url);
const credentialsPath = new URL('../src/lib/telemetry-credentials.ts', import.meta.url);

async function loadModule(caseSuffix) {
  return await import(`${modulePath.href}?case=${caseSuffix}-${Date.now()}`);
}

const INSTALL_ID = '3f1c6a1e-59b3-4c4f-9a6f-2f1f1d0a11b2';

test('resolveDistinctId is the random install id and nothing else', async () => {
  const { resolveDistinctId } = await loadModule('install-id');

  assert.equal(resolveDistinctId(INSTALL_ID), INSTALL_ID);
  assert.equal(resolveDistinctId(`  ${INSTALL_ID}\n`), INSTALL_ID);
});

test('resolveDistinctId takes no wallet input and carries no prefix', async () => {
  const identity = await loadModule('no-wallet');

  // The earlier design accepted a wallet address and HMAC'd it under a bundled salt; a public salt
  // lets anyone confirm which address is behind an id, so the whole path is gone.
  assert.equal(identity.resolveDistinctId.length, 1);
  assert.equal(identity.installIdentity, undefined);
  assert.ok(!resolveDistinctIdMatchesPrefix(identity.resolveDistinctId(INSTALL_ID)));
});

function resolveDistinctIdMatchesPrefix(value) {
  return /^(?:w|i)_/u.test(value);
}

test('the credentials module no longer ships an identity salt', async () => {
  const credentials = await import(`${credentialsPath.href}?case=no-salt-${Date.now()}`);

  assert.equal(credentials.telemetrySalt, undefined);
  assert.equal(typeof credentials.sentryDsn, 'function');
  assert.equal(typeof credentials.mixpanelToken, 'function');
  assert.equal(typeof credentials.mixpanelTrackUrl, 'function');
});
