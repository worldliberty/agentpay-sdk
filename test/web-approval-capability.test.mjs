import assert from 'node:assert/strict';
import test from 'node:test';

const modulePath = new URL('../apps/web/src/lib/approval-capability.ts', import.meta.url);

async function loadModule(caseSuffix) {
  return await import(`${modulePath.href}?case=${caseSuffix}-${Date.now()}`);
}

test('resolveApprovalCapability normalizes valid secure-link capability tokens', async () => {
  const capability = await loadModule('valid');
  const resolved = capability.resolveApprovalCapability('AA'.repeat(32));

  assert.deepEqual(resolved, {
    value: 'aa'.repeat(32),
    state: 'loaded',
    reason: null,
  });
});

test('resolveApprovalCapability treats empty secure-link capability tokens as missing', async () => {
  const capability = await loadModule('missing');
  const resolved = capability.resolveApprovalCapability(['   ']);

  assert.equal(resolved.value, null);
  assert.equal(resolved.state, 'missing');
  assert.match(resolved.reason ?? '', /missing its secure approval capability/);
});

test('resolveApprovalCapability rejects malformed secure-link capability tokens', async () => {
  const capability = await loadModule('invalid');
  const resolved = capability.resolveApprovalCapability('not-hex');

  assert.equal(resolved.value, null);
  assert.equal(resolved.state, 'invalid');
  assert.match(resolved.reason ?? '', /malformed or has been altered/);
});

test('persistApprovalCapability stores normalized capability tokens for later page reloads', async () => {
  const capability = await loadModule('persist');
  const storage = new Map();
  const resolved = capability.persistApprovalCapability('approval-1', 'AA'.repeat(32), {
    getItem: (key) => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, value),
  });

  assert.equal(resolved.state, 'loaded');
  assert.equal(storage.get(capability.approvalCapabilityStorageKey('approval-1')), 'aa'.repeat(32));
});

test('resolveStoredApprovalCapability loads normalized session capability values', async () => {
  const capability = await loadModule('stored');
  const storage = new Map([
    [capability.approvalCapabilityStorageKey('approval-2'), 'BB'.repeat(32)],
  ]);
  const resolved = capability.resolveStoredApprovalCapability('approval-2', {
    getItem: (key) => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, value),
    removeItem: (key) => storage.delete(key),
  });

  assert.deepEqual(resolved, {
    value: 'bb'.repeat(32),
    state: 'loaded',
    reason: null,
  });
});

test('resolveStoredApprovalCapability clears malformed stored values', async () => {
  const capability = await loadModule('stored-invalid');
  const storage = new Map([[capability.approvalCapabilityStorageKey('approval-3'), 'not-hex']]);
  const resolved = capability.resolveStoredApprovalCapability('approval-3', {
    getItem: (key) => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, value),
    removeItem: (key) => storage.delete(key),
  });

  assert.equal(resolved.state, 'invalid');
  assert.equal(storage.has(capability.approvalCapabilityStorageKey('approval-3')), false);
});

test('clearApprovalCapability removes stored capability and marks it consumed', async () => {
  const capability = await loadModule('clear');
  const key = capability.approvalCapabilityStorageKey('approval-4');
  const storage = new Map([[key, 'cc'.repeat(32)]]);

  const resolved = capability.clearApprovalCapability('approval-4', {
    getItem: (entryKey) => storage.get(entryKey) ?? null,
    setItem: (entryKey, value) => storage.set(entryKey, value),
    removeItem: (entryKey) => storage.delete(entryKey),
  });

  assert.equal(resolved.value, null);
  assert.equal(resolved.state, 'consumed');
  assert.match(resolved.reason ?? '', /already submitted from this browser session/);
  assert.equal(storage.has(key), false);
});

test('createApprovalCapabilitySyncMessage normalizes loaded capability sync payloads', async () => {
  const capability = await loadModule('sync-create-loaded');
  const message = capability.createApprovalCapabilitySyncMessage(
    ' approval-5 ',
    'DD'.repeat(32),
    'loaded',
  );

  assert.deepEqual(message, {
    approvalId: 'approval-5',
    capability: 'dd'.repeat(32),
    state: 'loaded',
  });
});

test('createApprovalCapabilitySyncMessage strips capability data from consumed sync payloads', async () => {
  const capability = await loadModule('sync-create-consumed');
  const message = capability.createApprovalCapabilitySyncMessage(
    'approval-6',
    'EE'.repeat(32),
    'consumed',
  );

  assert.deepEqual(message, {
    approvalId: 'approval-6',
    capability: null,
    state: 'consumed',
  });
});

test('parseApprovalCapabilitySyncMessage accepts valid loaded sync payloads', async () => {
  const capability = await loadModule('sync-parse-loaded');
  const message = capability.parseApprovalCapabilitySyncMessage({
    approvalId: ' approval-7 ',
    capability: 'FF'.repeat(32),
    state: 'loaded',
  });

  assert.deepEqual(message, {
    approvalId: 'approval-7',
    capability: 'ff'.repeat(32),
    state: 'loaded',
  });
});

test('parseApprovalCapabilitySyncMessage rejects malformed loaded sync payloads', async () => {
  const capability = await loadModule('sync-parse-invalid');
  const message = capability.parseApprovalCapabilitySyncMessage({
    approvalId: 'approval-8',
    capability: 'not-hex',
    state: 'loaded',
  });

  assert.equal(message, null);
});

test('parseApprovalLinkFragment reads capability, daemon id, and daemon key from the fragment', async () => {
  const capability = await loadModule('fragment-valid');
  const parsed = capability.parseApprovalLinkFragment(
    `#approvalCapability=${'AA'.repeat(32)}&daemonId=${'BB'.repeat(32)}&daemonKey=${'CC'.repeat(32)}`,
  );

  assert.equal(parsed.present, true);
  assert.deepEqual(parsed.capability, { value: 'aa'.repeat(32), state: 'loaded', reason: null });
  assert.equal(parsed.daemonId, 'bb'.repeat(32));
  assert.equal(parsed.daemonKey, 'cc'.repeat(32));
});

test('parseApprovalLinkFragment treats a capability without a well-formed daemon key as invalid', async () => {
  const capability = await loadModule('fragment-missing-key');
  const missingKey = capability.parseApprovalLinkFragment(
    `#approvalCapability=${'aa'.repeat(32)}&daemonId=${'bb'.repeat(32)}`,
  );
  const malformedKey = capability.parseApprovalLinkFragment(
    `#approvalCapability=${'aa'.repeat(32)}&daemonId=${'bb'.repeat(32)}&daemonKey=zz`,
  );

  assert.equal(missingKey.capability.state, 'invalid');
  assert.equal(missingKey.capability.value, null);
  assert.equal(malformedKey.capability.state, 'invalid');
});

test('parseApprovalLinkFragment reports an empty fragment as absent', async () => {
  const capability = await loadModule('fragment-empty');
  const parsed = capability.parseApprovalLinkFragment('');

  assert.equal(parsed.present, false);
  assert.equal(parsed.capability.state, 'missing');
});

test('daemonKeysMatch compares hex keys case-insensitively and rejects malformed input', async () => {
  const capability = await loadModule('daemon-key-match');

  assert.equal(capability.daemonKeysMatch('AB'.repeat(32), 'ab'.repeat(32)), true);
  assert.equal(capability.daemonKeysMatch('ab'.repeat(32), 'cd'.repeat(32)), false);
  assert.equal(capability.daemonKeysMatch(null, 'ab'.repeat(32)), false);
  assert.equal(capability.daemonKeysMatch('not-hex', 'not-hex'), false);
});

test('pinned daemon keys persist per approval and are cleared with the capability', async () => {
  const capability = await loadModule('daemon-key-storage');
  const storage = new Map();
  const storageLike = {
    getItem: (entryKey) => storage.get(entryKey) ?? null,
    setItem: (entryKey, value) => storage.set(entryKey, value),
    removeItem: (entryKey) => storage.delete(entryKey),
  };

  assert.equal(
    capability.persistApprovalDaemonKey('approval-9', 'DD'.repeat(32), storageLike),
    'dd'.repeat(32),
  );
  assert.equal(
    capability.resolveStoredApprovalDaemonKey('approval-9', storageLike),
    'dd'.repeat(32),
  );

  capability.clearApprovalCapability('approval-9', storageLike);
  assert.equal(capability.resolveStoredApprovalDaemonKey('approval-9', storageLike), null);
});

test('capability sync messages carry a normalized daemon key and reject malformed ones', async () => {
  const capability = await loadModule('sync-daemon-key');

  assert.deepEqual(
    capability.createApprovalCapabilitySyncMessage(
      'approval-10',
      'aa'.repeat(32),
      'loaded',
      'EE'.repeat(32),
    ),
    {
      approvalId: 'approval-10',
      capability: 'aa'.repeat(32),
      daemonKey: 'ee'.repeat(32),
      state: 'loaded',
    },
  );
  assert.equal(
    capability.parseApprovalCapabilitySyncMessage({
      approvalId: 'approval-10',
      capability: 'aa'.repeat(32),
      daemonKey: 'nope',
      state: 'loaded',
    }),
    null,
  );
});
