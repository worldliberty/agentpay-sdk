import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const modulePath = new URL('../src/lib/bootstrap-credentials.ts', import.meta.url);

function writePrivateFile(targetPath, contents) {
  fs.mkdirSync(path.dirname(targetPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(targetPath, contents, {
    encoding: 'utf8',
    mode: 0o600,
  });
  fs.chmodSync(targetPath, 0o600);
}

function validBootstrapPayload(overrides = {}) {
  return {
    lease_id: 'lease-123',
    lease_expires_at: '2099-01-01T00:00:00Z',
    per_tx_policy_id: 'policy-per-tx',
    daily_policy_id: 'policy-daily',
    weekly_policy_id: 'policy-weekly',
    per_tx_max_wei: '1',
    daily_max_wei: '2',
    weekly_max_wei: '3',
    vault_key_id: 'vault-key-123',
    vault_public_key: '03abcdef',
    agent_key_id: '00000000-0000-0000-0000-000000000001',
    agent_auth_token: 'agent-secret-token',
    network_scope: 'all networks',
    asset_scope: 'all assets',
    recipient_scope: 'all recipients',
    policy_attachment: 'policy_set',
    policy_note: 'bootstrap note',
    ...overrides,
  };
}

test('readBootstrapAgentCredentialsFile rejects oversized bootstrap payloads', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-oversized`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bootstrap-test-'));
  const bootstrapPath = path.join(tempRoot, 'bootstrap.json');

  writePrivateFile(
    bootstrapPath,
    JSON.stringify({
      agent_key_id: '00000000-0000-0000-0000-000000000001',
      agent_auth_token: 'x',
      padding: 'a'.repeat(256 * 1024),
    }),
  );

  assert.throws(
    () => bootstrap.readBootstrapAgentCredentialsFile(bootstrapPath),
    /must not exceed 262144 bytes/,
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('readBootstrapAgentCredentialsFile rejects invalid agent key ids', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-invalid-agent-key-id`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bootstrap-test-'));
  const bootstrapPath = path.join(tempRoot, 'bootstrap.json');

  writePrivateFile(
    bootstrapPath,
    JSON.stringify({
      agent_key_id: 'not-a-uuid',
      agent_auth_token: 'agent-token',
    }),
  );

  assert.throws(
    () => bootstrap.readBootstrapAgentCredentialsFile(bootstrapPath),
    /agentKeyId must be a valid UUID/,
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('readBootstrapAgentCredentialsFile rejects empty or whitespace agent auth tokens', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-empty-token`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bootstrap-test-'));
  const bootstrapPath = path.join(tempRoot, 'bootstrap.json');

  writePrivateFile(
    bootstrapPath,
    JSON.stringify({
      agent_key_id: '00000000-0000-0000-0000-000000000001',
      agent_auth_token: '   \n',
    }),
  );

  assert.throws(
    () => bootstrap.readBootstrapAgentCredentialsFile(bootstrapPath),
    /agent_auth_token is required/,
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('readBootstrapSetupFile parses summary and credentials from one validated payload', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-setup-file`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bootstrap-test-'));
  const bootstrapPath = path.join(tempRoot, 'bootstrap.json');

  writePrivateFile(
    bootstrapPath,
    JSON.stringify({
      lease_id: 'lease-123',
      lease_expires_at: '2099-01-01T00:00:00Z',
      per_tx_policy_id: 'policy-per-tx',
      daily_policy_id: 'policy-daily',
      weekly_policy_id: 'policy-weekly',
      per_tx_max_wei: '1',
      daily_max_wei: '2',
      weekly_max_wei: '3',
      vault_key_id: 'vault-key-123',
      vault_public_key: '03abcdef',
      agent_key_id: '00000000-0000-0000-0000-000000000001',
      agent_auth_token: 'agent-secret-token',
      network_scope: 'all networks',
      asset_scope: 'all assets',
      recipient_scope: 'all recipients',
      policy_attachment: 'policy_set',
      policy_note: 'bootstrap note',
    }),
  );

  const result = bootstrap.readBootstrapSetupFile(bootstrapPath);

  assert.equal(result.summary.sourcePath, bootstrapPath);
  assert.equal(result.summary.agentKeyId, '00000000-0000-0000-0000-000000000001');
  assert.equal(result.summary.perTxPolicyId, 'policy-per-tx');
  assert.equal(result.credentials.sourcePath, bootstrapPath);
  assert.equal(result.credentials.agentKeyId, '00000000-0000-0000-0000-000000000001');
  assert.equal(result.credentials.agentAuthToken, 'agent-secret-token');

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('readBootstrapSetupSummaryFile accepts unrestricted shared-config summaries', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-all-policies-summary`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bootstrap-test-'));
  const bootstrapPath = path.join(tempRoot, 'bootstrap.json');

  writePrivateFile(
    bootstrapPath,
    JSON.stringify(
      validBootstrapPayload({
        per_tx_policy_id: undefined,
        daily_policy_id: undefined,
        weekly_policy_id: undefined,
        per_tx_max_wei: undefined,
        daily_max_wei: undefined,
        weekly_max_wei: undefined,
        network_scope: undefined,
        asset_scope: undefined,
        recipient_scope: undefined,
        policy_attachment: 'all_policies',
        attached_policy_ids: [],
      }),
    ),
  );

  const summary = bootstrap.readBootstrapSetupSummaryFile(bootstrapPath);
  assert.equal(summary.policyAttachment, 'all_policies');
  assert.deepEqual(summary.attachedPolicyIds, []);
  assert.equal(summary.perTxPolicyId, null);

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('readBootstrapSetupSummaryFile accepts explicit-only attachments without bootstrap-created policies', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-explicit-policy-only`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bootstrap-test-'));
  const bootstrapPath = path.join(tempRoot, 'bootstrap.json');

  writePrivateFile(
    bootstrapPath,
    JSON.stringify(
      validBootstrapPayload({
        per_tx_policy_id: undefined,
        daily_policy_id: undefined,
        weekly_policy_id: undefined,
        per_tx_max_wei: undefined,
        daily_max_wei: undefined,
        weekly_max_wei: undefined,
        network_scope: undefined,
        asset_scope: undefined,
        recipient_scope: undefined,
        attached_policy_ids: ['00000000-0000-0000-0000-000000000099'],
      }),
    ),
  );

  const summary = bootstrap.readBootstrapSetupSummaryFile(bootstrapPath);
  assert.equal(summary.policyAttachment, 'policy_set');
  assert.deepEqual(summary.attachedPolicyIds, ['00000000-0000-0000-0000-000000000099']);
  assert.equal(summary.perTxPolicyId, null);

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('cleanupBootstrapAgentCredentialsFile is a no-op when the bootstrap file is missing', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-cleanup-missing`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bootstrap-test-'));
  const bootstrapPath = path.join(tempRoot, 'missing.json');

  assert.deepEqual(bootstrap.cleanupBootstrapAgentCredentialsFile(bootstrapPath, 'deleted'), {
    sourcePath: bootstrapPath,
    action: 'missing',
  });

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('cleanupBootstrapAgentCredentialsFile deletes malformed files when redaction cannot parse them', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-cleanup-fallback-delete`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bootstrap-test-'));
  const bootstrapPath = path.join(tempRoot, 'bootstrap.json');

  writePrivateFile(bootstrapPath, '{\n  "agent_auth_token": "secret"');

  assert.deepEqual(bootstrap.cleanupBootstrapAgentCredentialsFile(bootstrapPath, 'redacted'), {
    sourcePath: bootstrapPath,
    action: 'deleted',
  });
  assert.equal(fs.existsSync(bootstrapPath), false);

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('cleanupBootstrapAgentCredentialsFile returns a failed result when redaction and fallback delete both fail', async () => {
  const bootstrap = await import(
    modulePath.href + `?case=${Date.now()}-cleanup-fallback-delete-failure`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bootstrap-test-'));
  const bootstrapPath = path.join(tempRoot, 'bootstrap.json');

  writePrivateFile(bootstrapPath, '{\n  "agent_auth_token": "secret"');

  const originalRmSync = fs.rmSync;
  fs.rmSync = (targetPath, ...args) => {
    if (path.resolve(String(targetPath)) === bootstrapPath) {
      throw new Error('delete failed');
    }
    return originalRmSync.call(fs, targetPath, ...args);
  };

  try {
    const result = bootstrap.cleanupBootstrapAgentCredentialsFile(bootstrapPath, 'redacted');
    assert.equal(result.sourcePath, bootstrapPath);
    assert.equal(result.action, 'failed');
    assert.match(result.error, /redaction failed/u);
    assert.match(result.error, /fallback delete also failed: delete failed/u);
  } finally {
    fs.rmSync = originalRmSync;
  }

  assert.equal(fs.existsSync(bootstrapPath), true);

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('assertBootstrapSetupSummaryLeaseIsActive rejects invalid timestamps', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-invalid-lease-timestamp`);

  assert.throws(
    () => bootstrap.assertBootstrapSetupSummaryLeaseIsActive({ leaseExpiresAt: 'not-a-date' }),
    /lease_expires_at is not a valid ISO-8601 timestamp/,
  );
});

test('assertBootstrapSetupSummaryLeaseIsActive rejects expired bootstrap leases', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-expired-lease`);

  assert.throws(
    () =>
      bootstrap.assertBootstrapSetupSummaryLeaseIsActive(
        { leaseExpiresAt: '2020-01-01T00:00:00Z' },
        { now: () => Date.parse('2020-01-01T00:00:01Z') },
      ),
    /bootstrap summary lease has expired/,
  );
});

test('assertBootstrapSetupSummaryLeaseIsActive accepts active bootstrap leases', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-active-lease`);

  bootstrap.assertBootstrapSetupSummaryLeaseIsActive(
    { leaseExpiresAt: '2030-01-01T00:00:00Z' },
    { now: () => Date.parse('2029-12-31T23:59:59Z') },
  );
});

test('assertBootstrapSetupSummaryLeaseIsActive uses the default clock when deps are omitted', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-default-clock`);

  bootstrap.assertBootstrapSetupSummaryLeaseIsActive({
    leaseExpiresAt: '2099-01-01T00:00:00Z',
  });
});

test('redactBootstrapAgentCredentialsFile redacts both agent auth token and vault private key', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-redact-private-key`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bootstrap-test-'));
  const bootstrapPath = path.join(tempRoot, 'bootstrap.json');

  writePrivateFile(
    bootstrapPath,
    JSON.stringify({
      agent_key_id: '00000000-0000-0000-0000-000000000001',
      agent_auth_token: 'agent-secret-token',
      vault_private_key: '11'.repeat(32),
    }),
  );

  bootstrap.redactBootstrapAgentCredentialsFile(bootstrapPath);
  const payload = JSON.parse(fs.readFileSync(bootstrapPath, 'utf8'));
  assert.equal(payload.agent_auth_token, '<redacted>');
  assert.equal(payload.agent_auth_token_redacted, true);
  assert.equal(payload.vault_private_key, '<redacted>');
  assert.equal(payload.vault_private_key_redacted, true);

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('readBootstrapAgentCredentialsFile rejects blank file paths', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-blank-path`);
  assert.throws(
    () => bootstrap.readBootstrapAgentCredentialsFile('   '),
    /bootstrap credentials file path is required/,
  );
});

test('readBootstrapSetupFile rejects non-object JSON payloads', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-non-object-json`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bootstrap-test-'));
  const bootstrapPath = path.join(tempRoot, 'bootstrap.json');
  writePrivateFile(bootstrapPath, JSON.stringify(['not-an-object']));

  assert.throws(
    () => bootstrap.readBootstrapSetupFile(bootstrapPath),
    /must contain a JSON object/,
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('readBootstrapSetupSummaryFile parses destination and token policy arrays', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-full-array-summary`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bootstrap-test-'));
  const bootstrapPath = path.join(tempRoot, 'bootstrap.json');

  writePrivateFile(
    bootstrapPath,
    JSON.stringify(
      validBootstrapPayload({
        per_tx_policy_id: null,
        daily_policy_id: null,
        weekly_policy_id: null,
        network_scope: null,
        asset_scope: null,
        recipient_scope: null,
        destination_override_count: 1,
        destination_overrides: [
          {
            recipient: '0x1111111111111111111111111111111111111111',
            per_tx_policy_id: 'dest-per-tx',
            daily_policy_id: 'dest-daily',
            weekly_policy_id: 'dest-weekly',
            gas_policy_id: 'dest-gas',
            per_tx_max_wei: '10',
            daily_max_wei: '20',
            weekly_max_wei: '30',
            max_gas_per_chain_wei: '40',
            daily_max_tx_count: '5',
            daily_tx_count_policy_id: 'dest-daily-count',
            per_tx_max_fee_per_gas_wei: '6',
            per_tx_max_fee_per_gas_policy_id: 'dest-fee',
            per_tx_max_priority_fee_per_gas_wei: '7',
            per_tx_max_priority_fee_per_gas_policy_id: 'dest-priority',
            per_tx_max_calldata_bytes: '8',
            per_tx_max_calldata_bytes_policy_id: 'dest-calldata',
          },
        ],
        token_policies: [
          {
            token_key: 'usd1',
            symbol: 'USD1',
            chain_key: 'eth',
            chain_id: 1,
            asset_scope: 'erc20:0x0000000000000000000000000000000000000001',
            recipient_scope: 'all recipients',
            per_tx_policy_id: 'token-per-tx',
            daily_policy_id: 'token-daily',
            weekly_policy_id: 'token-weekly',
            gas_policy_id: 'token-gas',
            per_tx_max_wei: '11',
            daily_max_wei: '22',
            weekly_max_wei: '33',
            max_gas_per_chain_wei: '44',
            daily_max_tx_count: '9',
            daily_tx_count_policy_id: 'token-daily-count',
            per_tx_max_fee_per_gas_wei: '12',
            per_tx_max_fee_per_gas_policy_id: 'token-fee',
            per_tx_max_priority_fee_per_gas_wei: '13',
            per_tx_max_priority_fee_per_gas_policy_id: 'token-priority',
            per_tx_max_calldata_bytes: '14',
            per_tx_max_calldata_bytes_policy_id: 'token-calldata',
          },
        ],
        token_destination_overrides: [
          {
            token_key: 'usd1',
            symbol: 'USD1',
            chain_key: 'eth',
            chain_id: 1,
            recipient: '0x2222222222222222222222222222222222222222',
            asset_scope: 'erc20:0x0000000000000000000000000000000000000001',
            per_tx_policy_id: 'override-per-tx',
            daily_policy_id: 'override-daily',
            weekly_policy_id: 'override-weekly',
            gas_policy_id: 'override-gas',
            per_tx_max_wei: '101',
            daily_max_wei: '202',
            weekly_max_wei: '303',
            max_gas_per_chain_wei: '404',
            daily_max_tx_count: '4',
            daily_tx_count_policy_id: 'override-daily-count',
            per_tx_max_fee_per_gas_wei: '15',
            per_tx_max_fee_per_gas_policy_id: 'override-fee',
            per_tx_max_priority_fee_per_gas_wei: '16',
            per_tx_max_priority_fee_per_gas_policy_id: 'override-priority',
            per_tx_max_calldata_bytes: '17',
            per_tx_max_calldata_bytes_policy_id: 'override-calldata',
          },
        ],
        token_manual_approval_policies: [
          {
            token_key: 'usd1',
            symbol: 'USD1',
            chain_key: 'eth',
            chain_id: 1,
            priority: 100,
            min_amount_wei: '1',
            max_amount_wei: '1000',
            asset_scope: 'erc20:0x0000000000000000000000000000000000000001',
            recipient_scope: 'all recipients',
            policy_id: 'manual-approval',
          },
        ],
        attached_policy_ids: ['dest-per-tx', 'token-per-tx', 'override-per-tx', 'manual-approval'],
      }),
    ),
  );

  const summary = bootstrap.readBootstrapSetupSummaryFile(bootstrapPath);
  assert.equal(summary.destinationOverrides.length, 1);
  assert.equal(summary.tokenPolicies.length, 1);
  assert.equal(summary.tokenDestinationOverrides.length, 1);
  assert.equal(summary.tokenManualApprovalPolicies.length, 1);
  assert.equal(summary.destinationOverrides[0].dailyTxCountPolicyId, 'dest-daily-count');
  assert.equal(summary.tokenPolicies[0].perTxMaxCalldataBytesPolicyId, 'token-calldata');
  assert.equal(
    summary.tokenDestinationOverrides[0].perTxMaxPriorityFeePerGasPolicyId,
    'override-priority',
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('readBootstrapSetupSummaryFile rejects malformed optional field types', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-malformed-optional-types`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bootstrap-test-'));
  const bootstrapPath = path.join(tempRoot, 'bootstrap.json');

  const assertPayloadError = (payload, pattern) => {
    writePrivateFile(bootstrapPath, JSON.stringify(payload));
    assert.throws(() => bootstrap.readBootstrapSetupSummaryFile(bootstrapPath), pattern);
  };

  assertPayloadError(
    validBootstrapPayload({ network_scope: 123 }),
    /network_scope must be a string/,
  );
  assertPayloadError(
    validBootstrapPayload({ attached_policy_ids: [1, 'ok'] }),
    /attached_policy_ids must be an array of strings/,
  );
  assertPayloadError(
    validBootstrapPayload({ destination_override_count: '1' }),
    /destination_override_count must be a number/,
  );
  assertPayloadError(
    validBootstrapPayload({ token_policies: {} }),
    /token_policies must be an array/,
  );
  assertPayloadError(
    validBootstrapPayload({
      token_policies: [
        {
          token_key: 'usd1',
          symbol: 'USD1',
          chain_key: 'eth',
          asset_scope: 'erc20:0x0000000000000000000000000000000000000001',
          recipient_scope: 'all recipients',
          per_tx_policy_id: 'token-per-tx',
          daily_policy_id: 'token-daily',
          weekly_policy_id: 'token-weekly',
          per_tx_max_wei: '1',
          daily_max_wei: '2',
          weekly_max_wei: '3',
        },
      ],
    }),
    /token_policies\[0\]\.chain_id is required/,
  );
  assertPayloadError(validBootstrapPayload({ lease_id: '' }), /lease_id is required/);
  assertPayloadError(
    validBootstrapPayload({
      per_tx_policy_id: 'policy-per-tx',
      daily_policy_id: 'policy-daily',
      weekly_policy_id: 'policy-weekly',
      network_scope: null,
    }),
    /legacy bootstrap summary is missing policy scope fields/,
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('readBootstrapAgentCredentialsFile supports camelCase fallback keys and rejects non-boolean redaction flag', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-camel-and-redaction-type`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bootstrap-test-'));
  const bootstrapPath = path.join(tempRoot, 'bootstrap.json');

  writePrivateFile(
    bootstrapPath,
    JSON.stringify({
      agent_key_id: 123,
      agentKeyId: '00000000-0000-0000-0000-000000000001',
      agent_auth_token: 42,
      agentAuthToken: 'agent-secret-token',
      agent_auth_token_redacted: 'true',
    }),
  );
  assert.throws(
    () => bootstrap.readBootstrapAgentCredentialsFile(bootstrapPath),
    /agent_auth_token_redacted must be a boolean/,
  );

  writePrivateFile(
    bootstrapPath,
    JSON.stringify({
      agent_key_id: 123,
      agentKeyId: '00000000-0000-0000-0000-000000000001',
      agent_auth_token: 42,
      agentAuthToken: 'agent-secret-token',
    }),
  );
  const parsed = bootstrap.readBootstrapAgentCredentialsFile(bootstrapPath);
  assert.equal(parsed.agentKeyId, '00000000-0000-0000-0000-000000000001');
  assert.equal(parsed.agentAuthToken, 'agent-secret-token');

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('readBootstrapAgentCredentialsFile rejects <redacted> token payloads', async () => {
  const bootstrap = await import(
    modulePath.href + `?case=${Date.now()}-redacted-token-placeholder`
  );
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bootstrap-test-'));
  const bootstrapPath = path.join(tempRoot, 'bootstrap.json');
  writePrivateFile(
    bootstrapPath,
    JSON.stringify(
      validBootstrapPayload({
        agent_auth_token: '<redacted>',
      }),
    ),
  );

  assert.throws(
    () => bootstrap.readBootstrapAgentCredentialsFile(bootstrapPath),
    /contains a redacted agent auth token/,
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('readBootstrapAgentCredentialsFile rejects non-file bootstrap paths', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-non-file-target`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bootstrap-test-'));
  const bootstrapPath = path.join(tempRoot, 'bootstrap.json');
  fs.mkdirSync(bootstrapPath, { mode: 0o700 });

  assert.throws(
    () => bootstrap.readBootstrapAgentCredentialsFile(bootstrapPath),
    /must be a regular file/,
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('redactBootstrapAgentCredentialsFile adds missing redaction fields and updates camelCase private-key redaction flag', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-redaction-fields`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bootstrap-test-'));
  const bootstrapPath = path.join(tempRoot, 'bootstrap.json');
  writePrivateFile(
    bootstrapPath,
    JSON.stringify({
      vaultPrivateKey: '11'.repeat(32),
      vaultPrivateKeyRedacted: false,
      note: 'no token field present',
    }),
  );

  bootstrap.redactBootstrapAgentCredentialsFile(bootstrapPath);
  const payload = JSON.parse(fs.readFileSync(bootstrapPath, 'utf8'));
  assert.equal(payload.agent_auth_token, '<redacted>');
  assert.equal(payload.agent_auth_token_redacted, true);
  assert.equal(payload.vaultPrivateKey, '<redacted>');
  assert.equal(payload.vaultPrivateKeyRedacted, true);

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('redactBootstrapAgentCredentialsFile removes temporary files when atomic rename fails', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-redact-rename-failure`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bootstrap-test-'));
  const bootstrapPath = path.join(tempRoot, 'bootstrap.json');
  writePrivateFile(bootstrapPath, JSON.stringify(validBootstrapPayload()));

  const originalRenameSync = fs.renameSync;
  fs.renameSync = () => {
    throw new Error('rename failed');
  };

  try {
    assert.throws(
      () => bootstrap.redactBootstrapAgentCredentialsFile(bootstrapPath),
      /rename failed/,
    );
  } finally {
    fs.renameSync = originalRenameSync;
  }

  const leftovers = fs
    .readdirSync(path.dirname(bootstrapPath))
    .filter((entry) => entry.startsWith(`.${path.basename(bootstrapPath)}.tmp-`));
  assert.deepEqual(leftovers, []);

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('cleanupBootstrapAgentCredentialsFile rethrows unexpected filesystem errors', async () => {
  const bootstrap = await import(modulePath.href + `?case=${Date.now()}-cleanup-rethrow`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-bootstrap-test-'));
  const bootstrapPath = path.join(tempRoot, 'bootstrap.json');
  writePrivateFile(bootstrapPath, JSON.stringify(validBootstrapPayload()));

  const originalLstatSync = fs.lstatSync;
  fs.lstatSync = () => {
    const error = new Error('i/o failure');
    error.code = 'EIO';
    throw error;
  };

  try {
    assert.throws(
      () => bootstrap.cleanupBootstrapAgentCredentialsFile(bootstrapPath, 'deleted'),
      /i\/o failure/,
    );
  } finally {
    fs.lstatSync = originalLstatSync;
  }

  fs.rmSync(tempRoot, { recursive: true, force: true });
});
