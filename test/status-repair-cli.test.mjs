import assert from 'node:assert/strict';
import test from 'node:test';
import { Command } from 'commander';

const modulePath = new URL('../src/lib/status-repair-cli.ts', import.meta.url);
const TEST_AGENT_KEY_ID = '00000000-0000-0000-0000-000000000001';

function loadModule(caseId) {
  return import(`${modulePath.href}?case=${caseId}`);
}

function createStatusResult(overrides = {}) {
  return {
    platform: 'darwin',
    config: {
      readable: true,
      error: null,
      values: {},
    },
    agent: {
      agentKeyId: TEST_AGENT_KEY_ID,
      agentKeyIdValid: true,
      keychain: {
        supported: true,
        service: 'agentpay-agent-auth-token',
        tokenStored: true,
        error: null,
      },
      legacyConfigToken: {
        present: false,
        keychainMatch: null,
        error: null,
      },
    },
    chain: {
      chainId: 1,
      chainName: 'eth',
      rpcUrlConfigured: true,
      rpcUrlTrusted: true,
      error: null,
    },
    chainProfiles: [],
    bootstrapFiles: [],
    daemonSocket: {
      path: '/trusted/run/daemon.sock',
      trusted: true,
      error: null,
    },
    stateFile: {
      path: '/trusted/run/daemon-state.enc',
      present: true,
      trusted: true,
      error: null,
    },
    binaries: [
      {
        name: 'agentpay-daemon',
        path: '/trusted/bin/agentpay-daemon',
        installed: true,
        trusted: true,
        error: null,
      },
      {
        name: 'agentpay-admin',
        path: '/trusted/bin/agentpay-admin',
        installed: true,
        trusted: true,
        error: null,
      },
      {
        name: 'agentpay-agent',
        path: '/trusted/bin/agentpay-agent',
        installed: true,
        trusted: true,
        error: null,
      },
    ],
    security: {
      ready: true,
      warnings: [],
    },
    ...overrides,
  };
}

function createRepairResult(overrides = {}) {
  return {
    before: createStatusResult({
      security: {
        ready: false,
        warnings: ['legacy agentAuthToken is still present in config.json'],
      },
    }),
    after: createStatusResult(),
    legacyAgentAuth: {
      attempted: true,
      action: 'migrated',
      agentKeyId: TEST_AGENT_KEY_ID,
      reason: 'migrated',
      keychain: {
        service: 'agentpay-agent-auth-token',
        stored: true,
        overwritten: false,
        alreadyPresent: false,
        matchedExisting: false,
      },
    },
    bootstrapArtifacts: {
      attempted: true,
      action: 'deleted',
      agentpayHome: '/tmp/agentpay-home',
      files: [],
      error: null,
    },
    fixedWarnings: ['legacy agentAuthToken is still present in config.json'],
    remainingWarnings: [],
    newWarnings: [],
    ...overrides,
  };
}

test('registerStatusCommand parses argv, prints text output, and applies strict exit codes', async () => {
  const statusCli = await loadModule(`${Date.now()}-status`);
  const printed = [];
  let exitCode = null;

  const program = new Command().name('agentpay');
  statusCli.registerStatusCommand(program, {
    getWalletStatus: () =>
      createStatusResult({
        daemonSocket: {
          path: '/tmp/agentpay.sock',
          trusted: false,
          error: 'socket owner is not trusted',
        },
        security: {
          ready: false,
          warnings: ['daemon socket is not trusted: socket owner is not trusted'],
        },
      }),
    print: (payload, options) => {
      printed.push({ payload, options });
    },
    setExitCode: (code) => {
      exitCode = code;
    },
  });

  await program.parseAsync(['status', '--strict'], { from: 'user' });

  assert.equal(printed.length, 1);
  assert.equal(printed[0].options.asJson, false);
  assert.match(printed[0].payload, /^wallet status: attention required/m);
  assert.match(printed[0].payload, /- daemon socket is not trusted: socket owner is not trusted/);
  assert.equal(exitCode, 1);
});

test('registerStatusCommand returns raw JSON payloads when requested', async () => {
  const statusCli = await loadModule(`${Date.now()}-status-json`);
  const printed = [];

  const result = createStatusResult();
  const program = new Command().name('agentpay');
  statusCli.registerStatusCommand(program, {
    getWalletStatus: () => result,
    print: (payload, options) => {
      printed.push({ payload, options });
    },
    setExitCode: () => {},
  });

  await program.parseAsync(['status', '--json'], { from: 'user' });

  assert.deepEqual(printed, [
    {
      payload: result,
      options: {
        asJson: true,
      },
    },
  ]);
});

test('registerRepairCommand parses argv, forwards options, and derives strict exit code from repaired status', async () => {
  const statusCli = await loadModule(`${Date.now()}-repair`);
  const printed = [];
  let capturedInput = null;
  let exitCode = null;

  const program = new Command().name('agentpay');
  statusCli.registerRepairCommand(program, {
    repairWalletState: (input) => {
      capturedInput = input;
      return createRepairResult({
        after: createStatusResult({
          security: {
            ready: false,
            warnings: ['configured rpcUrl is not trusted: http://rpc.example'],
          },
        }),
        remainingWarnings: ['configured rpcUrl is not trusted: http://rpc.example'],
      });
    },
    print: (payload, options) => {
      printed.push({ payload, options });
    },
    setExitCode: (code) => {
      exitCode = code;
    },
  });

  await program.parseAsync(
    [
      'repair',
      '--agent-key-id',
      TEST_AGENT_KEY_ID,
      '--overwrite-keychain',
      '--redact-bootstrap',
      '--strict',
    ],
    { from: 'user' },
  );

  assert.deepEqual(capturedInput, {
    agentKeyId: TEST_AGENT_KEY_ID,
    overwriteKeychain: true,
    redactBootstrap: true,
  });
  assert.equal(printed.length, 1);
  assert.equal(printed[0].options.asJson, false);
  assert.match(printed[0].payload, /^wallet repair complete/m);
  assert.match(printed[0].payload, /remaining warnings \(1\):/);
  assert.equal(exitCode, 1);
});

test('registerRepairCommand returns raw JSON payloads when requested', async () => {
  const statusCli = await loadModule(`${Date.now()}-repair-json`);
  const printed = [];
  const result = createRepairResult();

  const program = new Command().name('agentpay');
  statusCli.registerRepairCommand(program, {
    repairWalletState: () => result,
    print: (payload, options) => {
      printed.push({ payload, options });
    },
    setExitCode: () => {},
  });

  await program.parseAsync(['repair', '--json'], { from: 'user' });

  assert.deepEqual(printed, [
    {
      payload: result,
      options: {
        asJson: true,
      },
    },
  ]);
});

test('status/repair commands use default print and default exit-code handlers', async () => {
  const statusCli = await loadModule(`${Date.now()}-defaults`);
  const originalStdoutWrite = process.stdout.write.bind(process.stdout);
  const captured = [];
  const previousExitCode = process.exitCode;

  process.stdout.write = (chunk, ...args) => {
    captured.push(String(chunk));
    return originalStdoutWrite(chunk, ...args);
  };

  try {
    const statusProgram = new Command().name('agentpay');
    statusCli.registerStatusCommand(statusProgram, {
      getWalletStatus: () =>
        createStatusResult({
          security: {
            ready: false,
            warnings: ['daemon socket is not trusted'],
          },
        }),
      resolveWalletStatusExitCode: () => 7,
    });
    await statusProgram.parseAsync(['status'], { from: 'user' });

    assert.match(captured.join(''), /wallet status:/u);
    assert.equal(process.exitCode, 7);

    captured.length = 0;
    process.exitCode = undefined;

    const repairProgram = new Command().name('agentpay');
    statusCli.registerRepairCommand(repairProgram, {
      repairWalletState: () => createRepairResult(),
      resolveWalletStatusExitCode: () => 9,
    });
    await repairProgram.parseAsync(['repair'], { from: 'user' });

    assert.match(captured.join(''), /wallet repair complete/u);
    assert.equal(process.exitCode, 9);
  } finally {
    process.stdout.write = originalStdoutWrite;
    process.exitCode = previousExitCode;
  }
});

test('default printer emits JSON payloads when --json is requested', async () => {
  const statusCli = await loadModule(`${Date.now()}-defaults-json`);
  const originalStdoutWrite = process.stdout.write.bind(process.stdout);
  const captured = [];
  const previousExitCode = process.exitCode;

  process.stdout.write = (chunk, ...args) => {
    captured.push(String(chunk));
    return originalStdoutWrite(chunk, ...args);
  };

  try {
    const statusProgram = new Command().name('agentpay');
    statusCli.registerStatusCommand(statusProgram, {
      getWalletStatus: () => createStatusResult(),
      resolveWalletStatusExitCode: () => 0,
    });
    await statusProgram.parseAsync(['status', '--json'], { from: 'user' });

    const rendered = captured.join('');
    assert.match(rendered, /"platform": "darwin"/u);
    assert.equal(process.exitCode, 0);
  } finally {
    process.stdout.write = originalStdoutWrite;
    process.exitCode = previousExitCode;
  }
});
