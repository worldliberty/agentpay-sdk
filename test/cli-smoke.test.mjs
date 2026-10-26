import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const repoRoot = new URL('..', import.meta.url).pathname;

function makeIsolatedHome() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-cli-home-'));
}

function runCli(args, homeDir, extraEnv = {}) {
  const agentpayHome = path.join(homeDir, '.agentpay');
  const env = {
    ...process.env,
    HOME: homeDir,
    AGENTPAY_HOME: agentpayHome,
    // A smoke run must never phone home, even when this file is run outside the test harness.
    AGENTPAY_TELEMETRY: '0',
    ...extraEnv,
  };
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) {
      delete env[key];
    }
  }
  return spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
    env,
  });
}

function combinedOutput(result) {
  return `${result.stdout ?? ''}${result.stderr ?? ''}`;
}

test('cli help and config commands run in an isolated home', () => {
  const homeDir = makeIsolatedHome();
  const agentpayHome = path.join(homeDir, '.agentpay');

  try {
    const help = runCli(['--help'], homeDir);
    assert.equal(help.status, 0);
    assert.match(help.stdout, /Single entrypoint for AgentPay/u);

    const configHelp = runCli(['config', '--help'], homeDir);
    assert.equal(configHelp.status, 0);
    assert.match(configHelp.stdout, /Manage ~\/\.agentpay configuration/u);

    const configPath = runCli(['config', 'path'], homeDir);
    assert.equal(configPath.status, 0);
    assert.equal(configPath.stdout.trim(), path.join(agentpayHome, 'config.json'));

    const configShow = runCli(['config', 'show', '--json'], homeDir);
    assert.equal(configShow.status, 0);
    const payload = JSON.parse(configShow.stdout);
    assert.equal(payload.paths.agentpayHome, agentpayHome);
    assert.equal(payload.paths.configPath, path.join(agentpayHome, 'config.json'));
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('config set enforces local admin mutation access in non-interactive mode', () => {
  const homeDir = makeIsolatedHome();

  try {
    const result = runCli(['config', 'set', 'rpcUrl', 'https://eth.llamarpc.com'], homeDir);
    assert.equal(result.status, 1);
    assert.match(combinedOutput(result), /requires verified root access/u);
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('rpc and tx command validation fails closed for unsafe rpc urls', () => {
  const homeDir = makeIsolatedHome();
  const addressA = '0x0000000000000000000000000000000000000001';
  const addressB = '0x0000000000000000000000000000000000000002';
  const txHash = `0x${'1'.repeat(64)}`;
  const rpcCommands = [
    ['rpc', 'chain', '--rpc-url', 'http://example.com'],
    ['rpc', 'block-number', '--rpc-url', 'http://example.com'],
    ['rpc', 'account', '--address', addressA, '--rpc-url', 'http://example.com'],
    ['rpc', 'balance', '--address', addressA, '--rpc-url', 'http://example.com'],
    ['rpc', 'nonce', '--address', addressA, '--rpc-url', 'http://example.com'],
    ['rpc', 'fees', '--rpc-url', 'http://example.com'],
    [
      'rpc',
      'gas-estimate',
      '--from',
      addressA,
      '--to',
      addressB,
      '--rpc-url',
      'http://example.com',
    ],
    ['rpc', 'tx', '--hash', txHash, '--rpc-url', 'http://example.com'],
    ['rpc', 'receipt', '--hash', txHash, '--rpc-url', 'http://example.com'],
    ['rpc', 'code', '--address', addressA, '--rpc-url', 'http://example.com'],
    ['rpc', 'broadcast-raw', '--raw-tx-hex', '0x01', '--rpc-url', 'http://example.com'],
  ];

  try {
    for (const commandArgs of rpcCommands) {
      const rpcCommand = runCli(commandArgs, homeDir);
      assert.equal(rpcCommand.status, 1);
      assert.match(combinedOutput(rpcCommand), /must use https unless it targets localhost/u);
    }

    const txBroadcast = runCli(
      [
        'tx',
        'broadcast',
        '--from',
        addressA,
        '--to',
        addressB,
        '--network',
        'eth',
        '--rpc-url',
        'http://example.com',
      ],
      homeDir,
    );
    assert.equal(txBroadcast.status, 1);
    assert.match(combinedOutput(txBroadcast), /must use https unless it targets localhost/u);
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('asset commands fail before rust/network when signer or token metadata is missing', () => {
  const homeDir = makeIsolatedHome();

  try {
    const transferNative = runCli(
      [
        'transfer-native',
        '--to',
        '0x0000000000000000000000000000000000000002',
        '--amount',
        '1',
        '--network',
        'eth',
      ],
      homeDir,
    );
    assert.equal(transferNative.status, 1);
    assert.match(combinedOutput(transferNative), /agentKeyId is required/u);

    const approve = runCli(
      [
        'approve',
        '--token',
        '0x0000000000000000000000000000000000000003',
        '--spender',
        '0x0000000000000000000000000000000000000002',
        '--amount',
        '1',
        '--network',
        'eth',
      ],
      homeDir,
    );
    assert.equal(approve.status, 1);
    assert.match(combinedOutput(approve), /is not configured; save it first/u);
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('admin setup plan is non-destructive and returns machine-readable output', () => {
  const homeDir = makeIsolatedHome();

  try {
    const setupPlan = runCli(['admin', 'setup', '--plan', '--json'], homeDir);
    assert.equal(setupPlan.status, 0);
    const payload = JSON.parse(setupPlan.stdout);
    assert.equal(payload.command, 'setup');
    assert.equal(payload.mode, 'plan');
    assert.equal(payload.walletSetup.bootstrapOutput.autoGenerated, true);
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('destructive admin commands fail closed in non-interactive sessions without root password input', () => {
  const homeDir = makeIsolatedHome();

  try {
    const reset = runCli(['admin', 'reset', '--yes', '--non-interactive', '--json'], homeDir);
    assert.equal(reset.status, 1);
    if (process.platform === 'darwin' || process.platform === 'linux') {
      assert.match(
        combinedOutput(reset),
        /System admin password for sudo is required; rerun on a local TTY/u,
      );
    } else {
      assert.match(
        combinedOutput(reset),
        /`agentpay admin reset` is currently supported only on macOS and Linux/u,
      );
    }

    const uninstall = runCli(
      ['admin', 'uninstall', '--yes', '--non-interactive', '--json'],
      homeDir,
    );
    assert.equal(uninstall.status, 1);
    if (process.platform === 'darwin' || process.platform === 'linux') {
      assert.match(
        combinedOutput(uninstall),
        /System admin password for sudo is required; rerun on a local TTY/u,
      );
    } else {
      assert.match(
        combinedOutput(uninstall),
        /`agentpay admin uninstall` is currently supported only on macOS and Linux/u,
      );
    }
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('telemetry status, enable, and disable manage the stored opt-in', () => {
  const homeDir = makeIsolatedHome();
  const telemetryPath = path.join(homeDir, '.agentpay', 'telemetry.json');
  // With the env opt-out lifted, nothing may still reach a real endpoint.
  const liftedOptOut = {
    AGENTPAY_TELEMETRY: undefined,
    DO_NOT_TRACK: undefined,
    AGENTPAY_MIXPANEL_URL: 'http://127.0.0.1:9/track',
    AGENTPAY_SENTRY_DSN: '',
  };

  try {
    const status = runCli(['telemetry', 'status', '--json'], homeDir);
    assert.equal(status.status, 0);
    assert.deepEqual(JSON.parse(status.stdout), {
      command: 'telemetry status',
      enabled: false,
      disabledReason: 'env-opt-out',
    });

    const disable = runCli(['telemetry', 'disable', '--json'], homeDir);
    assert.equal(disable.status, 0);
    assert.deepEqual(JSON.parse(disable.stdout), { command: 'telemetry disable', enabled: false });
    const disabledState = JSON.parse(fs.readFileSync(telemetryPath, 'utf8'));
    assert.equal(disabledState.enabled, false);
    assert.equal((fs.statSync(telemetryPath).mode & 0o777).toString(8), '600');

    const storedOptOut = runCli(['telemetry', 'status', '--json'], homeDir, liftedOptOut);
    assert.equal(storedOptOut.status, 0);
    assert.equal(JSON.parse(storedOptOut.stdout).disabledReason, 'stored-opt-out');
    assert.doesNotMatch(storedOptOut.stderr, /anonymous usage analytics/u);

    // The env opt-out still wins over a stored opt-in, and the command says so.
    const enable = runCli(['telemetry', 'enable', '--json'], homeDir);
    assert.equal(enable.status, 0);
    assert.deepEqual(JSON.parse(enable.stdout), {
      command: 'telemetry enable',
      enabled: false,
      disabledReason: 'env-opt-out',
    });
    const enabledState = JSON.parse(fs.readFileSync(telemetryPath, 'utf8'));
    assert.equal(enabledState.enabled, true);
    assert.equal(enabledState.installId, disabledState.installId, 'the install id is kept');

    const doNotTrack = runCli(['telemetry', 'status', '--json'], homeDir, {
      ...liftedOptOut,
      DO_NOT_TRACK: '1',
    });
    assert.equal(JSON.parse(doNotTrack.stdout).disabledReason, 'do-not-track');
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('version and usage errors exit cleanly and print the error once', () => {
  const homeDir = makeIsolatedHome();

  try {
    const version = runCli(['telemetry', '--version'], homeDir);
    assert.equal(version.status, 0);
    assert.match(version.stdout, /^\d+\.\d+\.\d+/u);

    const unknown = runCli(['definitely-not-a-command'], homeDir);
    assert.equal(unknown.status, 1);
    const output = combinedOutput(unknown);
    assert.equal(output.match(/unknown command/gu)?.length, 1, output);

    const missingArgument = runCli(['config', 'set'], homeDir);
    assert.equal(missingArgument.status, 1);
    assert.equal(combinedOutput(missingArgument).match(/missing required argument/gu)?.length, 1);
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});
