import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const repoRoot = new URL('..', import.meta.url).pathname;

function makeIsolatedHome() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-railgun-cli-home-'));
}

function runCli(args, homeDir) {
  const agentpayHome = path.join(homeDir, '.agentpay');
  return spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      HOME: homeDir,
      AGENTPAY_HOME: agentpayHome,
    },
  });
}

function combinedOutput(result) {
  return `${result.stdout ?? ''}${result.stderr ?? ''}`;
}

test('railgun subcommands show usage with --help', () => {
  const homeDir = makeIsolatedHome();
  try {
    for (const command of ['shield', 'unshield', 'private-transfer', 'private-balance']) {
      const result = runCli([command, '--help'], homeDir);
      assert.equal(result.status, 0, `${command} --help should exit 0; got ${result.status}`);
      assert.match(result.stdout, /--network/u, `${command} --help should mention --network`);
    }

    const shieldHelp = runCli(['shield', '--help'], homeDir);
    assert.match(shieldHelp.stdout, /--to-railgun-address/u);
    assert.match(shieldHelp.stdout, /--token/u);

    const unshieldHelp = runCli(['unshield', '--help'], homeDir);
    assert.match(unshieldHelp.stdout, /--via-broadcaster/u);
    assert.match(unshieldHelp.stdout, /--to /u);

    const privateTransferHelp = runCli(['private-transfer', '--help'], homeDir);
    assert.match(privateTransferHelp.stdout, /--to-railgun-address/u);
    assert.match(privateTransferHelp.stdout, /--self-broadcast/u);

    const privateBalanceHelp = runCli(['private-balance', '--help'], homeDir);
    assert.match(privateBalanceHelp.stdout, /--token/u);
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('private-balance reports Track 4 sidecar unavailability and exits non-zero', () => {
  const homeDir = makeIsolatedHome();
  try {
    const result = runCli(['private-balance', '--network', 'eth', '--json'], homeDir);
    assert.equal(result.status, 3);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.command, 'private-balance');
    assert.equal(payload.status, 'unavailable');
    assert.match(payload.reason, /railgun-prover sidecar/u);
    assert.equal(payload.token, null);
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('shield rejects malformed Railgun shielded addresses before spawning the agent', () => {
  const homeDir = makeIsolatedHome();
  try {
    const result = runCli(
      [
        'shield',
        '--network',
        'eth',
        '--token',
        '0x0000000000000000000000000000000000000003',
        '--amount',
        '1',
        '--to-railgun-address',
        'definitely-not-a-railgun-address',
      ],
      homeDir,
    );
    assert.equal(result.status, 1);
    assert.match(combinedOutput(result), /(toRailgunAddress|0zk1|is not configured)/u);
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('railgun-address reports unavailable when the config has no derived address', () => {
  // Setup-less fresh AGENTPAY_HOME means no wallet block in config, so the
  // address can't be read. Must exit non-zero with a clear "not derived"
  // message rather than printing an empty string.
  const homeDir = makeIsolatedHome();
  try {
    const result = runCli(['railgun-address', '--json'], homeDir);
    assert.equal(result.status, 2, 'exit 2 when address is missing');
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.status, 'unavailable');
    assert.match(payload.reason, /(setup|wallet metadata)/u);
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});

test('private-transfer surfaces the broadcaster-control flag without expecting a value', () => {
  // Regression for a bug where the TS handler pushed `--via-broadcaster <bool>`
  // but the Rust subcommand modelled the flag as a SetTrue switch, so every
  // invocation died with `error: unexpected argument 'true' found`. The
  // contract today: TS surfaces `--self-broadcast`; the Rust subcommand
  // accepts the same name as a presence switch and inverts internally.
  const homeDir = makeIsolatedHome();
  try {
    const helpResult = runCli(['private-transfer', '--help'], homeDir);
    assert.equal(helpResult.status, 0);
    assert.match(helpResult.stdout, /--self-broadcast/u);
    assert.doesNotMatch(
      helpResult.stdout,
      /--via-broadcaster <[^>]+>/u,
      'private-transfer must not advertise a value-taking --via-broadcaster',
    );
  } finally {
    fs.rmSync(homeDir, { recursive: true, force: true });
  }
});
