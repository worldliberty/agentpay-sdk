import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const modulePath = new URL('../packages/config/src/index.ts', import.meta.url);

function withMockedEuid(euid, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(process, 'geteuid');
  Object.defineProperty(process, 'geteuid', {
    configurable: true,
    value: () => euid,
  });

  try {
    return fn();
  } finally {
    if (descriptor) {
      Object.defineProperty(process, 'geteuid', descriptor);
    } else {
      delete process.geteuid;
    }
  }
}

function modeBits(targetPath) {
  return fs.statSync(targetPath).mode & 0o777;
}

test('writeConfig creates private home and config permissions', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  const config = await import(modulePath.href + `?case=${Date.now()}-1`);
  const written = config.writeConfig({
    rpcUrl: 'https://rpc.example',
    agentAuthToken: 'secret-token',
  });

  assert.equal(written.rpcUrl, 'https://rpc.example');
  assert.equal(modeBits(agentpayHome) & 0o077, 0);
  assert.equal(modeBits(config.resolveConfigPath()) & 0o177, 0);

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('readConfig tightens permissive config file modes on unix', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  const config = await import(modulePath.href + `?case=${Date.now()}-perm`);
  config.ensureAgentPayHome();
  fs.writeFileSync(config.resolveConfigPath(), JSON.stringify({ rpcUrl: 'https://rpc.example' }), {
    encoding: 'utf8',
    mode: 0o644,
  });
  fs.chmodSync(config.resolveConfigPath(), 0o644);

  const parsed = config.readConfig();
  assert.equal(parsed.rpcUrl, 'https://rpc.example');
  assert.equal(modeBits(config.resolveConfigPath()) & 0o077, 0);

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('readConfig rejects symlinked config files', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  const config = await import(modulePath.href + `?case=${Date.now()}-2`);
  config.ensureAgentPayHome();

  const target = path.join(tempRoot, 'seed.json');
  fs.writeFileSync(target, JSON.stringify({ rpcUrl: 'https://rpc.example' }), 'utf8');
  fs.symlinkSync(target, config.resolveConfigPath());

  assert.throws(() => config.readConfig(), /must not be a symlink/);

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('ensureAgentPayHome rejects insecure ancestor directories on unix', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const sharedRoot = path.join(tempRoot, 'shared');
  fs.mkdirSync(sharedRoot, { recursive: true, mode: 0o777 });
  fs.chmodSync(sharedRoot, 0o777);
  process.env.AGENTPAY_HOME = path.join(sharedRoot, 'home');

  const config = await import(modulePath.href + `?case=${Date.now()}-ancestor-mode`);

  assert.throws(() => config.ensureAgentPayHome(), /must not be writable by group\/other/);

  delete process.env.AGENTPAY_HOME;
  fs.chmodSync(sharedRoot, 0o700);
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('config trust ignores SUDO_UID unless the process is running as root', async () => {
  const config = await import(modulePath.href + `?case=${Date.now()}-sudo-ignore`);
  const originalSudoUid = process.env.SUDO_UID;
  process.env.SUDO_UID = '12345';

  try {
    const allowed = withMockedEuid(501, () =>
      Array.from(config.allowedOwnerUids()).sort((a, b) => a - b),
    );
    assert.deepEqual(allowed, [501]);
  } finally {
    if (originalSudoUid === undefined) {
      delete process.env.SUDO_UID;
    } else {
      process.env.SUDO_UID = originalSudoUid;
    }
  }
});

test('config trust includes SUDO_UID when the process is running as root', async () => {
  const config = await import(modulePath.href + `?case=${Date.now()}-sudo-root`);
  const originalSudoUid = process.env.SUDO_UID;
  process.env.SUDO_UID = '12345';

  try {
    const allowed = withMockedEuid(0, () =>
      Array.from(config.allowedOwnerUids()).sort((a, b) => a - b),
    );
    assert.deepEqual(allowed, [0, 12345]);
  } finally {
    if (originalSudoUid === undefined) {
      delete process.env.SUDO_UID;
    } else {
      process.env.SUDO_UID = originalSudoUid;
    }
  }
});

test('assertSafeRpcUrl accepts https and localhost http endpoints', async () => {
  const config = await import(modulePath.href + `?case=${Date.now()}-rpc-safe`);

  assert.equal(config.assertSafeRpcUrl('https://rpc.example'), 'https://rpc.example');
  assert.equal(config.assertSafeRpcUrl(' http://127.0.0.1:8545 '), 'http://127.0.0.1:8545');
  assert.equal(config.assertSafeRpcUrl('http://[::1]:8545'), 'http://[::1]:8545');
});

test('assertSafeRpcUrl rejects remote http and embedded credentials', async () => {
  const config = await import(modulePath.href + `?case=${Date.now()}-rpc-unsafe`);

  assert.throws(
    () => config.assertSafeRpcUrl('http://rpc.example'),
    /must use https unless it targets localhost or a loopback address/,
  );
  assert.throws(
    () => config.assertSafeRpcUrl('https://user:secret@rpc.example'),
    /must not include embedded credentials/,
  );
});

test('writeConfig rejects insecure remote rpcUrl values', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  const config = await import(modulePath.href + `?case=${Date.now()}-write-rpc-unsafe`);

  assert.throws(
    () => config.writeConfig({ rpcUrl: 'http://rpc.example' }),
    /must use https unless it targets localhost or a loopback address/,
  );

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('writeConfig normalizes sensitive path values to absolute paths', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const previousCwd = process.cwd();
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  try {
    process.chdir(tempRoot);
    const config = await import(modulePath.href + `?case=${Date.now()}-normalize-paths`);

    const written = config.writeConfig({
      daemonSocket: './daemon/run/daemon.sock',
      stateFile: './daemon/state/daemon-state.enc',
      rustBinDir: './rust/bin',
    });

    assert.equal(written.daemonSocket, path.resolve('daemon/run/daemon.sock'));
    assert.equal(written.stateFile, path.resolve('daemon/state/daemon-state.enc'));
    assert.equal(written.rustBinDir, path.resolve('rust/bin'));
  } finally {
    process.chdir(previousCwd);
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('writeConfig rejects daemon sockets under insecure directories on unix', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  const shared = path.join(tempRoot, 'shared');
  process.env.AGENTPAY_HOME = agentpayHome;

  fs.mkdirSync(shared, { recursive: true, mode: 0o777 });
  fs.chmodSync(shared, 0o777);

  try {
    const config = await import(modulePath.href + `?case=${Date.now()}-reject-daemon-path`);

    assert.throws(
      () => config.writeConfig({ daemonSocket: path.join(shared, 'daemon.sock') }),
      /daemonSocket directory .* must not be writable by group\/other/,
    );
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.chmodSync(shared, 0o700);
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('writeConfig rejects symlinked rustBinDir values', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  const realBinDir = path.join(tempRoot, 'real-bin');
  const linkedBinDir = path.join(tempRoot, 'linked-bin');
  process.env.AGENTPAY_HOME = agentpayHome;

  fs.mkdirSync(realBinDir, { recursive: true });
  fs.symlinkSync(realBinDir, linkedBinDir);

  try {
    const config = await import(modulePath.href + `?case=${Date.now()}-reject-rust-bin-symlink`);

    assert.throws(
      () => config.writeConfig({ rustBinDir: linkedBinDir }),
      /rustBinDir .* must not be a symlink/,
    );
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('writeConfig rejects rustBinDir values that traverse symlinked ancestor directories', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  const realRoot = path.join(tempRoot, 'real-root');
  const linkedRoot = path.join(tempRoot, 'linked-root');
  const realBinDir = path.join(realRoot, 'bin');
  const linkedBinDir = path.join(linkedRoot, 'bin');
  process.env.AGENTPAY_HOME = agentpayHome;

  fs.mkdirSync(realBinDir, { recursive: true });
  fs.symlinkSync(realRoot, linkedRoot);

  try {
    const config = await import(
      modulePath.href + `?case=${Date.now()}-reject-rust-bin-ancestor-symlink`
    );

    assert.throws(
      () => config.writeConfig({ rustBinDir: linkedBinDir }),
      /must not traverse symlinked ancestor directories/,
    );
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('readConfig rejects oversized config files', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  const config = await import(modulePath.href + `?case=${Date.now()}-oversized-config`);
  config.ensureAgentPayHome();
  fs.writeFileSync(
    config.resolveConfigPath(),
    JSON.stringify({
      rpcUrl: 'https://rpc.example',
      padding: 'a'.repeat(256 * 1024),
    }),
    {
      encoding: 'utf8',
      mode: 0o600,
    },
  );
  fs.chmodSync(config.resolveConfigPath(), 0o600);

  assert.throws(() => config.readConfig(), /must not exceed 262144 bytes/);

  delete process.env.AGENTPAY_HOME;
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('writeConfig accepts inaccessible root-private stateFile paths when the parent directory is trusted', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  const config = await import(modulePath.href + `?case=${Date.now()}-statefile-inaccessible`);
  const originalLstatSync = fs.lstatSync;
  const inaccessiblePath = '/var/db/agentpay/daemon-state.enc';

  try {
    fs.lstatSync = (targetPath, ...args) => {
      if (path.resolve(String(targetPath)) === inaccessiblePath) {
        const error = new Error(`EACCES: permission denied, lstat '${inaccessiblePath}'`);
        error.code = 'EACCES';
        throw error;
      }
      return originalLstatSync.call(fs, targetPath, ...args);
    };

    const written = config.writeConfig({
      stateFile: inaccessiblePath,
    });

    assert.equal(written.stateFile, inaccessiblePath);
  } finally {
    fs.lstatSync = originalLstatSync;
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('builtin tokens expose default chain coverage', async () => {
  const config = await import(modulePath.href + `?case=${Date.now()}-builtin-tokens`);

  const builtin = config.listBuiltinTokens();
  const keys = builtin.map((entry) => entry.key);
  assert.deepEqual(keys, ['bnb', 'eth', 'pathusd', 'usd', 'usd1', 'usdc.e']);

  const bnb = builtin.find((entry) => entry.key === 'bnb');
  assert.ok(bnb);
  assert.ok(
    bnb.chains.some((chain) => chain.key === 'bsc' && chain.isNative && chain.decimals === 18),
  );

  const eth = builtin.find((entry) => entry.key === 'eth');
  assert.ok(eth);
  assert.ok(
    eth.chains.some((chain) => chain.key === 'ethereum' && chain.isNative && chain.decimals === 18),
  );

  const usd = builtin.find((entry) => entry.key === 'usd');
  assert.ok(usd);
  assert.ok(
    usd.chains.some((chain) => chain.key === 'tempo' && chain.isNative && chain.decimals === 6),
  );
  assert.equal(
    usd.chains.some((chain) => chain.key === 'tempo-moderato'),
    false,
  );

  const usd1 = builtin.find((entry) => entry.key === 'usd1');
  assert.ok(usd1);
  assert.ok(
    usd1.chains.some(
      (chain) =>
        chain.key === 'eth' && chain.address === '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
    ),
  );
  assert.ok(
    usd1.chains.some(
      (chain) =>
        chain.key === 'bsc' && chain.address === '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
    ),
  );

  const pathUsd = builtin.find((entry) => entry.key === 'pathusd');
  assert.ok(pathUsd);
  assert.equal(pathUsd.symbol, 'PATH/USD');
  assert.ok(
    pathUsd.chains.some(
      (chain) =>
        chain.key === 'tempo' &&
        chain.address === '0x20c0000000000000000000000000000000000000' &&
        chain.decimals === 6,
    ),
  );
  assert.ok(
    pathUsd.chains.some(
      (chain) =>
        chain.key === 'tempo-testnet' &&
        chain.address === '0x20c0000000000000000000000000000000000000' &&
        chain.decimals === 6,
    ),
  );

  const usdce = builtin.find((entry) => entry.key === 'usdc.e');
  assert.ok(usdce);
  assert.equal(usdce.symbol, 'USDC.e');
  assert.ok(
    usdce.chains.some(
      (chain) =>
        chain.key === 'tempo' &&
        chain.address === '0x20c000000000000000000000b9537d11c60e8b50' &&
        chain.decimals === 6,
    ),
  );
  assert.ok(
    usdce.chains.some(
      (chain) =>
        chain.key === 'tempo-testnet' &&
        chain.address === '0x20c0000000000000000000009e8d7eb59b783726' &&
        chain.decimals === 6,
    ),
  );
  assert.equal(
    builtin.find((entry) => entry.key === 'usdc'),
    undefined,
  );
});

test('builtin chains expose tempo mainnet and testnet defaults', async () => {
  const config = await import(modulePath.href + `?case=${Date.now()}-builtin-chains`);

  const builtin = config.listBuiltinChains();
  assert.ok(
    builtin.some(
      (chain) =>
        chain.name === 'tempo' &&
        chain.chainId === 4217 &&
        chain.rpcUrl === 'https://rpc.presto.tempo.xyz',
    ),
  );
  assert.ok(
    builtin.some(
      (chain) =>
        chain.name === 'tempo-testnet' &&
        chain.chainId === 42431 &&
        chain.rpcUrl === 'https://rpc.moderato.tempo.xyz',
    ),
  );
});

test('default config seeds eth, bsc, tempo, unrestricted builtin payment assets', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  try {
    const config = await import(modulePath.href + `?case=${Date.now()}-default-seeds`);
    const parsed = config.readConfig();

    assert.equal(parsed.chains?.eth?.chainId, 1);
    assert.equal(parsed.chains?.eth?.rpcUrl, 'https://eth.llamarpc.com');
    assert.equal(parsed.chains?.bsc?.chainId, 56);
    assert.equal(parsed.chains?.bsc?.rpcUrl, 'https://bsc.drpc.org');
    assert.equal(parsed.chains?.tempo?.chainId, 4217);
    assert.equal(parsed.chains?.tempo?.rpcUrl, 'https://rpc.presto.tempo.xyz');
    assert.equal(parsed.chains?.['tempo-testnet']?.chainId, 42431);
    assert.equal(parsed.chains?.['tempo-testnet']?.rpcUrl, 'https://rpc.moderato.tempo.xyz');

    assert.equal(parsed.tokens?.bnb?.symbol, 'BNB');
    assert.equal(parsed.tokens?.bnb?.defaultPolicy, undefined);
    assert.equal(parsed.tokens?.bnb?.chains?.bsc?.isNative, true);
    assert.equal(parsed.tokens?.bnb?.chains?.bsc?.decimals, 18);
    assert.equal(parsed.tokens?.bnb?.chains?.bsc?.address, undefined);

    assert.equal(parsed.tokens?.eth?.symbol, 'ETH');
    assert.equal(parsed.tokens?.eth?.defaultPolicy, undefined);
    assert.equal(parsed.tokens?.eth?.chains?.eth?.isNative, true);
    assert.equal(parsed.tokens?.eth?.chains?.eth?.decimals, 18);
    assert.equal(parsed.tokens?.eth?.chains?.eth?.address, undefined);

    assert.equal(parsed.tokens?.usd?.symbol, 'USD');
    assert.equal(parsed.tokens?.usd?.defaultPolicy, undefined);
    assert.equal(parsed.tokens?.usd?.chains?.tempo?.isNative, true);
    assert.equal(parsed.tokens?.usd?.chains?.tempo?.decimals, 6);
    assert.equal(parsed.tokens?.usd?.chains?.tempo?.address, undefined);

    assert.equal(parsed.tokens?.usd1?.symbol, 'USD1');
    assert.equal(parsed.tokens?.usd1?.defaultPolicy, undefined);
    assert.equal(
      parsed.tokens?.usd1?.chains?.eth?.address,
      '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
    );
    assert.equal(
      parsed.tokens?.usd1?.chains?.bsc?.address,
      '0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d',
    );
    assert.equal(parsed.tokens?.usd1?.chains?.eth?.defaultPolicy, undefined);
    assert.equal(parsed.tokens?.usd1?.chains?.bsc?.defaultPolicy, undefined);

    assert.equal(parsed.tokens?.pathusd?.symbol, 'PATH/USD');
    assert.equal(parsed.tokens?.pathusd?.defaultPolicy, undefined);
    assert.equal(
      parsed.tokens?.pathusd?.chains?.tempo?.address,
      '0x20c0000000000000000000000000000000000000',
    );
    assert.equal(parsed.tokens?.pathusd?.chains?.tempo?.decimals, 6);
    assert.equal(
      parsed.tokens?.pathusd?.chains?.['tempo-testnet']?.address,
      '0x20c0000000000000000000000000000000000000',
    );
    assert.equal(parsed.tokens?.pathusd?.chains?.['tempo-testnet']?.decimals, 6);
    assert.equal(parsed.tokens?.['usdc.e']?.symbol, 'USDC.e');
    assert.equal(
      parsed.tokens?.['usdc.e']?.chains?.tempo?.address,
      '0x20c000000000000000000000b9537d11c60e8b50',
    );
    assert.equal(parsed.tokens?.['usdc.e']?.chains?.tempo?.decimals, 6);
    assert.equal(
      parsed.tokens?.['usdc.e']?.chains?.['tempo-testnet']?.address,
      '0x20c0000000000000000000009e8d7eb59b783726',
    );
    assert.equal(parsed.tokens?.['usdc.e']?.chains?.['tempo-testnet']?.decimals, 6);

    assert.deepEqual(Object.keys(parsed.tokens ?? {}).sort(), [
      'bnb',
      'eth',
      'pathusd',
      'usd',
      'usd1',
      'usdc.e',
    ]);
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('readConfig reseeds defaults for legacy empty chains and tokens', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  try {
    fs.mkdirSync(agentpayHome, { recursive: true, mode: 0o700 });
    fs.writeFileSync(
      path.join(agentpayHome, 'config.json'),
      `${JSON.stringify(
        {
          chainId: 56,
          chainName: 'bsc',
          rpcUrl: 'https://rpc.bsc.example',
          chains: {},
          tokens: {},
        },
        null,
        2,
      )}\n`,
      { encoding: 'utf8', mode: 0o600 },
    );

    const config = await import(modulePath.href + `?case=${Date.now()}-legacy-empty-seeds`);
    const parsed = config.readConfig();

    assert.equal(parsed.chainId, 56);
    assert.equal(parsed.chainName, 'bsc');
    assert.equal(parsed.rpcUrl, 'https://rpc.bsc.example');
    assert.equal(parsed.chains?.eth?.rpcUrl, 'https://eth.llamarpc.com');
    assert.equal(parsed.chains?.bsc?.rpcUrl, 'https://bsc.drpc.org');
    assert.equal(parsed.chains?.tempo?.rpcUrl, 'https://rpc.presto.tempo.xyz');
    assert.equal(parsed.chains?.['tempo-testnet']?.rpcUrl, 'https://rpc.moderato.tempo.xyz');
    assert.equal(parsed.tokens?.bnb?.chains?.bsc?.isNative, true);
    assert.equal(parsed.tokens?.eth?.chains?.eth?.isNative, true);
    assert.equal(parsed.tokens?.usd?.chains?.tempo?.isNative, true);
    assert.equal(
      parsed.tokens?.pathusd?.chains?.tempo?.address,
      '0x20c0000000000000000000000000000000000000',
    );
    assert.equal(
      parsed.tokens?.pathusd?.chains?.['tempo-testnet']?.address,
      '0x20c0000000000000000000000000000000000000',
    );
    assert.equal(parsed.tokens?.usd1?.defaultPolicy, undefined);
    assert.equal(
      parsed.tokens?.['usdc.e']?.chains?.tempo?.address,
      '0x20c000000000000000000000b9537d11c60e8b50',
    );
    assert.equal(
      parsed.tokens?.['usdc.e']?.chains?.['tempo-testnet']?.address,
      '0x20c0000000000000000000009e8d7eb59b783726',
    );
    assert.deepEqual(Object.keys(parsed.tokens ?? {}).sort(), [
      'bnb',
      'eth',
      'pathusd',
      'usd',
      'usd1',
      'usdc.e',
    ]);
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('readConfig merges new default tempo assets into existing non-empty configs', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  try {
    fs.mkdirSync(agentpayHome, { recursive: true, mode: 0o700 });
    fs.writeFileSync(
      path.join(agentpayHome, 'config.json'),
      `${JSON.stringify(
        {
          chains: {
            eth: {
              chainId: 1,
              name: 'ETH',
              rpcUrl: 'https://eth.llamarpc.com',
            },
            bsc: {
              chainId: 56,
              name: 'BSC',
              rpcUrl: 'https://bsc.drpc.org',
            },
          },
          tokens: {
            bnb: {
              name: 'BNB',
              symbol: 'BNB',
              chains: {
                bsc: {
                  chainId: 56,
                  isNative: true,
                  decimals: 18,
                },
              },
            },
          },
        },
        null,
        2,
      )}\n`,
      { encoding: 'utf8', mode: 0o600 },
    );

    const config = await import(modulePath.href + `?case=${Date.now()}-merge-new-defaults`);
    const parsed = config.readConfig();

    assert.equal(parsed.chains?.tempo?.rpcUrl, 'https://rpc.presto.tempo.xyz');
    assert.equal(parsed.chains?.['tempo-testnet']?.rpcUrl, 'https://rpc.moderato.tempo.xyz');
    assert.equal(parsed.tokens?.usd?.chains?.tempo?.isNative, true);
    assert.equal(parsed.tokens?.usd?.chains?.tempo?.decimals, 6);
    assert.equal(
      parsed.tokens?.pathusd?.chains?.tempo?.address,
      '0x20c0000000000000000000000000000000000000',
    );
    assert.equal(
      parsed.tokens?.['usdc.e']?.chains?.tempo?.address,
      '0x20c000000000000000000000b9537d11c60e8b50',
    );
    assert.equal(
      parsed.tokens?.['usdc.e']?.chains?.['tempo-testnet']?.address,
      '0x20c0000000000000000000009e8d7eb59b783726',
    );
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('readConfig accepts Rust-style null optional policy fields', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  try {
    fs.mkdirSync(agentpayHome, { recursive: true, mode: 0o700 });
    fs.writeFileSync(
      path.join(agentpayHome, 'config.json'),
      `${JSON.stringify(
        {
          chains: {
            bsc: {
              chainId: 56,
              name: 'BSC',
              rpcUrl: 'https://bsc.drpc.org',
            },
          },
          tokens: {
            bnb: {
              name: 'BNB',
              symbol: 'BNB',
              defaultPolicy: {
                perTxAmount: null,
                dailyAmount: null,
                weeklyAmount: null,
                perTxAmountDecimal: '0.01',
                dailyAmountDecimal: '0.2',
                weeklyAmountDecimal: '1.4',
                maxGasPerChainWei: null,
                dailyMaxTxCount: null,
                perTxMaxFeePerGasGwei: null,
                perTxMaxFeePerGasWei: null,
                perTxMaxPriorityFeePerGasWei: null,
                perTxMaxCalldataBytes: null,
              },
              chains: {
                bsc: {
                  chainId: 56,
                  isNative: true,
                  address: null,
                  decimals: 18,
                  defaultPolicy: {
                    perTxAmount: null,
                    dailyAmount: null,
                    weeklyAmount: null,
                    perTxAmountDecimal: '0.01',
                    dailyAmountDecimal: '0.2',
                    weeklyAmountDecimal: '1.4',
                    maxGasPerChainWei: null,
                    dailyMaxTxCount: null,
                    perTxMaxFeePerGasGwei: null,
                    perTxMaxFeePerGasWei: null,
                    perTxMaxPriorityFeePerGasWei: null,
                    perTxMaxCalldataBytes: null,
                  },
                },
              },
            },
          },
        },
        null,
        2,
      )}\n`,
      { encoding: 'utf8', mode: 0o600 },
    );

    const config = await import(modulePath.href + `?case=${Date.now()}-rust-null-optionals`);
    const parsed = config.readConfig();

    assert.equal(parsed.tokens?.bnb?.defaultPolicy?.perTxAmount, undefined);
    assert.equal(parsed.tokens?.bnb?.defaultPolicy?.perTxAmountDecimal, '0.01');
    assert.equal(parsed.tokens?.bnb?.chains?.bsc?.defaultPolicy?.perTxAmount, undefined);
    assert.equal(parsed.tokens?.bnb?.chains?.bsc?.defaultPolicy?.dailyAmountDecimal, '0.2');
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('readConfig normalizes blank rpcUrl fields instead of bricking the CLI', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  try {
    fs.mkdirSync(agentpayHome, { recursive: true, mode: 0o700 });
    fs.writeFileSync(
      path.join(agentpayHome, 'config.json'),
      `${JSON.stringify(
        {
          chainId: 56,
          chainName: 'sol',
          rpcUrl: '   ',
          chains: {
            sol: {
              chainId: 101,
              name: 'sol',
              rpcUrl: '   ',
            },
          },
        },
        null,
        2,
      )}\n`,
      { encoding: 'utf8', mode: 0o600 },
    );

    const config = await import(modulePath.href + `?case=${Date.now()}-blank-rpc-url`);
    const parsed = config.readConfig();

    assert.equal(parsed.rpcUrl, undefined);
    assert.equal(parsed.chains?.sol?.rpcUrl, undefined);
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('readConfig keeps malformed optional rpcUrl fields readable for repair workflows', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  try {
    fs.mkdirSync(agentpayHome, { recursive: true, mode: 0o700 });
    fs.writeFileSync(
      path.join(agentpayHome, 'config.json'),
      `${JSON.stringify(
        {
          rpcUrl: 'not-a-url',
          chains: {
            sol: {
              chainId: 101,
              name: 'sol',
              rpcUrl: 'not-a-url',
            },
          },
        },
        null,
        2,
      )}\n`,
      { encoding: 'utf8', mode: 0o600 },
    );

    const config = await import(modulePath.href + `?case=${Date.now()}-invalid-optional-rpc-url`);
    const parsed = config.readConfig();

    assert.equal(parsed.rpcUrl, 'not-a-url');
    assert.equal(parsed.chains?.sol?.rpcUrl, 'not-a-url');
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('saveChainProfile still validates newly provided rpcUrl values', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  try {
    const config = await import(modulePath.href + `?case=${Date.now()}-save-chain-profile-rpc-url`);

    assert.throws(
      () =>
        config.saveChainProfile('sol', {
          chainId: 101,
          name: 'sol',
          rpcUrl: 'not-a-url',
        }),
      /chain profile 'sol' rpcUrl must be a valid http\(s\) URL/,
    );
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('removeChainProfile rejects unknown configured networks', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  try {
    const config = await import(modulePath.href + `?case=${Date.now()}-remove-missing-chain`);

    assert.throws(() => config.removeChainProfile('missing'), /network 'missing' does not exist/);
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('writeConfig treats whitespace rpcUrl updates as clearing the override', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  try {
    const config = await import(modulePath.href + `?case=${Date.now()}-clear-rpc-url`);
    config.writeConfig({ rpcUrl: 'https://rpc.example' });

    const updated = config.writeConfig({ rpcUrl: '   ' });
    assert.equal(updated.rpcUrl, undefined);

    const persisted = config.readConfig();
    assert.equal(persisted.rpcUrl, undefined);
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('readConfig treats wallet null as absent', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  try {
    fs.mkdirSync(agentpayHome, { recursive: true, mode: 0o700 });
    fs.writeFileSync(
      path.join(agentpayHome, 'config.json'),
      `${JSON.stringify(
        {
          wallet: null,
        },
        null,
        2,
      )}\n`,
      { encoding: 'utf8', mode: 0o600 },
    );

    const config = await import(modulePath.href + `?case=${Date.now()}-wallet-null`);
    const parsed = config.readConfig();

    assert.equal(parsed.wallet, undefined);
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('resolveTokenProfile finds configured and builtin tokens', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  try {
    const config = await import(modulePath.href + `?case=${Date.now()}-resolve-token-profile`);
    config.saveTokenProfile('TreasuryUSD', {
      symbol: 'TUSD',
      chains: {
        ethereum: {
          chainId: 1,
          isNative: false,
          address: '0x0000000000000000000000000000000000000001',
          decimals: 18,
        },
      },
    });

    const configured = config.resolveTokenProfile('tusd');
    assert.equal(configured?.source, 'configured');
    assert.equal(configured?.key, 'treasuryusd');

    const seeded = config.resolveTokenProfile('ETH');
    assert.equal(seeded?.source, 'configured');
    assert.equal(seeded?.key, 'eth');

    const builtin = config.resolveTokenProfile('ETH', { tokens: {} });
    assert.equal(builtin?.source, 'builtin');
    assert.equal(builtin?.key, 'eth');

    const builtinUsdce = config.resolveTokenProfile('USDC.E', { tokens: {} });
    assert.equal(builtinUsdce?.source, 'builtin');
    assert.equal(builtinUsdce?.key, 'usdc.e');
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('resolveChainProfile finds builtin chains by numeric chainId', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  try {
    const config = await import(modulePath.href + `?case=${Date.now()}-resolve-chain-profile`);

    const tempo = config.resolveChainProfile('4217', { chains: {} });
    assert.equal(tempo?.source, 'builtin');
    assert.equal(tempo?.key, 'tempo');
    assert.equal(tempo?.rpcUrl, 'https://rpc.presto.tempo.xyz');

    const moderato = config.resolveChainProfile('42431', { chains: {} });
    assert.equal(moderato?.source, 'builtin');
    assert.equal(moderato?.key, 'tempo-testnet');
    assert.equal(moderato?.rpcUrl, 'https://rpc.moderato.tempo.xyz');
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('writeConfig normalizes chain and token profile keys', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  try {
    const config = await import(modulePath.href + `?case=${Date.now()}-normalize-chain-token-keys`);
    const written = config.writeConfig({
      chains: {
        EthereumMain: {
          chainId: 1,
          name: 'Ethereum Main',
          rpcUrl: 'https://rpc.example',
        },
      },
      tokens: {
        TreasuryUSD: {
          symbol: 'TUSD',
          chains: {
            Ethereum: {
              chainId: 1,
              isNative: false,
              address: '0x0000000000000000000000000000000000000001',
              decimals: 6,
              defaultPolicy: {
                perTxAmount: 25,
                dailyAmount: 100,
              },
            },
          },
        },
      },
    });

    assert.equal(Object.keys(written.chains ?? {}).join(','), 'ethereummain');
    assert.equal(written.chains?.ethereummain?.rpcUrl, 'https://rpc.example');
    assert.equal(Object.keys(written.tokens ?? {}).join(','), 'treasuryusd');
    assert.equal(Object.keys(written.tokens?.treasuryusd?.chains ?? {}).join(','), 'ethereum');
    assert.equal(written.tokens?.treasuryusd?.chains?.ethereum?.defaultPolicy?.perTxAmount, 25);
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('writeConfig rejects invalid native token addresses', async () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-config-test-'));
  const agentpayHome = path.join(tempRoot, 'home');
  process.env.AGENTPAY_HOME = agentpayHome;

  try {
    const config = await import(
      modulePath.href + `?case=${Date.now()}-invalid-native-token-address`
    );

    assert.throws(
      () =>
        config.writeConfig({
          tokens: {
            eth: {
              symbol: 'ETH',
              chains: {
                ethereum: {
                  chainId: 1,
                  isNative: true,
                  address: '0x0000000000000000000000000000000000000001',
                  decimals: 18,
                },
              },
            },
          },
        }),
      /must not set address when isNative=true/,
    );
  } finally {
    delete process.env.AGENTPAY_HOME;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
