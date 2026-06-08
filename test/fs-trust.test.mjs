import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const modulePath = new URL('../src/lib/fs-trust.ts', import.meta.url);

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

function withMissingGeteuid(fn) {
  const descriptor = Object.getOwnPropertyDescriptor(process, 'geteuid');
  Object.defineProperty(process, 'geteuid', {
    configurable: true,
    value: undefined,
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

function withMockedPlatform(platform, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', {
    configurable: true,
    value: platform,
  });

  try {
    return fn();
  } finally {
    if (descriptor) {
      Object.defineProperty(process, 'platform', descriptor);
    } else {
      delete process.platform;
    }
  }
}

function withMockedFs(overrides, fn) {
  const originals = new Map();
  for (const [key, value] of Object.entries(overrides)) {
    originals.set(key, fs[key]);
    fs[key] = value;
  }

  try {
    return fn();
  } finally {
    for (const [key, value] of originals.entries()) {
      fs[key] = value;
    }
  }
}

function makeStats({
  uid = 0,
  mode = 0o700,
  directory = false,
  file = false,
  socket = false,
  symlink = false,
} = {}) {
  return {
    uid,
    mode,
    isDirectory: () => directory,
    isFile: () => file,
    isSocket: () => socket,
    isSymbolicLink: () => symlink,
  };
}

function writeExecutable(targetPath, body = '#!/bin/sh\necho ok\n') {
  fs.writeFileSync(targetPath, body, { encoding: 'utf8', mode: 0o700 });
  fs.chmodSync(targetPath, 0o700);
}

async function listenOnUnixSocket(socketPath) {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      server.off('error', reject);
      resolve();
    });
  });
  return server;
}

async function closeUnixSocket(server, socketPath) {
  await new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
  fs.rmSync(socketPath, { force: true });
}

test('assertTrustedExecutablePath accepts trusted local binaries', async () => {
  const trust = await import(`${modulePath.href}?case=${Date.now()}-1`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-fs-trust-'));
  const binDir = path.join(tempRoot, 'bin');
  fs.mkdirSync(binDir, { mode: 0o755 });
  const executable = path.join(binDir, 'agentpay-agent');
  writeExecutable(executable);

  assert.doesNotThrow(() => trust.assertTrustedExecutablePath(executable));

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('assertTrustedExecutablePath rejects symlinked binaries', async () => {
  const trust = await import(`${modulePath.href}?case=${Date.now()}-2`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-fs-trust-'));
  const binDir = path.join(tempRoot, 'bin');
  fs.mkdirSync(binDir, { mode: 0o755 });
  const target = path.join(tempRoot, 'target-agent');
  const executable = path.join(binDir, 'agentpay-agent');
  writeExecutable(target);
  fs.symlinkSync(target, executable);

  assert.throws(() => trust.assertTrustedExecutablePath(executable), /must not be a symlink/);

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('assertTrustedExecutablePath rejects group-writable binaries on unix', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const trust = await import(`${modulePath.href}?case=${Date.now()}-3`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-fs-trust-'));
  const binDir = path.join(tempRoot, 'bin');
  fs.mkdirSync(binDir, { mode: 0o755 });
  const executable = path.join(binDir, 'agentpay-agent');
  writeExecutable(executable);
  fs.chmodSync(executable, 0o720);

  assert.throws(
    () => trust.assertTrustedExecutablePath(executable),
    /must not be writable by group\/other/,
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('assertTrustedExecutablePath rejects group-writable binary directories on unix', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const trust = await import(`${modulePath.href}?case=${Date.now()}-4`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-fs-trust-'));
  const binDir = path.join(tempRoot, 'bin');
  fs.mkdirSync(binDir, { mode: 0o777 });
  fs.chmodSync(binDir, 0o777);
  const executable = path.join(binDir, 'agentpay-agent');
  writeExecutable(executable);

  assert.throws(
    () => trust.assertTrustedExecutablePath(executable),
    /Rust binary directory .* must not be writable by group\/other/,
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('assertTrustedExecutablePath rejects insecure ancestor directories on unix', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const trust = await import(`${modulePath.href}?case=${Date.now()}-ancestor-mode`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-fs-trust-'));
  const sharedRoot = path.join(tempRoot, 'shared');
  const binDir = path.join(sharedRoot, 'bin');
  fs.mkdirSync(binDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(sharedRoot, 0o777);
  fs.chmodSync(binDir, 0o700);

  const executable = path.join(binDir, 'agentpay-agent');
  writeExecutable(executable);

  assert.throws(
    () => trust.assertTrustedExecutablePath(executable),
    /Rust binary directory .* must not be writable by group\/other/,
  );

  fs.chmodSync(sharedRoot, 0o700);
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('assertTrustedExecutablePath rejects sudo-caller-owned binaries when the wrapper runs as root', async () => {
  if (process.platform === 'win32' || typeof process.getuid !== 'function') {
    return;
  }

  const trust = await import(`${modulePath.href}?case=${Date.now()}-root-owned-binary-only`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-fs-trust-'));
  const binDir = path.join(tempRoot, 'bin');
  fs.mkdirSync(binDir, { mode: 0o700 });
  fs.chmodSync(binDir, 0o700);
  const executable = path.join(binDir, 'agentpay-agent');
  writeExecutable(executable);

  const originalSudoUid = process.env.SUDO_UID;
  process.env.SUDO_UID = String(process.getuid());

  try {
    assert.throws(
      () => withMockedEuid(0, () => trust.assertTrustedExecutablePath(executable)),
      /Rust binary .* must be owned by root/,
    );
  } finally {
    if (originalSudoUid === undefined) {
      delete process.env.SUDO_UID;
    } else {
      process.env.SUDO_UID = originalSudoUid;
    }
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('allowedOwnerUids ignores SUDO_UID unless the process is running as root', async () => {
  const trust = await import(`${modulePath.href}?case=${Date.now()}-sudo-ignore`);
  const originalSudoUid = process.env.SUDO_UID;
  process.env.SUDO_UID = '12345';

  try {
    const allowed = withMockedEuid(501, () =>
      Array.from(trust.allowedOwnerUids()).sort((a, b) => a - b),
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

test('allowedOwnerUids includes SUDO_UID when the process is running as root', async () => {
  const trust = await import(`${modulePath.href}?case=${Date.now()}-sudo-root`);
  const originalSudoUid = process.env.SUDO_UID;
  process.env.SUDO_UID = '12345';

  try {
    const allowed = withMockedEuid(0, () =>
      Array.from(trust.allowedOwnerUids()).sort((a, b) => a - b),
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

test('allowedOwnerUids returns an empty set when geteuid is unavailable', async () => {
  const trust = await import(`${modulePath.href}?case=${Date.now()}-sudo-no-geteuid`);
  const originalSudoUid = process.env.SUDO_UID;
  process.env.SUDO_UID = '12345';

  try {
    const allowed = withMissingGeteuid(() => Array.from(trust.allowedOwnerUids()));
    assert.deepEqual(allowed, []);
  } finally {
    if (originalSudoUid === undefined) {
      delete process.env.SUDO_UID;
    } else {
      process.env.SUDO_UID = originalSudoUid;
    }
  }
});

test('assertTrustedDaemonSocketPath accepts trusted unix sockets', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const trust = await import(`${modulePath.href}?case=${Date.now()}-socket-ok`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-fs-trust-'));
  const socketDir = path.join(tempRoot, 'run');
  const socketPath = path.join(socketDir, 'daemon.sock');
  fs.mkdirSync(socketDir, { mode: 0o755 });

  const server = await listenOnUnixSocket(socketPath);

  assert.equal(trust.assertTrustedDaemonSocketPath(socketPath), path.resolve(socketPath));

  await closeUnixSocket(server, socketPath);
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('daemon socket validators cover ENOENT and synthetic admin success branches', async () => {
  const trust = await import(
    `${modulePath.href}?case=${Date.now()}-socket-missing-and-admin-success`
  );
  const daemonSocket = '/virtual/user/run/daemon.sock';
  const adminSocket = '/virtual/root/run/daemon.sock';

  const rootAwareLstat = (targetPath) => {
    const resolved = path.resolve(String(targetPath));
    if (
      resolved === '/' ||
      resolved === '/virtual' ||
      resolved === '/virtual/user' ||
      resolved === '/virtual/user/run' ||
      resolved === '/virtual/root' ||
      resolved === '/virtual/root/run'
    ) {
      return makeStats({ uid: 0, mode: 0o700, directory: true });
    }
    const error = new Error(`missing: ${resolved}`);
    error.code = 'ENOENT';
    throw error;
  };

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === daemonSocket) {
          const error = new Error('missing daemon socket');
          error.code = 'ENOENT';
          throw error;
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => trust.assertTrustedDaemonSocketPath(daemonSocket, 'Virtual daemon socket'),
        /does not exist/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === adminSocket) {
          const error = new Error('missing admin daemon socket');
          error.code = 'ENOENT';
          throw error;
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => trust.assertTrustedAdminDaemonSocketPath(adminSocket, 'Managed daemon socket'),
        /does not exist/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === adminSocket) {
          return makeStats({ uid: 0, mode: 0o700, socket: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.equal(
        trust.assertTrustedAdminDaemonSocketPath(adminSocket, 'Managed daemon socket'),
        adminSocket,
      );
    },
  );
});

test('assertTrustedDaemonSocketPath rejects sudo-caller-owned unix sockets when the wrapper runs as root', async () => {
  if (process.platform === 'win32' || typeof process.getuid !== 'function') {
    return;
  }

  const trust = await import(`${modulePath.href}?case=${Date.now()}-socket-root-owner-only`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-fs-trust-'));
  const socketDir = path.join(tempRoot, 'run');
  const socketPath = path.join(socketDir, 'daemon.sock');
  fs.mkdirSync(socketDir, { mode: 0o755 });

  const server = await listenOnUnixSocket(socketPath);
  const originalSudoUid = process.env.SUDO_UID;
  process.env.SUDO_UID = String(process.getuid());

  try {
    assert.throws(
      () => withMockedEuid(0, () => trust.assertTrustedDaemonSocketPath(socketPath)),
      /must be owned by root/,
    );
  } finally {
    if (originalSudoUid === undefined) {
      delete process.env.SUDO_UID;
    } else {
      process.env.SUDO_UID = originalSudoUid;
    }
    await closeUnixSocket(server, socketPath);
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('assertTrustedAdminDaemonSocketPath rejects non-root-owned unix sockets', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const trust = await import(`${modulePath.href}?case=${Date.now()}-admin-socket-owner`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-fs-trust-'));
  const socketDir = path.join(tempRoot, 'run');
  const socketPath = path.join(socketDir, 'daemon.sock');
  fs.mkdirSync(socketDir, { mode: 0o755 });

  const server = await listenOnUnixSocket(socketPath);

  assert.throws(
    () => trust.assertTrustedAdminDaemonSocketPath(socketPath),
    /must be owned by root/,
  );

  await closeUnixSocket(server, socketPath);
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('assertTrustedRootPlannedDaemonSocketPath rejects planned sockets under non-root directories', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const trust = await import(`${modulePath.href}?case=${Date.now()}-planned-admin-socket-root-dir`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-fs-trust-'));
  const plannedSocketPath = path.join(tempRoot, 'run', 'daemon.sock');

  assert.throws(
    () =>
      trust.assertTrustedRootPlannedDaemonSocketPath(plannedSocketPath, 'Managed daemon socket'),
    /must be owned by root/,
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('assertTrustedRootPlannedPrivateFilePath rejects planned state files under non-root directories', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const trust = await import(`${modulePath.href}?case=${Date.now()}-planned-state-file-root-dir`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-fs-trust-'));
  const plannedStateFile = path.join(tempRoot, 'state', 'daemon-state.enc');

  assert.throws(
    () =>
      trust.assertTrustedRootPlannedPrivateFilePath(plannedStateFile, 'Managed daemon state file'),
    /must be owned by root/,
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('assertTrustedDaemonSocketPath rejects insecure ancestor directories on unix', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const trust = await import(`${modulePath.href}?case=${Date.now()}-socket-ancestor-mode`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-fs-trust-'));
  const sharedRoot = path.join(tempRoot, 'shared');
  const socketDir = path.join(sharedRoot, 'run');
  const socketPath = path.join(socketDir, 'daemon.sock');
  fs.mkdirSync(socketDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(sharedRoot, 0o777);
  fs.chmodSync(socketDir, 0o700);

  const server = await listenOnUnixSocket(socketPath);

  assert.throws(
    () => trust.assertTrustedDaemonSocketPath(socketPath),
    /Daemon socket directory .* must not be writable by group\/other/,
  );

  await closeUnixSocket(server, socketPath);
  fs.chmodSync(sharedRoot, 0o700);
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('assertTrustedDaemonSocketPath rejects symlinked socket paths', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const trust = await import(`${modulePath.href}?case=${Date.now()}-socket-link`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-fs-trust-'));
  const socketDir = path.join(tempRoot, 'run');
  const actualSocketPath = path.join(socketDir, 'daemon.sock');
  const symlinkSocketPath = path.join(socketDir, 'daemon-link.sock');
  fs.mkdirSync(socketDir, { mode: 0o755 });

  const server = await listenOnUnixSocket(actualSocketPath);
  fs.symlinkSync(actualSocketPath, symlinkSocketPath);

  assert.throws(
    () => trust.assertTrustedDaemonSocketPath(symlinkSocketPath),
    /must not be a symlink/,
  );

  fs.rmSync(symlinkSocketPath, { force: true });
  await closeUnixSocket(server, actualSocketPath);
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('assertTrustedDaemonSocketPath rejects symlinked ancestor directories', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const trust = await import(`${modulePath.href}?case=${Date.now()}-socket-ancestor-link`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-fs-trust-'));
  const realRoot = path.join(tempRoot, 'real-root');
  const linkedRoot = path.join(tempRoot, 'linked-root');
  const socketDir = path.join(realRoot, 'run');
  const actualSocketPath = path.join(socketDir, 'daemon.sock');
  const linkedSocketPath = path.join(linkedRoot, 'run', 'daemon.sock');

  fs.mkdirSync(socketDir, { recursive: true, mode: 0o700 });
  fs.symlinkSync(realRoot, linkedRoot);

  const server = await listenOnUnixSocket(actualSocketPath);

  assert.throws(
    () => trust.assertTrustedDaemonSocketPath(linkedSocketPath),
    /must not traverse symlinked ancestor directories/,
  );

  await closeUnixSocket(server, actualSocketPath);
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('assertTrustedDaemonSocketPath rejects non-socket files', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const trust = await import(`${modulePath.href}?case=${Date.now()}-socket-file`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-fs-trust-'));
  const socketDir = path.join(tempRoot, 'run');
  const fakeSocketPath = path.join(socketDir, 'daemon.sock');
  fs.mkdirSync(socketDir, { mode: 0o755 });
  fs.writeFileSync(fakeSocketPath, 'not-a-socket', { mode: 0o600 });

  assert.throws(() => trust.assertTrustedDaemonSocketPath(fakeSocketPath), /must be a unix socket/);

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('assertTrustedPrivateFilePath accepts trusted private files and allows missing files when requested', async () => {
  const trust = await import(`${modulePath.href}?case=${Date.now()}-private-file-ok`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-fs-trust-'));
  const secureDir = path.join(tempRoot, 'state');
  const stateFile = path.join(secureDir, 'daemon-state.enc');
  fs.mkdirSync(secureDir, { mode: 0o700 });
  fs.writeFileSync(stateFile, 'encrypted-state', { mode: 0o600 });
  fs.chmodSync(secureDir, 0o700);
  fs.chmodSync(stateFile, 0o600);

  assert.equal(
    trust.assertTrustedPrivateFilePath(stateFile, 'State file'),
    path.resolve(stateFile),
  );
  assert.equal(
    trust.assertTrustedPrivateFilePath(path.join(secureDir, 'missing.enc'), 'State file', {
      allowMissing: true,
    }),
    path.resolve(path.join(secureDir, 'missing.enc')),
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('assertTrustedPrivateFilePath rejects group-readable files on unix', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const trust = await import(`${modulePath.href}?case=${Date.now()}-private-file-mode`);
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-fs-trust-'));
  const secureDir = path.join(tempRoot, 'state');
  const stateFile = path.join(secureDir, 'daemon-state.enc');
  fs.mkdirSync(secureDir, { mode: 0o700 });
  fs.writeFileSync(stateFile, 'encrypted-state', { mode: 0o640 });
  fs.chmodSync(secureDir, 0o700);
  fs.chmodSync(stateFile, 0o640);

  assert.throws(
    () => trust.assertTrustedPrivateFilePath(stateFile, 'State file'),
    /must not grant group\/other permissions/,
  );

  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('assertTrustedRootPrivateFilePath rejects inaccessible files instead of trusting them', async () => {
  if (process.platform === 'win32') {
    return;
  }

  const trust = await import(`${modulePath.href}?case=${Date.now()}-root-private-inaccessible`);
  const originalLstatSync = fs.lstatSync;
  const inaccessibleDir = path.join(os.tmpdir(), 'agentpay-root-private');
  const inaccessibleFile = path.join(inaccessibleDir, 'daemon-state.enc');
  fs.mkdirSync(inaccessibleDir, { recursive: true, mode: 0o700 });
  const directoryStats = {
    uid: 0,
    mode: 0o700,
    isDirectory: () => true,
    isFile: () => false,
    isSocket: () => false,
    isSymbolicLink: () => false,
  };

  fs.lstatSync = (targetPath) => {
    if (path.resolve(String(targetPath)) === path.resolve(inaccessibleFile)) {
      const error = new Error('permission denied');
      error.code = 'EACCES';
      throw error;
    }
    return directoryStats;
  };

  try {
    assert.throws(
      () => trust.assertTrustedRootPrivateFilePath(inaccessibleFile, 'State file'),
      /is not accessible to the current process/,
    );
  } finally {
    fs.lstatSync = originalLstatSync;
    fs.rmSync(inaccessibleDir, { recursive: true, force: true });
  }
});

test('owner/stat guards enforce uid rules and allow win32 short-circuits', async () => {
  const trust = await import(`${modulePath.href}?case=${Date.now()}-owner-guard-edges`);

  assert.throws(
    () => trust.assertTrustedOwner(makeStats({ uid: 4242 }), '/tmp/example', 'Example path'),
    /must be owned by the current user, sudo caller, or root/,
  );
  assert.throws(
    () => trust.assertRootOwned(makeStats({ uid: 'unknown' }), '/tmp/example', 'Example path'),
    /owner could not be determined/,
  );

  withMockedPlatform('win32', () => {
    assert.doesNotThrow(() =>
      trust.assertTrustedOwner(makeStats({ uid: 4242 }), 'C:\\temp\\example', 'Example path'),
    );
    assert.doesNotThrow(() =>
      trust.assertRootOwned(makeStats({ uid: 4242 }), 'C:\\temp\\example', 'Example path'),
    );
    assert.doesNotThrow(() =>
      trust.assertPrivateFileStats(
        makeStats({ uid: 4242, mode: 0o777, file: true }),
        'C:\\temp\\secret.txt',
        'Secret file',
      ),
    );
  });
});

test('root planned path validators exercise symlink, non-directory, missing, and non-socket branches', async () => {
  const trust = await import(`${modulePath.href}?case=${Date.now()}-root-planned-edges`);
  const plannedDir = '/virtual/root/run';
  const plannedSocket = '/virtual/root/run/daemon.sock';
  const plannedState = '/virtual/root/run/state.enc';
  const rootDirStats = makeStats({ uid: 0, mode: 0o700, directory: true });

  const rootAwareLstat = (targetPath) => {
    const resolved = path.resolve(String(targetPath));
    if (resolved === '/') {
      return makeStats({ uid: 0, mode: 0o755, directory: true });
    }
    if (
      resolved === '/virtual' ||
      resolved === '/virtual/root' ||
      resolved === '/virtual/root/run'
    ) {
      return rootDirStats;
    }
    const error = new Error(`missing: ${resolved}`);
    error.code = 'ENOENT';
    throw error;
  };

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === plannedDir) {
          return makeStats({ uid: 0, mode: 0o700, symlink: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => trust.assertTrustedRootPlannedDirectoryPath(plannedDir, 'Planned root directory'),
        /must not be a symlink/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === plannedDir) {
          return makeStats({ uid: 0, mode: 0o600, file: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => trust.assertTrustedRootPlannedDirectoryPath(plannedDir, 'Planned root directory'),
        /must be a directory/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === plannedDir) {
          const error = new Error('missing planned dir');
          error.code = 'ENOENT';
          throw error;
        }
        if (resolved === '/virtual/root') {
          return makeStats({ uid: 0, mode: 0o700, symlink: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => trust.assertTrustedRootPlannedDirectoryPath(plannedDir, 'Planned root directory'),
        /must not be a symlink/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === plannedDir) {
          const error = new Error('missing planned dir');
          error.code = 'ENOENT';
          throw error;
        }
        if (resolved === '/virtual/root') {
          return makeStats({ uid: 0, mode: 0o600, file: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => trust.assertTrustedRootPlannedDirectoryPath(plannedDir, 'Planned root directory'),
        /must be a directory/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === plannedSocket) {
          const error = new Error('missing socket');
          error.code = 'ENOENT';
          throw error;
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      const resolved = withMockedEuid(0, () =>
        trust.assertTrustedRootPlannedDaemonSocketPath(plannedSocket, 'Managed daemon socket'),
      );
      assert.equal(resolved, path.resolve(plannedSocket));
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === plannedSocket) {
          return makeStats({ uid: 0, mode: 0o700, symlink: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () =>
          withMockedEuid(0, () =>
            trust.assertTrustedRootPlannedDaemonSocketPath(plannedSocket, 'Managed daemon socket'),
          ),
        /must not be a symlink/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === plannedSocket) {
          return makeStats({ uid: 0, mode: 0o700, file: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () =>
          withMockedEuid(0, () =>
            trust.assertTrustedRootPlannedDaemonSocketPath(plannedSocket, 'Managed daemon socket'),
          ),
        /must be a unix socket/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === plannedState) {
          const error = new Error('lstat failed');
          error.code = 'EIO';
          throw error;
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () =>
          withMockedEuid(0, () =>
            trust.assertTrustedRootPlannedPrivateFilePath(plannedState, 'Managed state file'),
          ),
        /lstat failed/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === plannedState) {
          return null;
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      const resolved = withMockedEuid(0, () =>
        trust.assertTrustedRootPlannedPrivateFilePath(plannedState, 'Managed state file'),
      );
      assert.equal(resolved, path.resolve(plannedState));
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === plannedState) {
          return makeStats({ uid: 0, mode: 0o700, symlink: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () =>
          withMockedEuid(0, () =>
            trust.assertTrustedRootPlannedPrivateFilePath(plannedState, 'Managed state file'),
          ),
        /must not be a symlink/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === plannedState) {
          return makeStats({ uid: 0, mode: 0o700, directory: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () =>
          withMockedEuid(0, () =>
            trust.assertTrustedRootPlannedPrivateFilePath(plannedState, 'Managed state file'),
          ),
        /must be a regular file/,
      );
    },
  );
});

test('private-file, secure-read, and executable trust branches handle synthetic failures', async () => {
  const trust = await import(`${modulePath.href}?case=${Date.now()}-private-and-exec-edges`);
  const privateFilePath = '/virtual/root/run/daemon-state.enc';
  const binaryPath = '/virtual/root/bin/agentpay-daemon';
  const binaryDir = '/virtual/root/bin';

  const rootAwareLstat = (targetPath) => {
    const resolved = path.resolve(String(targetPath));
    if (resolved === '/') {
      return makeStats({ uid: 0, mode: 0o755, directory: true });
    }
    if (
      resolved === '/virtual' ||
      resolved === '/virtual/root' ||
      resolved === '/virtual/root/run' ||
      resolved === '/virtual/root/bin'
    ) {
      return makeStats({ uid: 0, mode: 0o700, directory: true });
    }
    const error = new Error(`missing: ${resolved}`);
    error.code = 'ENOENT';
    throw error;
  };

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        if (path.resolve(String(targetPath)) === privateFilePath) {
          const error = new Error('missing');
          error.code = 'ENOENT';
          throw error;
        }
        return rootAwareLstat(targetPath);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      const resolved = withMockedEuid(0, () =>
        trust.assertTrustedRootPrivateFilePath(privateFilePath, 'State file', {
          allowMissing: true,
        }),
      );
      assert.equal(resolved, privateFilePath);
      assert.throws(
        () =>
          withMockedEuid(0, () =>
            trust.assertTrustedRootPrivateFilePath(privateFilePath, 'State file'),
          ),
        /does not exist/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        if (path.resolve(String(targetPath)) === privateFilePath) {
          const error = new Error('boom');
          error.code = 'EIO';
          throw error;
        }
        return rootAwareLstat(targetPath);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () =>
          withMockedEuid(0, () =>
            trust.assertTrustedRootPrivateFilePath(privateFilePath, 'State file'),
          ),
        /boom/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === privateFilePath) {
          return makeStats({ uid: 0, mode: 0o700, directory: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => trust.assertTrustedPrivateFilePath(privateFilePath, 'State file'),
        /must be a regular file/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === privateFilePath) {
          const error = new Error('unexpected lstat error');
          error.code = 'EIO';
          throw error;
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => trust.assertTrustedPrivateFilePath(privateFilePath, 'State file'),
        /unexpected lstat error/,
      );
    },
  );

  withMockedFs(
    {
      openSync: () => 99,
      fstatSync: () => makeStats({ uid: 0, mode: 0o700, directory: true }),
      closeSync: () => {},
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
      lstatSync: (targetPath) => rootAwareLstat(targetPath),
    },
    () => {
      assert.throws(
        () => trust.readUtf8FileSecure('/virtual/root/run/not-a-file', 'Secure read target'),
        /must be a regular file/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === binaryPath) {
          return makeStats({ uid: 0, mode: 0o700, file: true });
        }
        if (resolved === binaryDir) {
          return makeStats({ uid: 0, mode: 0o700, symlink: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => withMockedEuid(0, () => trust.assertTrustedExecutablePath(binaryPath)),
        /must not be a symlink/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === binaryPath) {
          return makeStats({ uid: 0, mode: 0o700, file: true });
        }
        if (resolved === binaryDir) {
          return makeStats({ uid: 0, mode: 0o700, file: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => withMockedEuid(0, () => trust.assertTrustedExecutablePath(binaryPath)),
        /must be a directory/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === binaryPath) {
          return makeStats({ uid: 0, mode: 0o700, file: true });
        }
        if (resolved === binaryDir) {
          return makeStats({ uid: 0, mode: 0o777, directory: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => withMockedEuid(0, () => trust.assertTrustedExecutablePath(binaryPath)),
        /must not be writable by group\/other/,
      );
    },
  );
});

test('directory and daemon socket trust checks cover sticky, symlink, and rethrow branches', async () => {
  const trust = await import(`${modulePath.href}?case=${Date.now()}-directory-and-socket-edges`);

  assert.throws(
    () => trust.assertTrustedExecutablePath('/'),
    /must be a regular file|must be owned/,
  );
  assert.throws(
    () => trust.assertTrustedExecutablePath('/tmp'),
    /must be a regular file|must be owned|must not be a symlink/,
  );

  if (process.platform !== 'win32') {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-fs-trust-sticky-'));
    const stickyParent = path.join(tempRoot, 'sticky');
    const child = path.join(stickyParent, 'child');
    fs.mkdirSync(child, { recursive: true, mode: 0o700 });
    fs.chmodSync(stickyParent, 0o1777);
    fs.chmodSync(child, 0o700);
    assert.doesNotThrow(() => trust.assertTrustedDirectoryPath(child, 'Sticky child path'));
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }

  withMockedPlatform('win32', () => {
    withMockedFs(
      {
        lstatSync: () => makeStats({ uid: 999, mode: 0o777, directory: true }),
        realpathSync: {
          native: (targetPath) => path.resolve(String(targetPath)),
        },
      },
      () => {
        assert.doesNotThrow(() =>
          trust.assertTrustedDirectoryPath('C:\\Users\\tester\\agentpay', 'Windows path'),
        );
      },
    );
  });

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === '/virtual/socket-dir') {
          return makeStats({ uid: 0, mode: 0o700, directory: true });
        }
        if (resolved === '/virtual/socket-dir/daemon.sock') {
          const error = new Error('socket lstat failed');
          error.code = 'EIO';
          throw error;
        }
        if (resolved === '/virtual' || resolved === '/') {
          return makeStats({ uid: 0, mode: 0o755, directory: true });
        }
        const error = new Error('missing');
        error.code = 'ENOENT';
        throw error;
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => trust.assertTrustedDaemonSocketPath('/virtual/socket-dir/daemon.sock'),
        /socket lstat failed/,
      );
    },
  );

  const rootOwnedLstat = (targetPath) => {
    const resolved = path.resolve(String(targetPath));
    if (
      resolved === '/' ||
      resolved === '/virtual' ||
      resolved === '/virtual/root' ||
      resolved === '/virtual/root/run'
    ) {
      return makeStats({ uid: 0, mode: 0o700, directory: true });
    }
    const error = new Error('missing');
    error.code = 'ENOENT';
    throw error;
  };

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        if (path.resolve(String(targetPath)) === '/virtual/root/run/daemon.sock') {
          return makeStats({ uid: 0, mode: 0o700, symlink: true });
        }
        return rootOwnedLstat(targetPath);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () =>
          withMockedEuid(0, () =>
            trust.assertTrustedAdminDaemonSocketPath('/virtual/root/run/daemon.sock'),
          ),
        /must not be a symlink/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        if (path.resolve(String(targetPath)) === '/virtual/root/run/daemon.sock') {
          return makeStats({ uid: 0, mode: 0o700, file: true });
        }
        return rootOwnedLstat(targetPath);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () =>
          withMockedEuid(0, () =>
            trust.assertTrustedAdminDaemonSocketPath('/virtual/root/run/daemon.sock'),
          ),
        /must be a unix socket/,
      );
    },
  );
});

test('root and private file validators cover remaining ENOENT, type, and success branches', async () => {
  const trust = await import(`${modulePath.href}?case=${Date.now()}-root-private-remaining`);
  const plannedDir = '/ghost/missing/path';
  const rootDir = '/virtual/root';
  const statePath = '/virtual/root/run/state.enc';

  withMockedFs(
    {
      lstatSync: () => {
        const error = new Error('all missing');
        error.code = 'ENOENT';
        throw error;
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => trust.assertTrustedRootPlannedDirectoryPath(plannedDir, 'Ghost path'),
        /No existing ancestor directory found/,
      );
    },
  );

  const rootAwareLstat = (targetPath) => {
    const resolved = path.resolve(String(targetPath));
    if (
      resolved === '/' ||
      resolved === '/virtual' ||
      resolved === '/virtual/root' ||
      resolved === '/virtual/root/run'
    ) {
      return makeStats({ uid: 0, mode: 0o700, directory: true });
    }
    const error = new Error('missing');
    error.code = 'ENOENT';
    throw error;
  };

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === rootDir) {
          return makeStats({ uid: 0, mode: 0o700, symlink: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => withMockedEuid(0, () => trust.assertTrustedRootDirectoryPath(rootDir, 'Root dir')),
        /must not be a symlink/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === rootDir) {
          return makeStats({ uid: 0, mode: 0o600, file: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => withMockedEuid(0, () => trust.assertTrustedRootDirectoryPath(rootDir, 'Root dir')),
        /must be a directory/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === '/virtual') {
          return makeStats({ uid: 0, mode: 0o600, file: true });
        }
        if (resolved === '/' || resolved === '/virtual/root' || resolved === '/virtual/root/run') {
          return makeStats({ uid: 0, mode: 0o700, directory: true });
        }
        const error = new Error('missing');
        error.code = 'ENOENT';
        throw error;
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () =>
          withMockedEuid(0, () =>
            trust.assertTrustedRootDirectoryPath('/virtual/root/run', 'Root dir'),
          ),
        /must be a directory/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === statePath) {
          return makeStats({ uid: 0, mode: 0o700, symlink: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () =>
          withMockedEuid(0, () => trust.assertTrustedRootPrivateFilePath(statePath, 'State file')),
        /must not be a symlink/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === statePath) {
          return makeStats({ uid: 0, mode: 0o700, directory: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () =>
          withMockedEuid(0, () => trust.assertTrustedRootPrivateFilePath(statePath, 'State file')),
        /must be a regular file/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === statePath) {
          return makeStats({ uid: 0, mode: 0o600, file: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.equal(
        withMockedEuid(0, () => trust.assertTrustedRootPrivateFilePath(statePath, 'State file')),
        statePath,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === statePath) {
          const error = new Error('private file missing');
          error.code = 'ENOENT';
          throw error;
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => trust.assertTrustedPrivateFilePath(statePath, 'State file'),
        /does not exist/,
      );
    },
  );

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'agentpay-fs-trust-nonfile-'));
  assert.throws(() => trust.assertTrustedExecutablePath(tempRoot), /must be a regular file/);
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test('root planned validators cover existing socket/file success and EACCES branches', async () => {
  const trust = await import(`${modulePath.href}?case=${Date.now()}-root-planned-success-edges`);
  const plannedSocket = '/virtual/root/run/daemon.sock';
  const plannedPrivateFile = '/virtual/root/run/state.enc';

  const rootAwareLstat = (targetPath) => {
    const resolved = path.resolve(String(targetPath));
    if (
      resolved === '/' ||
      resolved === '/virtual' ||
      resolved === '/virtual/root' ||
      resolved === '/virtual/root/run'
    ) {
      return makeStats({ uid: 0, mode: 0o700, directory: true });
    }
    const error = new Error(`missing: ${resolved}`);
    error.code = 'ENOENT';
    throw error;
  };

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === plannedSocket) {
          return makeStats({ uid: 0, mode: 0o700, socket: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.equal(
        withMockedEuid(0, () =>
          trust.assertTrustedRootPlannedDaemonSocketPath(plannedSocket, 'Managed daemon socket'),
        ),
        plannedSocket,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === plannedPrivateFile) {
          const error = new Error('permission denied');
          error.code = 'EACCES';
          throw error;
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.equal(
        withMockedEuid(0, () =>
          trust.assertTrustedRootPlannedPrivateFilePath(plannedPrivateFile, 'Managed state file'),
        ),
        plannedPrivateFile,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === plannedPrivateFile) {
          return makeStats({ uid: 0, mode: 0o600, file: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.equal(
        withMockedEuid(0, () =>
          trust.assertTrustedRootPlannedPrivateFilePath(plannedPrivateFile, 'Managed state file'),
        ),
        plannedPrivateFile,
      );
    },
  );
});

test('secure-read and private-file helpers cover symlink and byte-limit branches', async () => {
  const trust = await import(
    `${modulePath.href}?case=${Date.now()}-secure-read-and-private-symlink`
  );
  const privatePath = '/virtual/root/run/private.enc';
  const secureFilePath = '/virtual/root/run/data.json';

  const rootAwareLstat = (targetPath) => {
    const resolved = path.resolve(String(targetPath));
    if (
      resolved === '/' ||
      resolved === '/virtual' ||
      resolved === '/virtual/root' ||
      resolved === '/virtual/root/run'
    ) {
      return makeStats({ uid: 0, mode: 0o700, directory: true });
    }
    const error = new Error(`missing: ${resolved}`);
    error.code = 'ENOENT';
    throw error;
  };

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === privatePath) {
          return makeStats({ uid: 0, mode: 0o700, symlink: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => trust.assertTrustedPrivateFilePath(privatePath, 'Private file'),
        /must not be a symlink/,
      );
    },
  );

  withMockedFs(
    {
      openSync: () => 101,
      fstatSync: () => ({ ...makeStats({ uid: 0, mode: 0o600, file: true }), size: 6 }),
      closeSync: () => {},
      readFileSync: () => 'secret',
      lstatSync: (targetPath) => rootAwareLstat(targetPath),
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.equal(trust.readUtf8FileSecure(secureFilePath, 'Secure file'), 'secret');
    },
  );

  withMockedFs(
    {
      openSync: () => 102,
      fstatSync: () => ({ ...makeStats({ uid: 0, mode: 0o600, file: true }), size: 8 }),
      closeSync: () => {},
      readFileSync: () => 'too-large',
      lstatSync: (targetPath) => rootAwareLstat(targetPath),
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => trust.readUtf8FileSecure(secureFilePath, 'Secure file', 4),
        /must not exceed 4 bytes/,
      );
    },
  );
});

test('secure-read and executable helpers cover win32 open flags and root-owned executable success', async () => {
  const trust = await import(
    `${modulePath.href}?case=${Date.now()}-secure-read-win32-and-root-exec-success`
  );
  const secureFilePath = '/virtual/root/run/data.json';
  const binaryPath = '/virtual/root/bin/agentpay-daemon';

  const rootAwareLstat = (targetPath) => {
    const resolved = path.resolve(String(targetPath));
    if (
      resolved === '/' ||
      resolved === '/virtual' ||
      resolved === '/virtual/root' ||
      resolved === '/virtual/root/run' ||
      resolved === '/virtual/root/bin'
    ) {
      return makeStats({ uid: 0, mode: 0o700, directory: true });
    }
    const error = new Error(`missing: ${resolved}`);
    error.code = 'ENOENT';
    throw error;
  };

  let observedOpenFlags = null;
  withMockedPlatform('win32', () => {
    withMockedFs(
      {
        openSync: (_targetPath, flags) => {
          observedOpenFlags = flags;
          return 103;
        },
        fstatSync: () => ({ ...makeStats({ uid: 0, mode: 0o600, file: true }), size: 4 }),
        closeSync: () => {},
        readFileSync: () => 'data',
        lstatSync: (targetPath) => rootAwareLstat(targetPath),
        realpathSync: {
          native: (targetPath) => path.resolve(String(targetPath)),
        },
      },
      () => {
        assert.equal(trust.readUtf8FileSecure(secureFilePath, 'Secure file'), 'data');
      },
    );
  });
  assert.equal(observedOpenFlags, fs.constants.O_RDONLY);

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === binaryPath) {
          return makeStats({ uid: 0, mode: 0o700, file: true });
        }
        return rootAwareLstat(resolved);
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.doesNotThrow(() =>
        withMockedEuid(0, () => trust.assertTrustedExecutablePath(binaryPath)),
      );
    },
  );
});

test('directory trust helpers rethrow non-ENOENT and enforce target type checks', async () => {
  const trust = await import(`${modulePath.href}?case=${Date.now()}-directory-trust-extra-edges`);

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        if (path.resolve(String(targetPath)) === '/virtual') {
          const error = new Error('ancestor lstat boom');
          error.code = 'EIO';
          throw error;
        }
        const error = new Error('missing');
        error.code = 'ENOENT';
        throw error;
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => trust.assertTrustedDirectoryPath('/virtual/example', 'Virtual directory'),
        /ancestor lstat boom/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === '/virtual/example') {
          return makeStats({ uid: 0, mode: 0o700, symlink: true });
        }
        if (resolved === '/virtual' || resolved === '/') {
          return makeStats({ uid: 0, mode: 0o700, directory: true });
        }
        const error = new Error('missing');
        error.code = 'ENOENT';
        throw error;
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => trust.assertTrustedDirectoryPath('/virtual/example', 'Virtual directory'),
        /must not be a symlink/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === '/virtual/example') {
          return makeStats({ uid: 0, mode: 0o600, file: true });
        }
        if (resolved === '/virtual' || resolved === '/') {
          return makeStats({ uid: 0, mode: 0o700, directory: true });
        }
        const error = new Error('missing');
        error.code = 'ENOENT';
        throw error;
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => trust.assertTrustedDirectoryPath('/virtual/example', 'Virtual directory'),
        /must be a directory/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === '/virtual/example') {
          return makeStats({ uid: 0, mode: 0o700, directory: true });
        }
        if (resolved === '/virtual') {
          return makeStats({ uid: 0, mode: 0o600, file: true });
        }
        if (resolved === '/') {
          return makeStats({ uid: 0, mode: 0o700, directory: true });
        }
        const error = new Error('missing');
        error.code = 'ENOENT';
        throw error;
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () => trust.assertTrustedDirectoryPath('/virtual/example', 'Virtual directory'),
        /must be a directory/,
      );
    },
  );

  withMockedFs(
    {
      lstatSync: (targetPath) => {
        const resolved = path.resolve(String(targetPath));
        if (resolved === '/virtual/root/run') {
          return makeStats({ uid: 0, mode: 0o700, directory: true });
        }
        if (resolved === '/virtual/root/run/daemon.sock') {
          const error = new Error('socket stat exploded');
          error.code = 'EIO';
          throw error;
        }
        if (resolved === '/virtual' || resolved === '/virtual/root' || resolved === '/') {
          return makeStats({ uid: 0, mode: 0o700, directory: true });
        }
        const error = new Error('missing');
        error.code = 'ENOENT';
        throw error;
      },
      realpathSync: {
        native: (targetPath) => path.resolve(String(targetPath)),
      },
    },
    () => {
      assert.throws(
        () =>
          withMockedEuid(0, () =>
            trust.assertTrustedAdminDaemonSocketPath('/virtual/root/run/daemon.sock'),
          ),
        /socket stat exploded/,
      );
    },
  );
});
