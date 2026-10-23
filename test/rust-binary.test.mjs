import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { PassThrough, Readable } from 'node:stream';
import test from 'node:test';

const require = createRequire(import.meta.url);
const configModulePath = new URL('../packages/config/src/index.ts', import.meta.url);

function makeTempRoot(prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.chmodSync(root, 0o700);
  return root;
}

function writeExecutable(dir, name, scriptBody, mode = 0o700) {
  const filePath = path.join(dir, name);
  fs.writeFileSync(filePath, `#!/bin/sh\n${scriptBody}\n`, { mode });
  return filePath;
}

function createSocketServer(socketPath) {
  const server = net.createServer();
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => resolve(server));
  });
}

async function importRustModule(caseLabel) {
  const modulePath = new URL('../src/lib/rust.ts', import.meta.url);
  return import(`${modulePath.href}?case=${Date.now()}-${caseLabel}`);
}

async function withMockedSpawn(factory, fn) {
  const childProcess = require('node:child_process');
  const originalSpawn = childProcess.spawn;
  childProcess.spawn = factory;
  syncBuiltinESMExports();

  try {
    await fn();
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
  }
}

test('runRustBinaryJson relays daemon socket and stdin for agent commands', async () => {
  const root = makeTempRoot('agentpay-rust-json-');
  const socketPath = path.join(root, 'daemon.sock');
  const stdinCapturePath = path.join(root, 'stdin.txt');
  const daemonCapturePath = path.join(root, 'daemon.txt');
  const binaryName = 'agentpay-agent';
  const server = await createSocketServer(socketPath);

  try {
    writeExecutable(
      root,
      binaryName,
      [
        'stdin_file="$1"',
        'daemon_file="$2"',
        'cat > "$stdin_file"',
        `printf "%s" "\${AGENTPAY_DAEMON_SOCKET:-}" > "$daemon_file"`,
        'printf \'{"ok":true}\'',
      ].join('\n'),
    );

    const rust = await importRustModule('json-success');
    const result = await rust.runRustBinaryJson(
      binaryName,
      [stdinCapturePath, daemonCapturePath, '--agent-auth-token-stdin'],
      {
        rustBinDir: root,
        daemonSocket: socketPath,
      },
      {
        stdin: 'agent-auth-secret\n',
        preSuppliedSecretStdin: 'agentAuthToken',
        scrubSensitiveEnv: true,
      },
    );

    assert.deepEqual(result, { ok: true });
    assert.equal(fs.readFileSync(stdinCapturePath, 'utf8'), 'agent-auth-secret\n');
    assert.equal(fs.readFileSync(daemonCapturePath, 'utf8'), socketPath);
  } finally {
    server.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary throws RustBinaryExitError for non-zero exits', async () => {
  const root = makeTempRoot('agentpay-rust-nonzero-');
  const binaryName = 'agentpay-daemon';

  try {
    writeExecutable(
      root,
      binaryName,
      ['echo "child-stdout"', 'echo "child-stderr" 1>&2', 'exit 9'].join('\n'),
    );

    const rust = await importRustModule('nonzero');
    await assert.rejects(
      () => rust.runRustBinary(binaryName, ['--help'], { rustBinDir: root }),
      (error) => {
        assert.equal(error.name, 'RustBinaryExitError');
        assert.equal(error.binaryName, binaryName);
        assert.equal(error.code, 9);
        assert.match(error.stdout, /child-stdout/u);
        assert.match(error.stderr, /child-stderr/u);
        assert.match(error.message, /child-stderr/u);
        return true;
      },
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary falls back to the exit-code message when stderr is empty', async () => {
  const root = makeTempRoot('agentpay-rust-nonzero-empty-stderr-');
  const binaryName = 'agentpay-daemon';

  try {
    writeExecutable(root, binaryName, ['echo "child-stdout"', 'exit 9'].join('\n'));

    const rust = await importRustModule('nonzero-empty-stderr');
    await assert.rejects(
      () => rust.runRustBinary(binaryName, ['--help'], { rustBinDir: root }),
      (error) => {
        assert.equal(error.name, 'RustBinaryExitError');
        assert.equal(error.message, `${binaryName} exited with code 9`);
        return true;
      },
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary deduplicates repeated Rust error-chain leaf messages', async () => {
  const root = makeTempRoot('agentpay-rust-dedup-stderr-');
  const binaryName = 'agentpay-daemon';

  try {
    writeExecutable(
      root,
      binaryName,
      [
        'echo "Error: transfer denied" 1>&2',
        'echo "Caused by:" 1>&2',
        'echo "  0: per transaction max 1 < requested 2" 1>&2',
        'echo "  1: per transaction max 1 < requested 2" 1>&2',
        'exit 9',
      ].join('\n'),
    );

    const rust = await importRustModule('dedup-stderr');
    await assert.rejects(
      () => rust.runRustBinary(binaryName, ['--help'], { rustBinDir: root }),
      (error) => {
        assert.equal(error.name, 'RustBinaryExitError');
        assert.equal(error.message, 'transfer denied\nper transaction max 1 < requested 2');
        assert.match(error.stderr, /Caused by:/u);
        return true;
      },
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('passthroughRustBinary refuses to relay AGENTPAY_AGENT_AUTH_TOKEN from the environment', async () => {
  const root = makeTempRoot('agentpay-rust-pass-through-');
  const socketPath = path.join(root, 'daemon.sock');
  const stdinCapturePath = path.join(root, 'stdin.txt');
  const daemonCapturePath = path.join(root, 'daemon.txt');
  const binaryName = 'agentpay-agent';
  const server = await createSocketServer(socketPath);
  const originalAgentToken = process.env.AGENTPAY_AGENT_AUTH_TOKEN;
  process.env.AGENTPAY_AGENT_AUTH_TOKEN = 'env-agent-token';

  try {
    writeExecutable(
      root,
      binaryName,
      [
        `cat > "${stdinCapturePath}"`,
        `printf "%s" "\${AGENTPAY_DAEMON_SOCKET:-}" > "${daemonCapturePath}"`,
        'exit 7',
      ].join('\n'),
    );

    const rust = await importRustModule('passthrough');
    await assert.rejects(
      () =>
        rust.passthroughRustBinary(binaryName, [], {
          rustBinDir: root,
          daemonSocket: socketPath,
        }),
      /AGENTPAY_AGENT_AUTH_TOKEN is disabled by default for security/u,
    );

    // The binary must never have been spawned with the env-sourced secret.
    assert.equal(fs.existsSync(stdinCapturePath), false);
    assert.equal(fs.existsSync(daemonCapturePath), false);
  } finally {
    if (originalAgentToken === undefined) {
      delete process.env.AGENTPAY_AGENT_AUTH_TOKEN;
    } else {
      process.env.AGENTPAY_AGENT_AUTH_TOKEN = originalAgentToken;
    }
    server.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary reports missing binaries before spawn', async () => {
  const root = makeTempRoot('agentpay-rust-missing-');

  try {
    const rust = await importRustModule('missing');
    await assert.rejects(
      () => rust.runRustBinary('agentpay-agent', ['--help'], { rustBinDir: root }),
      /is not installed/u,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary reads default config and preserves an explicit daemon socket environment value', async () => {
  const root = makeTempRoot('agentpay-rust-default-config-');
  const agentpayHome = path.join(root, 'home');
  const socketPath = path.join(root, 'daemon.sock');
  const envSocketPath = path.join(root, 'explicit-daemon.sock');
  const stdinCapturePath = path.join(root, 'stdin.txt');
  const daemonCapturePath = path.join(root, 'daemon.txt');
  const binaryName = 'agentpay-agent';
  const server = await createSocketServer(socketPath);
  const envServer = await createSocketServer(envSocketPath);
  const originalAgentPayHome = process.env.AGENTPAY_HOME;
  const originalDaemonSocket = process.env.AGENTPAY_DAEMON_SOCKET;

  process.env.AGENTPAY_HOME = agentpayHome;
  process.env.AGENTPAY_DAEMON_SOCKET = envSocketPath;

  try {
    const configModule = await import(
      `${configModulePath.href}?case=${Date.now()}-rust-default-config`
    );
    configModule.writeConfig({ rustBinDir: root, daemonSocket: socketPath });
    writeExecutable(
      root,
      binaryName,
      [
        'stdin_file="$1"',
        'daemon_file="$2"',
        'cat > "$stdin_file"',
        `printf "%s" "\${AGENTPAY_DAEMON_SOCKET:-}" > "$daemon_file"`,
        'printf \'{"ok":true}\'',
      ].join('\n'),
    );

    const rust = await importRustModule('default-config');
    const result = await rust.runRustBinaryJson(
      binaryName,
      [stdinCapturePath, daemonCapturePath, '--agent-auth-token-stdin'],
      undefined,
      {
        stdin: 'agent-auth-secret\n',
        preSuppliedSecretStdin: 'agentAuthToken',
        scrubSensitiveEnv: true,
      },
    );

    assert.deepEqual(result, { ok: true });
    assert.equal(fs.readFileSync(daemonCapturePath, 'utf8'), envSocketPath);
  } finally {
    if (originalAgentPayHome === undefined) {
      delete process.env.AGENTPAY_HOME;
    } else {
      process.env.AGENTPAY_HOME = originalAgentPayHome;
    }
    if (originalDaemonSocket === undefined) {
      delete process.env.AGENTPAY_DAEMON_SOCKET;
    } else {
      process.env.AGENTPAY_DAEMON_SOCKET = originalDaemonSocket;
    }
    server.close();
    envServer.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinaryJson rejects invalid JSON payloads', async () => {
  const root = makeTempRoot('agentpay-rust-json-fail-');
  const binaryName = 'agentpay-daemon';

  try {
    writeExecutable(root, binaryName, ['echo "not-json"', 'exit 0'].join('\n'));
    const rust = await importRustModule('json-parse-fail');
    await assert.rejects(
      () => rust.runRustBinaryJson(binaryName, ['--help'], { rustBinDir: root }),
      /Unexpected token/u,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('passthroughRustBinary normalizes null close codes to 1', async () => {
  const root = makeTempRoot('agentpay-rust-passthrough-null-close-');
  const binaryName = 'agentpay-daemon';

  try {
    writeExecutable(root, binaryName, 'exit 0');

    await withMockedSpawn(
      (_command, _args, _options) => {
        const child = new EventEmitter();
        child.on = child.addListener.bind(child);
        setImmediate(() => child.emit('close', null));
        return child;
      },
      async () => {
        const rust = await importRustModule('passthrough-null-close');
        const code = await rust.passthroughRustBinary(binaryName, ['--help'], { rustBinDir: root });
        assert.equal(code, 1);
      },
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('passthroughRustBinary maps close signals to their shell-style exit codes', async () => {
  const root = makeTempRoot('agentpay-rust-passthrough-signal-close-');
  const binaryName = 'agentpay-daemon';

  try {
    writeExecutable(root, binaryName, 'exit 0');

    for (const [signal, expectedCode] of [
      ['SIGKILL', 137],
      ['SIGINT', 130],
    ]) {
      await withMockedSpawn(
        (_command, _args, _options) => {
          const child = new EventEmitter();
          child.on = child.addListener.bind(child);
          setImmediate(() => child.emit('close', null, signal));
          return child;
        },
        async () => {
          const rust = await importRustModule(`passthrough-signal-close-${signal.toLowerCase()}`);
          const code = await rust.passthroughRustBinary(binaryName, ['--help'], {
            rustBinDir: root,
          });
          assert.equal(code, expectedCode);
        },
      );
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary normalizes null close codes to 1', async () => {
  const root = makeTempRoot('agentpay-rust-run-null-close-');
  const binaryName = 'agentpay-daemon';

  try {
    writeExecutable(root, binaryName, 'exit 0');

    await withMockedSpawn(
      (_command, _args, _options) => {
        const child = new EventEmitter();
        child.stdout = new PassThrough();
        child.stderr = new PassThrough();
        setImmediate(() => child.emit('close', null));
        return child;
      },
      async () => {
        const rust = await importRustModule('run-null-close');
        await assert.rejects(
          () => rust.runRustBinary(binaryName, ['--help'], { rustBinDir: root }),
          /exited with code 1/,
        );
      },
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary maps close signals to their shell-style exit codes', async () => {
  const root = makeTempRoot('agentpay-rust-run-signal-close-');
  const binaryName = 'agentpay-daemon';

  try {
    writeExecutable(root, binaryName, 'exit 0');

    for (const [signal, expectedCode] of [
      ['SIGKILL', 137],
      ['SIGINT', 130],
    ]) {
      await withMockedSpawn(
        (_command, _args, _options) => {
          const child = new EventEmitter();
          child.stdout = new PassThrough();
          child.stderr = new PassThrough();
          setImmediate(() => child.emit('close', null, signal));
          return child;
        },
        async () => {
          const rust = await importRustModule(`run-signal-close-${signal.toLowerCase()}`);
          await assert.rejects(
            () => rust.runRustBinary(binaryName, ['--help'], { rustBinDir: root }),
            (error) => {
              assert.equal(error.name, 'RustBinaryExitError');
              assert.equal(error.code, expectedCode);
              assert.equal(error.message, `${binaryName} exited with code ${expectedCode}`);
              return true;
            },
          );
        },
      );
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary surfaces spawn errors from non-executable binaries', async () => {
  const root = makeTempRoot('agentpay-rust-spawn-error-');
  const binaryName = 'agentpay-daemon';

  try {
    writeExecutable(root, binaryName, 'echo "should-not-run"', 0o600);
    const rust = await importRustModule('spawn-error');
    await assert.rejects(
      () => rust.runRustBinary(binaryName, ['--help'], { rustBinDir: root }),
      (error) => {
        assert.equal(error?.code, 'EACCES');
        return true;
      },
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary tolerates child stdin EPIPE when the child exits before reading secrets', async () => {
  const root = makeTempRoot('agentpay-rust-epipe-');
  const binaryName = 'agentpay-agent';
  const socketPath = path.join(root, 'daemon.sock');
  const server = await createSocketServer(socketPath);

  try {
    writeExecutable(root, binaryName, 'exit 0');

    await withMockedSpawn(
      (_command, _args, _options) => {
        const child = new EventEmitter();
        child.stdout = new PassThrough();
        child.stderr = new PassThrough();
        child.stdin = new EventEmitter();
        child.stdin.end = () => {
          setImmediate(() => {
            child.stdin.emit(
              'error',
              Object.assign(new Error('broken pipe'), {
                code: 'EPIPE',
              }),
            );
            child.emit('close', 0);
          });
        };
        return child;
      },
      async () => {
        const rust = await importRustModule('stdin-epipe');
        const result = await rust.runRustBinary(
          binaryName,
          ['--agent-auth-token-stdin'],
          { rustBinDir: root, daemonSocket: socketPath },
          {
            stdin: 'agent-auth-secret\n',
            preSuppliedSecretStdin: 'agentAuthToken',
            scrubSensitiveEnv: true,
          },
        );

        assert.equal(result.code, 0);
        assert.equal(result.stdout, '');
        assert.equal(result.stderr, '');
      },
    );
  } finally {
    server.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary tolerates synchronous child stdin EPIPE throws when the child exits before reading secrets', async () => {
  const root = makeTempRoot('agentpay-rust-sync-epipe-');
  const binaryName = 'agentpay-agent';
  const socketPath = path.join(root, 'daemon.sock');
  const server = await createSocketServer(socketPath);

  try {
    writeExecutable(root, binaryName, 'exit 0');

    await withMockedSpawn(
      (_command, _args, _options) => {
        const child = new EventEmitter();
        child.stdout = new PassThrough();
        child.stderr = new PassThrough();
        child.stdin = new EventEmitter();
        child.stdin.end = () => {
          setImmediate(() => {
            child.emit('close', 0);
          });
          throw Object.assign(new Error('broken pipe'), {
            code: 'EPIPE',
          });
        };
        return child;
      },
      async () => {
        const rust = await importRustModule('stdin-sync-epipe');
        const result = await rust.runRustBinary(
          binaryName,
          ['--agent-auth-token-stdin'],
          { rustBinDir: root, daemonSocket: socketPath },
          {
            stdin: 'agent-auth-secret\n',
            preSuppliedSecretStdin: 'agentAuthToken',
            scrubSensitiveEnv: true,
          },
        );

        assert.equal(result.code, 0);
        assert.equal(result.stdout, '');
        assert.equal(result.stderr, '');
      },
    );
  } finally {
    server.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('passthroughRustBinary tolerates late child stdin EPIPE after end callback runs', async () => {
  const root = makeTempRoot('agentpay-rust-passthrough-late-epipe-');
  const binaryName = 'agentpay-agent';
  const socketPath = path.join(root, 'daemon.sock');
  const server = await createSocketServer(socketPath);

  try {
    writeExecutable(root, binaryName, 'exit 0');

    await withMockedSpawn(
      (_command, _args, _options) => {
        const child = new EventEmitter();
        child.stdout = new PassThrough();
        child.stderr = new PassThrough();
        child.stdin = new EventEmitter();
        child.stdin.end = (_input, callback) => {
          if (typeof callback === 'function') {
            callback();
          }
          setImmediate(() => {
            child.stdin.emit(
              'error',
              Object.assign(new Error('broken pipe'), {
                code: 'EPIPE',
              }),
            );
            child.stdin.emit('close');
            child.emit('close', 0);
          });
        };
        return child;
      },
      async () => {
        const rust = await importRustModule('passthrough-late-stdin-epipe');
        // The env-token relay is gone, so feed the secret through the stdin relay instead.
        const originalStdinDescriptor = Object.getOwnPropertyDescriptor(process, 'stdin');
        const mockedStdin = Readable.from(['agent-auth-secret\n']);
        mockedStdin.setEncoding('utf8');
        Object.defineProperty(process, 'stdin', { value: mockedStdin, configurable: true });
        try {
          const code = await rust.passthroughRustBinary(
            binaryName,
            ['--agent-auth-token-stdin', 'transfer'],
            { rustBinDir: root, daemonSocket: socketPath },
          );

          assert.equal(code, 0);
        } finally {
          if (originalStdinDescriptor) {
            Object.defineProperty(process, 'stdin', originalStdinDescriptor);
          }
        }
      },
    );
  } finally {
    server.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary rejects child stdin errors other than EPIPE', async () => {
  const root = makeTempRoot('agentpay-rust-stdin-error-');
  const binaryName = 'agentpay-agent';
  const socketPath = path.join(root, 'daemon.sock');
  const server = await createSocketServer(socketPath);

  try {
    writeExecutable(root, binaryName, 'exit 0');

    await withMockedSpawn(
      (_command, _args, _options) => {
        const child = new EventEmitter();
        child.stdout = new PassThrough();
        child.stderr = new PassThrough();
        child.stdin = new EventEmitter();
        child.stdin.end = () => {
          setImmediate(() => {
            child.stdin.emit(
              'error',
              Object.assign(new Error('stream reset'), {
                code: 'ECONNRESET',
              }),
            );
            child.emit('close', 0);
          });
        };
        return child;
      },
      async () => {
        const rust = await importRustModule('stdin-non-epipe');
        await assert.rejects(
          () =>
            rust.runRustBinary(
              binaryName,
              ['--agent-auth-token-stdin'],
              { rustBinDir: root, daemonSocket: socketPath },
              {
                stdin: 'agent-auth-secret\n',
                preSuppliedSecretStdin: 'agentAuthToken',
                scrubSensitiveEnv: true,
              },
            ),
          /stream reset/,
        );
      },
    );
  } finally {
    server.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary rejects synchronous child stdin errors other than EPIPE', async () => {
  const root = makeTempRoot('agentpay-rust-sync-stdin-error-');
  const binaryName = 'agentpay-agent';
  const socketPath = path.join(root, 'daemon.sock');
  const server = await createSocketServer(socketPath);

  try {
    writeExecutable(root, binaryName, 'exit 0');

    await withMockedSpawn(
      (_command, _args, _options) => {
        const child = new EventEmitter();
        child.stdout = new PassThrough();
        child.stderr = new PassThrough();
        child.stdin = new EventEmitter();
        child.stdin.end = () => {
          setImmediate(() => {
            child.emit('close', 0);
          });
          throw Object.assign(new Error('stream reset'), {
            code: 'ECONNRESET',
          });
        };
        return child;
      },
      async () => {
        const rust = await importRustModule('stdin-sync-non-epipe');
        await assert.rejects(
          () =>
            rust.runRustBinary(
              binaryName,
              ['--agent-auth-token-stdin'],
              { rustBinDir: root, daemonSocket: socketPath },
              {
                stdin: 'agent-auth-secret\n',
                preSuppliedSecretStdin: 'agentAuthToken',
                scrubSensitiveEnv: true,
              },
            ),
          /stream reset/,
        );
      },
    );
  } finally {
    server.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinaryJson hides sensitive stdout from JSON parse errors', async () => {
  const root = makeTempRoot('agentpay-rust-sensitive-json-');
  const binaryName = 'agentpay-admin';

  try {
    writeExecutable(
      root,
      binaryName,
      ['printf "%s" "0xdeadbeef-private-key"', 'exit 0'].join('\n'),
    );
    const rust = await importRustModule('sensitive-json');

    await assert.rejects(
      () =>
        rust.runRustBinaryJson(
          binaryName,
          ['--help'],
          { rustBinDir: root },
          {
            sensitiveStdout: true,
          },
        ),
      (error) => {
        assert.equal(error.name, 'RustBinaryJsonParseError');
        assert.equal(error.message, `${binaryName} returned non-JSON output`);
        assert.equal('stdout' in error, false);
        assert.equal(error.stdout, undefined);
        assert.doesNotMatch(String(error.cause?.message ?? ''), /private-key/u);
        return true;
      },
    );

    // Without the flag the snippet is still surfaced for diagnostics.
    await assert.rejects(
      () => rust.runRustBinaryJson(binaryName, ['--help'], { rustBinDir: root }),
      (error) => {
        assert.equal(error.name, 'RustBinaryJsonParseError');
        assert.match(error.message, /stdout: 0xdeadbeef-private-key/u);
        assert.equal(error.stdout, '0xdeadbeef-private-key');
        return true;
      },
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary redacts sensitive stdout on non-zero exits', async () => {
  const root = makeTempRoot('agentpay-rust-sensitive-exit-');
  const binaryName = 'agentpay-admin';

  try {
    writeExecutable(
      root,
      binaryName,
      ['printf "%s" "0xdeadbeef-private-key"', 'echo "vault locked" 1>&2', 'exit 9'].join('\n'),
    );
    const rust = await importRustModule('sensitive-exit');

    await assert.rejects(
      () =>
        rust.runRustBinary(binaryName, ['--help'], { rustBinDir: root }, { sensitiveStdout: true }),
      (error) => {
        assert.equal(error.name, 'RustBinaryExitError');
        assert.equal(error.code, 9);
        assert.equal(error.stdout, '');
        assert.match(error.message, /vault locked/u);
        assert.doesNotMatch(error.message, /private-key/u);
        return true;
      },
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary decodes multibyte stdout split across pipe chunks without corruption', async () => {
  const root = makeTempRoot('agentpay-rust-multibyte-');
  const binaryName = 'agentpay-admin';
  const repeat = 70_000;

  try {
    // 70k x 3-byte characters = 210_000 bytes, several pipe reads that do not align to 3 bytes.
    writeExecutable(
      root,
      binaryName,
      `exec "${process.execPath}" -e "process.stdout.write('\\u20ac'.repeat(${repeat}))"`,
    );
    const rust = await importRustModule('multibyte');
    const result = await rust.runRustBinary(binaryName, ['--help'], { rustBinDir: root });

    assert.equal(result.code, 0);
    assert.equal(result.stdout.length, repeat);
    assert.equal(result.stdout, '€'.repeat(repeat));
    assert.doesNotMatch(result.stdout, /�/u);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary terminates children that exceed the 4 MiB stdout cap', async () => {
  const root = makeTempRoot('agentpay-rust-stdout-cap-');
  const binaryName = 'agentpay-admin';

  try {
    writeExecutable(root, binaryName, 'exec head -c 6000000 /dev/zero');
    const rust = await importRustModule('stdout-cap');

    await assert.rejects(
      () => rust.runRustBinary(binaryName, ['--help'], { rustBinDir: root }),
      (error) => {
        assert.equal(error.name, 'RustBinaryAbortedError');
        assert.equal(error.reason, 'stdout-limit');
        assert.match(error.message, /produced more than 4194304 bytes on stdout/u);
        return true;
      },
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary terminates children that exceed the 4 MiB stderr cap', async () => {
  const root = makeTempRoot('agentpay-rust-stderr-cap-');
  const binaryName = 'agentpay-admin';

  try {
    writeExecutable(root, binaryName, 'exec head -c 6000000 /dev/zero 1>&2');
    const rust = await importRustModule('stderr-cap');

    await assert.rejects(
      () => rust.runRustBinary(binaryName, ['--help'], { rustBinDir: root }),
      (error) => {
        assert.equal(error.name, 'RustBinaryAbortedError');
        assert.equal(error.reason, 'stderr-limit');
        assert.match(error.message, /produced more than 4194304 bytes on stderr/u);
        return true;
      },
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary times out cooperative children with SIGTERM', async () => {
  const root = makeTempRoot('agentpay-rust-timeout-term-');
  const binaryName = 'agentpay-admin';

  try {
    writeExecutable(root, binaryName, 'exec sleep 30');
    const rust = await importRustModule('timeout-term');
    const started = Date.now();

    await assert.rejects(
      () => rust.runRustBinary(binaryName, ['--help'], { rustBinDir: root }, { timeoutMs: 200 }),
      (error) => {
        assert.equal(error.name, 'RustBinaryAbortedError');
        assert.equal(error.reason, 'timeout');
        assert.match(error.message, /did not exit within 200ms and was terminated/u);
        return true;
      },
    );
    assert.ok(
      Date.now() - started < 1_500,
      'SIGTERM should end the child before the SIGKILL grace',
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary escalates to SIGKILL when a timed-out child ignores SIGTERM', async () => {
  const root = makeTempRoot('agentpay-rust-timeout-kill-');
  const binaryName = 'agentpay-admin';

  try {
    // Not every sleep(1) keeps a shell-ignored SIGTERM disposition across exec, so ignore it
    // explicitly in the process that actually stays alive.
    // The shell trap covers the window before perl has installed its own handler.
    writeExecutable(
      root,
      binaryName,
      ["trap '' TERM", `exec perl -e '$SIG{TERM} = "IGNORE"; sleep 30'`].join('\n'),
    );
    const rust = await importRustModule('timeout-kill');
    const started = Date.now();

    await assert.rejects(
      // Leave the child time to install its TERM traps before the timeout fires, even when the
      // full suite has the machine under load; otherwise SIGTERM can land before `trap` runs.
      () => rust.runRustBinary(binaryName, ['--help'], { rustBinDir: root }, { timeoutMs: 2_000 }),
      (error) => {
        assert.equal(error.name, 'RustBinaryAbortedError');
        assert.equal(error.reason, 'timeout');
        return true;
      },
    );
    const elapsed = Date.now() - started;
    assert.ok(elapsed >= 3_000, `expected the SIGTERM grace period to elapse, took ${elapsed}ms`);
    assert.ok(elapsed < 12_000, `expected SIGKILL to end the child promptly, took ${elapsed}ms`);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary rejects non-positive timeouts before spawning', async () => {
  const root = makeTempRoot('agentpay-rust-timeout-invalid-');
  const binaryName = 'agentpay-admin';

  try {
    writeExecutable(root, binaryName, 'exit 0');
    const rust = await importRustModule('timeout-invalid');

    await assert.rejects(
      () => rust.runRustBinary(binaryName, ['--help'], { rustBinDir: root }, { timeoutMs: 0 }),
      /timeoutMs must be a positive number of milliseconds/u,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary surfaces agent exit code 3 (unavailable) as a plain error with the stderr message', async () => {
  const root = makeTempRoot('agentpay-rust-agent-unavailable-');
  const binaryName = 'agentpay-agent';

  try {
    writeExecutable(
      root,
      binaryName,
      ['echo "error: private balance is unavailable for this wallet" 1>&2', 'exit 3'].join('\n'),
    );

    const rust = await importRustModule('agent-unavailable');
    await assert.rejects(
      () => rust.runRustBinary(binaryName, ['--help'], { rustBinDir: root }),
      (error) => {
        assert.equal(error.name, 'RustBinaryExitError');
        assert.equal(error.code, 3);
        assert.equal(error.stdout, '');
        assert.match(error.message, /private balance is unavailable/u);
        return true;
      },
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary hands extraInputFd3 to the child on an fd 3 pipe and closes it', async () => {
  const root = makeTempRoot('agentpay-rust-fd3-');
  const binaryName = 'agentpay-admin';

  try {
    // `cat <&3` only finishes once the parent ends the pipe, so this also proves fd 3 is closed.
    writeExecutable(root, binaryName, 'exec cat <&3');
    const rust = await importRustModule('extra-input-fd3');
    const result = await rust.runRustBinary(
      binaryName,
      ['--help'],
      { rustBinDir: root },
      { extraInputFd3: 'imported-key-material\n' },
    );

    assert.equal(result.code, 0);
    assert.equal(result.stdout, 'imported-key-material\n');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary does not open fd 3 for the child unless extraInputFd3 is set', async () => {
  const root = makeTempRoot('agentpay-rust-no-fd3-');
  const binaryName = 'agentpay-admin';

  try {
    writeExecutable(
      root,
      binaryName,
      'if { true <&3; } 2>/dev/null; then echo open; else echo closed; fi',
    );
    const rust = await importRustModule('no-extra-input-fd3');
    const result = await rust.runRustBinary(binaryName, ['--help'], { rustBinDir: root });

    assert.equal(result.stdout.trim(), 'closed');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('runRustBinary tolerates fd 3 EPIPE when the child exits before reading the extra input', async () => {
  const root = makeTempRoot('agentpay-rust-fd3-epipe-');
  const binaryName = 'agentpay-admin';
  let spawnOptions;

  try {
    writeExecutable(root, binaryName, 'exit 0');

    await withMockedSpawn(
      (_command, _args, options) => {
        spawnOptions = options;
        const child = new EventEmitter();
        child.stdout = new PassThrough();
        child.stderr = new PassThrough();
        const fd3 = new EventEmitter();
        fd3.write = () => true;
        fd3.end = () => {
          setImmediate(() => {
            fd3.emit('error', Object.assign(new Error('broken pipe'), { code: 'EPIPE' }));
            child.emit('close', 0);
          });
        };
        child.stdio = [null, child.stdout, child.stderr, fd3];
        return child;
      },
      async () => {
        const rust = await importRustModule('extra-input-fd3-epipe');
        const result = await rust.runRustBinary(
          binaryName,
          ['--help'],
          { rustBinDir: root },
          { extraInputFd3: 'imported-key-material\n' },
        );
        assert.equal(result.code, 0);
      },
    );

    assert.deepEqual(spawnOptions.stdio, ['ignore', 'pipe', 'pipe', 'pipe']);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
