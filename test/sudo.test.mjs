import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import test from 'node:test';

const modulePath = new URL('../src/lib/sudo.ts', import.meta.url);

function createSpawnStub(steps) {
  const calls = [];

  const spawnCommand = (command, args, options) => {
    const step = steps.shift();
    assert.ok(step, `unexpected spawn call: ${command} ${args.join(' ')}`);

    const call = {
      command,
      args,
      options,
      stdin: '',
    };
    calls.push(call);

    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.stdin = new PassThrough();
    child.stdin.on('data', (chunk) => {
      call.stdin += chunk.toString();
    });
    child.stdin.on('end', () => {
      setImmediate(() => {
        if (step.stdout) {
          child.stdout.write(step.stdout);
        }
        if (step.stderr) {
          child.stderr.write(step.stderr);
        }
        child.stdout.end();
        child.stderr.end();
        child.emit(
          'close',
          Object.hasOwn(step, 'closeCode') ? step.closeCode : (step.code ?? 0),
          step.signal ?? null,
        );
      });
    });

    return child;
  };

  return { calls, spawnCommand };
}

test('createSudoSession primes sudo once and keeps later command stdin free of the password', async () => {
  const sudo = await import(`${modulePath.href}?case=${Date.now()}-prime-once`);
  const { calls, spawnCommand } = createSpawnStub([{ code: 0 }, { code: 0, stdout: '501\n' }]);
  let promptCount = 0;

  const session = sudo.createSudoSession({
    promptPassword: async () => {
      promptCount += 1;
      return 'root-secret';
    },
    isRoot: () => false,
    spawnCommand,
  });

  await session.prime();
  const result = await session.run(['/usr/bin/id', '-u']);

  assert.equal(result.code, 0);
  assert.equal(result.stdout, '501\n');
  assert.equal(promptCount, 1);
  assert.deepEqual(
    calls.map((call) => [call.command, call.args]),
    [
      ['sudo', ['-S', '-p', '', '-v']],
      ['sudo', ['-n', '/usr/bin/id', '-u']],
    ],
  );
  assert.equal(calls[0].stdin, 'root-secret\n');
  assert.equal(calls[1].stdin, '');
});

test('createSudoSession re-prompts after sudo authentication expires and retries once', async () => {
  const sudo = await import(`${modulePath.href}?case=${Date.now()}-reprime`);
  const { calls, spawnCommand } = createSpawnStub([
    { code: 0 },
    { code: 1, stderr: 'sudo: a password is required\n' },
    { code: 0 },
    { code: 0, stdout: 'ok\n' },
  ]);
  const promptedPasswords = ['root-secret-1', 'root-secret-2'];

  const session = sudo.createSudoSession({
    promptPassword: async () => promptedPasswords.shift(),
    isRoot: () => false,
    spawnCommand,
  });

  const result = await session.run(['/usr/bin/true']);

  assert.equal(result.code, 0);
  assert.equal(result.stdout, 'ok\n');
  assert.deepEqual(
    calls.map((call) => [call.command, call.args, call.stdin]),
    [
      ['sudo', ['-S', '-p', '', '-v'], 'root-secret-1\n'],
      ['sudo', ['-n', '/usr/bin/true'], ''],
      ['sudo', ['-S', '-p', '', '-v'], 'root-secret-2\n'],
      ['sudo', ['-n', '/usr/bin/true'], ''],
    ],
  );
});

test('createSudoSession bypasses sudo entirely for root processes', async () => {
  const sudo = await import(`${modulePath.href}?case=${Date.now()}-root-bypass`);
  const { calls, spawnCommand } = createSpawnStub([{ code: 0, stdout: 'done\n' }]);
  let promptCount = 0;

  const session = sudo.createSudoSession({
    promptPassword: async () => {
      promptCount += 1;
      return 'unused';
    },
    isRoot: () => true,
    spawnCommand,
  });

  const result = await session.run(['/bin/echo', 'done']);

  assert.equal(result.code, 0);
  assert.equal(result.stdout, 'done\n');
  assert.equal(promptCount, 0);
  assert.deepEqual(
    calls.map((call) => [call.command, call.args]),
    [['/bin/echo', ['done']]],
  );
});

test('createSudoSession prime marks root sessions ready without invoking sudo', async () => {
  const sudo = await import(`${modulePath.href}?case=${Date.now()}-root-prime`);
  const { calls, spawnCommand } = createSpawnStub([{ code: 0 }]);
  let promptCount = 0;

  const session = sudo.createSudoSession({
    promptPassword: async () => {
      promptCount += 1;
      return 'unused';
    },
    isRoot: () => true,
    spawnCommand,
  });

  await session.prime();
  const result = await session.run(['/usr/bin/true']);

  assert.equal(result.code, 0);
  assert.equal(promptCount, 0);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], {
    command: '/usr/bin/true',
    args: [],
    options: {
      stdio: ['pipe', 'pipe', 'pipe'],
    },
    stdin: '',
  });
});

test('createSudoSession rewrites sudo authentication failures with a user-facing explanation', async () => {
  const sudo = await import(`${modulePath.href}?case=${Date.now()}-auth-failure`);
  const { spawnCommand } = createSpawnStub([
    { code: 1, stderr: 'Sorry, try again.\nsudo: no password was provided\n' },
  ]);

  const session = sudo.createSudoSession({
    promptPassword: async () => 'wrong-secret',
    isRoot: () => false,
    spawnCommand,
  });

  await assert.rejects(
    () => session.prime(),
    /sudo authentication failed\. Enter your system admin password used for sudo, not the AgentPay vault password\./,
  );
});

test('createSudoSession surfaces sudo credential check failures during priming', async () => {
  const sudo = await import(`${modulePath.href}?case=${Date.now()}-prime-failure`);
  const { spawnCommand } = createSpawnStub([{ code: 23, stderr: 'sudo: incorrect password\n' }]);

  const session = sudo.createSudoSession({
    promptPassword: async () => 'bad-secret',
    isRoot: () => false,
    spawnCommand,
  });

  await assert.rejects(
    () => session.prime(),
    /sudo authentication failed\. Enter your system admin password used for sudo, not the AgentPay vault password\./,
  );
});

test('createSudoSession prime falls back to stdout or exit-code messages when sudo emits no stderr', async () => {
  const sudo = await import(`${modulePath.href}?case=${Date.now()}-prime-failure-fallbacks`);

  {
    const { spawnCommand } = createSpawnStub([{ code: 23, stdout: 'stdout-only failure\n' }]);
    const session = sudo.createSudoSession({
      promptPassword: async () => 'bad-secret',
      isRoot: () => false,
      spawnCommand,
    });

    await assert.rejects(() => session.prime(), /stdout-only failure/);
  }

  {
    const { spawnCommand } = createSpawnStub([{ code: 23 }]);
    const session = sudo.createSudoSession({
      promptPassword: async () => 'bad-secret',
      isRoot: () => false,
      spawnCommand,
    });

    await assert.rejects(() => session.prime(), /sudo credential check failed \(exit code 23\)/);
  }

  {
    const { spawnCommand } = createSpawnStub([{ closeCode: null, signal: 'SIGTERM' }]);
    const session = sudo.createSudoSession({
      promptPassword: async () => 'bad-secret',
      isRoot: () => false,
      spawnCommand,
    });

    await assert.rejects(() => session.prime(), /sudo credential check failed \(exit code 143\)/);
  }
});

test('createSudoSession requires a command when running sudo', async () => {
  const sudo = await import(`${modulePath.href}?case=${Date.now()}-missing-command`);

  const session = sudo.createSudoSession({
    promptPassword: async () => 'unused',
    isRoot: () => false,
  });

  await assert.rejects(() => session.run([]), /sudo command arguments are required/);
});

test('createSudoSession can inherit child output and treats null close codes as failures', async () => {
  const sudo = await import(`${modulePath.href}?case=${Date.now()}-inherit-output`);
  const { spawnCommand } = createSpawnStub([
    { closeCode: null, stdout: 'visible-out\n', stderr: 'visible-err\n' },
  ]);
  let seenStdout = '';
  let seenStderr = '';

  const session = sudo.createSudoSession({
    promptPassword: async () => 'unused',
    isRoot: () => true,
    spawnCommand,
    stdout: {
      write(chunk) {
        seenStdout += chunk;
        return true;
      },
    },
    stderr: {
      write(chunk) {
        seenStderr += chunk;
        return true;
      },
    },
  });

  const result = await session.run(['/bin/echo', 'hello'], { inheritOutput: true });

  assert.equal(result.code, 1);
  assert.equal(result.stdout, 'visible-out\n');
  assert.equal(result.stderr, 'visible-err\n');
  assert.equal(seenStdout, 'visible-out\n');
  assert.equal(seenStderr, 'visible-err\n');
});

test('createSudoSession maps signaled child exits to shell-style exit codes', async () => {
  const sudo = await import(`${modulePath.href}?case=${Date.now()}-signal-close`);
  const { spawnCommand } = createSpawnStub([
    { closeCode: null, signal: 'SIGINT', stdout: 'visible-out\n', stderr: 'visible-err\n' },
  ]);

  const session = sudo.createSudoSession({
    promptPassword: async () => 'unused',
    isRoot: () => true,
    spawnCommand,
  });

  const result = await session.run(['/bin/echo', 'hello']);

  assert.equal(result.code, 130);
  assert.equal(result.stdout, 'visible-out\n');
  assert.equal(result.stderr, 'visible-err\n');
});

test('createSudoSession injects explicit environment assignments through sudo when requested', async () => {
  const sudo = await import(modulePath.href + `?case=${Date.now()}-sudo-env`);
  const { calls, spawnCommand } = createSpawnStub([
    { code: 0 },
    { code: 0, stdout: 'ok\n' },
  ]);

  const session = sudo.createSudoSession({
    promptPassword: async () => 'root-secret',
    isRoot: () => false,
    spawnCommand,
  });

  const result = await session.run(['/usr/bin/true'], {
    env: {
      AGENTPAY_RELAY_DAEMON_TOKEN: 'relay-secret',
    },
  });

  assert.equal(result.code, 0);
  assert.equal(result.stdout, 'ok\n');
  assert.deepEqual(
    calls.map((call) => [call.command, call.args]),
    [
      ['sudo', ['-S', '-p', '', '-v']],
      [
        'sudo',
        ['-n', '/usr/bin/env', 'AGENTPAY_RELAY_DAEMON_TOKEN=relay-secret', '/usr/bin/true'],
      ],
    ],
  );
});

test('createSudoSession retries on each recognized sudo authentication failure shape', async () => {
  const sudo = await import(`${modulePath.href}?case=${Date.now()}-auth-failure-shapes`);

  for (const message of [
    'sudo: incorrect password\n',
    'sudo: no password was provided\n',
    'Sorry, try again.\n',
  ]) {
    const { calls, spawnCommand } = createSpawnStub([
      { code: 0 },
      { code: 1, stderr: message },
      { code: 0 },
      { code: 0, stdout: 'ok\n' },
    ]);
    const session = sudo.createSudoSession({
      promptPassword: async () => 'root-secret',
      isRoot: () => false,
      spawnCommand,
    });

    const result = await session.run(['/usr/bin/true']);

    assert.equal(result.code, 0);
    assert.equal(result.stdout, 'ok\n');
    assert.equal(calls.length, 4);
  }
});

test('createSudoSession returns non-authentication sudo failures without retrying', async () => {
  const sudo = await import(`${modulePath.href}?case=${Date.now()}-non-auth-failure`);
  const { calls, spawnCommand } = createSpawnStub([
    { code: 0 },
    { code: 42, stderr: 'sudo: policy plugin failed\n' },
  ]);
  let promptCount = 0;

  const session = sudo.createSudoSession({
    promptPassword: async () => {
      promptCount += 1;
      return 'root-secret';
    },
    isRoot: () => false,
    spawnCommand,
  });

  const result = await session.run(['/usr/bin/true']);

  assert.equal(result.code, 42);
  assert.equal(result.stderr, 'sudo: policy plugin failed\n');
  assert.equal(promptCount, 1);
  assert.equal(calls.length, 2);
});

test('createSudoSession tolerates child stdin EPIPE when sudo exits before reading the password', async () => {
  const sudo = await import(`${modulePath.href}?case=${Date.now()}-stdin-epipe`);

  const session = sudo.createSudoSession({
    promptPassword: async () => 'root-secret',
    isRoot: () => false,
    spawnCommand: () => {
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
          child.emit('close', 0, null);
        });
      };
      return child;
    },
  });

  await session.prime();
  const result = await session.run(['/usr/bin/true']);

  assert.equal(result.code, 0);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
});

test('createSudoSession tolerates synchronous child stdin EPIPE throws when sudo exits before reading the password', async () => {
  const sudo = await import(`${modulePath.href}?case=${Date.now()}-stdin-sync-epipe`);

  const session = sudo.createSudoSession({
    promptPassword: async () => 'root-secret',
    isRoot: () => false,
    spawnCommand: () => {
      const child = new EventEmitter();
      child.stdout = new PassThrough();
      child.stderr = new PassThrough();
      child.stdin = new EventEmitter();
      child.stdin.end = () => {
        setImmediate(() => {
          child.emit('close', 0, null);
        });
        throw Object.assign(new Error('broken pipe'), {
          code: 'EPIPE',
        });
      };
      return child;
    },
  });

  await session.prime();
  const result = await session.run(['/usr/bin/true']);

  assert.equal(result.code, 0);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
});

test('createSudoSession tolerates late child stdin EPIPE after the end callback runs', async () => {
  const sudo = await import(`${modulePath.href}?case=${Date.now()}-stdin-late-epipe`);
  let spawnCount = 0;

  const session = sudo.createSudoSession({
    promptPassword: async () => 'root-secret',
    isRoot: () => false,
    spawnCommand: () => {
      spawnCount += 1;
      const child = new EventEmitter();
      child.stdout = new PassThrough();
      child.stderr = new PassThrough();
      child.stdin = new EventEmitter();
      if (spawnCount === 1) {
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
            child.emit('close', 0, null);
          });
        };
        return child;
      }

      child.stdin.end = (_input, callback) => {
        if (typeof callback === 'function') {
          callback();
        }
        setImmediate(() => {
          child.stdout.end();
          child.stderr.end();
          child.stdin.emit('close');
          child.emit('close', 0, null);
        });
      };
      return child;
    },
  });

  await session.prime();
  const result = await session.run(['/usr/bin/true']);

  assert.equal(result.code, 0);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
});

test('createSudoSession rejects child stdin errors other than EPIPE', async () => {
  const sudo = await import(`${modulePath.href}?case=${Date.now()}-stdin-error`);

  const session = sudo.createSudoSession({
    promptPassword: async () => 'root-secret',
    isRoot: () => false,
    spawnCommand: () => {
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
          child.emit('close', 0, null);
        });
      };
      return child;
    },
  });

  await assert.rejects(() => session.prime(), /stream reset/u);
});
