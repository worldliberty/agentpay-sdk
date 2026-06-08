import assert from 'node:assert/strict';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import test from 'node:test';

const modulePath = new URL('../src/lib/local-admin-access.ts', import.meta.url);

async function withMockedPrompt(answer, fn, options = {}) {
  const originalCreateInterface = readline.createInterface;
  const stdinDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
  const stdoutDescriptor = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
  const stderrDescriptor = Object.getOwnPropertyDescriptor(process.stderr, 'isTTY');
  const rawModeDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'setRawMode');
  const isRawDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'isRaw');
  Object.defineProperty(process.stdin, 'isTTY', { value: true, configurable: true });
  Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });
  Object.defineProperty(process.stderr, 'isTTY', { value: true, configurable: true });
  Object.defineProperty(process.stdin, 'isRaw', {
    value: false,
    writable: true,
    configurable: true,
  });
  Object.defineProperty(process.stdin, 'setRawMode', {
    value: (mode) => {
      process.stdin.isRaw = mode;
      if (mode) {
        process.nextTick(() => {
          process.stdin.emit('data', Buffer.from(answer, 'utf8'));
          process.stdin.emit('data', Buffer.from('\r', 'utf8'));
        });
      }
      return process.stdin;
    },
    configurable: true,
  });
  readline.createInterface = () => {
    const rl = {
      output: {
        write() {
          return true;
        },
      },
      question(query, callback) {
        options.onQuestion?.({ query, rl, writes: [] });
        callback(answer);
      },
      close() {},
    };
    return rl;
  };
  try {
    await fn({ writes: [] });
  } finally {
    readline.createInterface = originalCreateInterface;
    if (stdinDescriptor) {
      Object.defineProperty(process.stdin, 'isTTY', stdinDescriptor);
    } else {
      delete process.stdin.isTTY;
    }
    if (stdoutDescriptor) {
      Object.defineProperty(process.stdout, 'isTTY', stdoutDescriptor);
    } else {
      delete process.stdout.isTTY;
    }
    if (stderrDescriptor) {
      Object.defineProperty(process.stderr, 'isTTY', stderrDescriptor);
    } else {
      delete process.stderr.isTTY;
    }
    if (rawModeDescriptor) {
      Object.defineProperty(process.stdin, 'setRawMode', rawModeDescriptor);
    } else {
      delete process.stdin.setRawMode;
    }
    if (isRawDescriptor) {
      Object.defineProperty(process.stdin, 'isRaw', isRawDescriptor);
    } else {
      delete process.stdin.isRaw;
    }
  }
}

async function withMockedSudoOnPath(scriptBody, fn) {
  const originalPath = process.env.PATH;
  const tempDir = await mkdtemp(path.join(os.tmpdir(), 'agentpay-local-admin-sudo-'));
  const sudoPath = path.join(tempDir, 'sudo');
  await writeFile(sudoPath, scriptBody);
  await chmod(sudoPath, 0o755);
  process.env.PATH = `${tempDir}${path.delimiter}${originalPath ?? ''}`;
  try {
    await fn();
  } finally {
    if (originalPath === undefined) {
      delete process.env.PATH;
    } else {
      process.env.PATH = originalPath;
    }
    await rm(tempDir, { recursive: true, force: true });
  }
}

test('requireLocalAdminMutationAccess bypasses sudo validation for non-sudo root processes', async () => {
  const access = await import(`${modulePath.href}?case=${Date.now()}-root-bypass`);
  let ensured = false;

  await access.requireLocalAdminMutationAccess('agentpay admin token set-chain', {
    isRoot: () => true,
    isSudoWrappedInvocation: () => false,
    ensureRootAccess: async () => {
      ensured = true;
    },
  });

  assert.equal(ensured, false);
});

test('requireLocalAdminMutationAccess rejects sudo-wrapped root invocations before mutating config', async () => {
  const access = await import(`${modulePath.href}?case=${Date.now()}-sudo-wrapped-root`);
  let ensured = false;

  await assert.rejects(
    () =>
      access.requireLocalAdminMutationAccess('agentpay admin token set-chain', {
        isRoot: () => true,
        isSudoWrappedInvocation: () => true,
        ensureRootAccess: async () => {
          ensured = true;
        },
      }),
    /run `agentpay admin token set-chain` as your normal local user, not with sudo; the CLI prompts for sudo internally and running it as root can target the wrong local AgentPay home/,
  );

  assert.equal(ensured, false);
});

test('requireLocalAdminMutationAccess uses the default root detector when deps omit isRoot', async () => {
  const access = await import(`${modulePath.href}?case=${Date.now()}-default-root-detector`);
  const geteuidDescriptor = Object.getOwnPropertyDescriptor(process, 'geteuid');
  const originalSudoUid = process.env.SUDO_UID;

  Object.defineProperty(process, 'geteuid', {
    value: () => 0,
    configurable: true,
  });
  delete process.env.SUDO_UID;

  try {
    await assert.doesNotReject(() =>
      access.requireLocalAdminMutationAccess('agentpay admin token set-chain', {
        ensureRootAccess: async () => {
          throw new Error('should not run');
        },
      }),
    );
  } finally {
    if (originalSudoUid === undefined) {
      delete process.env.SUDO_UID;
    } else {
      process.env.SUDO_UID = originalSudoUid;
    }
    if (geteuidDescriptor) {
      Object.defineProperty(process, 'geteuid', geteuidDescriptor);
    } else {
      delete process.geteuid;
    }
  }
});

test('requireLocalAdminMutationAccess uses the default sudo detector to reject sudo-wrapped invocations', async () => {
  const access = await import(`${modulePath.href}?case=${Date.now()}-default-sudo-detector`);
  const geteuidDescriptor = Object.getOwnPropertyDescriptor(process, 'geteuid');
  const originalSudoUid = process.env.SUDO_UID;

  Object.defineProperty(process, 'geteuid', {
    value: () => 0,
    configurable: true,
  });
  process.env.SUDO_UID = '501';

  try {
    await assert.rejects(
      () =>
        access.requireLocalAdminMutationAccess('agentpay admin token set-chain', {
          ensureRootAccess: async () => {
            throw new Error('should not run');
          },
        }),
      /run `agentpay admin token set-chain` as your normal local user, not with sudo; the CLI prompts for sudo internally and running it as root can target the wrong local AgentPay home/,
    );
  } finally {
    if (originalSudoUid === undefined) {
      delete process.env.SUDO_UID;
    } else {
      process.env.SUDO_UID = originalSudoUid;
    }
    if (geteuidDescriptor) {
      Object.defineProperty(process, 'geteuid', geteuidDescriptor);
    } else {
      delete process.geteuid;
    }
  }
});

test('requireLocalAdminMutationAccess validates root access for non-root processes', async () => {
  const access = await import(`${modulePath.href}?case=${Date.now()}-validate-root`);
  let ensured = false;

  await access.requireLocalAdminMutationAccess('agentpay admin chain add', {
    isRoot: () => false,
    ensureRootAccess: async () => {
      ensured = true;
    },
  });

  assert.equal(ensured, true);
});

test('requireLocalAdminMutationAccess rewrites sudo failures with the command label', async () => {
  const access = await import(`${modulePath.href}?case=${Date.now()}-rewrite-error`);

  await assert.rejects(
    () =>
      access.requireLocalAdminMutationAccess('agentpay admin token remove', {
        isRoot: () => false,
        ensureRootAccess: async () => {
          throw new Error('Local admin password for sudo is required; rerun on a local TTY');
        },
      }),
    /agentpay admin token remove requires verified root access before local admin configuration can change: Local admin password for sudo is required; rerun on a local TTY/,
  );
});

test('requireLocalAdminMutationAccess rewrites non-Error sudo failures with the command label', async () => {
  const access = await import(`${modulePath.href}?case=${Date.now()}-rewrite-non-error`);

  await assert.rejects(
    () =>
      access.requireLocalAdminMutationAccess('agentpay admin token remove', {
        isRoot: () => false,
        ensureRootAccess: async () => {
          throw 'plain failure';
        },
      }),
    /agentpay admin token remove requires verified root access before local admin configuration can change: plain failure/,
  );
});

test('withLocalAdminMutationAccess executes the wrapped action after root validation', async () => {
  const access = await import(`${modulePath.href}?case=${Date.now()}-wrap-success`);
  const seen = [];

  const wrapped = access.withLocalAdminMutationAccess(
    'agentpay admin chain switch',
    async (selector, options) => {
      seen.push(['action', selector, options]);
      return { selector, saved: Boolean(options.save) };
    },
    {
      isRoot: () => false,
      ensureRootAccess: async () => {
        seen.push(['auth']);
      },
    },
  );

  const result = await wrapped('eth', { save: true });

  assert.deepEqual(seen, [['auth'], ['action', 'eth', { save: true }]]);
  assert.deepEqual(result, { selector: 'eth', saved: true });
});

test('withLocalAdminMutationAccess blocks the wrapped action when root validation fails', async () => {
  const access = await import(`${modulePath.href}?case=${Date.now()}-wrap-failure`);
  let actionRan = false;

  const wrapped = access.withLocalAdminMutationAccess(
    'agentpay admin token set-chain',
    async () => {
      actionRan = true;
    },
    {
      isRoot: () => false,
      ensureRootAccess: async () => {
        throw new Error('sudo credential check failed');
      },
    },
  );

  await assert.rejects(
    () => wrapped('usd1', 'eth', {}),
    /agentpay admin token set-chain requires verified root access before local admin configuration can change: sudo credential check failed/,
  );
  assert.equal(actionRan, false);
});

test('withDynamicLocalAdminMutationAccess resolves the command label from runtime arguments', async () => {
  const access = await import(`${modulePath.href}?case=${Date.now()}-dynamic-success`);
  const seen = [];

  const wrapped = access.withDynamicLocalAdminMutationAccess(
    (key, value) => `agentpay config set ${key}=${value}`,
    async (key, value) => {
      seen.push(['action', key, value]);
      return `${key}:${value}`;
    },
    {
      isRoot: () => false,
      ensureRootAccess: async () => {
        seen.push(['auth']);
      },
    },
  );

  const result = await wrapped('rpcUrl', 'https://rpc.example');

  assert.deepEqual(seen, [['auth'], ['action', 'rpcUrl', 'https://rpc.example']]);
  assert.equal(result, 'rpcUrl:https://rpc.example');
});

test('withDynamicLocalAdminMutationAccess uses the resolved label in access failures', async () => {
  const access = await import(`${modulePath.href}?case=${Date.now()}-dynamic-failure`);
  let actionRan = false;

  const wrapped = access.withDynamicLocalAdminMutationAccess(
    (subcommand) => `agentpay config agent-auth ${subcommand}`,
    async () => {
      actionRan = true;
    },
    {
      isRoot: () => false,
      ensureRootAccess: async () => {
        throw new Error('Local admin password for sudo is required; rerun on a local TTY');
      },
    },
  );

  await assert.rejects(
    () => wrapped('clear'),
    /agentpay config agent-auth clear requires verified root access before local admin configuration can change: Local admin password for sudo is required; rerun on a local TTY/,
  );
  assert.equal(actionRan, false);
});

test('requireLocalAdminMutationAccess fails closed without a local TTY when sudo prompt is required', async () => {
  const access = await import(`${modulePath.href}?case=${Date.now()}-default-sudo-no-tty`);
  const stdinDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
  const stdoutDescriptor = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
  Object.defineProperty(process.stdin, 'isTTY', { value: false, configurable: true });
  Object.defineProperty(process.stdout, 'isTTY', { value: false, configurable: true });
  try {
    await assert.rejects(
      () =>
        access.requireLocalAdminMutationAccess('agentpay admin chain add', { isRoot: () => false }),
      /agentpay admin chain add requires verified root access before local admin configuration can change: Local admin password for sudo is required; rerun on a local TTY/,
    );
  } finally {
    if (stdinDescriptor) {
      Object.defineProperty(process.stdin, 'isTTY', stdinDescriptor);
    } else {
      delete process.stdin.isTTY;
    }
    if (stdoutDescriptor) {
      Object.defineProperty(process.stdout, 'isTTY', stdoutDescriptor);
    } else {
      delete process.stdout.isTTY;
    }
  }
});

test('requireLocalAdminMutationAccess rejects whitespace-only root passwords during hidden prompt validation', async () => {
  const access = await import(`${modulePath.href}?case=${Date.now()}-default-sudo-empty-password`);
  await withMockedPrompt('   ', async () => {
    await assert.rejects(
      () =>
        access.requireLocalAdminMutationAccess('agentpay admin token remove', {
          isRoot: () => false,
        }),
      /agentpay admin token remove requires verified root access before local admin configuration can change: Local admin password for sudo must not be empty or whitespace/,
    );
  });
});

test('requireLocalAdminMutationAccess rejects oversized hidden sudo prompt secrets', async () => {
  const access = await import(
    `${modulePath.href}?case=${Date.now()}-default-sudo-oversized-password`
  );
  const oversized = 'x'.repeat(16 * 1024 + 1);
  await withMockedPrompt(oversized, async () => {
    await assert.rejects(
      () =>
        access.requireLocalAdminMutationAccess('agentpay admin token set-chain', {
          isRoot: () => false,
        }),
      /agentpay admin token set-chain requires verified root access before local admin configuration can change: Local admin password for sudo must not exceed 16384 bytes/,
    );
  });
});

test('requireLocalAdminMutationAccess accepts a valid hidden prompt without echoing the sudo password', async () => {
  await withMockedSudoOnPath('#!/bin/sh\ncat >/dev/null\nexit 0\n', async () => {
    const access = await import(`${modulePath.href}?case=${Date.now()}-default-sudo-success`);
    let rendered = '';
    const originalStderrWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk, ...args) => {
      rendered += String(chunk);
      return originalStderrWrite(chunk, ...args);
    };

    try {
      await withMockedPrompt('root-secret', async () => {
        await access.requireLocalAdminMutationAccess('agentpay admin chain add', {
          isRoot: () => false,
        });
      });
    } finally {
      process.stderr.write = originalStderrWrite;
    }

    assert.doesNotMatch(rendered, /root-secret/u);
    assert.match(
      rendered,
      /Local admin password for sudo \(input hidden; required to change local admin chain and token configuration\): /u,
    );
    assert.match(rendered, /\n/u);
  });
});
