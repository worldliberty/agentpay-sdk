import assert from 'node:assert/strict';
import test from 'node:test';

const modulePath = new URL('../src/lib/admin-guard.ts', import.meta.url);

function loadModule(caseId) {
  return import(modulePath.href + `?case=${caseId}`);
}

async function withMockedProcessUidFns({ geteuid, getuid }, fn) {
  const geteuidDescriptor = Object.getOwnPropertyDescriptor(process, 'geteuid');
  const getuidDescriptor = Object.getOwnPropertyDescriptor(process, 'getuid');

  if (geteuidDescriptor?.configurable ?? true) {
    Object.defineProperty(process, 'geteuid', { value: geteuid, configurable: true });
  }
  if (getuidDescriptor?.configurable ?? true) {
    Object.defineProperty(process, 'getuid', { value: getuid, configurable: true });
  }

  try {
    await fn();
  } finally {
    if (geteuidDescriptor) {
      Object.defineProperty(process, 'geteuid', geteuidDescriptor);
    } else {
      delete process.geteuid;
    }
    if (getuidDescriptor) {
      Object.defineProperty(process, 'getuid', getuidDescriptor);
    } else {
      delete process.getuid;
    }
  }
}

async function withMockedTty(stdinIsTTY, stderrIsTTY, fn) {
  const stdinDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
  const stderrDescriptor = Object.getOwnPropertyDescriptor(process.stderr, 'isTTY');
  Object.defineProperty(process.stdin, 'isTTY', { value: stdinIsTTY, configurable: true });
  Object.defineProperty(process.stderr, 'isTTY', { value: stderrIsTTY, configurable: true });
  try {
    await fn();
  } finally {
    if (stdinDescriptor) {
      Object.defineProperty(process.stdin, 'isTTY', stdinDescriptor);
    } else {
      delete process.stdin.isTTY;
    }
    if (stderrDescriptor) {
      Object.defineProperty(process.stderr, 'isTTY', stderrDescriptor);
    } else {
      delete process.stderr.isTTY;
    }
  }
}

test('forwardedArgsSkipAdminAccessGuard skips help and version invocations only', async () => {
  const adminGuard = await loadModule(`${Date.now()}-skip`);

  assert.equal(adminGuard.forwardedArgsSkipAdminAccessGuard([]), false);
  assert.equal(adminGuard.forwardedArgsSkipAdminAccessGuard(['help']), true);
  assert.equal(adminGuard.forwardedArgsSkipAdminAccessGuard(['--help']), true);
  assert.equal(adminGuard.forwardedArgsSkipAdminAccessGuard(['bootstrap', '-h']), true);
  assert.equal(adminGuard.forwardedArgsSkipAdminAccessGuard(['--version']), true);
  assert.equal(adminGuard.forwardedArgsSkipAdminAccessGuard(['bootstrap']), false);
  assert.equal(adminGuard.forwardedArgsSkipAdminAccessGuard(['bootstrap', 'help']), false);
  assert.equal(adminGuard.forwardedArgsSkipAdminAccessGuard(['bootstrap', '--', '--help']), false);
});

test('assertAdminAccessPreconditions allows non-admin binaries without a password source', async () => {
  const adminGuard = await loadModule(`${Date.now()}-non-admin`);

  assert.doesNotThrow(() =>
    adminGuard.assertAdminAccessPreconditions('agentpay-agent', ['broadcast'], {
      env: {},
      getEffectiveUid: () => 501,
      stdinIsTty: false,
      stderrIsTty: false,
    }),
  );
});

test('assertAdminAccessPreconditions still requires a password source or tty when running as root', async () => {
  const adminGuard = await loadModule(`${Date.now()}-root`);

  assert.throws(
    () =>
      adminGuard.assertAdminAccessPreconditions('agentpay-admin', ['bootstrap'], {
        env: {},
        getEffectiveUid: () => 0,
        stdinIsTty: false,
        stderrIsTty: false,
      }),
    /require --vault-password-stdin or a local TTY/,
  );

  assert.doesNotThrow(() =>
    adminGuard.assertAdminAccessPreconditions('agentpay-admin', ['bootstrap'], {
      env: {},
      getEffectiveUid: () => 0,
      stdinIsTty: true,
      stderrIsTty: true,
    }),
  );
});

test('assertAdminAccessPreconditions allows stdin password relay', async () => {
  const adminGuard = await loadModule(`${Date.now()}-password-sources`);

  assert.doesNotThrow(() =>
    adminGuard.assertAdminAccessPreconditions(
      'agentpay-admin',
      ['bootstrap', '--vault-password-stdin'],
      {
        env: {},
        getEffectiveUid: () => 501,
        stdinIsTty: false,
        stderrIsTty: false,
      },
    ),
  );
});

test('assertAdminAccessPreconditions rejects insecure argv and env password sources', async () => {
  const adminGuard = await loadModule(`${Date.now()}-reject-insecure-password-sources`);

  assert.throws(
    () =>
      adminGuard.assertAdminAccessPreconditions(
        'agentpay-admin',
        ['bootstrap', '--vault-password=secret'],
        {
          env: {},
          getEffectiveUid: () => 501,
          stdinIsTty: false,
          stderrIsTty: false,
        },
      ),
    /insecure --vault-password is disabled/,
  );

  assert.throws(
    () =>
      adminGuard.assertAdminAccessPreconditions('agentpay-admin', ['bootstrap'], {
        env: { AGENTPAY_VAULT_PASSWORD: 'secret' },
        getEffectiveUid: () => 501,
        stdinIsTty: false,
        stderrIsTty: false,
      }),
    /AGENTPAY_VAULT_PASSWORD is disabled for security/,
  );
});

test('resolveAdminAccess falls back to process.getuid and then null when euid helpers are unavailable', async () => {
  const adminGuard = await loadModule(`${Date.now()}-uid-fallback`);

  await withMockedProcessUidFns(
    {
      geteuid: undefined,
      getuid: () => 0,
    },
    async () => {
      const access = adminGuard.resolveAdminAccess(
        'agentpay-admin',
        ['bootstrap', '--vault-password-stdin'],
        {
          env: {},
          stdinIsTty: false,
          stderrIsTty: false,
        },
      );
      assert.equal(access.runningAsRoot, true);
    },
  );

  await withMockedProcessUidFns(
    {
      geteuid: undefined,
      getuid: undefined,
    },
    async () => {
      const access = adminGuard.resolveAdminAccess(
        'agentpay-admin',
        ['bootstrap', '--vault-password-stdin'],
        {
          env: {},
          stdinIsTty: false,
          stderrIsTty: false,
        },
      );
      assert.equal(access.runningAsRoot, false);
    },
  );
});

test('resolveAdminAccess rejects split vault password options without a usable value', async () => {
  const adminGuard = await loadModule(`${Date.now()}-split-password-value`);

  assert.throws(
    () =>
      adminGuard.resolveAdminAccess(
        'agentpay-admin',
        ['bootstrap', '--vault-password', '-secret'],
        {
          env: {},
          getEffectiveUid: () => 501,
          stdinIsTty: false,
          stderrIsTty: false,
        },
      ),
    /--vault-password requires a value/,
  );
});

test('resolveAdminAccess treats split vault password values as insecure when they are present', async () => {
  const adminGuard = await loadModule(`${Date.now()}-split-password-present`);

  const access = adminGuard.resolveAdminAccess(
    'agentpay-admin',
    ['bootstrap', '--vault-password', 'secret'],
    {
      env: {},
      getEffectiveUid: () => 501,
      stdinIsTty: false,
      stderrIsTty: false,
    },
  );

  assert.equal(access.permitted, false);
  assert.equal(access.mode, 'blocked');
  assert.match(access.reason, /insecure --vault-password is disabled/);
});

test('resolveAdminAccess uses default env and tty deps when explicit overrides are omitted', async () => {
  const adminGuard = await loadModule(`${Date.now()}-default-env-tty`);
  const originalEnv = process.env.AGENTPAY_VAULT_PASSWORD;

  process.env.AGENTPAY_VAULT_PASSWORD = 'from-env';
  await withMockedProcessUidFns(
    {
      geteuid: () => 0,
      getuid: () => 501,
    },
    async () => {
      await withMockedTty(true, false, async () => {
        const access = adminGuard.resolveAdminAccess('agentpay-admin', ['bootstrap']);
        assert.equal(access.runningAsRoot, true);
        assert.equal(access.canPromptSecurely, false);
        assert.equal(access.hasVaultPasswordSource, true);
        assert.equal(access.permitted, false);
        assert.match(access.reason, /AGENTPAY_VAULT_PASSWORD is disabled/);
      });
    },
  );

  if (originalEnv === undefined) {
    delete process.env.AGENTPAY_VAULT_PASSWORD;
  } else {
    process.env.AGENTPAY_VAULT_PASSWORD = originalEnv;
  }
});

test('assertAdminAccessPreconditions allows interactive admin terminals', async () => {
  const adminGuard = await loadModule(`${Date.now()}-tty`);

  assert.doesNotThrow(() =>
    adminGuard.assertAdminAccessPreconditions('agentpay-admin', ['bootstrap'], {
      env: {},
      getEffectiveUid: () => 501,
      stdinIsTty: true,
      stderrIsTty: true,
    }),
  );
});

test('resolveAdminAccess reports interactive prompting only when prompts are allowed', async () => {
  const adminGuard = await loadModule(`${Date.now()}-resolve-interactive`);

  const interactive = adminGuard.resolveAdminAccess('agentpay-admin', ['bootstrap'], {
    env: {},
    getEffectiveUid: () => 501,
    stdinIsTty: true,
    stderrIsTty: true,
  });
  assert.equal(interactive.permitted, true);
  assert.equal(interactive.mode, 'interactive-prompt');

  const nonInteractive = adminGuard.resolveAdminAccess(
    'agentpay-admin',
    ['bootstrap', '--non-interactive'],
    {
      env: {},
      getEffectiveUid: () => 501,
      stdinIsTty: true,
      stderrIsTty: true,
    },
  );
  assert.equal(nonInteractive.permitted, false);
  assert.equal(nonInteractive.mode, 'blocked');
  assert.match(nonInteractive.reason, /vault password is required in non-interactive mode/);
});

test('assertAdminAccessPreconditions rejects non-root non-interactive admin invocations without a password source', async () => {
  const adminGuard = await loadModule(`${Date.now()}-reject`);

  assert.throws(
    () =>
      adminGuard.assertAdminAccessPreconditions('agentpay-admin', ['bootstrap'], {
        env: {},
        getEffectiveUid: () => 501,
        stdinIsTty: false,
        stderrIsTty: false,
      }),
    /require --vault-password-stdin or a local TTY/,
  );
});

test('assertAdminAccessPreconditions rejects tty admin invocations when --non-interactive omits a password source', async () => {
  const adminGuard = await loadModule(`${Date.now()}-reject-non-interactive-tty`);

  assert.throws(
    () =>
      adminGuard.assertAdminAccessPreconditions(
        'agentpay-admin',
        ['bootstrap', '--non-interactive'],
        {
          env: {},
          getEffectiveUid: () => 501,
          stdinIsTty: true,
          stderrIsTty: true,
        },
      ),
    /use --vault-password-stdin/,
  );
});

test('assertAdminAccessPreconditions rejects root non-interactive admin invocations without a password source', async () => {
  const adminGuard = await loadModule(`${Date.now()}-reject-root-non-interactive`);

  assert.throws(
    () =>
      adminGuard.assertAdminAccessPreconditions(
        'agentpay-admin',
        ['bootstrap', '--non-interactive'],
        {
          env: {},
          getEffectiveUid: () => 0,
          stdinIsTty: true,
          stderrIsTty: true,
        },
      ),
    /use --vault-password-stdin/,
  );
});

test('resolveAdminAccess ignores password and non-interactive markers after option terminator', async () => {
  const adminGuard = await loadModule(`${Date.now()}-option-terminator`);

  const access = adminGuard.resolveAdminAccess(
    'agentpay-admin',
    ['bootstrap', '--', '--vault-password=secret', '--vault-password-stdin', '--non-interactive'],
    {
      env: {},
      getEffectiveUid: () => 501,
      stdinIsTty: true,
      stderrIsTty: true,
    },
  );

  assert.equal(access.permitted, true);
  assert.equal(access.mode, 'interactive-prompt');
  assert.equal(access.hasVaultPasswordSource, false);
  assert.equal(access.nonInteractive, false);
});

test('resolveAdminAccess blocks password markers placed after option terminator without a tty', async () => {
  const adminGuard = await loadModule(`${Date.now()}-option-terminator-blocked`);

  const access = adminGuard.resolveAdminAccess(
    'agentpay-admin',
    ['bootstrap', '--', '--vault-password=secret'],
    {
      env: {},
      getEffectiveUid: () => 501,
      stdinIsTty: false,
      stderrIsTty: false,
    },
  );

  assert.equal(access.permitted, false);
  assert.equal(access.mode, 'blocked');
  assert.match(access.reason, /require --vault-password-stdin or a local TTY/);
});
