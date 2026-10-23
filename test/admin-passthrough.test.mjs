import assert from 'node:assert/strict';
import test from 'node:test';

const modulePath = new URL('../src/lib/admin-passthrough.ts', import.meta.url);

function loadModule(caseId) {
  return import(`${modulePath.href}?case=${caseId}`);
}

test('blockedRawAdminPassthroughMessage redirects rotate-agent-auth-token to the safe wrapper', async () => {
  const passthrough = await loadModule(`${Date.now()}-rotate`);

  assert.match(
    passthrough.blockedRawAdminPassthroughMessage('rotate-agent-auth-token') ?? '',
    /use `agentpay config agent-auth rotate` so the rotated token is stored in the local credential store/,
  );
});

test('blockedRawAdminPassthroughMessage redirects revoke-agent-key to the safe wrapper', async () => {
  const passthrough = await loadModule(`${Date.now()}-revoke`);

  assert.match(
    passthrough.blockedRawAdminPassthroughMessage('revoke-agent-key') ?? '',
    /use `agentpay config agent-auth revoke` so local credentials are removed safely/,
  );
});

test('rewriteAdminHelpText removes raw bootstrap and agent token management passthrough entries', async () => {
  const passthrough = await loadModule(`${Date.now()}-help`);

  const rendered =
    passthrough.rewriteAdminHelpText(`Admin CLI for configuring vault policies and agent keys
  bootstrap                       Create spending policies and issue a vault key + agent key
  rotate-agent-auth-token         Rotate the bearer token for an existing agent key
  revoke-agent-key                Revoke an existing agent key and invalidate its bearer token
  help                            Print this message or the help of the given subcommand(s)
`);

  assert.doesNotMatch(rendered, /\bbootstrap\b/);
  assert.doesNotMatch(rendered, /rotate-agent-auth-token/);
  assert.doesNotMatch(rendered, /revoke-agent-key/);
  assert.match(
    rendered,
    /Admin CLI for configuring daemon setup, policies, chains, tokens, and agent keys/,
  );
});

const TS_OWNED_NAMES = [
  'setup',
  'tui',
  'reset',
  'uninstall',
  'wallet-backup',
  'resume-manual-approval-request',
  'chain',
  'token',
  'daemon',
];

test('rewriteAdminHelpText lists every TypeScript-owned admin subcommand exactly once', async () => {
  const passthrough = await loadModule(`${Date.now()}-help-table`);

  assert.deepEqual(
    passthrough.TS_OWNED_ADMIN_SUBCOMMANDS.map((entry) => entry.name),
    TS_OWNED_NAMES,
  );

  const rustHelp = `Admin CLI for configuring vault policies and agent keys

Usage: agentpay-admin [OPTIONS] <COMMAND>

Commands:
  bootstrap                        Create spending policies and issue a vault key + agent key
  tui                              Launch interactive terminal UI for bootstrap configuration
  list-policies                    List policies
  reset                            Remove the managed daemon state and local wallet credentials
  help                             Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
`;

  for (const input of [rustHelp, rustHelp.replace(/^ {2}help .*\n/mu, ''), '']) {
    const rendered = passthrough.rewriteAdminHelpText(input);
    for (const name of TS_OWNED_NAMES) {
      const rows = rendered
        .split('\n')
        .filter((line) => new RegExp(`^\\s{2,}${name}\\s`, 'u').test(line));
      assert.equal(rows.length, 1, `expected exactly one '${name}' row in:\n${rendered}`);
    }
    assert.doesNotMatch(rendered, /^\s+bootstrap\s/mu);
  }

  const rendered = passthrough.rewriteAdminHelpText(rustHelp);
  assert.match(rendered, /^\s+list-policies\s/mu);
  assert.ok(rendered.indexOf('  setup ') < rendered.indexOf('  help '));
});

test('parseNestedAdminCommand handles help and usage errors without exiting the process', async () => {
  const passthrough = await loadModule(`${Date.now()}-nested-parse`);
  const { Command } = await import('commander');

  const buildProgram = () => {
    const program = new Command('chain');
    program.configureOutput({ writeOut: () => {}, writeErr: () => {} });
    program
      .command('add')
      .requiredOption('--name <value>')
      .action(() => {});
    return program;
  };

  const originalExit = process.exit;
  process.exit = (code) => {
    throw new Error(`process.exit(${code}) must not be called`);
  };
  try {
    process.exitCode = undefined;
    await passthrough.parseNestedAdminCommand(buildProgram(), ['--help']);
    assert.equal(process.exitCode, undefined);

    await passthrough.parseNestedAdminCommand(buildProgram(), ['add', '--help']);
    assert.equal(process.exitCode, undefined);

    // Subcommands built before the override must not exit the process on usage errors.
    await passthrough.parseNestedAdminCommand(buildProgram(), ['add']);
    assert.equal(process.exitCode, 1);
  } finally {
    process.exit = originalExit;
    process.exitCode = undefined;
  }

  await assert.rejects(() => {
    const program = new Command('boom');
    program.action(() => {
      throw new Error('action failed');
    });
    return passthrough.parseNestedAdminCommand(program, []);
  }, /action failed/u);
});
