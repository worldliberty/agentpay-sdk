import test from 'node:test';
import assert from 'node:assert/strict';

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

  const rendered = passthrough.rewriteAdminHelpText(`Admin CLI for configuring vault policies and agent keys
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
