import assert from 'node:assert/strict';
import test from 'node:test';

const modulePath = new URL('../src/lib/telemetry-agent-command.ts', import.meta.url);

async function loadModule(caseSuffix) {
  return await import(`${modulePath.href}?case=${caseSuffix}-${Date.now()}`);
}

test('describeAgentCommand ignores subcommands that cannot move a balance', async () => {
  const { describeAgentCommand } = await loadModule('untracked');

  assert.equal(
    describeAgentCommand(['eip712-typed-data', '--typed-data-json', '{}'], 'success'),
    undefined,
  );
});

test('describeAgentCommand reads the action, chain, and amount from argv', async () => {
  const { describeAgentCommand } = await loadModule('argv');

  const event = describeAgentCommand(
    ['transfer', '--network', '56', '--token', '0xabc', '--to', '0xdef', '--amount-wei', '2500000'],
    'success',
    { assetDecimals: 6, assetSymbol: 'USD1' },
  );

  assert.equal(event.action, 'transfer');
  assert.equal(event.chainId, 56);
  assert.equal(event.asset, 'USD1');
  assert.equal(event.amount, 2.5);
  assert.equal(event.broadcast, false);
  assert.equal(event.result, 'success');
});

test('describeAgentCommand prefers an explicit amount over zero-valued calldata', async () => {
  const { describeAgentCommand } = await loadModule('erc20-broadcast');

  // An ERC-20 broadcast carries its amount in calldata and passes `--value-wei 0`.
  const event = describeAgentCommand(
    ['broadcast', '--network', '56', '--value-wei', '0', '--data-hex', '0xa9059cbb'],
    'awaiting_approval',
    { amountWei: 5_000_000n, assetDecimals: 6, assetSymbol: 'USD1', broadcast: true },
  );

  assert.equal(event.action, 'broadcast');
  assert.equal(event.amount, 5);
  assert.equal(event.broadcast, true);
  assert.equal(event.result, 'awaiting_approval');
});

test('describeAgentCommand tracks the real rust subcommand names for solana and payment flows', async () => {
  const { describeAgentCommand } = await loadModule('real-subcommands');

  // These are the names actually passed to agentpay-agent; earlier guesses like 'transfer-sol'
  // never matched, so those flows emitted nothing at all.
  const cases = [
    ['solana-sol-transfer', 'transfer_sol'],
    ['solana-spl-transfer', 'transfer_spl'],
    ['eip3009-transfer-with-authorization', 'x402'],
    ['tempo-session-open-transaction', 'mpp'],
    ['tempo-session-top-up-transaction', 'mpp'],
    ['tempo-session-voucher', 'mpp'],
    ['shield', 'shield'],
    ['unshield', 'unshield'],
    ['private-transfer', 'private_transfer'],
  ];

  for (const [subcommand, expected] of cases) {
    const event = describeAgentCommand([subcommand, '--network', '1'], 'success');
    assert.ok(event, `${subcommand} should be tracked`);
    assert.equal(event.action, expected);
  }
});

test('describeAgentCommand omits the amount when decimals are unknown', async () => {
  const { describeAgentCommand } = await loadModule('no-decimals');

  const event = describeAgentCommand(
    ['transfer-native', '--network', '1', '--amount-wei', '1000'],
    'failed',
  );

  assert.equal(event.action, 'transfer_native');
  assert.equal(event.amount, undefined);
  assert.equal(event.result, 'failed');
});

test('the top-level command names a failure signed through the generic broadcast subcommand', async () => {
  const { describeAgentCommand, setTelemetryCommandContext } = await loadModule('command-context');

  // `transfer --broadcast` signs via `broadcast`; without the context its failures were counted
  // under `broadcast` while its successes were recorded by the caller under `transfer`.
  setTelemetryCommandContext(['transfer']);
  const failed = describeAgentCommand(
    ['broadcast', '--network', '56', '--value-wei', '0', '--data-hex', '0xa9059cbb'],
    'failed',
    { amountWei: 5_000_000n, assetDecimals: 6, assetSymbol: 'USD1', broadcast: true },
  );
  assert.equal(failed.action, 'transfer');
  assert.equal(failed.result, 'failed');
  assert.equal(failed.amount, 5);

  setTelemetryCommandContext(['transfer-native']);
  assert.equal(
    describeAgentCommand(['broadcast', '--network', '1', '--value-wei', '10'], 'failed').action,
    'transfer_native',
  );
});

test('the top-level command relabels but never creates a balance mutation', async () => {
  const { describeAgentCommand, setTelemetryCommandContext } = await loadModule('no-create');

  // A read-only signing step inside `mpp` must not become a mutation just because the command is.
  setTelemetryCommandContext(['mpp']);
  assert.equal(
    describeAgentCommand(['eip712-typed-data', '--typed-data-json', '{}'], 'success'),
    undefined,
  );
  assert.equal(
    describeAgentCommand(['tempo-session-voucher', '--network', '1'], 'success').action,
    'mpp',
  );
});

test('unknown or absent top-level commands fall back to the rust subcommand', async () => {
  const { describeAgentCommand, setTelemetryCommandContext } = await loadModule('fallback');

  assert.equal(describeAgentCommand(['broadcast', '--network', '1'], 'failed').action, 'broadcast');

  setTelemetryCommandContext(['tx', 'broadcast']);
  assert.equal(describeAgentCommand(['broadcast', '--network', '1'], 'failed').action, 'broadcast');

  setTelemetryCommandContext([]);
  assert.equal(describeAgentCommand(['approve', '--network', '1'], 'success').action, 'approve');
});
