import { afterEach, describe, expect, it } from 'vitest';
import { createSudoRelay, RELAYED_METHODS } from '../src/auth/privileged.js';
import type { CommandRunner } from '../src/auth/process.js';
import { parseRelayRequest } from '../src/commands/privileged.js';
import { SignerCallError, UsageError } from '../src/errors.js';
import { runCli } from '../src/program.js';
import { AGENT_KEY_ID, type TestContext, testContext } from './helpers/context.js';
import { body, fail, type Handler, ok } from './helpers/fake-daemon.js';
import { fixture } from './helpers/fixtures.js';
import { fakeIo } from './helpers/io.js';

const APPROVAL_ID = 'e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090';
let t: TestContext | null = null;
afterEach(async () => {
  await t?.close();
  t = null;
});

const signer: Handler = (call) => {
  switch (call.method) {
    case 'ListManualApprovalRequests':
      return body(fixture('rpc/ListManualApprovalRequests.response.json'));
    case 'DecideManualApprovalRequest':
      return body(fixture('rpc/DecideManualApprovalRequest.response.json'));
    case 'ListSpendingLimits':
      return body(fixture('rpc/ListSpendingLimits.response.json'));
    case 'SetSpendingLimits':
      return body(fixture('rpc/SetSpendingLimits.response.json'));
    case 'EnrollAdminCredential':
      return body(fixture('rpc/EnrollAdminCredential.response.json'));
    default:
      return { close: true };
  }
};
const payments: Handler = (call) =>
  call.method === 'GetConfig' ? body(fixture('payments/GetConfig.response.json')) : { close: true };

async function run(argv: string[], options: Parameters<typeof testContext>[0] = {}) {
  t = await testContext({
    signer,
    payments,
    ...options,
  });
  const code = await runCli(argv, t.context);
  return { code, io: t.io, signerCalls: t.signer.calls };
}

describe('admin commands', () => {
  it('admin approvals --json lists pending requests as the root peer', async () => {
    const { code, io, signerCalls } = await run(['admin', 'approvals', '--json'], { euid: 0 });
    expect(code).toBe(0);
    expect(io.json<{ id: string }[]>().map((r) => r.id)).toEqual([APPROVAL_ID]);
    expect(signerCalls[1]).toEqual({
      method: 'ListManualApprovalRequests',
      params: { auth: 'peer_credentials' },
    });
  });

  it('admin approvals in a terminal opens the approvals screen (as the user, not under sudo)', async () => {
    const { code } = await run(['admin', 'approvals'], { io: fakeIo({ isTTY: true }) });
    expect(code).toBe(0);
    expect(t?.rendered).toHaveLength(1);
  });

  it('tells a non-root user without Touch ID to re-run with sudo', async () => {
    const { code, io } = await run(['admin', 'approve', APPROVAL_ID, '--json']);
    expect(code).toBe(1);
    expect(io.json()).toMatchObject({
      error: {
        code: 'sudo_required',
        next_action: `Run it again with sudo: \`sudo agentpay admin approve ${APPROVAL_ID}\`.`,
      },
    });
  });

  it('approves as root with --yes', async () => {
    const { code, io, signerCalls } = await run(
      ['admin', 'approve', APPROVAL_ID, '--yes', '--json'],
      { euid: 0 },
    );
    expect(code).toBe(0);
    expect(io.json()).toMatchObject({ id: APPROVAL_ID, status: 'approved' });
    expect(signerCalls.at(-1)).toEqual({
      method: 'DecideManualApprovalRequest',
      params: {
        auth: 'peer_credentials',
        approval_request_id: APPROVAL_ID,
        decision: 'approve',
        rejection_reason: null,
      },
    });
  });

  it('asks for confirmation as root in a terminal, and needs --yes without one', async () => {
    const declined = await run(['admin', 'reject', APPROVAL_ID, '--reason', 'too much'], {
      euid: 0,
      io: fakeIo({ isTTY: true, answers: ['n'] }),
    });
    expect(declined.code).toBe(1);
    expect(declined.io.questions).toEqual(['Reject this request? [y/N] ']);
    expect(declined.io.err()).toContain('Amount   1 USD1');
    expect(declined.signerCalls.some((c) => c.method === 'DecideManualApprovalRequest')).toBe(
      false,
    );
    await t?.close();
    const noTty = await run(['admin', 'approve', APPROVAL_ID], { euid: 0 });
    expect(noTty.code).toBe(2);
    expect(noTty.io.err()).toContain('--yes');
  });

  it('reports an approval that is already decided', async () => {
    const decided: Handler = (call) =>
      call.method === 'ListManualApprovalRequests'
        ? ok('ManualApprovalRequests', [])
        : signer(call);
    const { code, io } = await run(['admin', 'approve', APPROVAL_ID, '--yes', '--json'], {
      euid: 0,
      signer: decided,
    });
    expect(code).toBe(1);
    expect(io.json()).toMatchObject({ error: { code: 'UnknownManualApprovalRequest' } });
  });

  it('admin limits --json shows every configured asset; unlisted ones are blocked', async () => {
    const { io, signerCalls } = await run(['admin', 'limits', '--json'], { euid: 0 });
    const rows =
      io.json<
        {
          asset: string;
          network: string;
          status: string;
          per_tx: string | null;
          daily_used: string | null;
        }[]
      >();
    expect(signerCalls.find((c) => c.method === 'ListSpendingLimits')?.params).toEqual({
      auth: 'peer_credentials',
      agent_key_id: AGENT_KEY_ID,
    });
    expect(rows.find((r) => r.asset === 'usd1' && r.network === 'bsc')).toMatchObject({
      status: 'custom',
      per_tx: '100',
      daily_used: '1',
    });
    expect(rows.find((r) => r.asset === 'bnb')).toMatchObject({ status: 'custom', per_tx: '0.01' });
    expect(rows.find((r) => r.asset === 'usd1' && r.network === 'eth')).toMatchObject({
      status: 'excluded',
      per_tx: '10',
    });
  });

  it('admin limits set replaces the whole limit set, keeping hidden caps', async () => {
    const { code, signerCalls, io } = await run(
      [
        'admin',
        'limits',
        'set',
        'usd1',
        '--per-tx',
        '25',
        '--daily',
        '100',
        '--weekly',
        '300',
        '--json',
      ],
      { euid: 0 },
    );
    expect(code).toBe(0);
    // `--json` after a subcommand is parsed by `admin limits`; it still selects JSON.
    expect(io.json()).toMatchObject({ asset: 'usd1', per_tx: '25', status: 'custom' });
    const sent = signerCalls.find((c) => c.method === 'SetSpendingLimits')?.params as {
      agent_key_id: string;
      limits: Record<string, unknown>[];
    };
    expect(sent.agent_key_id).toBe(AGENT_KEY_ID);
    expect(sent.limits).toEqual([
      {
        chain_id: 56,
        asset: { kind: 'native_eth' },
        per_tx_max_wei: '10000000000000000',
        daily_max_wei: '50000000000000000',
        weekly_max_wei: '100000000000000000',
      },
      {
        chain_id: 56,
        asset: { kind: 'erc20', value: '0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d' },
        per_tx_max_wei: '25000000000000000000',
        daily_max_wei: '100000000000000000000',
        weekly_max_wei: '300000000000000000000',
        max_gas_per_tx_wei: '2000000000000000',
      },
    ]);
  });

  it('touch-id status reports unavailable off macOS', async () => {
    const { io } = await run(['admin', 'touch-id', 'status', '--json']);
    expect(io.json()).toMatchObject({ state: 'unavailable', credential_id: null });
  });
});

describe('sudo relay', () => {
  it('validates relay requests on the root side', () => {
    expect(
      parseRelayRequest(
        '{"method":"EnrollAdminCredential","params":{"public_key_sec1_hex":"04","label":"x"}}',
      ).method,
    ).toBe('EnrollAdminCredential');
    expect(() => parseRelayRequest('{"method":"SignForAgent","params":{}}')).toThrow(UsageError);
    expect(() =>
      parseRelayRequest('{"method":"ListManualApprovalRequests","params":{"auth":"x"}}'),
    ).toThrow(UsageError);
    expect(RELAYED_METHODS).not.toContain('ExportVaultPrivateKey');
  });

  it('forwards one admin call as the root peer and prints the response', async () => {
    const { code, io, signerCalls } = await run(['admin', 'privileged'], {
      euid: 0,
      io: fakeIo({ stdin: JSON.stringify({ method: 'ListManualApprovalRequests', params: {} }) }),
    });
    expect(code).toBe(0);
    expect(signerCalls[1]).toEqual({
      method: 'ListManualApprovalRequests',
      params: { auth: 'peer_credentials' },
    });
    expect(io.json()).toMatchObject({ ok: true, response: { type: 'ManualApprovalRequests' } });
  });

  it('passes daemon errors back and refuses to run without root', async () => {
    const failing = await run(['admin', 'privileged'], {
      euid: 0,
      io: fakeIo({ stdin: JSON.stringify({ method: 'DecideManualApprovalRequest', params: {} }) }),
      signer: () => fail('UnknownManualApprovalRequest', APPROVAL_ID),
    });
    expect(failing.io.json()).toEqual({
      ok: false,
      error: { kind: 'UnknownManualApprovalRequest', data: APPROVAL_ID },
    });
    await t?.close();
    const user = await run(['admin', 'privileged'], { io: fakeIo({ stdin: '{}' }) });
    expect(user.code).toBe(1);
    expect(user.io.err()).toContain('must run as root');
  });

  it('tries `sudo -n` first, then lets sudo prompt on the terminal', async () => {
    const calls: {
      args: readonly string[];
      inheritStderr: boolean | undefined;
      input: string | undefined;
    }[] = [];
    const run: CommandRunner = async (_command, args, options) => {
      calls.push({ args, inheritStderr: options?.inheritStderr, input: options?.input });
      return calls.length === 1
        ? { status: 1, stdout: '', stderr: 'sudo: a password is required\n' }
        : {
            status: 0,
            stdout: JSON.stringify({ ok: true, response: { type: 'Unit' } }),
            stderr: '',
          };
    };
    const relay = createSudoRelay(run, ['/usr/bin/node', '/opt/agentpay/cli.js']);
    await expect(
      relay.run({ method: 'RevokeAdminCredential', params: { id: 'x' } }),
    ).resolves.toEqual({ type: 'Unit' });
    expect(calls[0]?.args).toEqual([
      '-n',
      '--',
      '/usr/bin/node',
      '/opt/agentpay/cli.js',
      'admin',
      'privileged',
    ]);
    expect(calls[1]?.args).toEqual([
      '--',
      '/usr/bin/node',
      '/opt/agentpay/cli.js',
      'admin',
      'privileged',
    ]);
    expect(calls[1]?.inheritStderr).toBe(true);
    expect(JSON.parse(calls[1]?.input ?? '')).toEqual({
      method: 'RevokeAdminCredential',
      params: { id: 'x' },
    });
  });

  it('raises daemon errors from the relay as SignerCallError', async () => {
    const run: CommandRunner = async () => ({
      status: 0,
      stdout: JSON.stringify({ ok: false, error: { kind: 'RootPeerRequired' } }),
      stderr: '',
    });
    await expect(
      createSudoRelay(run, ['agentpay']).run({ method: 'EnrollAdminCredential', params: {} }),
    ).rejects.toBeInstanceOf(SignerCallError);
  });
});

describe('setup', () => {
  it('runs `sudo agentpay-setup install --user <me>` and explains the wizard needs a terminal', async () => {
    const runs: { command: string; args: readonly string[]; interactive: boolean | undefined }[] =
      [];
    const runner: CommandRunner = async (command, args, options) => {
      runs.push({ command, args, interactive: options?.interactive });
      return { status: 0, stdout: '', stderr: '' };
    };
    const { code, io } = await run(['setup'], {
      run: runner,
      env: { ...process.env, AGENTPAY_SETUP_BIN: '/opt/agentpay/bin/agentpay-setup' },
    });
    expect(runs[0]).toMatchObject({ command: 'sudo', interactive: true });
    expect(runs[0]?.args.slice(0, 3)).toEqual([
      '/opt/agentpay/bin/agentpay-setup',
      'install',
      '--user',
    ]);
    expect(code).toBe(2);
    expect(io.out()).toContain('needs an interactive terminal');
  });

  it('refuses to run as root', async () => {
    const { code, io } = await run(['setup', '--skip-install'], { euid: 0 });
    expect(code).toBe(1);
    expect(io.err()).toContain('not root');
  });
});

describe('admin under sudo', () => {
  it('admin limits works as root without the agent token, from the built-in configuration', async () => {
    t = await testContext({
      signer,
      payments,
      euid: 0,
      credentials: false,
      io: fakeIo({ isTTY: true }),
    });
    t.context.state.update({ agentKeyId: AGENT_KEY_ID });
    const code = await runCli(['admin', 'limits'], t.context);
    expect(code).toBe(0);
    expect(t.rendered).toHaveLength(0);
    expect(t.io.out()).toMatch(/USD1\s+bsc\s+100\s+500\s+1000\s+custom/u);
  });
});
