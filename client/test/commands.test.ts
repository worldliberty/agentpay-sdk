import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { CommandRunner } from '../src/auth/process.js';
import { sessionKeyFromFile } from '../src/commands/http.js';
import { runCli } from '../src/program.js';
import { OnboardingWizard } from '../src/screens/onboarding/OnboardingWizard.js';
import { SetupMenu } from '../src/screens/SetupMenu.js';
import { AGENT_KEY_ID, AGENT_TOKEN, type TestContext, testContext } from './helpers/context.js';
import { body, fail, type Handler } from './helpers/fake-daemon.js';
import { fixture, fixtureData } from './helpers/fixtures.js';
import { fakeIo } from './helpers/io.js';

const AUTH = { agent_key_id: AGENT_KEY_ID, agent_auth_token: AGENT_TOKEN };
let t: TestContext | null = null;
afterEach(async () => {
  await t?.close();
  t = null;
});

/** Answers each payments method with its API fixture. */
const PAYMENT_FIXTURES: Record<string, string> = {
  WalletSummary: 'payments/wallet/WalletSummary.response.json',
  Status: 'payments/wallet/Status.response.json',
  FundingRequest: 'payments/wallet/FundingRequest.response.json',
  GetConfig: 'payments/GetConfig.response.json',
  SetConfig: 'payments/SetConfig.response.json',
  Transfer: 'payments/evm/Transfer.response.json',
  TransferNative: 'payments/evm/TransferNative.response.json',
  Approve: 'payments/evm/Approve.response.json',
  Broadcast: 'payments/evm/Broadcast.response.json',
  ResumeApproved: 'payments/evm/ResumeApproved.response.json',
  SignTypedData: 'payments/evm/SignTypedData.response.json',
  TransferSol: 'payments/solana/TransferSol.response.json',
  TransferSpl: 'payments/solana/TransferSpl.response.json',
  X402Fetch: 'payments/x402/X402Fetch.response.json',
  MppFetch: 'payments/mpp/MppFetch.response.json',
  ProxyStart: 'payments/proxy/ProxyStart.response.json',
  ProxyStop: 'payments/proxy/ProxyStop.response.json',
  ProxyStatus: 'payments/proxy/ProxyStatus.response.json',
  TelemetryStatus: 'payments/telemetry/TelemetryStatus.response.json',
  SetTelemetry: 'payments/telemetry/SetTelemetry.response.json',
};
const fromFixtures: Handler = (call) => {
  const path = PAYMENT_FIXTURES[call.method];
  return path ? body(fixture(path)) : { close: true };
};

async function run(argv: string[], options: Parameters<typeof testContext>[0] = {}) {
  t = await testContext({ payments: fromFixtures, ...options });
  const code = await runCli(argv, t.context);
  return { code, io: t.io, calls: t.payments.calls };
}

describe('agent commands (--json)', () => {
  it('wallet --json prints WalletSummary as documented', async () => {
    const { code, io, calls } = await run(['wallet', '--json']);
    expect(code).toBe(0);
    expect(io.json()).toEqual(fixtureData('payments/wallet/WalletSummary.response.json'));
    expect(calls[1]).toEqual({ method: 'WalletSummary', params: { auth: AUTH } });
  });

  it('status --json and fund --json pass the results through', async () => {
    expect((await run(['status', '--json'])).io.json()).toEqual(
      fixtureData('payments/wallet/Status.response.json'),
    );
    await t?.close();
    const fund = await run(['fund', '--asset', 'usd1', '--amount', '25', '--qr', '--json']);
    expect(fund.calls[1]?.params).toEqual({ auth: AUTH, qr: true, asset: 'usd1', amount: '25' });
    expect(fund.io.json()).toMatchObject({ uri: expect.stringMatching(/^ethereum:/u) });
  });

  it('transfer maps the TypeScript CLI flags to Transfer params', async () => {
    const { code, io, calls } = await run([
      'transfer',
      '--network',
      'bsc',
      '--token',
      'usd1',
      '--to',
      '0x5aeda56215b167893e80b4fe645ba6d5bab767de',
      '--amount',
      '1',
      '--broadcast',
      '--json',
    ]);
    expect(code).toBe(0);
    expect(calls[1]).toEqual({
      method: 'Transfer',
      params: {
        auth: AUTH,
        broadcast: true,
        wait_for_receipt: true,
        approval_wait_secs: 300,
        network: 'bsc',
        asset: 'usd1',
        to: '0x5aeda56215b167893e80b4fe645ba6d5bab767de',
        amount: '1',
      },
    });
    expect(io.json()).toEqual(fixtureData('payments/evm/Transfer.response.json'));
  });

  it('a held payment prints status manual_approval_pending and exits 3', async () => {
    const { code, io } = await run([
      'approve',
      '--spender',
      '0x000000000022d473030f116ddee9f6b43ac78ba3',
      '--amount',
      '100',
      '--broadcast',
      '--no-wait',
      '--json',
    ]);
    expect(code).toBe(3);
    expect(io.json()).toMatchObject({
      status: 'manual_approval_pending',
      approval_request_id: 'e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090',
      method: 'Approve',
      next_action: expect.stringContaining(
        'agentpay admin approve e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090',
      ),
    });
  });

  it('signs without broadcasting by default and does not wait for approval', async () => {
    const { calls } = await run([
      'transfer-native',
      '--to',
      '0x5aeda56215b167893e80b4fe645ba6d5bab767de',
      '--amount',
      '0.01',
      '--json',
    ]);
    expect(calls[1]?.params).toEqual({
      auth: AUTH,
      broadcast: false,
      wait_for_receipt: false,
      approval_wait_secs: 0,
      to: '0x5aeda56215b167893e80b4fe645ba6d5bab767de',
      amount: '0.01',
    });
  });

  it('transfer-sol builds Solana options', async () => {
    const { calls, io } = await run([
      'transfer-sol',
      '--network',
      'solana-devnet',
      '--to',
      '3D34zRx4vQzu1hMJsk9kMSduU6pNwDeSxEg95DMNMZGG',
      '--amount',
      '0.0015',
      '--broadcast',
      '--approval-wait',
      '60',
      '--json',
    ]);
    expect(calls[1]?.params).toEqual({
      auth: AUTH,
      network: 'solana-devnet',
      to: '3D34zRx4vQzu1hMJsk9kMSduU6pNwDeSxEg95DMNMZGG',
      amount: { decimal: '0.0015' },
      options: {
        broadcast: true,
        wait_for_confirmation: true,
        nonce: 'auto',
        reveal_raw_tx: false,
        approval_wait_secs: 60,
      },
    });
    expect(io.json()).toMatchObject({ broadcast: { status: 'confirmed' } });
  });

  it('x402 --json keeps the TypeScript CLI shape', async () => {
    const { io, calls } = await run([
      'x402',
      'https://api.example.com/weather?city=Lisbon',
      '--header',
      'Accept: application/json',
      '--max-amount',
      '10000',
      '--json',
    ]);
    expect(calls[1]?.params).toEqual({
      auth: AUTH,
      url: 'https://api.example.com/weather?city=Lisbon',
      headers: [{ name: 'Accept', value: 'application/json' }],
      max_amount: '10000',
    });
    expect(io.json()).toMatchObject({
      protocol: 'x402',
      status: 200,
      ok: true,
      headers: { 'content-type': 'application/json' },
      body: { city: 'Lisbon', temperature_c: 21 },
      payment: { scheme: 'exact', amount: '1000' },
    });
  });

  it('mpp maps session flags and adds the legacy payment aliases', async () => {
    const stateFile = join(process.env.HOME ?? '', 'llm-session.json');
    const { io, calls } = await run([
      'mpp',
      'https://llm.example.com/v1/complete',
      '--method',
      'post',
      '--json-body',
      '{"prompt":"Say hi"}',
      '--deposit',
      '1000000',
      '--max-deposit',
      '5000000',
      '--session-state-file',
      stateFile,
      '--json',
    ]);
    expect(calls[1]?.params).toEqual({
      auth: AUTH,
      url: 'https://llm.example.com/v1/complete',
      method: 'POST',
      headers: [{ name: 'Content-Type', value: 'application/json' }],
      body: { type: 'text', data: '{"prompt":"Say hi"}' },
      close_session: false,
      deposit: '1000000',
      max_deposit: '5000000',
      session_key: sessionKeyFromFile(stateFile),
    });
    expect(sessionKeyFromFile(stateFile)).toMatch(/^file:llm-session:[0-9a-f]{12}$/u);
    expect(io.json()).toMatchObject({
      protocol: 'mpp',
      body: { text: 'Hi!' },
      payment: {
        intent: 'session',
        sessionProtocol: 'v2',
        closeReceipt: null,
        receipt: { spent: '75000' },
      },
    });
  });

  it('mpp passes --network and --currency and names the method and network it paid on', async () => {
    const { io, calls } = await run([
      'mpp',
      'https://api.example.com/data',
      '--network',
      'base',
      '--currency',
      '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
    ]);
    expect(calls[1]?.params).toMatchObject({
      network: 'base',
      currency: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
    });
    expect(io.err()).toContain('via MPP tempo on tempo-testnet');
  });

  it('mpp refuses decimal amounts (they are base units)', async () => {
    const { code, io } = await run(['mpp', 'https://x.test', '--amount', '0.005']);
    expect(code).toBe(2);
    expect(io.err()).toContain('base units');
  });

  it('proxy start writes a private env file with the secret proxy URL', async () => {
    const { io } = await run([
      'proxy',
      'start',
      '--port',
      '8402',
      '--allow-host',
      'api.example.com',
      '--json',
    ]);
    const result = io.json<{ env_file: string; ca_file: string; proxy_url: string }>();
    expect(statSync(result.env_file).mode & 0o777).toBe(0o600);
    expect(readFileSync(result.env_file, 'utf8')).toContain(`HTTPS_PROXY='${result.proxy_url}'`);
    expect(readFileSync(result.ca_file, 'utf8')).toContain('BEGIN CERTIFICATE');
  });

  it('proxy start passes the MPP token, deposit, and deposit cap', async () => {
    const { calls } = await run([
      'proxy',
      'start',
      '--allow-host',
      'openai.mpp.tempo.xyz',
      '--currency',
      '0x20c0000000000000000000000000000000000000',
      '--deposit',
      '100000',
      '--max-deposit',
      '1000000',
      '--json',
    ]);
    const start = calls.find((call) => call.method === 'ProxyStart');
    expect(start?.params).toMatchObject({
      allowed_hosts: ['openai.mpp.tempo.xyz'],
      currency: '0x20c0000000000000000000000000000000000000',
      deposit: '100000',
      max_deposit: '1000000',
    });
  });

  it('config set edits the configuration through SetConfig', async () => {
    const { calls } = await run([
      'config',
      'set',
      'chains.bsc.rpc_url',
      'https://bsc-dataseed.bnbchain.org',
      '--json',
    ]);
    const sent = calls[2]?.params as { config: { chains: { bsc: { rpc_url: string } } } };
    expect(calls[2]?.method).toBe('SetConfig');
    expect(sent.config.chains.bsc.rpc_url).toBe('https://bsc-dataseed.bnbchain.org');
  });

  it('config set takes a comma-separated list of backup RPCs, or none', async () => {
    const { calls } = await run([
      'config',
      'set',
      'chains.bsc.fallback_rpc_urls',
      'https://1rpc.io/bnb, https://bsc-dataseed.bnbchain.org',
      '--json',
    ]);
    const sent = calls[2]?.params as {
      config: { chains: { bsc: { fallback_rpc_urls: string[] } } };
    };
    expect(sent.config.chains.bsc.fallback_rpc_urls).toEqual([
      'https://1rpc.io/bnb',
      'https://bsc-dataseed.bnbchain.org',
    ]);
    const cleared = await run(['config', 'set', 'chains.bsc.fallback_rpc_urls', 'none', '--json']);
    const none = cleared.calls[2]?.params as typeof sent;
    expect(none.config.chains.bsc.fallback_rpc_urls).toEqual([]);
  });

  it('config show --json still reports the client when nothing is set up', async () => {
    const { code, io } = await run(['config', 'show', '--json'], { credentials: false });
    expect(code).toBe(4);
    expect(io.json()).toMatchObject({
      setup_required: true,
      payments: null,
      client: { agent_key_id: null, agent_auth_token_stored: false },
      next_action: expect.stringContaining('agentpay setup'),
    });
  });

  it('config agent-auth set stores the token from stdin', async () => {
    t = await testContext({ credentials: false, io: fakeIo({ stdin: `${AGENT_TOKEN}\n` }) });
    const code = await runCli(
      [
        'config',
        'agent-auth',
        'set',
        '--agent-key-id',
        AGENT_KEY_ID,
        '--agent-auth-token-stdin',
        '--json',
      ],
      t.context,
    );
    expect(code).toBe(0);
    expect(await t.context.secrets.read(AGENT_KEY_ID)).toBe(AGENT_TOKEN);
    expect(t.context.state.read().agentKeyId).toBe(AGENT_KEY_ID);
  });

  it('telemetry disable sends SetTelemetry', async () => {
    const { calls, io } = await run(['telemetry', 'disable', '--json']);
    expect(calls[1]).toEqual({ method: 'SetTelemetry', params: { auth: AUTH, enabled: false } });
    expect(io.json()).toMatchObject({ enabled: false, disabled_reason: 'stored_opt_out' });
  });

  it('errors in --json mode are one JSON document with a next action', async () => {
    const { code, io } = await run(['wallet', '--json'], {
      payments: () => fail('ChainRpc', 'eth_chainId failed'),
    });
    expect(code).toBe(1);
    expect(io.json()).toEqual({
      error: {
        code: 'ChainRpc',
        message: 'The network did not answer as expected: eth_chainId failed.',
        next_action: expect.stringContaining('agentpay config set'),
        detail: { kind: 'ChainRpc', data: 'eth_chainId failed' },
      },
    });
  });

  it('errors without --json go to stderr as message plus next action', async () => {
    const { code, io } = await run(['wallet'], { credentials: false });
    expect(code).toBe(4);
    expect(io.out()).toBe('');
    expect(io.err()).toMatch(
      /^Error: No agent credentials were found for this user\.\nNext: Run `agentpay setup`/u,
    );
  });

  it('text output of wallet is aligned and short', async () => {
    const { io } = await run(['wallet']);
    expect(io.out()).toMatchSnapshot();
  });

  it('link and bitrefill are not commands', async () => {
    for (const command of ['link', 'bitrefill']) {
      const { code } = await run([command, 'onboard']);
      expect(code).toBe(2);
    }
  });

  it('unknown commands are usage errors', async () => {
    const { code, io } = await run(['nope']);
    expect(code).toBe(2);
    expect(io.err()).toContain('unknown command "nope"');
  });
});

describe('setup on a machine that is already set up', () => {
  const sudo = () =>
    vi.fn(async () => ({ status: 0, stdout: '', stderr: '' })) as unknown as CommandRunner;

  it('asks what to change instead of reinstalling or replacing the limits', async () => {
    const runner = sudo();
    const { code } = await run(['setup'], { io: fakeIo({ isTTY: true }), run: runner });
    expect(code).toBe(0);
    expect(t?.rendered[0]?.type).toBe(SetupMenu);
    expect(runner).not.toHaveBeenCalled();
  });

  it('runs the whole setup with --full', async () => {
    const runner = sudo();
    await run(['setup', '--full'], { io: fakeIo({ isTTY: true }), run: runner });
    expect(vi.mocked(runner).mock.calls[0]?.[0]).toBe('sudo');
    expect(t?.rendered[0]?.type).toBe(OnboardingWizard);
  });

  it('runs the whole setup when there are no credentials yet', async () => {
    const runner = sudo();
    await run(['setup'], { io: fakeIo({ isTTY: true }), run: runner, credentials: false });
    expect(vi.mocked(runner).mock.calls[0]?.[0]).toBe('sudo');
    expect(t?.rendered[0]?.type).toBe(OnboardingWizard);
  });
});
