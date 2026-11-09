import { afterEach, describe, expect, it, vi } from 'vitest';
import type { CommandRunner } from '../src/auth/process.js';
import { runCli } from '../src/program.js';
import { type TestContext, testContext } from './helpers/context.js';
import { body, ok } from './helpers/fake-daemon.js';
import { fixture } from './helpers/fixtures.js';
import { fakeIo } from './helpers/io.js';
import { activity } from './helpers/services.js';

let t: TestContext | null = null;
afterEach(async () => {
  await t?.close();
  t = null;
});

const pending = {
  ...activity,
  approvals: [
    {
      ...(activity.approvals[0] as (typeof activity.approvals)[number]),
      id: 'f1f1f1f1-0000-4000-8000-000000000001',
      status: 'pending' as const,
      amount: '50',
      reasons: [
        {
          limit: 'daily' as const,
          policy_id: null,
          max: '100000000000000000000',
          used: '80000000000000000000',
          requested_amount_wei: '50000000000000000000',
        },
      ],
    },
  ],
};

describe('agentpay activity and notify', () => {
  it('activity --json passes Activity through', async () => {
    t = await testContext({
      payments: (call) =>
        call.method === 'Activity'
          ? body(fixture('payments/wallet/Activity.response.json'))
          : { close: true },
    });
    const code = await runCli(['activity', '--json', '--limit', '5'], t.context);
    expect(code).toBe(0);
    expect(t.io.json()).toEqual(activity);
    expect(t.payments.calls.find((c) => c.method === 'Activity')?.params).toMatchObject({
      limit: 5,
    });
  });

  it('notify --once shows one notification per waiting payment, once', async () => {
    const run = vi.fn(async () => ({
      status: 0,
      stdout: '',
      stderr: '',
    })) as unknown as CommandRunner;
    t = await testContext({
      platform: 'darwin',
      run,
      io: fakeIo(),
      payments: (call) =>
        call.method === 'Activity'
          ? ok('Activity', pending)
          : call.method === 'GetConfig'
            ? body(fixture('payments/GetConfig.response.json'))
            : { close: true },
    });
    await runCli(['notify', '--once'], t.context);
    await runCli(['notify', '--once'], t.context);
    const calls = vi.mocked(run).mock.calls as unknown as [string, string[]][];
    const shown = calls.filter(([command]) => command === '/usr/bin/osascript');
    expect(shown).toHaveLength(1);
    expect(shown[0]?.[1]?.[1]).toContain(
      'Approve 50 USD1 on BSC? Over daily limit. Run agentpay to review.',
    );
  });
});
