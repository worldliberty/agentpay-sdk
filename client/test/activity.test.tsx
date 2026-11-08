import { describe, expect, it, vi } from 'vitest';
import { activityLines } from '../src/format/activity.js';
import { ActivityScreen } from '../src/screens/Activity.js';
import { KEY, press, render, waitFor } from './helpers/ink.js';
import { activity, config, fakeAppServices } from './helpers/services.js';

const NOW = new Date('2026-11-05T13:00:00Z');
const waiting = {
  ...activity,
  approvals: [
    ...activity.approvals,
    {
      ...(activity.approvals[0] as (typeof activity.approvals)[number]),
      id: 'f1f1f1f1-0000-4000-8000-000000000001',
      status: 'pending' as const,
      amount: '50',
      amount_wei: '50000000000000000000',
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

describe('activity', () => {
  it('lists recent payments as within limits or approved by you', () => {
    const text = activityLines(activity, config, NOW).join('\n');
    expect(text).toContain('Recent payments');
    expect(text).toMatch(/55 min ago\s+150 USD1\s+→ 0x5aed…67de\s+BSC\s+approved by you/u);
    expect(text).toMatch(/1 h ago\s+40 USD1\s+→ 0x5aed…67de\s+BSC\s+within limits/u);
    expect(text).not.toContain('waiting for your approval');
  });

  it('puts payments waiting for approval first, with why', () => {
    const text = activityLines(waiting, config, NOW).join('\n');
    expect(text.indexOf('1 payment is waiting for your approval')).toBe(0);
    expect(text).toContain('50 USD1 on BSC → 0x5aed…67de');
    expect(text).toContain(
      'Over your daily limit: 80 USD1 of 100 USD1 used, this payment is 50 USD1',
    );
  });

  it('the screen opens Approvals with a when something waits', async () => {
    const services = fakeAppServices({
      loadActivity: vi.fn(async () => ({ result: waiting, config })),
    });
    const onOpenApprovals = vi.fn();
    const { lastFrame, stdin } = render(
      <ActivityScreen
        services={services}
        onBack={() => {}}
        onOpenApprovals={onOpenApprovals}
        now={() => NOW}
      />,
    );
    const frame = await waitFor(lastFrame, 'Recent payments');
    expect(frame).toContain('! 1 payment is waiting for your approval');
    expect(frame).toContain('a approvals');
    expect(frame).toContain('approved by you');
    await press(stdin, 'a');
    expect(onOpenApprovals).toHaveBeenCalled();
    await press(stdin, KEY.escape);
  });
});
