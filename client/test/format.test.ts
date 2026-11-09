import { describe, expect, it } from 'vitest';
import { describeDaemonError } from '../src/errors.js';
import {
  compareDecimal,
  displayAmount,
  formatUnits,
  parseUnits,
  stepAmount,
} from '../src/format/amount.js';
import { summarizeApproval } from '../src/format/approval.js';
import { relativeTime, shortAddress, timestampToDate } from '../src/format/text.js';
import type { ManualApprovalRequest, PaymentsConfig } from '../src/generated/index.js';
import { fixtureData } from './helpers/fixtures.js';

describe('amounts', () => {
  it('converts between whole units and base units exactly', () => {
    expect(parseUnits('1.5', 18)).toBe(1_500_000_000_000_000_000n);
    expect(parseUnits('0.000001', 6)).toBe(1n);
    expect(() => parseUnits('0.0000001', 6)).toThrow(RangeError);
    expect(() => parseUnits('1e3', 6)).toThrow(RangeError);
    expect(formatUnits(25_500_000_000_000_000_000n, 18)).toBe('25.5');
    expect(formatUnits(0n, 6)).toBe('0');
    expect(compareDecimal('10', '9.99')).toBe(1);
    expect(compareDecimal('0.5', '0.50')).toBe(0);
  });

  it('formats for display without rounding up', () => {
    expect(displayAmount('1234567.1234569')).toBe('1,234,567.123456');
    expect(displayAmount('25.50')).toBe('25.5');
  });

  it('steps limits along the 1-2-5 ladder', () => {
    expect(stepAmount('10', 1)).toBe('20');
    expect(stepAmount('10', -1)).toBe('5');
    expect(stepAmount('7', 1)).toBe('10');
    expect(stepAmount('0.01', -1)).toBe('0.005');
    expect(stepAmount('', 1)).toBe('0.001');
  });
});

describe('text helpers', () => {
  it('decodes the daemon timestamp array', () => {
    expect(timestampToDate([2026, 309, 12, 0, 0, 0, 0, 0, 0]).toISOString()).toBe(
      '2026-11-05T12:00:00.000Z',
    );
    expect(relativeTime(new Date('2026-11-05T12:00:00Z'), new Date('2026-11-05T12:05:00Z'))).toBe(
      '5 min ago',
    );
    expect(shortAddress('0x5aeda56215b167893e80b4fe645ba6d5bab767de')).toBe('0x5aed…67de');
  });
});

describe('approval summary', () => {
  const config = fixtureData<PaymentsConfig>('payments/GetConfig.response.json');
  const [request] = fixtureData<ManualApprovalRequest[]>(
    'rpc/ListManualApprovalRequests.response.json',
  );

  it('names the action, recipient, amount, and network', () => {
    expect(request && summarizeApproval(request, config)).toEqual({
      action: 'Send',
      to: '0x5aeda56215b167893e80b4fe645ba6d5bab767de',
      amount: '1 USD1',
      symbol: 'USD1',
      network: 'BSC',
      agentKeyId: '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d',
      reasons: ['A policy asks for your approval'],
      shortReason: 'needs approval',
    });
  });

  it('says which limits a payment goes over, in the token’s units', () => {
    if (!request) {
      throw new Error('no approval fixture');
    }
    const usd1 = (whole: number) => (BigInt(whole) * 10n ** 18n).toString();
    const over = {
      ...request,
      amount_wei: usd1(50),
      reasons: [
        {
          limit: 'per_payment' as const,
          policy_id: null,
          max: usd1(25),
          used: null,
          requested_amount_wei: usd1(50),
        },
        {
          limit: 'daily' as const,
          policy_id: null,
          max: usd1(100),
          used: usd1(80),
          requested_amount_wei: usd1(50),
        },
        {
          limit: 'daily_count' as const,
          policy_id: null,
          max: '10',
          used: '10',
          requested_amount_wei: usd1(50),
        },
      ],
    };
    const summary = summarizeApproval(over, config);
    expect(summary.reasons).toEqual([
      'Over the per-payment limit of 25 USD1',
      'Over your daily limit: 80 USD1 of 100 USD1 used, this payment is 50 USD1',
      'Over your daily payment count: 10 of 10 payments already today',
    ]);
    expect(summary.shortReason).toBe('over per-payment limit');
  });

  it('falls back to base units when the token is unknown', () => {
    expect(request && summarizeApproval(request, null).amount).toBe(
      '1000000000000000000 base units of 0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d',
    );
  });
});

describe('policy refusals', () => {
  it('tell no limits at all apart from no limit for this token and network', () => {
    const policy = (data: 'NoAttachedPolicies' | 'NoApplicablePolicies') =>
      describeDaemonError({ kind: 'Policy', data });
    expect(policy('NoAttachedPolicies').message).toContain('no spending limits yet');
    expect(policy('NoApplicablePolicies').message).toContain('covers this token on this network');
  });
});
