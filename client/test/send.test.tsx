import { afterEach, describe, expect, it, vi } from 'vitest';
import { sendPayment } from '../src/app/send.js';
import { createAppServices } from '../src/app/services.js';
import type { PaymentsClient } from '../src/daemon/payments.js';
import { PaymentsCallError } from '../src/errors.js';
import {
  amountProblem,
  maxAmount,
  recipientProblem,
  sendOptions,
  sendOutcome,
} from '../src/format/send.js';
import { SendScreen } from '../src/screens/Send.js';
import { type TestContext, testContext } from './helpers/context.js';
import { body } from './helpers/fake-daemon.js';
import { fixture } from './helpers/fixtures.js';
import { KEY, press, render, waitFor } from './helpers/ink.js';
import { config, fakeAppServices, wallet } from './helpers/services.js';

const TO = '0x5aeda56215b167893e80b4fe645ba6d5bab767de';
const options = sendOptions(config, wallet, { includeTestnets: true });
const pick = (id: string) => {
  const option = options.find((o) => o.id === id);
  if (!option) {
    throw new Error(id);
  }
  return option;
};

describe('what can be sent', () => {
  it('lists every token with its balance, the default first', () => {
    expect(options[0]).toMatchObject({ id: 'bsc/usd1', balance: '25.5', native: false });
    expect(pick('bsc/bnb')).toMatchObject({ native: true, balance: '2', family: 'evm' });
    expect(pick('solana-devnet/usdc')).toMatchObject({ family: 'solana', native: false });
    expect(pick('eth/usd1').balance).toBeNull();
  });

  it('keeps a little of a native coin back for fees when sending the maximum', () => {
    expect(maxAmount(pick('bsc/usd1'))).toBe('25.5');
    expect(maxAmount(pick('bsc/bnb'))).toBe('1.999');
    expect(maxAmount(pick('solana-devnet/sol'))).toBe('0.0009');
  });

  it('checks the recipient for the network and refuses this wallet', () => {
    const usd1 = pick('bsc/usd1');
    const own = [wallet.evm_address, wallet.solana_address];
    expect(recipientProblem(usd1, TO, own)).toBeNull();
    expect(recipientProblem(usd1, '0x123', own)).toContain('40 hex');
    expect(
      recipientProblem(usd1, wallet.evm_address?.toUpperCase().replace('0X', '0x') ?? '', own),
    ).toContain('own address');
    expect(recipientProblem(pick('solana-devnet/sol'), TO, own)).toContain('Solana address');
  });

  it('checks the amount against the decimals and the balance', () => {
    const usd1 = pick('bsc/usd1');
    expect(amountProblem(usd1, '10')).toBeNull();
    expect(amountProblem(usd1, '0')).toContain('above 0');
    expect(amountProblem(usd1, '30')).toContain('more than the 25.5 USD1');
    expect(amountProblem(pick('solana-devnet/sol'), '0.0000000001')).toContain('9 decimal places');
  });
});

describe('sending', () => {
  const fakePayments = () => {
    const sent = { type: 'EvmTransaction', data: { tx_hash: '0xh', receipt: { success: true } } };
    return {
      transfer: vi.fn(async () => sent),
      transferNative: vi.fn(async () => sent),
      transferSol: vi.fn(async () => ({
        type: 'SolanaTransfer',
        data: { signature: 's', broadcast: { status: 'confirmed' } },
      })),
      transferSpl: vi.fn(async () => ({ type: 'SolanaTransfer', data: { signature: 's' } })),
    };
  };

  it('uses the payment method for the asset, broadcasting without waiting for an approval', async () => {
    const payments = fakePayments();
    const client = payments as unknown as PaymentsClient;
    await sendPayment(client, pick('bsc/usd1'), TO, '10');
    expect(payments.transfer).toHaveBeenCalledWith({
      network: 'bsc',
      asset: 'usd1',
      to: TO,
      amount: '10',
      broadcast: true,
      wait_for_receipt: true,
      approval_wait_secs: 0,
    });
    await sendPayment(client, pick('bsc/bnb'), TO, '0.5');
    expect(payments.transferNative).toHaveBeenCalledWith(
      expect.objectContaining({ network: 'bsc', amount: '0.5', approval_wait_secs: 0 }),
    );
    const sol = pick('solana-devnet/sol');
    await sendPayment(client, sol, 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', '0.0005');
    expect(payments.transferSol).toHaveBeenCalledWith(
      expect.objectContaining({
        amount: { decimal: '0.0005' },
        options: expect.objectContaining({ broadcast: true, approval_wait_secs: 0 }),
      }),
    );
    const usdc = pick('solana-devnet/usdc');
    await sendPayment(client, usdc, 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', '1');
    expect(payments.transferSpl).toHaveBeenCalledWith(
      expect.objectContaining({ mint: usdc.token }),
    );
  });

  it('turns the daemon’s answers into sent or waiting', () => {
    expect(
      sendOutcome({
        type: 'ManualApprovalPending',
        data: { approval_request_id: 'id-1' },
      } as never),
    ).toEqual({ kind: 'pending', approvalRequestId: 'id-1', reasons: [] });
    expect(
      sendOutcome({
        type: 'EvmTransaction',
        data: { tx_hash: '0xh', receipt: { success: false } },
      } as never),
    ).toMatchObject({ kind: 'sent', failed: true });
  });
});

describe('Send screen', () => {
  async function toReview(services = fakeAppServices()) {
    const view = render(<SendScreen services={services} onBack={() => {}} />);
    await waitFor(view.lastFrame, '› USD1 on BSC');
    expect(view.lastFrame()).toContain('25.5 available');
    await press(view.stdin, KEY.enter);
    await waitFor(view.lastFrame, 'To');
    await press(view.stdin, ...TO.split(''), KEY.enter);
    await waitFor(view.lastFrame, 'm for the maximum');
    await press(view.stdin, 'm');
    await waitFor(view.lastFrame, '25.5');
    await press(view.stdin, KEY.enter);
    const review = await waitFor(view.lastFrame, 'Review payment');
    return { ...view, services, review };
  }

  it('reviews, then sends and shows the transaction', async () => {
    const { review, stdin, lastFrame, services } = await toReview();
    expect(review).toContain(`To       ${TO}`);
    expect(review).toContain('Amount   25.5 USD1');
    expect(review).toContain('Above them it waits for your approval.');
    await press(stdin, KEY.enter);
    const sent = await waitFor(lastFrame, '✓ Sent 25.5 USD1 to 0x5aed…67de.');
    expect(sent).toContain('Confirmed on the network.');
    expect(services.send).toHaveBeenCalledWith(pick('bsc/usd1'), TO, '25.5');
  });

  it('a payment above the limits waits; approving sends it', async () => {
    const services = fakeAppServices({
      send: vi.fn(async () => ({
        kind: 'pending' as const,
        approvalRequestId: 'req-1',
        reasons: ['Over your daily limit: 80 USD1 of 100 USD1 used, this payment is 25.5 USD1'],
      })),
    });
    const { stdin, lastFrame } = await toReview(services);
    await press(stdin, KEY.enter);
    const waiting = await waitFor(lastFrame, 'Waiting for your approval');
    expect(waiting).toContain('Over your daily limit');
    expect(waiting).toContain('› Approve and send now');
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, '✓ Sent 25.5 USD1');
    expect(services.approveAndSend).toHaveBeenCalledWith('req-1');
  });

  it('a waiting payment can be left for later', async () => {
    const services = fakeAppServices({
      send: vi.fn(async () => ({
        kind: 'pending' as const,
        approvalRequestId: 'req-1',
        reasons: [],
      })),
    });
    const { stdin, lastFrame } = await toReview(services);
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Waiting for your approval');
    await press(stdin, KEY.down, KEY.enter);
    await waitFor(lastFrame, 'Left in Approvals');
    expect(services.approveAndSend).not.toHaveBeenCalled();
  });

  it('shows why a send failed', async () => {
    const services = fakeAppServices({
      send: vi.fn(async () => {
        throw new PaymentsCallError({ kind: 'InsufficientFunds', data: 'not enough' } as never);
      }),
    });
    const { stdin, lastFrame } = await toReview(services);
    await press(stdin, KEY.enter);
    const failed = await waitFor(lastFrame, '✗');
    expect(failed).toContain('Send another');
  });

  it('says when there is nothing to send, and starts on something that can be sent', async () => {
    const empty = fakeAppServices({
      loadSend: vi.fn(async () => ({
        options: options.map((o) => ({ ...o, balance: '0' })),
        ownAddresses: [],
      })),
    });
    const view = render(<SendScreen services={empty} onBack={() => {}} />);
    await waitFor(view.lastFrame, 'nothing to send yet');

    const someBnb = fakeAppServices({
      loadSend: vi.fn(async () => ({
        options: options.map((o) => ({ ...o, balance: o.id === 'bsc/bnb' ? '1' : '0' })),
        ownAddresses: [],
      })),
    });
    const other = render(<SendScreen services={someBnb} onBack={() => {}} />);
    const frame = await waitFor(other.lastFrame, '› BNB on BSC');
    expect(frame).not.toContain('nothing to send yet');
  });

  it('refuses a bad address before going on', async () => {
    const view = render(<SendScreen services={fakeAppServices()} onBack={() => {}} />);
    await waitFor(view.lastFrame, '› USD1 on BSC');
    await press(view.stdin, KEY.enter);
    await waitFor(view.lastFrame, 'To');
    await press(view.stdin, ...'0x12'.split(''), KEY.enter);
    await waitFor(view.lastFrame, '40 hex characters');
    expect(view.lastFrame()).not.toContain('Amount');
  });
});

describe('approve and send against the daemons', () => {
  let t: TestContext | null = null;
  afterEach(async () => {
    await t?.close();
    t = null;
  });

  it('approves the request as the owner, then resumes the payment', async () => {
    t = await testContext({
      euid: 0,
      signer: (call) =>
        call.method === 'ListManualApprovalRequests'
          ? body(fixture('rpc/ListManualApprovalRequests.response.json'))
          : call.method === 'DecideManualApprovalRequest'
            ? body(fixture('rpc/DecideManualApprovalRequest.response.json'))
            : { close: true },
      payments: (call) =>
        call.method === 'ResumeApproved'
          ? body(fixture('payments/evm/ResumeApproved.response.json'))
          : { close: true },
    });
    const services = createAppServices(
      t.context,
      await t.context.payments({}),
      t.context.admin({ relay: false }),
    );
    const outcome = await services.approveAndSend('e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090');
    expect(outcome.kind).toBe('sent');
    const decide = t.signer.calls.find((c) => c.method === 'DecideManualApprovalRequest');
    expect(decide?.params).toMatchObject({ decision: 'approve' });
    const resume = t.payments.calls.find((c) => c.method === 'ResumeApproved');
    expect(resume?.params).toMatchObject({
      approval_request_id: 'e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090',
    });
  });
});
