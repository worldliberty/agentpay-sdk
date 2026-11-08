/** Sends one payment from the TUI through the payment method that fits the asset. */
import type { PaymentsClient } from '../daemon/payments.js';
import type { SendOption } from '../format/send.js';

/**
 * Broadcasts and waits for the receipt or confirmation, but never for an approval: a payment
 * above the limits comes back `ManualApprovalPending` at once, and the screen offers to approve.
 */
export function sendPayment(
  payments: PaymentsClient,
  option: SendOption,
  to: string,
  amount: string,
) {
  if (option.family === 'solana') {
    const options = {
      broadcast: true,
      wait_for_confirmation: true,
      nonce: 'auto' as const,
      approval_wait_secs: 0,
      reveal_raw_tx: false,
    };
    return option.native || !option.token
      ? payments.transferSol({ network: option.network, to, amount: { decimal: amount }, options })
      : payments.transferSpl({
          network: option.network,
          mint: option.token,
          to,
          amount: { decimal: amount },
          options,
        });
  }
  const tx = { broadcast: true, wait_for_receipt: true, approval_wait_secs: 0 };
  return option.native
    ? payments.transferNative({ network: option.network, to, amount, ...tx })
    : payments.transfer({ network: option.network, asset: option.asset, to, amount, ...tx });
}
