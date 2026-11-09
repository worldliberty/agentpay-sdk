/** How wallets from `ListWallets` are shown and picked: by address, age, and agent keys. */
import { copy } from '../copy/index.js';
import type { WalletInfo } from '../generated/index.js';
import { columns, shortAddress, timestampToDate } from './text.js';

/** The wallet's main address: EVM, else Solana, else (no address) its vault key id. */
export function walletAddress(wallet: WalletInfo): string {
  return wallet.evm_address ?? wallet.solana_address ?? wallet.vault_key_id;
}

/** The UTC creation date, `2026-11-05`. */
export function walletCreated(wallet: WalletInfo): string {
  return timestampToDate(wallet.created_at).toISOString().slice(0, 10);
}

/** `Trading bot · 0x2c75…5c23 · created 2026-11-05 · 1 agent key` (the name when it has one). */
export function walletLabel(wallet: WalletInfo): string {
  const w = copy.common.wallet;
  return [
    ...(wallet.name ? [wallet.name] : []),
    shortAddress(walletAddress(wallet)),
    w.created(walletCreated(wallet)),
    w.agentKeys(wallet.agent_key_ids.length),
  ].join(' · ');
}

/** One aligned line per wallet with its full addresses, for command output. */
export function walletLines(wallets: readonly WalletInfo[]): string[] {
  const w = copy.common.wallet;
  return columns([
    w.columns,
    ...wallets.map((wallet) => [
      wallet.name ?? '—',
      wallet.vault_key_id,
      wallet.evm_address ?? '—',
      wallet.solana_address ?? '—',
      walletCreated(wallet),
      String(wallet.agent_key_ids.length),
    ]),
  ]);
}

/**
 * The wallet `selector` names: its vault key id or one of its addresses (EVM addresses in any
 * case). `null` when no wallet matches.
 */
export function findWallet(wallets: readonly WalletInfo[], selector: string): WalletInfo | null {
  const wanted = selector.trim();
  const lower = wanted.toLowerCase();
  return (
    wallets.find(
      (wallet) =>
        wallet.vault_key_id.toLowerCase() === lower ||
        wallet.evm_address?.toLowerCase() === lower ||
        wallet.solana_address === wanted,
    ) ?? null
  );
}
