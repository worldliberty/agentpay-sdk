/**
 * Networks as people see them: balances grouped by network (the default first, test networks
 * last), and a chain's RPC failure as a short reason with one next action.
 */
import { copy, type Guidance } from '../copy/index.js';
import type { WalletBalanceEntry, WirePaymentsError } from '../generated/index.js';
import { isTestnetChain } from '../limits/model.js';

/** Why a network could not be read, in plain words, and what to do about it. */
export function chainProblem(network: string, error: WirePaymentsError | null): Guidance {
  const n = copy.networks;
  const data = error && 'data' in error ? (error as { data: unknown }).data : null;
  const detail = typeof data === 'string' ? data : '';
  const text = detail.toLowerCase();
  const reason =
    error === null
      ? n.noRpc
      : /rate.?limit|429|too many requests|upgrade to paid/u.test(text)
        ? n.rateLimited
        : /timed? ?out|deadline/u.test(text)
          ? n.timedOut
          : /reports chain id|different chain|wrong chain|as the configured chain/u.test(text)
            ? n.wrongChain
            : /unreachable|connect|refused|dns|resolve|network is down|no route/u.test(text)
              ? n.unreachable
              : /no rpc|rpc_url/u.test(text)
                ? n.noRpc
                : (detail.split('\n')[0] ?? n.unreachable);
  return { message: reason, next: n.setRpc(network) };
}

export interface NetworkBalances {
  network: string;
  chainName: string;
  testnet: boolean;
  entries: WalletBalanceEntry[];
  /** Set when no balance of this network could be read. */
  problem: Guidance | null;
}

/**
 * Balances by network: the default network first, then main networks by name, then test
 * networks (left out unless `includeTestnets`). Inside a network, the default asset first.
 */
export function groupBalances(
  entries: readonly WalletBalanceEntry[],
  options: { defaultNetwork: string; defaultAsset?: string; includeTestnets: boolean },
): NetworkBalances[] {
  const groups = new Map<string, NetworkBalances>();
  for (const entry of entries) {
    const testnet = isTestnetChain(entry.chain_id);
    if (testnet && !options.includeTestnets) {
      continue;
    }
    let group = groups.get(entry.network);
    if (!group) {
      group = {
        network: entry.network,
        chainName: entry.chain_name,
        testnet,
        entries: [],
        problem: null,
      };
      groups.set(entry.network, group);
    }
    group.entries.push(entry);
  }
  for (const group of groups.values()) {
    const failed = group.entries.every((entry) => entry.balance === null);
    group.problem = failed ? chainProblem(group.network, group.entries[0]?.error ?? null) : null;
    group.entries.sort(
      (a, b) =>
        Number(b.asset === options.defaultAsset) - Number(a.asset === options.defaultAsset) ||
        a.symbol.localeCompare(b.symbol),
    );
  }
  const rank = (group: NetworkBalances) =>
    group.testnet ? 2 : group.network === options.defaultNetwork ? 0 : 1;
  return [...groups.values()].sort(
    (a, b) => rank(a) - rank(b) || a.chainName.localeCompare(b.chainName),
  );
}

/** Whether a balance is exactly zero (so it can be shown quietly). */
export function isZeroBalance(entry: WalletBalanceEntry): boolean {
  return entry.balance_base_units === '0';
}
