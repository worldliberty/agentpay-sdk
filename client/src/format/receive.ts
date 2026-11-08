/**
 * What can be received: every configured token on every network, as choices for the Receive
 * screen. The wallet has one address per chain family, so every token on a network shares it.
 */
import type { PaymentsConfig } from '../generated/index.js';
import { hasNativeAsset, isTestnetChain } from '../limits/model.js';

export interface ReceiveOption {
  /** `<network>/<asset>`, unique. */
  id: string;
  /** Payments config keys, as `FundingRequest` takes them. */
  network: string;
  asset: string;
  symbol: string;
  networkName: string;
  testnet: boolean;
}

/**
 * The receivable assets, the default network and asset first, then main networks before test
 * networks. Test networks are left out unless `includeTestnets`.
 */
export function receiveOptions(
  config: PaymentsConfig,
  { includeTestnets }: { includeTestnets: boolean },
): ReceiveOption[] {
  const options: ReceiveOption[] = [];
  for (const [asset, token] of Object.entries(config.tokens)) {
    for (const [network, deployment] of Object.entries(token.chains)) {
      const chain = config.chains[network];
      const testnet = isTestnetChain(deployment.chain_id);
      if (
        !chain ||
        (testnet && !includeTestnets) ||
        (deployment.is_native && !hasNativeAsset(deployment.chain_id))
      ) {
        continue;
      }
      options.push({
        id: `${network}/${asset}`,
        network,
        asset,
        symbol: token.symbol,
        networkName: chain.name,
        testnet,
      });
    }
  }
  const rank = (option: ReceiveOption) =>
    (option.network === config.default_network ? 0 : 2) +
    (option.asset === config.default_asset ? 0 : 1) +
    (option.testnet ? 4 : 0);
  return options.sort(
    (a, b) =>
      rank(a) - rank(b) ||
      a.networkName.localeCompare(b.networkName) ||
      a.symbol.localeCompare(b.symbol),
  );
}
