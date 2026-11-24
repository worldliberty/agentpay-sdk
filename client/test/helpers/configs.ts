import type { PaymentsConfig } from '../../src/generated/index.js';
import { DEFAULT_PAYMENTS_CONFIG } from '../../src/limits/default-config.js';

/**
 * The built-in configuration with ETH's recommended limits removed, like a token added without
 * a recommendation: its rows start undecided (`unset`), so setup asks about each one.
 */
export function withoutEthLimits(): PaymentsConfig {
  const config = structuredClone(DEFAULT_PAYMENTS_CONFIG);
  const eth = config.tokens.eth;
  if (!eth) {
    throw new Error('the built-in configuration has no ETH');
  }
  eth.recommended_limits = null;
  return config;
}
