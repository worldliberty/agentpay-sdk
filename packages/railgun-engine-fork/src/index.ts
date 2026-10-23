/**
 * Skeleton package for the AgentPay-internal fork of
 * `@railgun-community/engine`. The real fork is multi-week work and will
 * land in Track 3. Until then this module exports only a sentinel and a
 * typed throw helper so downstream code that accidentally imports from
 * here fails loudly with a clear message.
 *
 * See `./MAINTENANCE.md` for the upstream pin, rebase cadence, and the
 * exact files we plan to replace key-access calls inside.
 */

export const RAILGUN_ENGINE_FORK_STATUS = 'skeleton-not-vendored' as const;

export type RailgunEngineForkStatus = typeof RAILGUN_ENGINE_FORK_STATUS;

export function notVendoredYet(method: string): never {
  throw new Error(
    `${method} is not available: @worldlibertyfinancial/railgun-engine-fork is a skeleton. Track 3 vendoring (~10k lines from @railgun-community/engine) is pending; do not import from this package until that work lands.`,
  );
}
