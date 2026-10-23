import type {
  BalanceMutationAction,
  BalanceMutationEvent,
  BalanceMutationResult,
} from './telemetry.js';

/**
 * Maps the Rust agent subcommand to an analytics action. Subcommands absent from this table are
 * read-only and produce no event.
 */
const TRACKED_ACTIONS: Readonly<Record<string, BalanceMutationAction>> = {
  approve: 'approve',
  broadcast: 'broadcast',
  'eip3009-transfer-with-authorization': 'x402',
  'private-transfer': 'private_transfer',
  shield: 'shield',
  'solana-sol-transfer': 'transfer_sol',
  'solana-spl-transfer': 'transfer_spl',
  'tempo-session-open-transaction': 'mpp',
  'tempo-session-top-up-transaction': 'mpp',
  'tempo-session-voucher': 'mpp',
  transfer: 'transfer',
  'transfer-native': 'transfer_native',
  unshield: 'unshield',
};

/**
 * Maps the top-level `agentpay` command to an analytics action. The Rust subcommand alone is
 * ambiguous: `transfer --broadcast` signs through the generic `broadcast` subcommand, so a failure
 * there would be counted as a `broadcast` while its success is recorded as a `transfer`.
 */
const COMMAND_ACTIONS: Readonly<Record<string, BalanceMutationAction>> = {
  approve: 'approve',
  mpp: 'mpp',
  'private-transfer': 'private_transfer',
  shield: 'shield',
  transfer: 'transfer',
  'transfer-native': 'transfer_native',
  'transfer-sol': 'transfer_sol',
  'transfer-spl': 'transfer_spl',
  unshield: 'unshield',
  x402: 'x402',
};

const AMOUNT_FLAGS = ['--amount-wei', '--value-wei', '--amount-lamports', '--amount'] as const;

let commandPath: readonly string[] = [];

/**
 * Records the commander path of the running command (`['transfer']`, `['config', 'set']`). Called
 * once per invocation from the root `preAction` hook, before any Rust binary is spawned.
 */
export function setTelemetryCommandContext(nextCommandPath: readonly string[]): void {
  commandPath = [...nextCommandPath];
}

/**
 * Only a mutating Rust subcommand can move a balance, so that decides whether an event exists at
 * all; a read-only step inside a tracked command (typed-data signing in `mpp`, say) must not be
 * counted as one. The top-level command then decides what the event is called.
 */
export function resolveBalanceMutationAction(
  commandArgs: readonly string[],
): BalanceMutationAction | undefined {
  const rustAction = TRACKED_ACTIONS[commandArgs[0] ?? ''];
  if (!rustAction) {
    return undefined;
  }

  return COMMAND_ACTIONS[commandPath[0] ?? ''] ?? rustAction;
}

function readFlag(commandArgs: readonly string[], flag: string): string | undefined {
  const index = commandArgs.indexOf(flag);
  if (index < 0) {
    return undefined;
  }

  return commandArgs[index + 1];
}

function readAmountUnits(
  commandArgs: readonly string[],
  decimals: number | undefined,
): number | undefined {
  if (decimals === undefined) {
    return undefined;
  }

  for (const flag of AMOUNT_FLAGS) {
    const raw = readFlag(commandArgs, flag);
    if (raw === undefined) {
      continue;
    }

    try {
      return toUnits(BigInt(raw), decimals);
    } catch {
      return undefined;
    }
  }

  return undefined;
}

export interface AgentCommandTelemetryContext {
  assetDecimals?: number;
  assetSymbol?: string;
  broadcast?: boolean;
  /**
   * Explicit amount in base units. Required for ERC-20 broadcasts, where the transfer amount lives
   * in the encoded calldata and `--value-wei` is zero.
   */
  amountWei?: bigint;
}

function toUnits(amountWei: bigint, decimals: number): number {
  return Number(amountWei) / 10 ** decimals;
}

/**
 * Builds a `balance_mutation` event from the argv handed to the Rust agent binary. Returns
 * undefined for subcommands that cannot change a balance. The amount is exact here and is
 * bucketed by `trackBalanceMutation` before it leaves the process.
 */
export function describeAgentCommand(
  commandArgs: readonly string[],
  result: BalanceMutationResult,
  context: AgentCommandTelemetryContext = {},
): BalanceMutationEvent | undefined {
  const action = resolveBalanceMutationAction(commandArgs);
  if (!action) {
    return undefined;
  }

  const chainId = Number(readFlag(commandArgs, '--network'));
  const amount =
    context.amountWei !== undefined && context.assetDecimals !== undefined
      ? toUnits(context.amountWei, context.assetDecimals)
      : readAmountUnits(commandArgs, context.assetDecimals);

  return {
    action,
    amount,
    asset: context.assetSymbol,
    broadcast: context.broadcast ?? false,
    chainId: Number.isFinite(chainId) ? chainId : undefined,
    result,
  };
}
