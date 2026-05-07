import type { Command } from 'commander';
import type { Address, Hex } from 'viem';
import type { WlfiConfig } from '../../packages/config/src/index.js';
import type {
  AssetBroadcastPlan,
  AssetBroadcastPlanInput,
  CompleteAssetBroadcastDeps,
  CompletedAssetBroadcast,
  ResolveAssetBroadcastPlanDeps,
} from '../lib/asset-broadcast.js';
import type { ResolvedAssetMetadata, RustAmountOutputShape } from '../lib/config-amounts.js';
import type {
  SolanaComputeBudget,
  SolanaSolTransferContext,
  SolanaTransferContext,
} from '../lib/solana-transfer.js';

export interface CliPluginContext {
  cli: {
    print: (payload: unknown, asJson: boolean) => void;
    setExitCode: (code: number) => void;
    addAgentCommandAuthOptions: (command: Command) => Command;
  };
  config: {
    readConfig: () => WlfiConfig;
    resolveCliRpcUrl: (rpcUrl: string | undefined, network: string, config: WlfiConfig) => string;
    resolveWalletAddress: (config: WlfiConfig) => Address;
  };
  values: {
    assertAddress: (value: string, label: string) => Address;
    parseBigIntString: (value: string, label: string) => bigint;
    parseIntegerString: (value: string, label: string) => number;
    parsePositiveBigIntString: (value: string, label: string) => bigint;
    parsePositiveIntegerString: (value: string, label: string) => number;
  };
  agent: {
    runJson: <T>(input: {
      commandArgs: string[] | (() => Promise<string[]> | string[]);
      auth: Record<string, unknown>;
      config: WlfiConfig;
      asJson: boolean;
      waitForManualApproval?: boolean;
    }) => Promise<T | null>;
    rewriteAmountError: (error: unknown, asset: ResolvedAssetMetadata) => Error;
  };
  broadcast: {
    resolvePlan: (
      input: AssetBroadcastPlanInput,
      deps: ResolveAssetBroadcastPlanDeps,
    ) => Promise<AssetBroadcastPlan>;
    resolvePlanDeps: ResolveAssetBroadcastPlanDeps;
    complete: (
      plan: AssetBroadcastPlan,
      signed: RustAmountOutputShape,
      deps: CompleteAssetBroadcastDeps,
    ) => Promise<CompletedAssetBroadcast>;
    completeDeps: CompleteAssetBroadcastDeps;
    formatOutput: (input: {
      command: string;
      counterparty: Address;
      asset: ResolvedAssetMetadata;
      signed: RustAmountOutputShape;
      plan: AssetBroadcastPlan;
      signedNonce?: number;
      networkTxHash: Hex;
      revealRawTx: boolean;
      revealSignature: boolean;
    }) => unknown;
    reportOnchainReceiptStatus: (input: {
      rpcUrl: string;
      txHash: Hex;
      asJson: boolean;
    }) => Promise<void>;
  };
  solana: {
    resolveWalletAddress: (config: WlfiConfig) => Promise<string> | string;
    resolveSolTransferContext: (input: {
      rpcUrl: string;
      feePayer: string;
      recipient: string;
    }) => Promise<SolanaSolTransferContext>;
    resolveSplTransferContext: (input: {
      rpcUrl: string;
      feePayer: string;
      mint: string;
      recipientOwner: string;
    }) => Promise<SolanaTransferContext>;
    resolveTransferFee: (input: {
      rpcUrl: string;
      mint: string;
      tokenProgram: SolanaTransferContext['tokenProgram'];
      amountWei: bigint;
    }) => Promise<{ transferInstruction: string; transferFeeWei: string | null }>;
    resolveComputeBudget: (input: {
      rpcUrl: string;
      defaultComputeUnitLimit: number;
      computeUnitLimit?: string;
      computeUnitPriceMicroLamports?: string;
    }) => Promise<SolanaComputeBudget>;
    resolveDurableNonceForBroadcast: (input: {
      rpcUrl: string;
      chainId: string | number;
      recentBlockhash: string;
      feePayer: string;
      explicitNonceAccount?: string;
      auth: Record<string, unknown>;
      config: WlfiConfig;
      asJson: boolean;
    }) => Promise<{ nonceAccount: string; nonceAuthority: string; nonce: string }>;
    broadcastSignedTransaction: (
      rpcUrl: string,
      signedTransactionBase64: string,
    ) => Promise<string>;
    reportSignatureStatus: (input: {
      rpcUrl: string;
      signature: string;
      asJson: boolean;
    }) => Promise<void>;
    defaults: {
      solTransferComputeUnitLimit: number;
      splTransferComputeUnitLimit: number;
    };
  };
  exitCodes: {
    challengeRequired: number;
    waitTimeout: number;
  };
}

export interface CliPlugin {
  name: string;
  register: (program: Command, context: CliPluginContext) => void;
}

export function registerCliPlugins(
  program: Command,
  context: CliPluginContext,
  plugins: readonly CliPlugin[],
): void {
  for (const plugin of plugins) {
    plugin.register(program, context);
  }
}
