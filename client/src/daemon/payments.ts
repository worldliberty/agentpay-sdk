/** Typed helpers for every payments service method, bound to one agent's credentials. */
import type {
  ActivityParams,
  ActivityResult,
  AddTokenParams,
  AddTokenResult,
  AgentAuth,
  ApproveParams,
  BroadcastParams,
  FundingRequestParams,
  FundingRequestResult,
  LookupTokenParams,
  MppFetchParams,
  PaymentsConfig,
  PaymentsRpcRequest,
  PaymentsRpcResponse,
  ProxyStartParams,
  ProxyStartResult,
  ProxyStatusResult,
  ResumeApprovedParams,
  SignTypedDataParams,
  StatusResult,
  TelemetryStatusResult,
  TokenInfo,
  TransferNativeParams,
  TransferParams,
  TransferSolParams,
  TransferSplParams,
  WalletBalanceEntry,
  WalletBalanceParams,
  WalletSummaryResult,
  X402FetchParams,
} from '../generated/index.js';
import { RpcClient, type RpcClientOptions, type Variant } from './rpc.js';

export type PaymentsRpc = RpcClient<PaymentsRpcRequest, PaymentsRpcResponse>;
type Params<T> = Omit<T, 'auth'>;

/** Results of the EVM payment methods. */
export type EvmPaymentResponse = Variant<
  PaymentsRpcResponse,
  'EvmSignature' | 'EvmTransaction' | 'ManualApprovalPending'
>;
export type SolanaPaymentResponse = Variant<
  PaymentsRpcResponse,
  'SolanaTransfer' | 'ManualApprovalPending'
>;

const SECOND = 1000;
const MAX_APPROVAL_WAIT_SECS = 600;
const MAX_RECEIPT_SECS = 120;

/** Client timeout for a call that may wait for an operator and for the chain. */
export function paymentTimeoutMs(options: {
  approvalWaitSecs?: number | undefined;
  receiptSecs?: number | undefined;
  networkSecs: number;
}): number {
  const approval = Math.min(options.approvalWaitSecs ?? 0, MAX_APPROVAL_WAIT_SECS);
  const receipt = Math.min(options.receiptSecs ?? 0, MAX_RECEIPT_SECS);
  return (approval + receipt + options.networkSecs + 15) * SECOND;
}

function evmTimeout(params: {
  approval_wait_secs?: number;
  wait_for_receipt: boolean;
  receipt_timeout_secs?: number;
}): number {
  return paymentTimeoutMs({
    approvalWaitSecs: params.approval_wait_secs,
    receiptSecs: params.wait_for_receipt ? (params.receipt_timeout_secs ?? 30) : 0,
    networkSecs: 60,
  });
}

/**
 * The payments service's methods that need no agent credentials (`LookupToken`), so setup can
 * use them before the wallet and its agent key exist. The socket's peer allowlist still applies.
 */
export class PublicPaymentsClient {
  readonly rpc: PaymentsRpc;

  constructor(options: RpcClientOptions | PaymentsRpc) {
    this.rpc = options instanceof RpcClient ? options : new RpcClient(options);
  }

  /** Reads a token from its network; changes nothing. */
  async lookupToken(params: LookupTokenParams): Promise<TokenInfo> {
    return (await this.rpc.call({ method: 'LookupToken', params }, ['TokenInfo'])).data;
  }
}

export class PaymentsClient {
  readonly rpc: PaymentsRpc;
  private readonly auth: AgentAuth;

  constructor(options: RpcClientOptions | PaymentsRpc, auth: AgentAuth) {
    this.rpc = options instanceof RpcClient ? options : new RpcClient(options);
    this.auth = auth;
  }

  /** The agent this client pays as. */
  get agentKeyId(): string {
    return this.auth.agent_key_id;
  }

  hello() {
    return this.rpc.hello();
  }

  async getConfig(): Promise<PaymentsConfig> {
    return (await this.rpc.call({ method: 'GetConfig', params: { auth: this.auth } }, ['Config']))
      .data;
  }

  async setConfig(config: PaymentsConfig): Promise<PaymentsConfig> {
    return (
      await this.rpc.call({ method: 'SetConfig', params: { auth: this.auth, config } }, ['Config'])
    ).data;
  }

  /** Reads a token from its network and adds it to the configuration (`AddToken`). */
  async addToken(params: Params<AddTokenParams>): Promise<AddTokenResult> {
    return (
      await this.rpc.call({ method: 'AddToken', params: { auth: this.auth, ...params } }, [
        'TokenAdded',
      ])
    ).data;
  }

  /** This agent's recent payments and approval requests (`Activity`). */
  async activity(params: Params<ActivityParams> = {}): Promise<ActivityResult> {
    return (
      await this.rpc.call({ method: 'Activity', params: { auth: this.auth, ...params } }, [
        'Activity',
      ])
    ).data;
  }

  async walletSummary(): Promise<WalletSummaryResult> {
    const response = await this.rpc.call(
      { method: 'WalletSummary', params: { auth: this.auth } },
      ['WalletSummary'],
      45 * SECOND,
    );
    return response.data;
  }

  async walletBalance(params: Params<WalletBalanceParams>): Promise<WalletBalanceEntry> {
    const response = await this.rpc.call(
      { method: 'WalletBalance', params: { ...params, auth: this.auth } },
      ['WalletBalance'],
      30 * SECOND,
    );
    return response.data;
  }

  async fundingRequest(params: Params<FundingRequestParams>): Promise<FundingRequestResult> {
    const response = await this.rpc.call(
      { method: 'FundingRequest', params: { ...params, auth: this.auth } },
      ['FundingRequest'],
    );
    return response.data;
  }

  async status(): Promise<StatusResult> {
    const response = await this.rpc.call(
      { method: 'Status', params: { auth: this.auth } },
      ['Status'],
      45 * SECOND,
    );
    return response.data;
  }

  transfer(params: Params<TransferParams>): Promise<EvmPaymentResponse> {
    return this.rpc.call(
      { method: 'Transfer', params: { ...params, auth: this.auth } },
      ['EvmSignature', 'EvmTransaction', 'ManualApprovalPending'],
      evmTimeout(params),
    );
  }

  transferNative(params: Params<TransferNativeParams>): Promise<EvmPaymentResponse> {
    return this.rpc.call(
      { method: 'TransferNative', params: { ...params, auth: this.auth } },
      ['EvmSignature', 'EvmTransaction', 'ManualApprovalPending'],
      evmTimeout(params),
    );
  }

  approve(params: Params<ApproveParams>): Promise<EvmPaymentResponse> {
    return this.rpc.call(
      { method: 'Approve', params: { ...params, auth: this.auth } },
      ['EvmSignature', 'EvmTransaction', 'ManualApprovalPending'],
      evmTimeout(params),
    );
  }

  broadcast(params: Params<BroadcastParams>): Promise<EvmPaymentResponse> {
    return this.rpc.call(
      { method: 'Broadcast', params: { ...params, auth: this.auth } },
      ['EvmTransaction', 'ManualApprovalPending'],
      evmTimeout(params),
    );
  }

  signTypedData(params: Params<SignTypedDataParams>): Promise<EvmPaymentResponse> {
    return this.rpc.call(
      { method: 'SignTypedData', params: { ...params, auth: this.auth } },
      ['EvmSignature', 'ManualApprovalPending'],
      paymentTimeoutMs({ approvalWaitSecs: params.approval_wait_secs, networkSecs: 15 }),
    );
  }

  resumeApproved(
    params: Params<ResumeApprovedParams>,
  ): Promise<EvmPaymentResponse | SolanaPaymentResponse> {
    return this.rpc.call(
      { method: 'ResumeApproved', params: { ...params, auth: this.auth } },
      ['EvmSignature', 'EvmTransaction', 'SolanaTransfer', 'ManualApprovalPending'],
      paymentTimeoutMs({
        approvalWaitSecs: params.approval_wait_secs,
        receiptSecs: MAX_RECEIPT_SECS,
        networkSecs: 60,
      }),
    );
  }

  transferSol(params: Params<TransferSolParams>): Promise<SolanaPaymentResponse> {
    return this.rpc.call(
      { method: 'TransferSol', params: { ...params, auth: this.auth } },
      ['SolanaTransfer', 'ManualApprovalPending'],
      paymentTimeoutMs({
        approvalWaitSecs: params.options.approval_wait_secs,
        receiptSecs: 30,
        networkSecs: 60,
      }),
    );
  }

  transferSpl(params: Params<TransferSplParams>): Promise<SolanaPaymentResponse> {
    return this.rpc.call(
      { method: 'TransferSpl', params: { ...params, auth: this.auth } },
      ['SolanaTransfer', 'ManualApprovalPending'],
      paymentTimeoutMs({
        approvalWaitSecs: params.options.approval_wait_secs,
        receiptSecs: 30,
        networkSecs: 60,
      }),
    );
  }

  async x402(params: Params<X402FetchParams>) {
    const response = await this.rpc.call(
      { method: 'X402Fetch', params: { ...params, auth: this.auth } },
      ['X402Response'],
      paymentTimeoutMs({ approvalWaitSecs: params.approval_wait_secs, networkSecs: 180 }),
    );
    return response.data;
  }

  async mpp(params: Params<MppFetchParams>) {
    const response = await this.rpc.call(
      { method: 'MppFetch', params: { ...params, auth: this.auth } },
      ['MppResponse'],
      paymentTimeoutMs({ approvalWaitSecs: params.approval_wait_secs, networkSecs: 300 }),
    );
    return response.data;
  }

  async proxyStart(params: Params<ProxyStartParams>): Promise<ProxyStartResult> {
    const response = await this.rpc.call(
      { method: 'ProxyStart', params: { ...params, auth: this.auth } },
      ['ProxyStarted'],
    );
    return response.data;
  }

  async proxyStop(): Promise<ProxyStatusResult> {
    return (
      await this.rpc.call({ method: 'ProxyStop', params: { auth: this.auth } }, ['ProxyStatus'])
    ).data;
  }

  async proxyStatus(): Promise<ProxyStatusResult> {
    return (
      await this.rpc.call({ method: 'ProxyStatus', params: { auth: this.auth } }, ['ProxyStatus'])
    ).data;
  }

  async telemetryStatus(): Promise<TelemetryStatusResult> {
    return (
      await this.rpc.call({ method: 'TelemetryStatus', params: { auth: this.auth } }, [
        'TelemetryStatus',
      ])
    ).data;
  }

  async setTelemetry(enabled: boolean): Promise<TelemetryStatusResult> {
    return (
      await this.rpc.call({ method: 'SetTelemetry', params: { auth: this.auth, enabled } }, [
        'TelemetryStatus',
      ])
    ).data;
  }
}
