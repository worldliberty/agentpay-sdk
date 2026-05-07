import type { WlfiConfig } from '../../packages/config/src/index.js';
import {
  formatConfiguredAmount,
  normalizeAgentAmountOutput,
  parseConfiguredAmount,
} from '../lib/config-amounts.js';
import {
  createSolayerClient,
  deleteStoredSolayerSession,
  parseSolayerSignature,
  readStoredSolayerSession,
  redactSolayerSensitiveFields,
  resolveSolayerNetwork,
  SolayerCardLimitPeriod,
  SolayerCardType,
  type SolayerClient,
  SolayerEmailType,
  SolayerSignatureMessageType,
  storeSolayerSession,
} from '../lib/solayer.js';
import type { CliPlugin, CliPluginContext } from './types.js';

const SOLAYER_USDC_MAINNET_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';

interface JsonOptions {
  json: boolean;
}

interface NetworkOptions extends JsonOptions {
  network?: string;
}

interface SolayerWalletLoginOptions extends NetworkOptions, Record<string, unknown> {}

interface SolayerExternalPrepareOptions extends NetworkOptions {
  address: string;
  transaction: boolean;
}

interface SolayerExternalVerifyOptions extends NetworkOptions {
  address: string;
  messageId: string;
  signature: string;
  walletName?: string;
  txB64?: string;
}

interface SolayerEmailLoginOptions extends NetworkOptions {
  email: string;
}

interface SolayerEmailVerifyOptions extends NetworkOptions {
  sessionId: string;
  otp: string;
  signup: boolean;
}

interface SolayerSocialLoginOptions extends JsonOptions {
  provider: 'google' | 'apple';
  tokenStdin: boolean;
  signup: boolean;
}

interface SolayerFundOptions extends NetworkOptions, Record<string, unknown> {
  amount: string;
  broadcast: boolean;
  rpcUrl?: string;
  feePayer?: string;
  mint?: string;
  durableNonceAccount?: string;
  computeUnitLimit?: string;
  computeUnitPriceMicroLamports?: string;
  wait: boolean;
  revealRawTx: boolean;
}

interface SolayerCreateCardOptions extends NetworkOptions {
  name?: string;
  limitPeriod?: string;
  limitUsd?: string;
  revealSensitive: boolean;
}

interface SolayerCardIdOptions extends NetworkOptions {
  cardId: string;
  revealSensitive: boolean;
  tfaSessionId?: string;
}

interface SolayerCardTransactionsOptions extends NetworkOptions {
  cardId?: string;
  start?: string;
  end?: string;
  pageSize?: string;
  page?: string;
}

function requireString(value: string | undefined, label: string): string {
  const normalized = value?.trim();
  if (!normalized) {
    throw new Error(`${label} is required`);
  }
  return normalized;
}

function parseLimitPeriod(value: string | undefined): SolayerCardLimitPeriod | undefined {
  const normalized = value?.trim().toLowerCase();
  if (!normalized) {
    return undefined;
  }
  switch (normalized) {
    case 'day':
      return SolayerCardLimitPeriod.Day;
    case 'week':
      return SolayerCardLimitPeriod.Week;
    case 'month':
      return SolayerCardLimitPeriod.Month;
    case 'year':
      return SolayerCardLimitPeriod.Year;
    case 'total':
      return SolayerCardLimitPeriod.Total;
    default:
      throw new Error('--limit-period must be one of day, week, month, year, total');
  }
}

function writeSolayerOutput(
  context: CliPluginContext,
  value: unknown,
  options: { json: boolean; revealSensitive?: boolean },
): void {
  context.cli.print(redactSolayerSensitiveFields(value, options.revealSensitive), options.json);
}

function solayerClient(): SolayerClient {
  return createSolayerClient();
}

async function readSecretFromStdin(label: string): Promise<string> {
  if (process.stdin.isTTY) {
    throw new Error(`${label} must be provided with --token-stdin`);
  }
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const value = Buffer.concat(chunks).toString('utf8').trim();
  if (!value) {
    throw new Error(`${label} is required on stdin`);
  }
  return value;
}

async function completeAuthSession(input: {
  client: SolayerClient;
  sessionId: string;
  exists: boolean;
  signup: boolean;
}) {
  if (!input.exists && !input.signup) {
    throw new Error('Solayer account does not exist; rerun with --signup to create it');
  }
  const result = input.exists
    ? await input.client.signIn(input.sessionId)
    : await input.client.signUp(input.sessionId);
  if (!result.token) {
    throw new Error('Solayer did not return a session token');
  }
  return storeSolayerSession({
    token: result.token,
    deviceId: input.client.deviceId,
  });
}

function resolveSolayerUsdcMint(
  config: WlfiConfig,
  network: string | undefined,
  override?: string,
): string {
  const explicit = override?.trim();
  if (explicit) {
    return explicit;
  }
  const networkKey = network?.trim() || 'solana-mainnet';
  const configured = config.tokens?.usdc?.chains?.[networkKey]?.address?.trim();
  return configured || SOLAYER_USDC_MAINNET_MINT;
}

function solayerNetworkSelector(network: string | undefined): string {
  return network?.trim() || 'solana-mainnet';
}

function solayerChainId(network: string | undefined): number {
  return solayerNetworkSelector(network) === 'solana-testnet' ? 900000003 : 900000001;
}

function humanAmountFromBaseUnits(amountWei: bigint, decimals: number): string {
  return formatConfiguredAmount(amountWei, decimals);
}

async function runSolayerWalletLogin(
  context: CliPluginContext,
  options: SolayerWalletLoginOptions,
) {
  const config = context.config.readConfig();
  const address = await context.solana.resolveWalletAddress(config);
  const client = solayerClient();
  const network = resolveSolayerNetwork(options.network);
  const prepared = await client.getSignatureMessage({
    network,
    address,
    messageType: SolayerSignatureMessageType.WalletMessage,
  });
  if (!prepared.message || !prepared.messageId) {
    throw new Error('Solayer did not return a wallet login challenge');
  }
  const signed = await context.agent.runJson<{
    command: string;
    network: string;
    asset: string;
    counterparty: string;
    amount_wei: string;
    signature_hex: string;
    signature_base58?: string;
  }>({
    commandArgs: [
      'solana-message-sign',
      '--network',
      String(solayerChainId(options.network)),
      '--address',
      address,
      '--domain',
      'solayer',
      '--message',
      prepared.message,
    ],
    auth: options,
    config,
    asJson: options.json,
    waitForManualApproval: true,
  });
  if (!signed) {
    return;
  }
  const signature = signed.signature_base58 ?? signed.signature_hex;
  if (!signature) {
    throw new Error('Rust agent did not return a Solayer wallet signature');
  }
  const verified = await client.verifySignature({
    network,
    address,
    signature: parseSolayerSignature(signature),
    messageId: prepared.messageId,
    walletName: 'AgentPay',
  });
  const stored = storeSolayerSession({
    token: verified.token,
    deviceId: client.deviceId,
  });
  writeSolayerOutput(
    context,
    {
      authenticated: true,
      address,
      updatedAt: stored.updatedAt,
      deviceId: stored.deviceId,
    },
    options,
  );
}

async function runSolayerFund(context: CliPluginContext, options: SolayerFundOptions) {
  const config = context.config.readConfig();
  const networkSelector = solayerNetworkSelector(options.network);
  const network = resolveSolayerNetwork(networkSelector);
  const rpcUrl = context.config.resolveCliRpcUrl(options.rpcUrl, networkSelector, config);
  const client = solayerClient();
  const { depositAddress } = await client.getDepositAddress(network);
  const mint = resolveSolayerUsdcMint(config, networkSelector, options.mint);
  const feePayer = options.feePayer?.trim() || (await context.solana.resolveWalletAddress(config));
  const transferContext = await context.solana.resolveSplTransferContext({
    rpcUrl,
    feePayer,
    mint,
    recipientOwner: depositAddress,
  });
  const amountWei = parseConfiguredAmount(options.amount, transferContext.asset.decimals, 'amount');
  const computeBudget = await context.solana.resolveComputeBudget({
    rpcUrl,
    defaultComputeUnitLimit: context.solana.defaults.splTransferComputeUnitLimit,
    computeUnitLimit: options.computeUnitLimit,
    computeUnitPriceMicroLamports: options.computeUnitPriceMicroLamports,
  });
  const transferFee = await context.solana.resolveTransferFee({
    rpcUrl,
    mint: transferContext.mint,
    tokenProgram: transferContext.tokenProgram,
    amountWei,
  });
  const resolveDurableNonce = () =>
    options.broadcast || options.durableNonceAccount
      ? context.solana.resolveDurableNonceForBroadcast({
          rpcUrl,
          chainId: solayerChainId(networkSelector),
          recentBlockhash: transferContext.recentBlockhash,
          feePayer: transferContext.feePayer,
          explicitNonceAccount: options.durableNonceAccount,
          auth: options,
          config,
          asJson: options.json,
        })
      : Promise.resolve(null);

  const signed = await context.agent.runJson<{
    command: string;
    network: string;
    asset: string;
    counterparty: string;
    amount_wei: string;
    signature_hex: string;
    signature_base58?: string;
    raw_tx_base64?: string;
    tx_id?: string;
  }>({
    commandArgs: async () => {
      const durableNonce = await resolveDurableNonce();
      return [
        'solana-spl-transfer',
        '--network',
        String(solayerChainId(networkSelector)),
        '--recent-blockhash',
        durableNonce?.nonce ?? transferContext.recentBlockhash,
        ...(durableNonce ? ['--durable-nonce-account', durableNonce.nonceAccount] : []),
        '--fee-payer',
        transferContext.feePayer,
        '--mint',
        transferContext.mint,
        '--recipient-owner',
        transferContext.recipientOwner,
        '--amount-wei',
        amountWei.toString(),
        '--decimals',
        String(transferContext.asset.decimals),
        '--token-program',
        transferContext.tokenProgram,
        ...(transferFee.transferFeeWei ? ['--transfer-fee-wei', transferFee.transferFeeWei] : []),
        ...(computeBudget.computeUnitLimit
          ? ['--compute-unit-limit', computeBudget.computeUnitLimit]
          : []),
        ...(computeBudget.computeUnitPriceMicroLamports
          ? ['--compute-unit-price-micro-lamports', computeBudget.computeUnitPriceMicroLamports]
          : []),
      ];
    },
    auth: options,
    config,
    asJson: options.json,
    waitForManualApproval: options.broadcast,
  });
  if (!signed) {
    return;
  }

  const normalized = normalizeAgentAmountOutput(signed, transferContext.asset);
  if (!options.broadcast) {
    writeSolayerOutput(
      context,
      {
        mode: 'preview',
        depositAddress,
        network: networkSelector,
        mint,
        amount: humanAmountFromBaseUnits(amountWei, transferContext.asset.decimals),
        amountBaseUnits: amountWei.toString(),
        transfer: normalized,
      },
      options,
    );
    return;
  }

  if (!signed.raw_tx_base64) {
    throw new Error('Rust agent did not return raw_tx_base64 for Solayer funding transfer');
  }
  const networkTxId = await context.solana.broadcastSignedTransaction(rpcUrl, signed.raw_tx_base64);
  writeSolayerOutput(
    context,
    {
      mode: 'broadcast',
      depositAddress,
      network: networkSelector,
      mint,
      amount: humanAmountFromBaseUnits(amountWei, transferContext.asset.decimals),
      amountBaseUnits: amountWei.toString(),
      txId: signed.tx_id ?? null,
      networkTxId,
      rawTxBase64: options.revealRawTx ? signed.raw_tx_base64 : undefined,
      transfer: normalized,
    },
    options,
  );
  if (options.wait) {
    await context.solana.reportSignatureStatus({
      rpcUrl,
      signature: networkTxId,
      asJson: options.json,
    });
  }
}

export const solayerCliPlugin: CliPlugin = {
  name: 'solayer',
  register(program, context) {
    const solayer = program
      .command('solayer')
      .description('Solayer Pay account, funding, and card operations');

    const session = solayer.command('session').description('Manage Solayer session state');
    session
      .command('status')
      .option('--json', 'Print JSON output', false)
      .action((options: JsonOptions) => {
        const stored = readStoredSolayerSession();
        writeSolayerOutput(
          context,
          {
            authenticated: Boolean(stored),
            updatedAt: stored?.updatedAt ?? null,
            deviceId: stored?.deviceId ?? null,
          },
          options,
        );
      });
    session
      .command('logout')
      .option('--json', 'Print JSON output', false)
      .action(async (options: JsonOptions) => {
        const client = solayerClient();
        const hadSession = Boolean(readStoredSolayerSession());
        if (hadSession) {
          try {
            await client.logout();
          } catch {}
        }
        const removed = deleteStoredSolayerSession();
        writeSolayerOutput(context, { removed }, options);
      });

    const login = solayer.command('login').description('Authenticate with Solayer');
    context.cli
      .addAgentCommandAuthOptions(
        login
          .command('wallet')
          .description('Login with the local AgentPay Solana wallet')
          .option('--network <name>', 'Solayer network', 'solana-mainnet'),
      )
      .action(async (options: SolayerWalletLoginOptions) => {
        await runSolayerWalletLogin(context, options);
      });

    const externalWallet = login
      .command('external-wallet')
      .description('Login with an externally signed Solayer wallet challenge');
    externalWallet
      .command('prepare')
      .requiredOption('--address <address>', 'Solana wallet address')
      .option('--network <name>', 'Solayer network', 'solana-mainnet')
      .option(
        '--transaction',
        'Prepare a wallet transaction challenge instead of a message challenge',
        false,
      )
      .option('--json', 'Print JSON output', false)
      .action(async (options: SolayerExternalPrepareOptions) => {
        const client = solayerClient();
        const prepared = await client.getSignatureMessage({
          network: resolveSolayerNetwork(options.network),
          address: options.address,
          messageType: options.transaction
            ? SolayerSignatureMessageType.WalletTransaction
            : SolayerSignatureMessageType.WalletMessage,
        });
        writeSolayerOutput(
          context,
          {
            ...prepared,
            address: options.address,
            network: options.network ?? 'solana-mainnet',
            mode: options.transaction ? 'transaction' : 'message',
          },
          options,
        );
      });
    externalWallet
      .command('verify')
      .requiredOption('--address <address>', 'Solana wallet address')
      .requiredOption('--message-id <id>', 'Solayer message id returned by prepare')
      .requiredOption('--signature <signature>', 'Signature as hex or base58')
      .option('--wallet-name <name>', 'Wallet name sent to Solayer', 'AgentPay')
      .option('--tx-b64 <tx>', 'Signed Solana transaction base64 for transaction challenges')
      .option('--network <name>', 'Solayer network', 'solana-mainnet')
      .option('--json', 'Print JSON output', false)
      .action(async (options: SolayerExternalVerifyOptions) => {
        const client = solayerClient();
        const verified = await client.verifySignature({
          network: resolveSolayerNetwork(options.network),
          address: options.address,
          signature: parseSolayerSignature(options.signature),
          messageId: options.messageId,
          walletName: options.walletName ?? 'AgentPay',
          txB64: options.txB64,
        });
        const stored = storeSolayerSession({
          token: verified.token,
          deviceId: client.deviceId,
        });
        writeSolayerOutput(
          context,
          {
            authenticated: true,
            updatedAt: stored.updatedAt,
            deviceId: stored.deviceId,
          },
          options,
        );
      });

    const email = login.command('email').description('Login with Solayer email OTP');
    email
      .command('start')
      .requiredOption('--email <email>', 'Email address')
      .option('--network <name>', 'Solayer network', 'solana-mainnet')
      .option('--json', 'Print JSON output', false)
      .action(async (options: SolayerEmailLoginOptions) => {
        const response = await solayerClient().sendEmail({
          network: resolveSolayerNetwork(options.network),
          email: options.email,
          emailType: SolayerEmailType.Login,
        });
        writeSolayerOutput(context, response, options);
      });
    email
      .command('verify')
      .requiredOption('--session-id <id>', 'OTP session id')
      .requiredOption('--otp <code>', 'Email OTP')
      .option('--signup', 'Create the Solayer account if it does not exist', false)
      .option('--network <name>', 'Solayer network', 'solana-mainnet')
      .option('--json', 'Print JSON output', false)
      .action(async (options: SolayerEmailVerifyOptions) => {
        const client = solayerClient();
        const verified = await client.verifyEmailOtp({
          network: resolveSolayerNetwork(options.network),
          sessionId: options.sessionId,
          otp: options.otp,
          emailType: SolayerEmailType.Login,
        });
        const account = await client.checkAccount({ emailToken: verified.sessionId });
        const stored = await completeAuthSession({
          client,
          sessionId: account.sessionId,
          exists: account.exists,
          signup: options.signup,
        });
        writeSolayerOutput(
          context,
          {
            authenticated: true,
            created: !account.exists,
            updatedAt: stored.updatedAt,
            deviceId: stored.deviceId,
          },
          options,
        );
      });

    login
      .command('social')
      .requiredOption('--provider <provider>', 'google or apple')
      .requiredOption('--token-stdin', 'Read provider token from stdin')
      .option('--signup', 'Create the Solayer account if it does not exist', false)
      .option('--json', 'Print JSON output', false)
      .action(async (options: SolayerSocialLoginOptions) => {
        const provider = requireString(options.provider, '--provider').toLowerCase();
        if (provider !== 'google' && provider !== 'apple') {
          throw new Error('--provider must be google or apple');
        }
        const token = await readSecretFromStdin(`${provider} token`);
        const client = solayerClient();
        const account = await client.checkAccount(
          provider === 'google' ? { googleToken: token } : { appleToken: token },
        );
        const stored = await completeAuthSession({
          client,
          sessionId: account.sessionId,
          exists: account.exists,
          signup: options.signup,
        });
        writeSolayerOutput(
          context,
          {
            authenticated: true,
            created: !account.exists,
            updatedAt: stored.updatedAt,
            deviceId: stored.deviceId,
          },
          options,
        );
      });

    solayer
      .command('account')
      .option('--json', 'Print JSON output', false)
      .action(async (options: JsonOptions) => {
        writeSolayerOutput(context, await solayerClient().getAccountInfo(), options);
      });

    solayer
      .command('deposit-address')
      .option('--network <name>', 'Solayer network', 'solana-mainnet')
      .option('--json', 'Print JSON output', false)
      .action(async (options: NetworkOptions) => {
        writeSolayerOutput(
          context,
          await solayerClient().getDepositAddress(resolveSolayerNetwork(options.network)),
          options,
        );
      });

    context.cli
      .addAgentCommandAuthOptions(
        solayer
          .command('fund')
          .requiredOption('--amount <amount>', 'USDC amount to send to the Solayer deposit address')
          .option('--network <name>', 'Solayer network', 'solana-mainnet')
          .option('--mint <address>', 'Override Solana USDC mint')
          .option(
            '--broadcast',
            'Broadcast the funding transfer through the AgentPay daemon path',
            false,
          )
          .option('--rpc-url <url>', 'Solana RPC URL override used only for broadcast')
          .option(
            '--fee-payer <address>',
            'Fee payer override; defaults to configured AgentPay Solana wallet',
          )
          .option('--durable-nonce-account <address>', 'Internal Solana nonce account override')
          .option('--compute-unit-limit <units>', 'Optional compute unit limit override')
          .option(
            '--compute-unit-price-micro-lamports <price>',
            'Optional compute unit price override',
          )
          .option('--no-wait', 'Do not wait up to 30s for signature confirmation after broadcast')
          .option(
            '--reveal-raw-tx',
            'Include the signed raw transaction bytes in broadcast output',
            false,
          ),
      )
      .action(async (options: SolayerFundOptions) => {
        await runSolayerFund(context, options);
      });

    const kyc = solayer.command('kyc').description('Manage Solayer KYC state');
    kyc
      .command('status')
      .option('--network <name>', 'Solayer network', 'solana-mainnet')
      .option('--json', 'Print JSON output', false)
      .action(async (options: NetworkOptions) => {
        writeSolayerOutput(
          context,
          await solayerClient().getKycInfo(resolveSolayerNetwork(options.network)),
          options,
        );
      });
    kyc
      .command('link')
      .option('--network <name>', 'Solayer network', 'solana-mainnet')
      .option('--json', 'Print JSON output', false)
      .action(async (options: NetworkOptions) => {
        writeSolayerOutput(
          context,
          await solayerClient().getKycAuth(resolveSolayerNetwork(options.network)),
          options,
        );
      });
    kyc
      .command('email')
      .requiredOption('--email <email>', 'KYC email address')
      .option('--network <name>', 'Solayer network', 'solana-mainnet')
      .option('--json', 'Print JSON output', false)
      .action(async (options: SolayerEmailLoginOptions) => {
        writeSolayerOutput(
          context,
          await solayerClient().sendEmail({
            network: resolveSolayerNetwork(options.network),
            email: options.email,
            emailType: SolayerEmailType.Kyc,
          }),
          options,
        );
      });
    kyc
      .command('email-verify')
      .requiredOption('--session-id <id>', 'OTP session id')
      .requiredOption('--otp <code>', 'Email OTP')
      .option('--network <name>', 'Solayer network', 'solana-mainnet')
      .option('--json', 'Print JSON output', false)
      .action(async (options: SolayerEmailVerifyOptions) => {
        writeSolayerOutput(
          context,
          await solayerClient().verifyEmailOtp({
            network: resolveSolayerNetwork(options.network),
            sessionId: options.sessionId,
            otp: options.otp,
            emailType: SolayerEmailType.Kyc,
          }),
          options,
        );
      });

    const protocol = solayer.command('protocol').description('Accept Solayer protocols');
    protocol
      .command('accept')
      .option('--kyc', 'Accept KYC protocol', false)
      .option('--card', 'Accept card protocol', false)
      .option('--json', 'Print JSON output', false)
      .action(async (options: JsonOptions & { kyc?: boolean; card?: boolean }) => {
        if (!options.kyc && !options.card) {
          throw new Error('choose --kyc or --card');
        }
        await solayerClient().acceptProtocol({ kyc: options.kyc, card: options.card });
        writeSolayerOutput(context, { accepted: options.kyc ? 'kyc' : 'card' }, options);
      });

    const application = solayer
      .command('application')
      .description('Manage Solayer card application');
    for (const commandName of ['status', 'create', 'update'] as const) {
      application
        .command(commandName)
        .option('--network <name>', 'Solayer network', 'solana-mainnet')
        .option('--json', 'Print JSON output', false)
        .action(async (options: NetworkOptions) => {
          const client = solayerClient();
          const network = resolveSolayerNetwork(options.network);
          const response =
            commandName === 'create'
              ? await client.createApplication(network)
              : commandName === 'update'
                ? await client.updateApplication(network)
                : await client.getApplication(network);
          writeSolayerOutput(context, response, options);
        });
    }

    const card = solayer.command('card').description('Manage Solayer cards');
    card
      .command('list')
      .option('--network <name>', 'Solayer network', 'solana-mainnet')
      .option('--json', 'Print JSON output', false)
      .action(async (options: NetworkOptions) => {
        writeSolayerOutput(
          context,
          await solayerClient().getCards({ network: resolveSolayerNetwork(options.network) }),
          options,
        );
      });
    card
      .command('create')
      .option('--name <name>', 'Card display name')
      .option('--limit-period <period>', 'day, week, month, year, or total')
      .option('--limit-usd <amount>', 'Limit amount in USD')
      .option('--reveal-sensitive', 'Include PAN/CVC returned by Solayer in command output', false)
      .option('--network <name>', 'Solayer network', 'solana-mainnet')
      .option('--json', 'Print JSON output', false)
      .action(async (options: SolayerCreateCardOptions) => {
        const period = parseLimitPeriod(options.limitPeriod);
        const response = await solayerClient().createCard({
          network: resolveSolayerNetwork(options.network),
          name: options.name,
          type: SolayerCardType.Virtual,
          limit:
            period || options.limitUsd
              ? {
                  period,
                  valueInUsd: options.limitUsd,
                }
              : undefined,
        });
        writeSolayerOutput(context, response, options);
      });
    card
      .command('details')
      .requiredOption('--card-id <id>', 'Solayer card id')
      .option('--network <name>', 'Solayer network', 'solana-mainnet')
      .option('--json', 'Print JSON output', false)
      .action(async (options: SolayerCardIdOptions) => {
        writeSolayerOutput(
          context,
          await solayerClient().getCardDetails({
            network: resolveSolayerNetwork(options.network),
            cardId: options.cardId,
          }),
          options,
        );
      });
    card
      .command('reveal')
      .requiredOption('--card-id <id>', 'Solayer card id')
      .requiredOption('--reveal-sensitive', 'Required to print PAN/CVC')
      .option('--tfa-session-id <id>', 'Solayer TFA session id when required')
      .option('--network <name>', 'Solayer network', 'solana-mainnet')
      .option('--json', 'Print JSON output', false)
      .action(async (options: SolayerCardIdOptions) => {
        writeSolayerOutput(
          context,
          await solayerClient().getCardEncryptedInfo({
            network: resolveSolayerNetwork(options.network),
            cardId: options.cardId,
            tfaSessionId: options.tfaSessionId,
          }),
          { ...options, revealSensitive: true },
        );
      });
    card
      .command('pin')
      .requiredOption('--card-id <id>', 'Solayer card id')
      .requiredOption('--reveal-sensitive', 'Required to print card PIN')
      .option('--json', 'Print JSON output', false)
      .action(async (options: SolayerCardIdOptions) => {
        writeSolayerOutput(context, await solayerClient().getCardPin(options.cardId), {
          ...options,
          revealSensitive: true,
        });
      });
    card
      .command('transactions')
      .option('--card-id <id>', 'Filter by card id')
      .option('--start <unix-ms>', 'Start timestamp in milliseconds')
      .option('--end <unix-ms>', 'End timestamp in milliseconds')
      .option('--page-size <n>', 'Page size')
      .option('--page <n>', 'Page number')
      .option('--network <name>', 'Solayer network', 'solana-mainnet')
      .option('--json', 'Print JSON output', false)
      .action(async (options: SolayerCardTransactionsOptions) => {
        writeSolayerOutput(
          context,
          await solayerClient().getCardTransactions({
            network: resolveSolayerNetwork(options.network),
            startTimestamp: options.start,
            endTimestamp: options.end,
            pageSize: options.pageSize,
            page: options.page,
            cardId: options.cardId,
          }),
          options,
        );
      });
  },
};
