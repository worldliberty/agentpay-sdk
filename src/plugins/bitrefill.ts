import type { BitrefillClient, BitrefillInvoice } from '../lib/bitrefill.js';
import {
  BitrefillChallengeRequiredError,
  buildBitrefillBuyPreview,
  createBitrefillClient,
  findBitrefillInvoiceAccessToken,
  isBitrefillInvoiceFailureStatus,
  listStoredBitrefillInvoices,
  listSupportedBitrefillPaymentQuotes,
  rememberBitrefillInvoiceAccessToken,
  resolveBitrefillInvoicePayment,
  resolveBitrefillPaymentQuote,
  validateBitrefillProductAmount,
} from '../lib/bitrefill.js';
import type { ResolvedAssetMetadata, RustAmountOutputShape } from '../lib/config-amounts.js';
import type { CliPlugin, CliPluginContext } from './types.js';

interface BitrefillJsonOptions {
  json: boolean;
}

interface BitrefillSearchOptions extends BitrefillJsonOptions {
  query: string;
}

interface BitrefillProductOptions extends BitrefillJsonOptions {
  slug: string;
}

interface BitrefillBuyOptions extends BitrefillJsonOptions, Record<string, unknown> {
  slug: string;
  amount: string;
  paymentMethod?: string;
  email?: string;
  broadcast: boolean;
  rpcUrl?: string;
  from?: string;
  nonce?: string;
  gasLimit?: string;
  maxFeePerGasWei?: string;
  maxPriorityFeePerGasWei?: string;
  txType: string;
  wait: boolean;
  revealRawTx: boolean;
  revealSignature: boolean;
}

interface BitrefillInvoiceGetOptions extends BitrefillJsonOptions {
  invoiceId: string;
  accessToken?: string;
}

interface BitrefillInvoiceWaitOptions extends BitrefillInvoiceGetOptions {
  timeout: string;
}

function requiredStringOption(value: string | undefined, flag: string): string {
  const normalized = value?.trim();
  if (!normalized) {
    throw new Error(`${flag} is required`);
  }
  return normalized;
}

function stripBitrefillRawFields(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => stripBitrefillRawFields(entry));
  }
  if (!value || typeof value !== 'object') {
    return value;
  }
  const output: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (entry === undefined || key === 'raw') {
      continue;
    }
    output[key] = stripBitrefillRawFields(entry);
  }
  return output;
}

function formatYamlScalar(value: string | number | boolean | null | undefined): string {
  if (value === null) {
    return 'null';
  }
  if (value === undefined) {
    return 'null';
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  if (!value.length) {
    return '""';
  }
  if (/[\n\r]/u.test(value)) {
    return '|-';
  }
  if (/^(true|false|null|~)$/iu.test(value) || /^[-+]?[0-9]+(\.[0-9]+)?$/u.test(value)) {
    return JSON.stringify(value);
  }
  if (/^[A-Za-z0-9_./:@+-]+$/u.test(value)) {
    return value;
  }
  return JSON.stringify(value);
}

function indentYamlBlock(value: string, indent: number): string {
  const padding = ' '.repeat(indent);
  return value
    .split('\n')
    .map((line) => `${padding}${line}`)
    .join('\n');
}

function formatBitrefillYaml(value: unknown, indent = 0): string {
  const padding = ' '.repeat(indent);
  if (
    value === null ||
    value === undefined ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return `${padding}${formatYamlScalar(value)}`;
  }
  if (typeof value === 'string') {
    if (value.includes('\n')) {
      return `${padding}|-\n${indentYamlBlock(value, indent + 2)}`;
    }
    return `${padding}${formatYamlScalar(value)}`;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      return `${padding}[]`;
    }
    return value
      .map((entry) => {
        if (
          entry === null ||
          entry === undefined ||
          typeof entry === 'number' ||
          typeof entry === 'boolean' ||
          (typeof entry === 'string' && !entry.includes('\n'))
        ) {
          return `${padding}- ${formatYamlScalar(entry as string | number | boolean | null | undefined)}`;
        }
        if (typeof entry === 'string') {
          return `${padding}- |-\n${indentYamlBlock(entry, indent + 2)}`;
        }
        const nested = formatBitrefillYaml(entry, indent + 2);
        return `${padding}-\n${nested}`;
      })
      .join('\n');
  }
  const entries = Object.entries(value as Record<string, unknown>).filter(
    ([, entry]) => entry !== undefined,
  );
  if (entries.length === 0) {
    return `${padding}{}`;
  }
  return entries
    .map(([key, entry]) => {
      if (
        entry === null ||
        typeof entry === 'number' ||
        typeof entry === 'boolean' ||
        (typeof entry === 'string' && !entry.includes('\n'))
      ) {
        return `${padding}${key}: ${formatYamlScalar(entry as string | number | boolean | null)}`;
      }
      if (typeof entry === 'string') {
        return `${padding}${key}: |-\n${indentYamlBlock(entry, indent + 2)}`;
      }
      return `${padding}${key}:\n${formatBitrefillYaml(entry, indent + 2)}`;
    })
    .join('\n');
}

function toBitrefillDisplayPayload(payload: unknown): unknown {
  const normalized = stripBitrefillRawFields(payload);
  if (!normalized || typeof normalized !== 'object' || Array.isArray(normalized)) {
    return normalized;
  }
  if ('slug' in normalized && 'name' in normalized && 'amountMode' in normalized) {
    const product = normalized as Record<string, unknown>;
    const packages = Array.isArray(product.packages)
      ? product.packages.map((entry) => {
          if (!entry || typeof entry !== 'object') {
            return entry;
          }
          const candidate = entry as Record<string, unknown>;
          return `${candidate.label ?? candidate.value} (${candidate.value ?? candidate.label})`;
        })
      : [];
    const range =
      product.range && typeof product.range === 'object'
        ? (product.range as Record<string, unknown>)
        : null;
    const reviews = Array.isArray(product.reviews)
      ? product.reviews.slice(0, 3).map((entry) => {
          if (!entry || typeof entry !== 'object') {
            return entry;
          }
          const review = entry as Record<string, unknown>;
          const rating =
            review.rating !== null && review.rating !== undefined
              ? `${review.rating}/${review.maxRating ?? 5}`
              : null;
          return {
            rating,
            author: review.author ?? null,
            date: review.date ?? null,
            content: review.content ?? null,
          };
        })
      : [];
    return {
      slug: product.slug ?? null,
      name: product.name ?? null,
      country: product.country ?? null,
      currency: product.currency ?? null,
      amountMode: product.amountMode ?? null,
      categories: product.categories ?? [],
      commonAmounts: range ? packages : undefined,
      availableAmounts: range ? undefined : packages,
      amountRange: range,
      description: product.description ?? null,
      howToRedeem: product.instructions ?? null,
      termsAndConditions: product.termsAndConditions ?? null,
      reviews,
      totalReviews: Array.isArray(product.reviews) ? product.reviews.length : 0,
    };
  }
  return normalized;
}

function printBitrefillOutput(context: CliPluginContext, payload: unknown, asJson: boolean): void {
  if (asJson) {
    context.cli.print(payload, true);
    return;
  }
  context.cli.print(formatBitrefillYaml(toBitrefillDisplayPayload(payload)), false);
}

function writeBitrefillProgressEvent(payload: unknown, asJson: boolean): void {
  if (asJson) {
    console.error(
      JSON.stringify(
        payload,
        (_key, value) => (typeof value === 'bigint' ? value.toString() : value),
        2,
      ),
    );
    return;
  }
  if (typeof payload === 'string') {
    console.error(payload);
    return;
  }
  console.error(formatBitrefillYaml(stripBitrefillRawFields(payload)));
}

function reportBitrefillInvoiceCreated(
  invoice: Pick<BitrefillInvoice, 'id' | 'accessToken' | 'status' | 'paymentMethod'>,
  asJson: boolean,
): void {
  writeBitrefillProgressEvent(
    {
      event: 'bitrefillInvoiceCreated',
      invoiceId: invoice.id,
      accessToken: invoice.accessToken,
      status: invoice.status,
      paymentMethod: invoice.paymentMethod,
    },
    asJson,
  );
}

function buildBitrefillBuyQuoteOutput(input: {
  product: { slug: string; name: string; currency: string | null };
  amount: string;
  cartId: string;
  selectedPaymentMethod?: string;
  paymentQuotes: ReturnType<typeof listSupportedBitrefillPaymentQuotes>;
}) {
  return {
    mode: 'quote',
    product: {
      slug: input.product.slug,
      name: input.product.name,
      amount: input.amount,
      currency: input.product.currency,
    },
    cartId: input.cartId,
    selectedPaymentMethod: input.selectedPaymentMethod ?? null,
    broadcastRequested: false,
    availablePaymentMethods: input.paymentQuotes,
  };
}

async function withBitrefillClient<T>(fn: (client: BitrefillClient) => Promise<T>): Promise<T> {
  const client = createBitrefillClient();
  try {
    return await fn(client);
  } finally {
    client.destroy();
  }
}

function printBitrefillChallengeRequired(
  context: CliPluginContext,
  error: BitrefillChallengeRequiredError,
  asJson: boolean,
) {
  if (error.output.invoiceId && error.output.accessToken) {
    rememberBitrefillInvoiceAccessToken({
      invoiceId: error.output.invoiceId,
      accessToken: error.output.accessToken,
    });
  }
  printBitrefillOutput(context, error.output, asJson);
  context.cli.setExitCode(context.exitCodes.challengeRequired);
}

function resolveBitrefillInvoiceAccessToken(invoiceId: string, accessToken?: string): string {
  const explicit = accessToken?.trim();
  if (explicit) {
    rememberBitrefillInvoiceAccessToken({
      invoiceId,
      accessToken: explicit,
    });
    return explicit;
  }
  const stored = findBitrefillInvoiceAccessToken(invoiceId);
  if (stored) {
    return stored;
  }
  throw new Error(
    `--access-token is required when no stored Bitrefill token exists for invoice '${invoiceId}'`,
  );
}

async function waitForBitrefillInvoice(
  context: CliPluginContext,
  client: BitrefillClient,
  invoice: BitrefillInvoice,
): Promise<
  | {
      finalInvoice: BitrefillInvoice;
      invoiceWait: { timedOut: boolean; status: string; orders: typeof invoice.orders };
    }
  | {
      finalInvoice: BitrefillInvoice;
      invoiceWait: { timedOut: false; skipped: true; reason: string };
    }
> {
  if (!invoice.accessToken) {
    return {
      finalInvoice: invoice,
      invoiceWait: {
        timedOut: false,
        skipped: true,
        reason: 'missing invoice access token',
      },
    };
  }

  const waited = await client.waitForInvoice({
    invoiceId: invoice.id,
    accessToken: invoice.accessToken,
  });
  if (waited.timedOut) {
    context.cli.setExitCode(context.exitCodes.waitTimeout);
  } else if (isBitrefillInvoiceFailureStatus(waited.invoice.status)) {
    context.cli.setExitCode(1);
  }

  return {
    finalInvoice: waited.invoice,
    invoiceWait: {
      timedOut: waited.timedOut,
      status: waited.invoice.status,
      orders: waited.invoice.orders,
    },
  };
}

export const bitrefillCliPlugin: CliPlugin = {
  name: 'bitrefill',
  register(program, context) {
    const bitrefill = program
      .command('bitrefill')
      .description('Bitrefill gift card checkout through direct site APIs');

    bitrefill
      .command('search')
      .description('Search Bitrefill products')
      .requiredOption('--query <text>', 'Required. Search query')
      .option('--json', 'Print JSON output', false)
      .action(async (options: BitrefillSearchOptions) => {
        try {
          const results = await withBitrefillClient((client) => client.search(options.query));
          printBitrefillOutput(context, results, options.json);
        } catch (error) {
          if (error instanceof BitrefillChallengeRequiredError) {
            printBitrefillChallengeRequired(context, error, options.json);
            return;
          }
          throw error;
        }
      });

    bitrefill
      .command('product')
      .description('Fetch Bitrefill product details')
      .requiredOption('--slug <slug>', 'Required. Bitrefill product slug')
      .option('--json', 'Print JSON output', false)
      .action(async (options: BitrefillProductOptions) => {
        try {
          const product = await withBitrefillClient((client) => client.getProduct(options.slug));
          printBitrefillOutput(context, product, options.json);
        } catch (error) {
          if (error instanceof BitrefillChallengeRequiredError) {
            printBitrefillChallengeRequired(context, error, options.json);
            return;
          }
          throw error;
        }
      });

    context.cli
      .addAgentCommandAuthOptions(
        bitrefill
          .command('buy')
          .description(
            'Show supported EVM payment methods for a product amount, optionally filtered by --payment-method; add --broadcast to create and pay the Bitrefill invoice immediately',
          )
          .requiredOption('--slug <slug>', 'Required. Bitrefill product slug')
          .requiredOption('--amount <amount>', 'Required. Gift card amount in product currency')
          .option(
            '--payment-method <method>',
            'Optional. Supported EVM payment method filter; required for --broadcast',
          )
          .option('--email <email>', 'Optional. Delivery email; required when using --broadcast')
          .option(
            '--broadcast',
            'Broadcast the invoice payment through the AgentPay daemon path',
            false,
          )
          .option('--rpc-url <url>', 'RPC URL override used only for broadcast')
          .option(
            '--from <address>',
            'Sender address override for broadcast; defaults to configured wallet address',
          )
          .option('--nonce <nonce>', 'Explicit nonce override for broadcast')
          .option('--gas-limit <gas>', 'Gas limit override for broadcast')
          .option('--max-fee-per-gas-wei <wei>', 'Max fee per gas override for broadcast')
          .option(
            '--max-priority-fee-per-gas-wei <wei>',
            'Priority fee per gas override for broadcast',
          )
          .option('--tx-type <type>', 'Typed tx value for broadcast', '0x02')
          .option('--no-wait', 'Do not wait up to 30s for on-chain receipt and invoice status')
          .option(
            '--reveal-raw-tx',
            'Include the signed raw transaction bytes in broadcast output',
            false,
          )
          .option('--reveal-signature', 'Include signer r/s/v fields in broadcast output', false),
      )
      .action(async (options: BitrefillBuyOptions) => {
        let paymentAsset: ResolvedAssetMetadata | null = null;

        try {
          const output = await withBitrefillClient(async (client) => {
            const product = await client.getProduct(options.slug);
            const amount = validateBitrefillProductAmount(product, options.amount);
            const cart = await client.createCart({ slug: product.slug, amount });
            const selectedMethod = options.paymentMethod?.trim() ?? '';
            if (!options.broadcast) {
              const supportedQuotes = listSupportedBitrefillPaymentQuotes(cart);
              const filteredQuotes = selectedMethod
                ? [resolveBitrefillPaymentQuote(cart, selectedMethod)]
                : supportedQuotes;
              return buildBitrefillBuyQuoteOutput({
                product: {
                  slug: product.slug,
                  name: product.name,
                  currency: product.currency,
                },
                amount,
                cartId: cart.id,
                selectedPaymentMethod: selectedMethod || undefined,
                paymentQuotes: filteredQuotes,
              });
            }

            if (!selectedMethod) {
              throw new Error('--payment-method is required with --broadcast');
            }

            const email = requiredStringOption(options.email, '--email');
            const selectedQuote = resolveBitrefillPaymentQuote(cart, selectedMethod);
            const invoice = await client.createInvoice({
              cart,
              email,
              paymentMethod: selectedQuote.method,
            });
            const preview = buildBitrefillBuyPreview({
              product,
              amount,
              invoice,
              cart,
            });
            preview.availablePaymentMethods = [selectedQuote];
            reportBitrefillInvoiceCreated(invoice, options.json);

            if (!options.broadcast) {
              return preview;
            }

            const config = context.config.readConfig();
            const payment = resolveBitrefillInvoicePayment(invoice);
            paymentAsset = payment.asset;
            const plan = await context.broadcast.resolvePlan(
              {
                rpcUrl: context.config.resolveCliRpcUrl(
                  options.rpcUrl,
                  payment.networkSelector,
                  config,
                ),
                chainId: payment.chainId,
                from: options.from
                  ? context.values.assertAddress(options.from, 'from')
                  : context.config.resolveWalletAddress(config),
                to: payment.broadcastTo,
                valueWei: payment.valueWei,
                dataHex: payment.dataHex,
                nonce: options.nonce
                  ? context.values.parseIntegerString(options.nonce, 'nonce')
                  : undefined,
                gasLimit: options.gasLimit
                  ? context.values.parsePositiveBigIntString(options.gasLimit, 'gasLimit')
                  : undefined,
                maxFeePerGasWei: options.maxFeePerGasWei
                  ? context.values.parsePositiveBigIntString(
                      options.maxFeePerGasWei,
                      'maxFeePerGasWei',
                    )
                  : undefined,
                maxPriorityFeePerGasWei: options.maxPriorityFeePerGasWei
                  ? context.values.parseBigIntString(
                      options.maxPriorityFeePerGasWei,
                      'maxPriorityFeePerGasWei',
                    )
                  : undefined,
                txType: options.txType,
              },
              context.broadcast.resolvePlanDeps,
            );
            const signed = await context.agent.runJson<RustAmountOutputShape>({
              commandArgs: [
                'broadcast',
                '--network',
                String(plan.chainId),
                '--nonce',
                String(plan.nonce),
                '--to',
                plan.to,
                '--value-wei',
                plan.valueWei.toString(),
                '--data-hex',
                plan.dataHex,
                '--gas-limit',
                plan.gasLimit.toString(),
                '--max-fee-per-gas-wei',
                plan.maxFeePerGasWei.toString(),
                '--max-priority-fee-per-gas-wei',
                plan.maxPriorityFeePerGasWei.toString(),
                '--tx-type',
                plan.txType,
              ],
              auth: options,
              config,
              asJson: options.json,
              waitForManualApproval: true,
            });
            if (!signed) {
              return null;
            }

            const completed = await context.broadcast.complete(
              plan,
              signed,
              context.broadcast.completeDeps,
            );

            if (options.wait) {
              await context.broadcast.reportOnchainReceiptStatus({
                rpcUrl: plan.rpcUrl,
                txHash: completed.networkTxHash,
                asJson: options.json,
              });
            }

            let finalInvoice = invoice;
            let invoiceWait:
              | { timedOut: boolean; status: string; orders: typeof invoice.orders }
              | { timedOut: false; skipped: true; reason: string }
              | null = null;

            if (options.wait) {
              const waited = await waitForBitrefillInvoice(context, client, invoice);
              finalInvoice = waited.finalInvoice;
              invoiceWait = waited.invoiceWait;
            }

            return {
              ...buildBitrefillBuyPreview({
                product,
                amount,
                invoice: finalInvoice,
                cart,
              }),
              mode: 'broadcast',
              broadcastRequested: true,
              broadcast: context.broadcast.formatOutput({
                command: 'bitrefill-buy',
                counterparty: payment.recipient,
                asset: payment.asset,
                signed,
                plan,
                signedNonce: completed.signedNonce,
                networkTxHash: completed.networkTxHash,
                revealRawTx: options.revealRawTx,
                revealSignature: options.revealSignature,
              }),
              invoiceWait,
            };
          });

          if (output) {
            printBitrefillOutput(context, output, options.json);
          }
        } catch (error) {
          if (error instanceof BitrefillChallengeRequiredError) {
            printBitrefillChallengeRequired(context, error, options.json);
            return;
          }
          if (paymentAsset) {
            throw context.agent.rewriteAmountError(error, paymentAsset);
          }
          throw error;
        }
      });

    const bitrefillInvoice = bitrefill.command('invoice').description('Bitrefill invoice helpers');

    bitrefillInvoice
      .command('list')
      .description('List locally stored Bitrefill invoices with saved access tokens')
      .option('--json', 'Print JSON output', false)
      .action((options: BitrefillJsonOptions) => {
        printBitrefillOutput(context, listStoredBitrefillInvoices(), options.json);
      });

    bitrefillInvoice
      .command('get')
      .description('Fetch a Bitrefill invoice by id and access token')
      .requiredOption('--invoice-id <id>', 'Required. Bitrefill invoice id')
      .option(
        '--access-token <token>',
        'Optional. Bitrefill invoice access token; defaults to the stored token for this invoice when available',
      )
      .option('--json', 'Print JSON output', false)
      .action(async (options: BitrefillInvoiceGetOptions) => {
        try {
          const accessToken = resolveBitrefillInvoiceAccessToken(
            options.invoiceId,
            options.accessToken,
          );
          const invoice = await withBitrefillClient((client) =>
            client.getInvoice({
              invoiceId: options.invoiceId,
              accessToken,
            }),
          );
          printBitrefillOutput(context, invoice, options.json);
        } catch (error) {
          if (error instanceof BitrefillChallengeRequiredError) {
            printBitrefillChallengeRequired(context, error, options.json);
            return;
          }
          throw error;
        }
      });

    bitrefillInvoice
      .command('wait')
      .description('Poll a Bitrefill invoice until terminal success/failure or timeout')
      .requiredOption('--invoice-id <id>', 'Required. Bitrefill invoice id')
      .option(
        '--access-token <token>',
        'Optional. Bitrefill invoice access token; defaults to the stored token for this invoice when available',
      )
      .option('--timeout <seconds>', 'Maximum time to wait before timing out', '60')
      .option('--json', 'Print JSON output', false)
      .action(async (options: BitrefillInvoiceWaitOptions) => {
        try {
          const accessToken = resolveBitrefillInvoiceAccessToken(
            options.invoiceId,
            options.accessToken,
          );
          const timeoutMs =
            context.values.parsePositiveIntegerString(options.timeout, 'timeout') * 1000;
          const result = await withBitrefillClient((client) =>
            client.waitForInvoice({
              invoiceId: options.invoiceId,
              accessToken,
              timeoutMs,
            }),
          );
          printBitrefillOutput(context, result, options.json);
          if (result.timedOut) {
            context.cli.setExitCode(context.exitCodes.waitTimeout);
            return;
          }
          if (isBitrefillInvoiceFailureStatus(result.invoice.status)) {
            context.cli.setExitCode(1);
          }
        } catch (error) {
          if (error instanceof BitrefillChallengeRequiredError) {
            printBitrefillChallengeRequired(context, error, options.json);
            return;
          }
          throw error;
        }
      });
  },
};
