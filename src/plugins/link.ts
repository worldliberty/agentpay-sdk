import type { Command } from 'commander';
import {
  buildLinkCardCreateArgs,
  createLinkCard,
  type LinkCliFormat,
  linkCliVersion,
  onboardLinkAccount,
  runLinkCli,
} from '../lib/link.js';
import type { CliPlugin, CliPluginContext } from './types.js';

interface LinkCommonOptions {
  auth?: string;
  json?: boolean;
}

interface LinkOnboardCliOptions extends LinkCommonOptions {
  clientName?: string;
  interval: string;
  timeout: string;
  maxAttempts?: string;
  demo?: boolean;
}

interface LinkCardCliOptions extends LinkCommonOptions {
  paymentMethodId: string;
  merchantName: string;
  merchantUrl: string;
  context: string;
  amount: string;
  currency?: string;
  lineItem: string[];
  total: string[];
  outputFile?: string;
  force: boolean;
  test: boolean;
  interval: string;
  maxAttempts: string;
  timeout: string;
}

interface LinkInstallOptions extends LinkCommonOptions {
  serve?: boolean;
}

interface LinkPassthroughOptions extends LinkCommonOptions {
  format?: LinkCliFormat;
  fullOutput?: boolean;
}

function parsePositiveInteger(value: string, label: string): number {
  if (!/^[1-9][0-9]*$/u.test(value)) {
    throw new Error(`${label} must be a positive integer`);
  }
  return Number(value);
}

function parseNonNegativeInteger(value: string, label: string): number {
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) {
    throw new Error(`${label} must be a non-negative integer`);
  }
  return Number(value);
}

async function runPassthrough(
  context: CliPluginContext,
  args: string[],
  options: LinkPassthroughOptions,
): Promise<void> {
  const result = await runLinkCli(args, {
    authFile: options.auth,
    format: options.json ? 'json' : options.format,
    fullOutput: options.fullOutput,
    inheritStdio: true,
  });
  if (result.status !== 0) {
    context.cli.setExitCode(result.status);
  }
}

function addLinkCommonOptions(command: Command): Command {
  return command
    .option('--auth <path>', 'Use a dedicated Link auth credential file')
    .option('--json', 'Print JSON output', false);
}

function addPassthroughOptions(command: Command): Command {
  return addLinkCommonOptions(command)
    .option('--format <format>', 'Pass a Link CLI output format')
    .option('--full-output', 'Show the full Link CLI output envelope', false)
    .allowUnknownOption(true)
    .allowExcessArguments(true);
}

function collectRepeated(value: string, previous: string[]): string[] {
  previous.push(value);
  return previous;
}

export const linkCliPlugin: CliPlugin = {
  name: 'link',
  register(program: Command, context: CliPluginContext): void {
    const link = program.command('link').description('Use Stripe Link for fiat agent payments');

    addLinkCommonOptions(
      link
        .command('install')
        .description('Verify the bundled Link CLI and show third-party integration entrypoints')
        .option('--serve', 'Print HTTP MCP server startup guidance', false),
    ).action((options: LinkInstallOptions) => {
      const version = linkCliVersion();
      const payload = {
        linkCliVersion: version,
        cli: {
          onboard: 'agentpay link onboard',
          card: 'agentpay link card --payment-method-id <id> --merchant-name <name> --merchant-url <url> --amount <cents> --context <text>',
          passthrough: 'agentpay link spend-request --help',
        },
        sdk: {
          import: '@worldlibertyfinancial/agentpay-sdk/link',
          helpers: [
            'onboardLinkAccount',
            'getLinkStatus',
            'listLinkPaymentMethods',
            'createLinkCard',
            'runLinkCli',
          ],
        },
        mcp: options.serve
          ? {
              command: 'agentpay link serve --port 54321',
              endpoint: 'http://localhost:54321/mcp',
            }
          : undefined,
      };
      context.cli.print(payload, options.json ?? false);
    });

    addLinkCommonOptions(
      link
        .command('onboard')
        .description('Bind a Link account and list available Link payment methods')
        .option('--client-name <name>', 'Name shown in Link when approving this agent', 'AgentPay')
        .option('--interval <seconds>', 'Auth polling interval', '5')
        .option('--timeout <seconds>', 'Auth polling timeout', '300')
        .option('--max-attempts <count>', 'Maximum auth polling attempts')
        .option('--demo', 'Run the full official link-cli onboard demo', false),
    ).action(async (options: LinkOnboardCliOptions) => {
      if (options.demo) {
        await runPassthrough(context, ['onboard'], options);
        return;
      }

      if (options.json) {
        const loginArgs = [
          'auth',
          'login',
          '--client-name',
          options.clientName ?? 'AgentPay',
          '--interval',
          options.interval,
          '--timeout',
          options.timeout,
        ];
        if (options.maxAttempts) {
          loginArgs.push('--max-attempts', options.maxAttempts);
        }
        const login = await runLinkCli(loginArgs, {
          authFile: options.auth,
          format: 'json',
        });
        if (login.status !== 0) {
          context.cli.setExitCode(login.status);
          process.stderr.write(login.stderr || login.stdout);
          return;
        }
        const methods = await runLinkCli(['payment-methods', 'list'], {
          authFile: options.auth,
          format: 'json',
        });
        if (methods.status !== 0) {
          context.cli.setExitCode(methods.status);
          process.stderr.write(methods.stderr || methods.stdout);
          return;
        }
        context.cli.print(
          {
            auth: login.stdout.trim() ? JSON.parse(login.stdout) : null,
            paymentMethods: methods.stdout.trim() ? JSON.parse(methods.stdout) : null,
          },
          true,
        );
        return;
      }

      await onboardLinkAccount({
        authFile: options.auth,
        clientName: options.clientName,
        intervalSeconds: parsePositiveInteger(options.interval, '--interval'),
        timeoutSeconds: parsePositiveInteger(options.timeout, '--timeout'),
        maxAttempts:
          options.maxAttempts === undefined
            ? undefined
            : parseNonNegativeInteger(options.maxAttempts, '--max-attempts'),
      });
    });

    addLinkCommonOptions(
      link.command('status').description('Show Link account binding status'),
    ).action(async (options: LinkCommonOptions) => {
      await runPassthrough(context, ['auth', 'status'], {
        ...options,
        json: options.json ?? true,
      });
    });

    addPassthroughOptions(
      link
        .command('payment-methods [args...]')
        .description('List payment methods saved to the bound Link account'),
    ).action(async (args: string[] = [], options: LinkPassthroughOptions) => {
      await runPassthrough(
        context,
        ['payment-methods', ...(args.length ? args : ['list'])],
        options,
      );
    });

    addLinkCommonOptions(
      link
        .command('card')
        .description('Create an approved Link virtual card for an agent purchase')
        .requiredOption('--payment-method-id <id>', 'Link payment method id')
        .requiredOption('--merchant-name <name>', 'Merchant name shown in Link approval')
        .requiredOption('--merchant-url <url>', 'Merchant URL shown in Link approval')
        .requiredOption('--context <text>', 'Purchase context shown to the user in Link')
        .requiredOption('--amount <cents>', 'Amount in cents, max 50000')
        .option('--currency <code>', 'Currency code', 'usd')
        .option(
          '--line-item <item>',
          'Line item in Link key:value format; repeatable',
          collectRepeated,
          [],
        )
        .option(
          '--total <total>',
          'Total in Link key:value format; repeatable',
          collectRepeated,
          [],
        )
        .option('--output-file <path>', 'Where full card credentials should be written')
        .option('--force', 'Allow replacing an existing output file', false)
        .option('--test', 'Create testmode credentials through Link', false)
        .option('--interval <seconds>', 'Approval polling interval', '2')
        .option('--max-attempts <count>', 'Maximum approval polling attempts', '300')
        .option('--timeout <seconds>', 'Approval polling timeout', '600'),
    ).action(async (options: LinkCardCliOptions) => {
      const amountCents = parsePositiveInteger(options.amount, '--amount');
      const intervalSeconds = parsePositiveInteger(options.interval, '--interval');
      const maxAttempts = parseNonNegativeInteger(options.maxAttempts, '--max-attempts');
      const timeoutSeconds = parsePositiveInteger(options.timeout, '--timeout');

      if (options.json) {
        const payload = await createLinkCard({
          authFile: options.auth,
          paymentMethodId: options.paymentMethodId,
          merchantName: options.merchantName,
          merchantUrl: options.merchantUrl,
          context: options.context,
          amountCents,
          currency: options.currency,
          lineItems: options.lineItem,
          totals: options.total,
          outputFile: options.outputFile,
          force: options.force,
          test: options.test,
          intervalSeconds,
          maxAttempts,
          timeoutSeconds,
        });
        context.cli.print(payload, true);
        return;
      }

      const { args } = buildLinkCardCreateArgs({
        authFile: options.auth,
        paymentMethodId: options.paymentMethodId,
        merchantName: options.merchantName,
        merchantUrl: options.merchantUrl,
        context: options.context,
        amountCents,
        currency: options.currency,
        lineItems: options.lineItem,
        totals: options.total,
        outputFile: options.outputFile,
        force: options.force,
        test: options.test,
        intervalSeconds,
        maxAttempts,
        timeoutSeconds,
      });
      await runPassthrough(context, args, { auth: options.auth });
    });

    for (const commandName of [
      'auth',
      'demo',
      'mpp',
      'serve',
      'shipping-address',
      'spend-request',
      'user-info',
    ]) {
      addPassthroughOptions(
        link
          .command(`${commandName} [args...]`)
          .description(`Pass through to link-cli ${commandName}`),
      ).action(async (args: string[] = [], options: LinkPassthroughOptions) => {
        await runPassthrough(context, [commandName, ...args], options);
      });
    }
  },
};
