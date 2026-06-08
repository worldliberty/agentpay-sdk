import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';

const moduleRequire = createRequire(
  typeof __filename === 'string' ? __filename : path.join(process.cwd(), 'agentpay-link.js'),
);

export type LinkCliFormat = 'toon' | 'json' | 'yaml' | 'md' | 'jsonl';

export interface LinkCliInvocation {
  command: string;
  args: string[];
}

export interface LinkCliRunOptions {
  authFile?: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  format?: LinkCliFormat;
  fullOutput?: boolean;
  inheritStdio?: boolean;
  input?: string | Buffer;
}

export interface LinkCliResult {
  status: number;
  stdout: string;
  stderr: string;
}

export interface LinkOnboardOptions extends LinkCliRunOptions {
  clientName?: string;
  intervalSeconds?: number;
  timeoutSeconds?: number;
  maxAttempts?: number;
}

export interface LinkCardOptions extends LinkCliRunOptions {
  paymentMethodId: string;
  merchantName: string;
  merchantUrl: string;
  context: string;
  amountCents: number;
  currency?: string;
  lineItems?: string[];
  totals?: string[];
  outputFile?: string;
  force?: boolean;
  test?: boolean;
  intervalSeconds?: number;
  maxAttempts?: number;
  timeoutSeconds?: number;
}

export interface LinkCardJsonResult {
  spendRequestId: string | null;
  cardOutputFile: string;
  created: unknown;
  retrieved: unknown;
}

function envWithQuietLinkUpdates(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  return {
    ...env,
    NO_UPDATE_NOTIFIER: env.NO_UPDATE_NOTIFIER ?? '1',
  };
}

export function resolveBundledLinkCliInvocation(
  env: NodeJS.ProcessEnv = process.env,
): LinkCliInvocation {
  const override = env.AGENTPAY_LINK_CLI_BIN?.trim();
  if (override) {
    return { command: override, args: [] };
  }

  const packageJsonPath = moduleRequire.resolve('@stripe/link-cli/package.json');
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8')) as {
    bin?: string | Record<string, string>;
  };
  const bin = typeof packageJson.bin === 'string' ? packageJson.bin : packageJson.bin?.['link-cli'];
  if (!bin) {
    throw new Error('@stripe/link-cli does not expose a link-cli binary');
  }

  return {
    command: process.execPath,
    args: [path.join(path.dirname(packageJsonPath), bin)],
  };
}

export function buildLinkCliArgs(
  commandArgs: string[],
  options: Pick<LinkCliRunOptions, 'authFile' | 'format' | 'fullOutput'> = {},
): string[] {
  const args = [...commandArgs];
  if (options.authFile) {
    args.push('--auth', options.authFile);
  }
  if (options.format) {
    args.push('--format', options.format);
  }
  if (options.fullOutput) {
    args.push('--full-output');
  }
  return args;
}

export function runLinkCliSync(
  commandArgs: string[],
  options: LinkCliRunOptions = {},
): LinkCliResult {
  const invocation = resolveBundledLinkCliInvocation(options.env);
  const result = spawnSync(
    invocation.command,
    [...invocation.args, ...buildLinkCliArgs(commandArgs, options)],
    {
      cwd: options.cwd,
      encoding: 'utf8',
      env: envWithQuietLinkUpdates(options.env),
      input: options.input,
      stdio: options.inheritStdio ? 'inherit' : 'pipe',
    },
  );
  if (result.error) {
    throw result.error;
  }
  return {
    status: result.status ?? 1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

export function runLinkCli(
  commandArgs: string[],
  options: LinkCliRunOptions = {},
): Promise<LinkCliResult> {
  const invocation = resolveBundledLinkCliInvocation(options.env);
  const stdio = options.inheritStdio ? 'inherit' : 'pipe';
  return new Promise((resolve, reject) => {
    const child = spawn(
      invocation.command,
      [...invocation.args, ...buildLinkCliArgs(commandArgs, options)],
      {
        cwd: options.cwd,
        env: envWithQuietLinkUpdates(options.env),
        stdio,
      },
    );

    let stdout = '';
    let stderr = '';
    if (!options.inheritStdio) {
      child.stdout?.on('data', (chunk) => {
        stdout += chunk.toString();
      });
      child.stderr?.on('data', (chunk) => {
        stderr += chunk.toString();
      });
    }
    child.on('error', reject);
    child.on('close', (status, signal) => {
      resolve({
        status:
          status ??
          (typeof signal === 'string' && typeof os.constants.signals[signal] === 'number'
            ? 128 + os.constants.signals[signal]
            : 1),
        stdout,
        stderr,
      });
    });

    if (options.input !== undefined && !options.inheritStdio) {
      child.stdin?.end(options.input);
      return;
    }
    if (!options.inheritStdio) {
      child.stdin?.end();
    }
  });
}

export async function runLinkCliJson<T = unknown>(
  commandArgs: string[],
  options: Omit<LinkCliRunOptions, 'format' | 'inheritStdio'> = {},
): Promise<T> {
  const result = await runLinkCli(commandArgs, { ...options, format: 'json' });
  if (result.status !== 0) {
    throw new Error(
      result.stderr.trim() || result.stdout.trim() || `link-cli exited with code ${result.status}`,
    );
  }
  const raw = result.stdout.trim();
  if (!raw) {
    return null as T;
  }
  return JSON.parse(raw) as T;
}

export function defaultLinkCardOutputFile(merchantName = 'merchant'): string {
  const safeMerchant =
    merchantName
      .toLowerCase()
      .replace(/[^a-z0-9]+/gu, '-')
      .replace(/^-|-$/gu, '')
      .slice(0, 40) || 'merchant';
  const timestamp = new Date().toISOString().replace(/[:.]/gu, '-');
  return path.join(os.homedir(), '.agentpay', 'link-cards', `${timestamp}-${safeMerchant}.json`);
}

export function normalizeLinkPurchaseContext(input: {
  context: string;
  merchantName: string;
  amountCents: number;
  currency?: string;
}): string {
  const context = input.context.trim();
  if (context.length >= 100) {
    return context;
  }
  const currency = (input.currency ?? 'usd').toUpperCase();
  return [
    context,
    `The user asked AgentPay to create a Link spend request so an agent can complete a purchase at ${input.merchantName}.`,
    `The requested amount is ${input.amountCents} cents in ${currency}, and the user will approve or decline this request in the Link app before any card credential is usable.`,
  ]
    .filter(Boolean)
    .join(' ');
}

export function buildLinkCardCreateArgs(options: LinkCardOptions): {
  args: string[];
  outputFile: string;
} {
  const currency = options.currency ?? 'usd';
  const outputFile = options.outputFile ?? defaultLinkCardOutputFile(options.merchantName);
  const lineItems = options.lineItems?.length
    ? options.lineItems
    : [`name:${options.merchantName} purchase,unit_amount:${options.amountCents},quantity:1`];
  const totals = options.totals?.length
    ? options.totals
    : [`type:total,display_text:Total,amount:${options.amountCents}`];
  const args = [
    'spend-request',
    'create',
    '--payment-method-id',
    options.paymentMethodId,
    '--credential-type',
    'card',
    '--merchant-name',
    options.merchantName,
    '--merchant-url',
    options.merchantUrl,
    '--context',
    normalizeLinkPurchaseContext({
      context: options.context,
      merchantName: options.merchantName,
      amountCents: options.amountCents,
      currency,
    }),
    '--amount',
    String(options.amountCents),
    '--currency',
    currency,
    '--request-approval',
    '--output-file',
    outputFile,
  ];
  for (const item of lineItems) {
    args.push('--line-item', item);
  }
  for (const total of totals) {
    args.push('--total', total);
  }
  if (options.force) {
    args.push('--force');
  }
  if (options.test) {
    args.push('--test');
  }
  return { args, outputFile };
}

function firstLinkOutputEntry(value: unknown): Record<string, unknown> | null {
  if (Array.isArray(value)) {
    const first = value[0];
    return first && typeof first === 'object' ? (first as Record<string, unknown>) : null;
  }
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
}

export async function onboardLinkAccount(options: LinkOnboardOptions = {}): Promise<void> {
  const loginArgs = [
    'auth',
    'login',
    '--client-name',
    options.clientName ?? 'AgentPay',
    '--interval',
    String(options.intervalSeconds ?? 5),
    '--timeout',
    String(options.timeoutSeconds ?? 300),
  ];
  if (options.maxAttempts !== undefined) {
    loginArgs.push('--max-attempts', String(options.maxAttempts));
  }

  const login = await runLinkCli(loginArgs, { ...options, inheritStdio: true });
  if (login.status !== 0) {
    throw new Error(`link-cli auth login exited with code ${login.status}`);
  }

  const methods = await runLinkCli(['payment-methods', 'list'], {
    ...options,
    inheritStdio: true,
  });
  if (methods.status !== 0) {
    throw new Error(`link-cli payment-methods list exited with code ${methods.status}`);
  }
}

export function getLinkStatus(options: Omit<LinkCliRunOptions, 'format'> = {}): Promise<unknown> {
  return runLinkCliJson(['auth', 'status'], options);
}

export function listLinkPaymentMethods(
  options: Omit<LinkCliRunOptions, 'format'> = {},
): Promise<unknown> {
  return runLinkCliJson(['payment-methods', 'list'], options);
}

export async function createLinkCard(options: LinkCardOptions): Promise<LinkCardJsonResult> {
  const { args, outputFile } = buildLinkCardCreateArgs(options);
  const created = await runLinkCliJson(args, options);
  const createdEntry = firstLinkOutputEntry(created);
  const spendRequestId = typeof createdEntry?.id === 'string' ? createdEntry.id : null;
  if (!spendRequestId) {
    return {
      spendRequestId,
      cardOutputFile: outputFile,
      created,
      retrieved: null,
    };
  }

  const retrieveArgs = [
    'spend-request',
    'retrieve',
    spendRequestId,
    '--include',
    'card',
    '--interval',
    String(options.intervalSeconds ?? 2),
    '--max-attempts',
    String(options.maxAttempts ?? 300),
    '--timeout',
    String(options.timeoutSeconds ?? 600),
    '--output-file',
    outputFile,
  ];
  if (options.force) {
    retrieveArgs.push('--force');
  }
  const retrieved = await runLinkCliJson(retrieveArgs, options);
  return {
    spendRequestId,
    cardOutputFile: outputFile,
    created,
    retrieved,
  };
}

export function linkCliVersion(options: Omit<LinkCliRunOptions, 'format'> = {}): string {
  const result = runLinkCliSync(['--version'], options);
  if (result.status !== 0) {
    throw new Error(
      result.stderr.trim() || result.stdout.trim() || `link-cli exited with code ${result.status}`,
    );
  }
  return result.stdout.trim();
}
