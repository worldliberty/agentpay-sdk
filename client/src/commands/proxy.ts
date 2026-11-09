/**
 * `proxy start|stop|status`. The proxy URL embeds a secret token, so `start` writes it to a
 * private env file (0600) for child processes instead of suggesting it on a command line.
 */
import type { Command } from 'commander';
import { writePrivateFile } from '../auth/files.js';
import { homeFiles } from '../auth/home.js';
import { copy } from '../copy/index.js';
import type { ProxyStatusResult } from '../generated/index.js';
import {
  type AgentOptions,
  baseUnits,
  collect,
  opt,
  positiveInt,
  withAgentOptions,
} from './options.js';
import { emit } from './output.js';
import { type CommandEnv, handler } from './run.js';

interface StartOptions extends AgentOptions {
  port?: number;
  allowHost?: string[];
  maxAmount?: string;
  currency?: string;
  network?: string;
  deposit?: string;
  maxDeposit?: string;
}

function statusText(status: ProxyStatusResult): string[] {
  const p = copy.commands.proxy;
  return status.running && status.address
    ? [
        p.running(status.address),
        p.counters(status.requests, status.payments, status.failed_payments),
      ]
    : [p.stopped, p.counters(status.requests, status.payments, status.failed_payments)];
}

/** Shell-safe `KEY='value'` line. */
function envLine(key: string, value: string): string {
  return `${key}='${value.replaceAll("'", "'\\''")}'`;
}

export function registerProxyCommands(program: Command, env: CommandEnv): void {
  const p = copy.commands.proxy;
  const proxy = program.command('proxy').description(p.description);

  withAgentOptions(
    proxy
      .command('start')
      .description(p.start)
      .option('--port <port>', p.port, positiveInt)
      .option('--allow-host <host>', p.allowHost, collect)
      .option('--max-amount <units>', p.maxAmount, baseUnits)
      .option('--currency <address>', p.currency)
      .option('--network <network>', p.network)
      .option('--deposit <units>', p.deposit, baseUnits)
      .option('--max-deposit <units>', p.maxDeposit, baseUnits),
  ).action(
    handler(env, async (options: StartOptions) => {
      const payments = await env.context.payments(options);
      const started = await payments.proxyStart({
        ...opt('port', options.port),
        ...opt('allowed_hosts', options.allowHost),
        ...opt('max_amount', options.maxAmount),
        ...opt('currency', options.currency),
        ...opt('network', options.network),
        ...opt('deposit', options.deposit),
        ...opt('max_deposit', options.maxDeposit),
      });
      const home = env.context.home;
      const caFile = homeFiles.proxyCa(home);
      const envFile = homeFiles.proxyEnv(home);
      writePrivateFile(caFile, started.ca_certificate_pem, 0o644);
      writePrivateFile(
        envFile,
        `${[
          envLine('HTTP_PROXY', started.proxy_url),
          envLine('HTTPS_PROXY', started.proxy_url),
          envLine('http_proxy', started.proxy_url),
          envLine('https_proxy', started.proxy_url),
          envLine('NODE_EXTRA_CA_CERTS', caFile),
          envLine('SSL_CERT_FILE', caFile),
          envLine('REQUESTS_CA_BUNDLE', caFile),
          envLine('CURL_CA_BUNDLE', caFile),
        ].join('\n')}\n`,
      );
      emit(env.context.io, options.json, { ...started, env_file: envFile, ca_file: caFile }, () => [
        ...statusText(started.status),
        p.useEnv(envFile),
        p.secretWarning,
      ]);
    }),
  );

  withAgentOptions(proxy.command('stop').description(p.stop)).action(
    handler(env, async (options: AgentOptions) => {
      const status = await (await env.context.payments(options)).proxyStop();
      emit(env.context.io, options.json, status, () => statusText(status));
    }),
  );

  withAgentOptions(proxy.command('status').description(p.status)).action(
    handler(env, async (options: AgentOptions) => {
      const status = await (await env.context.payments(options)).proxyStatus();
      emit(env.context.io, options.json, status, () => statusText(status));
    }),
  );
}
