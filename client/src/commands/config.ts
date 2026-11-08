/** `config show|set|agent-auth` and `telemetry status|enable|disable`. */
import type { Command } from 'commander';
import type { Context } from '../app/context.js';
import { isUuid } from '../auth/client-state.js';
import { assertStorableSecret } from '../auth/secret-store.js';
import { copy } from '../copy/index.js';
import { AgentPayError, EXIT, UsageError } from '../errors.js';
import type { PaymentsConfig, TelemetryStatusResult } from '../generated/index.js';
import { type AgentOptions, type JsonOption, withAgentOptions } from './options.js';
import { emit, reportError } from './output.js';
import { type CommandEnv, handler } from './run.js';

/** The client-side half of `config show`: where credentials come from. */
async function clientInfo(context: Context) {
  const agentKeyId = context.state.read().agentKeyId;
  let tokenStored = false;
  if (agentKeyId) {
    try {
      tokenStored = (await context.secrets.read(agentKeyId)) !== null;
    } catch {
      tokenStored = false;
    }
  }
  return {
    agent_key_id: agentKeyId,
    agent_auth_token_stored: tokenStored,
    credential_store: context.secrets.label,
    home: context.home,
    signer_socket: context.endpoints.signer.path,
    payments_socket: context.endpoints.payments.path,
  };
}

function configText(
  config: PaymentsConfig | null,
  client: Awaited<ReturnType<typeof clientInfo>>,
): string[] {
  const lines = [
    `agent_key_id: ${client.agent_key_id ?? copy.common.notSet}`,
    `credential store: ${client.credential_store}${client.agent_auth_token_stored ? '' : ' (no token)'}`,
  ];
  if (config) {
    lines.push(
      `default_network: ${config.default_network}`,
      `default_asset: ${config.default_asset}`,
      '',
    );
    const c = copy.commands.config;
    lines.push(c.networksHeading);
    for (const [key, chain] of Object.entries(config.chains)) {
      lines.push(
        `  ${key}: ${chain.name} (chain ${chain.chain_id})`,
        `    ${c.rpc}: ${chain.rpc_url ?? c.noRpc}`,
      );
      if (chain.fallback_rpc_urls.length > 0) {
        lines.push(`    ${c.backups}: ${chain.fallback_rpc_urls.join(', ')}`);
      }
    }
  }
  return lines;
}

/** Applies `key = value` to a copy of `config`. Returns `null` for a client-side key. */
export function applySetting(config: PaymentsConfig, key: string, value: string): PaymentsConfig {
  const normalized = key.replaceAll('-', '_');
  if (normalized === 'default_network') {
    return { ...config, default_network: value };
  }
  if (normalized === 'default_asset') {
    return { ...config, default_asset: value };
  }
  const backups =
    /^chains\.([^.]+)\.fallback_rpc_urls$/u.exec(normalized) ??
    /^fallback_rpc_urls\.([^.]+)$/u.exec(normalized);
  const backupNetwork = backups?.[1];
  if (backupNetwork !== undefined) {
    const chain = config.chains[backupNetwork];
    if (!chain) {
      throw new UsageError(`unknown network "${backupNetwork}"`);
    }
    // A comma-separated list, tried in order; "none" (or empty) removes them.
    const urls =
      value === '' || value === 'none'
        ? []
        : value
            .split(',')
            .map((url) => url.trim())
            .filter((url) => url !== '');
    return {
      ...config,
      chains: { ...config.chains, [backupNetwork]: { ...chain, fallback_rpc_urls: urls } },
    };
  }
  const rpc =
    /^chains\.([^.]+)\.rpc_url$/u.exec(normalized) ?? /^rpc_url\.([^.]+)$/u.exec(normalized);
  const network = rpc?.[1];
  if (network !== undefined) {
    const chain = config.chains[network];
    if (!chain) {
      throw new UsageError(`unknown network "${network}"`);
    }
    const rpcUrl = value === '' || value === 'none' ? null : value;
    return { ...config, chains: { ...config.chains, [network]: { ...chain, rpc_url: rpcUrl } } };
  }
  throw new UsageError(copy.commands.config.unknownKey(key));
}

function telemetryText(status: TelemetryStatusResult): string[] {
  return [copy.commands.telemetry.state(status.enabled, status.disabled_reason), '', status.notice];
}

interface AgentAuthSetOptions extends JsonOption {
  agentKeyId: string;
  agentAuthTokenStdin?: boolean;
}

export function registerConfigCommands(program: Command, env: CommandEnv): void {
  const c = copy.commands.config;
  const config = program.command('config').description(c.description);

  withAgentOptions(config.command('show').description(c.show)).action(
    handler(env, async (options: AgentOptions) => {
      const client = await clientInfo(env.context);
      try {
        const payments = await (await env.context.payments(options)).getConfig();
        emit(env.context.io, options.json, { ...payments, client }, () =>
          configText(payments, client),
        );
        return EXIT.ok;
      } catch (error) {
        if (!(error instanceof AgentPayError) || error.exitCode !== EXIT.notSetUp) {
          throw error;
        }
        // Not set up: still report what the client knows, then say what to do.
        if (options.json) {
          emit(
            env.context.io,
            true,
            { client, payments: null, setup_required: true, next_action: error.guidance.next },
            () => [],
          );
          return EXIT.notSetUp;
        }
        emit(env.context.io, false, null, () => configText(null, client));
        return reportError(env.context.io, false, error);
      }
    }),
  );

  withAgentOptions(
    config.command('set').description(c.set).argument('<key>').argument('<value>'),
  ).action(
    handler(env, async (key: string, value: string, options: AgentOptions) => {
      if (['agent_key_id', 'agent-key-id', 'agentKeyId'].includes(key)) {
        if (!isUuid(value)) {
          throw new UsageError('agent_key_id must be a UUID');
        }
        env.context.state.update({ agentKeyId: value.toLowerCase() });
        emit(env.context.io, options.json, { agent_key_id: value.toLowerCase() }, () => [c.saved]);
        return;
      }
      const payments = await env.context.payments(options);
      const updated = await payments.setConfig(
        applySetting(await payments.getConfig(), key, value),
      );
      emit(env.context.io, options.json, updated, () => [c.saved]);
    }),
  );

  const agentAuth = config.command('agent-auth').description(c.agentAuth);
  agentAuth
    .command('set')
    .description(c.agentAuthSet)
    .requiredOption('--agent-key-id <uuid>', copy.commands.program.agentKeyId)
    .option('--agent-auth-token-stdin', copy.commands.program.agentAuthTokenStdin)
    .option('--json', copy.commands.program.json)
    .action(
      handler(env, async (options: AgentAuthSetOptions) => {
        if (!isUuid(options.agentKeyId)) {
          throw new UsageError('--agent-key-id must be a UUID');
        }
        const agentKeyId = options.agentKeyId.trim().toLowerCase();
        const token = assertStorableSecret(await env.context.io.readStdin());
        await env.context.secrets.write(agentKeyId, token);
        env.context.state.update({ agentKeyId });
        emit(
          env.context.io,
          options.json,
          { agent_key_id: agentKeyId, credential_store: env.context.secrets.label },
          () => [c.saved],
        );
      }),
    );

  agentAuth
    .command('clear')
    .description(c.agentAuthClear)
    .option('--agent-key-id <uuid>', copy.commands.program.agentKeyId)
    .option('--json', copy.commands.program.json)
    .action(
      handler(env, async (options: { agentKeyId?: string; json?: boolean }) => {
        const agentKeyId = options.agentKeyId ?? env.context.state.read().agentKeyId;
        const removed = agentKeyId ? await env.context.secrets.remove(agentKeyId) : false;
        emit(env.context.io, options.json, { agent_key_id: agentKeyId, removed }, () => [
          c.cleared,
        ]);
      }),
    );

  const t = copy.commands.telemetry;
  const telemetry = program.command('telemetry').description(t.description);
  withAgentOptions(telemetry.command('status').description(t.status)).action(
    handler(env, async (options: AgentOptions) => {
      const status = await (await env.context.payments(options)).telemetryStatus();
      emit(env.context.io, options.json, status, () => telemetryText(status));
    }),
  );
  for (const [name, enabled] of [
    ['enable', true],
    ['disable', false],
  ] as const) {
    withAgentOptions(telemetry.command(name).description(enabled ? t.enable : t.disable)).action(
      handler(env, async (options: AgentOptions) => {
        const status = await (await env.context.payments(options)).setTelemetry(enabled);
        emit(env.context.io, options.json, status, () => telemetryText(status));
      }),
    );
  }
}
