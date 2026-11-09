/**
 * Administrator commands. Each confirms with Touch ID (macOS, when enabled) or needs a root peer
 * (`sudo agentpay admin …`); otherwise the error says to re-run with sudo. In a terminal,
 * `approvals` and `limits` open the interactive screens. The wallet commands (`wallets`,
 * `wallet-backup`) are in `admin-wallets.ts`.
 */
import { existsSync } from 'node:fs';
import type { Command } from 'commander';
import { createElement } from 'react';
import type { AdminActions } from '../app/admin-actions.js';
import { createAppServices } from '../app/services.js';
import { disableTouchId, enableTouchId, touchIdStatus } from '../app/touch-id-setup.js';
import { resolveAgentKeyId } from '../auth/agent-credentials.js';
import { copy } from '../copy/index.js';
import { EXIT, UsageError } from '../errors.js';
import { summarizeApproval } from '../format/approval.js';
import { columns, relativeTime, shortAddress, timestampToDate } from '../format/text.js';
import type { ManualApprovalRequest, PaymentsConfig } from '../generated/index.js';
import { DEFAULT_PAYMENTS_CONFIG } from '../limits/default-config.js';
import {
  isNoLimit,
  type LimitRow,
  limitRowJson,
  rowsFromConfig,
  setRowLimits,
  toSpendingLimits,
} from '../limits/model.js';
import { App, type Route } from '../screens/App.js';
import { registerAdminWalletCommands } from './admin-wallets.js';
import { type ResumeOptions, resumePayment } from './evm.js';
import { type AgentOptions, decimalAmount, type JsonOption, withAgentOptions } from './options.js';
import { emit } from './output.js';
import type { CommandEnv } from './run.js';
import { handler } from './run.js';

const COMMAND = {
  approvals: 'agentpay admin approvals',
  approve: (id: string) => `agentpay admin approve ${id}`,
  reject: (id: string) => `agentpay admin reject ${id}`,
  limits: 'agentpay admin limits',
  touchId: 'agentpay admin touch-id enable',
};

async function optionalConfig(
  env: CommandEnv,
  options: AgentOptions,
): Promise<PaymentsConfig | null> {
  try {
    return await (await env.context.payments(options)).getConfig();
  } catch {
    return null;
  }
}

function approvalLines(
  requests: readonly ManualApprovalRequest[],
  config: PaymentsConfig | null,
): string[] {
  if (requests.length === 0) {
    return [copy.commands.admin.noPending];
  }
  return columns(
    requests.map((request) => {
      const summary = summarizeApproval(request, config);
      return [
        request.id,
        `${summary.action} ${summary.amount}`,
        `→ ${shortAddress(summary.to)}`,
        summary.network,
        request.status,
        relativeTime(timestampToDate(request.created_at)),
      ];
    }),
  );
}

/** Opens an interactive route of the home app (approvals, limits, security). */
async function openScreen(env: CommandEnv, options: AgentOptions, route: Route): Promise<void> {
  const payments = await env.context.payments(options);
  const admin = env.context.admin({ relay: true });
  try {
    await env.context.render(
      createElement(App, {
        services: createAppServices(env.context, payments, admin),
        initial: route,
      }),
    );
  } finally {
    await admin.dispose();
  }
}

interface ApprovalsOptions extends AgentOptions {
  all?: boolean;
}

async function listApprovals(env: CommandEnv, options: ApprovalsOptions): Promise<number> {
  if (interactive(env, options) && !options.all) {
    await openScreen(env, options, 'approvals');
    return EXIT.ok;
  }
  const requests = (
    await env.context.admin({ relay: false }).listApprovals(COMMAND.approvals)
  ).filter((request) => options.all || request.status === 'pending');
  const config = options.json ? null : await optionalConfig(env, options);
  emit(env.context.io, options.json, requests, () => approvalLines(requests, config));
  return EXIT.ok;
}

interface DecideOptions extends AgentOptions {
  yes?: boolean;
  reason?: string;
}

async function decide(
  env: CommandEnv,
  id: string,
  decision: 'approve' | 'reject',
  options: DecideOptions,
): Promise<number> {
  const a = copy.commands.admin;
  const io = env.context.io;
  const admin: AdminActions = env.context.admin({ relay: false });
  const confirmNeeded = admin.method() === 'root' && !options.yes;
  if (confirmNeeded && !io.isTTY) {
    throw new UsageError(`add --yes to ${decision} without a confirmation prompt`);
  }
  const config = await optionalConfig(env, options);
  const decided = await admin.decideById(
    id,
    decision,
    options.reason ?? null,
    decision === 'approve' ? COMMAND.approve(id) : COMMAND.reject(id),
    async (request) => {
      if (!options.json) {
        const s = summarizeApproval(request, config);
        const r = copy.screens.approvals.rows;
        io.stderr(
          `${columns([
            [r.action, s.action],
            [r.to, s.to],
            [r.amount, s.amount],
            [r.network, s.network],
            [r.agent, s.agentKeyId],
          ]).join('\n')}\n`,
        );
      }
      if (!confirmNeeded) {
        return true;
      }
      const answer = await io.question(decision === 'approve' ? a.confirmApprove : a.confirmReject);
      return /^y(es)?$/iu.test(answer.trim());
    },
  );
  if (!decided) {
    emit(io, options.json, { status: 'aborted' }, () => [a.aborted]);
    return EXIT.failure;
  }
  emit(io, options.json, decided, () => [decision === 'approve' ? a.approved : a.rejected]);
  return EXIT.ok;
}

interface LimitsOptions extends AgentOptions {
  network?: string;
  perTx?: string;
  daily?: string;
  weekly?: string;
  exclude?: boolean;
}

/**
 * The agent's limit rows. Only the agent key id is required: under sudo the user's agent token
 * is usually out of reach (another keychain), so the configuration falls back to the built-in
 * default when the payments service cannot be asked.
 */
async function loadRows(env: CommandEnv, options: AgentOptions, admin: AdminActions) {
  const { context } = env;
  const agentKeyId = resolveAgentKeyId(options, {
    env: context.env,
    state: context.state,
    store: context.secrets,
    readStdin: () => context.io.readStdin(),
  });
  const config = (await optionalConfig(env, options)) ?? DEFAULT_PAYMENTS_CONFIG;
  const report = await admin.listLimits(agentKeyId, COMMAND.limits);
  return { config, agentKeyId, rows: rowsFromConfig(config, report.limits) };
}

/** Interactive screens run as the user; under sudo the commands print instead. */
function interactive(env: CommandEnv, options: AgentOptions): boolean {
  return env.context.io.isTTY && !options.json && env.context.euid !== 0;
}

function limitsText(rows: LimitRow[]): string[] {
  const amount = (value: string, decimals: number) =>
    !value ? '—' : isNoLimit(value, decimals) ? copy.screens.limits.noLimit : value;
  return columns([
    ['ASSET', 'NETWORK', 'PER PAYMENT', 'PER DAY', 'PER WEEK', 'STATUS'],
    ...rows.map((row) => [
      row.symbol,
      row.network,
      amount(row.perTx, row.decimals),
      amount(row.daily, row.decimals),
      amount(row.weekly, row.decimals),
      limitRowJson(row).status,
    ]),
  ]);
}

type TouchIdOptions = JsonOption;

export function registerAdminCommands(program: Command, env: CommandEnv): void {
  const a = copy.commands.admin;
  const admin = program.command('admin').description(a.description);

  withAgentOptions(
    admin.command('approvals').description(a.approvals).option('--all', a.all),
  ).action(handler(env, (options: ApprovalsOptions) => listApprovals(env, options)));
  withAgentOptions(admin.command('list-manual-approval-requests', { hidden: true })).action(
    handler(env, (options: ApprovalsOptions) => listApprovals(env, { ...options, all: true })),
  );

  for (const decision of ['approve', 'reject'] as const) {
    const command = admin
      .command(decision)
      .description(decision === 'approve' ? a.approve : a.reject)
      .argument('<approval-request-id>')
      .option('--yes', a.yes);
    if (decision === 'reject') {
      command.option('--reason <text>', a.reason);
    }
    withAgentOptions(command).action(
      handler(env, (id: string, options: DecideOptions) => decide(env, id, decision, options)),
    );
    withAgentOptions(
      admin
        .command(`${decision}-manual-approval-request`, { hidden: true })
        .requiredOption('--approval-request-id <uuid>')
        .option('--rejection-reason <text>')
        .option('--yes'),
    ).action(
      handler(
        env,
        (options: DecideOptions & { approvalRequestId: string; rejectionReason?: string }) =>
          decide(env, options.approvalRequestId, decision, {
            ...options,
            ...(options.rejectionReason ? { reason: options.rejectionReason } : {}),
          }),
      ),
    );
  }

  const limits = withAgentOptions(admin.command('limits').description(a.limits)).action(
    handler(env, async (options: AgentOptions) => {
      if (interactive(env, options)) {
        await openScreen(env, options, 'limits');
        return EXIT.ok;
      }
      const { rows } = await loadRows(env, options, env.context.admin({ relay: false }));
      const json = rows.map(limitRowJson);
      emit(env.context.io, options.json, json, () => limitsText(rows));
      return EXIT.ok;
    }),
  );
  withAgentOptions(
    limits
      .command('set')
      .description(a.limitsSet)
      .argument('<asset>')
      .option('--network <network>', copy.commands.evm.network)
      .option('--per-tx <amount>', a.perTx, decimalAmount)
      .option('--daily <amount>', a.daily, decimalAmount)
      .option('--weekly <amount>', a.weekly, decimalAmount)
      .option('--exclude', a.excludeAsset),
  ).action(
    handler(env, async (asset: string, options: LimitsOptions) => {
      const actions = env.context.admin({ relay: false });
      const { config, agentKeyId, rows } = await loadRows(env, options, actions);
      const id = `${asset.toLowerCase()}@${options.network ?? config.default_network}`;
      const index = rows.findIndex((row) => row.id === id);
      const target = rows[index];
      if (!target) {
        throw new UsageError(`no configured asset ${id}; see \`agentpay admin limits --json\``);
      }
      const updated = setRowLimits(target, options);
      if (updated.status === 'unset') {
        throw new UsageError('set --per-tx, --daily, and --weekly, or --exclude');
      }
      rows[index] = updated;
      const limits = toSpendingLimits(rows);
      if (limits.length === 0) {
        throw new UsageError(copy.onboarding.limits.atLeastOne);
      }
      await actions.setLimits(agentKeyId, limits, COMMAND.limits);
      emit(env.context.io, options.json, limitRowJson(updated), () => [a.limitSaved]);
      return EXIT.ok;
    }),
  );

  const touchId = admin.command('touch-id').description(a.touchId);
  const touchIdAction = (name: 'enable' | 'status' | 'disable', description: string) =>
    touchId
      .command(name)
      .description(description)
      .option('--json', copy.commands.program.json)
      .action(
        handler(env, async (options: TouchIdOptions) => {
          const actions = env.context.admin({ relay: name !== 'status' });
          const deps = env.context.touchId(actions);
          if (name === 'enable') {
            if (!options.json) {
              env.context.io.stderr(`${a.touchIdEnrolling}\n`);
            }
            await enableTouchId(deps, COMMAND.touchId);
          } else if (name === 'disable') {
            await disableTouchId(deps, COMMAND.touchId);
          }
          const state = await touchIdStatus(deps);
          emit(
            env.context.io,
            options.json,
            {
              state,
              credential_id: env.context.state.read().adminCredentialId,
              key_file: deps.keyFile,
              key_file_exists: existsSync(deps.keyFile),
              helper: deps.helper?.path ?? null,
            },
            () => [
              state === 'on'
                ? a.touchIdOn
                : state === 'off'
                  ? a.touchIdOff
                  : copy.errors.touchIdUnavailable.message,
            ],
          );
          return EXIT.ok;
        }),
      );
  touchIdAction('enable', a.touchIdEnable);
  touchIdAction('status', a.touchIdStatus);
  touchIdAction('disable', a.touchIdDisable);

  registerAdminWalletCommands(admin, env);

  // Compatibility with the TypeScript CLI's admin entry points.
  withAgentOptions(
    admin
      .command('resume-manual-approval-request', { hidden: true })
      .requiredOption('--approval-request-id <uuid>'),
  ).action(handler(env, (options: ResumeOptions) => resumePayment(env, options)));
}
