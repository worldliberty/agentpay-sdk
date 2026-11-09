/**
 * `agentpay activity` (this agent's waiting approvals and recent payments) and
 * `agentpay notify` (the approval alerts loop the background service runs; see notify/).
 */
import type { Command } from 'commander';
import { copy } from '../copy/index.js';
import { activityLines, approvalHeadline, waitingApprovals } from '../format/activity.js';
import { approvalReasons } from '../format/approval.js';
import type { PaymentsConfig } from '../generated/index.js';
import { alertOnce, fileNotifiedStore } from '../notify/alerts.js';
import { type AgentOptions, withAgentOptions } from './options.js';
import { emit } from './output.js';
import { type CommandEnv, handler } from './run.js';

const POLL_MS = 5_000;

interface ActivityOptions extends AgentOptions {
  limit?: string;
}

export function registerActivityCommands(program: Command, env: CommandEnv): void {
  const c = copy.commands.activity;
  withAgentOptions(
    program.command('activity').description(c.description).option('--limit <count>', c.limit),
  ).action(
    handler(env, async (options: ActivityOptions) => {
      const payments = await env.context.payments(options);
      const limit = options.limit ? Number.parseInt(options.limit, 10) : 20;
      const [result, config] = await Promise.all([
        payments.activity({ limit: Number.isInteger(limit) && limit > 0 ? limit : 20 }),
        payments.getConfig().catch(() => null),
      ]);
      emit(env.context.io, options.json, result, () => activityLines(result, config));
    }),
  );

  // Run by the per-user background service; not meant to be typed.
  program
    .command('notify', { hidden: true })
    .description(c.notify)
    .option('--once', c.once)
    .action(
      handler(env, async (options: { once?: boolean }) => {
        const { context } = env;
        const store = fileNotifiedStore(context.home);
        let config: PaymentsConfig | null = null;
        const tick = async () => {
          const payments = await context.payments({});
          config ??= await payments.getConfig().catch(() => null);
          const result = await payments.activity({ limit: 50 });
          return alertOnce({
            pending: async () =>
              waitingApprovals(result).map((approval) => ({
                id: approval.id,
                amount: approvalHeadline(approval, config),
                reason: approvalReasons(approval, config).shortReason,
              })),
            store,
            run: context.run,
            platform: context.platform,
            text: (alert) => ({
              title: copy.screens.alerts.title,
              message: copy.screens.alerts.message(alert.amount, alert.reason),
            }),
          });
        };
        if (options.once) {
          await tick();
          return;
        }
        // Until stopped: a failed poll (services restarting, no credentials yet) is logged and
        // retried on the next tick.
        for (;;) {
          await tick().catch((error: unknown) => {
            context.io.stderr(`${new Date().toISOString()} ${String(error)}\n`);
          });
          await new Promise((resolve) => setTimeout(resolve, POLL_MS));
        }
      }),
    );
}
