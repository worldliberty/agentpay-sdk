/** `wallet`, `status`, and `fund`. */
import type { Command } from 'commander';
import { copy } from '../copy/index.js';
import { displayAmount } from '../format/amount.js';
import { chainProblem, groupBalances } from '../format/networks.js';
import { columns } from '../format/text.js';
import type {
  FundingRequestResult,
  StatusResult,
  WalletSummaryResult,
} from '../generated/index.js';
import { isTestnetChain } from '../limits/model.js';
import { glyph } from '../ui/theme.js';
import { type AgentOptions, decimalAmount, opt, withAgentOptions } from './options.js';
import { emit } from './output.js';
import { type CommandEnv, handler } from './run.js';

export function walletText(wallet: WalletSummaryResult): string[] {
  const w = copy.commands.wallet;
  const lines: string[] = [w.title];
  if (wallet.evm_address) {
    lines.push(`  ${w.evm}: ${wallet.evm_address}`);
  }
  if (wallet.solana_address) {
    lines.push(`  ${w.solana}: ${wallet.solana_address}`);
  }
  const defaultEntry = wallet.balances.find(
    (entry) => entry.network === wallet.default_network && entry.asset === wallet.default_asset,
  );
  lines.push(
    `  ${w.defaults(
      defaultEntry?.chain_name ?? wallet.default_network,
      defaultEntry?.symbol ?? wallet.default_asset,
    )}`,
  );
  const groups = groupBalances(wallet.balances, {
    defaultNetwork: wallet.default_network,
    defaultAsset: wallet.default_asset,
    includeTestnets: true,
  });
  const section = (testnet: boolean): string[] => {
    const shown = groups.filter((group) => group.testnet === testnet);
    // Right-align the amounts so their digits line up.
    const width = Math.max(
      0,
      ...shown.flatMap((group) =>
        group.entries.map((entry) => (entry.balance ? displayAmount(entry.balance).length : 0)),
      ),
    );
    return columns(
      shown.flatMap((group) =>
        group.problem
          ? [[`  ${group.chainName}`, `${glyph.cross} ${group.problem.message}`]]
          : group.entries.map((entry, index) => [
              index === 0 ? `  ${group.chainName}` : '',
              entry.balance === null
                ? `${glyph.cross} ${chainProblem(entry.network, entry.error).message}`
                : `${displayAmount(entry.balance).padStart(width)} ${entry.symbol}`,
            ]),
      ),
    );
  };
  lines.push('', w.balancesHeading, ...section(false));
  const testnets = section(true);
  if (testnets.length > 0) {
    lines.push('', copy.networks.testnets, ...testnets);
  }
  const unreadable = groups.filter((group) => group.problem && !group.testnet);
  const [first] = unreadable;
  if (first?.problem) {
    lines.push(
      '',
      `${copy.networks.unreadable(unreadable.length)}. ${copy.common.next}: ${first.problem.next}`,
    );
  }
  return lines;
}

export function statusText(status: StatusResult): string[] {
  const s = copy.commands.status;
  const lines = [
    s.service(status.service.service_version, status.service.api_version),
    s.signer(status.signer.reachable, status.signer.daemon_version),
    s.canSpend(status.can_spend),
    s.telemetry(status.telemetry_enabled),
  ];
  const chainLine = (chain: StatusResult['chains'][number]) =>
    chain.reachable === true
      ? `  ${glyph.check} ${chain.chain_name}${chain.using_backup_rpc ? ` (${s.onBackup})` : ''}`
      : `  ${glyph.cross} ${chain.chain_name}: ${
          chain.rpc_configured ? chainProblem(chain.network, chain.error).message : s.noRpc
        }`;
  const byName = (a: { chain_name: string }, b: { chain_name: string }) =>
    a.chain_name.localeCompare(b.chain_name);
  const main = status.chains.filter((chain) => !isTestnetChain(chain.chain_id)).sort(byName);
  const test = status.chains.filter((chain) => isTestnetChain(chain.chain_id)).sort(byName);
  lines.push('', s.networksHeading, ...main.map(chainLine));
  if (test.length > 0) {
    lines.push('', copy.networks.testnets, ...test.map(chainLine));
  }
  if (status.warnings.length > 0) {
    lines.push('', s.warningsHeading);
    for (const warning of status.warnings) {
      const chain = status.chains.find((c) => c.network === warning.network);
      if (warning.code === 'chain_unreachable' && chain) {
        // The daemon's message is generic; its per-chain error says what actually happened.
        const problem = chainProblem(chain.network, chain.error);
        lines.push(
          `  ${glyph.warning} ${chain.chain_name}: ${problem.message}.`,
          `    ${copy.common.next}: ${problem.next}`,
        );
      } else {
        lines.push(`  ${glyph.warning} ${warning.message}`);
      }
    }
  } else {
    lines.push('', s.healthy);
  }
  return lines;
}

export function fundingText(funding: FundingRequestResult): string[] {
  const r = copy.screens.receive;
  return [
    ...(funding.qr ? [funding.qr.terminal, ''] : []),
    `${r.address}: ${funding.address}`,
    `${r.network}: ${funding.chain_name} (chain ${funding.chain_id})`,
    `${r.asset}: ${funding.symbol}${funding.token ? ` (${funding.token})` : ''}`,
    `URI: ${funding.uri}`,
    '',
    funding.instructions,
    ...(funding.gas ? [funding.gas.note] : []),
  ];
}

interface FundOptions extends AgentOptions {
  network?: string;
  asset?: string;
  token?: string;
  amount?: string;
  qr?: boolean;
}

export function registerWalletCommands(program: Command, env: CommandEnv): void {
  const c = copy.commands;
  withAgentOptions(program.command('wallet').description(c.wallet.description)).action(
    handler(env, async (options: AgentOptions) => {
      const payments = await env.context.payments(options);
      const wallet = await payments.walletSummary();
      emit(env.context.io, options.json, wallet, () => walletText(wallet));
    }),
  );

  withAgentOptions(program.command('status').description(c.status.description)).action(
    handler(env, async (options: AgentOptions) => {
      const payments = await env.context.payments(options);
      const status = await payments.status();
      emit(env.context.io, options.json, status, () => statusText(status));
    }),
  );

  withAgentOptions(
    program
      .command('fund')
      .description(c.fund.description)
      .option('--network <network>', c.fund.network)
      .option('--asset <asset>', c.fund.asset)
      .option('--token <asset>', c.fund.asset)
      .option('--amount <amount>', c.fund.amount, decimalAmount)
      .option('--qr', c.fund.qr),
  ).action(
    handler(env, async (options: FundOptions) => {
      const payments = await env.context.payments(options);
      const funding = await payments.fundingRequest({
        qr: options.qr === true,
        ...opt('network', options.network),
        ...opt('asset', options.asset ?? options.token),
        ...opt('amount', options.amount),
      });
      emit(env.context.io, options.json, funding, () => fundingText(funding));
    }),
  );
}
