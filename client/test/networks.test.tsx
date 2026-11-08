import { describe, expect, it, vi } from 'vitest';
import { statusText } from '../src/commands/wallet.js';
import { chainProblem, groupBalances } from '../src/format/networks.js';
import type { StatusResult, WalletBalanceEntry, WalletInfo } from '../src/generated/index.js';
import { HomeScreen } from '../src/screens/Home.js';
import { WalletPickerStep } from '../src/screens/onboarding/steps.js';
import { fixtureData } from './helpers/fixtures.js';
import { KEY, press, render, waitFor } from './helpers/ink.js';
import { wallet } from './helpers/services.js';

const rpc = (data: string) => ({ kind: 'ChainRpc', data }) as never;

describe('chain problems in plain words', () => {
  it.each([
    [
      'eth_chainId failed: node error 15: You reached Public endpoint rate limit, please upgrade to paid plan',
      'The public RPC is limiting requests',
    ],
    // The RPC method name must not read as a chain mismatch.
    ['eth_chainId failed: endpoint unreachable', 'The RPC cannot be reached'],
    ['eth_blockNumber failed: request timed out', 'The RPC did not answer in time'],
    [
      "the RPC endpoint of network 'bsc' reports chain id 1, expected 56",
      'The RPC serves a different network',
    ],
    ['something new\nwith details', 'something new'],
  ])('%s', (data, reason) => {
    const problem = chainProblem('bsc', rpc(data));
    expect(problem.message).toBe(reason);
    expect(problem.next).toContain('agentpay config set chains.bsc.rpc_url <URL>');
  });

  it('a missing RPC URL', () => {
    expect(chainProblem('eth', null).message).toBe('No RPC URL is set');
  });
});

describe('balances by network', () => {
  const entries = wallet.balances;

  it('puts the default network first and test networks last, or leaves them out', () => {
    const all = groupBalances(entries, {
      defaultNetwork: 'bsc',
      defaultAsset: 'usd1',
      includeTestnets: true,
    });
    expect(all.map((g) => [g.network, g.testnet])).toEqual([
      ['bsc', false],
      ['eth', false],
      ['solana-devnet', true],
    ]);
    expect(all[0]?.entries[0]?.asset).toBe('usd1');
    const main = groupBalances(entries, { defaultNetwork: 'bsc', includeTestnets: false });
    expect(main.some((g) => g.testnet)).toBe(false);
  });

  it('gives a network whose reads all failed one problem', () => {
    const [, eth] = groupBalances(entries, { defaultNetwork: 'bsc', includeTestnets: false });
    expect(eth?.problem?.message).toBe('The RPC cannot be reached');
    const failedOne: WalletBalanceEntry[] = [
      { ...(entries[0] as WalletBalanceEntry), balance: null, error: rpc('x') },
      entries[1] as WalletBalanceEntry,
    ];
    const [bsc] = groupBalances(failedOne, { defaultNetwork: 'bsc', includeTestnets: false });
    expect(bsc?.problem).toBeNull();
  });
});

describe('status text', () => {
  const status = fixtureData<StatusResult>('payments/wallet/Status.response.json');

  it('lists networks with their reasons and replaces the generic warning', () => {
    const text = statusText(status).join('\n');
    expect(text).toContain('✓ BSC');
    expect(text).toContain('✗ ETH: The RPC cannot be reached');
    expect(text).toContain('Test networks\n  ✓ Solana Devnet');
    expect(text).toContain(
      'Next: Use your own RPC: `agentpay config set chains.eth.rpc_url <URL>` (backups: `chains.eth.fallback_rpc_urls`).',
    );
    expect(text).not.toContain('did not answer as the configured chain');
  });
});

describe('Home balances', () => {
  it('hides test networks until t, and explains unreadable networks', async () => {
    const { lastFrame, stdin } = render(
      <HomeScreen load={async () => ({ wallet, pendingApprovals: 0 })} onAction={() => {}} />,
    );
    const frame = await waitFor(lastFrame, 'Balances');
    expect(frame).toContain('✗ The RPC cannot be reached');
    expect(frame).toContain('1 network cannot be read');
    expect(frame).not.toContain('Solana Devnet');
    expect(frame).toContain('t test networks');
    await press(stdin, 't');
    const shown = await waitFor(lastFrame, 'Solana Devnet');
    expect(shown).toContain('Test networks');
    expect(shown).toContain('t hide test networks');
  });
});

describe('wallet picker', () => {
  it('selects and marks the wallet the agents use', async () => {
    const [example] = fixtureData<never[]>('rpc/ListWallets.response.json') as unknown as {
      vault_key_id: string;
      agent_key_ids: string[];
    }[];
    if (!example) {
      throw new Error('no wallet fixture');
    }
    const wallets = [
      { vaultKeyId: 'old', info: { ...example, vault_key_id: 'old', agent_key_ids: [] } },
      { vaultKeyId: example.vault_key_id, info: example },
    ] as never;
    const onPick = vi.fn();
    const { lastFrame, stdin } = render(
      <WalletPickerStep
        wallets={wallets}
        currentAgentKeyId={example.agent_key_ids[0] ?? null}
        onPick={onPick}
        onBack={() => {}}
      />,
    );
    const frame = await waitFor(lastFrame, 'used by your agents');
    expect(frame.split('\n').find((line) => line.includes('›'))).toContain('used by your agents');
    await press(stdin, KEY.enter);
    expect(onPick).toHaveBeenCalledWith(example.vault_key_id);
  });
});

describe('wallet picker in setup', () => {
  it('confirms before moving the agents to another wallet', async () => {
    const [example] = fixtureData<WalletInfo[]>('rpc/ListWallets.response.json');
    if (!example) {
      throw new Error('no wallet fixture');
    }
    const inUse = { ...example, agent_key_ids: ['5e134267-fe6d-41fe-9264-d01e30aba2a8'] };
    const old = { ...example, vault_key_id: 'old-wallet', agent_key_ids: [] };
    const onPick = vi.fn();
    const { lastFrame, stdin } = render(
      <WalletPickerStep
        wallets={[
          { vaultKeyId: 'old-wallet', info: old },
          { vaultKeyId: inUse.vault_key_id, info: inUse },
        ]}
        currentAgentKeyId="5e134267-fe6d-41fe-9264-d01e30aba2a8"
        onPick={onPick}
        onBack={() => {}}
      />,
    );
    await waitFor(lastFrame, 'used by your agents');
    await press(stdin, KEY.up, KEY.enter);
    const confirm = await waitFor(lastFrame, 'Switch wallets?');
    expect(confirm).toContain('Agents will use');
    expect(onPick).not.toHaveBeenCalled();
    await press(stdin, KEY.enter);
    expect(onPick).toHaveBeenCalledWith('old-wallet');
  });
});
