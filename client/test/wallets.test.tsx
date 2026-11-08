import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ReactElement } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { bootstrapMode, createAppServices } from '../src/app/services.js';
import { RELAYED_METHODS } from '../src/auth/privileged.js';
import { findWallet, walletLabel, walletLines } from '../src/format/wallets.js';
import type { ExportWalletBackupParams, WalletInfo } from '../src/generated/index.js';
import { runCli } from '../src/program.js';
import { BackupWalletPicker } from '../src/screens/BackupForm.js';
import { OnboardingWizard } from '../src/screens/onboarding/OnboardingWizard.js';
import { WalletsScreen } from '../src/screens/Wallets.js';
import { type TestContext, testContext } from './helpers/context.js';
import { body, fail, type Handler, ok } from './helpers/fake-daemon.js';
import { fixture, fixtureData } from './helpers/fixtures.js';
import { KEY, press, render, waitFor } from './helpers/ink.js';
import { fakeIo } from './helpers/io.js';
import { fakeAppServices, fakeOnboardingServices, limitsReport } from './helpers/services.js';

const [EXAMPLE] = fixtureData<WalletInfo[]>('rpc/ListWallets.response.json') as [WalletInfo];
const OTHER: WalletInfo = {
  vault_key_id: 'a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d',
  name: null,
  algorithm: 'secp256k1',
  evm_address: '0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d',
  solana_address: null,
  created_at: [2026, 310, 9, 0, 0, 0, 0, 0, 0],
  source: 'Imported',
  agent_key_ids: [],
};

describe('wallet formatting', () => {
  it('labels a wallet by name, short address, creation date, and agent keys', () => {
    expect(walletLabel(EXAMPLE)).toBe(
      'Trading bot · 0x2c75…5c23 · created 2026-11-05 · 1 agent key',
    );
    expect(walletLabel(OTHER)).toBe('0x8d0d…8b0d · created 2026-11-06 · 0 agent keys');
    // An ed25519 key has only a Solana address.
    expect(walletLabel({ ...EXAMPLE, name: null, evm_address: null, agent_key_ids: [] })).toBe(
      '9fijMe…eigk · created 2026-11-05 · 0 agent keys',
    );
  });

  it('finds a wallet by vault key id or by address in any case', () => {
    const wallets = [EXAMPLE, OTHER];
    expect(findWallet(wallets, OTHER.vault_key_id.toUpperCase())).toBe(OTHER);
    expect(findWallet(wallets, '0x2C7536E3605D9C16A7A3D7B1898E529396A65C23')).toBe(EXAMPLE);
    expect(findWallet(wallets, EXAMPLE.solana_address ?? '')).toBe(EXAMPLE);
    expect(findWallet(wallets, '0x0000000000000000000000000000000000000000')).toBeNull();
  });

  it('lists wallets with their names and full addresses', () => {
    const [header, first, second] = walletLines([EXAMPLE, OTHER]);
    expect(header?.split(/\s{2,}/u)).toEqual([
      'NAME',
      'VAULT KEY ID',
      'EVM ADDRESS',
      'SOLANA ADDRESS',
      'CREATED',
      'AGENT KEYS',
    ]);
    expect(first?.split(/\s{2,}/u)).toEqual([
      'Trading bot',
      EXAMPLE.vault_key_id,
      EXAMPLE.evm_address,
      EXAMPLE.solana_address,
      '2026-11-05',
      '1',
    ]);
    expect(second?.split(/\s{2,}/u)).toEqual([
      '—',
      OTHER.vault_key_id,
      OTHER.evm_address,
      '—',
      '2026-11-06',
      '0',
    ]);
  });
});

describe('welcome step: keep the existing wallet', () => {
  async function welcome(listWallets: () => Promise<WalletInfo[]>, ready = 'Create a new wallet') {
    const services = fakeOnboardingServices({ listWallets: vi.fn(listWallets) });
    const view = render(<OnboardingWizard services={services} />);
    const frame = await waitFor(view.lastFrame, ready);
    return { ...view, services, frame };
  }

  it('reads the wallets first and keeps the only one by its id', async () => {
    const { lastFrame, stdin, services, frame } = await welcome(async () => [EXAMPLE]);
    expect(services.listWallets).toHaveBeenCalledTimes(1);
    expect(frame).toContain(
      'Keep the existing wallet  Trading bot · 0x2c75…5c23 · created 2026-11-05 · 1 agent key',
    );
    // Keeping is the default: Enter never replaces a wallet by accident.
    expect(frame).toContain('› Keep the existing wallet');
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Protect your wallet');
    expect(lastFrame()).not.toContain('Choose the wallet to keep');
    await press(stdin, KEY.down, KEY.enter);
    await waitFor(lastFrame, 'Set spending limits');
    // The wizard keeps the chosen wallet when it creates the agent key.
    await press(stdin, 'X', KEY.enter);
    await waitFor(lastFrame, 'Your wallet is ready.');
    expect(vi.mocked(services.createWallet).mock.calls[0]?.[0]).toEqual({
      kind: 'reuse',
      vaultKeyId: EXAMPLE.vault_key_id,
    });
  });

  it('asks which of several wallets to keep, by address, and goes back with esc', async () => {
    const { lastFrame, stdin, services, frame } = await welcome(async () => [EXAMPLE, OTHER]);
    expect(frame).toContain('Keep the existing wallet  2 wallets on this machine; choose one next');
    await press(stdin, KEY.enter);

    const picker = await waitFor(lastFrame, 'Choose the wallet to keep');
    expect(picker).toContain('Step 1 of 6');
    expect(picker).toContain('› Trading bot · 0x2c75…5c23 · created 2026-11-05 · 1 agent key');
    expect(picker).toContain('  0x8d0d…8b0d · created 2026-11-06 · 0 agent keys');
    expect(picker).toContain('↑↓ select · enter confirm · esc back');
    await press(stdin, KEY.escape);
    expect(await waitFor(lastFrame, 'Welcome to AgentPay')).not.toContain(
      'Choose the wallet to keep',
    );

    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Choose the wallet to keep');
    await press(stdin, KEY.down, KEY.enter);
    await waitFor(lastFrame, 'Protect your wallet');
    await press(stdin, KEY.down, KEY.enter);
    await waitFor(lastFrame, 'Set spending limits');
    await press(stdin, 'X', KEY.enter);
    await waitFor(lastFrame, 'Your wallet is ready.');
    expect(vi.mocked(services.createWallet).mock.calls[0]?.[0]).toEqual({
      kind: 'reuse',
      vaultKeyId: OTHER.vault_key_id,
    });
  });

  it('offers no wallet to keep when the machine has none', async () => {
    const { frame } = await welcome(async () => []);
    expect(frame).toContain('Restore from a backup');
    expect(frame).not.toContain('Keep the existing wallet');
  });

  it('stops on the error, offering no choice, until the wallets can be read', async () => {
    let attempts = 0;
    const { lastFrame, stdin, services, frame } = await welcome(async () => {
      attempts += 1;
      if (attempts === 1) {
        throw new Error('sudo was cancelled');
      }
      return [EXAMPLE];
    }, 'r retry');
    expect(frame).toContain('sudo was cancelled');
    expect(frame).not.toContain('Create a new wallet');
    await press(stdin, KEY.enter);
    expect(lastFrame()).not.toContain('Protect your wallet');

    await press(stdin, 'r');
    await waitFor(lastFrame, '› Keep the existing wallet');
    expect(services.listWallets).toHaveBeenCalledTimes(2);
    expect(services.createWallet).not.toHaveBeenCalled();
  });
});

describe('admin wallet commands', () => {
  let t: TestContext | null = null;
  afterEach(async () => {
    await t?.close();
    t = null;
  });

  /** A signer daemon holding `wallets`, answering backups with the API example. */
  function signer(wallets: WalletInfo[]): Handler {
    return (call) => {
      switch (call.method) {
        case 'ListWallets':
          return ok('Wallets', wallets);
        case 'ExportWalletBackup':
          return wallets.length > 1 && !(call.params as ExportWalletBackupParams).vault_key_id
            ? fail(
                'InvalidWalletRequest',
                `the daemon holds ${wallets.length} vault keys; pass vault_key_id`,
              )
            : body(fixture('rpc/ExportWalletBackup.response.json'));
        default:
          return { close: true };
      }
    };
  }

  async function run(argv: string[], wallets: WalletInfo[], io = fakeIo()) {
    t = await testContext({ euid: 0, signer: signer(wallets), io });
    const code = await runCli(argv, t.context);
    const calls = t.signer.calls.filter((call) => call.method !== 'Hello');
    return { code, io: t.io, calls, rendered: t.rendered };
  }

  const backupPath = () => join(mkdtempSync(join(tmpdir(), 'apw-')), 'backup.json');

  it('the sudo relay forwards ListWallets', () => {
    expect(RELAYED_METHODS).toContain('ListWallets');
  });

  it('admin wallets --json lists the daemon’s wallets as the root peer', async () => {
    const { code, io, calls } = await run(['admin', 'wallets', '--json'], [EXAMPLE, OTHER]);
    expect(code).toBe(0);
    expect(io.json()).toEqual([EXAMPLE, OTHER]);
    expect(calls).toEqual([{ method: 'ListWallets', params: { auth: 'peer_credentials' } }]);
  });

  it('admin wallets prints one line per wallet, or says there is none', async () => {
    const listed = await run(['admin', 'wallets'], [EXAMPLE]);
    expect(listed.io.out()).toContain(`${EXAMPLE.vault_key_id}  ${EXAMPLE.evm_address}`);
    await t?.close();
    const empty = await run(['admin', 'wallets'], []);
    expect(empty.io.out()).toContain('There is no wallet on this machine yet.');
  });

  it('exports the only wallet without --wallet and without listing first', async () => {
    const path = backupPath();
    const { code, calls } = await run(
      ['admin', 'wallet-backup', 'export', '--passphrase-stdin', '--output', path],
      [EXAMPLE],
      fakeIo({ stdin: 'correct horse battery staple' }),
    );
    expect(code).toBe(0);
    expect(calls.map((call) => call.method)).toEqual(['ExportWalletBackup']);
    expect(readFileSync(path, 'utf8')).toContain('agentpay-wallet-backup');
  });

  it('fails with the wallet list when several wallets exist and none is named', async () => {
    const { code, io } = await run(
      [
        'admin',
        'wallet-backup',
        'export',
        '--passphrase-stdin',
        '--output',
        backupPath(),
        '--json',
      ],
      [EXAMPLE, OTHER],
      fakeIo({ stdin: 'correct horse battery staple' }),
    );
    expect(code).toBe(2);
    const { error } = io.json<{ error: { code: string; message: string; next_action: string } }>();
    expect(error.code).toBe('wallet_choice_needed');
    expect(error.message).toContain('This machine has 2 wallets, so the command must name one:');
    expect(error.message).toContain(EXAMPLE.evm_address);
    expect(error.message).toContain(OTHER.vault_key_id);
    expect(error.next_action).toBe('Run the command again with `--wallet <vault-key-id|address>`.');
  });

  it('exports the wallet --wallet names by address or by vault key id', async () => {
    const byAddress = await run(
      [
        'admin',
        'wallet-backup',
        'export',
        '--passphrase-stdin',
        '--output',
        backupPath(),
        '--wallet',
        OTHER.evm_address?.toUpperCase().replace('0X', '0x') ?? '',
      ],
      [EXAMPLE, OTHER],
      fakeIo({ stdin: 'correct horse battery staple' }),
    );
    expect(byAddress.code).toBe(0);
    expect(byAddress.calls.at(-1)?.params).toMatchObject({ vault_key_id: OTHER.vault_key_id });
    await t?.close();

    const byId = await run(
      [
        'admin',
        'wallet-backup',
        'export',
        '--passphrase-stdin',
        '--output',
        backupPath(),
        '--wallet',
        OTHER.vault_key_id,
      ],
      [EXAMPLE, OTHER],
      fakeIo({ stdin: 'correct horse battery staple' }),
    );
    expect(byId.code).toBe(0);
    // A vault key id needs no lookup.
    expect(byId.calls.map((call) => call.method)).toEqual(['ExportWalletBackup']);
    expect(byId.calls[0]?.params).toMatchObject({ vault_key_id: OTHER.vault_key_id });
  });

  it('refuses a --wallet that names no wallet, listing the wallets', async () => {
    const { code, io, calls } = await run(
      [
        'admin',
        'wallet-backup',
        'export',
        '--passphrase-stdin',
        '--output',
        backupPath(),
        '--wallet',
        '0x0000000000000000000000000000000000000000',
      ],
      [EXAMPLE, OTHER],
      fakeIo({ stdin: 'correct horse battery staple' }),
    );
    expect(code).toBe(2);
    expect(io.err()).toContain(
      'No wallet on this machine is 0x0000000000000000000000000000000000000000',
    );
    expect(io.err()).toContain(OTHER.vault_key_id);
    expect(calls.map((call) => call.method)).toEqual(['ListWallets']);
  });

  it('shows the wallet picker in a terminal when several wallets exist', async () => {
    const { code, rendered, io } = await run(
      ['admin', 'wallet-backup', 'export'],
      [EXAMPLE, OTHER],
      fakeIo({ isTTY: true }),
    );
    const [picker] = rendered as ReactElement<{ wallets: WalletInfo[] }>[];
    expect(picker?.type).toBe(BackupWalletPicker);
    expect(picker?.props.wallets).toEqual([EXAMPLE, OTHER]);
    // The test renderer never picks, which is the same as esc: nothing is exported.
    expect(code).toBe(1);
    expect(io.err()).toContain('Nothing was changed.');
  });

  it('goes straight to the backup form in a terminal when there is one wallet', async () => {
    const { code, rendered } = await run(
      ['admin', 'wallet-backup', 'export'],
      [EXAMPLE],
      fakeIo({ isTTY: true }),
    );
    expect(code).toBe(0);
    expect(rendered).toHaveLength(1);
    expect(rendered[0]?.type).not.toBe(BackupWalletPicker);
  });
});

describe('backup wallet picker', () => {
  it('reports the chosen wallet', async () => {
    const onPick = vi.fn();
    const { lastFrame, stdin } = render(
      <BackupWalletPicker wallets={[EXAMPLE, OTHER]} onPick={onPick} />,
    );
    const frame = await waitFor(lastFrame, 'Choose the wallet to back up');
    expect(frame).toContain('This machine has 2 AgentPay wallets. Choose the one to back up.');
    await press(stdin, KEY.down, KEY.enter);
    expect(onPick).toHaveBeenCalledWith(OTHER.vault_key_id);
  });
});

describe('Wallet screen', () => {
  const current = { ...EXAMPLE, agent_key_ids: ['5e134267-fe6d-41fe-9264-d01e30aba2a8'] };
  const other = { ...OTHER, agent_key_ids: [] };

  it('marks the wallet the agents use and switches only after a confirmation naming both', async () => {
    const services = fakeAppServices({
      listWallets: vi.fn(async () => [other, current]),
      currentAgentKeyId: () => '5e134267-fe6d-41fe-9264-d01e30aba2a8',
    });
    const { lastFrame, stdin } = render(<WalletsScreen services={services} onBack={() => {}} />);
    const list = await waitFor(lastFrame, 'used by your agents');
    expect(list.split('\n').find((line) => line.includes('›'))).toContain('used by your agents');

    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Your agents already use this wallet.');
    await press(stdin, KEY.up);
    await waitFor(lastFrame, `› ${walletLabel(other)}`);
    await press(stdin, KEY.enter);
    const confirm = await waitFor(lastFrame, 'Switch wallets?');
    expect(confirm).toContain(`Agents will use  ${walletLabel(other)}`);
    expect(confirm).toContain(`Instead of       ${walletLabel(current)}`);
    expect(services.switchWallet).not.toHaveBeenCalled();
    await press(stdin, KEY.escape);
    await waitFor(lastFrame, 'Choose one to switch');
    expect(services.switchWallet).not.toHaveBeenCalled();

    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Switch wallets?');
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, `Your agents now use ${walletLabel(other)}.`);
    expect(services.switchWallet).toHaveBeenCalledWith(other);
  });
});

describe('switching wallets against the daemons', () => {
  let t: TestContext | null = null;
  afterEach(async () => {
    await t?.close();
    t = null;
  });

  it('reuses a key whose token this user still has, without touching the daemon', async () => {
    t = await testContext({ euid: 0 });
    const services = createAppServices(
      t.context,
      await t.context.payments({}),
      t.context.admin({ relay: false }),
    );
    await t.context.secrets.write('11111111-2222-4333-8444-555555555555', 'tok.en');
    await services.switchWallet({
      ...OTHER,
      agent_key_ids: ['11111111-2222-4333-8444-555555555555'],
    });
    expect(t.context.state.read().agentKeyId).toBe('11111111-2222-4333-8444-555555555555');
    expect(t.signer.calls.filter((c) => c.method !== 'Hello')).toEqual([]);
  });

  it('otherwise gives that wallet a new agent key with the current limits', async () => {
    t = await testContext({
      euid: 0,
      signer: (call) =>
        call.method === 'ListSpendingLimits'
          ? body(fixture('rpc/ListSpendingLimits.response.json'))
          : call.method === 'BootstrapWallet'
            ? body(fixture('rpc/BootstrapWallet.response.json'))
            : { close: true },
    });
    const services = createAppServices(
      t.context,
      await t.context.payments({}),
      t.context.admin({ relay: false }),
    );
    await services.switchWallet({ ...OTHER, agent_key_ids: [] });
    const bootstrap = t.signer.calls.find((c) => c.method === 'BootstrapWallet');
    const params = bootstrap?.params as { mode: unknown; limits: unknown[] };
    expect(params.mode).toEqual({ kind: 'reuse', vault_key_id: OTHER.vault_key_id });
    expect(params.limits).toEqual(limitsReport.limits.map((s) => s.limit));
  });
});

describe('naming wallets', () => {
  let t: TestContext | null = null;
  afterEach(async () => {
    await t?.close();
    t = null;
  });

  it('renames the highlighted wallet on the Wallet screen; an empty name removes it', async () => {
    const services = fakeAppServices({
      listWallets: vi.fn(async () => [EXAMPLE, OTHER]),
      currentAgentKeyId: () => null,
    });
    const { lastFrame, stdin } = render(<WalletsScreen services={services} onBack={() => {}} />);
    await waitFor(lastFrame, '› Trading bot');
    await press(stdin, KEY.down, 'n');
    await waitFor(lastFrame, 'Name this wallet');
    await press(stdin, ...'Ops'.split(''), KEY.enter);
    await waitFor(lastFrame, 'Named “Ops”.');
    expect(services.renameWallet).toHaveBeenCalledWith(OTHER, 'Ops');

    await press(stdin, KEY.up, 'n');
    const form = await waitFor(lastFrame, 'Name this wallet');
    expect(form).toContain('Trading bot');
    await press(stdin, ...Array.from({ length: 11 }, () => KEY.backspace), KEY.enter);
    await waitFor(lastFrame, 'Name removed.');
    expect(services.renameWallet).toHaveBeenLastCalledWith(EXAMPLE, null);
  });

  it('admin wallets rename names a wallet by address through RenameWallet', async () => {
    t = await testContext({
      euid: 0,
      signer: (call) =>
        call.method === 'ListWallets'
          ? ok('Wallets', [EXAMPLE, OTHER])
          : call.method === 'RenameWallet'
            ? body(fixture('rpc/RenameWallet.response.json'))
            : { close: true },
    });
    const code = await runCli(
      ['admin', 'wallets', 'rename', EXAMPLE.evm_address ?? '', 'Trading bot', '--json'],
      t.context,
    );
    expect(code).toBe(0);
    const call = t.signer.calls.find((c) => c.method === 'RenameWallet');
    expect(call?.params).toMatchObject({ vault_key_id: EXAMPLE.vault_key_id, name: 'Trading bot' });

    const cleared = await runCli(
      ['admin', 'wallets', 'rename', EXAMPLE.vault_key_id, '--clear'],
      t.context,
    );
    expect(cleared).toBe(0);
    expect(t.signer.calls.filter((c) => c.method === 'RenameWallet').at(-1)?.params).toMatchObject({
      name: null,
    });
    expect(RELAYED_METHODS).toContain('RenameWallet');
  });

  it('passes the name chosen in setup to BootstrapWallet', () => {
    expect(bootstrapMode({ kind: 'create', replaceExisting: false, name: 'Ops' }, null)).toEqual({
      kind: 'create',
      replace_existing: false,
      name: 'Ops',
    });
    expect(bootstrapMode({ kind: 'create', replaceExisting: false }, null)).toEqual({
      kind: 'create',
      replace_existing: false,
    });
  });
});
