import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createOnboardingServices } from '../src/app/services.js';
import { existingWalletIds, SignerCallError } from '../src/errors.js';
import type {
  BootstrapWalletParams,
  VerifyWalletBackupParams,
  WalletInfo,
  WireDaemonError,
} from '../src/generated/index.js';
import { DEFAULT_PAYMENTS_CONFIG } from '../src/limits/default-config.js';
import {
  isTestnetRow,
  rowsFromConfig,
  toggleExcluded,
  toSpendingLimits,
} from '../src/limits/model.js';
import { OnboardingWizard } from '../src/screens/onboarding/OnboardingWizard.js';
import type { OnboardingServices } from '../src/screens/types.js';
import { AGENT_KEY_ID, AGENT_TOKEN, type TestContext, testContext } from './helpers/context.js';
import { body, fail, type Handler, ok } from './helpers/fake-daemon.js';
import { fixture, fixtureData } from './helpers/fixtures.js';
import { KEY, press, render, waitFor } from './helpers/ink.js';
import { fakeOnboardingServices, wallet } from './helpers/services.js';

/** Position of ETH on Ethereum among the rows the wizard shows (main networks only). */
const ethRow = () =>
  rowsFromConfig(DEFAULT_PAYMENTS_CONFIG)
    .filter((row) => !isTestnetRow(row))
    .findIndex((row) => row.id === 'eth@eth');

describe('onboarding wizard', () => {
  it('walks welcome → Touch ID → limits → creating → backup → done without timers', async () => {
    const services = fakeOnboardingServices();
    const onFinish = vi.fn();
    const { lastFrame, stdin } = render(
      <OnboardingWizard services={services} onFinish={onFinish} />,
    );

    const welcome = await waitFor(lastFrame, 'Create a new wallet');
    expect(welcome).toMatchSnapshot('welcome');
    await press(stdin, KEY.enter);
    // An optional name for the new wallet.
    await waitFor(lastFrame, 'Name this wallet (optional)');
    await press(stdin, ...'Trading bot'.split(''), KEY.enter);

    const touchId = await waitFor(lastFrame, 'Turn on Touch ID (recommended)');
    expect(touchId).toContain('Step 2 of 6');
    expect(touchId).toMatchSnapshot('protect your wallet');
    await press(stdin, KEY.enter);
    expect(services.enableTouchId).toHaveBeenCalled();

    const limits = await waitFor(lastFrame, '4 assets need a limit or must be blocked');
    expect(limits).toContain('Step 3 of 6');
    expect(limits).toMatchSnapshot('spending limits');
    // Enter does nothing until every asset is decided.
    await press(stdin, KEY.enter);
    expect(lastFrame()).toContain('Set spending limits');
    // ETH has no recommended limit: block it on Ethereum, then on every other network at once.
    await press(stdin, ...Array.from({ length: ethRow() }, () => KEY.down), 'x');
    await waitFor(lastFrame, '3 assets need a limit or must be blocked');
    await press(stdin, 'X');
    await waitFor(lastFrame, 'Every asset has a limit or is blocked.');
    await press(stdin, KEY.enter);

    const creating = await waitFor(lastFrame, 'Your wallet is ready.');
    expect(creating).toContain('✓ Generating wallet keys');
    expect(creating).toContain('✓ Saving the credentials to your keychain');
    const [choice, rows] = vi.mocked(services.createWallet).mock.calls[0] ?? [];
    expect(choice).toEqual({ kind: 'create', replaceExisting: false, name: 'Trading bot' });
    expect(rows?.find((row) => row.id === 'eth@eth')?.status).toBe('excluded');
    expect(rows?.find((row) => row.id === 'usd1@bsc')?.status).toBe('recommended');
    // Test networks were not shown, so they are blocked, never given unseen limits.
    const testnetRows = rows?.filter(isTestnetRow) ?? [];
    expect(new Set(testnetRows.map((row) => row.network))).toEqual(
      new Set(['arbitrum-sepolia', 'base-sepolia', 'solana-devnet', 'tempo-testnet']),
    );
    expect(testnetRows.every((row) => row.status === 'excluded')).toBe(true);
    expect(
      toSpendingLimits(rows ?? []).some((limit) => [42431, 84532, 421614].includes(limit.chain_id)),
    ).toBe(false);
    await press(stdin, KEY.enter);

    const backup = await waitFor(lastFrame, 'Back up your wallet');
    expect(backup).toContain('Skip for now');
    await press(stdin, KEY.down, KEY.enter);

    const done = await waitFor(lastFrame, 'You’re all set');
    expect(done).toContain(wallet.evm_address ?? '');
    expect(done).toMatchSnapshot('done');
    await press(stdin, KEY.down, KEY.enter);
    expect(onFinish).toHaveBeenCalledWith({
      wallet: { evmAddress: wallet.evm_address, solanaAddress: wallet.solana_address },
      touchId: true,
      backupPath: null,
    });
  });

  it('restores from a backup file and shows the funding screen at the end', async () => {
    const services = fakeOnboardingServices({ touchIdState: async () => 'unavailable' });
    const { lastFrame, stdin } = render(<OnboardingWizard services={services} />);
    await waitFor(lastFrame, 'Restore from a backup');
    await press(
      stdin,
      KEY.down,
      KEY.enter,
      '/backups/wallet.json',
      KEY.enter,
      'correct horse battery',
      KEY.enter,
      // Keep the name saved in the backup.
      KEY.enter,
    );
    await waitFor(lastFrame, 'Admin approvals use sudo');
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Set spending limits');
    await press(stdin, ...Array.from({ length: ethRow() }, () => KEY.down), '+', 'X', KEY.enter);
    await waitFor(lastFrame, 'Restoring wallet keys from the backup');
    expect(vi.mocked(services.createWallet).mock.calls[0]?.[0]).toEqual({
      kind: 'restore',
      path: '/backups/wallet.json',
      passphrase: 'correct horse battery',
      replaceExisting: false,
    });
    await waitFor(lastFrame, 'Your wallet is ready.');
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Back up your wallet');
    await press(stdin, KEY.down, KEY.enter);
    await waitFor(lastFrame, 'You’re all set');
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Important things to know');
    expect(services.funding).toHaveBeenCalled();
  });

  it('shows a creation failure with retry', async () => {
    let attempts = 0;
    const services = fakeOnboardingServices({
      touchIdState: async () => 'unavailable',
      loadLimits: async () =>
        rowsFromConfig(DEFAULT_PAYMENTS_CONFIG).map((row) =>
          row.status === 'unset' ? toggleExcluded(row) : row,
        ),
      createWallet: async () => {
        attempts += 1;
        if (attempts === 1) {
          throw new Error('daemon restarted');
        }
        return { evmAddress: '0xabc', solanaAddress: null };
      },
    });
    const { lastFrame, stdin } = render(<OnboardingWizard services={services} />);
    await waitFor(lastFrame, 'Create a new wallet');
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Name this wallet');
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Continue');
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Every asset has a limit');
    await press(stdin, KEY.enter);
    expect(await waitFor(lastFrame, 'daemon restarted')).toContain('✗');
    await press(stdin, 'r');
    await waitFor(lastFrame, 'Your wallet is ready.');
  });

  /** Runs the wizard up to wallet creation against a machine that already has a wallet. */
  async function walletExists() {
    const createWallet = vi.fn(async (choice: { kind: string; replaceExisting?: boolean }) => {
      if (choice.kind !== 'reuse' && !choice.replaceExisting) {
        throw new SignerCallError({
          kind: 'WalletAlreadyExists',
          data: { vault_key_ids: ['5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d'] },
        });
      }
      return { evmAddress: '0xabc', solanaAddress: null };
    });
    const services = fakeOnboardingServices({
      touchIdState: async () => 'unavailable',
      loadLimits: async () =>
        rowsFromConfig(DEFAULT_PAYMENTS_CONFIG).map((row) =>
          row.status === 'unset' ? toggleExcluded(row) : row,
        ),
      createWallet,
    });
    const view = render(<OnboardingWizard services={services} />);
    await waitFor(view.lastFrame, 'Create a new wallet');
    await press(view.stdin, KEY.enter);
    await waitFor(view.lastFrame, 'Name this wallet');
    await press(view.stdin, KEY.enter);
    await waitFor(view.lastFrame, 'Continue');
    await press(view.stdin, KEY.enter);
    await waitFor(view.lastFrame, 'Every asset has a limit');
    await press(view.stdin, KEY.enter);
    const warning = await waitFor(view.lastFrame, 'A wallet already exists');
    return { ...view, createWallet, warning };
  }

  it('keeps an existing wallet by default instead of replacing it', async () => {
    const { lastFrame, stdin, createWallet, warning } = await walletExists();
    expect(warning).toContain('Replacing it cannot be undone');
    expect(warning).toContain('Keep the existing wallet');
    expect(warning).not.toContain('✗');
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Your wallet is ready.');
    expect(createWallet.mock.calls.map(([choice]) => choice)).toEqual([
      { kind: 'create', replaceExisting: false },
      { kind: 'reuse', vaultKeyId: '5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d' },
    ]);
  });

  it('replaces an existing wallet only after OVERWRITE is typed', async () => {
    const { lastFrame, stdin, createWallet } = await walletExists();
    await press(stdin, KEY.down, KEY.enter);
    await waitFor(lastFrame, 'Type OVERWRITE to delete the existing wallet');
    // Anything but the exact word is refused; esc goes back to the safe choice.
    await press(stdin, 'overwrite', KEY.enter);
    await waitFor(lastFrame, 'Type OVERWRITE exactly');
    await press(stdin, KEY.escape);
    await waitFor(lastFrame, 'Delete it and create a new wallet');
    expect(createWallet).toHaveBeenCalledTimes(1);

    await press(stdin, KEY.down, KEY.enter, 'OVERWRITE', KEY.enter);
    await waitFor(lastFrame, 'Your wallet is ready.');
    expect(createWallet.mock.calls.map(([choice]) => choice)).toEqual([
      { kind: 'create', replaceExisting: false },
      { kind: 'create', replaceExisting: true },
    ]);
  });
});

describe('onboarding services', () => {
  let t: TestContext | null = null;
  afterEach(async () => {
    await t?.close();
    t = null;
  });

  it('bootstraps the wallet with the chosen limits and stores the agent token', async () => {
    t = await testContext({
      euid: 0,
      credentials: false,
      signer: (call) =>
        call.method === 'BootstrapWallet'
          ? body(fixture('rpc/BootstrapWallet.response.json'))
          : { close: true },
    });
    const services = createOnboardingServices(t.context, t.context.admin({ relay: false }));
    const rows = (await services.loadLimits()).map((row) =>
      row.status === 'unset' ? toggleExcluded(row) : row,
    );
    const progress: string[] = [];
    const created = await services.createWallet(
      { kind: 'create', replaceExisting: false },
      rows,
      (task) => progress.push(task),
    );
    expect(progress).toEqual(['keys', 'agent', 'store']);
    expect(created).toEqual({
      evmAddress: '0x2c7536e3605d9c16a7a3d7b1898e529396a65c23',
      solanaAddress: '9fijMemJYwXS5QD85Qxsq7iKqvSebgb6LvpGftgkeigk',
    });
    const call = t.signer.calls.find((c) => c.method === 'BootstrapWallet');
    expect(call?.params).toMatchObject({
      auth: 'peer_credentials',
      mode: { kind: 'create', replace_existing: false },
    });
    expect((call?.params as { limits?: unknown[] } | undefined)?.limits?.length).toBeGreaterThan(0);
    expect(await t.context.secrets.read(AGENT_KEY_ID)).toBe(AGENT_TOKEN);
    expect(t.context.state.read().agentKeyId).toBe(AGENT_KEY_ID);
    // Before any credentials exist the payments service was never asked for its configuration.
    expect(t.payments.calls).toEqual([]);
  });

  it('replaces credentials the daemons no longer accept instead of stopping at the limits', async () => {
    // A previous install left credentials behind; its state was removed.
    t = await testContext({
      euid: 0,
      payments: () => fail('AgentAuthenticationFailed'),
      signer: (call) =>
        call.method === 'BootstrapWallet'
          ? body(fixture('rpc/BootstrapWallet.response.json'))
          : { close: true },
    });
    const services = createOnboardingServices(t.context, t.context.admin({ relay: false }));
    const rows = (await services.loadLimits()).map((row) =>
      row.status === 'unset' ? toggleExcluded(row) : row,
    );
    expect(rows.length).toBeGreaterThan(0);
    await services.createWallet({ kind: 'create', replaceExisting: false }, rows, () => {});
    expect(t.signer.calls.some((call) => call.method === 'BootstrapWallet')).toBe(true);
    expect(await t.context.secrets.read(AGENT_KEY_ID)).toBe(AGENT_TOKEN);
  });

  async function bootstrapCall(choice: Parameters<OnboardingServices['createWallet']>[0]) {
    t = await testContext({
      euid: 0,
      credentials: false,
      signer: (call) =>
        call.method === 'BootstrapWallet'
          ? body(fixture('rpc/BootstrapWallet.response.json'))
          : { close: true },
    });
    const services = createOnboardingServices(t.context, t.context.admin({ relay: false }));
    const rows = (await services.loadLimits()).map((row) =>
      row.status === 'unset' ? toggleExcluded(row) : row,
    );
    await services.createWallet(choice, rows, () => {});
    return t.signer.calls.find((c) => c.method === 'BootstrapWallet')
      ?.params as BootstrapWalletParams;
  }

  it('sends replace_existing: true only for a confirmed overwrite', async () => {
    const params = await bootstrapCall({ kind: 'create', replaceExisting: true });
    expect(params.mode).toEqual({ kind: 'create', replace_existing: true });
  });

  it('restores from the backup file verbatim', async () => {
    const backup = fixture<{ params: VerifyWalletBackupParams }>(
      'rpc/VerifyWalletBackup.request.json',
    ).params;
    const path = join(mkdtempSync(join(tmpdir(), 'apb-')), 'backup.json');
    writeFileSync(path, backup.backup_json);
    const params = await bootstrapCall({
      kind: 'restore',
      path,
      passphrase: backup.passphrase,
      replaceExisting: false,
    });
    expect(params.mode).toEqual({
      kind: 'restore_from_backup',
      backup_json: backup.backup_json,
      passphrase: backup.passphrase,
      replace_existing: false,
    });
  });

  it('surfaces WalletAlreadyExists as a typed error with one next action', async () => {
    t = await testContext({
      euid: 0,
      credentials: false,
      signer: () => fail('WalletAlreadyExists', { vault_key_ids: ['a', 'b'] }),
    });
    const services = createOnboardingServices(t.context, t.context.admin({ relay: false }));
    const rows = (await services.loadLimits()).map((row) =>
      row.status === 'unset' ? toggleExcluded(row) : row,
    );
    const error = await services
      .createWallet({ kind: 'create', replaceExisting: false }, rows, () => {})
      .catch((e: unknown) => e);
    expect(existingWalletIds(error)).toEqual(['a', 'b']);
    expect((error as SignerCallError).guidance).toEqual({
      message: '2 wallets already exist on this machine, so nothing was changed.',
      next: 'Run `agentpay setup` again and choose “Keep the existing wallet” to pick the wallet to keep; nothing is deleted.',
    });
    expect(await t.context.secrets.read(AGENT_KEY_ID)).toBeNull();
  });

  it('points an ambiguous reuse to the wallet picker, not back to the same choice', async () => {
    t = await testContext({
      euid: 0,
      credentials: false,
      signer: () =>
        fail('InvalidWalletRequest', 'the daemon holds 2 vault keys; pass vault_key_id'),
    });
    const services = createOnboardingServices(t.context, t.context.admin({ relay: false }));
    const rows = (await services.loadLimits()).map((row) =>
      row.status === 'unset' ? toggleExcluded(row) : row,
    );
    const error = await services
      .createWallet({ kind: 'reuse' }, rows, () => {})
      .catch((e: unknown) => e);
    expect((error as SignerCallError).guidance.next).toContain(
      'choose “Keep the existing wallet” to pick the wallet to keep',
    );
    expect(await t.context.secrets.read(AGENT_KEY_ID)).toBeNull();
  });
});

describe('onboarding wizard on a machine with several wallets', () => {
  const FIRST = '5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d';
  const SECOND = 'a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d';
  let t: TestContext | null = null;
  afterEach(async () => {
    await t?.close();
    t = null;
  });

  /** The API's `WalletAlreadyExists` example, reporting `ids` as the wallets on the machine. */
  function walletAlreadyExists(ids: string[]) {
    const example = fixture<WireDaemonError[]>('errors.json').find(
      (error) => error.kind === 'WalletAlreadyExists',
    );
    return fail('WalletAlreadyExists', {
      ...(example as { data: object }).data,
      vault_key_ids: ids,
    });
  }

  const bootstrapModes = () =>
    (t?.signer.calls ?? [])
      .filter((call) => call.method === 'BootstrapWallet')
      .map((call) => (call.params as BootstrapWalletParams).mode);

  /** The API's `ListWallets` example, once per id, each a day older than the next. */
  function walletList(ids: string[]): WalletInfo[] {
    const [example] = fixtureData<WalletInfo[]>('rpc/ListWallets.response.json');
    return ids.map((id, index) => ({
      ...(example as WalletInfo),
      vault_key_id: id,
      created_at: [2026, 300 + index, 11, 59, 0, 0, 0, 0, 0],
      agent_key_ids: index === 0 ? [] : (example as WalletInfo).agent_key_ids,
    }));
  }

  /**
   * Runs the real onboarding services against a signer daemon holding `ids`: `create` is
   * refused with `WalletAlreadyExists`, `reuse` answers with the API's bootstrap example, and
   * `ListWallets` lists them (with `listable: false`, only for the welcome step: the overwrite
   * step's read fails). The user picks "Create" anyway. Stops at the overwrite warning.
   */
  async function untilOverwriteWarning(
    ids: string[],
    options: { credentials?: boolean; listable?: boolean } = {},
  ) {
    let listed = 0;
    t = await testContext({
      euid: 0,
      credentials: options.credentials ?? false,
      signer: (call) => {
        if (call.method === 'ListWallets' && (options.listable !== false || listed++ === 0)) {
          return ok('Wallets', walletList(ids));
        }
        if (call.method !== 'BootstrapWallet') {
          return { close: true };
        }
        return (call.params as BootstrapWalletParams).mode.kind === 'reuse'
          ? body(fixture('rpc/BootstrapWallet.response.json'))
          : walletAlreadyExists(ids);
      },
    });
    const services = createOnboardingServices(t.context, t.context.admin({ relay: false }));
    const view = render(<OnboardingWizard services={services} />);
    await waitFor(view.lastFrame, '› Keep the existing wallet');
    await press(view.stdin, KEY.up, KEY.up, KEY.enter);
    await waitFor(view.lastFrame, 'Name this wallet');
    await press(view.stdin, KEY.enter);
    await waitFor(view.lastFrame, 'Admin approvals use sudo');
    await press(view.stdin, KEY.enter);
    await waitFor(view.lastFrame, '4 assets need a limit or must be blocked');
    await press(view.stdin, 'X');
    await waitFor(view.lastFrame, 'Every asset has a limit or is blocked.');
    await press(view.stdin, KEY.enter);
    await waitFor(view.lastFrame, 'Replacing it cannot be undone');
    return view;
  }

  it('asks which wallet to keep, by address, and reuses the chosen vault key', async () => {
    const { lastFrame, stdin } = await untilOverwriteWarning([FIRST, SECOND]);
    const warning = lastFrame() ?? '';
    expect(warning).toContain('This machine already has 2 AgentPay wallets.');
    expect(warning).toContain('Trading bot · 0x2c75…5c23 · created 2026-10-27 · 0 agent keys');
    expect(warning).toContain('Trading bot · 0x2c75…5c23 · created 2026-10-28 · 1 agent key');
    await press(stdin, KEY.enter);

    const picker = await waitFor(lastFrame, 'Choose the wallet to keep');
    expect(picker).toContain('This machine has 2 AgentPay wallets.');
    expect(picker).toContain('› Trading bot · 0x2c75…5c23 · created 2026-10-27 · 0 agent keys');
    expect(picker).toContain('  Trading bot · 0x2c75…5c23 · created 2026-10-28 · 1 agent key');
    expect(picker).not.toContain(FIRST);
    expect(picker).not.toContain('listed by key id');
    expect(picker).toContain('↑↓ select · enter confirm · esc back');
    expect(picker).toContain('Step 4 of 6');
    await press(stdin, KEY.down, KEY.enter);

    await waitFor(lastFrame, 'Your wallet is ready.');
    expect(bootstrapModes()).toEqual([
      { kind: 'create', replace_existing: false },
      { kind: 'reuse', vault_key_id: SECOND },
    ]);
    expect(await t?.context.secrets.read(AGENT_KEY_ID)).toBe(AGENT_TOKEN);
  });

  it('shows the wallets by key id when the wallet list cannot be read', async () => {
    const { lastFrame, stdin } = await untilOverwriteWarning([FIRST, SECOND], {
      listable: false,
    });
    expect(lastFrame()).toContain(FIRST);
    await press(stdin, KEY.enter);
    const picker = await waitFor(lastFrame, 'Choose the wallet to keep');
    expect(picker).toContain(`Wallet 1  ${FIRST}`);
    expect(picker).toContain(`Wallet 2  ${SECOND}`);
    expect(picker).toContain('wallets are shown by key id');
    await press(stdin, KEY.down, KEY.enter);
    await waitFor(lastFrame, 'Your wallet is ready.');
    expect(bootstrapModes()).toEqual([
      { kind: 'create', replace_existing: false },
      { kind: 'reuse', vault_key_id: SECOND },
    ]);
  });

  it('keeps the only wallet by its id without a picker', async () => {
    const { lastFrame, stdin, frames } = await untilOverwriteWarning([FIRST]);
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Your wallet is ready.');
    expect(frames.some((frame) => frame.includes('Choose the wallet to keep'))).toBe(false);
    expect(bootstrapModes()).toEqual([
      { kind: 'create', replace_existing: false },
      { kind: 'reuse', vault_key_id: FIRST },
    ]);
  });

  it('goes back from the picker to the overwrite warning with esc', async () => {
    const { lastFrame, stdin } = await untilOverwriteWarning([FIRST, SECOND]);
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Choose the wallet to keep');
    await press(stdin, KEY.escape);

    const warning = await waitFor(lastFrame, 'Replacing it cannot be undone');
    expect(warning).toContain('A wallet already exists');
    expect(warning).not.toContain('Choose the wallet to keep');
    expect(bootstrapModes()).toEqual([{ kind: 'create', replace_existing: false }]);

    // Keeping again shows the picker again, starting at the first wallet.
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Choose the wallet to keep');
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Your wallet is ready.');
    expect(bootstrapModes()).toEqual([
      { kind: 'create', replace_existing: false },
      { kind: 'reuse', vault_key_id: FIRST },
    ]);
  });
});

describe('onboarding services with a chosen wallet', () => {
  let t: TestContext | null = null;
  afterEach(async () => {
    await t?.close();
    t = null;
  });

  async function keep(vaultKeyId: string, signer: Handler) {
    t = await testContext({ euid: 0, credentials: true, signer });
    const services = createOnboardingServices(t.context, t.context.admin({ relay: false }));
    const rows = rowsFromConfig(DEFAULT_PAYMENTS_CONFIG).map((row) =>
      row.status === 'unset' ? toggleExcluded(row) : row,
    );
    await services.createWallet({ kind: 'reuse', vaultKeyId }, rows, () => {});
    return services;
  }

  it('falls back to the chosen wallet’s own agent key when the stored one is another wallet’s', async () => {
    const vaultKeyId = 'a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d';
    await keep(vaultKeyId, (call) => {
      const mode = (call.params as BootstrapWalletParams).mode;
      return mode.kind === 'reuse' && mode.agent_key_id
        ? fail(
            'InvalidWalletRequest',
            `agent key ${mode.agent_key_id} belongs to another vault key`,
          )
        : body(fixture('rpc/BootstrapWallet.response.json'));
    });
    expect(
      t?.signer.calls
        .filter((call) => call.method === 'BootstrapWallet')
        .map((call) => (call.params as BootstrapWalletParams).mode),
    ).toEqual([
      { kind: 'reuse', vault_key_id: vaultKeyId, agent_key_id: AGENT_KEY_ID },
      { kind: 'reuse', vault_key_id: vaultKeyId },
    ]);
  });

  it('backs up the wallet it set up', async () => {
    const services = await keep('5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d', (call) =>
      body(fixture(`rpc/${call.method}.response.json`)),
    );
    const path = join(mkdtempSync(join(tmpdir(), 'apb-')), 'backup.json');
    await services.exportBackup(path, 'correct horse battery staple');
    expect(
      t?.signer.calls.find((call) => call.method === 'ExportWalletBackup')?.params,
    ).toMatchObject({
      vault_key_id: '5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d',
    });
  });
});
