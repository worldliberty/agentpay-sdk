import { afterEach, describe, expect, it, vi } from 'vitest';
import { createOnboardingServices } from '../src/app/services.js';
import { PaymentsCallError } from '../src/errors.js';
import type { SpendingLimit, TokenInfo } from '../src/generated/index.js';
import { DEFAULT_PAYMENTS_CONFIG } from '../src/limits/default-config.js';
import {
  isTestnetRow,
  rowsFromConfig,
  toggleExcluded,
  toSpendingLimits,
} from '../src/limits/model.js';
import { LimitsScreen } from '../src/screens/Limits.js';
import { OnboardingWizard } from '../src/screens/onboarding/OnboardingWizard.js';
import type { NewToken } from '../src/screens/types.js';
import { AGENT_KEY_ID, type TestContext, testContext } from './helpers/context.js';
import { body, fail } from './helpers/fake-daemon.js';
import { fixture, fixtureData } from './helpers/fixtures.js';
import { KEY, press, render, waitFor } from './helpers/ink.js';
import { fakeAppServices, fakeOnboardingServices, newTokenRowFor } from './helpers/services.js';

const USDT = '0x55d398326f99059fF775485246999027B3197955';

async function type(stdin: { write: (data: string) => void }, text: string) {
  await press(stdin, ...text.split(''));
}

/** Walks the wizard to the spending limits step. */
async function toLimits(services = fakeOnboardingServices()) {
  const view = render(<OnboardingWizard services={services} />);
  await waitFor(view.lastFrame, 'Create a new wallet');
  await press(view.stdin, KEY.enter);
  await waitFor(view.lastFrame, 'Name this wallet');
  await press(view.stdin, KEY.enter);
  await waitFor(view.lastFrame, 'Protect your wallet');
  await press(view.stdin, KEY.down, KEY.enter);
  await waitFor(view.lastFrame, 'Set spending limits');
  return { ...view, services };
}

describe('adding a token in the spending limits step', () => {
  it('reads the token, adds it as a row to limit, and saves it with the wallet', async () => {
    const { lastFrame, stdin, services } = await toLimits();
    expect(lastFrame()).toContain('a add token');
    await press(stdin, 'a');
    await waitFor(lastFrame, 'Choose the network');
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Contract address');
    await type(stdin, USDT);
    await press(stdin, KEY.enter);

    const table = await waitFor(lastFrame, 'Added USDT on BSC (18 decimals)');
    expect(services.lookupToken).toHaveBeenCalledWith({ network: 'bsc', address: USDT });
    // The new row is selected, and setup cannot continue until it has a limit or is blocked.
    expect(table).toContain('› USDT');
    expect(table).toContain('5 assets need a limit or must be blocked');
    await press(stdin, '+');
    // ETH still needs a decision: block it on Ethereum. The wizard shows main networks only, and
    // the new token is the last row.
    const shown = rowsFromConfig(DEFAULT_PAYMENTS_CONFIG).filter((row) => !isTestnetRow(row));
    const fromUsdtToEth = shown.length - shown.findIndex((row) => row.id === 'eth@eth');
    await press(stdin, ...Array.from({ length: fromUsdtToEth }, () => KEY.up), 'x');
    await waitFor(lastFrame, '3 assets need a limit or must be blocked');
    // Then on its other networks at once.
    await press(stdin, 'X');
    await waitFor(lastFrame, 'Every asset has a limit or is blocked.');
    await press(stdin, KEY.enter);

    await waitFor(lastFrame, 'Your wallet is ready.');
    const [, chosen] = vi.mocked(services.createWallet).mock.calls[0] ?? [];
    const usdt = chosen?.find((row) => row.symbol === 'USDT');
    expect(usdt?.status).toBe('custom');
    expect(usdt?.newToken).toEqual({ network: 'bsc', address: USDT, symbol: 'USDT', decimals: 18 });
    expect(
      toSpendingLimits(chosen ?? []).some(
        (l) => l.asset.kind === 'erc20' && l.asset.value === USDT.toLowerCase(),
      ),
    ).toBe(true);
  });

  it('takes typed-in symbol and decimals when the network cannot be read', async () => {
    const lookupToken = vi.fn(async (token: NewToken) => {
      if (token.decimals === undefined) {
        throw new PaymentsCallError({
          kind: 'ChainRpc',
          data: 'eth_call failed: rate limited',
        } as never);
      }
      return { row: newTokenRowFor(token), verified: false };
    });
    const { lastFrame, stdin } = await toLimits(fakeOnboardingServices({ lookupToken }));
    await press(stdin, 'a');
    await waitFor(lastFrame, 'Choose the network');
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Contract address');
    await type(stdin, USDT);
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'fill in the details below');
    await type(stdin, 'USDT');
    await press(stdin, KEY.enter);
    await type(stdin, '18');
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Added USDT on BSC (18 decimals, entered by you)');
    expect(lookupToken).toHaveBeenLastCalledWith({
      network: 'bsc',
      address: USDT,
      symbol: 'USDT',
      decimals: 18,
    });
  });

  it('asks for a Solana mint’s symbol, and esc backs out without adding anything', async () => {
    const { lastFrame, stdin, services } = await toLimits();
    await press(stdin, 'a');
    await waitFor(lastFrame, 'Choose the network');
    await press(stdin, KEY.down, KEY.down, KEY.enter);
    await waitFor(lastFrame, 'Mint address');
    await type(stdin, 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB');
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'For example USDT');
    expect(services.lookupToken).not.toHaveBeenCalled();
    await press(stdin, KEY.escape, KEY.escape, KEY.escape);
    const back = await waitFor(lastFrame, 'a add token');
    expect(back).toContain('Set spending limits');
    expect(back).toContain('4 assets need a limit or must be blocked');
  });
});

describe('adding a token on the Limits screen', () => {
  it('adds the row and saves it with the other limits', async () => {
    const services = fakeAppServices();
    const { lastFrame, stdin } = render(<LimitsScreen services={services} onBack={() => {}} />);
    await waitFor(lastFrame, 'Per payment');
    await press(stdin, 'a');
    await waitFor(lastFrame, 'Choose the network');
    await press(stdin, KEY.enter);
    await type(stdin, USDT);
    await press(stdin, KEY.enter);
    await waitFor(lastFrame, 'Added USDT on BSC');
    await press(stdin, '+', KEY.enter);
    await vi.waitFor(() => expect(services.saveLimits).toHaveBeenCalled());
    const [saved] = vi.mocked(services.saveLimits).mock.calls[0] ?? [];
    expect(saved?.find((row) => row.symbol === 'USDT')?.status).toBe('custom');
  });
});

describe('token services against the daemons', () => {
  let t: TestContext | null = null;
  afterEach(async () => {
    await t?.close();
    t = null;
  });

  const info = fixtureData<TokenInfo>('payments/LookupToken.response.json');

  it('looks a token up before any credentials exist, then saves it once the wallet does', async () => {
    t = await testContext({
      euid: 0,
      credentials: false,
      signer: (call) =>
        call.method === 'BootstrapWallet'
          ? body(fixture('rpc/BootstrapWallet.response.json'))
          : { close: true },
      payments: (call) =>
        call.method === 'LookupToken'
          ? body(fixture('payments/LookupToken.response.json'))
          : call.method === 'AddToken'
            ? body(fixture('payments/AddToken.response.json'))
            : { close: true },
    });
    const services = createOnboardingServices(t.context, t.context.admin({ relay: false }));
    const rows = await services.loadLimits();
    const { row, verified } = await services.lookupToken({
      network: info.network,
      address: info.address,
    });
    const lookup = t.payments.calls.find((c) => c.method === 'LookupToken');
    expect(lookup?.params).toEqual({ network: info.network, address: info.address });
    expect(row).toMatchObject({ symbol: info.symbol, decimals: info.decimals, status: 'unset' });
    expect(verified).toBe(info.verified_on_chain);

    const chosen = [
      ...rows.map((r) => (r.status === 'unset' ? toggleExcluded(r) : r)),
      { ...row, status: 'custom' as const, perTx: '1', daily: '10', weekly: '50' },
    ];
    const created = await services.createWallet(
      { kind: 'create', replaceExisting: false },
      chosen,
      () => {},
    );
    expect(created.unsavedTokens).toBeUndefined();
    const add = t.payments.calls.find((c) => c.method === 'AddToken');
    expect(add?.params).toMatchObject({
      network: info.network,
      address: info.address,
      symbol: info.symbol,
      decimals: info.decimals,
      auth: { agent_key_id: AGENT_KEY_ID },
    });
    const bootstrap = t.signer.calls.find((c) => c.method === 'BootstrapWallet');
    const limits = (bootstrap?.params as { limits: SpendingLimit[] } | undefined)?.limits ?? [];
    expect(limits.map((l) => JSON.stringify(l.asset))).toContain(JSON.stringify(row.asset));
  });

  it('reports a token it could not save without failing the wallet', async () => {
    t = await testContext({
      euid: 0,
      credentials: false,
      signer: (call) =>
        call.method === 'BootstrapWallet'
          ? body(fixture('rpc/BootstrapWallet.response.json'))
          : { close: true },
      payments: (call) =>
        call.method === 'AddToken' ? fail('ChainRpc', 'endpoint unreachable') : { close: true },
    });
    const services = createOnboardingServices(t.context, t.context.admin({ relay: false }));
    const rows = await services.loadLimits();
    const usdt = {
      ...newTokenRowFor({ network: 'bsc', address: USDT }),
      status: 'custom' as const,
      perTx: '1',
      daily: '1',
      weekly: '1',
    };
    const created = await services.createWallet(
      { kind: 'create', replaceExisting: false },
      [...rows.map((r) => (r.status === 'unset' ? toggleExcluded(r) : r)), usdt],
      () => {},
    );
    expect(created.unsavedTokens).toEqual(['USDT on BSC']);
  });
});
