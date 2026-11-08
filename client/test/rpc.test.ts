import { afterEach, describe, expect, it } from 'vitest';
import { copy } from '../src/copy/index.js';
import { PaymentsClient } from '../src/daemon/payments.js';
import { majorVersion } from '../src/daemon/rpc.js';
import { SignerClient } from '../src/daemon/signer.js';
import {
  IncompatibleApiError,
  PaymentsCallError,
  ProtocolError,
  SignerCallError,
} from '../src/errors.js';
import {
  API_VERSION,
  type DaemonRpcRequest,
  type WireDaemonError,
} from '../src/generated/index.js';
import {
  body,
  type FakeDaemon,
  fail,
  type Handler,
  HELLO,
  ok,
  startFakeDaemon,
  withHello,
} from './helpers/fake-daemon.js';
import { fixture } from './helpers/fixtures.js';

const uid = process.getuid?.() ?? 0;
const daemons: FakeDaemon[] = [];
afterEach(async () => {
  await Promise.all(daemons.splice(0).map((d) => d.close()));
});

async function signerFor(handler: Handler) {
  const daemon = await startFakeDaemon(handler);
  daemons.push(daemon);
  const client = new SignerClient({
    endpoint: { service: 'signer', path: daemon.path, trust: () => ({ kind: 'user', uid }) },
  });
  return { daemon, client };
}

const AUTH = { agent_key_id: '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d', agent_auth_token: 't' };

describe('RPC client', () => {
  it('handshakes once and then sends typed requests', async () => {
    const { daemon, client } = await signerFor(
      withHello(() => body(fixture('rpc/ListManualApprovalRequests.response.json'))),
    );
    const listed = await client.listApprovals('peer_credentials');
    await client.listApprovals('peer_credentials');
    expect(listed[0]?.status).toBe('pending');
    expect(daemon.calls.map((c) => c.method)).toEqual([
      'Hello',
      'ListManualApprovalRequests',
      'ListManualApprovalRequests',
    ]);
    expect(daemon.calls[1]).toEqual({
      method: 'ListManualApprovalRequests',
      params: { auth: 'peer_credentials' },
    });
  });

  it('accepts a daemon reporting the generated API_VERSION', async () => {
    const { client } = await signerFor(withHello(() => ok('ManualApprovalRequests', [])));
    expect((await client.hello()).api_version).toBe(API_VERSION);
    await expect(client.listApprovals('peer_credentials')).resolves.toEqual([]);
  });

  it('accepts another minor or patch version of the same major version', async () => {
    const major = majorVersion(API_VERSION);
    for (const theirs of [`${major}.0.0`, `${major}.99.7`]) {
      const { client } = await signerFor((call) =>
        call.method === 'Hello'
          ? ok('Hello', { ...HELLO, api_version: theirs })
          : ok('ManualApprovalRequests', []),
      );
      await expect(client.listApprovals('peer_credentials')).resolves.toEqual([]);
    }
  });

  it('refuses a daemon with another major API version', async () => {
    const next = `${Number(majorVersion(API_VERSION)) + 1}.0.0`;
    const { daemon, client } = await signerFor(() => ok('Hello', { ...HELLO, api_version: next }));
    const error = await client.listApprovals('peer_credentials').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(IncompatibleApiError);
    expect((error as IncompatibleApiError).guidance.message).toContain(API_VERSION);
    expect(daemon.calls.map((c) => c.method)).toEqual(['Hello']);
  });

  it('rejects an unexpected response variant', async () => {
    const { client } = await signerFor(withHello(() => ok('Unit')));
    await expect(client.listApprovals('peer_credentials')).rejects.toBeInstanceOf(ProtocolError);
  });

  it('turns signer errors into typed errors with guidance', async () => {
    const { client } = await signerFor(withHello(() => fail('AdminAuthenticationRequired')));
    const error = await client.listApprovals('peer_credentials').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SignerCallError);
    expect((error as SignerCallError).wire).toEqual({ kind: 'AdminAuthenticationRequired' });
    expect((error as SignerCallError).guidance.next).toMatch(/sudo/u);
  });

  it('rejects a response variant of another method', async () => {
    const { client } = await signerFor(
      withHello(() => body(fixture('rpc/ListSpendingLimits.response.json'))),
    );
    await expect(client.exportWalletBackup('peer_credentials', 'x'.repeat(12))).rejects.toThrow(
      ProtocolError,
    );
  });

  it('binds payments calls to the agent credentials', async () => {
    const daemon = await startFakeDaemon(
      withHello((call) =>
        call.method === 'WalletSummary'
          ? body(fixture('payments/wallet/WalletSummary.response.json'))
          : fail('ManualApprovalPending', {
              approval_request_id: 'e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090',
            }),
      ),
    );
    daemons.push(daemon);
    const payments = new PaymentsClient(
      {
        endpoint: { service: 'payments', path: daemon.path, trust: () => ({ kind: 'user', uid }) },
      },
      AUTH,
    );
    expect((await payments.walletSummary()).default_network).toBe('bsc');
    expect(daemon.calls[1]).toEqual({ method: 'WalletSummary', params: { auth: AUTH } });
    const error = await payments.x402({ url: 'https://x.test' }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(PaymentsCallError);
    expect((error as PaymentsCallError).exitCode).toBe(3);
  });
});

/** A request fixture of `method`, typed as the generated request. */
function requestFixture<M extends DaemonRpcRequest['method']>(method: M) {
  return fixture<Extract<DaemonRpcRequest, { method: M }>>(`rpc/${method}.request.json`);
}

/**
 * Each wallet and limits call against a fake daemon that answers with the API's response
 * fixture: the client must send exactly the documented request and return the response data.
 */
describe('signer wallet and limits calls', () => {
  async function exchange<M extends DaemonRpcRequest['method']>(method: M) {
    const response = fixture(`rpc/${method}.response.json`);
    const { daemon, client } = await signerFor(withHello(() => body(response)));
    return { daemon, client, request: requestFixture(method), data: response.data };
  }

  it('BootstrapWallet', async () => {
    const { daemon, client, request, data } = await exchange('BootstrapWallet');
    const { auth, mode, limits } = request.params;
    expect(mode).toEqual({ kind: 'create', replace_existing: false });
    const result = await client.bootstrapWallet(auth, mode, limits);
    expect(daemon.calls[1]).toEqual(request);
    expect(result).toEqual(data);
    expect(result.outcome).toBe('created');
    expect(result.agent_credentials.auth_token).toMatch(/\./u);
  });

  it('ExportWalletBackup', async () => {
    const { daemon, client, request, data } = await exchange('ExportWalletBackup');
    const result = await client.exportWalletBackup(request.params.auth, request.params.passphrase);
    expect(daemon.calls[1]).toEqual(request);
    expect(result).toEqual(data);
    expect(result.backup_json.endsWith('\n')).toBe(true);
  });

  it('VerifyWalletBackup', async () => {
    const { daemon, client, request, data } = await exchange('VerifyWalletBackup');
    const { auth, backup_json, passphrase } = request.params;
    const result = await client.verifyWalletBackup(auth, backup_json, passphrase);
    expect(daemon.calls[1]).toEqual(request);
    expect(result).toEqual(data);
  });

  it('ListSpendingLimits', async () => {
    const { daemon, client, request, data } = await exchange('ListSpendingLimits');
    const result = await client.listSpendingLimits(
      request.params.auth,
      request.params.agent_key_id,
    );
    expect(daemon.calls[1]).toEqual(request);
    expect(result).toEqual(data);
    expect(result.limits).toHaveLength(2);
  });

  it('SetSpendingLimits', async () => {
    const { daemon, client, request, data } = await exchange('SetSpendingLimits');
    const { auth, agent_key_id, limits } = request.params;
    const result = await client.setSpendingLimits(auth, agent_key_id, limits);
    expect(daemon.calls[1]).toEqual(request);
    expect(result).toEqual(data);
  });
});

describe('wallet error guidance', () => {
  const WALLET_KINDS = [
    'WalletAlreadyExists',
    'WalletNotFound',
    'InvalidWalletRequest',
    'InvalidSpendingLimits',
    'InvalidWalletBackup',
    'WalletBackupDecryptionFailed',
    'WeakBackupPassphrase',
    'UnknownSignedTransaction',
  ] as const;
  const examples = fixture<WireDaemonError[]>('errors.json');

  it.each(WALLET_KINDS)('%s has its own message and one next action', (kind) => {
    const wire = examples.find((example) => example.kind === kind);
    expect(wire).toBeDefined();
    const { guidance } = new SignerCallError(wire as WireDaemonError);
    const generic = copy.errors.generic(kind, '');
    expect(guidance.message).not.toMatch(new RegExp(`^${kind}`, 'u'));
    expect(guidance.next).not.toBe(generic.next);
    expect(guidance.next.split(/(?<=\.)\s/u)).toHaveLength(1);
  });

  it('carries the daemon detail and numbers into the copy', () => {
    const guidance = (kind: string) =>
      new SignerCallError(examples.find((e) => e.kind === kind) as WireDaemonError).guidance;
    expect(guidance('WeakBackupPassphrase').next).toBe('Use at least 12 characters.');
    expect(guidance('InvalidSpendingLimits').message).toContain(
      'daily_max_wei must be at least per_tx_max_wei',
    );
    expect(guidance('WalletAlreadyExists').message).toBe(
      'A wallet already exists on this machine, so nothing was changed.',
    );
  });

  it('arrives from the daemon as a SignerCallError', async () => {
    const { client } = await signerFor(withHello(() => fail('WalletBackupDecryptionFailed')));
    const error = await client
      .verifyWalletBackup('peer_credentials', '{}', 'wrong')
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SignerCallError);
    expect((error as SignerCallError).guidance).toEqual(copy.errors.backupDecryption);
  });
});
