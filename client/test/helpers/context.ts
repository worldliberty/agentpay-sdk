/** A `Context` wired to fake daemons and in-memory stores. */
import type { ReactElement } from 'react';
import { type Context, type ContextOptions, createContext } from '../../src/app/context.js';
import { memoryClientStateStore } from '../../src/auth/client-state.js';
import { memorySecretStore } from '../../src/auth/secret-store.js';
import { type FakeDaemon, type Handler, startFakeDaemon, withHello } from './fake-daemon.js';
import { type FakeIo, fakeIo } from './io.js';

export const AGENT_KEY_ID = '9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d';
export const AGENT_TOKEN = '8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7';

export interface TestContext {
  context: Context;
  io: FakeIo;
  signer: FakeDaemon;
  payments: FakeDaemon;
  rendered: ReactElement[];
  close(): Promise<void>;
}

export async function testContext(
  options: {
    signer?: Handler;
    payments?: Handler;
    io?: FakeIo;
    credentials?: boolean;
  } & Omit<ContextOptions, 'io'> = {},
): Promise<TestContext> {
  const unexpected: Handler = () => ({ close: true });
  const signer = await startFakeDaemon(withHello(options.signer ?? unexpected));
  const payments = await startFakeDaemon(withHello(options.payments ?? unexpected));
  const io = options.io ?? fakeIo();
  const withCredentials = options.credentials ?? true;
  const rendered: ReactElement[] = [];
  const context = createContext({
    platform: 'linux',
    euid: 501,
    helper: null,
    state: memoryClientStateStore(withCredentials ? { agentKeyId: AGENT_KEY_ID } : {}),
    secrets: memorySecretStore(withCredentials ? { [AGENT_KEY_ID]: AGENT_TOKEN } : {}),
    render: async (element) => {
      rendered.push(element);
    },
    ...options,
    io,
    overrides: { daemonSocket: signer.path, paymentsSocket: payments.path },
  });
  return {
    context,
    io,
    signer,
    payments,
    rendered,
    close: async () => {
      await Promise.all([signer.close(), payments.close()]);
    },
  };
}
