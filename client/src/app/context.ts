/**
 * Everything a command or screen needs from the environment, created once per process. Tests
 * replace any part (I/O, runner, transport, stores, helper, relay, renderer).
 */
import { existsSync } from 'node:fs';
import { userInfo } from 'node:os';
import { createInterface } from 'node:readline/promises';
import { render } from 'ink';
import { createElement, type ReactElement } from 'react';
import { type AdminAuthorizer, createAdminAuthorizer } from '../auth/admin-auth.js';
import { type AgentAuthFlags, resolveAgentAuth } from '../auth/agent-credentials.js';
import { type ClientStateStore, fileClientStateStore } from '../auth/client-state.js';
import { agentpayHome, homeFiles } from '../auth/home.js';
import { createPasswordPrompter, type PasswordPrompter } from '../auth/password-prompt.js';
import { createSudoRelay, type PrivilegedRunner } from '../auth/privileged.js';
import { type CommandRunner, runCommand } from '../auth/process.js';
import { platformSecretStore, type SecretStore } from '../auth/secret-store.js';
import { createTouchIdHelper, resolveHelperPath, type TouchIdHelper } from '../auth/touch-id.js';
import { type EndpointOverrides, type Endpoints, resolveEndpoints } from '../daemon/endpoints.js';
import { PaymentsClient, PublicPaymentsClient } from '../daemon/payments.js';
import { SignerClient } from '../daemon/signer.js';
import type { TrustFs } from '../daemon/socket-trust.js';
import type { Exchange } from '../daemon/transport.js';
import { PasswordPromptHost } from '../screens/PasswordPrompt.js';
import { ThemeProvider, themeFromEnv } from '../ui/theme.js';
import { AdminActions } from './admin-actions.js';
import type { TouchIdDeps } from './touch-id-setup.js';

export interface Io {
  stdout(text: string | Uint8Array): void;
  stderr(text: string): void;
  readStdin(): Promise<string>;
  /** Asks a yes/no style question on the terminal (never used for secrets). */
  question(prompt: string): Promise<string>;
  /** Whether both stdin and stdout are terminals (interactive screens allowed). */
  isTTY: boolean;
}

export const processIo: Io = {
  stdout: (text) => {
    process.stdout.write(text);
  },
  stderr: (text) => {
    process.stderr.write(text);
  },
  readStdin: async () => {
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
    }
    return Buffer.concat(chunks).toString('utf8');
  },
  question: async (prompt) => {
    const lines = createInterface({ input: process.stdin, output: process.stderr });
    try {
      return await lines.question(prompt);
    } finally {
      lines.close();
    }
  },
  isTTY: Boolean(process.stdin.isTTY && process.stdout.isTTY),
};

export interface Context {
  env: NodeJS.ProcessEnv;
  platform: NodeJS.Platform;
  euid: number;
  home: string;
  io: Io;
  run: CommandRunner;
  endpoints: Endpoints;
  /** Points the clients at explicit sockets (`--daemon-socket`, `--payments-socket`). */
  setSockets(overrides: EndpointOverrides): void;
  state: ClientStateStore;
  secrets: SecretStore;
  /** How to start this client again (for the sudo relay and setup). */
  self: readonly string[];
  /** Lets the sudo relay ask for the password inside the terminal UI. */
  passwordPrompter: PasswordPrompter;
  signer(): SignerClient;
  payments(flags: AgentAuthFlags): Promise<PaymentsClient>;
  /** The payments service without agent credentials (only `LookupToken`). */
  publicPayments(): PublicPaymentsClient;
  helper(): TouchIdHelper | null;
  authorizer(): AdminAuthorizer;
  /** Admin operations; `relay` lets interactive flows fall back to the sudo relay. */
  admin(options: { relay: boolean }): AdminActions;
  touchId(admin: AdminActions): TouchIdDeps;
  /** Renders an Ink element and resolves when it exits. */
  render(element: ReactElement): Promise<void>;
}

export interface ContextOptions {
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  euid?: number;
  io?: Io;
  run?: CommandRunner;
  exchange?: Exchange;
  trustFs?: TrustFs;
  state?: ClientStateStore;
  secrets?: SecretStore;
  helper?: TouchIdHelper | null;
  relay?: PrivilegedRunner;
  overrides?: EndpointOverrides;
  self?: readonly string[];
  render?: (element: ReactElement) => Promise<void>;
}

function defaultRender(env: NodeJS.ProcessEnv, prompter: PasswordPrompter) {
  return async (element: ReactElement) => {
    // Every screen can be asked for the sudo password (see PasswordPromptHost).
    const hosted = createElement(PasswordPromptHost, { prompter }, element);
    const instance = render(createElement(ThemeProvider, { theme: themeFromEnv(env) }, hosted));
    await instance.waitUntilExit();
  };
}

export function createContext(options: ContextOptions = {}): Context {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  const euid = options.euid ?? process.geteuid?.() ?? -1;
  const home = agentpayHome(env);
  const run = options.run ?? runCommand;
  const resolve = (overrides: EndpointOverrides | undefined) =>
    resolveEndpoints({
      env,
      platform,
      uid: process.getuid?.() ?? euid,
      ...(overrides ? { overrides } : {}),
      ...(options.trustFs ? { fs: options.trustFs } : {}),
    });
  const endpoints = resolve(options.overrides);
  const rpcOptions = (endpoint: Endpoints['signer']) => ({
    endpoint,
    ...(options.exchange ? { exchange: options.exchange } : {}),
    ...(options.trustFs ? { trustFs: options.trustFs } : {}),
  });
  const state = options.state ?? fileClientStateStore(home);
  const secrets =
    options.secrets ?? platformSecretStore(platform, run, homeFiles.agentAuthDir(home));
  const self = options.self ?? [process.execPath, process.argv[1] ?? 'agentpay'];
  const passwordPrompter = createPasswordPrompter();
  const keyFile = homeFiles.adminKey(home);

  let signer: SignerClient | null = null;
  let helper: TouchIdHelper | null | undefined = options.helper;
  let authorizer: AdminAuthorizer | null = null;

  const context: Context = {
    env,
    platform,
    euid,
    home,
    io: options.io ?? processIo,
    run,
    endpoints,
    setSockets(overrides) {
      Object.assign(endpoints, resolve({ ...options.overrides, ...overrides }));
      signer = null;
      authorizer = null;
    },
    state,
    secrets,
    self,
    passwordPrompter,
    signer() {
      signer ??= new SignerClient(rpcOptions(endpoints.signer));
      return signer;
    },
    async payments(flags) {
      const auth = await resolveAgentAuth(flags, {
        env,
        state,
        store: secrets,
        readStdin: () => context.io.readStdin(),
      });
      return new PaymentsClient(rpcOptions(endpoints.payments), auth);
    },
    publicPayments() {
      return new PublicPaymentsClient(rpcOptions(endpoints.payments));
    },
    helper() {
      if (helper === undefined) {
        const path = platform === 'darwin' ? resolveHelperPath(env) : null;
        helper = path ? createTouchIdHelper(path, run) : null;
      }
      return helper;
    },
    authorizer() {
      authorizer ??= createAdminAuthorizer({
        euid,
        platform,
        state,
        helper: context.helper(),
        keyFile,
        keyFileExists: existsSync,
        signer: context.signer(),
      });
      return authorizer;
    },
    admin({ relay }) {
      return new AdminActions({
        signer: context.signer(),
        authorizer: context.authorizer(),
        relay: relay ? (options.relay ?? createSudoRelay(run, self, passwordPrompter)) : null,
        euid,
      });
    },
    touchId(admin) {
      return {
        platform,
        helper: context.helper(),
        keyFile,
        keyFileExists: existsSync,
        state,
        admin,
        label: `Touch ID (${safeUsername()})`.slice(0, 64),
      };
    },
    render: options.render ?? defaultRender(env, passwordPrompter),
  };
  return context;
}

function safeUsername(): string {
  try {
    return userInfo().username.replace(/[^\w.-]/gu, '') || 'user';
  } catch {
    return 'user';
  }
}
