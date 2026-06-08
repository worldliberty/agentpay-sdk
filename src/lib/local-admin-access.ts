import { promptHiddenTty } from './hidden-tty-prompt.js';
import { createSudoSession } from './sudo.js';

const MAX_SECRET_STDIN_BYTES = 16 * 1024;

export interface LocalAdminMutationAccessDeps {
  isRoot?: () => boolean;
  isSudoWrappedInvocation?: () => boolean;
  ensureRootAccess?: () => Promise<void>;
}

function renderError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function validateSecret(value: string, label: string): string {
  if (Buffer.byteLength(value, 'utf8') > MAX_SECRET_STDIN_BYTES) {
    throw new Error(`${label} must not exceed ${MAX_SECRET_STDIN_BYTES} bytes`);
  }
  if (!value.trim()) {
    throw new Error(`${label} must not be empty or whitespace`);
  }
  return value;
}

function currentProcessIsRoot(): boolean {
  return typeof process.geteuid === 'function' && process.geteuid() === 0;
}

function currentProcessIsSudoWrappedInvocation(): boolean {
  return (
    currentProcessIsRoot() &&
    typeof process.env.SUDO_UID === 'string' &&
    process.env.SUDO_UID.trim().length > 0
  );
}

function assertNotInvokedViaSudo(
  commandLabel: string,
  isSudoWrappedInvocation: () => boolean,
): void {
  if (!isSudoWrappedInvocation()) {
    return;
  }
  throw new Error(
    `run \`${commandLabel}\` as your normal local user, not with sudo; the CLI prompts for sudo internally and running it as root can target the wrong local AgentPay home`,
  );
}

async function promptHidden(query: string, label: string): Promise<string> {
  const answer = await promptHiddenTty(query, `${label} is required; rerun on a local TTY`);
  return validateSecret(answer, label);
}

const sudoSession = createSudoSession({
  promptPassword: async () =>
    await promptHidden(
      'Local admin password for sudo (input hidden; required to change local admin chain and token configuration): ',
      'Local admin password for sudo',
    ),
});

export async function requireLocalAdminMutationAccess(
  commandLabel: string,
  deps: LocalAdminMutationAccessDeps = {},
): Promise<void> {
  const isSudoWrappedInvocation =
    deps.isSudoWrappedInvocation ?? currentProcessIsSudoWrappedInvocation;
  assertNotInvokedViaSudo(commandLabel, isSudoWrappedInvocation);

  const isRoot = deps.isRoot ?? currentProcessIsRoot;
  if (isRoot()) {
    return;
  }

  const ensureRootAccess = deps.ensureRootAccess ?? (() => sudoSession.prime());
  try {
    await ensureRootAccess();
  } catch (error) {
    throw new Error(
      `${commandLabel} requires verified root access before local admin configuration can change: ${renderError(error)}`,
    );
  }
}

export function withLocalAdminMutationAccess<TArgs extends unknown[], TReturn>(
  commandLabel: string,
  action: (...args: TArgs) => TReturn | Promise<TReturn>,
  deps: LocalAdminMutationAccessDeps = {},
): (...args: TArgs) => Promise<TReturn> {
  return async (...args: TArgs): Promise<TReturn> => {
    await requireLocalAdminMutationAccess(commandLabel, deps);
    return await action(...args);
  };
}

export function withDynamicLocalAdminMutationAccess<TArgs extends unknown[], TReturn>(
  resolveCommandLabel: (...args: TArgs) => string,
  action: (...args: TArgs) => TReturn | Promise<TReturn>,
  deps: LocalAdminMutationAccessDeps = {},
): (...args: TArgs) => Promise<TReturn> {
  return async (...args: TArgs): Promise<TReturn> => {
    await requireLocalAdminMutationAccess(resolveCommandLabel(...args), deps);
    return await action(...args);
  };
}
