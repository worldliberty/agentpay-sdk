const BIGINT_BUFFER_WARNING =
  'bigint: Failed to load bindings, pure JS will be used (try npm run rebuild?)';

type GlobalWithAgentPayConsolePatch = typeof globalThis & {
  __agentpaySuppressBigintBufferWarningInstalled?: boolean;
};

const globalState = globalThis as GlobalWithAgentPayConsolePatch;

if (!globalState.__agentpaySuppressBigintBufferWarningInstalled) {
  const originalWarn = console.warn.bind(console);
  console.warn = (...args: unknown[]) => {
    if (args.length === 1 && args[0] === BIGINT_BUFFER_WARNING) {
      return;
    }
    originalWarn(...args);
  };
  globalState.__agentpaySuppressBigintBufferWarningInstalled = true;
}
