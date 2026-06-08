import { defineConfig } from 'tsup';

const suppressBigintBufferWarningBanner = `#!/usr/bin/env node
const __agentpayBigintBufferWarning = 'bigint: Failed to load bindings, pure JS will be used (try npm run rebuild?)';
if (!globalThis.__agentpaySuppressBigintBufferWarningInstalled) {
  const __agentpayOriginalConsoleWarn = console.warn.bind(console);
  console.warn = (...args) => {
    if (args.length === 1 && args[0] === __agentpayBigintBufferWarning) {
      return;
    }
    __agentpayOriginalConsoleWarn(...args);
  };
  globalThis.__agentpaySuppressBigintBufferWarningInstalled = true;
}`;

export default defineConfig({
  entry: {
    cli: 'src/cli.ts',
    link: 'src/lib/link.ts',
  },
  format: ['cjs'],
  platform: 'node',
  target: 'node20',
  clean: true,
  sourcemap: true,
  dts: false,
  banner: {
    js: suppressBigintBufferWarningBanner,
  },
  outExtension() {
    return { js: '.cjs' };
  },
  noExternal: [
    '@worldlibertyfinancial/agent-config',
    '@worldlibertyfinancial/agent-rpc',
    'commander',
    'viem',
  ],
});
