import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts', 'test/**/*.test.tsx'],
    environment: 'node',
    // Every test gets a private HOME/AGENTPAY_HOME (see test/setup.ts); nothing touches the
    // real keychain, daemon sockets, or sudo.
    setupFiles: ['test/setup.ts'],
    restoreMocks: true,
    testTimeout: 10_000,
  },
});
