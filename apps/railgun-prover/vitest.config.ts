import { defineConfig } from 'vitest/config';

export default defineConfig({
  esbuild: {
    target: 'node20',
  },
  test: {
    environment: 'node',
    exclude: ['node_modules', 'dist', '.turbo'],
    globals: true,
    include: ['src/**/*.test.ts'],
  },
});
