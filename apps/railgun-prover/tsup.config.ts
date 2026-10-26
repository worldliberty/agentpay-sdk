import { defineConfig } from 'tsup';

export default defineConfig({
  bundle: true,
  clean: true,
  dts: false,
  entry: {
    'railgun-prover': 'src/index.ts',
  },
  format: ['cjs'],
  outDir: 'dist',
  platform: 'node',
  sourcemap: true,
  splitting: false,
  target: 'node20',
  outExtension() {
    return { js: '.cjs' };
  },
});
