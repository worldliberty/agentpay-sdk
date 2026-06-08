import { defineConfig } from 'tsup';

export default defineConfig({
  entry: [
    'src/tailwind.ts',
    'src/utils/cn.ts',
    'src/components/badge.tsx',
    'src/components/button.tsx',
    'src/components/card.tsx',
    'src/components/input.tsx',
    'src/components/label.tsx',
    'src/components/separator.tsx',
    'src/components/textarea.tsx',
  ],
  format: ['esm'],
  dts: true,
  sourcemap: true,
  clean: true,
  external: ['react', 'react-dom'],
});
