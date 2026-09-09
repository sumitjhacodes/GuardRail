import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'input/index': 'src/input/index.ts',
    'output/index': 'src/output/index.ts',
    'policies/index': 'src/policies/index.ts',
    'ai-detector/index': 'src/ai-detector/index.ts',
    'supply-chain/index': 'src/supply-chain/index.ts',
    'observability/index': 'src/observability/index.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  treeshake: true,
  outDir: 'dist',
});
