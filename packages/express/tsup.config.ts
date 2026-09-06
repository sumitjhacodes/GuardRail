import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  treeshake: true,
  external: ['express', '@guardrail/core'],
  esbuildOptions(options) {
    options.banner = undefined;
  },
  // Avoid default+named CJS interop warning
  cjsInterop: true,
});