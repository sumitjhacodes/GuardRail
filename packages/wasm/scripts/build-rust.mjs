import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'rust');

function has(cmd) {
  const r = spawnSync(cmd, ['--version'], { encoding: 'utf8', shell: true });
  return r.status === 0;
}

if (!has('rustc') || !has('wasm-pack')) {
  console.warn(
    '[@guardrail/wasm] rustc/wasm-pack not found — skipping Rust build. JS accelerator remains available.',
  );
  process.exit(0);
}

if (!existsSync(join(root, 'Cargo.toml'))) {
  console.error('Missing rust/Cargo.toml');
  process.exit(1);
}

const result = spawnSync(
  'wasm-pack',
  ['build', '--target', 'nodejs', '--out-dir', '../pkg', root],
  { stdio: 'inherit', shell: true },
);
process.exit(result.status ?? 1);
