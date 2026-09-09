# @guardrail/wasm

Pattern-matching accelerator for Guardrail detectors.

## Default (JS)

```ts
import { createJsAccelerator } from '@guardrail/wasm';
import { setPatternAccelerator } from '@guardrail/core';

setPatternAccelerator(createJsAccelerator());
```

## Optional Rust WASM

Requires `rustc` + `wasm-pack`. See [`rust/README.md`](./rust/README.md).

```bash
npm run build:rust --workspace=@guardrail/wasm
```

If Rust tooling is missing, detectors keep using the pure JS path in `@guardrail/core`.
