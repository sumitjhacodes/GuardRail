# Rust WASM (optional)

This crate is **optional**. Guardrail ships a JS accelerator by default.

## Build

```bash
# from packages/wasm
npm run build:rust
```

Requires:

- [Rust](https://rustup.rs/) (`rustc`, `cargo`)
- [`wasm-pack`](https://rustwasm.github.io/wasm-pack/)

CI may skip this job when the toolchain is absent — see root workflow comments.
