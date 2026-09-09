# Changelog

## 0.3.0 — Phase 3

### Added
- Supply-chain verifier (`@guardrail/core/supply-chain`) — offline lockfile integrity, install-script policy, pluggable threat deny lists (`verifyImports`)
- Observability helpers (`@guardrail/core/observability`) — Prometheus-style counters from the events bus (`createMetrics`, `healthWithMetrics`)
- Optional pattern accelerator hook (`setPatternAccelerator`) with JS fallback in detectors
- `@guardrail/wasm` — JS accelerator package + optional Rust/wasm-pack scaffold
- `@guardrail/next` — Next.js middleware adapter (Edge-safe request validation)
- Docs for supply-chain, metrics, Next.js, and WASM

## 0.2.0 — Phase 2

### Added
- Behavior policies engine (`@guardrail/core/policies`) with priority, phases, short-circuit, events
- AI code detector (`@guardrail/core/ai-detector`) with `scanCode` / `scanCode.dynamic` and top patterns
- `@guardrail/fastify` plugin adapter
- `@guardrail/hono` middleware adapter
- Policy wiring in Express (before + after response phases)
- Evasion/property tests; vulnerable-sample fixtures
- Public docs under `docs/`
- SQL detector decoding for common URL encodings

## 0.1.0 — Phase 1 MVP

### Added
- `@guardrail/core` — fluent input rules (`sqlSafe`, `xssSafe`, `noSecrets`, `noPathTraversal`, uuid/email/number/object/array/file)
- Dialect-aware SQL injection detection and context-aware XSS detection
- Output redaction (`redact`, `redactPaths`) and error sanitization
- Security events bus (`violation`, `block`, `allow`)
- `@guardrail/express` — middleware, response wrapping, `errorHandler`, health check
- Express basic example, Vitest suite, CI workflow, benchmarks
