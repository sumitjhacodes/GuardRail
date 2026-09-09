# Changelog

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
