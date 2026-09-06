# Changelog

## 0.1.0 — Phase 1 MVP

### Added
- `@guardrail/core` — fluent input rules (`sqlSafe`, `xssSafe`, `noSecrets`, `noPathTraversal`, uuid/email/number/object/array/file)
- Dialect-aware SQL injection detection and context-aware XSS detection
- Output redaction (`redact`, `redactPaths`) and error sanitization
- Security events bus (`violation`, `block`, `allow`)
- `@guardrail/express` — middleware, response wrapping, `errorHandler`, health check
- Express basic example, Vitest suite, CI workflow, benchmarks
