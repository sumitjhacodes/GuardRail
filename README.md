# Guardrail

**Runtime security enforcement for AI-generated and hand-written application code.**

[![CI](https://github.com/guardrail-security/guardrail/actions/workflows/ci.yml/badge.svg)](https://github.com/guardrail-security/guardrail/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)](https://www.typescriptlang.org/)
[![Coverage](https://img.shields.io/badge/coverage-90%25%2B-brightgreen)](packages/core)

Guardrail sits between your app and the outside world — scanning inputs, sanitizing outputs, and failing closed when something looks wrong.

> **Phase 3:** Supply-chain verification, observability metrics, Next.js adapter, optional WASM accelerator.

## Quick start

```bash
npm install @guardrail/core @guardrail/express
```

```typescript
import express from 'express';
import { guardrail, rules } from '@guardrail/express';

const app = express();
app.use(express.json());

app.use(guardrail({
  outputs: {
    redact: ['password', 'ssn', 'token'],
    headers: {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
    },
  },
}));

app.post('/api/search',
  guardrail({
    inputs: {
      q: rules.string().sqlSafe().xssSafe().noSecrets().maxLength(100),
    },
  }),
  (req, res) => {
    res.json({ results: [], password: 'will-be-redacted' });
  },
);

app.use(guardrail.errorHandler());
app.listen(3000);
```

## Why Guardrail?

AI coding assistants ship fast — and often ship SQL concatenation, missing auth checks, and secrets in logs. Guardrail adds a transparent, zero-config-friendly security layer so those mistakes are blocked at runtime instead of becoming incidents.

## Features (Phase 3)

| Module | Package | Status |
|--------|---------|--------|
| Input scanner | `@guardrail/core` / `./input` | Done |
| Output sanitizer | `@guardrail/core` / `./output` | Done |
| Behavior policies | `@guardrail/core` / `./policies` | Done |
| AI code detector | `@guardrail/core` / `./ai-detector` | Done |
| Supply chain verifier | `@guardrail/core/supply-chain` | Done |
| Observability metrics | `@guardrail/core/observability` | Done |
| Express adapter | `@guardrail/express` | Done |
| Fastify adapter | `@guardrail/fastify` | Done |
| Hono adapter | `@guardrail/hono` | Done |
| Next.js adapter | `@guardrail/next` | Done |
| WASM / JS accelerator | `@guardrail/wasm` | Done (JS default; Rust optional) |

### Supply chain (startup / CI)

```typescript
import { verifyImports } from '@guardrail/core/supply-chain';

const result = await verifyImports({
  checksums: { source: 'package-lock.json', algorithm: 'sha512' },
  behaviorProfile: { childProcess: { allowed: false } },
  threatIntelligence: { blockKnownMalicious: true },
});
if (!result.ok) process.exit(1);
```

### Metrics

```typescript
import { createMetrics } from '@guardrail/core/observability';

const metrics = createMetrics();
app.get('/metrics', (_req, res) => res.type('text/plain').send(metrics.toPrometheus()));
```

### Input rules

```typescript
import { rules } from '@guardrail/core';

rules.string().sqlSafe().xssSafe().noSecrets().noPathTraversal().maxLength(100);
rules.uuid();
rules.email();
rules.number().min(0).max(150);
rules.object({ zip: rules.string().matches(/^\d{5}$/) });
rules.array(rules.string()).maxItems(10);
rules.file().maxSize(5_000_000).mimeTypes(['image/png']).noExecutable();
```

### Behavior policies

```typescript
guardrail({
  policies: [
    {
      name: 'admin-only',
      when: (req) => !!req.path?.startsWith('/api/admin'),
      invariant: (req) => req.user?.role === 'admin',
      onViolation: 'block',
      priority: 10,
    },
  ],
});
```

### AI code detector

```typescript
import { scanCode } from '@guardrail/core/ai-detector';

const findings = await scanCode({
  entryPoint: './src',
  include: ['**/*.ts'],
  severity: 'medium',
});
```

## Monorepo

```
packages/core      — zero runtime dependencies
packages/express  — Express middleware
packages/fastify  — Fastify plugin
packages/hono     — Hono middleware
packages/next     — Next.js middleware
packages/wasm     — JS accelerator + optional Rust WASM
docs/
examples/express-basic
```

```bash
npm install
npm run build
npm test
npm run benchmark   # ~0.01ms mean for <1KB validateInputs on this machine
```

## Security principles

- **Fail closed** — errors default to block, not allow
- **No eval** — library never uses `eval` or `new Function`
- **Prototype-safe** — null-prototype objects for scratch maps
- **Secrets never logged** — detections emit sanitized events only
- **Timing-safe compares** available in utils for secret equality
- **Offline-first supply chain** — lockfile checks without network by default

## Documentation

- [docs/](docs/) — guides for rules, policies, AI detector, frameworks, supply-chain, metrics
- [SECURITY.md](SECURITY.md) — disclosure process
- [CONTRIBUTING.md](CONTRIBUTING.md) — local development
- [examples/express-basic](examples/express-basic) — runnable demo

## License

MIT
