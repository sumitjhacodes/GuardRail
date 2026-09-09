# Guardrail

**Runtime security enforcement for AI-generated and hand-written application code.**

[![CI](https://github.com/guardrail-security/guardrail/actions/workflows/ci.yml/badge.svg)](https://github.com/guardrail-security/guardrail/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)](https://www.typescriptlang.org/)
[![Coverage](https://img.shields.io/badge/coverage-90%25%2B-brightgreen)](packages/core)

Guardrail sits between your app and the outside world — scanning inputs, sanitizing outputs, and failing closed when something looks wrong.

> **Phase 2:** Core policies + AI detector, Express/Fastify/Hono adapters.

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

## Features (Phase 2)

| Module | Package | Status |
|--------|---------|--------|
| Input scanner | `@guardrail/core` / `./input` | Done |
| Output sanitizer | `@guardrail/core` / `./output` | Done |
| Behavior policies | `@guardrail/core` / `./policies` | Done |
| AI code detector | `@guardrail/core` / `./ai-detector` | Done |
| Express adapter | `@guardrail/express` | Done |
| Fastify adapter | `@guardrail/fastify` | Done |
| Hono adapter | `@guardrail/hono` | Done |
| Supply chain verifier | `@guardrail/core/supply-chain` | Phase 3 |
| WASM pattern engine | `@guardrail/wasm` | Phase 3 |
| Next.js adapter | `@guardrail/next` | Phase 3 |

### Input rules

```typescript
import { rules } from '@guardrail/core';

rules.string().sqlSafe().xssSafe().noSecrets().noPathTraversal().maxLength(100);
rules.uuid();
rules.email(); // .domainExists() for optional DNS MX check
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
packages/core      — zero runtime dependencies (input, output, policies, ai-detector)
packages/express  — Express middleware
packages/fastify  — Fastify plugin
packages/hono     — Hono middleware
docs/             — public guides
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

## Documentation

- [docs/](docs/) — getting started, rules, policies, AI detector, frameworks
- [SECURITY.md](SECURITY.md) — disclosure process
- [CONTRIBUTING.md](CONTRIBUTING.md) — local development
- [examples/express-basic](examples/express-basic) — runnable demo

## License

MIT
