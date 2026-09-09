# Framework Adapters

## Express

```typescript
import { guardrail, rules } from '@guardrail/express';
app.use(guardrail({ outputs: { redact: ['password'] } }));
app.post('/x', guardrail({ inputs: { q: rules.string().sqlSafe() } }), handler);
app.use(guardrail.errorHandler());
```

## Fastify

```typescript
import guardrailFastify, { rules } from '@guardrail/fastify';
await app.register(guardrailFastify, {
  inputs: { q: rules.string().sqlSafe() },
  outputs: { redact: ['password'] },
});
```

## Hono

```typescript
import { guardrail, rules } from '@guardrail/hono';
app.use('*', guardrail({
  inputs: { q: rules.string().sqlSafe() },
  outputs: { redact: ['password'] },
}));
```

## Next.js

```typescript
// middleware.ts
import { guardrail, rules } from '@guardrail/next';

export const middleware = guardrail.next({
  inputs: { q: rules.string().sqlSafe() },
  outputs: { headers: { 'X-Content-Type-Options': 'nosniff' } },
});

export const config = { matcher: '/api/:path*' };
```

Use `sanitizeResponse` / `enforceAfterPolicies` inside Route Handlers for output redaction and after-phase policies. Run `verifyImports` and metrics in Node (not Edge).

After middleware validates inputs, read the stripped body with `getValidatedBody(req)` — Next cannot rewrite the request body stream, so Guardrail forwards JSON via the `x-guardrail-body` header.
