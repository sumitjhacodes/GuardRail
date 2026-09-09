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
