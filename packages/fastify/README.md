# @guardrail/fastify

Fastify plugin for Guardrail.

```typescript
import Fastify from 'fastify';
import guardrailFastify, { rules } from '@guardrail/fastify';

const app = Fastify();
await app.register(guardrailFastify, {
  inputs: { q: rules.string().sqlSafe() },
  outputs: { redact: ['password'] },
});
```
