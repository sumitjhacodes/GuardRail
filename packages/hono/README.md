# @guardrail/hono

Hono middleware for Guardrail.

```typescript
import { Hono } from 'hono';
import { guardrail, rules } from '@guardrail/hono';

const app = new Hono();
app.use('*', guardrail({
  inputs: { q: rules.string().sqlSafe() },
  outputs: { redact: ['password'] },
}));
```
