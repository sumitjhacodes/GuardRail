# @guardrail/express

Express middleware for Guardrail.

```typescript
import express from 'express';
import { guardrail, rules } from '@guardrail/express';

const app = express();
app.use(express.json());
app.use(guardrail({ outputs: { redact: ['password'] } }));
app.post('/api/search',
  guardrail({ inputs: { q: rules.string().sqlSafe() } }),
  (req, res) => res.json({ ok: true }),
);
app.use(guardrail.errorHandler());
```

Peer dependency: `express` >= 4.
