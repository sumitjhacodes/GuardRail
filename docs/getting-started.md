# Getting Started

```bash
npm install @guardrail/core @guardrail/express
```

```typescript
import express from 'express';
import { guardrail, rules } from '@guardrail/express';

const app = express();
app.use(express.json());

app.use(guardrail({
  outputs: { redact: ['password', 'token'] },
  policies: [
    {
      name: 'admin-only',
      when: (req) => !!req.path?.startsWith('/api/admin'),
      invariant: (req) => req.user?.role === 'admin',
      onViolation: 'block',
    },
  ],
}));

app.post('/api/search',
  guardrail({
    inputs: {
      q: rules.string().sqlSafe().xssSafe().maxLength(100),
    },
  }),
  (req, res) => res.json({ ok: true }),
);

app.use(guardrail.errorHandler());
app.listen(3000);
```

Scan code offline:

```typescript
import { scanCode } from '@guardrail/core/ai-detector';

const findings = await scanCode({
  entryPoint: './src',
  include: ['./src/**/*.ts'],
  severity: 'medium',
});
```
