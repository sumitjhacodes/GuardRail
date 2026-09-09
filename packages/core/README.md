# @guardrail/core

Zero-dependency runtime security engine.

```typescript
import { guardrail, rules, scanCode, runPolicies } from '@guardrail/core';

const gr = guardrail({
  inputs: { search: rules.string().sqlSafe().xssSafe().maxLength(100) },
  outputs: { redact: ['password'] },
  policies: [
    {
      name: 'admin-only',
      when: (req) => !!req.path?.startsWith('/api/admin'),
      invariant: (req) => req.user?.role === 'admin',
      onViolation: 'block',
    },
  ],
});

const findings = await scanCode({ entryPoint: './src', include: ['**/*.ts'] });
```

Subpath exports: `./input`, `./output`, `./policies`, `./ai-detector`.
