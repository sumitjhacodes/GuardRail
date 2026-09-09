# AI Code Detector

Offline / startup scanner for risky patterns common in AI-generated code.

```typescript
import { scanCode } from '@guardrail/core/ai-detector';

const findings = await scanCode({
  entryPoint: './src',
  include: ['**/*.ts'],
  exclude: ['**/node_modules/**'],
  patterns: ['all'],
  severity: 'medium',
});

const dynamic = scanCode.dynamic(`
  function auth(token) {
    return token === process.env.SECRET;
  }
`);
```

## Patterns

concatenated-sql, unsafe-regex, timing-attack, hardcoded-secrets, unsafe-deserialization, insecure-random, prototype-pollution, path-traversal, missing-auth, missing-csrf
