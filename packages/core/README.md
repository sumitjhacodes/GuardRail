# @guardrail/core

Zero-dependency runtime security engine: fluent input rules, detectors (SQL/XSS/secrets/path traversal), output redaction, and events.

```typescript
import { guardrail, rules, events } from '@guardrail/core';

const gr = guardrail({
  inputs: {
    search: rules.string().sqlSafe().xssSafe().maxLength(100),
  },
  outputs: { redact: ['password'] },
});

const result = await gr.validate({ search: 'hello' });
```

See the root [README](../../README.md) for full documentation.
