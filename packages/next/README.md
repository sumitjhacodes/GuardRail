# @guardrail/next

Next.js middleware adapter for Guardrail (Edge-compatible request validation).

```ts
// middleware.ts
import { guardrail, rules } from '@guardrail/next';

export const middleware = guardrail.next({
  inputs: {
    q: rules.string().sqlSafe().maxLength(100),
  },
  outputs: {
    headers: { 'X-Content-Type-Options': 'nosniff' },
  },
  policies: [
    {
      name: 'admin-only',
      when: (req) => !!req.path?.startsWith('/api/admin'),
      invariant: (req) => req.user?.role === 'admin',
      onViolation: 'block',
    },
  ],
});

export const config = {
  matcher: '/api/:path*',
};
```

For response redaction / after-policies in Route Handlers, use `sanitizeResponse` and `enforceAfterPolicies`.

**Mass-assignment:** middleware forwards the stripped body on `x-guardrail-body`. In Route Handlers use:

```ts
import { getValidatedBody } from '@guardrail/next';

export async function POST(req: NextRequest) {
  const body = await getValidatedBody(req); // validated fields only
}
```

Supply-chain checks (`verifyImports`) and metrics (`createMetrics`) should run in Node (startup / Route Handlers), not Edge middleware.
