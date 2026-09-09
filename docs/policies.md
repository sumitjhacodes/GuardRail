# Behavior Policies

```typescript
guardrail({
  policies: [
    {
      name: 'admin-only',
      when: (req) => !!req.path?.startsWith('/api/admin'),
      invariant: (req) => req.user?.role === 'admin',
      onViolation: 'block', // or 'log' | 'alert' | custom fn
      priority: 10,
      phase: 'before', // or 'after' (runs on response body)
    },
  ],
});
```

- Sorted by `priority` (ascending)
- Short-circuits on first `block`
- Emits `violation` / `block` / `alert` on the shared events bus
- `phase: 'after'` can inspect `res.body` (IDOR-style checks)
