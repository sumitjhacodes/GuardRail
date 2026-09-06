# Contributing

Thanks for helping improve Guardrail.

## Setup

```bash
git clone <repo>
cd GuardRail
npm install
npm run build
npm test
```

Requires Node.js 18+.

## Packages

- `packages/core` — core engine (zero runtime deps)
- `packages/express` — Express adapter

## Scripts

| Command | Description |
|---------|-------------|
| `npm run build` | Build all packages |
| `npm test` | Run unit + integration tests |
| `npm run typecheck` | TypeScript check |
| `npm run benchmark` | Input scanner microbench |

## Coding standards

- TypeScript `strict` mode
- No `eval` / `new Function`
- Prefer `Object.create(null)` for dynamic maps
- Every security detector needs tests (including evasion cases when relevant)
- Keep `@guardrail/core` free of runtime dependencies

## Pull requests

1. Branch from `main`
2. Add/adjust tests
3. Ensure `npm test` and `npm run typecheck` pass
4. Describe the threat model change if touching detectors

## Security

See [SECURITY.md](SECURITY.md) for vulnerability disclosure.
