# Security Rules

## String security constraints

| Method | Blocks |
|--------|--------|
| `.sqlSafe()` | SQL injection patterns (incl. dialect packs) |
| `.xssSafe()` | XSS / script injection (context-aware) |
| `.noSecrets()` | API keys, JWTs, private keys |
| `.noPathTraversal()` | `../`, absolute paths, null bytes |

## Other builders

- `rules.uuid()`, `rules.email()`, `rules.number().min().max()`
- `rules.object({ ... })` — strips unknown nested keys
- `rules.array(item).maxItems(n)`
- `rules.file().maxSize().mimeTypes().noExecutable()`

Object validation returns **shape-stripped** data via `parse()` so mass-assignment fields never reach handlers.
