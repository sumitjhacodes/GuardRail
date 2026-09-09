# Supply-chain verification

Offline-first checks for npm lockfiles. Run at **startup or CI**, not on every HTTP request.

```ts
import { verifyImports } from '@guardrail/core/supply-chain';

const result = await verifyImports({
  lockfile: './package-lock.json',
  checksums: { algorithm: 'sha512', requireIntegrity: true },
  behaviorProfile: {
    networkAccess: { allowedHosts: ['registry.npmjs.org'], blockUnknown: true },
    childProcess: { allowed: false },
    allowlistedInstallScripts: ['esbuild'],
  },
  threatIntelligence: {
    blockKnownMalicious: true,
    denyList: ['color-names-js'],
    // Optional online feed:
    // lookup: async ({ name, version }) => fetchOsV(name, version),
  },
});

if (!result.ok) {
  console.error(result.findings);
  process.exit(1);
}
```

## What it checks

| Check | Codes |
|-------|--------|
| Missing / weak integrity | `MISSING_INTEGRITY`, `WEAK_INTEGRITY`, `INVALID_INTEGRITY` |
| Install scripts when disallowed | `INSTALL_SCRIPT` |
| Deny list / threat lookup | `KNOWN_MALICIOUS`, `THREAT_FEED_HIT` |
| Suspicious script text helper | `SUSPICIOUS_POSTINSTALL` (`scanPostinstallScript`) |

Network allowlists are **advisory** (documented for sandbox/firewall enforcement). Guardrail does not intercept process network calls.
