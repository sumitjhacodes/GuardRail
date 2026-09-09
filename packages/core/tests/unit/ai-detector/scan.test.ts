import { describe, expect, it } from 'vitest';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanCode } from '@guardrail/core';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = resolve(__dirname, '../../fixtures/vulnerable-samples');

describe('AI code detector', () => {
  it('scanCode.dynamic detects timing-attack', () => {
    const results = scanCode.dynamic(`
      function auth(token) {
        return token === process.env.ADMIN_TOKEN;
      }
    `);
    expect(results.some((r) => r.pattern === 'timing-attack')).toBe(true);
  });

  it('scanCode.dynamic detects hardcoded-secrets', () => {
    const results = scanCode.dynamic(`
      const apiKey = "supersecretkeyvalue123";
    `);
    expect(results.some((r) => r.pattern === 'hardcoded-secrets')).toBe(true);
  });

  it('scanCode.dynamic detects concatenated-sql', () => {
    const results = scanCode.dynamic(`
      db.query(\`SELECT * FROM users WHERE id = '\${req.query.id}'\`);
    `);
    expect(results.some((r) => r.pattern === 'concatenated-sql')).toBe(true);
  });

  it('scanCode.dynamic detects insecure-random', () => {
    const results = scanCode.dynamic(`const t = Math.random();`);
    expect(results.some((r) => r.pattern === 'insecure-random')).toBe(true);
  });

  it('scanCode.dynamic detects prototype-pollution', () => {
    const results = scanCode.dynamic(`obj['__proto__'] = { admin: true };`);
    expect(results.some((r) => r.pattern === 'prototype-pollution')).toBe(true);
  });

  it('respects minimum severity', () => {
    const results = scanCode.dynamic(`const t = Math.random();`, {
      severity: 'critical',
    });
    expect(results.every((r) => r.severity === 'critical')).toBe(true);
    expect(results.some((r) => r.pattern === 'insecure-random')).toBe(false);
  });

  it('scans fixture files on disk', async () => {
    const file = resolve(fixturesDir, 'sample-vulns.ts');
    const results = await scanCode({
      entryPoint: file,
      patterns: ['all'],
      severity: 'medium',
    });
    expect(results.length).toBeGreaterThan(0);
    expect(results.some((r) => r.pattern === 'hardcoded-secrets')).toBe(true);
    expect(results.some((r) => r.pattern === 'timing-attack')).toBe(true);
  });

  it('directory scan with default include finds .ts sources', async () => {
    const results = await scanCode({
      entryPoint: fixturesDir,
      patterns: ['hardcoded-secrets'],
      severity: 'medium',
    });
    expect(results.length).toBeGreaterThan(0);
    expect(results.some((r) => r.file.endsWith('sample-vulns.ts'))).toBe(true);
  });
});
