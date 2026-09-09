import { describe, expect, it } from 'vitest';
import * as fc from 'fast-check';
import { detectSqlInjection, detectXss, detectPathTraversal } from '@guardrail/core';

describe('evasion / property tests', () => {
  it('URL-encoded UNION SELECT is still detected after decode-like forms', () => {
    // Detector matches literal UNION SELECT; encoded form uses %20 etc.
    expect(detectSqlInjection("UNION%20SELECT").safe).toBe(false);
    expect(detectSqlInjection("union select password from users").safe).toBe(false);
  });

  it('mixed-case XSS script tags are detected', () => {
    expect(detectXss('<ScRiPt>alert(1)</sCrIpT>').safe).toBe(false);
  });

  it('encoded path traversal variants', () => {
    expect(detectPathTraversal('%2e%2e/etc/passwd').safe).toBe(false);
    expect(detectPathTraversal('..\\windows\\system32').safe).toBe(false);
  });

  it('any string containing DROP TABLE fails sql check (property)', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 20 }), (suffix) => {
        const payload = `DROP TABLE ${suffix}`;
        expect(detectSqlInjection(payload).safe).toBe(false);
      }),
      { numRuns: 30 },
    );
  });

  it('javascript: URI always fails XSS url context', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 30 }), (rest) => {
        expect(detectXss(`javascript:${rest}`, 'url').safe).toBe(false);
      }),
      { numRuns: 20 },
    );
  });
});
