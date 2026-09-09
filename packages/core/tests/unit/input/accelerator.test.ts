import { describe, expect, it, afterEach } from 'vitest';
import {
  detectSqlInjection,
  setPatternAccelerator,
  getPatternAccelerator,
} from '@guardrail/core';

describe('pattern accelerator hook', () => {
  afterEach(() => {
    setPatternAccelerator(null);
  });

  it('uses accelerator when registered', () => {
    setPatternAccelerator({
      name: 'test',
      matchSql: (input) =>
        input.includes('ACCEL')
          ? { name: 'accel-hit', matched: 'ACCEL' }
          : null,
    });
    expect(getPatternAccelerator()?.name).toBe('test');
    const hit = detectSqlInjection('ACCEL payload');
    expect(hit.safe).toBe(false);
    expect(hit.pattern).toBe('accel-hit');

    const clean = detectSqlInjection('hello world');
    // accelerator returned null → candidate skipped; no JS match either
    expect(clean.safe).toBe(true);
  });

  it('falls back to JS when accelerator unset', () => {
    const hit = detectSqlInjection('UNION SELECT 1');
    expect(hit.safe).toBe(false);
    expect(hit.pattern).toBe('union-select');
  });
});
