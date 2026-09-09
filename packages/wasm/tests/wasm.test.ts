import { describe, expect, it } from 'vitest';
import { createJsAccelerator, matchSql } from '../src/index.ts';

describe('@guardrail/wasm', () => {
  it('matchSql detects union select', () => {
    const hit = matchSql('1 UNION SELECT 1', [
      { name: 'union-select', pattern: /UNION\s+SELECT/i },
    ]);
    expect(hit?.name).toBe('union-select');
  });

  it('matchSql returns null for clean input', () => {
    expect(matchSql('hello', [{ name: 'union-select', pattern: /UNION\s+SELECT/i }])).toBeNull();
  });

  it('createJsAccelerator exposes name', () => {
    expect(createJsAccelerator().name).toBe('js');
  });
});
