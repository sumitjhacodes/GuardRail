/**
 * Optional accelerator interface for hot-path pattern matching.
 * Core detectors use JS by default; call setPatternAccelerator() when WASM is loaded.
 */

export interface PatternMatch {
  name: string;
  matched: string;
}

export interface PatternAccelerator {
  /** Return first matching pattern name/snippet, or null if safe */
  matchSql?: (input: string, patterns: ReadonlyArray<{ name: string; pattern: RegExp }>) => PatternMatch | null;
  /** Implementation label for health / metrics */
  name: string;
}

let accelerator: PatternAccelerator | null = null;

export function setPatternAccelerator(next: PatternAccelerator | null): void {
  accelerator = next;
}

export function getPatternAccelerator(): PatternAccelerator | null {
  return accelerator;
}

export function matchSqlWithAccelerator(
  input: string,
  patterns: ReadonlyArray<{ name: string; pattern: RegExp }>,
): PatternMatch | null | undefined {
  if (!accelerator?.matchSql) return undefined;
  try {
    return accelerator.matchSql(input, patterns);
  } catch {
    return undefined;
  }
}
