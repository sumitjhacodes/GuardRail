/**
 * JS pattern accelerator for Guardrail detectors.
 * Drop-in when Rust WASM is not built; same API surface as the WASM module.
 */

export interface PatternMatch {
  name: string;
  matched: string;
}

export function matchSql(
  input: string,
  patterns: ReadonlyArray<{ name: string; pattern: RegExp }>,
): PatternMatch | null {
  for (const { name, pattern } of patterns) {
    // Clone flags — lastIndex safety for global regexes
    const re = new RegExp(pattern.source, pattern.flags.replace('g', '') || pattern.flags);
    const match = re.exec(input);
    if (match) {
      return { name, matched: match[0]?.slice(0, 64) ?? name };
    }
  }
  return null;
}

export function createJsAccelerator(): {
  name: string;
  matchSql: typeof matchSql;
} {
  return { name: 'js', matchSql };
}

export const VERSION = '0.3.0';
