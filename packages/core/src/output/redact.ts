import { createNullObject } from '../utils/security.js';

const DEFAULT_PLACEHOLDER = '[REDACTED]';

/**
 * Deep redaction by key name (recursive).
 * Prototype-safe, circular-reference-safe.
 */
export function redactByKeys(
  obj: unknown,
  keys: readonly string[],
  placeholder = DEFAULT_PLACEHOLDER,
): unknown {
  const keySet = new Set(keys.map((k) => k.toLowerCase()));
  return deepWalk(obj, (key, value) => {
    if (key !== null && keySet.has(key.toLowerCase())) {
      return { replace: true, value: placeholder };
    }
    return { replace: false, value };
  });
}

/**
 * Path-based redaction supporting wildcards.
 * Example: 'user.paymentMethods.*.number'
 */
export function deepRedact(
  obj: unknown,
  paths: readonly string[],
  placeholder = DEFAULT_PLACEHOLDER,
): unknown {
  if (!paths.length) return obj;

  const compiled = paths.map(compilePath);
  return deepWalk(obj, (_key, value, pathSoFar) => {
    for (const matcher of compiled) {
      if (matcher(pathSoFar)) {
        return { replace: true, value: placeholder };
      }
    }
    return { replace: false, value };
  });
}

type PathMatcher = (path: string[]) => boolean;

function compilePath(path: string): PathMatcher {
  const parts = path.split('.');
  return (current: string[]) => {
    if (parts.length !== current.length && !parts.includes('**')) {
      // Allow trailing match only when lengths equal unless ** used
      if (parts.length !== current.length) return false;
    }
    if (parts.length !== current.length) return false;
    for (let i = 0; i < parts.length; i++) {
      const p = parts[i]!;
      const c = current[i]!;
      if (p === '*') continue;
      if (p !== c) return false;
    }
    return true;
  };
}

type WalkDecision = { replace: boolean; value: unknown };

function deepWalk(
  obj: unknown,
  visitor: (key: string | null, value: unknown, path: string[]) => WalkDecision,
  seen = new WeakSet<object>(),
  path: string[] = [],
): unknown {
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }

  if (seen.has(obj as object)) {
    return '[Circular]';
  }
  seen.add(obj as object);

  if (Array.isArray(obj)) {
    return obj.map((item, i) => {
      const nextPath = [...path, String(i)];
      const decision = visitor(String(i), item, nextPath);
      if (decision.replace) return decision.value;
      return deepWalk(item, visitor, seen, nextPath);
    });
  }

  const result = createNullObject<Record<string, unknown>>();
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    const nextPath = [...path, key];
    const decision = visitor(key, value, nextPath);
    if (decision.replace) {
      result[key] = decision.value;
    } else if (value !== null && typeof value === 'object') {
      result[key] = deepWalk(value, visitor, seen, nextPath);
    } else {
      result[key] = value;
    }
  }
  return result;
}

/** Apply both key and path redaction. */
export function sanitizeOutput(
  data: unknown,
  options: {
    redact?: readonly string[];
    redactPaths?: readonly string[];
    placeholder?: string;
  },
): unknown {
  const placeholder = options.placeholder ?? DEFAULT_PLACEHOLDER;
  let result = data;
  if (options.redact?.length) {
    result = redactByKeys(result, options.redact, placeholder);
  }
  if (options.redactPaths?.length) {
    result = deepRedact(result, options.redactPaths, placeholder);
  }
  return result;
}
