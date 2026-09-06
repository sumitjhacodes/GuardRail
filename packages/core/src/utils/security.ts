/** Create a null-prototype object (prototype-pollution safe). */
export function createNullObject<T extends Record<string, unknown> = Record<string, unknown>>(): T {
  return Object.create(null) as T;
}

/** ISO timestamp. */
export function nowIso(): string {
  return new Date().toISOString();
}

/** Timing-safe string equality. */
export function timingSafeEqualString(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Compare against self to keep constant-ish time on length mismatch
    const dummy = Buffer.alloc(bufA.length);
    timingSafeEqualBuffers(bufA, dummy);
    return false;
  }
  return timingSafeEqualBuffers(bufA, bufB);
}

function timingSafeEqualBuffers(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i]! ^ b[i]!;
  }
  return result === 0;
}

/** Sanitize a value for inclusion in client-facing error responses. */
export function sanitizeValueForClient(value: unknown, production: boolean): unknown {
  if (!production) return value;
  if (typeof value === 'string') {
    if (value.length > 64) return `${value.slice(0, 8)}…[redacted]`;
    return '[redacted]';
  }
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  return '[redacted]';
}

/** Never log raw secrets — return a safe placeholder. */
export function redactSecretForLog(value: string): string {
  if (value.length <= 8) return '***';
  return `${value.slice(0, 4)}…${value.slice(-2)} (${value.length} chars)`;
}

/** Check production mode at call time (not module load). */
export function isProduction(): boolean {
  return typeof process !== 'undefined' && process.env?.NODE_ENV === 'production';
}

/** Deep freeze an object graph (best-effort, skips cycles). */
export function deepFreeze<T>(obj: T, seen = new WeakSet<object>()): T {
  if (obj === null || typeof obj !== 'object') return obj;
  if (seen.has(obj as object)) return obj;
  seen.add(obj as object);
  Object.freeze(obj);
  for (const value of Object.values(obj as object)) {
    deepFreeze(value, seen);
  }
  return obj;
}

