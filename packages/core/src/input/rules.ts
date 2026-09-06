import type {
  FieldParseResult,
  FieldRule,
  FileInput,
  SqlDialect,
  ValidationError,
  XssContext,
} from '../types.js';
import {
  detectPathTraversal,
  detectSecrets,
  detectSqlInjection,
  detectXss,
} from './detectors/index.js';
import { createNullObject, isProduction, sanitizeValueForClient } from '../utils/security.js';

type SyncValidate = (value: unknown, field: string) => ValidationError[];
type AsyncValidate = (value: unknown, field: string) => Promise<ValidationError[]>;

abstract class BaseRule<T> implements FieldRule<T> {
  declare readonly _type?: T;
  protected checks: Array<SyncValidate | AsyncValidate> = [];

  protected add(check: SyncValidate | AsyncValidate): this {
    this.checks.push(check);
    return this;
  }

  async validate(value: unknown, field: string): Promise<ValidationError[]> {
    const parsed = await this.parse(value, field);
    return parsed.errors;
  }

  async parse(value: unknown, field: string): Promise<FieldParseResult<T>> {
    const errors: ValidationError[] = [];
    for (const check of this.checks) {
      const result = await check(value, field);
      if (result.length > 0) {
        errors.push(...result);
        // Fail fast on security violations
        if (result.some((e) => e.code.endsWith('_DETECTED') || e.code === 'SECRET_DETECTED')) {
          return { errors };
        }
      }
    }
    if (errors.length > 0) return { errors };
    return { errors: [], value: value as T };
  }
}

function err(
  field: string,
  code: string,
  message: string,
  value?: unknown,
  pattern?: string,
): ValidationError {
  const production = isProduction();
  const e: ValidationError = { field, code, message };
  if (value !== undefined) {
    e.value = sanitizeValueForClient(value, production);
  }
  if (pattern) e.pattern = pattern;
  return e;
}

// ─── StringRule ─────────────────────────────────────────────────────────────

export class StringRule extends BaseRule<string> {
  constructor() {
    super();
    this.add((value, field) => {
      if (value === undefined || value === null) {
        return [err(field, 'REQUIRED', 'Value is required')];
      }
      if (typeof value !== 'string') {
        return [err(field, 'INVALID_TYPE', 'Must be a string', value)];
      }
      return [];
    });
  }

  minLength(n: number): this {
    return this.add((value, field) => {
      if (typeof value === 'string' && value.length < n) {
        return [err(field, 'MIN_LENGTH', `Must be at least ${n} characters`, value)];
      }
      return [];
    });
  }

  maxLength(n: number): this {
    return this.add((value, field) => {
      if (typeof value === 'string' && value.length > n) {
        return [err(field, 'MAX_LENGTH', `Must be at most ${n} characters`, value)];
      }
      return [];
    });
  }

  matches(re: RegExp): this {
    return this.add((value, field) => {
      if (typeof value === 'string' && !re.test(value)) {
        return [err(field, 'PATTERN_MISMATCH', 'Does not match required pattern', value)];
      }
      return [];
    });
  }

  oneOf(options: readonly string[]): this {
    const set = new Set(options);
    return this.add((value, field) => {
      if (typeof value === 'string' && !set.has(value)) {
        return [
          err(field, 'NOT_ONE_OF', `Must be one of: ${options.join(', ')}`, value),
        ];
      }
      return [];
    });
  }

  sqlSafe(opts?: { dialect?: SqlDialect }): this {
    const dialect = opts?.dialect ?? 'all';
    return this.add((value, field) => {
      if (typeof value !== 'string') return [];
      const result = detectSqlInjection(value, dialect);
      if (!result.safe) {
        return [
          err(
            field,
            'SQL_INJECTION_DETECTED',
            'Input contains potentially dangerous SQL patterns',
            value,
            result.pattern,
          ),
        ];
      }
      return [];
    });
  }

  xssSafe(opts?: { context?: XssContext }): this {
    const context = opts?.context ?? 'html';
    return this.add((value, field) => {
      if (typeof value !== 'string') return [];
      const result = detectXss(value, context);
      if (!result.safe) {
        return [
          err(
            field,
            'XSS_DETECTED',
            'Input contains potentially dangerous XSS patterns',
            value,
            result.pattern,
          ),
        ];
      }
      return [];
    });
  }

  noSecrets(): this {
    return this.add((value, field) => {
      if (typeof value !== 'string') return [];
      const result = detectSecrets(value);
      if (!result.safe) {
        return [
          err(
            field,
            'SECRET_DETECTED',
            'Input appears to contain a secret or credential',
            undefined,
            result.pattern,
          ),
        ];
      }
      return [];
    });
  }

  noPathTraversal(): this {
    return this.add((value, field) => {
      if (typeof value !== 'string') return [];
      const result = detectPathTraversal(value);
      if (!result.safe) {
        return [
          err(
            field,
            'PATH_TRAVERSAL_DETECTED',
            'Input contains path traversal patterns',
            value,
            result.pattern,
          ),
        ];
      }
      return [];
    });
  }

  strongPassword(): this {
    return this.add((value, field) => {
      if (typeof value !== 'string') return [];
      const errors: ValidationError[] = [];
      if (value.length < 8) {
        errors.push(err(field, 'WEAK_PASSWORD', 'Password must be at least 8 characters'));
      }
      if (!/[A-Z]/.test(value)) {
        errors.push(err(field, 'WEAK_PASSWORD', 'Password must contain an uppercase letter'));
      }
      if (!/[a-z]/.test(value)) {
        errors.push(err(field, 'WEAK_PASSWORD', 'Password must contain a lowercase letter'));
      }
      if (!/[0-9]/.test(value)) {
        errors.push(err(field, 'WEAK_PASSWORD', 'Password must contain a digit'));
      }
      if (!/[^A-Za-z0-9]/.test(value)) {
        errors.push(err(field, 'WEAK_PASSWORD', 'Password must contain a special character'));
      }
      return errors;
    });
  }

  optional(): OptionalRule<string> {
    return new OptionalRule(this);
  }
}

// ─── NumberRule ─────────────────────────────────────────────────────────────

export class NumberRule extends BaseRule<number> {
  constructor() {
    super();
    this.add((value, field) => {
      if (value === undefined || value === null) {
        return [err(field, 'REQUIRED', 'Value is required')];
      }
      if (typeof value !== 'number' || Number.isNaN(value)) {
        return [err(field, 'INVALID_TYPE', 'Must be a number', value)];
      }
      return [];
    });
  }

  min(n: number): this {
    return this.add((value, field) => {
      if (typeof value === 'number' && value < n) {
        return [err(field, 'MIN_VALUE', `Must be at least ${n}`, value)];
      }
      return [];
    });
  }

  max(n: number): this {
    return this.add((value, field) => {
      if (typeof value === 'number' && value > n) {
        return [err(field, 'MAX_VALUE', `Must be at most ${n}`, value)];
      }
      return [];
    });
  }

  optional(): OptionalRule<number> {
    return new OptionalRule(this);
  }
}

// ─── UuidRule ───────────────────────────────────────────────────────────────

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export class UuidRule extends BaseRule<string> {
  constructor() {
    super();
    this.add((value, field) => {
      if (value === undefined || value === null) {
        return [err(field, 'REQUIRED', 'Value is required')];
      }
      if (typeof value !== 'string' || !UUID_RE.test(value)) {
        return [err(field, 'INVALID_UUID', 'Must be a valid UUID', value)];
      }
      return [];
    });
  }

  optional(): OptionalRule<string> {
    return new OptionalRule(this);
  }
}

// ─── EmailRule ──────────────────────────────────────────────────────────────

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export class EmailRule extends BaseRule<string> {
  private checkDomain = false;

  constructor() {
    super();
    this.add((value, field) => {
      if (value === undefined || value === null) {
        return [err(field, 'REQUIRED', 'Value is required')];
      }
      if (typeof value !== 'string' || !EMAIL_RE.test(value)) {
        return [err(field, 'INVALID_EMAIL', 'Must be a valid email address', value)];
      }
      return [];
    });
  }

  /** Enable DNS MX lookup (async). Off by default for <1ms hot path. */
  domainExists(): this {
    this.checkDomain = true;
    return this.add(async (value, field) => {
      if (typeof value !== 'string' || !this.checkDomain) return [];
      const domain = value.split('@')[1];
      if (!domain) {
        return [err(field, 'INVALID_EMAIL', 'Must be a valid email address', value)];
      }
      try {
        const dns = await import('node:dns/promises');
        await dns.resolveMx(domain);
        return [];
      } catch {
        return [err(field, 'EMAIL_DOMAIN_NOT_FOUND', `Email domain does not exist: ${domain}`)];
      }
    });
  }

  optional(): OptionalRule<string> {
    return new OptionalRule(this);
  }
}

// ─── ObjectRule ─────────────────────────────────────────────────────────────

export class ObjectRule<T extends Record<string, FieldRule>> extends BaseRule<{
  [K in keyof T]: T[K] extends FieldRule<infer U> ? U : unknown;
}> {
  constructor(private readonly shape: T) {
    super();
  }

  override async parse(
    value: unknown,
    field: string,
  ): Promise<FieldParseResult<{ [K in keyof T]: T[K] extends FieldRule<infer U> ? U : unknown }>> {
    if (value === undefined || value === null) {
      return { errors: [err(field, 'REQUIRED', 'Value is required')] };
    }
    if (typeof value !== 'object' || Array.isArray(value)) {
      return { errors: [err(field, 'INVALID_TYPE', 'Must be an object', value)] };
    }

    const obj = value as Record<string, unknown>;
    const cleaned = createNullObject<Record<string, unknown>>();
    const errors: ValidationError[] = [];

    for (const key of Object.keys(this.shape)) {
      const rule = this.shape[key]!;
      const nested = await rule.parse(obj[key], `${field}.${key}`);
      if (nested.errors.length > 0) {
        errors.push(...nested.errors);
      } else {
        cleaned[key] = nested.value;
      }
    }

    if (errors.length > 0) return { errors };
    return {
      errors: [],
      value: cleaned as { [K in keyof T]: T[K] extends FieldRule<infer U> ? U : unknown },
    };
  }
}

// ─── ArrayRule ──────────────────────────────────────────────────────────────

export class ArrayRule<T> extends BaseRule<T[]> {
  constructor(private readonly itemRule: FieldRule<T>) {
    super();
    this.add(async (value, field) => {
      if (value === undefined || value === null) {
        return [err(field, 'REQUIRED', 'Value is required')];
      }
      if (!Array.isArray(value)) {
        return [err(field, 'INVALID_TYPE', 'Must be an array', value)];
      }
      return [];
    });
  }

  override async parse(value: unknown, field: string): Promise<FieldParseResult<T[]>> {
    // Run length / type checks from add()
    const base = await super.parse(value, field);
    if (base.errors.length > 0) return { errors: base.errors };
    if (!Array.isArray(value)) {
      return { errors: [err(field, 'INVALID_TYPE', 'Must be an array', value)] };
    }

    const cleaned: T[] = [];
    const errors: ValidationError[] = [];
    for (let i = 0; i < value.length; i++) {
      const nested = await this.itemRule.parse(value[i], `${field}[${i}]`);
      if (nested.errors.length > 0) {
        errors.push(...nested.errors);
      } else {
        cleaned.push(nested.value as T);
      }
    }
    if (errors.length > 0) return { errors };
    return { errors: [], value: cleaned };
  }

  maxItems(n: number): this {
    return this.add((value, field) => {
      if (Array.isArray(value) && value.length > n) {
        return [err(field, 'MAX_ITEMS', `Must have at most ${n} items`, value.length)];
      }
      return [];
    });
  }

  minItems(n: number): this {
    return this.add((value, field) => {
      if (Array.isArray(value) && value.length < n) {
        return [err(field, 'MIN_ITEMS', `Must have at least ${n} items`, value.length)];
      }
      return [];
    });
  }
}

// ─── FileRule ───────────────────────────────────────────────────────────────

const EXECUTABLE_EXTENSIONS = new Set([
  'exe',
  'bat',
  'cmd',
  'com',
  'msi',
  'scr',
  'ps1',
  'sh',
  'bash',
  'dll',
  'so',
  'dylib',
  'js',
  'vbs',
  'wsf',
  'jar',
]);

const EXECUTABLE_MAGIC: Array<{ name: string; bytes: number[] }> = [
  { name: 'mz-exe', bytes: [0x4d, 0x5a] },
  { name: 'elf', bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { name: 'mach-o', bytes: [0xfe, 0xed, 0xfa, 0xce] },
];

export class FileRule extends BaseRule<FileInput> {
  private malwareScanEnabled = false;

  constructor() {
    super();
    this.add((value, field) => {
      if (value === undefined || value === null) {
        return [err(field, 'REQUIRED', 'File is required')];
      }
      if (typeof value !== 'object') {
        return [err(field, 'INVALID_TYPE', 'Must be a file object')];
      }
      return [];
    });
  }

  maxSize(bytes: number): this {
    return this.add((value, field) => {
      const file = value as FileInput;
      if (typeof file.size === 'number' && file.size > bytes) {
        return [err(field, 'FILE_TOO_LARGE', `File exceeds max size of ${bytes} bytes`)];
      }
      return [];
    });
  }

  mimeTypes(allowed: readonly string[]): this {
    const set = new Set(allowed.map((m) => m.toLowerCase()));
    return this.add((value, field) => {
      const file = value as FileInput;
      const mime = (file.mimetype ?? '').toLowerCase();
      if (mime && !set.has(mime)) {
        return [err(field, 'INVALID_MIME_TYPE', `MIME type not allowed: ${mime}`)];
      }
      return [];
    });
  }

  noExecutable(): this {
    return this.add((value, field) => {
      const file = value as FileInput;
      const name = file.filename ?? file.originalname ?? '';
      const ext = name.split('.').pop()?.toLowerCase() ?? '';
      if (EXECUTABLE_EXTENSIONS.has(ext)) {
        return [err(field, 'EXECUTABLE_FILE', 'Executable files are not allowed')];
      }
      const buf = file.buffer;
      if (buf && buf.length >= 2) {
        for (const magic of EXECUTABLE_MAGIC) {
          if (magic.bytes.every((b, i) => buf[i] === b)) {
            return [err(field, 'EXECUTABLE_FILE', `Executable content detected (${magic.name})`)];
          }
        }
      }
      return [];
    });
  }

  /** Stub for ClamAV / malware scanner integration. */
  scanMalware(): this {
    this.malwareScanEnabled = true;
    return this.add((_value, field) => {
      if (this.malwareScanEnabled) {
        // Stub: always passes unless a scanner is wired in later
        return [];
      }
      return [err(field, 'MALWARE_SCAN_NOT_CONFIGURED', 'Malware scanning is not configured')];
    });
  }
}

// ─── Optional wrapper ───────────────────────────────────────────────────────

export class OptionalRule<T> implements FieldRule<T | undefined> {
  declare readonly _type?: T | undefined;

  constructor(private readonly inner: FieldRule<T>) {}

  async validate(value: unknown, field: string): Promise<ValidationError[]> {
    const parsed = await this.parse(value, field);
    return parsed.errors;
  }

  async parse(value: unknown, field: string): Promise<FieldParseResult<T | undefined>> {
    if (value === undefined || value === null) {
      return { errors: [], value: undefined };
    }
    return this.inner.parse(value, field);
  }
}

// ─── Factory ────────────────────────────────────────────────────────────────

export const rules = {
  string: () => new StringRule(),
  number: () => new NumberRule(),
  uuid: () => new UuidRule(),
  email: () => new EmailRule(),
  object: <T extends Record<string, FieldRule>>(shape: T) => new ObjectRule(shape),
  array: <T>(item: FieldRule<T>) => new ArrayRule(item),
  file: () => new FileRule(),
} as const;
