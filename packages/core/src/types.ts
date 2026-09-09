/** Shared Guardrail types */

export type SqlDialect = 'mysql' | 'postgres' | 'sqlite' | 'mssql' | 'all';

export type XssContext = 'html' | 'attribute' | 'js' | 'css' | 'url';

export type ViolationAction = 'block' | 'log' | 'alert';

export interface ValidationError {
  field: string;
  code: string;
  message: string;
  value?: unknown;
  pattern?: string;
}

export interface ValidationResult<T = unknown> {
  valid: boolean;
  data?: T;
  errors: ValidationError[];
  requestId: string;
  timestamp: string;
}

export interface FieldParseResult<T = unknown> {
  errors: ValidationError[];
  /** Present when validation succeeds — shape-stripped for objects */
  value?: T;
}

export interface FieldRule<T = unknown> {
  readonly _type?: T;
  validate(value: unknown, field: string): Promise<ValidationError[]> | ValidationError[];
  /** Validate and return a cleaned value (strips unknown object keys). */
  parse(value: unknown, field: string): Promise<FieldParseResult<T>> | FieldParseResult<T>;
}

export type InferRuleType<R> = R extends FieldRule<infer T> ? T : unknown;

export type InferInputs<T extends Record<string, FieldRule>> = {
  [K in keyof T]: InferRuleType<T[K]>;
};

export interface ErrorSanitizationConfig {
  hideStackTraces?: boolean;
  hideServerInfo?: boolean;
  customErrorMessages?: Record<string, string>;
  placeholder?: string;
}

export interface OutputsConfig {
  redact?: string[];
  redactPaths?: string[];
  redactPlaceholder?: string;
  /** Duck-typed Zod-like schema with safeParse */
  schema?: {
    safeParse: (data: unknown) => {
      success: boolean;
      data?: unknown;
      error?: { message?: string; issues?: unknown[] };
    };
  };
  headers?: Record<string, string>;
  errorSanitization?: ErrorSanitizationConfig;
}

export interface GuardrailConfig<TInputs extends Record<string, FieldRule> = Record<string, FieldRule>> {
  inputs?: TInputs;
  outputs?: OutputsConfig;
  /** Behavior policies evaluated around the request lifecycle */
  policies?: Policy[];
  debug?: boolean;
  /** Fail closed on unexpected errors (default: true) */
  failClosed?: boolean;
}

/** When a policy runs relative to the application handler */
export type PolicyPhase = 'before' | 'after';

export interface PolicyViolation {
  policy: string;
  message: string;
  requestId: string;
  timestamp: string;
}

export interface Policy {
  name: string;
  when: (req: GuardrailRequest) => boolean | Promise<boolean>;
  invariant: (
    req: GuardrailRequest,
    res?: GuardrailResponse,
  ) => boolean | Promise<boolean>;
  onViolation:
    | 'block'
    | 'log'
    | 'alert'
    | ((req: GuardrailRequest, res: GuardrailResponse | undefined, violation: PolicyViolation) => void);
  /** Lower runs first (default: 100) */
  priority?: number;
  /** before = pre-handler (default); after = post-response body */
  phase?: PolicyPhase;
}

export interface PolicyRunResult {
  allowed: boolean;
  blocked: boolean;
  violations: PolicyViolation[];
}

export interface GuardrailRequest {
  method?: string;
  path?: string;
  ip?: string;
  body?: unknown;
  query?: unknown;
  params?: unknown;
  headers?: Record<string, string | string[] | undefined>;
  user?: { id?: string; role?: string; [key: string]: unknown };
  [key: string]: unknown;
}

export interface GuardrailResponse {
  locals?: Record<string, unknown>;
  body?: unknown;
  statusCode?: number;
  [key: string]: unknown;
}

export interface SecurityEvent {
  type: 'violation' | 'block' | 'allow' | 'alert';
  violationType?: string;
  field?: string;
  code?: string;
  message?: string;
  requestId: string;
  path?: string;
  method?: string;
  timestamp: string;
  meta?: Record<string, unknown>;
}

export interface HealthCheckResult {
  status: 'healthy' | 'degraded' | 'unhealthy';
  version: string;
  rulesLoaded: number;
}

export interface FileInput {
  filename?: string;
  mimetype?: string;
  size?: number;
  buffer?: Uint8Array | Buffer;
  originalname?: string;
}

export class GuardrailConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GuardrailConfigError';
  }
}

export class GuardrailValidationError extends Error {
  readonly result: ValidationResult;

  constructor(result: ValidationResult) {
    super(`Validation failed with ${result.errors.length} error(s)`);
    this.name = 'GuardrailValidationError';
    this.result = result;
  }
}
