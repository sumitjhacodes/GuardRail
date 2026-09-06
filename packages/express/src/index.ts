import {
  createGuardrail,
  events,
  healthCheck,
  sanitizeError,
  validateConfig,
  VERSION,
  type FieldRule,
  type GuardrailConfig,
  type GuardrailInstance,
  type OutputsConfig,
} from '@guardrail/core';
import type {
  ErrorRequestHandler,
  Request,
  RequestHandler,
  Response,
} from 'express';
import { randomBytes } from 'node:crypto';

export type {
  FieldRule,
  GuardrailConfig,
  InferInputs,
  ValidationResult,
} from '@guardrail/core';

export { rules, events, VERSION } from '@guardrail/core';

declare global {
  namespace Express {
    interface Request {
      guardrail?: {
        requestId: string;
        validated?: unknown;
        instance?: GuardrailInstance;
        /** Accumulated outputs config (errorSanitization preserved across layers) */
        outputs?: OutputsConfig;
      };
    }
  }
}

export interface ExpressGuardrailOptions<TInputs extends Record<string, FieldRule>>
  extends GuardrailConfig<TInputs> {
  /** Which request sources to validate (default: body, then query/params for matching keys) */
  sources?: Array<'body' | 'query' | 'params'>;
  /** HTTP status for blocked requests (default: 400) */
  statusCode?: number;
}

type GuardrailMiddleware = RequestHandler & {
  errorHandler: () => ErrorRequestHandler;
  healthCheck: () => RequestHandler;
  validateConfig: typeof validateConfig;
  VERSION: string;
};

function createRequestId(): string {
  return `req_${randomBytes(8).toString('hex')}`;
}

/**
 * Merge body / query / params for validation.
 * Body wins on key conflicts; query and params fill missing keys listed in inputs.
 */
function collectInputData(
  req: Request,
  inputKeys: string[],
  sources: Array<'body' | 'query' | 'params'>,
): Record<string, unknown> {
  const data: Record<string, unknown> = Object.create(null);
  const keySet = new Set(inputKeys);

  const take = (source: unknown) => {
    if (!source || typeof source !== 'object') return;
    for (const key of Object.keys(source as object)) {
      if (keySet.has(key) && data[key] === undefined) {
        data[key] = (source as Record<string, unknown>)[key];
      }
    }
  };

  // Body first (wins)
  if (sources.includes('body') && req.body && typeof req.body === 'object') {
    for (const key of inputKeys) {
      if (key in (req.body as object)) {
        data[key] = (req.body as Record<string, unknown>)[key];
      }
    }
  }

  if (sources.includes('query')) take(req.query);
  if (sources.includes('params')) take(req.params);

  // If no keys configured, pass through entire body
  if (inputKeys.length === 0 && sources.includes('body')) {
    return (req.body ?? Object.create(null)) as Record<string, unknown>;
  }

  return data;
}

function mergeOutputs(
  previous: OutputsConfig | undefined,
  next: OutputsConfig | undefined,
): OutputsConfig | undefined {
  if (!previous) return next;
  if (!next) return previous;
  return {
    ...previous,
    ...next,
    // Prefer explicit next, else keep earlier (global) errorSanitization
    errorSanitization: next.errorSanitization ?? previous.errorSanitization,
    redact: next.redact ?? previous.redact,
    redactPaths: next.redactPaths ?? previous.redactPaths,
    headers: { ...previous.headers, ...next.headers },
  };
}

function applySecurityHeaders(res: Response, headers?: Record<string, string>): void {
  if (!headers) return;
  for (const [name, value] of Object.entries(headers)) {
    res.setHeader(name, value);
  }
}

const SANITIZERS = Symbol.for('guardrail.sanitizers');
const RESPONSE_WRAPPED = Symbol.for('guardrail.responseWrapped');

type SanitizerFn = (data: unknown) => unknown;

function wrapResponse(
  res: Response,
  instance: GuardrailInstance,
  headers?: Record<string, string>,
): void {
  applySecurityHeaders(res, headers);

  const resAny = res as Response & {
    [SANITIZERS]?: SanitizerFn[];
    [RESPONSE_WRAPPED]?: boolean;
  };

  const bag = resAny[SANITIZERS] ?? [];
  bag.push((data) => instance.sanitize(data));
  resAny[SANITIZERS] = bag;

  if (resAny[RESPONSE_WRAPPED]) return;
  resAny[RESPONSE_WRAPPED] = true;

  const originalJson = res.json.bind(res);
  const originalSend = res.send.bind(res);

  const runSanitizers = (body: unknown): unknown => {
    let current = body;
    for (const sanitize of resAny[SANITIZERS] ?? []) {
      current = sanitize(current);
    }
    return current;
  };

  res.json = function guardedJson(body: unknown) {
    return originalJson(runSanitizers(body));
  };

  res.send = function guardedSend(body: unknown) {
    if (body !== null && typeof body === 'object' && !Buffer.isBuffer(body)) {
      return originalSend(runSanitizers(body) as string);
    }
    if (typeof body === 'string') {
      try {
        const parsed = JSON.parse(body) as unknown;
        return originalSend(JSON.stringify(runSanitizers(parsed)));
      } catch {
        return originalSend(body);
      }
    }
    return originalSend(body as string);
  };
}

/**
 * Express middleware factory.
 *
 * @example
 * ```ts
 * import express from 'express';
 * import { guardrail, rules } from '@guardrail/express';
 *
 * const app = express();
 * app.use(express.json());
 * app.use(guardrail({
 *   inputs: { search: rules.string().sqlSafe().xssSafe() },
 *   outputs: { redact: ['password', 'ssn'] },
 * }));
 * app.use(guardrail.errorHandler());
 * ```
 */
export function guardrail<TInputs extends Record<string, FieldRule>>(
  config: ExpressGuardrailOptions<TInputs> = {},
): GuardrailMiddleware {
  validateConfig(config);
  const instance = createGuardrail(config);
  const sources = config.sources ?? ['body', 'query', 'params'];
  const statusCode = config.statusCode ?? 400;
  const inputKeys = config.inputs ? Object.keys(config.inputs) : [];
  const failClosed = config.failClosed !== false;

  const middleware: RequestHandler = async (req, res, next) => {
    const requestId = req.guardrail?.requestId ?? createRequestId();
    req.guardrail = {
      requestId,
      instance,
      outputs: mergeOutputs(req.guardrail?.outputs, config.outputs),
      validated: req.guardrail?.validated,
    };

    try {
      wrapResponse(res, instance, config.outputs?.headers);

      if (config.inputs && inputKeys.length > 0) {
        const data = collectInputData(req, inputKeys, sources);
        const result = await instance.validate(data, requestId);

        if (!result.valid) {
          events.emit({
            type: 'block',
            requestId,
            path: req.path,
            method: req.method,
            timestamp: result.timestamp,
            violationType: result.errors[0]?.code,
          });

          res.status(statusCode).json({
            valid: false,
            errors: result.errors,
            requestId: result.requestId,
            timestamp: result.timestamp,
          });
          return;
        }

        req.guardrail.validated = result.data;

        // Replace body with shape-stripped validated data only (no mass-assignment)
        if (result.data && typeof result.data === 'object') {
          req.body = { ...(result.data as object) };
        }
      }

      next();
    } catch (err) {
      if (config.debug) {
        console.error('[guardrail/express]', err);
      }

      if (!failClosed) {
        next(err);
        return;
      }

      const timestamp = new Date().toISOString();
      events.emit({
        type: 'block',
        requestId,
        path: req.path,
        method: req.method,
        timestamp,
        violationType: 'INTERNAL_ERROR',
      });
      res.status(statusCode).json({
        valid: false,
        errors: [
          {
            field: '_root',
            code: 'INTERNAL_ERROR',
            message: 'Security validation failed',
          },
        ],
        requestId,
        timestamp,
      });
    }
  };

  const wrapped = middleware as GuardrailMiddleware;
  // Prefer this instance's outputs when calling mw.errorHandler()
  wrapped.errorHandler = () => errorHandler(config.outputs);
  wrapped.healthCheck = () => healthCheckHandler(instance);
  wrapped.validateConfig = validateConfig;
  wrapped.VERSION = VERSION;
  return wrapped;
}

/** Express error handler — sanitizes errors before sending to client. */
export function errorHandler(
  errConfig?: OutputsConfig,
): ErrorRequestHandler {
  return (err, req, res, _next) => {
    const requestId = req.guardrail?.requestId ?? createRequestId();
    // Explicit arg > accumulated middleware outputs > safe defaults
    const outputs = errConfig ?? req.guardrail?.outputs;
    const sanitized = sanitizeError(
      err,
      outputs?.errorSanitization ?? {
        hideStackTraces: process.env.NODE_ENV === 'production',
        hideServerInfo: true,
      },
      requestId,
    );

    if (!res.headersSent) {
      res.status(sanitized.statusCode >= 400 ? sanitized.statusCode : 500).json({
        error: sanitized.message,
        code: sanitized.code,
        requestId: sanitized.requestId,
        ...(sanitized.stack ? { stack: sanitized.stack } : {}),
      });
    }
  };
}

function healthCheckHandler(instance?: GuardrailInstance): RequestHandler {
  return (_req, res) => {
    res.json(healthCheck(instance));
  };
}

guardrail.errorHandler = errorHandler;
guardrail.healthCheck = () => healthCheckHandler();
guardrail.validateConfig = validateConfig;
guardrail.VERSION = VERSION;
