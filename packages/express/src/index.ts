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
  type GuardrailRequest,
  type GuardrailResponse,
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
  Policy,
  ValidationResult,
} from '@guardrail/core';

export { rules, events, VERSION, runPolicies, scanCode } from '@guardrail/core';

declare global {
  namespace Express {
    interface Request {
      guardrail?: {
        requestId: string;
        validated?: unknown;
        instance?: GuardrailInstance;
        outputs?: OutputsConfig;
      };
      user?: { id?: string; role?: string; [key: string]: unknown };
    }
  }
}

export interface ExpressGuardrailOptions<TInputs extends Record<string, FieldRule>>
  extends GuardrailConfig<TInputs> {
  sources?: Array<'body' | 'query' | 'params'>;
  statusCode?: number;
  /** HTTP status when a policy blocks (default: 403) */
  policyStatusCode?: number;
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

function toGuardrailRequest(req: Request): GuardrailRequest {
  return {
    method: req.method,
    path: req.path,
    ip: req.ip,
    body: req.body,
    query: req.query,
    params: req.params,
    headers: req.headers as Record<string, string | string[] | undefined>,
    user: req.user,
  };
}

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

  if (sources.includes('body') && req.body && typeof req.body === 'object') {
    for (const key of inputKeys) {
      if (key in (req.body as object)) {
        data[key] = (req.body as Record<string, unknown>)[key];
      }
    }
  }

  if (sources.includes('query')) take(req.query);
  if (sources.includes('params')) take(req.params);

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
const AFTER_POLICIES = Symbol.for('guardrail.afterPolicies');

type SanitizerFn = (data: unknown) => unknown;

type AfterPolicyDecision = {
  blocked: boolean;
  payload?: unknown;
  statusCode?: number;
};

type AfterPolicyRunner = (body: unknown) => Promise<AfterPolicyDecision>;

function wrapResponse(
  res: Response,
  instance: GuardrailInstance,
  headers: Record<string, string> | undefined,
  afterPolicyRunner?: AfterPolicyRunner,
): void {
  applySecurityHeaders(res, headers);

  const resAny = res as Response & {
    [SANITIZERS]?: SanitizerFn[];
    [RESPONSE_WRAPPED]?: boolean;
    [AFTER_POLICIES]?: AfterPolicyRunner;
  };

  const bag = resAny[SANITIZERS] ?? [];
  bag.push((data) => instance.sanitize(data));
  resAny[SANITIZERS] = bag;

  if (afterPolicyRunner) {
    const previous = resAny[AFTER_POLICIES];
    // Chain stacked middleware after-runners instead of overwriting
    resAny[AFTER_POLICIES] = previous
      ? async (body) => {
          const first = await previous(body);
          if (first.blocked) return first;
          return afterPolicyRunner(body);
        }
      : afterPolicyRunner;
  }

  if (resAny[RESPONSE_WRAPPED]) return;
  resAny[RESPONSE_WRAPPED] = true;

  const originalJson = res.json.bind(res);
  const originalSend = res.send.bind(res);
  // Express res.json() calls res.send() internally — guard against re-entry
  let flushing = false;

  const runSanitizers = (body: unknown): unknown => {
    let current = body;
    for (const sanitize of resAny[SANITIZERS] ?? []) {
      current = sanitize(current);
    }
    return current;
  };

  const finishJson = async (body: unknown) => {
    const after = resAny[AFTER_POLICIES];
    if (after) {
      const decision = await after(body);
      if (decision.blocked) {
        // Use originalJson directly — guarded json would recurse forever
        res.statusCode = decision.statusCode ?? 403;
        flushing = true;
        try {
          return originalJson(
            decision.payload ?? {
              valid: false,
              errors: [{ field: '_policy', code: 'POLICY_VIOLATION', message: 'Policy violation' }],
            },
          );
        } finally {
          flushing = false;
        }
      }
    }
    flushing = true;
    try {
      return originalJson(runSanitizers(body));
    } finally {
      flushing = false;
    }
  };

  res.json = function guardedJson(body: unknown) {
    return finishJson(body) as unknown as Response;
  };

  res.send = function guardedSend(body: unknown) {
    if (flushing) {
      return originalSend(body as string);
    }
    if (body !== null && typeof body === 'object' && !Buffer.isBuffer(body)) {
      return finishJson(body) as unknown as Response;
    }
    if (typeof body === 'string') {
      try {
        const parsed = JSON.parse(body) as unknown;
        return finishJson(parsed) as unknown as Response;
      } catch {
        return originalSend(body);
      }
    }
    return originalSend(body as string);
  };
}

export function guardrail<TInputs extends Record<string, FieldRule>>(
  config: ExpressGuardrailOptions<TInputs> = {},
): GuardrailMiddleware {
  validateConfig(config);
  const instance = createGuardrail(config);
  const sources = config.sources ?? ['body', 'query', 'params'];
  const statusCode = config.statusCode ?? 400;
  const policyStatusCode = config.policyStatusCode ?? 403;
  const inputKeys = config.inputs ? Object.keys(config.inputs) : [];
  const failClosed = config.failClosed !== false;
  const hasPolicies = (config.policies?.length ?? 0) > 0;

  const middleware: RequestHandler = async (req, res, next) => {
    const requestId = req.guardrail?.requestId ?? createRequestId();
    req.guardrail = {
      requestId,
      instance,
      outputs: mergeOutputs(req.guardrail?.outputs, config.outputs),
      validated: req.guardrail?.validated,
    };

    try {
      const afterPolicyRunner = hasPolicies
        ? async (body: unknown) => {
            const grReq = toGuardrailRequest(req);
            const grRes: GuardrailResponse = {
              locals: res.locals as Record<string, unknown>,
              body,
              statusCode: res.statusCode,
            };
            const result = await instance.runPolicies(grReq, grRes, {
              requestId,
              phase: 'after',
            });
            if (result.blocked) {
              return {
                blocked: true,
                statusCode: policyStatusCode,
                payload: {
                  valid: false,
                  errors: result.violations.map((v) => ({
                    field: '_policy',
                    code: 'POLICY_VIOLATION',
                    message: v.message,
                    pattern: v.policy,
                  })),
                  requestId,
                  timestamp: new Date().toISOString(),
                },
              };
            }
            return { blocked: false };
          }
        : undefined;

      wrapResponse(res, instance, config.outputs?.headers, afterPolicyRunner);

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
        if (result.data && typeof result.data === 'object') {
          req.body = { ...(result.data as object) };
        }
      }

      if (hasPolicies) {
        const before = await instance.runPolicies(toGuardrailRequest(req), {
          locals: res.locals as Record<string, unknown>,
        }, { requestId, phase: 'before' });

        if (before.blocked) {
          res.status(policyStatusCode).json({
            valid: false,
            errors: before.violations.map((v) => ({
              field: '_policy',
              code: 'POLICY_VIOLATION',
              message: v.message,
              pattern: v.policy,
            })),
            requestId,
            timestamp: new Date().toISOString(),
          });
          return;
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
  wrapped.errorHandler = () => errorHandler(config.outputs);
  wrapped.healthCheck = () => healthCheckHandler(instance);
  wrapped.validateConfig = validateConfig;
  wrapped.VERSION = VERSION;
  return wrapped;
}

export function errorHandler(errConfig?: OutputsConfig): ErrorRequestHandler {
  return (err, req, res, _next) => {
    const requestId = req.guardrail?.requestId ?? createRequestId();
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
