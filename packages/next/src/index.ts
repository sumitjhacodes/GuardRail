import {
  createGuardrail,
  validateConfig,
  type FieldRule,
  type GuardrailConfig,
  type GuardrailRequest,
  type GuardrailResponse,
} from '@guardrail/core';
import { NextResponse, type NextRequest } from 'next/server';

export type { FieldRule, GuardrailConfig, Policy } from '@guardrail/core';
export {
  rules,
  events,
  VERSION,
  runPolicies,
  scanCode,
  verifyImports,
  createMetrics,
  healthCheck,
} from '@guardrail/core';

/** Header carrying JSON-stringified validated/stripped body for Route Handlers */
export const GUARDRAIL_BODY_HEADER = 'x-guardrail-body';
export const GUARDRAIL_VALIDATED_HEADER = 'x-guardrail-validated';

export interface NextGuardrailOptions<TInputs extends Record<string, FieldRule>>
  extends GuardrailConfig<TInputs> {
  statusCode?: number;
  policyStatusCode?: number;
  /**
   * Paths to skip (e.g. static assets). Checked against pathname.
   * Default: _next, favicon, common static extensions.
   */
  ignore?: Array<string | RegExp>;
}

function defaultIgnore(pathname: string): boolean {
  if (pathname.startsWith('/_next')) return true;
  if (pathname === '/favicon.ico') return true;
  return /\.(?:css|js|map|png|jpg|jpeg|gif|svg|ico|woff2?)$/i.test(pathname);
}

function toRequest(
  req: NextRequest,
  body: unknown,
  user?: GuardrailRequest['user'],
): GuardrailRequest {
  return {
    method: req.method,
    path: req.nextUrl.pathname,
    ip: req.headers.get('x-forwarded-for') ?? undefined,
    body,
    query: Object.fromEntries(req.nextUrl.searchParams.entries()),
    params: {},
    headers: Object.fromEntries(req.headers.entries()),
    user,
  };
}

async function readJsonBody(req: NextRequest): Promise<unknown> {
  const ct = req.headers.get('content-type') ?? '';
  if (!ct.includes('application/json')) return undefined;
  try {
    return await req.json();
  } catch {
    return undefined;
  }
}

function jsonError(
  status: number,
  payload: unknown,
  headers?: Record<string, string>,
): NextResponse {
  const res = NextResponse.json(payload, { status });
  if (headers) {
    for (const [k, v] of Object.entries(headers)) res.headers.set(k, v);
  }
  return res;
}

/**
 * Read the validated/stripped body forwarded by middleware.
 * Prefer this in Route Handlers over `req.json()` so mass-assignment stripping applies.
 *
 * Next middleware cannot replace the request body stream — it forwards JSON via
 * {@link GUARDRAIL_BODY_HEADER}. Falls back to `request.json()` when the header is absent.
 */
export async function getValidatedBody(
  request: NextRequest | Request,
): Promise<unknown> {
  const header = request.headers.get(GUARDRAIL_BODY_HEADER);
  if (header != null && header !== '') {
    try {
      return JSON.parse(header) as unknown;
    } catch {
      // fall through to raw body
    }
  }
  const ct = request.headers.get('content-type') ?? '';
  if (!ct.includes('application/json')) return undefined;
  try {
    return await request.json();
  } catch {
    return undefined;
  }
}

/**
 * Next.js middleware factory — Edge-safe (no fs / DNS).
 *
 * ```ts
 * // middleware.ts
 * import { guardrail } from '@guardrail/next';
 * export const middleware = guardrail.next({
 *   inputs: { q: rules.string().sqlSafe() },
 * });
 * export const config = { matcher: '/api/:path*' };
 *
 * // app/api/search/route.ts
 * import { getValidatedBody } from '@guardrail/next';
 * export async function POST(req: NextRequest) {
 *   const body = await getValidatedBody(req); // stripped fields only
 * }
 * ```
 */
export function nextMiddleware<TInputs extends Record<string, FieldRule>>(
  config: NextGuardrailOptions<TInputs> = {},
): (req: NextRequest) => Promise<NextResponse> {
  validateConfig(config);
  const instance = createGuardrail(config);
  const statusCode = config.statusCode ?? 400;
  const policyStatusCode = config.policyStatusCode ?? 403;
  const inputKeys = config.inputs ? Object.keys(config.inputs) : [];
  const hasPolicies = (config.policies?.length ?? 0) > 0;
  const failClosed = config.failClosed !== false;

  return async (req: NextRequest) => {
    const pathname = req.nextUrl.pathname;
    if (config.ignore?.some((p) => (typeof p === 'string' ? pathname.includes(p) : p.test(pathname)))) {
      return NextResponse.next();
    }
    if (!config.ignore && defaultIgnore(pathname)) {
      return NextResponse.next();
    }

    try {
      const body = await readJsonBody(req);
      const role = req.headers.get('x-user-role') ?? undefined;
      const userId = req.headers.get('x-user-id') ?? undefined;
      const user = role || userId ? { id: userId ?? undefined, role: role ?? undefined } : undefined;

      let validatedBody = body;
      let didValidateInputs = false;

      if (config.inputs && inputKeys.length > 0) {
        const source =
          body && typeof body === 'object'
            ? (body as Record<string, unknown>)
            : (Object.create(null) as Record<string, unknown>);
        const data: Record<string, unknown> = Object.create(null);
        const query = Object.fromEntries(req.nextUrl.searchParams.entries());
        for (const key of inputKeys) {
          if (key in source) data[key] = source[key];
          else if (key in query) data[key] = query[key];
        }

        const result = await instance.validate(data);
        if (!result.valid) {
          return jsonError(
            statusCode,
            {
              valid: false,
              errors: result.errors,
              requestId: result.requestId,
              timestamp: result.timestamp,
            },
            config.outputs?.headers,
          );
        }
        if (result.data && typeof result.data === 'object') {
          validatedBody = result.data;
        }
        didValidateInputs = true;
      }

      if (hasPolicies) {
        const before = await instance.runPolicies(toRequest(req, validatedBody, user), undefined, {
          phase: 'before',
        });
        if (before.blocked) {
          return jsonError(
            policyStatusCode,
            {
              valid: false,
              errors: before.violations.map((v) => ({
                field: '_policy',
                code: 'POLICY_VIOLATION',
                message: v.message,
                pattern: v.policy,
              })),
            },
            config.outputs?.headers,
          );
        }
      }

      // Next middleware cannot replace the body stream — forward stripped JSON via header
      const requestHeaders = new Headers(req.headers);
      if (didValidateInputs && validatedBody !== undefined) {
        requestHeaders.set(GUARDRAIL_VALIDATED_HEADER, '1');
        requestHeaders.set(GUARDRAIL_BODY_HEADER, JSON.stringify(validatedBody));
      }
      if (config.outputs?.headers) {
        for (const [k, v] of Object.entries(config.outputs.headers)) {
          requestHeaders.set(`x-guardrail-header-${k}`, v);
        }
      }

      const res = NextResponse.next({ request: { headers: requestHeaders } });
      if (config.outputs?.headers) {
        for (const [k, v] of Object.entries(config.outputs.headers)) {
          res.headers.set(k, v);
        }
      }
      return res;
    } catch (err) {
      if (config.debug) console.error('[guardrail/next]', err);
      if (!failClosed) throw err;
      return jsonError(statusCode, {
        valid: false,
        errors: [
          { field: '_root', code: 'INTERNAL_ERROR', message: 'Security validation failed' },
        ],
      });
    }
  };
}

/** Namespace-style API matching the Phase 3 sketch: `guardrail.next({...})` */
export const guardrail = Object.assign(
  function guardrailFn<TInputs extends Record<string, FieldRule>>(
    config: NextGuardrailOptions<TInputs> = {},
  ) {
    return nextMiddleware(config);
  },
  { next: nextMiddleware },
);

export default guardrail;

/** Helper for Route Handlers: apply output sanitization to a JSON body. */
export function sanitizeResponse(
  config: GuardrailConfig,
  body: unknown,
): unknown {
  return createGuardrail(config).sanitize(body);
}

/** Run after-phase policies against a response body (for Route Handlers). */
export async function enforceAfterPolicies(
  config: GuardrailConfig,
  req: NextRequest,
  body: unknown,
  statusCode = 200,
): Promise<{ blocked: boolean; body: unknown; status: number }> {
  const instance = createGuardrail(config);
  const policyStatus =
    'policyStatusCode' in config
      ? Number((config as NextGuardrailOptions<Record<string, FieldRule>>).policyStatusCode ?? 403)
      : 403;
  const grReq = toRequest(req, undefined);
  const grRes: GuardrailResponse = { body, statusCode };
  const after = await instance.runPolicies(grReq, grRes, { phase: 'after' });
  if (after.blocked) {
    return {
      blocked: true,
      status: policyStatus,
      body: {
        valid: false,
        errors: after.violations.map((v) => ({
          field: '_policy',
          code: 'POLICY_VIOLATION',
          message: v.message,
          pattern: v.policy,
        })),
      },
    };
  }
  return { blocked: false, body: instance.sanitize(body), status: statusCode };
}
