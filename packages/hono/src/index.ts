import {
  createGuardrail,
  validateConfig,
  type FieldRule,
  type GuardrailConfig,
  type GuardrailRequest,
  type GuardrailResponse,
} from '@guardrail/core';
import type { Context, MiddlewareHandler, Next } from 'hono';

export type { FieldRule, GuardrailConfig, Policy } from '@guardrail/core';
export { rules, events, VERSION, runPolicies, scanCode } from '@guardrail/core';

export interface HonoGuardrailOptions<TInputs extends Record<string, FieldRule>>
  extends GuardrailConfig<TInputs> {
  statusCode?: number;
  policyStatusCode?: number;
}

function toRequest(
  c: Context,
  body: unknown,
  user?: GuardrailRequest['user'],
): GuardrailRequest {
  const url = new URL(c.req.url);
  return {
    method: c.req.method,
    path: url.pathname,
    ip: c.req.header('x-forwarded-for') ?? undefined,
    body,
    query: Object.fromEntries(url.searchParams.entries()),
    params: c.req.param(),
    headers: Object.fromEntries([...c.req.raw.headers.entries()]),
    user,
  };
}

/**
 * Hono middleware — `app.use('*', guardrail({ ... }))`.
 */
export function guardrail<TInputs extends Record<string, FieldRule>>(
  config: HonoGuardrailOptions<TInputs> = {},
): MiddlewareHandler {
  validateConfig(config);
  const instance = createGuardrail(config);
  const statusCode = config.statusCode ?? 400;
  const policyStatusCode = config.policyStatusCode ?? 403;
  const inputKeys = config.inputs ? Object.keys(config.inputs) : [];
  const hasPolicies = (config.policies?.length ?? 0) > 0;
  const failClosed = config.failClosed !== false;

  return async (c: Context, next: Next) => {
    try {
      let body: unknown;
      const contentType = c.req.header('content-type') ?? '';
      if (contentType.includes('application/json')) {
        try {
          body = await c.req.json();
        } catch {
          body = undefined;
        }
      }

      // Optional user attached by upstream middleware via header for tests
      const role = c.req.header('x-user-role') ?? undefined;
      const userId = c.req.header('x-user-id') ?? undefined;
      const user =
        role || userId ? { id: userId, role } : undefined;

      if (config.inputs && inputKeys.length > 0) {
        const source =
          body && typeof body === 'object'
            ? (body as Record<string, unknown>)
            : (Object.create(null) as Record<string, unknown>);
        const data: Record<string, unknown> = Object.create(null);
        const query = Object.fromEntries(new URL(c.req.url).searchParams.entries());
        const params = c.req.param();
        for (const key of inputKeys) {
          if (key in source) data[key] = source[key];
          else if (key in query) data[key] = query[key];
          else if (key in params) data[key] = params[key];
        }

        const result = await instance.validate(data);
        if (!result.valid) {
          return c.json(
            {
              valid: false,
              errors: result.errors,
              requestId: result.requestId,
              timestamp: result.timestamp,
            },
            statusCode as 400,
          );
        }
        if (result.data && typeof result.data === 'object') {
          body = result.data;
          // Hono caches the first c.req.json() — replace so handlers see stripped body
          const validated = result.data;
          c.req.json = (async () => validated) as typeof c.req.json;
          c.set('validated', validated);
        }
      }

      if (hasPolicies) {
        const before = await instance.runPolicies(toRequest(c, body, user), undefined, {
          phase: 'before',
        });
        if (before.blocked) {
          return c.json(
            {
              valid: false,
              errors: before.violations.map((v) => ({
                field: '_policy',
                code: 'POLICY_VIOLATION',
                message: v.message,
                pattern: v.policy,
              })),
              requestId: before.violations[0]?.requestId,
              timestamp: before.violations[0]?.timestamp,
            },
            policyStatusCode as 403,
          );
        }
      }

      await next();

      const extraHeaders = config.outputs?.headers;
      if (!config.outputs && !hasPolicies) {
        if (extraHeaders) {
          for (const [k, v] of Object.entries(extraHeaders)) c.header(k, v);
        }
        return;
      }

      const prev = c.res;
      if (!prev) return;
      const ct = prev.headers.get('content-type') ?? '';
      if (!ct.includes('application/json')) {
        if (extraHeaders) {
          for (const [k, v] of Object.entries(extraHeaders)) c.header(k, v);
        }
        return;
      }

      let json: unknown;
      try {
        json = JSON.parse(await prev.text());
      } catch {
        return;
      }

      const status = prev.status;
      const grRes: GuardrailResponse = { body: json, statusCode: status };

      if (hasPolicies) {
        const after = await instance.runPolicies(toRequest(c, body, user), grRes, {
          phase: 'after',
        });
        if (after.blocked) {
          c.res = new Response(
            JSON.stringify({
              valid: false,
              errors: after.violations.map((v) => ({
                field: '_policy',
                code: 'POLICY_VIOLATION',
                message: v.message,
                pattern: v.policy,
              })),
            }),
            {
              status: policyStatusCode,
              headers: { 'content-type': 'application/json' },
            },
          );
          return;
        }
      }

      const payload = config.outputs ? instance.sanitize(json) : json;
      const outHeaders = new Headers(prev.headers);
      outHeaders.set('content-type', 'application/json');
      if (extraHeaders) {
        for (const [k, v] of Object.entries(extraHeaders)) {
          outHeaders.set(k, v);
        }
      }
      c.res = new Response(JSON.stringify(payload), { status, headers: outHeaders });
    } catch (err) {
      if (config.debug) console.error('[guardrail/hono]', err);
      if (!failClosed) throw err;
      return c.json(
        {
          valid: false,
          errors: [
            { field: '_root', code: 'INTERNAL_ERROR', message: 'Security validation failed' },
          ],
        },
        statusCode as 400,
      );
    }
  };
}

export default guardrail;
