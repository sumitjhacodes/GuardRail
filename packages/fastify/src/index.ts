import {
  createGuardrail,
  validateConfig,
  type FieldRule,
  type GuardrailConfig,
  type GuardrailRequest,
  type GuardrailResponse,
} from '@guardrail/core';
import type {
  FastifyInstance,
  FastifyPluginAsync,
  FastifyRequest,
} from 'fastify';

export type { FieldRule, GuardrailConfig, Policy } from '@guardrail/core';
export { rules, events, VERSION, runPolicies, scanCode } from '@guardrail/core';

export interface FastifyGuardrailOptions<TInputs extends Record<string, FieldRule>>
  extends GuardrailConfig<TInputs> {
  statusCode?: number;
  policyStatusCode?: number;
}

function toRequest(req: FastifyRequest): GuardrailRequest {
  return {
    method: req.method,
    path: req.url.split('?')[0],
    ip: req.ip,
    body: req.body,
    query: req.query,
    params: req.params,
    headers: req.headers as Record<string, string | string[] | undefined>,
    user: (req as FastifyRequest & { user?: GuardrailRequest['user'] }).user,
  };
}

/**
 * Fastify plugin — register with `app.register(guardrailFastify, config)`.
 */
const guardrailFastify: FastifyPluginAsync<FastifyGuardrailOptions<Record<string, FieldRule>>> =
  async (fastify: FastifyInstance, opts) => {
    validateConfig(opts);
    const instance = createGuardrail(opts);
    const statusCode = opts.statusCode ?? 400;
    const policyStatusCode = opts.policyStatusCode ?? 403;
    const inputKeys = opts.inputs ? Object.keys(opts.inputs) : [];
    const hasPolicies = (opts.policies?.length ?? 0) > 0;
    const failClosed = opts.failClosed !== false;

    fastify.addHook('preHandler', async (req, reply) => {
      try {
        if (opts.inputs && inputKeys.length > 0) {
          const body =
            req.body && typeof req.body === 'object'
              ? (req.body as Record<string, unknown>)
              : Object.create(null);
          const data: Record<string, unknown> = Object.create(null);
          for (const key of inputKeys) {
            if (key in body) data[key] = body[key];
            else if (req.query && typeof req.query === 'object' && key in (req.query as object)) {
              data[key] = (req.query as Record<string, unknown>)[key];
            } else if (
              req.params &&
              typeof req.params === 'object' &&
              key in (req.params as object)
            ) {
              data[key] = (req.params as Record<string, unknown>)[key];
            }
          }

          const result = await instance.validate(data);
          if (!result.valid) {
            return reply.status(statusCode).send({
              valid: false,
              errors: result.errors,
              requestId: result.requestId,
              timestamp: result.timestamp,
            });
          }
          if (result.data && typeof result.data === 'object') {
            req.body = { ...(result.data as object) };
          }
        }

        if (hasPolicies) {
          const before = await instance.runPolicies(toRequest(req), undefined, {
            phase: 'before',
          });
          if (before.blocked) {
            return reply.status(policyStatusCode).send({
              valid: false,
              errors: before.violations.map((v) => ({
                field: '_policy',
                code: 'POLICY_VIOLATION',
                message: v.message,
                pattern: v.policy,
              })),
              requestId: before.violations[0]?.requestId,
              timestamp: before.violations[0]?.timestamp,
            });
          }
        }
      } catch (err) {
        if (opts.debug) console.error('[guardrail/fastify]', err);
        if (!failClosed) throw err;
        return reply.status(statusCode).send({
          valid: false,
          errors: [
            { field: '_root', code: 'INTERNAL_ERROR', message: 'Security validation failed' },
          ],
        });
      }
    });

    fastify.addHook('onSend', async (req, reply, payload) => {
      let body: unknown = payload;
      if (typeof payload === 'string') {
        try {
          body = JSON.parse(payload);
        } catch {
          return payload;
        }
      }

      if (hasPolicies && body !== null && typeof body === 'object') {
        const grRes: GuardrailResponse = {
          body,
          statusCode: reply.statusCode,
        };
        const after = await instance.runPolicies(toRequest(req), grRes, { phase: 'after' });
        if (after.blocked) {
          reply.code(policyStatusCode);
          return JSON.stringify({
            valid: false,
            errors: after.violations.map((v) => ({
              field: '_policy',
              code: 'POLICY_VIOLATION',
              message: v.message,
              pattern: v.policy,
            })),
          });
        }
      }

      if (opts.outputs && body !== null && typeof body === 'object') {
        const sanitized = instance.sanitize(body);
        if (opts.outputs.headers) {
          for (const [k, v] of Object.entries(opts.outputs.headers)) {
            void reply.header(k, v);
          }
        }
        return JSON.stringify(sanitized);
      }

      return payload;
    });
  };

export default guardrailFastify;
export { guardrailFastify };

// Break Fastify encapsulation so hooks apply to routes registered on the parent
;(guardrailFastify as unknown as { [key: symbol]: boolean })[Symbol.for('skip-override')] = true;
