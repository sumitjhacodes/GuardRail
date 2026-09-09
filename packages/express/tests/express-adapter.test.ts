import { describe, expect, it } from 'vitest';
import express from 'express';
import request from 'supertest';
import { guardrail, rules } from '../src/index.ts';

function createApp() {
  const app = express();
  app.use(express.json());

  app.use(
    guardrail({
      outputs: {
        redact: ['password', 'ssn'],
        headers: {
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
        },
        errorSanitization: {
          hideStackTraces: true,
          hideServerInfo: true,
          customErrorMessages: { SQL_ERROR: 'Database operation failed' },
        },
      },
    }),
  );

  app.post(
    '/api/search',
    guardrail({
      inputs: {
        q: rules.string().sqlSafe().xssSafe().noSecrets().maxLength(100),
      },
    }),
    (req, res) => {
      res.json({
        ok: true,
        q: (req.body as { q: string }).q,
        bodyKeys: Object.keys(req.body as object),
        password: 'secret',
      });
    },
  );

  app.get('/api/me', (_req, res) => {
    res.json({ name: 'Ada', password: 'hunter2', ssn: '123-45-6789' });
  });

  app.get('/boom', (_req, _res, next) => {
    next(
      Object.assign(new Error('relation "users" does not exist'), {
        code: 'SQL_ERROR',
        statusCode: 500,
      }),
    );
  });

  // Intentionally no explicit config — must use accumulated middleware outputs
  app.use(guardrail.errorHandler());

  return app;
}

describe('Express adapter', () => {
  const app = createApp();

  it('blocks SQL injection', async () => {
    const res = await request(app)
      .post('/api/search')
      .send({ q: 'UNION SELECT password FROM users' });
    expect(res.status).toBe(400);
    expect(res.body.valid).toBe(false);
    expect(res.body.errors[0].code).toBe('SQL_INJECTION_DETECTED');
  });

  it('blocks XSS', async () => {
    const res = await request(app)
      .post('/api/search')
      .send({ q: '<script>alert(1)</script>' });
    expect(res.status).toBe(400);
    expect(res.body.errors[0].code).toBe('XSS_DETECTED');
  });

  it('allows clean input and redacts password in response', async () => {
    const res = await request(app).post('/api/search').send({ q: 'sneakers' });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.password).toBe('[REDACTED]');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('DENY');
  });

  it('strips unvalidated body fields (mass-assignment protection)', async () => {
    const res = await request(app)
      .post('/api/search')
      .send({ q: 'sneakers', isAdmin: true, role: 'admin' });
    expect(res.status).toBe(200);
    expect(res.body.bodyKeys).toEqual(['q']);
  });

  it('redacts sensitive fields on GET', async () => {
    const res = await request(app).get('/api/me');
    expect(res.status).toBe(200);
    expect(res.body.password).toBe('[REDACTED]');
    expect(res.body.ssn).toBe('[REDACTED]');
    expect(res.body.name).toBe('Ada');
  });

  it('sanitizes errors using middleware outputs.errorSanitization', async () => {
    const res = await request(app).get('/boom');
    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Database operation failed');
    expect(res.body.stack).toBeUndefined();
  });

  it('honors failClosed: false by propagating errors', async () => {
    const local = express();
    local.use(express.json());
    local.post(
      '/x',
      guardrail({
        failClosed: false,
        inputs: {
          q: {
            validate: async () => {
              throw new Error('validator crashed');
            },
            parse: async () => {
              throw new Error('validator crashed');
            },
          },
        },
      }),
      (_req, res) => {
        res.json({ ok: true });
      },
    );
    local.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      res.status(500).json({ propagated: true, message: err.message });
    });

    const res = await request(local).post('/x').send({ q: 'hi' });
    expect(res.status).toBe(500);
    expect(res.body.propagated).toBe(true);
    expect(res.body.message).toBe('validator crashed');
  });

  it('blocks non-admin via before policy', async () => {
    const local = express();
    local.use(express.json());
    local.use(
      guardrail({
        policies: [
          {
            name: 'admin-only',
            when: (req) => !!req.path?.startsWith('/api/admin'),
            invariant: (req) => req.user?.role === 'admin',
            onViolation: 'block',
          },
        ],
      }),
    );
    local.get('/api/admin', (_req, res) => res.json({ ok: true }));

    const denied = await request(local).get('/api/admin');
    expect(denied.status).toBe(403);
    expect(denied.body.errors[0].code).toBe('POLICY_VIOLATION');
  });

  it('allows admin via before policy when req.user set', async () => {
    const local = express();
    local.use(express.json());
    local.use((req, _res, next) => {
      req.user = { role: 'admin', id: '1' };
      next();
    });
    local.use(
      guardrail({
        policies: [
          {
            name: 'admin-only',
            when: (req) => !!req.path?.startsWith('/api/admin'),
            invariant: (req) => req.user?.role === 'admin',
            onViolation: 'block',
          },
        ],
      }),
    );
    local.get('/api/admin', (_req, res) => res.json({ ok: true }));

    const allowed = await request(local).get('/api/admin');
    expect(allowed.status).toBe(200);
    expect(allowed.body.ok).toBe(true);
  });

  it('honors policyStatusCode for after-phase policy blocks', async () => {
    const local = express();
    local.use(express.json());
    local.use(
      guardrail({
        policyStatusCode: 451,
        policies: [
          {
            name: 'deny-ok',
            phase: 'after',
            when: () => true,
            invariant: (_req, res) => {
              const body = res?.body as { ok?: boolean } | undefined;
              return body?.ok !== true;
            },
            onViolation: 'block',
          },
        ],
      }),
    );
    local.get('/x', (_req, res) => res.json({ ok: true }));

    const res = await request(local).get('/x');
    expect(res.status).toBe(451);
    expect(res.body.errors[0].code).toBe('POLICY_VIOLATION');
  });

  it('chains after-phase policies across stacked middleware', async () => {
    const local = express();
    local.use(express.json());
    local.use(
      guardrail({
        policies: [
          {
            name: 'outer-after',
            phase: 'after',
            when: () => true,
            invariant: (_req, res) => {
              const body = res?.body as { mark?: string } | undefined;
              return body?.mark !== 'hit-outer';
            },
            onViolation: 'block',
          },
        ],
      }),
    );
    local.use(
      guardrail({
        policies: [
          {
            name: 'inner-after',
            phase: 'after',
            when: () => true,
            invariant: (_req, res) => {
              const body = res?.body as { mark?: string } | undefined;
              return body?.mark !== 'hit-inner';
            },
            onViolation: 'block',
          },
        ],
      }),
    );
    local.get('/outer', (_req, res) => res.json({ mark: 'hit-outer' }));
    local.get('/inner', (_req, res) => res.json({ mark: 'hit-inner' }));
    local.get('/ok', (_req, res) => res.json({ mark: 'other' }));

    const outer = await request(local).get('/outer');
    expect(outer.status).toBe(403);
    expect(outer.body.errors[0].pattern).toBe('outer-after');

    const inner = await request(local).get('/inner');
    expect(inner.status).toBe(403);
    expect(inner.body.errors[0].pattern).toBe('inner-after');

    const ok = await request(local).get('/ok');
    expect(ok.status).toBe(200);
    expect(ok.body.mark).toBe('other');
  });
});
