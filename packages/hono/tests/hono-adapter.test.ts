import { describe, expect, it } from 'vitest';
import { Hono } from 'hono';
import { guardrail, rules } from '../src/index.ts';

describe('Hono adapter', () => {
  it('blocks SQL injection', async () => {
    const app = new Hono();
    app.use(
      '*',
      guardrail({
        inputs: { q: rules.string().sqlSafe() },
      }),
    );
    app.post('/search', (c) => c.json({ ok: true }));

    const res = await app.request('http://localhost/search', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ q: 'UNION SELECT 1' }),
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.errors[0].code).toBe('SQL_INJECTION_DETECTED');
  });

  it('allows clean input and redacts output', async () => {
    const app = new Hono();
    app.use(
      '*',
      guardrail({
        inputs: { q: rules.string().maxLength(50) },
        outputs: {
          redact: ['password'],
          headers: { 'X-Content-Type-Options': 'nosniff' },
        },
      }),
    );
    app.post('/search', (c) => c.json({ ok: true, password: 'secret' }));

    const res = await app.request('http://localhost/search', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ q: 'hello' }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.password).toBe('[REDACTED]');
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
  });

  it('enforces admin policy via headers', async () => {
    const app = new Hono();
    app.use(
      '*',
      guardrail({
        policies: [
          {
            name: 'admin-only',
            when: (req) => !!req.path?.startsWith('/admin'),
            invariant: (req) => req.user?.role === 'admin',
            onViolation: 'block',
          },
        ],
      }),
    );
    app.get('/admin', (c) => c.json({ ok: true }));

    const denied = await app.request('http://localhost/admin');
    expect(denied.status).toBe(403);

    const allowed = await app.request('http://localhost/admin', {
      headers: { 'x-user-role': 'admin' },
    });
    expect(allowed.status).toBe(200);
  });

  it('strips unvalidated body fields for handlers via c.req.json()', async () => {
    const app = new Hono();
    app.use(
      '*',
      guardrail({
        inputs: { q: rules.string().maxLength(50) },
      }),
    );
    app.post('/search', async (c) => {
      const body = await c.req.json();
      return c.json({ keys: Object.keys(body as object), body });
    });

    const res = await app.request('http://localhost/search', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ q: 'hello', isAdmin: true, role: 'admin' }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.keys).toEqual(['q']);
    expect(body.body).toEqual({ q: 'hello' });
  });
});
