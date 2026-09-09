import { describe, expect, it } from 'vitest';
import Fastify from 'fastify';
import guardrailFastify, { rules } from '../src/index.ts';

describe('Fastify adapter', () => {
  it('blocks SQL injection', async () => {
    const app = Fastify();
    await app.register(guardrailFastify, {
      inputs: { q: rules.string().sqlSafe() },
    });
    app.post('/search', async () => ({ ok: true }));

    const res = await app.inject({
      method: 'POST',
      url: '/search',
      payload: { q: 'UNION SELECT 1' },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().errors[0].code).toBe('SQL_INJECTION_DETECTED');
    await app.close();
  });

  it('allows clean input and redacts output', async () => {
    const app = Fastify();
    await app.register(guardrailFastify, {
      inputs: { q: rules.string().maxLength(50) },
      outputs: { redact: ['password'] },
    });
    app.post('/search', async () => ({ ok: true, password: 'secret' }));

    const res = await app.inject({
      method: 'POST',
      url: '/search',
      payload: { q: 'hello' },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().password).toBe('[REDACTED]');
    await app.close();
  });

  it('enforces before policies', async () => {
    const app = Fastify();
    await app.register(guardrailFastify, {
      policies: [
        {
          name: 'admin-only',
          when: (req) => !!req.path?.startsWith('/admin'),
          invariant: (req) => req.user?.role === 'admin',
          onViolation: 'block',
        },
      ],
    });
    app.get('/admin', async () => ({ ok: true }));

    const res = await app.inject({ method: 'GET', url: '/admin' });
    expect(res.statusCode).toBe(403);
    await app.close();
  });
});
