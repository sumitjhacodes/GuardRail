import { describe, expect, it } from 'vitest';
import { NextRequest } from 'next/server';
import {
  guardrail,
  rules,
  getValidatedBody,
  GUARDRAIL_BODY_HEADER,
  GUARDRAIL_VALIDATED_HEADER,
} from '../src/index.ts';

function req(url: string, init?: RequestInit): NextRequest {
  return new NextRequest(new URL(url, 'http://localhost'), init);
}

describe('Next adapter', () => {
  it('blocks SQL injection on JSON body', async () => {
    const mw = guardrail.next({
      inputs: { q: rules.string().sqlSafe() },
    });
    const res = await mw(
      req('http://localhost/api/search', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ q: 'UNION SELECT 1' }),
      }),
    );
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.errors[0].code).toBe('SQL_INJECTION_DETECTED');
  });

  it('allows clean input and sets security headers', async () => {
    const mw = guardrail.next({
      inputs: { q: rules.string().maxLength(50) },
      outputs: { headers: { 'X-Content-Type-Options': 'nosniff' } },
    });
    const res = await mw(
      req('http://localhost/api/search', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ q: 'hello' }),
      }),
    );
    expect(res.status).toBe(200);
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
  });

  it('forwards stripped body for Route Handlers via header', async () => {
    const mw = guardrail.next({
      inputs: { q: rules.string().maxLength(50) },
    });
    const res = await mw(
      req('http://localhost/api/search', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ q: 'hello', isAdmin: true, role: 'admin' }),
      }),
    );
    expect(res.status).toBe(200);

    // Next prefixes overridden request headers on the middleware response
    const forwarded =
      res.headers.get(`x-middleware-request-${GUARDRAIL_BODY_HEADER}`) ??
      res.headers.get(GUARDRAIL_BODY_HEADER);
    expect(forwarded).toBeTruthy();
    expect(JSON.parse(forwarded!)).toEqual({ q: 'hello' });

    const flagged =
      res.headers.get(`x-middleware-request-${GUARDRAIL_VALIDATED_HEADER}`) ??
      res.headers.get(GUARDRAIL_VALIDATED_HEADER);
    expect(flagged).toBe('1');
  });

  it('getValidatedBody prefers the forwarded stripped payload', async () => {
    const request = req('http://localhost/api/search', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        [GUARDRAIL_BODY_HEADER]: JSON.stringify({ q: 'safe' }),
        [GUARDRAIL_VALIDATED_HEADER]: '1',
      },
      body: JSON.stringify({ q: 'safe', isAdmin: true }),
    });
    const body = await getValidatedBody(request);
    expect(body).toEqual({ q: 'safe' });
  });

  it('enforces admin policy via headers', async () => {
    const mw = guardrail.next({
      policies: [
        {
          name: 'admin-only',
          when: (r) => !!r.path?.startsWith('/api/admin'),
          invariant: (r) => r.user?.role === 'admin',
          onViolation: 'block',
        },
      ],
    });

    const denied = await mw(req('http://localhost/api/admin'));
    expect(denied.status).toBe(403);

    const allowed = await mw(
      req('http://localhost/api/admin', {
        headers: { 'x-user-role': 'admin' },
      }),
    );
    expect(allowed.status).toBe(200);
  });

  it('skips static assets by default', async () => {
    const mw = guardrail.next({
      inputs: { q: rules.string().sqlSafe() },
    });
    const res = await mw(req('http://localhost/favicon.ico'));
    expect(res.status).toBe(200);
  });
});
