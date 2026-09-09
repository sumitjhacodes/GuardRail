import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { events, runPolicies, type Policy } from '@guardrail/core';

describe('policy engine', () => {
  beforeEach(() => events.removeAllListeners());
  afterEach(() => events.removeAllListeners());

  it('allows when invariant passes', async () => {
    const policies: Policy[] = [
      {
        name: 'admin-only',
        when: (req) => !!req.path?.startsWith('/api/admin'),
        invariant: (req) => req.user?.role === 'admin',
        onViolation: 'block',
      },
    ];
    const result = await runPolicies(policies, {
      path: '/api/admin/users',
      user: { role: 'admin' },
    });
    expect(result.allowed).toBe(true);
    expect(result.blocked).toBe(false);
  });

  it('blocks and short-circuits on first violation', async () => {
    const order: string[] = [];
    const policies: Policy[] = [
      {
        name: 'first',
        priority: 1,
        when: () => true,
        invariant: () => {
          order.push('first');
          return false;
        },
        onViolation: 'block',
      },
      {
        name: 'second',
        priority: 2,
        when: () => true,
        invariant: () => {
          order.push('second');
          return false;
        },
        onViolation: 'block',
      },
    ];
    const result = await runPolicies(policies, { path: '/' });
    expect(result.blocked).toBe(true);
    expect(result.violations[0]?.policy).toBe('first');
    expect(order).toEqual(['first']);
  });

  it('respects priority order', async () => {
    const order: string[] = [];
    await runPolicies(
      [
        {
          name: 'late',
          priority: 50,
          when: () => true,
          invariant: () => {
            order.push('late');
            return true;
          },
          onViolation: 'block',
        },
        {
          name: 'early',
          priority: 1,
          when: () => true,
          invariant: () => {
            order.push('early');
            return true;
          },
          onViolation: 'block',
        },
      ],
      { path: '/' },
    );
    expect(order).toEqual(['early', 'late']);
  });

  it('log mode emits alert but does not block', async () => {
    const alerts: string[] = [];
    events.on('alert', (e) => alerts.push(e.type));
    const result = await runPolicies(
      [
        {
          name: 'soft',
          when: () => true,
          invariant: () => false,
          onViolation: 'log',
        },
      ],
      { path: '/' },
    );
    expect(result.blocked).toBe(false);
    expect(result.violations).toHaveLength(1);
    expect(alerts.length).toBeGreaterThan(0);
  });

  it('filters by phase', async () => {
    const result = await runPolicies(
      [
        {
          name: 'after-only',
          phase: 'after',
          when: () => true,
          invariant: () => false,
          onViolation: 'block',
        },
      ],
      { path: '/' },
      undefined,
      { phase: 'before' },
    );
    expect(result.blocked).toBe(false);
  });

  it('supports async when/invariant', async () => {
    const result = await runPolicies(
      [
        {
          name: 'async',
          when: async () => true,
          invariant: async () => false,
          onViolation: 'block',
        },
      ],
      { path: '/' },
    );
    expect(result.blocked).toBe(true);
  });
});
