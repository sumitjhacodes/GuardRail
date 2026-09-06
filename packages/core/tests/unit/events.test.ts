import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { events, guardrail, healthCheck, rules } from '@guardrail/core';

describe('events and health', () => {
  beforeEach(() => {
    events.removeAllListeners();
  });

  afterEach(() => {
    events.removeAllListeners();
  });

  it('emits violation and block on bad input', async () => {
    const seen: string[] = [];
    events.on('violation', () => seen.push('violation'));
    events.on('block', () => seen.push('block'));

    const gr = guardrail({
      inputs: { q: rules.string().sqlSafe() },
    });
    await gr.validate({ q: 'UNION SELECT 1' });
    expect(seen).toContain('violation');
    expect(seen).toContain('block');
  });

  it('emits allow on good input', async () => {
    let allowed = false;
    events.on('allow', () => {
      allowed = true;
    });
    const gr = guardrail({ inputs: { q: rules.string().maxLength(10) } });
    await gr.validate({ q: 'ok' });
    expect(allowed).toBe(true);
  });

  it('healthCheck returns healthy status', () => {
    const result = healthCheck();
    expect(result.status).toBe('healthy');
    expect(result.version).toBeTruthy();
    expect(result.rulesLoaded).toBeGreaterThan(0);
  });

  it('sanitizes output via instance', () => {
    const gr = guardrail({
      outputs: { redact: ['password'] },
    });
    const out = gr.sanitize({ user: 'a', password: 'secret' }) as {
      password: string;
    };
    expect(out.password).toBe('[REDACTED]');
  });
});
