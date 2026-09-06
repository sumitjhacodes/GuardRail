import { describe, expect, it } from 'vitest';
import { deepRedact, redactByKeys, sanitizeOutput } from '@guardrail/core';

describe('deep redact', () => {
  it('redacts by key name recursively', () => {
    const input = {
      user: { name: 'Ada', password: 'secret', nested: { token: 'abc' } },
      ssn: '123-45-6789',
    };
    const result = redactByKeys(input, ['password', 'ssn', 'token']) as {
      user: { password: string; nested: { token: string } };
      ssn: string;
    };
    expect(result.user.password).toBe('[REDACTED]');
    expect(result.ssn).toBe('[REDACTED]');
    expect(result.user.nested.token).toBe('[REDACTED]');
    expect(result.user.name).toBe('Ada');
  });

  it('redacts by path with wildcards', () => {
    const input = {
      user: {
        paymentMethods: [{ number: '4111' }, { number: '5500' }],
      },
    };
    const result = deepRedact(input, ['user.paymentMethods.*.number']) as {
      user: { paymentMethods: Array<{ number: string }> };
    };
    expect(result.user.paymentMethods[0]?.number).toBe('[REDACTED]');
    expect(result.user.paymentMethods[1]?.number).toBe('[REDACTED]');
  });

  it('handles circular references', () => {
    const input: Record<string, unknown> = { password: 'x' };
    input.self = input;
    const result = redactByKeys(input, ['password']) as Record<string, unknown>;
    expect(result.password).toBe('[REDACTED]');
    expect(result.self).toBe('[Circular]');
  });

  it('sanitizeOutput combines keys and paths', () => {
    const result = sanitizeOutput(
      { password: 'x', config: { database: { password: 'db' } } },
      {
        redact: ['password'],
        redactPaths: ['config.database.password'],
      },
    ) as { password: string; config: { database: { password: string } } };
    expect(result.password).toBe('[REDACTED]');
    expect(result.config.database.password).toBe('[REDACTED]');
  });
});
