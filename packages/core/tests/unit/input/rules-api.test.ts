import { describe, expect, it } from 'vitest';
import { guardrail, rules, validateConfig, GuardrailConfigError } from '@guardrail/core';

describe('rules API', () => {
  it('validates string length', async () => {
    const rule = rules.string().minLength(2).maxLength(5);
    expect((await rule.validate('a', 's')).length).toBeGreaterThan(0);
    expect((await rule.validate('abc', 's')).length).toBe(0);
    expect((await rule.validate('abcdef', 's')).length).toBeGreaterThan(0);
  });

  it('validates uuid', async () => {
    const rule = rules.uuid();
    expect((await rule.validate('not-a-uuid', 'id')).length).toBeGreaterThan(0);
    expect(
      (await rule.validate('550e8400-e29b-41d4-a716-446655440000', 'id')).length,
    ).toBe(0);
  });

  it('validates email format', async () => {
    const rule = rules.email();
    expect((await rule.validate('bad', 'email')).length).toBeGreaterThan(0);
    expect((await rule.validate('a@b.com', 'email')).length).toBe(0);
  });

  it('validates number range', async () => {
    const rule = rules.number().min(0).max(150);
    expect((await rule.validate(-1, 'age')).length).toBeGreaterThan(0);
    expect((await rule.validate(30, 'age')).length).toBe(0);
    expect((await rule.validate(200, 'age')).length).toBeGreaterThan(0);
  });

  it('validates nested objects', async () => {
    const rule = rules.object({
      street: rules.string().maxLength(200),
      zip: rules.string().matches(/^\d{5}(-\d{4})?$/),
      country: rules.string().oneOf(['US', 'CA', 'UK', 'DE']),
    });
    const ok = await rule.validate(
      { street: 'Main', zip: '12345', country: 'US' },
      'address',
    );
    expect(ok.length).toBe(0);

    const bad = await rule.validate(
      { street: 'Main', zip: 'abc', country: 'XX' },
      'address',
    );
    expect(bad.length).toBeGreaterThan(0);
  });

  it('strips unknown nested object properties', async () => {
    const gr = guardrail({
      inputs: {
        address: rules.object({
          street: rules.string().maxLength(200),
          country: rules.string().oneOf(['US', 'CA']),
        }),
      },
    });

    const result = await gr.validate({
      address: {
        street: 'Main',
        country: 'US',
        isAdmin: true,
        role: 'admin',
      },
    });

    expect(result.valid).toBe(true);
    expect(result.data?.address).toEqual({ street: 'Main', country: 'US' });
    expect(
      (result.data?.address as Record<string, unknown>).isAdmin,
    ).toBeUndefined();
  });

  it('validates arrays with maxItems', async () => {
    const rule = rules.array(rules.string().maxLength(50)).maxItems(2);
    expect((await rule.validate(['a', 'b'], 'tags')).length).toBe(0);
    expect((await rule.validate(['a', 'b', 'c'], 'tags')).length).toBeGreaterThan(0);
  });

  it('validates files', async () => {
    const rule = rules
      .file()
      .maxSize(1024)
      .mimeTypes(['image/png'])
      .noExecutable();

    expect(
      (
        await rule.validate(
          { filename: 'a.png', mimetype: 'image/png', size: 100 },
          'avatar',
        )
      ).length,
    ).toBe(0);

    expect(
      (
        await rule.validate(
          { filename: 'evil.exe', mimetype: 'application/octet-stream', size: 100 },
          'avatar',
        )
      ).some((e) => e.code === 'EXECUTABLE_FILE'),
    ).toBe(true);
  });

  it('strongPassword enforces complexity', async () => {
    const rule = rules.string().strongPassword();
    expect((await rule.validate('weak', 'pw')).length).toBeGreaterThan(0);
    expect((await rule.validate('Str0ng!Pass', 'pw')).length).toBe(0);
  });

  it('guardrail validate end-to-end', async () => {
    const gr = guardrail({
      inputs: {
        search: rules.string().sqlSafe().xssSafe().maxLength(100),
        age: rules.number().min(0).max(150),
      },
    });

    const bad = await gr.validate({ search: 'UNION SELECT * FROM users', age: 20 });
    expect(bad.valid).toBe(false);
    expect(bad.errors[0]?.code).toBe('SQL_INJECTION_DETECTED');

    const good = await gr.validate({ search: 'sneakers', age: 20 });
    expect(good.valid).toBe(true);
    expect(good.data?.search).toBe('sneakers');
  });

  it('validateConfig throws on bad config', () => {
    expect(() => validateConfig(null as never)).toThrow(GuardrailConfigError);
    expect(() =>
      validateConfig({ inputs: { x: 'nope' as never } }),
    ).toThrow(GuardrailConfigError);
    expect(() =>
      validateConfig({
        inputs: { email: rules.email() },
      }),
    ).not.toThrow();
  });
});
