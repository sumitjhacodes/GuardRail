import { describe, expect, it } from 'vitest';
import * as fc from 'fast-check';
import { detectSqlInjection, rules } from '@guardrail/core';

describe('SQL injection detection', () => {
  const payloads = [
    "' OR '1'='1",
    "1; DROP TABLE users--",
    "UNION SELECT username, password FROM users",
    "'; INSERT INTO users VALUES ('hacker')",
    "admin'--",
    "1' OR '1' = '1",
    "; shutdown",
    "BENCHMARK(1000000,SHA1('test'))",
    "SLEEP(5)",
    "WAITFOR DELAY '0:0:5'",
    "DELETE FROM accounts WHERE id=1",
  ];

  for (const payload of payloads) {
    it(`blocks: ${payload.slice(0, 40)}`, () => {
      expect(detectSqlInjection(payload).safe).toBe(false);
    });
  }

  it('allows benign search terms', () => {
    expect(detectSqlInjection('hello world').safe).toBe(true);
    expect(detectSqlInjection('product-123').safe).toBe(true);
    expect(detectSqlInjection('OBrien').safe).toBe(true);
  });

  it('detects MySQL-specific patterns when dialect=mysql', () => {
    expect(detectSqlInjection('LOAD_FILE("/etc/passwd")', 'mysql').safe).toBe(false);
  });

  it('detects Postgres-specific patterns', () => {
    expect(detectSqlInjection('SELECT pg_sleep(5)', 'postgres').safe).toBe(false);
  });

  it('detects MSSQL xp_cmdshell', () => {
    expect(detectSqlInjection('xp_cmdshell("dir")', 'mssql').safe).toBe(false);
  });

  it('sqlSafe rule blocks UNION SELECT (property)', async () => {
    await fc.assert(
      fc.asyncProperty(fc.string({ minLength: 1, maxLength: 40 }), async (suffix) => {
        const input = `UNION SELECT ${suffix}`;
        const errors = await rules.string().sqlSafe().validate(input, 'q');
        expect(errors.some((e) => e.code === 'SQL_INJECTION_DETECTED')).toBe(true);
      }),
      { numRuns: 25 },
    );
  });
});
