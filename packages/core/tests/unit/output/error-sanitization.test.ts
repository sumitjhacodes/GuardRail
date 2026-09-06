import { describe, expect, it } from 'vitest';
import { sanitizeError } from '@guardrail/core';

describe('error sanitization', () => {
  it('hides stack traces when configured', () => {
    const err = new Error('boom');
    const result = sanitizeError(err, { hideStackTraces: true });
    expect(result.stack).toBeUndefined();
    expect(result.message).toBe('boom');
  });

  it('scrubs file paths and internal hosts', () => {
    const err = new Error('Failed reading /Users/ada/project/secret.env on 127.0.0.1');
    const result = sanitizeError(err, { hideServerInfo: true, hideStackTraces: true });
    expect(result.message).not.toContain('/Users/ada');
    expect(result.message).not.toContain('127.0.0.1');
  });

  it('maps SQL errors to safe messages', () => {
    const err = new Error('relation "users" does not exist — postgres');
    const result = sanitizeError(err, {
      hideServerInfo: true,
      customErrorMessages: { SQL_ERROR: 'Database operation failed' },
    });
    expect(result.message).toBe('Database operation failed');
  });

  it('uses custom error messages by code', () => {
    const err = Object.assign(new Error('raw'), { code: 'AUTH_ERROR' });
    const result = sanitizeError(err, {
      customErrorMessages: { AUTH_ERROR: 'Authentication failed' },
    });
    expect(result.message).toBe('Authentication failed');
  });
});
