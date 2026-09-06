import { describe, expect, it } from 'vitest';
import { detectSecrets, rules } from '@guardrail/core';

describe('Secret detection', () => {
  it('detects OpenAI-style keys', () => {
    expect(detectSecrets('sk-abcdefghijklmnopqrstuvwxyz123456').safe).toBe(false);
  });

  it('detects GitHub tokens', () => {
    expect(detectSecrets('ghp_abcdefghijklmnopqrstuvwxyz1234567890').safe).toBe(false);
  });

  it('detects AWS access keys', () => {
    expect(detectSecrets('AKIAIOSFODNN7EXAMPLE').safe).toBe(false);
  });

  it('detects private keys', () => {
    expect(detectSecrets('-----BEGIN RSA PRIVATE KEY-----\nMIIE').safe).toBe(false);
  });

  it('detects JWTs', () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0vVK';
    expect(detectSecrets(jwt).safe).toBe(false);
  });

  it('detects labeled api keys', () => {
    expect(detectSecrets('api_key=abcdefghijklmnopqrstuvwxyz123456').safe).toBe(false);
  });

  it('allows normal text', () => {
    expect(detectSecrets('please reset my password tomorrow').safe).toBe(true);
  });

  it('noSecrets rule never includes raw secret in error value', async () => {
    const secret = 'sk-abcdefghijklmnopqrstuvwxyz123456789012';
    const errors = await rules.string().noSecrets().validate(secret, 'note');
    expect(errors[0]?.code).toBe('SECRET_DETECTED');
    expect(errors[0]?.value).toBeUndefined();
  });
});
