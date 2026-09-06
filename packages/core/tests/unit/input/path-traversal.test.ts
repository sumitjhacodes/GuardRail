import { describe, expect, it } from 'vitest';
import { detectPathTraversal, rules } from '@guardrail/core';

describe('Path traversal detection', () => {
  const payloads = [
    '../etc/passwd',
    '..\\windows\\system32',
    '%2e%2e%2fetc/passwd',
    '/etc/passwd',
    'C:\\Windows\\System32',
    '\\\\server\\share',
    'file%00.jpg',
  ];

  for (const payload of payloads) {
    it(`blocks: ${payload}`, () => {
      expect(detectPathTraversal(payload).safe).toBe(false);
    });
  }

  it('allows relative safe paths', () => {
    expect(detectPathTraversal('images/avatar.png').safe).toBe(true);
    expect(detectPathTraversal('docs/readme.md').safe).toBe(true);
  });

  it('noPathTraversal rule integrates', async () => {
    const errors = await rules.string().noPathTraversal().validate('../secret', 'path');
    expect(errors[0]?.code).toBe('PATH_TRAVERSAL_DETECTED');
  });
});
