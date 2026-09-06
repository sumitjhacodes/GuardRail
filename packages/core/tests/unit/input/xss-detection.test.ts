import { describe, expect, it } from 'vitest';
import { detectXss, rules } from '@guardrail/core';

describe('XSS detection', () => {
  const payloads = [
    '<script>alert(1)</script>',
    'javascript:alert(1)',
    '<img src=x onerror=alert(1)>',
    '<iframe src="evil.com"></iframe>',
    '<object data="evil.swf">',
    '<embed src="evil.swf">',
    'data:text/html,<script>alert(1)</script>',
    'expression(alert(1))',
    '<svg onload=alert(1)>',
    'eval("alert(1)")',
    'new Function("alert(1)")',
    'setTimeout("alert(1)", 0)',
    'setInterval("alert(1)", 0)',
  ];

  for (const payload of payloads) {
    it(`blocks: ${payload.slice(0, 40)}`, () => {
      expect(detectXss(payload).safe).toBe(false);
    });
  }

  it('allows benign HTML-ish text', () => {
    expect(detectXss('Hello <b>friend</b> — price is $5').safe).toBe(true);
    expect(detectXss('Click here for more info').safe).toBe(true);
  });

  it('context=url blocks javascript: URIs', () => {
    expect(detectXss('javascript:alert(1)', 'url').safe).toBe(false);
    expect(detectXss('https://example.com', 'url').safe).toBe(true);
  });

  it('context=css blocks expression()', () => {
    expect(detectXss('color: expression(alert(1))', 'css').safe).toBe(false);
  });

  it('xssSafe rule integrates', async () => {
    const errors = await rules.string().xssSafe().validate('<script>x</script>', 'bio');
    expect(errors[0]?.code).toBe('XSS_DETECTED');
  });
});
