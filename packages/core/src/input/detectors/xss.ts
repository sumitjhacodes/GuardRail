import type { XssContext } from '../../types.js';

export const XSS_HTML_PATTERNS: ReadonlyArray<{ name: string; pattern: RegExp }> = [
  { name: 'script-tag', pattern: /<script[^>]*>[\s\S]*?<\/script>/i },
  { name: 'javascript-uri', pattern: /javascript:/i },
  { name: 'event-handler', pattern: /on\w+\s*=/i },
  { name: 'iframe', pattern: /<iframe/i },
  { name: 'object', pattern: /<object/i },
  { name: 'embed', pattern: /<embed/i },
  { name: 'data-html', pattern: /data:text\/html/i },
  { name: 'expression', pattern: /expression\s*\(/i },
  { name: 'css-js-url', pattern: /url\s*\(\s*['"]*\s*javascript:/i },
  { name: 'svg-handler', pattern: /<svg[^>]*on\w+\s*=/i },
  { name: 'eval', pattern: /eval\s*\(/i },
  { name: 'new-function', pattern: /new\s+Function\s*\(/i },
  { name: 'settimeout-string', pattern: /setTimeout\s*\(\s*['"]/i },
  { name: 'setinterval-string', pattern: /setInterval\s*\(\s*['"]/i },
];

export const XSS_CONTEXT_PATTERNS: Record<
  XssContext,
  ReadonlyArray<{ name: string; pattern: RegExp }>
> = {
  html: XSS_HTML_PATTERNS,
  attribute: [
    { name: 'attr-break', pattern: /["']\s*[><]/ },
    { name: 'attr-javascript', pattern: /javascript:/i },
    { name: 'attr-event', pattern: /on\w+\s*=/i },
    { name: 'attr-data-html', pattern: /data:text\/html/i },
  ],
  js: [
    { name: 'js-eval', pattern: /eval\s*\(/i },
    { name: 'js-function', pattern: /new\s+Function\s*\(/i },
    { name: 'js-script-break', pattern: /<\/script/i },
    { name: 'js-settimeout', pattern: /setTimeout\s*\(\s*['"]/i },
  ],
  css: [
    { name: 'css-expression', pattern: /expression\s*\(/i },
    { name: 'css-js-url', pattern: /url\s*\(\s*['"]*\s*javascript:/i },
    { name: 'css-import', pattern: /@import/i },
    { name: 'css-behavior', pattern: /behavior\s*:/i },
  ],
  url: [
    { name: 'url-javascript', pattern: /^\s*javascript:/i },
    { name: 'url-data-html', pattern: /^\s*data:text\/html/i },
    { name: 'url-vbscript', pattern: /^\s*vbscript:/i },
  ],
};

const contextCache = new Map<string, ReadonlyArray<{ name: string; pattern: RegExp }>>();

export function getXssPatterns(
  context: XssContext = 'html',
): ReadonlyArray<{ name: string; pattern: RegExp }> {
  const cached = contextCache.get(context);
  if (cached) return cached;
  const patterns = XSS_CONTEXT_PATTERNS[context];
  contextCache.set(context, patterns);
  return patterns;
}

export interface XssScanResult {
  safe: boolean;
  pattern?: string;
  matched?: string;
}

export function detectXss(input: string, context: XssContext = 'html'): XssScanResult {
  for (const { name, pattern } of getXssPatterns(context)) {
    const match = input.match(pattern);
    if (match) {
      return { safe: false, pattern: name, matched: match[0]?.slice(0, 64) };
    }
  }
  return { safe: true };
}
