const PATH_TRAVERSAL_PATTERNS: ReadonlyArray<{ name: string; pattern: RegExp }> = [
  { name: 'dot-dot-slash', pattern: /\.\.(\/|\\)/ },
  { name: 'encoded-dot-dot', pattern: /(\%2e\%2e|\%2E\%2E)(\%2f|\%2F|\%5c|\%5C|\/|\\)/i },
  { name: 'unicode-dot-dot', pattern: /\u002e\u002e[\/\\]/ },
  { name: 'absolute-unix', pattern: /^\/(?!\/)/ },
  { name: 'absolute-windows', pattern: /^[a-zA-Z]:[\\/]/ },
  { name: 'unc-path', pattern: /^\\\\[^\\]/ },
  { name: 'null-byte', pattern: /%00|\0/ },
];

export interface PathTraversalScanResult {
  safe: boolean;
  pattern?: string;
}

export function detectPathTraversal(input: string): PathTraversalScanResult {
  for (const { name, pattern } of PATH_TRAVERSAL_PATTERNS) {
    if (pattern.test(input)) {
      return { safe: false, pattern: name };
    }
  }
  return { safe: true };
}
