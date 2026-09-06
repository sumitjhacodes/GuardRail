export const SECRET_PATTERNS: ReadonlyArray<{ name: string; pattern: RegExp }> = [
  { name: 'openai-key', pattern: /sk-[a-zA-Z0-9]{20,}/ },
  { name: 'github-token', pattern: /ghp_[a-zA-Z0-9]{36}/ },
  { name: 'aws-access-key', pattern: /AKIA[0-9A-Z]{16}/ },
  {
    name: 'private-key',
    pattern: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
  },
  {
    name: 'jwt',
    pattern: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/,
  },
  // Generic long hex/base64 tokens — lower priority, applied last
  { name: 'generic-api-key', pattern: /(?:api[_-]?key|apikey|secret|token)\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{32,}/i },
];

export interface SecretScanResult {
  safe: boolean;
  pattern?: string;
}

export function detectSecrets(input: string): SecretScanResult {
  for (const { name, pattern } of SECRET_PATTERNS) {
    if (pattern.test(input)) {
      return { safe: false, pattern: name };
    }
  }
  return { safe: true };
}
