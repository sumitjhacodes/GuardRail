export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface AiPattern {
  id: string;
  severity: Severity;
  description: string;
  fix: string;
  detect: (code: string) => boolean;
  /** Optional regex used to locate line/column in file scans */
  locate?: RegExp;
}

export const AI_VULNERABILITY_PATTERNS: Record<string, AiPattern> = {
  'concatenated-sql': {
    id: 'concatenated-sql',
    severity: 'critical',
    description: 'SQL query built via string concatenation or template interpolation',
    fix: 'Use parameterized queries or an ORM',
    detect: (code) =>
      /query\s*\(\s*[`"'].*\$\{[\s\S]*\}.*[`"']\s*\)/.test(code) ||
      /query\s*\(\s*[^)]*\+/.test(code) ||
      /execute\s*\(\s*[`"'].*\+/.test(code) ||
      /\.(?:query|execute)\s*\(\s*`[^`]*\$\{/.test(code),
    locate: /query\s*\(|execute\s*\(|\$\{/,
  },

  'unsafe-regex': {
    id: 'unsafe-regex',
    severity: 'high',
    description: 'Regex pattern may allow catastrophic backtracking (ReDoS)',
    fix: 'Use a regex testing tool and limit input length',
    detect: (code) =>
      /\([^)]*\+[^)]*\)\*/.test(code) ||
      /\(\[[^\]]+\]\+\)\+/.test(code) ||
      /new\s+RegExp\s*\([^)]*\+[^)]*\+/.test(code),
    locate: /new\s+RegExp|\(.*\+.*\)\*/,
  },

  'timing-attack': {
    id: 'timing-attack',
    severity: 'high',
    description: 'Secret compared with === which is not timing-safe',
    fix: 'Use crypto.timingSafeEqual() for secret comparison',
    detect: (code) =>
      /(?:password|token|apiKey|secret|api_key)\s*===?\s*/i.test(code) ||
      /===\s*(?:password|token|apiKey|secret)/i.test(code),
    locate: /(?:password|token|apiKey|secret)\s*===?/i,
  },

  'hardcoded-secrets': {
    id: 'hardcoded-secrets',
    severity: 'critical',
    description: 'Hardcoded secret, token, or password in source',
    fix: 'Use environment variables or a secrets manager',
    detect: (code) =>
      /const\s+\w*(?:key|token|secret|password)\w*\s*=\s*['"][^'"]{8,}['"]/i.test(
        code,
      ),
    locate: /const\s+\w*(?:key|token|secret|password)\w*\s*=/i,
  },

  'unsafe-deserialization': {
    id: 'unsafe-deserialization',
    severity: 'critical',
    description: 'Unsafe parse/eval of request body',
    fix: 'Use schema validation before parsing',
    detect: (code) =>
      /JSON\.parse\s*\(\s*[^)]*req\.body/.test(code) ||
      /eval\s*\(\s*[^)]*req\.body/.test(code) ||
      /new\s+Function\s*\(\s*[^)]*req\.body/.test(code),
    locate: /JSON\.parse|eval\s*\(|new\s+Function/,
  },

  'insecure-random': {
    id: 'insecure-random',
    severity: 'medium',
    description: 'Math.random() used — not suitable for security tokens',
    fix: 'Use crypto.randomBytes() or crypto.randomUUID()',
    detect: (code) => /Math\.random\s*\(\s*\)/.test(code),
    locate: /Math\.random\s*\(\s*\)/,
  },

  'prototype-pollution': {
    id: 'prototype-pollution',
    severity: 'high',
    description: 'Assignment via __proto__ or constructor may enable prototype pollution',
    fix: 'Use Object.create(null) or Object.freeze(); avoid dynamic proto keys',
    detect: (code) =>
      /\[\s*['"]__proto__['"]\s*\]/.test(code) ||
      /\[\s*['"]constructor['"]\s*\]/.test(code) ||
      /\.__proto__\s*=/.test(code),
    locate: /__proto__|constructor['"]\s*\]/,
  },

  'path-traversal': {
    id: 'path-traversal',
    severity: 'high',
    description: 'Filesystem path derived from request input without validation',
    fix: 'Validate and sanitize file paths; use path.resolve + allowlist',
    detect: (code) =>
      /fs\.(?:readFile|writeFile|readFileSync|writeFileSync|unlink|createReadStream)\s*\(\s*[^)]*req\./.test(
        code,
      ),
    locate: /fs\.(?:readFile|writeFile)/,
  },

  'missing-auth': {
    id: 'missing-auth',
    severity: 'critical',
    description: 'Route handler registered without nearby auth/middleware keywords (heuristic)',
    fix: 'Add authentication middleware',
    detect: (code) => {
      const hasRoute =
        /\.(?:get|post|put|patch|delete)\s*\(\s*['"`][^'"`]+['"`]\s*,/.test(code);
      if (!hasRoute) return false;
      const hasAuth =
        /auth|authenticate|requireAuth|isAuthenticated|passport|jwt|session/i.test(
          code,
        );
      return !hasAuth;
    },
    locate: /\.(?:get|post|put|patch|delete)\s*\(/,
  },

  'missing-csrf': {
    id: 'missing-csrf',
    severity: 'medium',
    description: 'Form POST / state-changing route without CSRF token references (heuristic)',
    fix: 'Add CSRF tokens',
    detect: (code) => {
      const hasFormPost =
        /method\s*=\s*['"]post['"]/i.test(code) ||
        /\.post\s*\(\s*['"`][^'"`]+['"`]/.test(code);
      if (!hasFormPost) return false;
      return !/csrf|csurf|_csrf|xsrf/i.test(code);
    },
    locate: /method\s*=\s*['"]post['"]|\.post\s*\(/i,
  },
};

export const SEVERITY_RANK: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};
