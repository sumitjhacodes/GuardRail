export { detectSqlInjection, getSqlPatterns, SQL_BASE_PATTERNS, SQL_DIALECT_PATTERNS } from './sql.js';
export { detectXss, getXssPatterns, XSS_HTML_PATTERNS, XSS_CONTEXT_PATTERNS } from './xss.js';
export { detectSecrets, SECRET_PATTERNS } from './secrets.js';
export { detectPathTraversal } from './path-traversal.js';
export {
  setPatternAccelerator,
  getPatternAccelerator,
  matchSqlWithAccelerator,
  type PatternAccelerator,
  type PatternMatch,
} from './accelerator.js';
