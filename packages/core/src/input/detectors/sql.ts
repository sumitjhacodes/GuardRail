import type { SqlDialect } from '../../types.js';
import { matchSqlWithAccelerator } from './accelerator.js';

/** Base SQL injection patterns (dialect-agnostic). */
export const SQL_BASE_PATTERNS: ReadonlyArray<{ name: string; pattern: RegExp }> = [
  { name: 'quote-comment', pattern: /(\%27)|(')|(\-\-)|(\%23)|(#)/i },
  {
    name: 'equals-quote',
    pattern: /((\%3D)|(=))[^\n]*((\%27)|(')|(\-\-)|(\%3B)|(;))/i,
  },
  {
    name: 'or-injection',
    pattern: /\w*((\%27)|('))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i,
  },
  { name: 'quote-union', pattern: /((\%27)|('))union/i },
  { name: 'exec-sp', pattern: /exec(\s|\+)+(s|x)p\w+/i },
  { name: 'union-select', pattern: /UNION\s+SELECT/i },
  { name: 'insert-into', pattern: /INSERT\s+INTO/i },
  { name: 'delete-from', pattern: /DELETE\s+FROM/i },
  { name: 'drop-table', pattern: /DROP\s+TABLE/i },
  { name: 'shutdown', pattern: /;\s*shutdown/i },
  { name: 'drop-stmt', pattern: /;\s*drop/i },
  { name: 'benchmark', pattern: /benchmark\s*\(/i },
  { name: 'sleep', pattern: /sleep\s*\(/i },
  { name: 'waitfor', pattern: /waitfor\s+delay/i },
];

/** Dialect-specific SQL patterns. */
export const SQL_DIALECT_PATTERNS: Record<
  Exclude<SqlDialect, 'all'>,
  ReadonlyArray<{ name: string; pattern: RegExp }>
> = {
  mysql: [
    { name: 'mysql-load-file', pattern: /load_file\s*\(/i },
    { name: 'mysql-into-outfile', pattern: /into\s+(out|dump)file/i },
    { name: 'mysql-information-schema', pattern: /information_schema/i },
  ],
  postgres: [
    { name: 'pg-copy', pattern: /COPY\s+.*\s+FROM\s+PROGRAM/i },
    { name: 'pg-dollar-quote', pattern: /\$\$[\s\S]*\$\$/ },
    { name: 'pg-pg_sleep', pattern: /pg_sleep\s*\(/i },
  ],
  sqlite: [
    { name: 'sqlite-attach', pattern: /ATTACH\s+(DATABASE)?/i },
    { name: 'sqlite-load-extension', pattern: /load_extension\s*\(/i },
  ],
  mssql: [
    { name: 'mssql-xp-cmdshell', pattern: /xp_cmdshell/i },
    { name: 'mssql-openrowset', pattern: /OPENROWSET/i },
    { name: 'mssql-sp-executesql', pattern: /sp_executesql/i },
  ],
};

const patternCache = new Map<string, ReadonlyArray<{ name: string; pattern: RegExp }>>();

export function getSqlPatterns(dialect: SqlDialect = 'all'): ReadonlyArray<{ name: string; pattern: RegExp }> {
  const cached = patternCache.get(dialect);
  if (cached) return cached;

  let patterns: { name: string; pattern: RegExp }[];
  if (dialect === 'all') {
    patterns = [
      ...SQL_BASE_PATTERNS,
      ...SQL_DIALECT_PATTERNS.mysql,
      ...SQL_DIALECT_PATTERNS.postgres,
      ...SQL_DIALECT_PATTERNS.sqlite,
      ...SQL_DIALECT_PATTERNS.mssql,
    ];
  } else {
    patterns = [...SQL_BASE_PATTERNS, ...SQL_DIALECT_PATTERNS[dialect]];
  }

  patternCache.set(dialect, patterns);
  return patterns;
}

export interface SqlScanResult {
  safe: boolean;
  pattern?: string;
  matched?: string;
}

export function detectSqlInjection(input: string, dialect: SqlDialect = 'all'): SqlScanResult {
  const candidates = [input];
  try {
    const decoded = decodeURIComponent(input.replace(/\+/g, ' '));
    if (decoded !== input) candidates.push(decoded);
  } catch {
    // ignore malformed URI sequences
  }
  // Common partial encodings
  const soft = input.replace(/%20/gi, ' ').replace(/%27/gi, "'").replace(/%3B/gi, ';');
  if (soft !== input) candidates.push(soft);

  for (const candidate of candidates) {
    const accelerated = matchSqlWithAccelerator(candidate, getSqlPatterns(dialect));
    if (accelerated) {
      return {
        safe: false,
        pattern: accelerated.name,
        matched: accelerated.matched.slice(0, 64),
      };
    }
    if (accelerated === null) {
      // Accelerator explicitly said safe for this candidate — still check remaining candidates
      continue;
    }
    for (const { name, pattern } of getSqlPatterns(dialect)) {
      const match = candidate.match(pattern);
      if (match) {
        return { safe: false, pattern: name, matched: match[0]?.slice(0, 64) };
      }
    }
  }
  return { safe: true };
}
