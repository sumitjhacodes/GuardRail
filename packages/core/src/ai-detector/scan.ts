import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative, resolve, sep } from 'node:path';
import {
  AI_VULNERABILITY_PATTERNS,
  SEVERITY_RANK,
  type AiPattern,
  type Severity,
} from './patterns.js';

export interface ScanResult {
  file: string;
  line: number;
  column: number;
  pattern: string;
  severity: Severity;
  description: string;
  fix: string;
  code: string;
}

export interface ScanCodeOptions {
  /** Project root / entry directory (default: cwd) */
  entryPoint?: string;
  include?: string[];
  exclude?: string[];
  /** Pattern ids, or ['all'] */
  patterns?: string[] | ['all'];
  /** Minimum severity to report (default: low) */
  severity?: Severity;
}

/** Expand `{a,b}` brace groups (one level at a time) into separate globs. */
function expandBraces(glob: string): string[] {
  const match = /\{([^{}]+)\}/.exec(glob);
  if (!match || match.index === undefined) return [glob];
  const alts = match[1].split(',');
  const start = match.index;
  const end = start + match[0].length;
  const out: string[] = [];
  for (const alt of alts) {
    out.push(...expandBraces(glob.slice(0, start) + alt + glob.slice(end)));
  }
  return out;
}

function matchesSingleGlob(pathPosix: string, pattern: string): boolean {
  // Normalize to forward slashes
  const path = pathPosix.replace(/\\/g, '/');
  let glob = pattern.replace(/\\/g, '/');

  // './src/**/*.ts' → 'src/**/*.ts'
  if (glob.startsWith('./')) glob = glob.slice(2);

  // Tokenize wildcards first so later regex inserts are not re-expanded
  const DS = '\0DS\0'; // **/
  const DD = '\0DD\0'; // **
  const STAR = '\0S\0';
  const Q = '\0Q\0';

  const escaped = glob
    .replace(/\*\*\//g, DS)
    .replace(/\*\*/g, DD)
    .replace(/\*/g, STAR)
    .replace(/\?/g, Q)
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replaceAll(DS, '(?:.*/)?')
    .replaceAll(DD, '.*')
    .replaceAll(STAR, '[^/]*')
    .replaceAll(Q, '[^/]');

  return new RegExp(`^${escaped}$`).test(path);
}

function matchesGlob(pathPosix: string, pattern: string): boolean {
  return expandBraces(pattern).some((p) => matchesSingleGlob(pathPosix, p));
}

function isExcluded(rel: string, exclude: string[]): boolean {
  const posix = rel.replace(/\\/g, '/');
  return exclude.some((p) => matchesGlob(posix, p) || matchesGlob(posix, p.replace(/^\.\//, '')));
}

function isIncluded(rel: string, include: string[]): boolean {
  if (include.length === 0) return true;
  const posix = rel.replace(/\\/g, '/');
  return include.some((p) => matchesGlob(posix, p) || matchesGlob(posix, p.replace(/^\.\//, '')));
}

async function walkFiles(root: string, dir: string, out: string[]): Promise<void> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === '.git') {
        continue;
      }
      await walkFiles(root, full, out);
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
}

function locateMatch(
  content: string,
  pattern: AiPattern,
): { line: number; column: number; snippet: string } {
  const locate = pattern.locate ?? /./;
  const match = locate.exec(content);
  if (!match || match.index === undefined) {
    const firstLine = content.split(/\r?\n/)[0] ?? '';
    return { line: 1, column: 1, snippet: firstLine.slice(0, 120) };
  }
  const before = content.slice(0, match.index);
  const line = before.split(/\r?\n/).length;
  const lastNl = before.lastIndexOf('\n');
  const column = match.index - lastNl;
  const lineStart = lastNl + 1;
  const lineEnd = content.indexOf('\n', match.index);
  const snippet = content
    .slice(lineStart, lineEnd === -1 ? undefined : lineEnd)
    .trim()
    .slice(0, 120);
  return { line, column, snippet };
}

function resolvePatterns(ids: string[] | undefined): AiPattern[] {
  if (!ids || ids.length === 0 || ids.includes('all')) {
    return Object.values(AI_VULNERABILITY_PATTERNS);
  }
  const out: AiPattern[] = [];
  for (const id of ids) {
    const p = AI_VULNERABILITY_PATTERNS[id];
    if (p) out.push(p);
  }
  return out;
}

function scanSource(
  file: string,
  content: string,
  patterns: AiPattern[],
  minSeverity: Severity,
): ScanResult[] {
  const minRank = SEVERITY_RANK[minSeverity];
  const results: ScanResult[] = [];
  for (const pattern of patterns) {
    if (SEVERITY_RANK[pattern.severity] < minRank) continue;
    if (!pattern.detect(content)) continue;
    const loc = locateMatch(content, pattern);
    results.push({
      file,
      line: loc.line,
      column: loc.column,
      pattern: pattern.id,
      severity: pattern.severity,
      description: pattern.description,
      fix: pattern.fix,
      code: loc.snippet,
    });
  }
  return results;
}

/**
 * Scan files on disk for AI-vulnerable code patterns.
 */
export async function scanCode(options: ScanCodeOptions = {}): Promise<ScanResult[]> {
  const root = resolve(options.entryPoint ?? process.cwd());
  const include = options.include ?? ['**/*.{ts,js,tsx,jsx,mjs,cjs}'];
  const exclude = options.exclude ?? ['**/node_modules/**', '**/dist/**', '**/.git/**'];
  const patterns = resolvePatterns(options.patterns);
  const minSeverity = options.severity ?? 'low';

  const rootStat = await stat(root).catch(() => null);
  const files: string[] = [];
  if (rootStat?.isFile()) {
    files.push(root);
  } else {
    await walkFiles(root, root, files);
  }

  const results: ScanResult[] = [];
  for (const file of files) {
    const rel = relative(root, file) || file.split(sep).pop() || file;
    const isSingleFile = !!rootStat?.isFile();
    if (!isSingleFile) {
      if (isExcluded(rel, exclude)) continue;
      if (!isIncluded(rel, include)) continue;
    }

    let content: string;
    try {
      content = await readFile(file, 'utf8');
    } catch {
      continue;
    }
    results.push(...scanSource(rel.replace(/\\/g, '/'), content, patterns, minSeverity));
  }

  return results;
}

/**
 * Scan a code string in-memory (for dynamic / generated snippets).
 */
function scanDynamic(code: string, options?: { patterns?: string[]; severity?: Severity }): ScanResult[] {
  const patterns = resolvePatterns(options?.patterns);
  const minSeverity = options?.severity ?? 'low';
  return scanSource('<dynamic>', code, patterns, minSeverity);
}

scanCode.dynamic = scanDynamic;

export type { AiPattern, Severity };
export { AI_VULNERABILITY_PATTERNS };
