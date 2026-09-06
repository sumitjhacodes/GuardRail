import type { ErrorSanitizationConfig } from '../types.js';
import { isProduction } from '../utils/security.js';

const FILE_PATH_RE = /(?:[A-Za-z]:\\|\/(?:Users|home|var|tmp|opt|usr|etc)\/)[^\s:'"]+/g;
const INTERNAL_IP_RE =
  /\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|127(?:\.\d{1,3}){3}|localhost)\b/gi;
const SQL_SCHEMA_RE =
  /\b(?:relation|table|column|schema)\s+["'`]?\w+["'`]?/gi;

export interface SanitizedError {
  message: string;
  code?: string;
  statusCode: number;
  requestId?: string;
  stack?: string;
}

/**
 * Sanitize errors for client responses.
 * Full details should be logged internally, never sent to the client in production.
 */
export function sanitizeError(
  error: unknown,
  config: ErrorSanitizationConfig = {},
  requestId?: string,
): SanitizedError {
  const hideStack =
    config.hideStackTraces ?? isProduction();
  const hideServer = config.hideServerInfo ?? true;
  const custom = config.customErrorMessages ?? {};

  let message = 'An unexpected error occurred';
  let code: string | undefined;
  let statusCode = 500;
  let stack: string | undefined;

  if (error instanceof Error) {
    message = error.message;
    stack = error.stack;
    const anyErr = error as Error & { code?: string; statusCode?: number; status?: number };
    code = anyErr.code;
    statusCode = anyErr.statusCode ?? anyErr.status ?? 500;
  } else if (typeof error === 'string') {
    message = error;
  }

  if (code && custom[code]) {
    message = custom[code]!;
  } else if (hideServer) {
    message = scrubTechnicalDetails(message);
  }

  // Map common DB / infra errors
  if (/sql|postgres|mysql|sqlite|sequelize|prisma/i.test(message) && !custom[code ?? '']) {
    message = custom['SQL_ERROR'] ?? 'Database operation failed';
    code = code ?? 'SQL_ERROR';
  }

  const result: SanitizedError = {
    message,
    statusCode,
    requestId,
  };
  if (code) result.code = code;
  if (!hideStack && stack) result.stack = stack;

  return result;
}

function scrubTechnicalDetails(message: string): string {
  return message
    .replace(FILE_PATH_RE, '[path]')
    .replace(INTERNAL_IP_RE, '[host]')
    .replace(SQL_SCHEMA_RE, '[schema]')
    .replace(/\s{2,}/g, ' ')
    .trim();
}
