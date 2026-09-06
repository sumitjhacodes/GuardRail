import type {
  FieldRule,
  InferInputs,
  ValidationError,
  ValidationResult,
} from '../types.js';
import { createNullObject, nowIso } from '../utils/security.js';
import { createRequestId } from '../utils/ids.js';

export async function validateInputs<T extends Record<string, FieldRule>>(
  schema: T,
  data: unknown,
  requestId = createRequestId(),
): Promise<ValidationResult<InferInputs<T>>> {
  const timestamp = nowIso();
  const errors: ValidationError[] = [];

  if (data === null || data === undefined || typeof data !== 'object' || Array.isArray(data)) {
    return {
      valid: false,
      errors: [
        {
          field: '_root',
          code: 'INVALID_INPUT',
          message: 'Input must be a plain object',
        },
      ],
      requestId,
      timestamp,
    };
  }

  const source = data as Record<string, unknown>;
  const validated = createNullObject<Record<string, unknown>>();

  for (const key of Object.keys(schema)) {
    const rule = schema[key]!;
    const parsed = await rule.parse(source[key], key);
    if (parsed.errors.length === 0) {
      validated[key] = parsed.value;
    } else {
      errors.push(...parsed.errors);
    }
  }

  if (errors.length > 0) {
    return { valid: false, errors, requestId, timestamp };
  }

  return {
    valid: true,
    data: validated as InferInputs<T>,
    errors: [],
    requestId,
    timestamp,
  };
}

export * from './rules.js';
export * from './detectors/index.js';
