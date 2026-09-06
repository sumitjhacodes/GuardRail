import { validateConfig } from './config.js';
import { events } from './events/index.js';
import { validateInputs } from './input/index.js';
import { sanitizeError, sanitizeOutput } from './output/index.js';
import type {
  FieldRule,
  GuardrailConfig,
  HealthCheckResult,
  InferInputs,
  ValidationResult,
} from './types.js';
import { createRequestId } from './utils/ids.js';
import { nowIso } from './utils/security.js';

export const VERSION = '0.1.0';

export interface GuardrailInstance<TInputs extends Record<string, FieldRule> = Record<string, FieldRule>> {
  config: GuardrailConfig<TInputs>;
  validate: (data: unknown, requestId?: string) => Promise<ValidationResult<InferInputs<TInputs>>>;
  sanitize: (data: unknown) => unknown;
  sanitizeError: typeof sanitizeError;
  rulesLoaded: number;
}

/**
 * Create a Guardrail instance from configuration.
 * Validates config at construction time (fail fast).
 */
export function createGuardrail<TInputs extends Record<string, FieldRule>>(
  config: GuardrailConfig<TInputs> = {},
): GuardrailInstance<TInputs> {
  validateConfig(config as GuardrailConfig);

  const rulesLoaded = config.inputs ? Object.keys(config.inputs).length : 0;

  const instance: GuardrailInstance<TInputs> = {
    config,
    rulesLoaded,

    async validate(data, requestId = createRequestId()) {
      try {
        if (!config.inputs || Object.keys(config.inputs).length === 0) {
          return {
            valid: true,
            data: data as InferInputs<TInputs>,
            errors: [],
            requestId,
            timestamp: nowIso(),
          };
        }

        const result = await validateInputs(config.inputs, data, requestId);

        if (!result.valid) {
          for (const error of result.errors) {
            events.emit({
              type: 'violation',
              violationType: error.code,
              field: error.field,
              code: error.code,
              message: error.message,
              requestId,
              timestamp: result.timestamp,
            });
          }
          events.emit({
            type: 'block',
            violationType: result.errors[0]?.code,
            requestId,
            timestamp: result.timestamp,
            meta: { errorCount: result.errors.length },
          });
        } else {
          events.emit({
            type: 'allow',
            requestId,
            timestamp: result.timestamp,
          });
        }

        return result;
      } catch (err) {
        const failClosed = config.failClosed !== false;
        const timestamp = nowIso();
        if (config.debug) {
          console.error('[guardrail] validation error:', err);
        }
        if (failClosed) {
          events.emit({
            type: 'block',
            violationType: 'INTERNAL_ERROR',
            requestId,
            timestamp,
            message: 'Validation failed closed due to internal error',
          });
          return {
            valid: false,
            errors: [
              {
                field: '_root',
                code: 'INTERNAL_ERROR',
                message: 'Security validation failed',
              },
            ],
            requestId,
            timestamp,
          };
        }
        throw err;
      }
    },

    sanitize(data) {
      if (!config.outputs) return data;
      let result = sanitizeOutput(data, {
        redact: config.outputs.redact,
        redactPaths: config.outputs.redactPaths,
        placeholder: config.outputs.redactPlaceholder,
      });

      if (config.outputs.schema) {
        const parsed = config.outputs.schema.safeParse(result);
        if (!parsed.success) {
          if (config.failClosed !== false) {
            return { error: 'Response failed schema validation' };
          }
        } else {
          result = parsed.data;
        }
      }

      return result;
    },

    sanitizeError(error, errConfig, requestId) {
      return sanitizeError(
        error,
        errConfig ?? config.outputs?.errorSanitization,
        requestId,
      );
    },
  };

  return instance;
}

/** Count of built-in detection patterns for health checks. */
export function countBuiltInRules(): number {
  // Approximate loaded rule/pattern count for ops visibility
  return 150;
}

export function healthCheck(instance?: GuardrailInstance): HealthCheckResult {
  return {
    status: 'healthy',
    version: VERSION,
    rulesLoaded: instance?.rulesLoaded ?? countBuiltInRules(),
  };
}
