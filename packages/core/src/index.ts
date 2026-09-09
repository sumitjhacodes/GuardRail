export type {
  ErrorSanitizationConfig,
  FieldParseResult,
  FieldRule,
  FileInput,
  GuardrailConfig,
  GuardrailRequest,
  GuardrailResponse,
  HealthCheckResult,
  InferInputs,
  InferRuleType,
  OutputsConfig,
  Policy,
  PolicyPhase,
  PolicyRunResult,
  PolicyViolation,
  SecurityEvent,
  SqlDialect,
  ValidationError,
  ValidationResult,
  ViolationAction,
  XssContext,
} from './types.js';

export { GuardrailConfigError, GuardrailValidationError } from './types.js';

export { rules, validateInputs } from './input/index.js';
export {
  detectSqlInjection,
  detectXss,
  detectSecrets,
  detectPathTraversal,
  getSqlPatterns,
  getXssPatterns,
} from './input/index.js';

export { deepRedact, redactByKeys, sanitizeOutput, sanitizeError } from './output/index.js';
export type { SanitizedError } from './output/index.js';

export { runPolicies } from './policies/index.js';
export type { RunPoliciesOptions } from './policies/index.js';

export {
  scanCode,
  AI_VULNERABILITY_PATTERNS,
  SEVERITY_RANK,
} from './ai-detector/index.js';
export type {
  ScanCodeOptions,
  ScanResult,
  AiPattern,
  Severity,
} from './ai-detector/index.js';

export { events } from './events/index.js';
export { validateConfig } from './config.js';
export {
  createGuardrail,
  healthCheck,
  VERSION,
  type GuardrailInstance,
} from './guardrail.js';

import { createGuardrail, healthCheck, VERSION } from './guardrail.js';
import { validateConfig } from './config.js';
import type { FieldRule, GuardrailConfig, HealthCheckResult } from './types.js';

/**
 * Primary API: create a configured Guardrail instance.
 */
export function guardrail<TInputs extends Record<string, FieldRule>>(
  config: GuardrailConfig<TInputs> = {},
) {
  return createGuardrail(config);
}

guardrail.validateConfig = validateConfig;
guardrail.healthCheck = (instance?: Parameters<typeof healthCheck>[0]): HealthCheckResult =>
  healthCheck(instance);
guardrail.VERSION = VERSION;
