import {
  GuardrailConfigError,
  type FieldRule,
  type GuardrailConfig,
  type Policy,
} from './types.js';

/**
 * Validate Guardrail configuration at startup. Fail fast on misconfiguration.
 */
export function validateConfig(config: GuardrailConfig): void {
  if (config === null || typeof config !== 'object' || Array.isArray(config)) {
    throw new GuardrailConfigError('Config must be a plain object');
  }

  if (config.inputs !== undefined) {
    if (typeof config.inputs !== 'object' || config.inputs === null || Array.isArray(config.inputs)) {
      throw new GuardrailConfigError('config.inputs must be an object of field rules');
    }
    for (const [key, rule] of Object.entries(config.inputs)) {
      if (!isFieldRule(rule)) {
        throw new GuardrailConfigError(
          `config.inputs.${key} must be a FieldRule (use rules.string(), rules.email(), etc.)`,
        );
      }
    }
  }

  if (config.outputs !== undefined) {
    const { outputs } = config;
    if (typeof outputs !== 'object' || outputs === null || Array.isArray(outputs)) {
      throw new GuardrailConfigError('config.outputs must be an object');
    }
    if (outputs.redact !== undefined && !Array.isArray(outputs.redact)) {
      throw new GuardrailConfigError('config.outputs.redact must be an array of strings');
    }
    if (outputs.redactPaths !== undefined && !Array.isArray(outputs.redactPaths)) {
      throw new GuardrailConfigError('config.outputs.redactPaths must be an array of strings');
    }
    if (
      outputs.schema !== undefined &&
      (typeof outputs.schema !== 'object' ||
        outputs.schema === null ||
        typeof outputs.schema.safeParse !== 'function')
    ) {
      throw new GuardrailConfigError(
        'config.outputs.schema must implement safeParse() (e.g. a Zod schema)',
      );
    }
    if (outputs.headers !== undefined) {
      if (typeof outputs.headers !== 'object' || outputs.headers === null) {
        throw new GuardrailConfigError('config.outputs.headers must be a string map');
      }
    }
  }

  if (config.policies !== undefined) {
    if (!Array.isArray(config.policies)) {
      throw new GuardrailConfigError('config.policies must be an array');
    }
    for (let i = 0; i < config.policies.length; i++) {
      assertPolicy(config.policies[i]!, i);
    }
  }

  if (config.debug !== undefined && typeof config.debug !== 'boolean') {
    throw new GuardrailConfigError('config.debug must be a boolean');
  }

  if (config.failClosed !== undefined && typeof config.failClosed !== 'boolean') {
    throw new GuardrailConfigError('config.failClosed must be a boolean');
  }
}

function assertPolicy(policy: Policy, index: number): void {
  if (!policy || typeof policy !== 'object') {
    throw new GuardrailConfigError(`config.policies[${index}] must be an object`);
  }
  if (typeof policy.name !== 'string' || !policy.name) {
    throw new GuardrailConfigError(`config.policies[${index}].name must be a non-empty string`);
  }
  if (typeof policy.when !== 'function') {
    throw new GuardrailConfigError(`config.policies[${index}].when must be a function`);
  }
  if (typeof policy.invariant !== 'function') {
    throw new GuardrailConfigError(`config.policies[${index}].invariant must be a function`);
  }
  const action = policy.onViolation;
  if (
    action !== 'block' &&
    action !== 'log' &&
    action !== 'alert' &&
    typeof action !== 'function'
  ) {
    throw new GuardrailConfigError(
      `config.policies[${index}].onViolation must be 'block' | 'log' | 'alert' | function`,
    );
  }
  if (policy.phase !== undefined && policy.phase !== 'before' && policy.phase !== 'after') {
    throw new GuardrailConfigError(
      `config.policies[${index}].phase must be 'before' | 'after'`,
    );
  }
}

function isFieldRule(value: unknown): value is FieldRule {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as FieldRule).validate === 'function' &&
    typeof (value as FieldRule).parse === 'function'
  );
}
