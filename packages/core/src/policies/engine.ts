import type {
  GuardrailRequest,
  GuardrailResponse,
  Policy,
  PolicyRunResult,
  PolicyViolation,
} from '../types.js';
import { events } from '../events/index.js';
import { createRequestId } from '../utils/ids.js';
import { nowIso } from '../utils/security.js';

export interface RunPoliciesOptions {
  requestId?: string;
  /** Only run policies for this phase (default: all matching policies in list) */
  phase?: 'before' | 'after';
  /** On engine error, block when true (default: true) */
  failClosed?: boolean;
  debug?: boolean;
}

/**
 * Execute policies in priority order (ascending).
 * Short-circuits on the first blocking violation.
 */
export async function runPolicies(
  policies: readonly Policy[],
  req: GuardrailRequest,
  res?: GuardrailResponse,
  options: RunPoliciesOptions = {},
): Promise<PolicyRunResult> {
  const requestId = options.requestId ?? createRequestId();
  const timestamp = nowIso();
  const failClosed = options.failClosed !== false;
  const violations: PolicyViolation[] = [];

  const sorted = [...policies].sort(
    (a, b) => (a.priority ?? 100) - (b.priority ?? 100),
  );

  for (const policy of sorted) {
    const phase = policy.phase ?? 'before';
    if (options.phase && phase !== options.phase) continue;

    try {
      const applies = await policy.when(req);
      if (!applies) continue;

      const ok = await policy.invariant(req, res);
      if (ok) continue;

      const violation: PolicyViolation = {
        policy: policy.name,
        message: `Policy "${policy.name}" violated`,
        requestId,
        timestamp,
      };
      violations.push(violation);

      events.emit({
        type: 'violation',
        violationType: 'POLICY_VIOLATION',
        code: 'POLICY_VIOLATION',
        message: violation.message,
        requestId,
        path: req.path,
        method: req.method,
        timestamp,
        meta: { policy: policy.name, phase },
      });

      const action = policy.onViolation;
      if (typeof action === 'function') {
        action(req, res, violation);
      } else if (action === 'log') {
        events.emit({
          type: 'alert',
          violationType: 'POLICY_VIOLATION',
          message: violation.message,
          requestId,
          path: req.path,
          method: req.method,
          timestamp,
          meta: { policy: policy.name, mode: 'log' },
        });
      } else if (action === 'alert') {
        events.emit({
          type: 'alert',
          violationType: 'POLICY_VIOLATION',
          message: violation.message,
          requestId,
          path: req.path,
          method: req.method,
          timestamp,
          meta: { policy: policy.name, mode: 'alert' },
        });
      } else {
        // block (default)
        events.emit({
          type: 'block',
          violationType: 'POLICY_VIOLATION',
          message: violation.message,
          requestId,
          path: req.path,
          method: req.method,
          timestamp,
          meta: { policy: policy.name },
        });
        return { allowed: false, blocked: true, violations };
      }
    } catch (err) {
      if (options.debug) {
        console.error(`[guardrail] policy "${policy.name}" error:`, err);
      }
      if (failClosed) {
        const violation: PolicyViolation = {
          policy: policy.name,
          message: `Policy "${policy.name}" failed closed due to internal error`,
          requestId,
          timestamp,
        };
        violations.push(violation);
        events.emit({
          type: 'block',
          violationType: 'POLICY_INTERNAL_ERROR',
          message: violation.message,
          requestId,
          path: req.path,
          method: req.method,
          timestamp,
          meta: { policy: policy.name },
        });
        return { allowed: false, blocked: true, violations };
      }
      throw err;
    }
  }

  return { allowed: true, blocked: false, violations };
}
