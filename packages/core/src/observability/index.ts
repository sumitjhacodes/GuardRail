import { events } from '../events/index.js';
import type { HealthCheckResult, SecurityEvent } from '../types.js';

const METRICS_VERSION = '0.3.0';

export interface MetricsSnapshot {
  requestsTotal: Record<string, number>;
  latencyMsSum: number;
  latencyMsCount: number;
  startedAt: string;
}

export interface GuardrailMetrics {
  /** Record a latency sample (ms) for histogram-style export */
  observeLatency: (ms: number) => void;
  /** Snapshot of counters */
  snapshot: () => MetricsSnapshot;
  /** Prometheus text exposition */
  toPrometheus: () => string;
  /** Stop listening to the events bus */
  dispose: () => void;
}

function labelKey(status: string, reason: string): string {
  return `${status}|${reason}`;
}

/**
 * Subscribe to Guardrail security events and expose Prometheus-style metrics.
 * Pure counters — no prom-client dependency.
 */
export function createMetrics(options?: {
  /** Auto-subscribe to events bus (default: true) */
  subscribe?: boolean;
}): GuardrailMetrics {
  const requestsTotal = Object.create(null) as Record<string, number>;
  let latencyMsSum = 0;
  let latencyMsCount = 0;
  const startedAt = new Date().toISOString();

  const bump = (status: string, reason: string) => {
    const key = labelKey(status, reason);
    requestsTotal[key] = (requestsTotal[key] ?? 0) + 1;
  };

  const onEvent = (event: SecurityEvent) => {
    if (event.type === 'block') {
      bump('blocked', event.violationType ?? event.code ?? 'unknown');
    } else if (event.type === 'allow') {
      bump('allowed', 'ok');
    } else if (event.type === 'alert') {
      bump('alert', event.violationType ?? event.code ?? 'unknown');
    } else if (event.type === 'violation') {
      bump('violation', event.violationType ?? event.code ?? 'unknown');
    }
  };

  let unsubscribe: (() => void) | undefined;
  if (options?.subscribe !== false) {
    unsubscribe = events.on('*', onEvent);
  }

  return {
    observeLatency(ms: number) {
      if (!Number.isFinite(ms) || ms < 0) return;
      latencyMsSum += ms;
      latencyMsCount += 1;
    },

    snapshot() {
      return {
        requestsTotal: { ...requestsTotal },
        latencyMsSum,
        latencyMsCount,
        startedAt,
      };
    },

    toPrometheus() {
      const lines: string[] = [
        '# HELP guardrail_requests_total Security decisions counted by status and reason',
        '# TYPE guardrail_requests_total counter',
      ];
      for (const [key, value] of Object.entries(requestsTotal)) {
        const [status, reason] = key.split('|');
        const safeReason = (reason ?? 'unknown').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
        lines.push(
          `guardrail_requests_total{status="${status}",reason="${safeReason}"} ${value}`,
        );
      }
      lines.push('# HELP guardrail_latency_ms_sum Request validation latency sum (ms)');
      lines.push('# TYPE guardrail_latency_ms_sum counter');
      lines.push(`guardrail_latency_ms_sum ${latencyMsSum}`);
      lines.push('# HELP guardrail_latency_ms_count Request validation latency samples');
      lines.push('# TYPE guardrail_latency_ms_count counter');
      lines.push(`guardrail_latency_ms_count ${latencyMsCount}`);
      if (latencyMsCount > 0) {
        const avg = latencyMsSum / latencyMsCount;
        lines.push('# HELP guardrail_latency_ms_avg Average validation latency (ms)');
        lines.push('# TYPE guardrail_latency_ms_avg gauge');
        lines.push(`guardrail_latency_ms_avg ${avg}`);
      }
      return `${lines.join('\n')}\n`;
    },

    dispose() {
      unsubscribe?.();
      unsubscribe = undefined;
    },
  };
}

/** Extend health payload with optional metrics summary. */
export function healthWithMetrics(
  metrics?: GuardrailMetrics,
  base?: HealthCheckResult,
): HealthCheckResult & { metrics?: MetricsSnapshot } {
  const health = base ?? {
    status: 'healthy' as const,
    version: METRICS_VERSION,
    rulesLoaded: 0,
  };
  if (!metrics) return health;
  return { ...health, metrics: metrics.snapshot() };
}
