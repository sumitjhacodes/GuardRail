import { describe, expect, it, afterEach } from 'vitest';
import { createMetrics, events, healthWithMetrics, healthCheck } from '@guardrail/core';

describe('observability metrics', () => {
  afterEach(() => {
    events.removeAllListeners();
  });

  it('counts block and allow events', () => {
    const metrics = createMetrics();
    events.emit({
      type: 'block',
      requestId: 'r1',
      timestamp: new Date().toISOString(),
      violationType: 'SQL_INJECTION_DETECTED',
    });
    events.emit({
      type: 'allow',
      requestId: 'r2',
      timestamp: new Date().toISOString(),
    });
    const snap = metrics.snapshot();
    expect(snap.requestsTotal['blocked|SQL_INJECTION_DETECTED']).toBe(1);
    expect(snap.requestsTotal['allowed|ok']).toBe(1);
    const text = metrics.toPrometheus();
    expect(text).toContain('guardrail_requests_total{status="blocked",reason="SQL_INJECTION_DETECTED"} 1');
    expect(text).toContain('guardrail_requests_total{status="allowed",reason="ok"} 1');
    metrics.dispose();
  });

  it('records latency samples', () => {
    const metrics = createMetrics({ subscribe: false });
    metrics.observeLatency(1.5);
    metrics.observeLatency(2.5);
    expect(metrics.snapshot().latencyMsCount).toBe(2);
    expect(metrics.toPrometheus()).toContain('guardrail_latency_ms_avg 2');
  });

  it('healthWithMetrics attaches snapshot', () => {
    const metrics = createMetrics({ subscribe: false });
    metrics.observeLatency(1);
    const health = healthWithMetrics(metrics, healthCheck());
    expect(health.metrics?.latencyMsCount).toBe(1);
    expect(health.status).toBe('healthy');
  });
});
