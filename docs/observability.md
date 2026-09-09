# Observability

Subscribe to Guardrail events and expose Prometheus-style text metrics (no `prom-client` required).

```ts
import { createMetrics, healthWithMetrics, healthCheck, events } from '@guardrail/core';

const metrics = createMetrics(); // listens to events.on('*')

app.get('/metrics', (_req, res) => {
  res.type('text/plain').send(metrics.toPrometheus());
});

app.get('/health/guardrail', (_req, res) => {
  res.json(healthWithMetrics(metrics, healthCheck()));
});

// Optional: record validation latency yourself
const t0 = performance.now();
await instance.validate(data);
metrics.observeLatency(performance.now() - t0);
```

## Metric names

```text
guardrail_requests_total{status="blocked|allowed|alert|violation",reason="..."}
guardrail_latency_ms_sum
guardrail_latency_ms_count
guardrail_latency_ms_avg
```

Call `metrics.dispose()` on shutdown to detach from the events bus.
