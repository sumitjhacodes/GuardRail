import express from 'express';
import { guardrail, rules, events } from '@guardrail/express';

const app = express();
app.use(express.json());

// Observe security events
events.on('block', (event) => {
  console.log('[security] blocked:', event.violationType, event.path ?? '', event.requestId);
});

// Global middleware — output redaction + security headers
app.use(
  guardrail({
    outputs: {
      redact: ['password', 'ssn', 'creditCard', 'cvv', 'token', 'apiKey'],
      headers: {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
      },
      errorSanitization: {
        hideStackTraces: process.env.NODE_ENV === 'production',
        hideServerInfo: true,
      },
    },
  }),
);

app.get('/health/guardrail', guardrail.healthCheck());

app.post(
  '/api/search',
  guardrail({
    inputs: {
      q: rules
        .string()
        .sqlSafe()
        .xssSafe()
        .noSecrets()
        .noPathTraversal()
        .minLength(1)
        .maxLength(100),
    },
  }),
  (req, res) => {
    const { q } = req.body as { q: string };
    res.json({
      results: [`Result for: ${q}`],
      // Demonstrates redaction — never returned to client
      password: 'should-be-redacted',
    });
  },
);

app.post(
  '/api/users',
  guardrail({
    inputs: {
      email: rules.email(),
      password: rules.string().minLength(8).strongPassword(),
      age: rules.number().min(0).max(150),
    },
  }),
  (req, res) => {
    const body = req.body as { email: string; age: number };
    res.status(201).json({
      id: '550e8400-e29b-41d4-a716-446655440000',
      email: body.email,
      age: body.age,
      password: 'hash-would-go-here',
    });
  },
);

app.use(guardrail.errorHandler());

const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => {
  console.log(`Guardrail example listening on http://localhost:${port}`);
  console.log('Try: POST /api/search {"q":"sneakers"}');
  console.log('Try: POST /api/search {"q":"UNION SELECT 1"}  (blocked)');
});
