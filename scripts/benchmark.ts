import { Bench } from 'tinybench';
import { rules, validateInputs } from '../packages/core/src/index.ts';

async function main() {
  const schema = {
    search: rules.string().sqlSafe().xssSafe().noSecrets().noPathTraversal().maxLength(100),
    email: rules.email(),
    age: rules.number().min(0).max(150),
  };

  const payload = {
    search: 'comfortable running shoes size 10',
    email: 'user@example.com',
    age: 32,
  };

  const bench = new Bench({ time: 1000 });

  bench.add('validateInputs (<1KB payload)', async () => {
    await validateInputs(schema, payload);
  });

  await bench.run();

  console.log('\nGuardrail Phase 1 benchmarks\n');
  for (const task of bench.tasks) {
    const hz = task.result?.hz ?? 0;
    // Prefer hz-derived latency (ms/op); tinybench mean units vary by version
    const ms = hz > 0 ? 1000 / hz : (task.result?.mean ?? 0);
    console.log(`${task.name}`);
    console.log(`  mean: ${ms.toFixed(4)} ms`);
    console.log(`  ops/s: ${hz.toFixed(0)}`);
    console.log(`  target: <1ms — ${ms < 1 ? 'PASS' : 'REVIEW'}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
