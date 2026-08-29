import { runCrdtSyncLatencyBenchmarks } from '../packages/core/src/__benchmarks__/crdt-sync-latency.js';
import { runCryptoOverheadBenchmarks } from '../packages/core/src/__benchmarks__/crypto-overhead.js';
import * as fs from 'fs';

const ITERATIONS = 50;

async function main() {
  console.log('CI benchmarks: ' + ITERATIONS + ' iterations per test...\n');

  const results = [
    await runCrdtSyncLatencyBenchmarks(ITERATIONS),
    await runCryptoOverheadBenchmarks(ITERATIONS),
  ];

  const report = results.map((suite) => ({
    benchmark: suite.benchmark,
    timestamp: suite.timestamp,
    system: suite.system,
    results: suite.results.map((r) => ({
      name: r.name,
      iterations: r.iterations,
      min: r.stats.min,
      mean: r.stats.mean,
      median: r.stats.median,
      p99: r.stats.p99,
      max: r.stats.max,
      stddev: r.stats.stddev,
      unit: r.unit,
      memoryDeltaBytes: r.memoryDeltaBytes ?? null,
    })),
  }));

  fs.writeFileSync('benchmark-results.json', JSON.stringify(report, null, 2));
  console.log('\nResults written to benchmark-results.json');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
