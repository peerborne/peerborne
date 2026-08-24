/**
 * Enhanced benchmark runner producing paper-quality statistical results.
 * Mirrors the version in @peerborne/core but avoids cross-package import
 * to keep the index benchmark suite self-contained.
 */

/** Statistical summary for a single benchmark run. */
export interface BenchmarkStats {
  min: number;
  max: number;
  mean: number;
  median: number;
  p99: number;
  stddev: number;
}

/** One benchmark entry with computed statistics and optional memory delta. */
export interface BenchmarkResultEntry {
  name: string;
  iterations: number;
  stats: BenchmarkStats;
  unit: string;
  memoryDeltaBytes?: number;
}

/** Aggregated results for a benchmark suite including runtime metadata. */
export interface BenchmarkSuiteResult {
  benchmark: string;
  timestamp: string;
  system: {
    node: string;
    platform: string;
    arch: string;
  };
  results: BenchmarkResultEntry[];
}

/** Benchmark runner that executes named cases and aggregates paper-ready statistics. */
export class PaperBenchmarkRunner {
  private _results: BenchmarkResultEntry[] = [];
  private _suiteName: string;

  constructor(suiteName: string) {
    this._suiteName = suiteName;
  }

  /**
   * Run a benchmark function multiple times and compute statistics.
   * Includes warmup runs (10% of iterations, minimum 1) that are discarded.
   */
  async run(
    name: string,
    fn: () => Promise<void> | void,
    iterations: number = 100,
    unit: string = 'ms',
  ): Promise<BenchmarkResultEntry> {
    if (!Number.isInteger(iterations) || iterations <= 0) {
      throw new RangeError(`iterations must be a positive integer, got ${iterations}`);
    }
    const warmupCount = Math.max(1, Math.floor(iterations * 0.1));

    // Warmup
    for (let i = 0; i < warmupCount; i++) {
      await fn();
    }

    // Force GC before measurement if available
    if (typeof global !== 'undefined' && typeof (global as any).gc === 'function') {
      (global as any).gc();
    }

    // Measure
    const times: number[] = [];
    const memBefore = typeof process !== 'undefined' && process.memoryUsage
      ? process.memoryUsage().heapUsed
      : undefined;

    for (let i = 0; i < iterations; i++) {
      const start = performance.now();
      await fn();
      const end = performance.now();
      times.push(end - start);
    }

    const memAfter = typeof process !== 'undefined' && process.memoryUsage
      ? process.memoryUsage().heapUsed
      : undefined;

    const stats = computeStats(times);
    const entry: BenchmarkResultEntry = {
      name,
      iterations,
      stats,
      unit,
      memoryDeltaBytes: memBefore !== undefined && memAfter !== undefined
        ? memAfter - memBefore
        : undefined,
    };
    this._results.push(entry);
    return entry;
  }

  /**
   * Return the full suite result with system metadata.
   */
  toSuiteResult(): BenchmarkSuiteResult {
    return {
      benchmark: this._suiteName,
      timestamp: new Date().toISOString(),
      system: {
        node: typeof process !== 'undefined' ? process.version : 'unknown',
        platform: typeof process !== 'undefined' ? process.platform : 'unknown',
        arch: typeof process !== 'undefined' ? process.arch : 'unknown',
      },
      results: this._results,
    };
  }

  get results(): BenchmarkResultEntry[] {
    return this._results;
  }

  /**
   * Format results as a markdown table for console output.
   */
  static formatTable(results: BenchmarkResultEntry[]): string {
    const unit = (results.length > 0 && results[0].unit) ? results[0].unit : 'ms';
    const header = `| Benchmark | Iters | Min (${unit}) | Mean (${unit}) | Median (${unit}) | P99 (${unit}) | Max (${unit}) | StdDev | Mem Delta |`;
    const sep =    '|-----------|-------|----------|-----------|-------------|----------|----------|--------|-----------|';
    const rows = results.map(r => {
      const memStr = r.memoryDeltaBytes !== undefined
        ? `${(r.memoryDeltaBytes / 1024).toFixed(1)} KB`
        : 'N/A';
      return `| ${r.name} | ${r.iterations} | ${r.stats.min.toFixed(3)} | ${r.stats.mean.toFixed(3)} | ${r.stats.median.toFixed(3)} | ${r.stats.p99.toFixed(3)} | ${r.stats.max.toFixed(3)} | ${r.stats.stddev.toFixed(3)} | ${memStr} |`;
    });
    return [header, sep, ...rows].join('\n');
  }
}

function computeStats(times: number[]): BenchmarkStats {
  const sorted = [...times].sort((a, b) => a - b);
  const n = sorted.length;
  const sum = sorted.reduce((a, b) => a + b, 0);
  const mean = sum / n;
  const variance = sorted.reduce((acc, t) => acc + (t - mean) ** 2, 0) / n;

  return {
    min: sorted[0],
    max: sorted[n - 1],
    mean,
    median: n % 2 === 0 ? (sorted[Math.floor(n / 2) - 1] + sorted[Math.floor(n / 2)]) / 2 : sorted[Math.floor(n / 2)],
    p99: sorted[Math.min(Math.ceil(n * 0.99) - 1, n - 1)],
    stddev: Math.sqrt(variance),
  };
}
