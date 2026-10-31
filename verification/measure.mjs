import { performance } from 'node:perf_hooks';
import { setImmediate as nextTurn } from 'node:timers/promises';

export { nextTurn };

export function memory() {
  globalThis.gc?.();
  const { heapUsed, external, arrayBuffers, rss } = process.memoryUsage();
  return { heapUsed, external, arrayBuffers, rss, forcedGC: !!globalThis.gc };
}

export function summary(samples) {
  if (samples.length === 0)
    return { count: 0, min: null, p50: null, p99: null, max: null };
  const sorted = [...samples].sort((a, b) => a - b);
  return {
    count: sorted.length,
    min: sorted[0],
    p50: sorted[Math.ceil(sorted.length * 0.5) - 1],
    p99: sorted[Math.ceil(sorted.length * 0.99) - 1],
    max: sorted.at(-1),
  };
}

export async function measure(operation) {
  const gaps = [];
  let last = performance.now();
  const timer = setInterval(() => {
    const now = performance.now();
    gaps.push(now - last);
    last = now;
  }, 1);
  await nextTurn();
  const cpu = process.cpuUsage();
  const start = performance.now();
  try {
    const value = await operation();
    // Include a final sample even when the entire operation blocked timers.
    await new Promise((resolve) => setTimeout(resolve, 0));
    const elapsedMs = performance.now() - start;
    const usage = process.cpuUsage(cpu);
    return {
      value,
      elapsedMs,
      cpuUserMs: usage.user / 1000,
      cpuSystemMs: usage.system / 1000,
      timerGapMs: summary(gaps),
    };
  } finally {
    clearInterval(timer);
  }
}

export function measuredOnly(measurement) {
  const { value: _value, ...metrics } = measurement;
  return metrics;
}
