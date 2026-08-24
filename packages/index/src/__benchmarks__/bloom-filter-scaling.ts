/**
 * Benchmark: Bloom Filter Scaling
 *
 * Measures the performance characteristics of BloomFilterCRDT:
 * - Insert time at various filter sizes (1K to 1M bits)
 * - Query time (positive and negative lookups)
 * - False positive rate at various fill ratios
 * - Serialization and deserialization time
 * - Memory footprint
 * - Merge (CRDT join) time
 */
import { PaperBenchmarkRunner, BenchmarkSuiteResult } from './paper-benchmark-runner.js';
import { BloomFilterCRDT } from '../bloom-filter-crdt.js';

const FILTER_SIZES = [
  { label: '1k-bits', bits: 1024 },
  { label: '8k-bits', bits: 8192 },
  { label: '64k-bits', bits: 65536 },
  { label: '256k-bits', bits: 262144 },
  { label: '1m-bits', bits: 1048576 },
];

const FILL_COUNTS = [100, 500, 1000, 5000, 10000];

/**
 * Run the bloom filter scaling benchmark suite.
 *
 * Measures insert throughput, positive/negative query time, false-positive rate,
 * serialization/deserialization cost, merge (CRDT join) time, and memory footprint
 * across a range of filter sizes (1K to 1M bits).
 *
 * @param iterations - Number of timed iterations per benchmark (default 100).
 * @returns Promise<BenchmarkSuiteResult> with statistical summaries for each benchmark.
 */
export async function runBloomFilterScalingBenchmarks(
  iterations: number = 100,
): Promise<BenchmarkSuiteResult> {
  const runner = new PaperBenchmarkRunner('bloom-filter-scaling');

  // --- Insert time at various filter sizes ---
  for (const { label, bits } of FILTER_SIZES) {
    await runner.run(`insert-1000-into-${label}`, () => {
      const filter = new BloomFilterCRDT(bits, 7);
      for (let i = 0; i < 1000; i++) {
        filter.add(`term_${i}`);
      }
    }, iterations);
  }

  // --- Query time: positive lookups (items exist) ---
  for (const { label, bits } of FILTER_SIZES) {
    const filter = new BloomFilterCRDT(bits, 7);
    for (let i = 0; i < 1000; i++) {
      filter.add(`term_${i}`);
    }

    await runner.run(`query-positive-${label}`, () => {
      let hits = 0;
      for (let i = 0; i < 100; i++) {
        if (filter.has(`term_${i}`)) hits++;
      }
      if (hits !== 100) {
        throw new Error(`query-positive-${label}: expected 100 hits but got ${hits}`);
      }
    }, iterations);
  }

  // --- Query time: negative lookups (items do not exist) ---
  for (const { label, bits } of FILTER_SIZES) {
    const filter = new BloomFilterCRDT(bits, 7);
    for (let i = 0; i < 1000; i++) {
      filter.add(`term_${i}`);
    }

    await runner.run(`query-negative-${label}`, () => {
      for (let i = 0; i < 100; i++) {
        filter.has(`missing_${i}`);
      }
    }, iterations);
  }

  // --- False positive rate at various fill counts ---
  console.log('\n  False positive rate measurements:');
  const defaultBits = 65536;
  for (const fillCount of FILL_COUNTS) {
    const filter = new BloomFilterCRDT(defaultBits, 7);
    for (let i = 0; i < fillCount; i++) {
      filter.add(`term_${i}`);
    }

    // Test 10000 items that were NOT inserted
    let falsePositives = 0;
    const testCount = 10000;
    for (let i = 0; i < testCount; i++) {
      if (filter.has(`nonexistent_${i}`)) {
        falsePositives++;
      }
    }

    const fpr = falsePositives / testCount;
    const fillRatio = filter.fillRatio();
    console.log(`    fill=${fillCount}, fillRatio=${(fillRatio * 100).toFixed(2)}%, FPR=${(fpr * 100).toFixed(4)}%`);

    // Benchmark the fill+check cycle as a timed operation
    await runner.run(`fpr-measurement-${fillCount}-items`, () => {
      const f = new BloomFilterCRDT(defaultBits, 7);
      for (let i = 0; i < fillCount; i++) {
        f.add(`term_${i}`);
      }
      // Check 100 negatives
      let fp = 0;
      for (let i = 0; i < 100; i++) {
        if (f.has(`nonexistent_${i}`)) fp++;
      }
      void fp;
    }, Math.max(10, Math.floor(iterations / 5)));
  }

  // --- Serialization time ---
  for (const { label, bits } of FILTER_SIZES) {
    const filter = new BloomFilterCRDT(bits, 7);
    for (let i = 0; i < 1000; i++) {
      filter.add(`term_${i}`);
    }

    await runner.run(`serialize-${label}`, () => {
      filter.serialize();
    }, iterations);

    const serialized = filter.serialize();
    await runner.run(`deserialize-${label}`, () => {
      BloomFilterCRDT.deserialize(serialized, bits, 7);
    }, iterations);

    // Report serialized size
    console.log(`  [${label}] serialized size: ${serialized.length} bytes`);
  }

  // --- Merge (CRDT join) time ---
  for (const { label, bits } of FILTER_SIZES) {
    const filter1 = new BloomFilterCRDT(bits, 7);
    const filter2 = new BloomFilterCRDT(bits, 7);
    for (let i = 0; i < 500; i++) {
      filter1.add(`a_${i}`);
      filter2.add(`b_${i}`);
    }

    await runner.run(`merge-${label}`, () => {
      // Create a fresh copy each iteration so merge is applied to unmerged state
      const target = BloomFilterCRDT.deserialize(filter1.serialize(), bits, 7);
      target.merge(filter2);
    }, iterations);
  }

  // --- Memory footprint ---
  console.log('\n  Memory footprint:');
  for (const { label, bits } of FILTER_SIZES) {
    const byteSize = Math.ceil(bits / 8);
    console.log(`    ${label}: ${byteSize} bytes (${(byteSize / 1024).toFixed(1)} KB)`);
  }

  return runner.toSuiteResult();
}
