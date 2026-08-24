/**
 * Benchmark: Blind Index Performance
 *
 * Measures the cost of blind index operations used for encrypted search:
 * - Token generation time (single field)
 * - Compound token generation time (multi-field)
 * - Token verification/matching time
 * - Scaling with number of indexed fields
 * - Field key derivation time (HKDF)
 */
import { Crypto } from '@peculiar/webcrypto';

if (typeof globalThis.crypto === 'undefined' || typeof globalThis.crypto.subtle === 'undefined') {
  (globalThis as any).crypto = new Crypto();
}

import { PaperBenchmarkRunner, BenchmarkSuiteResult } from './paper-benchmark-runner.js';
import { SubtleBlindIndexProvider } from '../subtle-blind-index-provider.js';

const FIELD_COUNTS = [1, 2, 4, 8, 16];

async function generateMasterKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true, // extractable - required by SubtleBlindIndexProvider
    ['encrypt', 'decrypt'],
  );
}

/**
 * Run the blind index performance benchmark suite.
 *
 * Measures field-key derivation, token generation (string, numeric, compound),
 * token match/mismatch comparison, field-count scaling, and batch throughput.
 *
 * @param iterations - Number of timed iterations per benchmark (default 100).
 * @returns Promise<BenchmarkSuiteResult> with statistical summaries for each benchmark.
 */
export async function runBlindIndexPerfBenchmarks(
  iterations: number = 100,
): Promise<BenchmarkSuiteResult> {
  const runner = new PaperBenchmarkRunner('blind-index-perf');
  const provider = new SubtleBlindIndexProvider();

  const masterKey = await generateMasterKey();

  // --- Field key derivation (HKDF) ---
  await runner.run('derive-field-key', async () => {
    await provider.deriveFieldKey(masterKey, 'title');
  }, iterations);

  // Pre-derive keys for remaining benchmarks
  const fieldKey = await provider.deriveFieldKey(masterKey, 'title');

  // --- Single field token generation ---
  const testValues = ['hello world', 'Peerborne benchmark', 'CRDT convergence', 'distributed system'];
  let valIdx = 0;
  await runner.run('compute-token-string', async () => {
    await provider.computeToken(fieldKey, testValues[valIdx++ % testValues.length]);
  }, iterations);

  // --- Numeric token generation ---
  let numIdx = 0;
  await runner.run('compute-token-number', async () => {
    await provider.computeToken(fieldKey, numIdx++);
  }, iterations);

  // --- Compound token generation (2 fields) ---
  await runner.run('compute-compound-token-2', async () => {
    await provider.computeCompoundToken(fieldKey, ['Alice', 'Technology']);
  }, iterations);

  // --- Compound token generation (4 fields) ---
  await runner.run('compute-compound-token-4', async () => {
    await provider.computeCompoundToken(fieldKey, ['Alice', 'Technology', 'Article Title', 42]);
  }, iterations);

  // --- Token matching: generate and compare ---
  const precomputedToken = await provider.computeToken(fieldKey, 'hello world');
  await runner.run('token-match-compare', async () => {
    const newToken = await provider.computeToken(fieldKey, 'hello world');
    if (newToken !== precomputedToken) {
      throw new Error(`token-match-compare: expected tokens to match but got ${newToken} !== ${precomputedToken}`);
    }
  }, iterations);

  // --- Token mismatch: generate and compare (negative) ---
  await runner.run('token-mismatch-compare', async () => {
    const newToken = await provider.computeToken(fieldKey, 'different value');
    if (newToken === precomputedToken) {
      throw new Error(`token-mismatch-compare: expected tokens to differ but both were ${newToken}`);
    }
  }, iterations);

  // --- Scaling: derive N field keys + compute N tokens ---
  for (const fieldCount of FIELD_COUNTS) {
    await runner.run(`derive-and-tokenize-${fieldCount}-fields`, async () => {
      for (let i = 0; i < fieldCount; i++) {
        const fk = await provider.deriveFieldKey(masterKey, `field_${i}`);
        await provider.computeToken(fk, `value-for-field-${i}`);
      }
    }, Math.max(10, Math.floor(iterations / 2)));
  }

  // --- Batch token generation: 100 values with same key ---
  await runner.run('batch-100-tokens', async () => {
    for (let i = 0; i < 100; i++) {
      await provider.computeToken(fieldKey, `value-${i}`);
    }
  }, Math.max(10, Math.floor(iterations / 5)));

  return runner.toSuiteResult();
}
