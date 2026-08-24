/**
 * Benchmark: Sync Pipeline Latency
 *
 * Measures per-operation latency of the Peerborne change pipeline at varying
 * payload sizes (1KB, 10KB, 100KB, 1MB):
 * - Sign and verify (ECDSA P-384)
 * - Encrypt and decrypt (AES-GCM)
 * - Combined sign+encrypt and decrypt+verify pipelines
 * - Serialize and deserialize change blocks (JSON wire format)
 */
import { PaperBenchmarkRunner, BenchmarkSuiteResult } from './benchmark-runner.js';
import { SubtleCrypto } from '../auth-subtlecrypto.js';
import { JSONSerializer } from '../json-serializer.js';
import {
  generateSigningKeyPair,
  generateEncryptionKey,
  generatePayload,
} from './crypto-setup.js';

const PAYLOAD_SIZES: Array<{ label: string; bytes: number }> = [
  { label: '1kb', bytes: 1024 },
  { label: '10kb', bytes: 10 * 1024 },
  { label: '100kb', bytes: 100 * 1024 },
  { label: '1mb', bytes: 1024 * 1024 },
];

/**
 * Run CRDT sync latency benchmarks for the Peerborne change pipeline.
 *
 * Measures per-operation latency for sign, verify, encrypt, decrypt,
 * serialize, and deserialize at payload sizes from 1KB to 1MB.
 * Also benchmarks the combined sign+encrypt and decrypt+verify pipelines.
 *
 * @param iterations - Number of iterations per benchmark (default 100)
 * @returns A {@link BenchmarkSuiteResult} with timing statistics for each operation and size
 */
export async function runCrdtSyncLatencyBenchmarks(
  iterations: number = 100,
): Promise<BenchmarkSuiteResult> {
  const runner = new PaperBenchmarkRunner('crdt-sync-latency');
  const auth = new SubtleCrypto();
  const serializer = new JSONSerializer<string>();

  // Generate keys once
  const signingKeyPair = await generateSigningKeyPair();
  const encryptionKey = await generateEncryptionKey();

  for (const { label, bytes } of PAYLOAD_SIZES) {
    const payload = generatePayload(bytes);

    // --- Sign ---
    await runner.run(`sign-${label}`, async () => {
      await auth.sign(payload, signingKeyPair.privateKey);
    }, iterations);

    // --- Verify ---
    const signature = await auth.sign(payload, signingKeyPair.privateKey);
    await runner.run(`verify-${label}`, async () => {
      const valid = await auth.verify(payload, signingKeyPair.publicKey, signature);
      if (!valid) {
        throw new Error(`Signature verification failed for verify-${label}`);
      }
    }, iterations);

    // --- Encrypt ---
    await runner.run(`encrypt-${label}`, async () => {
      await auth.encrypt(payload, encryptionKey);
    }, iterations);

    // --- Decrypt ---
    const encrypted = await auth.encrypt(payload, encryptionKey);
    await runner.run(`decrypt-${label}`, async () => {
      await auth.decrypt(encrypted.data, encryptionKey, encrypted.nonce);
    }, iterations);

    // --- Full pipeline: sign + encrypt ---
    await runner.run(`sign-encrypt-${label}`, async () => {
      const sig = await auth.sign(payload, signingKeyPair.privateKey);
      await auth.encrypt(payload, encryptionKey);
      // Prevent optimization
      void sig.length;
    }, iterations);

    // --- Full pipeline: decrypt + verify ---
    await runner.run(`decrypt-verify-${label}`, async () => {
      const decrypted = await auth.decrypt(encrypted.data, encryptionKey, encrypted.nonce);
      const valid = await auth.verify(decrypted, signingKeyPair.publicKey, signature);
      if (!valid) {
        throw new Error(`Signature verification failed for decrypt-verify-${label}`);
      }
    }, iterations);

    // --- Serialize change block ---
    const changeData = 'x'.repeat(bytes);
    const changeBlock = {
      changes: changeData,
      nonce: encrypted.nonce,
      blindIndexTokens: { title: 'abc123', author: 'def456' },
    };
    const serialized = serializer.serializeChangeBlock(changeBlock);

    await runner.run(`serialize-change-block-${label}`, () => {
      serializer.serializeChangeBlock(changeBlock);
    }, iterations);

    // --- Deserialize change block ---
    await runner.run(`deserialize-change-block-${label}`, () => {
      serializer.deserializeChangeBlock(serialized);
    }, iterations);

    // --- Serialize raw changes (Uint8Array payload) ---
    await runner.run(`serialize-changes-${label}`, () => {
      serializer.serializeChanges(changeData);
    }, iterations);

    // --- Deserialize raw changes ---
    const serializedChanges = serializer.serializeChanges(changeData);
    await runner.run(`deserialize-changes-${label}`, () => {
      serializer.deserializeChanges(serializedChanges);
    }, iterations);
  }

  return runner.toSuiteResult();
}
