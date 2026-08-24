/**
 * Benchmark: Crypto Overhead
 *
 * Compares plaintext vs encrypted change propagation and measures the isolated
 * cost of each cryptographic operation in the Peerborne pipeline:
 * - Plaintext change propagation time vs encrypted
 * - Signing overhead at different payload sizes
 * - Key generation and rotation time
 * - Isolated cost of each crypto operation (sign, verify, encrypt, decrypt)
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
 * Run crypto overhead benchmarks comparing plaintext vs encrypted pipelines.
 *
 * Measures key generation (ECDSA P-384, AES-GCM-256), key rotation cost,
 * and the isolated overhead of each cryptographic operation (sign, verify,
 * encrypt, decrypt) at payload sizes from 1KB to 1MB. Also compares full
 * plaintext serialization against the encrypted sign-encrypt-decrypt-verify
 * pipeline to quantify crypto overhead.
 *
 * @param iterations - Number of iterations per benchmark (default 100)
 * @returns A {@link BenchmarkSuiteResult} with timing statistics for each operation
 */
export async function runCryptoOverheadBenchmarks(
  iterations: number = 100,
): Promise<BenchmarkSuiteResult> {
  const runner = new PaperBenchmarkRunner('crypto-overhead');
  const auth = new SubtleCrypto();
  const serializer = new JSONSerializer<string>();

  // --- Key generation benchmarks ---
  await runner.run('keygen-ecdsa-p384', async () => {
    await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      false,
      ['sign', 'verify'],
    );
  }, iterations);

  await runner.run('keygen-aes-gcm-256', async () => {
    await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  }, iterations);

  // --- Key rotation simulation ---
  // Simulates what happens when a member is removed: new key generated + re-encrypt
  const rotationPayload = generatePayload(10 * 1024); // 10KB typical document
  await runner.run('key-rotation-10kb', async () => {
    // Generate new document key
    const newKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    // Re-encrypt with new key
    await auth.encrypt(rotationPayload, newKey);
  }, iterations);

  // --- Plaintext vs Encrypted change propagation ---
  for (const { label, bytes } of PAYLOAD_SIZES) {
    const payload = generatePayload(bytes);
    const signingKeyPair = await generateSigningKeyPair();
    const encryptionKey = await generateEncryptionKey();

    // Plaintext pipeline: serialize only (no crypto)
    const changeData = 'x'.repeat(bytes);
    await runner.run(`plaintext-pipeline-${label}`, () => {
      const serialized = serializer.serializeChanges(changeData);
      serializer.deserializeChanges(serialized);
    }, iterations);

    // Encrypted pipeline: serialize + sign + encrypt + decrypt + verify + deserialize
    await runner.run(`encrypted-pipeline-${label}`, async () => {
      // Sender side
      const changeBytes = serializer.serializeChanges(changeData);
      const sig = await auth.sign(changeBytes, signingKeyPair.privateKey);
      const enc = await auth.encrypt(changeBytes, encryptionKey);
      // Receiver side
      const dec = await auth.decrypt(enc.data, encryptionKey, enc.nonce);
      const valid = await auth.verify(dec, signingKeyPair.publicKey, sig);
      if (!valid) {
        throw new Error(`Signature verification failed for encrypted-pipeline-${label}`);
      }
      serializer.deserializeChanges(dec);
    }, iterations);

    // Isolated: signing overhead only
    await runner.run(`isolated-sign-${label}`, async () => {
      await auth.sign(payload, signingKeyPair.privateKey);
    }, iterations);

    // Isolated: verification overhead only
    const sig = await auth.sign(payload, signingKeyPair.privateKey);
    await runner.run(`isolated-verify-${label}`, async () => {
      const valid = await auth.verify(payload, signingKeyPair.publicKey, sig);
      if (!valid) {
        throw new Error(`Signature verification failed for isolated-verify-${label}`);
      }
    }, iterations);

    // Isolated: encryption overhead only
    await runner.run(`isolated-encrypt-${label}`, async () => {
      await auth.encrypt(payload, encryptionKey);
    }, iterations);

    // Isolated: decryption overhead only
    const encrypted = await auth.encrypt(payload, encryptionKey);
    await runner.run(`isolated-decrypt-${label}`, async () => {
      await auth.decrypt(encrypted.data, encryptionKey, encrypted.nonce);
    }, iterations);
  }

  return runner.toSuiteResult();
}
