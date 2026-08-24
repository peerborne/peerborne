/**
 * Shared crypto setup for benchmarks.
 * Uses @peculiar/webcrypto polyfill for Node.js environments.
 */
import { Crypto } from '@peculiar/webcrypto';

// Install polyfill if needed
if (typeof globalThis.crypto === 'undefined' || typeof globalThis.crypto.subtle === 'undefined') {
  (globalThis as any).crypto = new Crypto();
}

/**
 * Generate an ECDSA P-384 key pair for signing/verification benchmarks.
 */
export async function generateSigningKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['sign', 'verify'],
  );
}

/**
 * Generate an AES-GCM 256-bit key for encryption/decryption benchmarks.
 */
export async function generateEncryptionKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Generate a random payload of the given size in bytes.
 * Handles the 65536-byte limit of crypto.getRandomValues by chunking.
 */
export function generatePayload(sizeBytes: number): Uint8Array {
  const buf = new Uint8Array(sizeBytes);
  const chunkSize = 65536;
  for (let offset = 0; offset < sizeBytes; offset += chunkSize) {
    const length = Math.min(chunkSize, sizeBytes - offset);
    crypto.getRandomValues(buf.subarray(offset, offset + length));
  }
  return buf;
}
