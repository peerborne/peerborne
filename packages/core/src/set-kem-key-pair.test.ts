import { describe, expect, test } from '@jest/globals';
import { validateAndExportKemKeyPair } from './kem-key-pair.js';

/**
 * Validation coverage for the helper backing
 * `PeerborneDocument.setKemKeyPair`.
 *
 * The receive path in `_evaluateAndApplyBeeKEMWelcome` assumes (a)
 * ECDH P-256 keys and (b) a private key with `deriveBits` usage, and
 * it consumes the raw bytes of the public key on every incoming
 * Welcome. Without eager validation + caching, a misconfigured key
 * pair (wrong algorithm, wrong curve, missing usage, non-exportable
 * public key) would surface as a generic WebCrypto exception deep
 * inside the Welcome handler on the first invite.
 * `validateAndExportKemKeyPair` (and `setKemKeyPair` by extension)
 * validate the key pair up-front and eagerly export the raw public
 * key; these tests pin that contract without dragging the full
 * `PeerborneDocument` dependency graph into the test runner.
 */

describe('validateAndExportKemKeyPair', () => {
  test('accepts an ECDH P-256 key pair with deriveBits and returns raw public bytes', async () => {
    const keyPair = (await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    )) as CryptoKeyPair;

    const raw = await validateAndExportKemKeyPair(keyPair);

    expect(raw).toBeInstanceOf(Uint8Array);
    // SEC1-uncompressed P-256 point: 0x04 || X(32) || Y(32) = 65 bytes.
    expect(raw.byteLength).toBe(65);
    expect(raw[0]).toBe(0x04);

    // The returned bytes must equal a fresh raw export of the same key.
    const fresh = new Uint8Array(
      await crypto.subtle.exportKey('raw', keyPair.publicKey),
    );
    expect(raw).toEqual(fresh);
  });

  test('rejects an ECDSA key pair (wrong algorithm)', async () => {
    // ECDSA is the document-signing curve; it is NOT a valid KEM key
    // pair. The receive path uses `deriveBits` (an ECDH op) on the
    // private key, which would fail later. We must reject here so the
    // failure is visible at install time.
    const ecdsa = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    await expect(validateAndExportKemKeyPair(ecdsa)).rejects.toThrow(
      /must be ECDH/i,
    );
  });

  test('rejects an ECDH key pair on the wrong curve (P-384)', async () => {
    // The wire format pins P-256 (SEC1-uncompressed = 65 bytes).
    // Anything else would silently produce non-matching sealed
    // payloads and cause every Welcome to fail decryption.
    const p384 = (await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      ['deriveBits'],
    )) as CryptoKeyPair;
    await expect(validateAndExportKemKeyPair(p384)).rejects.toThrow(
      /must use curve P-256/i,
    );
  });

  test('rejects an ECDH P-256 key pair whose private key is missing deriveBits', async () => {
    // ECDH allows generating with `deriveKey` only (no `deriveBits`).
    // `eciesOpen` calls `deriveBits` though, so a `deriveKey`-only
    // private key would fail later. Reject up-front.
    const derivKeyOnly = (await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey'],
    )) as CryptoKeyPair;
    await expect(
      validateAndExportKemKeyPair(derivKeyOnly),
    ).rejects.toThrow(/deriveBits/);
  });
});
