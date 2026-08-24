import { describe, expect, test } from '@jest/globals';
import {
  eciesSeal,
  eciesOpen,
  generateEciesKeyPair,
  importEciesPublicKey,
  exportEciesPublicKey,
  ECIES_P256_PUBLIC_KEY_LENGTH,
} from './ecies.js';

/**
 * Direct-unit tests for the ECIES sealed-box primitive.
 *
 * The primitive is shared by the BeeKEM ratchet (`beekem.ts`,
 * encrypting node private keys along the path) and the BeeKEM Welcome
 * payload encryption path (`peerborne-document._sendBeeKEMWelcome`).
 * Both call sites depend on the wire format and key derivation staying
 * stable; cover the security-critical paths here so regressions surface
 * without standing up the rest of the stack.
 */

describe('ecies seal/open', () => {
  test('round-trips a payload through the intended recipient', async () => {
    const recipient = await generateEciesKeyPair();
    const plaintext = new TextEncoder().encode('hello, sealed world');
    const sealed = await eciesSeal(plaintext, recipient.publicKey);
    expect(sealed).toBeInstanceOf(Uint8Array);
    expect(sealed.byteLength).toBeGreaterThan(plaintext.byteLength);

    const opened = await eciesOpen(sealed, recipient.privateKey);
    expect(new TextDecoder().decode(opened)).toBe('hello, sealed world');
  });

  test('round-trips an empty payload', async () => {
    const recipient = await generateEciesKeyPair();
    const sealed = await eciesSeal(new Uint8Array(0), recipient.publicKey);
    const opened = await eciesOpen(sealed, recipient.privateKey);
    expect(opened.byteLength).toBe(0);
  });

  test('produces different sealed bytes for identical plaintexts (random salt + nonce)', async () => {
    const recipient = await generateEciesKeyPair();
    const plaintext = new Uint8Array([1, 2, 3, 4, 5]);
    const sealedA = await eciesSeal(plaintext, recipient.publicKey);
    const sealedB = await eciesSeal(plaintext, recipient.publicKey);
    expect(sealedA).not.toEqual(sealedB);
    // Both still decrypt to the same plaintext.
    expect(await eciesOpen(sealedA, recipient.privateKey)).toEqual(plaintext);
    expect(await eciesOpen(sealedB, recipient.privateKey)).toEqual(plaintext);
  });

  test('eciesOpen with the wrong recipient key fails', async () => {
    const intendedRecipient = await generateEciesKeyPair();
    const otherRecipient = await generateEciesKeyPair();
    const sealed = await eciesSeal(
      new TextEncoder().encode('secret'),
      intendedRecipient.publicKey,
    );

    // Decrypting with a different recipient's private key must fail.
    // The AES-GCM tag verification fails because the derived shared
    // secret differs; WebCrypto signals this by rejecting the promise.
    await expect(eciesOpen(sealed, otherRecipient.privateKey)).rejects.toThrow();
  });

  test('eciesOpen rejects a truncated payload', async () => {
    const recipient = await generateEciesKeyPair();
    const sealed = await eciesSeal(
      new TextEncoder().encode('secret'),
      recipient.publicKey,
    );
    // Lop off the AES-GCM tag and ciphertext entirely -- this is shorter
    // than the documented minimum length, so the validator should reject
    // it without ever invoking WebCrypto.
    const truncated = sealed.slice(0, 32);
    await expect(eciesOpen(truncated, recipient.privateKey)).rejects.toThrow(
      /sealed payload truncated/i,
    );
  });

  test('eciesOpen rejects a tampered ciphertext (AES-GCM integrity)', async () => {
    const recipient = await generateEciesKeyPair();
    const sealed = await eciesSeal(
      new TextEncoder().encode('payload to protect'),
      recipient.publicKey,
    );
    // Flip a bit in the ciphertext region (well past the salt /
    // ephemeral key / nonce header).
    const tampered = new Uint8Array(sealed);
    tampered[tampered.byteLength - 1] ^= 0x01;
    await expect(eciesOpen(tampered, recipient.privateKey)).rejects.toThrow();
  });

  test('exportEciesPublicKey + importEciesPublicKey round-trip', async () => {
    const keyPair = await generateEciesKeyPair();
    const raw = await exportEciesPublicKey(keyPair.publicKey);
    expect(raw.byteLength).toBe(ECIES_P256_PUBLIC_KEY_LENGTH);

    // Imported key works as a sealing target.
    const imported = await importEciesPublicKey(raw);
    const sealed = await eciesSeal(
      new TextEncoder().encode('via raw export'),
      imported,
    );
    const opened = await eciesOpen(sealed, keyPair.privateKey);
    expect(new TextDecoder().decode(opened)).toBe('via raw export');
  });

  test('importEciesPublicKey rejects wrong-length raw bytes', async () => {
    await expect(importEciesPublicKey(new Uint8Array(64))).rejects.toThrow(
      /must be 65 bytes/i,
    );
  });
});
