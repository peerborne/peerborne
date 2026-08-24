import { describe, expect, test } from '@jest/globals';
import {
  eciesSeal,
  eciesOpen,
  generateEciesKeyPair,
  importEciesPublicKey,
  exportEciesPublicKey,
  ECIES_P256_PUBLIC_KEY_LENGTH,
} from './ecies';

describe('eciesSeal / eciesOpen invariants', () => {
  test('round-trip: seal then open returns original plaintext', async () => {
    const bob = await generateEciesKeyPair();
    const plaintext = new Uint8Array([1, 2, 3, 4, 5]);
    const sealed = await eciesSeal(plaintext, bob.publicKey);
    const opened = await eciesOpen(sealed, bob.privateKey);
    expect(opened).toEqual(plaintext);
  });

  test('opening with wrong private key rejects', async () => {
    const bob = await generateEciesKeyPair();
    const charlie = await generateEciesKeyPair();
    const sealed = await eciesSeal(new Uint8Array([1, 2, 3]), bob.publicKey);
    await expect(eciesOpen(sealed, charlie.privateKey)).rejects.toThrow();
  });

  test('tampered sealed payload fails', async () => {
    const bob = await generateEciesKeyPair();
    const sealed = await eciesSeal(new Uint8Array([1, 2, 3]), bob.publicKey);
    sealed[sealed.length - 1] ^= 0xff;
    await expect(eciesOpen(sealed, bob.privateKey)).rejects.toThrow();
  });

  test('identical plaintext produces different ciphertext', async () => {
    const bob = await generateEciesKeyPair();
    const pt = new Uint8Array([1, 2, 3]);
    expect(await eciesSeal(pt, bob.publicKey)).not.toEqual(await eciesSeal(pt, bob.publicKey));
  });

  test('empty plaintext round-trips', async () => {
    const bob = await generateEciesKeyPair();
    const sealed = await eciesSeal(new Uint8Array(), bob.publicKey);
    expect(await eciesOpen(sealed, bob.privateKey)).toEqual(new Uint8Array());
  });

  test('truncated sealed payload rejects', async () => {
    const bob = await generateEciesKeyPair();
    const sealed = await eciesSeal(new Uint8Array([1, 2, 3]), bob.publicKey);
    await expect(eciesOpen(sealed.subarray(0, 50), bob.privateKey)).rejects.toThrow(/truncated/);
  });

  test('flipped HKDF salt fails', async () => {
    const bob = await generateEciesKeyPair();
    const sealed = await eciesSeal(new Uint8Array([1, 2, 3]), bob.publicKey);
    sealed[0] ^= 0xff;
    await expect(eciesOpen(sealed, bob.privateKey)).rejects.toThrow();
  });

  test('flipped nonce fails', async () => {
    const bob = await generateEciesKeyPair();
    const sealed = await eciesSeal(new Uint8Array([1, 2, 3]), bob.publicKey);
    sealed[32 + 65] ^= 0xff;
    await expect(eciesOpen(sealed, bob.privateKey)).rejects.toThrow();
  });
});

describe('importEciesPublicKey', () => {
  test('rejects wrong-length key', async () => {
    await expect(importEciesPublicKey(new Uint8Array(10))).rejects.toThrow(/must be 65 bytes/);
  });
  test('rejects empty key', async () => {
    await expect(importEciesPublicKey(new Uint8Array())).rejects.toThrow(/must be 65 bytes/);
  });
});

describe('generateEciesKeyPair / exportEciesPublicKey', () => {
  test('generated key pair has correct algorithm', async () => {
    const pair = await generateEciesKeyPair();
    const pubAlgo = pair.publicKey.algorithm as any;
    expect(pubAlgo.name).toBe('ECDH');
    expect(pubAlgo.namedCurve).toBe('P-256');
  });
  test('private key usages include deriveBits', async () => {
    const pair = await generateEciesKeyPair();
    expect(pair.privateKey.usages).toContain('deriveBits');
  });
});
