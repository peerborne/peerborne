import { describe, expect, test } from '@jest/globals';
import {
  DOC_KEY_INFO,
  deriveDocumentKeyFromRootSecret,
  deriveEpochIdFromRootSecret,
} from './derive-doc-key.js';

const ALGO = { name: 'AES-GCM' };

describe('deriveDocumentKeyFromRootSecret', () => {
  test('returns an extractable AES-GCM key usable for encrypt/decrypt', async () => {
    const rootSecret = crypto.getRandomValues(new Uint8Array(32));
    const key = await deriveDocumentKeyFromRootSecret(rootSecret);

    expect(key.type).toBe('secret');
    expect(key.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
    expect(key.usages).toEqual(expect.arrayContaining(['encrypt', 'decrypt']));
    expect(key.extractable).toBe(true);

    // Smoke-test: round-trip a plaintext through the derived key.
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode('hello, beekem');
    const ct = await crypto.subtle.encrypt(
      { ...ALGO, iv: nonce },
      key,
      plaintext,
    );
    const pt = await crypto.subtle.decrypt({ ...ALGO, iv: nonce }, key, ct);
    expect(new Uint8Array(pt)).toEqual(plaintext);
  });

  test('is deterministic in the root secret', async () => {
    const rootSecret = new Uint8Array(32).fill(7);
    const k1 = await deriveDocumentKeyFromRootSecret(rootSecret);
    const k2 = await deriveDocumentKeyFromRootSecret(rootSecret);

    // Same root secret should produce byte-identical keys.
    const raw1 = new Uint8Array(await crypto.subtle.exportKey('raw', k1));
    const raw2 = new Uint8Array(await crypto.subtle.exportKey('raw', k2));
    expect(raw1).toEqual(raw2);
  });

  test('produces different keys for different root secrets', async () => {
    const a = new Uint8Array(32).fill(1);
    const b = new Uint8Array(32).fill(2);
    const ka = await deriveDocumentKeyFromRootSecret(a);
    const kb = await deriveDocumentKeyFromRootSecret(b);
    const rawA = new Uint8Array(await crypto.subtle.exportKey('raw', ka));
    const rawB = new Uint8Array(await crypto.subtle.exportKey('raw', kb));
    expect(rawA).not.toEqual(rawB);
  });

  test('rejects non-Uint8Array input', async () => {
    await expect(
      deriveDocumentKeyFromRootSecret('not bytes' as unknown as Uint8Array),
    ).rejects.toThrow(/Uint8Array/);
  });

  test('rejects empty input', async () => {
    await expect(
      deriveDocumentKeyFromRootSecret(new Uint8Array(0)),
    ).rejects.toThrow(/must be 32 bytes; got 0/);
  });

  test('rejects 31-byte input (one short of the fixed width)', async () => {
    // A wrong-buffer that happens to be close to the right width
    // would otherwise feed HKDF and silently produce a key that
    // disagrees with every other peer's derivation. The byteLength
    // gate makes this fail at the call boundary.
    await expect(
      deriveDocumentKeyFromRootSecret(new Uint8Array(31)),
    ).rejects.toThrow(/must be 32 bytes; got 31/);
  });

  test('rejects 33-byte input (one over the fixed width)', async () => {
    await expect(
      deriveDocumentKeyFromRootSecret(new Uint8Array(33)),
    ).rejects.toThrow(/must be 32 bytes; got 33/);
  });

  test('exposes the version-tagged info label as a public constant', () => {
    // Lock in the on-wire-equivalent info string so a downstream
    // consumer can re-derive without round-tripping through the
    // helper (and so future bumps are intentional).
    expect(DOC_KEY_INFO).toBe('collabswarm-doc-key-v1');
  });
});

describe('deriveEpochIdFromRootSecret', () => {
  test('returns a 32-byte deterministic Uint8Array', async () => {
    const rootSecret = new Uint8Array(32).fill(42);
    const id1 = await deriveEpochIdFromRootSecret(rootSecret);
    const id2 = await deriveEpochIdFromRootSecret(rootSecret);
    expect(id1).toBeInstanceOf(Uint8Array);
    expect(id1.byteLength).toBe(32);
    expect(id1).toEqual(id2);
  });

  test('domain-separates from the document key', async () => {
    const rootSecret = crypto.getRandomValues(new Uint8Array(32));
    const epochId = await deriveEpochIdFromRootSecret(rootSecret);
    const key = await deriveDocumentKeyFromRootSecret(rootSecret);
    const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', key));
    // The epoch ID and AES key bytes should differ; both are 32 bytes
    // but derived under different HKDF info strings.
    expect(epochId).not.toEqual(rawKey);
  });

  test('produces different epoch IDs for different root secrets', async () => {
    const a = new Uint8Array(32).fill(1);
    const b = new Uint8Array(32).fill(2);
    const ida = await deriveEpochIdFromRootSecret(a);
    const idb = await deriveEpochIdFromRootSecret(b);
    expect(ida).not.toEqual(idb);
  });

  test('rejects empty input', async () => {
    await expect(
      deriveEpochIdFromRootSecret(new Uint8Array(0)),
    ).rejects.toThrow(/must be 32 bytes; got 0/);
  });

  test('rejects 31-byte input (one short of the fixed width)', async () => {
    await expect(
      deriveEpochIdFromRootSecret(new Uint8Array(31)),
    ).rejects.toThrow(/must be 32 bytes; got 31/);
  });

  test('rejects 33-byte input (one over the fixed width)', async () => {
    await expect(
      deriveEpochIdFromRootSecret(new Uint8Array(33)),
    ).rejects.toThrow(/must be 32 bytes; got 33/);
  });
});
