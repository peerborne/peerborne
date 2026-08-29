import { describe, expect, test } from '@jest/globals';
import {
  snapshotKemKeyPair,
  validateAndExportKemKeyPair,
} from './kem-key-pair';

describe('validateAndExportKemKeyPair', () => {
  test('snapshots caller-owned key-pair records before asynchronous use', async () => {
    const [first, second] = (await Promise.all([
      crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits'],
      ),
      crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits'],
      ),
    ])) as CryptoKeyPair[];
    const callerOwned = {
      privateKey: first.privateKey,
      publicKey: first.publicKey,
    };
    const snapshot = snapshotKemKeyPair(callerOwned);

    callerOwned.privateKey = second.privateKey;
    callerOwned.publicKey = second.publicKey;

    expect(snapshot.privateKey).toBe(first.privateKey);
    expect(snapshot.publicKey).toBe(first.publicKey);
    expect(Object.isFrozen(snapshot)).toBe(true);
    await expect(validateAndExportKemKeyPair(snapshot)).resolves.toHaveLength(65);
  });

  test('rejects non-ECDH keys', async () => {
    const rsaKeyPair = (await crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true, ['encrypt', 'decrypt'],
    )) as CryptoKeyPair;
    await expect(validateAndExportKemKeyPair(rsaKeyPair)).rejects.toThrow(/key pair must be ECDH/);
  });

  test('rejects ECDH keys on wrong curve', async () => {
    const p384Pair = (await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveBits'],
    )) as CryptoKeyPair;
    await expect(validateAndExportKemKeyPair(p384Pair)).rejects.toThrow(/must use curve P-256/);
  });

  test('rejects private key missing deriveBits usage', async () => {
    const pair = (await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey'],
    )) as CryptoKeyPair;
    await expect(validateAndExportKemKeyPair(pair)).rejects.toThrow(/usages must include 'deriveBits'/);
  });

  test('accepts valid P-256 ECDH key pair with deriveBits', async () => {
    const pair = (await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
    )) as CryptoKeyPair;
    const result = await validateAndExportKemKeyPair(pair);
    expect(result.length).toBe(65);
  });

  test('rejects individually valid keys from different P-256 pairs', async () => {
    const [first, second] = await Promise.all([
      crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits'],
      ),
      crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits'],
      ),
    ]) as CryptoKeyPair[];

    await expect(
      validateAndExportKemKeyPair({
        publicKey: first.publicKey,
        privateKey: second.privateKey,
      }),
    ).rejects.toThrow(/do not belong to the same pair/);
  });
});
