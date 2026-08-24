import { describe, expect, test, beforeEach } from '@jest/globals';
import {
  EPOCH_ID_LENGTH,
  GCM_NONCE_LENGTH,
  generateEpochId,
  deriveEpochSecret,
  deriveEncryptionKey,
  createEpoch,
  EpochManager,
  toHex,
} from './epoch.js';

/** Helper: create a deterministic Uint8Array of the given length from a seed byte. */
function makeBytes(length: number, seed: number): Uint8Array {
  const buf = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    buf[i] = (seed + i) & 0xff;
  }
  return buf;
}

const groupSecret1 = makeBytes(32, 0x01);
const groupSecret2 = makeBytes(32, 0xaa);
const parentEpochId = makeBytes(32, 0xff);

describe('generateEpochId', () => {
  test('produces a 32-byte Uint8Array', async () => {
    const id = await generateEpochId(groupSecret1);
    expect(id).toBeInstanceOf(Uint8Array);
    expect(id.length).toBe(EPOCH_ID_LENGTH);
  });

  test('same inputs produce same output (deterministic)', async () => {
    const id1 = await generateEpochId(groupSecret1);
    const id2 = await generateEpochId(groupSecret1);
    expect(toHex(id1)).toBe(toHex(id2));
  });

  test('different group secrets produce different IDs', async () => {
    const id1 = await generateEpochId(groupSecret1);
    const id2 = await generateEpochId(groupSecret2);
    expect(toHex(id1)).not.toBe(toHex(id2));
  });

  test('with parentEpochId differs from without', async () => {
    const idWithout = await generateEpochId(groupSecret1);
    const idWith = await generateEpochId(groupSecret1, parentEpochId);
    expect(toHex(idWithout)).not.toBe(toHex(idWith));
  });

  test('same inputs with parentEpochId are deterministic', async () => {
    const id1 = await generateEpochId(groupSecret1, parentEpochId);
    const id2 = await generateEpochId(groupSecret1, parentEpochId);
    expect(toHex(id1)).toBe(toHex(id2));
  });
});

describe('deriveEpochSecret', () => {
  test('produces a 32-byte Uint8Array', async () => {
    const epochId = await generateEpochId(groupSecret1);
    const secret = await deriveEpochSecret(groupSecret1, epochId);
    expect(secret).toBeInstanceOf(Uint8Array);
    expect(secret.length).toBe(32);
  });

  test('same inputs produce same output (deterministic)', async () => {
    const epochId = await generateEpochId(groupSecret1);
    const secret1 = await deriveEpochSecret(groupSecret1, epochId);
    const secret2 = await deriveEpochSecret(groupSecret1, epochId);
    expect(toHex(secret1)).toBe(toHex(secret2));
  });

  test('different group secrets produce different epoch secrets', async () => {
    const epochId = await generateEpochId(groupSecret1);
    const secret1 = await deriveEpochSecret(groupSecret1, epochId);
    const secret2 = await deriveEpochSecret(groupSecret2, epochId);
    expect(toHex(secret1)).not.toBe(toHex(secret2));
  });
});

describe('deriveEncryptionKey', () => {
  let epochSecret: Uint8Array;

  beforeEach(async () => {
    const epochId = await generateEpochId(groupSecret1);
    epochSecret = await deriveEpochSecret(groupSecret1, epochId);
  });

  test('produces a CryptoKey with algorithm AES-GCM', async () => {
    const key = await deriveEncryptionKey(epochSecret);
    expect(key).toBeDefined();
    expect((key.algorithm as AesKeyAlgorithm).name).toBe('AES-GCM');
  });

  test('key has 256-bit length', async () => {
    const key = await deriveEncryptionKey(epochSecret);
    expect((key.algorithm as AesKeyAlgorithm).length).toBe(256);
  });

  test('key has encrypt and decrypt usages', async () => {
    const key = await deriveEncryptionKey(epochSecret);
    expect(key.usages).toContain('encrypt');
    expect(key.usages).toContain('decrypt');
  });

  test('encryption round-trip works with derived key', async () => {
    const key = await deriveEncryptionKey(epochSecret);
    const plaintext = new TextEncoder().encode('hello peerborne');
    const nonce = crypto.getRandomValues(new Uint8Array(GCM_NONCE_LENGTH));

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      key,
      plaintext,
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce },
      key,
      ciphertext,
    );

    expect(new Uint8Array(decrypted)).toStrictEqual(plaintext);
  });

  test.each(['AES-CTR', 'AES-CBC'] as const)(
    'derives key with algorithm %s',
    async (alg) => {
      const key = await deriveEncryptionKey(epochSecret, alg);
      expect(key).toBeDefined();
      expect((key.algorithm as AesKeyAlgorithm).name).toBe(alg);
      expect((key.algorithm as AesKeyAlgorithm).length).toBe(256);
      expect(key.usages).toContain('encrypt');
      expect(key.usages).toContain('decrypt');
    },
  );

  test('different algorithms produce different keys from same secret', async () => {
    // Use CTR and CBC (both extractable) to verify distinct key material
    const ctrKey = await deriveEncryptionKey(epochSecret, 'AES-CTR');
    const cbcKey = await deriveEncryptionKey(epochSecret, 'AES-CBC');
    const ctrRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ctrKey));
    const cbcRaw = new Uint8Array(await crypto.subtle.exportKey('raw', cbcKey));
    // Different HKDF info strings should produce different key material
    expect(ctrRaw).not.toStrictEqual(cbcRaw);
  });

  test('GCM key is non-extractable, CTR/CBC keys are extractable', async () => {
    const gcmKey = await deriveEncryptionKey(epochSecret, 'AES-GCM');
    const ctrKey = await deriveEncryptionKey(epochSecret, 'AES-CTR');
    const cbcKey = await deriveEncryptionKey(epochSecret, 'AES-CBC');
    expect(gcmKey.extractable).toBe(false);
    expect(ctrKey.extractable).toBe(true);
    expect(cbcKey.extractable).toBe(true);
  });
});

describe('createEpoch', () => {
  const members = new Set(['member-hash-a', 'member-hash-b']);

  test('creates a complete Epoch with all fields populated', async () => {
    const epoch = await createEpoch(groupSecret1, members);
    expect(epoch.id).toBeInstanceOf(Uint8Array);
    expect(epoch.id.length).toBe(EPOCH_ID_LENGTH);
    expect(epoch.encryptionKey).toBeDefined();
    expect(epoch.memberHashes).toEqual(members);
    expect(epoch.parentEpochId).toBeUndefined();
    expect(typeof epoch.createdAt).toBe('number');
  });

  test('epoch id matches what generateEpochId would produce', async () => {
    const epoch = await createEpoch(groupSecret1, members);
    const expectedId = await generateEpochId(groupSecret1);
    expect(toHex(epoch.id)).toBe(toHex(expectedId));
  });

  test('epoch id with parentEpochId matches generateEpochId', async () => {
    const epoch = await createEpoch(groupSecret1, members, parentEpochId);
    const expectedId = await generateEpochId(groupSecret1, parentEpochId);
    expect(toHex(epoch.id)).toBe(toHex(expectedId));
    expect(epoch.parentEpochId).toBe(parentEpochId);
  });

  test('encryption key can encrypt and decrypt data', async () => {
    const epoch = await createEpoch(groupSecret1, members);
    const plaintext = new TextEncoder().encode('epoch test data');
    const nonce = crypto.getRandomValues(new Uint8Array(GCM_NONCE_LENGTH));

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      epoch.encryptionKey,
      plaintext,
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce },
      epoch.encryptionKey,
      ciphertext,
    );

    expect(new Uint8Array(decrypted)).toStrictEqual(plaintext);
  });
});

describe('EpochManager', () => {
  let manager: EpochManager;

  beforeEach(() => {
    manager = new EpochManager();
  });

  test('addEpoch and getEpoch', async () => {
    const epoch = await createEpoch(groupSecret1, new Set(['a']));
    manager.addEpoch(epoch);

    const retrieved = manager.getEpoch(epoch.id);
    expect(retrieved).toBeDefined();
    expect(toHex(retrieved!.id)).toBe(toHex(epoch.id));
  });

  test('currentEpoch returns undefined when no epochs added', () => {
    expect(manager.currentEpoch).toBeUndefined();
  });

  test('currentEpoch returns the most recently added epoch', async () => {
    const epoch1 = await createEpoch(groupSecret1, new Set(['a']));
    const epoch2 = await createEpoch(groupSecret2, new Set(['a', 'b']));
    manager.addEpoch(epoch1);
    manager.addEpoch(epoch2);

    expect(toHex(manager.currentEpoch!.id)).toBe(toHex(epoch2.id));
  });

  test('transitionEpoch creates a child epoch with correct parentEpochId', async () => {
    const epoch1 = await createEpoch(groupSecret1, new Set(['a']));
    manager.addEpoch(epoch1);

    const transition = await manager.transitionEpoch(
      groupSecret2,
      new Set(['a', 'b']),
      'member_added',
      { affectedMember: 'b' },
    );

    expect(transition.epoch.parentEpochId).toBeDefined();
    expect(toHex(transition.epoch.parentEpochId!)).toBe(toHex(epoch1.id));
    expect(transition.reason).toBe('member_added');
    expect(transition.affectedMember).toBe('b');
  });

  test.each([
    ['member_added', 'new-member'],
    ['member_removed', 'removed-member'],
    ['key_update', undefined],
  ] as const)(
    'transitionEpoch with reason=%s',
    async (...[reason, affectedMember]) => {
      const epoch1 = await createEpoch(groupSecret1, new Set(['a']));
      manager.addEpoch(epoch1);

      const transition = await manager.transitionEpoch(
        groupSecret2,
        new Set(['a']),
        reason,
        affectedMember ? { affectedMember } : undefined,
      );

      expect(transition.reason).toBe(reason);
      expect(transition.affectedMember).toBe(affectedMember);
      expect(toHex(manager.currentEpoch!.id)).toBe(toHex(transition.epoch.id));
    },
  );

  test('multiple transitions form a chain', async () => {
    const secrets = [groupSecret1, groupSecret2, makeBytes(32, 0x55)];
    const epoch0 = await createEpoch(secrets[0], new Set(['a']));
    manager.addEpoch(epoch0);

    const t1 = await manager.transitionEpoch(
      secrets[1],
      new Set(['a', 'b']),
      'member_added',
      { affectedMember: 'b' },
    );
    const t2 = await manager.transitionEpoch(
      secrets[2],
      new Set(['a']),
      'member_removed',
      { affectedMember: 'b' },
    );

    // Verify the chain: epoch0 <- t1 <- t2
    expect(t1.epoch.parentEpochId).toBeDefined();
    expect(toHex(t1.epoch.parentEpochId!)).toBe(toHex(epoch0.id));
    expect(t2.epoch.parentEpochId).toBeDefined();
    expect(toHex(t2.epoch.parentEpochId!)).toBe(toHex(t1.epoch.id));

    // All three epochs should be retrievable
    expect(manager.getEpoch(epoch0.id)).toBeDefined();
    expect(manager.getEpoch(t1.epoch.id)).toBeDefined();
    expect(manager.getEpoch(t2.epoch.id)).toBeDefined();

    // Current should be the last
    expect(toHex(manager.currentEpoch!.id)).toBe(toHex(t2.epoch.id));

    // Total count
    expect(manager.epochs.length).toBe(3);
  });
});
