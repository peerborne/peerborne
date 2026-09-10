import { describe, expect, test, beforeAll, jest } from '@jest/globals';
import { runInNewContext } from 'node:vm';
import { snapshotDeepEnumerableData } from '@peerborne/core';
import { YjsKeychain } from '../../yjs/src/peerborne-yjs.js';
import {
  Change as BinaryChange,
  clone as automergeClone,
  change as automergeChange,
  from as automergeFrom,
  getAllChanges as getAllAutomergeChanges,
  getChanges as getAutomergeChanges,
  init as automergeInit,
  merge as automergeMerge,
} from '@automerge/automerge';
import {
  AutomergeProvider,
  AutomergeACL,
  AutomergeACLProvider,
  AutomergeKeychain,
  AutomergeKeychainProvider,
  AutomergeJSONSerializer,
  serializeKey,
  deserializeKey,
} from './peerborne-automerge.js';
import {
  INITIAL_INVITATION_CAPACITY_PROFILE,
  MAX_KEYCHAIN_EPOCHS,
  INITIAL_INVITATION_MAX_ENCRYPTED_BOOTSTRAP_OVERHEAD_BYTES,
  INITIAL_INVITATION_MAX_MEMBERSHIP_GROWTH_BYTES,
  INITIAL_INVITATION_MAX_SEALED_WELCOME_GROWTH_BYTES,
  INITIAL_INVITATION_MAX_SIGNATURE_BYTES,
  MAX_MERKLE_DAG_DEPTH,
  BeeKEM,
  SubtleCrypto,
  eciesSeal,
  encodeWelcomeSealedPayload,
  type CRDTChangeNode,
  type CRDTSyncMessage,
} from '@peerborne/core';

// ECDSA P-384 JWK test keys (public only - ACL uses raw export which requires public keys)
const publicKeyData1 = {
  key_ops: ['verify'] as KeyUsage[],
  ext: true,
  kty: 'EC',
  x: 'iV0DESMDz3fcubTpUCMK4YLWbU9gDslDgdflc5OGrQVII_wCViDdqGbMTOmQLY0F',
  y: 'CQyfju2lK2mT0TIVDI-olIqFC3m3AayX0deHkw4JPCU-GwzV9k0BT295OSQ495kK',
  crv: 'P-384',
};
const publicKeyData2 = {
  key_ops: ['verify'] as KeyUsage[],
  ext: true,
  kty: 'EC',
  x: 'oodHRfDRDsXcpe2FvwctaK1y4pt8Lhx5tmiXZ-35vzXuDUD5zWhzPxgC8FZvyY0K',
  y: 'KhgG-mU2-mNbhgdK9_8nEMwPa2_bWWl_zlqY6Q4xuXYMOjhSLGydbFIDSAGBaNaJ',
  crv: 'P-384',
};

async function importECDSAPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['verify'],
  );
}

// ─── AutomergeProvider ──────────────────────────────────────────────

interface TestDoc {
  title: string;
  count: number;
}

describe('AutomergeProvider', () => {
  const provider = new AutomergeProvider<TestDoc>();

  test('newDocument() returns a valid Automerge Doc', () => {
    const doc = provider.newDocument();
    expect(doc).toBeDefined();
    // Automerge init docs are frozen plain objects
    expect(typeof doc).toBe('object');
  });

  test('localChange() applies a change and returns [newDoc, changes]', () => {
    const doc = provider.newDocument();
    const [newDoc, changes] = provider.localChange(doc, '', (d) => {
      d.title = 'hello';
      d.count = 1;
    });
    expect(newDoc.title).toBe('hello');
    expect(newDoc.count).toBe(1);
    expect(changes.length).toBeGreaterThan(0);
  });

  test('localChange() with a message passes through', () => {
    const doc = provider.newDocument();
    const [newDoc, changes] = provider.localChange(
      doc,
      'set title',
      (d) => {
        d.title = 'with message';
      },
    );
    expect(newDoc.title).toBe('with message');
    expect(changes.length).toBeGreaterThan(0);
  });

  test('remoteChange() applies binary changes from another doc', () => {
    const doc1 = provider.newDocument();
    const [updated1, changes] = provider.localChange(doc1, '', (d) => {
      d.title = 'remote';
      d.count = 42;
    });

    let doc2 = provider.newDocument();
    doc2 = provider.remoteChange(doc2, changes);
    expect(doc2.title).toBe('remote');
    expect(doc2.count).toBe(42);
  });

  test('getHistory() returns all changes', () => {
    const doc = provider.newDocument();
    const [doc2] = provider.localChange(doc, '', (d) => {
      d.title = 'a';
    });
    const [doc3] = provider.localChange(doc2, '', (d) => {
      d.count = 5;
    });
    const history = provider.getHistory(doc3);
    expect(history.length).toBe(2);
  });

  test('round-trip: localChange on doc1 -> remoteChange on doc2 -> docs match', () => {
    const doc1 = provider.newDocument();
    const [doc1a, changes1] = provider.localChange(doc1, '', (d) => {
      d.title = 'sync';
      d.count = 99;
    });

    let doc2 = provider.newDocument();
    doc2 = provider.remoteChange(doc2, changes1);

    expect(doc2.title).toBe(doc1a.title);
    expect(doc2.count).toBe(doc1a.count);
  });
});

// ─── serializeKey / deserializeKey ──────────────────────────────────

describe('serializeKey / deserializeKey', () => {
  test('round-trip serialize then deserialize an ECDSA public key', async () => {
    const key = await importECDSAPublicKey(publicKeyData1);
    const serialized = await serializeKey(key);
    expect(typeof serialized).toBe('string');
    expect(serialized.length).toBeGreaterThan(0);

    const deserialized = await deserializeKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      ['verify'],
    )(serialized);
    expect(deserialized).toBeDefined();
    expect(deserialized.type).toBe('public');

    // Re-serialize should produce the same base64 string
    const reSerialized = await serializeKey(deserialized);
    expect(reSerialized).toBe(serialized);
  });
});

// ─── AutomergeACL ───────────────────────────────────────────────────

describe('AutomergeACL', () => {
  let key1: CryptoKey;
  let key2: CryptoKey;

  beforeAll(async () => {
    key1 = await importECDSAPublicKey(publicKeyData1);
    key2 = await importECDSAPublicKey(publicKeyData2);
  });

  test('add() adds a user and check() returns true', async () => {
    const acl = new AutomergeACL();
    const changes = await acl.add(key1);
    expect(changes.length).toBeGreaterThan(0);
    expect(await acl.check(key1)).toBe(true);
  });

  test('remove() removes a user and check() returns false', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    expect(await acl.check(key1)).toBe(true);

    const removeChanges = await acl.remove(key1);
    expect(removeChanges.length).toBeGreaterThan(0);
    expect(await acl.check(key1)).toBe(false);
  });

  test('remove() is a no-op for a blank ACL', async () => {
    const acl = new AutomergeACL();

    await expect(acl.remove(key1)).resolves.toEqual([]);
    expect(acl.current()).toEqual([]);
  });

  test('check() returns false for an unknown key', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    expect(await acl.check(key2)).toBe(false);
  });

  test('users() returns all added keys', async () => {
    const acl = new AutomergeACL();
    await acl.add(key1);
    await acl.add(key2);

    const users = await acl.users();
    expect(users).toHaveLength(2);

    // Verify by serializing the returned keys and comparing
    const serialized1 = await serializeKey(key1);
    const serialized2 = await serializeKey(key2);
    const returnedSerialized = await Promise.all(users.map(serializeKey));
    expect(returnedSerialized).toContain(serialized1);
    expect(returnedSerialized).toContain(serialized2);
  });

  test('current() / merge() - export changes and verify merge', async () => {
    const acl1 = new AutomergeACL();
    await acl1.add(key1);
    await acl1.add(key2);

    const exported = acl1.current();
    expect(exported.length).toBeGreaterThan(0);

    // Merge back into the same ACL (self-merge is idempotent)
    acl1.merge(exported);
    expect(await acl1.check(key1)).toBe(true);
    expect(await acl1.check(key2)).toBe(true);
  });

  test('founder changes authorize its signing key in a fresh ACL', async () => {
    const signingPair = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    const founder = new AutomergeACL();
    const founderChanges = await founder.add(signingPair.publicKey);
    const receiver = new AutomergeACL();

    receiver.merge(founderChanges);

    expect(await receiver.check(signingPair.publicKey)).toBe(true);
    const writerKeys = await receiver.users();
    expect(writerKeys).toHaveLength(1);
    const [verifyingKey] = writerKeys;
    const payload = new Uint8Array([9, 8, 7, 6]);
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-384' },
      signingPair.privateKey,
      payload,
    );

    expect(
      await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-384' },
        verifyingKey,
        signature,
        payload,
      ),
    ).toBe(true);
  });

  test('fresh ACLs start from the same blank history', () => {
    const first = new AutomergeACL();
    const second = new AutomergeACL();

    expect(first.current()).toEqual([]);
    expect(second.current()).toEqual(first.current());
  });

  test('loads a complete ACL history from the legacy random-seed format', async () => {
    const serialized = await serializeKey(key1);
    const legacyBase = automergeFrom<{ users: Record<string, true> }>({
      users: {},
    });
    const legacyWithMember = automergeChange(legacyBase, (doc) => {
      doc.users[serialized] = true;
    });
    const receiver = new AutomergeACL();

    receiver.merge(getAllAutomergeChanges(legacyWithMember));

    expect(await receiver.check(key1)).toBe(true);
    expect(await receiver.users()).toHaveLength(1);
  });

  test('fails closed for a legacy incremental change that omitted its seed', async () => {
    const serialized = await serializeKey(key1);
    const legacyBase = automergeFrom<{ users: Record<string, true> }>({
      users: {},
    });
    const legacyWithMember = automergeChange(legacyBase, (doc) => {
      doc.users[serialized] = true;
    });
    const receiver = new AutomergeACL();

    receiver.merge(getAutomergeChanges(legacyBase, legacyWithMember));

    await expect(receiver.check(key1)).rejects.toThrow(
      /unresolved change dependencies.*complete ACL history/i,
    );
    expect(() => receiver.current()).toThrow(/cannot be migrated safely/i);
  });

  test('allows valid child-before-parent delivery once dependencies arrive', async () => {
    const sender = new AutomergeACL();
    const founderChanges = await sender.add(key1);
    const collaboratorChanges = await sender.add(key2);
    const receiver = new AutomergeACL();

    receiver.merge(collaboratorChanges);
    await expect(receiver.users()).rejects.toThrow(
      /unresolved change dependencies/i,
    );

    receiver.merge(founderChanges);
    expect(await receiver.check(key1)).toBe(true);
    expect(await receiver.check(key2)).toBe(true);
  });
});

describe('AutomergeACLProvider', () => {
  test('initialize() returns a new AutomergeACL', () => {
    const provider = new AutomergeACLProvider();
    const acl = provider.initialize();
    expect(acl).toBeInstanceOf(AutomergeACL);
  });
});

// ─── AutomergeKeychain ──────────────────────────────────────────────

type TestKeychainDoc = {
  keys: [string, string][];
  unrelated?: string;
};

function newTestKeychainDoc() {
  const seeded = automergeChange(
    automergeInit<TestKeychainDoc>(
      'ababababababababababababababababababababab',
    ),
    { time: 0 },
    (doc) => {
      doc.keys = [];
    },
  );
  return automergeClone(seeded);
}

function appendTestKeychainEntry(
  doc: ReturnType<typeof newTestKeychainDoc>,
  entry: [string, string],
) {
  return automergeChange(doc, (next) => {
    next.keys.push(entry);
  });
}

describe('AutomergeKeychain', () => {
  test('state commitment matches Yjs for the same ordered logical keys', async () => {
    const automerge = new AutomergeKeychain();
    const yjs = new YjsKeychain();
    expect(await automerge.stateCommitment()).toEqual(
      await yjs.stateCommitment(),
    );
    for (const [idFill, keyFill] of [
      [0x11, 0xaa],
      [0x22, 0xbb],
    ] as const) {
      const id = new Uint8Array(32).fill(idFill);
      const key = await crypto.subtle.importKey(
        'raw',
        new Uint8Array(32).fill(keyFill),
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt'],
      );
      await automerge.addEpochKey(id, key);
      await yjs.addEpochKey(id, key);
    }

    expect(await automerge.stateCommitment()).toEqual(
      await yjs.stateCommitment(),
    );
  });

  test('add() returns [keyIDBytes, CryptoKey, changes]', async () => {
    const keychain = new AutomergeKeychain();
    const [keyIDBytes, key, changes] = await keychain.add();

    expect(keyIDBytes).toBeInstanceOf(Uint8Array);
    // 32 bytes -- matches `keyIDLength` and the BeeKEM-derived epoch
    // ID width from `deriveEpochIdFromRootSecret`. A single fixed
    // width across both provisioning paths means the wire-format
    // key-ID prefix never needs to be truncated.
    expect(keyIDBytes.length).toBe(32);
    expect(key).toBeDefined();
    expect(key.type).toBe('secret');
    expect(changes.length).toBeGreaterThan(0);
  });

  test('prepareKey() stages a bounded random key without live mutation', async () => {
    const keychain = new AutomergeKeychain();
    const before = keychain.history();
    const prepared = await keychain.prepareKey();
    const stableId = new Uint8Array(prepared.keyId);
    expect(stableId).toHaveLength(32);
    expect(prepared.key.algorithm).toMatchObject({
      name: 'AES-GCM',
      length: 256,
    });
    expect(keychain.history()).toEqual(before);
    expect(await keychain.keys()).toHaveLength(0);

    const independent = new AutomergeKeychain();
    await independent.addEpochKey(stableId, prepared.key);
    independent.merge(prepared.currentKeyChange!);
    expect((await independent.keys()).map(([id]) => id)).toEqual([stableId]);

    prepared.keyId.fill(0xff);
    prepared.commit();
    expect((await keychain.current())[0]).toEqual(stableId);
    expect(keychain.getKey(stableId)).toBe(prepared.key);
    expect(() => prepared.commit()).toThrow(
      'Prepared epoch key was already committed',
    );
  });

  test('prepareKey() commit rejects a stale live base', async () => {
    const keychain = new AutomergeKeychain();
    const prepared = await keychain.prepareKey();
    await keychain.add();

    expect(() => prepared.commit()).toThrow(
      'Keychain changed while epoch key was staged',
    );
    expect(await keychain.keys()).toHaveLength(1);
  });

  test('keys() returns all added keys', async () => {
    const keychain = new AutomergeKeychain();
    await keychain.add();
    await keychain.add();

    const keys = await keychain.keys();
    expect(keys).toHaveLength(2);
    for (const [idBytes, key] of keys) {
      expect(idBytes).toBeInstanceOf(Uint8Array);
      expect(idBytes.length).toBe(32);
      expect(key).toBeDefined();
    }
  });

  test('history() / merge() - export changes and merge into a fresh keychain', async () => {
    const kc1 = new AutomergeKeychain();
    const [id1] = await kc1.add();
    const [id2] = await kc1.add();

    const exported = kc1.history();
    expect(exported.length).toBeGreaterThan(0);

    // Every AutomergeKeychain seeds its empty `keys: []` array under a
    // shared deterministic actor (KEYCHAIN_SEED_ACTOR) and then clones to
    // a per-instance random actor for subsequent writes. That makes the
    // initial empty-array op identical across instances, so full-history
    // merge into a fresh keychain is deterministic and preserves entries.
    const kc2 = new AutomergeKeychain();
    kc2.merge(exported);
    const ids = (await kc2.keys()).map(([id]) => Array.from(id));
    expect(ids).toContainEqual(Array.from(id1));
    expect(ids).toContainEqual(Array.from(id2));
  });

  test('prepareMerge detaches caller changes and commits independently of returned buffers', async () => {
    const source = new AutomergeKeychain();
    const [keyId] = await source.add();
    const callerChanges = source.history().map(
      (change) => new Uint8Array(change),
    );
    const receiver = new AutomergeKeychain();
    const prepared = receiver.prepareMerge(callerChanges);

    expect(prepared.changes).not.toBe(callerChanges);
    expect(prepared.changes[0]).not.toBe(callerChanges[0]);
    const stagedFirstByte = prepared.changes[0][0];
    callerChanges[0].fill(stagedFirstByte ^ 0xff);
    callerChanges.length = 0;
    expect(prepared.changes.length).toBeGreaterThan(0);
    expect(prepared.changes[0][0]).toBe(stagedFirstByte);

    prepared.changes[0].fill(stagedFirstByte ^ 0xff);
    prepared.changes.length = 0;
    prepared.commit();
    expect((await receiver.keys()).map(([id]) => Array.from(id))).toContainEqual(
      Array.from(keyId),
    );
  });

  test('seed history is deterministic across creation times', () => {
    const now = jest.spyOn(Date, 'now');
    try {
      now.mockReturnValue(1_000);
      const source = new AutomergeKeychain();

      now.mockReturnValue(3_000);
      const receiver = new AutomergeKeychain();

      const sourceHistory = source.history();
      const receiverHistory = receiver.history();
      expect(sourceHistory.length).toBeGreaterThan(0);
      expect(receiverHistory).toEqual(sourceHistory);
      expect(() => receiver.merge(sourceHistory)).not.toThrow();
    } finally {
      now.mockRestore();
    }
  });

  test('getKey() retrieves a cached key by ID', async () => {
    const keychain = new AutomergeKeychain();
    const [keyIDBytes, originalKey] = await keychain.add();

    const retrieved = keychain.getKey(keyIDBytes);
    expect(retrieved).toBeDefined();
    expect(retrieved).toBe(originalKey); // Same reference from cache
  });

  test('getKey() returns undefined for unknown ID', () => {
    const keychain = new AutomergeKeychain();
    const unknownID = new Uint8Array(32);
    unknownID.fill(0xff);
    const result = keychain.getKey(unknownID);
    expect(result).toBeUndefined();
  });

  test('currentKeyChange() reuses replay-safe history for a one-key keychain', async () => {
    const source = new AutomergeKeychain();
    const [id] = await source.add();

    const first = await source.currentKeyChange();
    const repeated = await source.currentKeyChange();
    expect(repeated).toEqual(first);
    const restored = new AutomergeKeychain();
    restored.merge(source.history());
    expect(await restored.currentKeyChange()).toEqual(first);

    const receiver = new AutomergeKeychain();
    receiver.merge(first);
    receiver.merge(repeated);
    expect(await receiver.currentKeyChange()).toEqual(first);
    expect((await receiver.keys()).map(([keyID]) => keyID)).toEqual([id]);
  });

  test('currentKeyChange() rejects a later key rather than synthesizing a fresh actor', async () => {
    const source = new AutomergeKeychain();
    await source.add();
    await source.add();
    const before = source.history().map((entry) => Array.from(entry));

    await expect(source.currentKeyChange()).rejects.toThrow(
      'Automerge cannot export the current key replay-safely',
    );
    expect(source.history().map((entry) => Array.from(entry))).toEqual(before);
  });

  test('historySince() reuses replay-safe history at the first key', async () => {
    const source = new AutomergeKeychain();
    const [id1] = await source.add();
    const [id2] = await source.add();
    const [id3] = await source.add();

    const first = await source.historySince(id1);
    const repeated = await source.historySince(id1);
    expect(repeated).toEqual(first);
    const restored = new AutomergeKeychain();
    restored.merge(source.history());
    const restoredHistory = await restored.historySince(id1);
    expect(restoredHistory).toEqual(first);

    const receiver = new AutomergeKeychain();
    receiver.merge(first);
    receiver.merge(repeated);
    receiver.merge(restoredHistory);
    const keys = await receiver.keys();
    expect(keys).toHaveLength(3);
    const ids = keys.map(([id]) => Array.from(id));
    expect(ids).toContainEqual(Array.from(id1));
    expect(ids).toContainEqual(Array.from(id2));
    expect(ids).toContainEqual(Array.from(id3));
  });

  test('historySince() repeatedly rejects an unknown boundary without mutation', async () => {
    const source = new AutomergeKeychain();
    await source.add();
    await source.add();
    const before = source.history().map((entry) => Array.from(entry));

    const unknownID = new Uint8Array(32).fill(0xff);
    await expect(source.historySince(unknownID)).rejects.toThrow(
      'Unknown keychain history boundary',
    );
    await expect(source.historySince(unknownID)).rejects.toThrow(
      'Unknown keychain history boundary',
    );
    expect(source.history().map((entry) => Array.from(entry))).toEqual(before);
  });

  test('historySince() rejects a later boundary rather than synthesizing fresh actors', async () => {
    const source = new AutomergeKeychain();
    await source.add();
    const [laterID] = await source.add();

    await expect(source.historySince(laterID)).rejects.toThrow(
      'Automerge cannot export this keychain suffix replay-safely',
    );
  });

  test('addEpochKey() rejects a duplicate ID without poisoning its cache', async () => {
    const source = new AutomergeKeychain();
    const [id, key] = await source.add();
    const replacement = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );

    await expect(source.addEpochKey(id, replacement)).rejects.toThrow(
      'Duplicate keychain key ID',
    );
    expect(source.getKey(id)).toBe(key);
    expect(await source.keys()).toHaveLength(1);
  });

  // ───────────────────────────────────────────────────────────────────
  // BeeKEM PathUpdate compatibility: the flow installs
  // epoch keys via addEpochKey(...) using the FULL 32-byte HKDF output
  // (no truncation). The keychain MUST store the key under a cache-key
  // form that round-trips with getKey() on the exact same 32 bytes.
  // Earlier revisions stored 32-byte epoch IDs under hex but, for
  // 16-byte inputs (the result of truncating to the old `keyIDLength`),
  // looked up under UUID format -- a deterministic cache miss on every
  // post-rotation lookup. These tests pin the round-trip behaviour.
  // ───────────────────────────────────────────────────────────────────

  test('addEpochKey() round-trips through getKey() for a 32-byte epoch ID', async () => {
    const keychain = new AutomergeKeychain();
    const epochId = crypto.getRandomValues(new Uint8Array(32));
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    await keychain.addEpochKey(epochId, key);

    // The exact 32-byte ID that went in must come back out of getKey.
    // A failure here means the epoch ID bytes did not round-trip through
    // the hexadecimal cache-key encoding.
    const retrieved = keychain.getKey(epochId);
    expect(retrieved).toBe(key);

    // current() must report the same 32-byte ID (and key) so
    // `_makeChange` writes the correct wire-format key-ID prefix.
    const [currentID, currentKey] = await keychain.current();
    expect(currentID.length).toBe(32);
    expect(Array.from(currentID)).toEqual(Array.from(epochId));
    expect(currentKey).toBe(key);
  });

  test.each([31, 33])(
    'prepareEpochKey() rejects a %i-byte epoch ID without mutating state',
    async (byteLength) => {
      const keychain = new AutomergeKeychain();
      const historyBefore = keychain
        .history()
        .map((binaryChange) => new Uint8Array(binaryChange));
      const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt'],
      );

      await expect(
        keychain.prepareEpochKey(new Uint8Array(byteLength), key),
      ).rejects.toThrow('Epoch ID has an invalid length or backing buffer');
      expect(keychain.history()).toEqual(historyBefore);
      expect(await keychain.keys()).toHaveLength(0);
    },
  );

  test('addEpochKey() rejects non-AES document keys without mutation', async () => {
    const keychain = new AutomergeKeychain();
    const before = keychain.history();
    const hmacKey = await crypto.subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      true,
      ['sign', 'verify'],
    );

    await expect(
      keychain.addEpochKey(new Uint8Array(32).fill(3), hmacKey),
    ).rejects.toThrow('Document key must be a 256-bit AES-GCM key');
    expect(keychain.history()).toEqual(before);
    expect(await keychain.keys()).toHaveLength(0);
  });

  test.each([31, 33])(
    'addEpochKey() rejects a %i-byte epoch ID without mutating state',
    async (byteLength) => {
      const keychain = new AutomergeKeychain();
      const historyBefore = keychain
        .history()
        .map((binaryChange) => new Uint8Array(binaryChange));
      const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt'],
      );

      await expect(
        keychain.addEpochKey(new Uint8Array(byteLength), key),
      ).rejects.toThrow('Epoch ID has an invalid length or backing buffer');
      expect(keychain.history()).toEqual(historyBefore);
      expect(await keychain.keys()).toHaveLength(0);
    },
  );

  test('prepareEpochKey() accepts cross-realm bytes and snapshots them before awaiting', async () => {
    const keychain = new AutomergeKeychain();
    const epochId = runInNewContext(
      'new Uint8Array(32).fill(7)',
    ) as Uint8Array;
    const expectedEpochId = new Uint8Array(32).fill(7);
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );

    expect(epochId).not.toBeInstanceOf(Uint8Array);
    const preparing = keychain.prepareEpochKey(epochId, key);
    epochId.fill(9);
    const prepared = await preparing;
    prepared.commit();

    const [currentId, currentKey] = await keychain.current();
    expect(currentId).toEqual(expectedEpochId);
    expect(currentKey).toBe(key);
    expect(keychain.getKey(expectedEpochId)).toBe(key);
  });

  test.each([
    ['another typed-array kind', new Uint16Array(16)],
    [
      'a Uint8Array lookalike',
      {
        byteLength: 32,
        length: 32,
        [Symbol.toStringTag]: 'Uint8Array',
      },
    ],
  ])('prepareEpochKey() rejects %s', async (_label, epochId) => {
    const keychain = new AutomergeKeychain();
    const historyBefore = keychain
      .history()
      .map((binaryChange) => new Uint8Array(binaryChange));
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );

    await expect(
      keychain.prepareEpochKey(epochId as unknown as Uint8Array, key),
    ).rejects.toThrow(/Epoch ID/);
    expect(keychain.history()).toEqual(historyBefore);
    expect(await keychain.keys()).toHaveLength(0);
  });

  test('prepareEpochKey() rejects SharedArrayBuffer-backed bytes', async () => {
    if (typeof SharedArrayBuffer === 'undefined') return;
    const keychain = new AutomergeKeychain();
    const historyBefore = keychain
      .history()
      .map((binaryChange) => new Uint8Array(binaryChange));
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );

    await expect(
      keychain.prepareEpochKey(
        new Uint8Array(new SharedArrayBuffer(32)),
        key,
      ),
    ).rejects.toThrow('Epoch ID has an invalid length or backing buffer');
    expect(keychain.history()).toEqual(historyBefore);
    expect(await keychain.keys()).toHaveLength(0);
  });

  test('prepareEpochKey() exposes an exact replay-safe current projection', async () => {
    const keychain = new AutomergeKeychain();
    const firstId = crypto.getRandomValues(new Uint8Array(32));
    const firstKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const first = await keychain.prepareEpochKey(firstId, firstKey);
    expect(first.currentKeyChange).toBeDefined();
    const receiver = new AutomergeKeychain();
    receiver.merge(first.currentKeyChange!);
    receiver.merge(first.currentKeyChange!);
    expect((await receiver.keys()).map(([id]) => id)).toEqual([firstId]);
    first.commit();

    const nextKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const nextId = crypto.getRandomValues(new Uint8Array(32));
    const next = await keychain.prepareEpochKey(nextId, nextKey);
    expect(next.currentKeyChange).toBeDefined();
    const narrowReceiver = new AutomergeKeychain();
    narrowReceiver.merge(next.currentKeyChange!);
    narrowReceiver.merge(next.currentKeyChange!);
    expect((await narrowReceiver.keys()).map(([id]) => id)).toEqual([nextId]);
  });

  test('prepareMerge() rejects non-canonical entries before live state or cache mutation', async () => {
    const validKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const serialized = await serializeKey(validKey);
    const invalidEntries: unknown[] = [
      ['aa'.repeat(16), serialized],
      ['AB'.repeat(32), serialized],
      ['ab'.repeat(32), 'not-a-key'],
      ['ab'.repeat(32), `${'A'.repeat(42)}B=`],
      ['ab'.repeat(32), serialized, 'extra'],
      ['ab'.repeat(32), 7],
    ];

    for (const entry of invalidEntries) {
      const malformed = appendTestKeychainEntry(
        newTestKeychainDoc(),
        entry as [string, string],
      );
      const receiver = new AutomergeKeychain();
      expect(() =>
        receiver.prepareMerge(getAllAutomergeChanges(malformed)),
      ).toThrow(/Invalid (keychain entry|serialized keychain key)/);
      expect(await receiver.keys()).toHaveLength(0);
      expect(receiver.getKey(new Uint8Array(32))).toBeUndefined();
    }
  });

  test('prepareMerge() rejects duplicate IDs before they can poison cached key material', async () => {
    const firstKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const secondKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const id = new Uint8Array(32).fill(5);
    const idHex = Array.from(id, (byte) =>
      byte.toString(16).padStart(2, '0'),
    ).join('');
    let duplicate = appendTestKeychainEntry(newTestKeychainDoc(), [
      idHex,
      await serializeKey(firstKey),
    ]);
    duplicate = appendTestKeychainEntry(duplicate, [
      idHex,
      await serializeKey(secondKey),
    ]);
    const receiver = new AutomergeKeychain();

    expect(() =>
      receiver.prepareMerge(getAllAutomergeChanges(duplicate)),
    ).toThrow('Duplicate keychain key ID');
    expect(await receiver.keys()).toHaveLength(0);
    expect(receiver.getKey(id)).toBeUndefined();
  });

  test('prepareMerge() rejects delete, rewrite, reorder, and unrelated operations', async () => {
    const firstKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const secondKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const firstEntry: [string, string] = [
      '11'.repeat(32),
      await serializeKey(firstKey),
    ];
    const secondEntry: [string, string] = [
      '22'.repeat(32),
      await serializeKey(secondKey),
    ];
    const firstDoc = appendTestKeychainEntry(newTestKeychainDoc(), firstEntry);
    const twoKeyDoc = appendTestKeychainEntry(firstDoc, secondEntry);

    const deleted = automergeChange(twoKeyDoc, (doc) => {
      doc.keys.splice(0, 1);
    });
    expect(() =>
      new AutomergeKeychain().prepareMerge(getAllAutomergeChanges(deleted)),
    ).toThrow(/non-append|unrelated metadata or operations/);

    const rewritten = automergeChange(automergeClone(firstDoc), (doc) => {
      doc.keys[0][1] = secondEntry[1];
    });
    expect(() =>
      new AutomergeKeychain().prepareMerge(getAllAutomergeChanges(rewritten)),
    ).toThrow(/non-append|rewrite|unrelated metadata or operations/);

    const reorderBase = appendTestKeychainEntry(
      newTestKeychainDoc(),
      firstEntry,
    );
    const receiver = new AutomergeKeychain();
    receiver.merge(getAllAutomergeChanges(reorderBase));
    const reordered = automergeChange(automergeClone(reorderBase), (doc) => {
      doc.keys.splice(0, 0, secondEntry);
    });
    expect(() =>
      receiver.prepareMerge(getAutomergeChanges(reorderBase, reordered)),
    ).toThrow(/non-append|append without rewriting entries/);

    const unrelatedBase = appendTestKeychainEntry(
      newTestKeychainDoc(),
      firstEntry,
    );
    const unrelated = automergeChange(automergeClone(unrelatedBase), (doc) => {
      doc.unrelated = 'not keychain state';
    });
    expect(() =>
      new AutomergeKeychain().prepareMerge(getAllAutomergeChanges(unrelated)),
    ).toThrow(/Invalid Automerge keychain document|unrelated operation/);

    const metadata = automergeChange(
      newTestKeychainDoc(),
      'unrelated retained metadata',
      (doc) => {
        doc.keys.push(firstEntry);
      },
    );
    expect(() =>
      new AutomergeKeychain().prepareMerge(getAllAutomergeChanges(metadata)),
    ).toThrow('Keychain history contains unrelated metadata');

    const concurrent = automergeMerge(
      appendTestKeychainEntry(newTestKeychainDoc(), firstEntry),
      appendTestKeychainEntry(newTestKeychainDoc(), secondEntry),
    );
    expect(() =>
      new AutomergeKeychain().prepareMerge(
        getAllAutomergeChanges(concurrent),
      ),
    ).toThrow('Keychain history is not a linear append sequence');
  });

  test('history projections reject tombstoned historical key material', async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const serialized = await serializeKey(key);
    let tombstoned = appendTestKeychainEntry(newTestKeychainDoc(), [
      '11'.repeat(32),
      serialized,
    ]);
    tombstoned = automergeChange(tombstoned, (doc) => {
      doc.keys.splice(0, 1);
    });
    tombstoned = appendTestKeychainEntry(tombstoned, [
      '22'.repeat(32),
      serialized,
    ]);
    const compromised = new AutomergeKeychain();
    Object.defineProperty(compromised, '_keychain', {
      value: tombstoned,
      writable: true,
    });

    expect(() => compromised.history()).toThrow(
      /non-append|unrelated metadata or operations/,
    );
    await expect(compromised.stateCommitment()).rejects.toThrow(
      /non-append|unrelated metadata or operations/,
    );
    await expect(compromised.keys()).rejects.toThrow(
      /non-append|unrelated metadata or operations/,
    );
    await expect(compromised.current()).rejects.toThrow(
      /non-append|unrelated metadata or operations/,
    );
    await expect(compromised.currentKeyChange()).rejects.toThrow(
      /non-append|unrelated metadata or operations/,
    );
    await expect(
      compromised.historySince(new Uint8Array(32).fill(0x22)),
    ).rejects.toThrow(/non-append|unrelated metadata or operations/);
  });

  test('prepareMerge() hydrates detached staged keys and transfers them only on commit', async () => {
    const source = new AutomergeKeychain();
    const [firstId] = await source.add();
    const [currentId] = await source.add();
    const receiver = new AutomergeKeychain();
    const prepared = receiver.prepareMerge(source.history());

    expect(prepared.currentKeyId).toEqual(currentId);
    prepared.keyIds[0].fill(0xff);
    prepared.currentKeyId!.fill(0xee);
    expect(await prepared.stateCommitment!()).toEqual(
      await source.stateCommitment(),
    );
    const hydrated = await prepared.hydrateKeys();
    expect(hydrated.map(([id]) => id)).toEqual([firstId, currentId]);
    expect(prepared.getKey(firstId)).toBe(hydrated[0][1]);
    expect(prepared.getKey(currentId)).toBe(hydrated[1][1]);
    expect(await receiver.keys()).toHaveLength(0);
    expect(receiver.getKey(currentId)).toBeUndefined();

    prepared.commit();
    expect(receiver.getKey(firstId)).toBe(hydrated[0][1]);
    expect(receiver.getKey(currentId)).toBe(hydrated[1][1]);
    expect((await receiver.current())[0]).toEqual(currentId);
    expect(await receiver.stateCommitment()).toEqual(
      await source.stateCommitment(),
    );
  });

  test('prepareMerge() accepts cross-realm bytes and rejects shared backing', async () => {
    const source = new AutomergeKeychain();
    const [id] = await source.add();
    const history = source.history();
    const crossRealm = history.map(
      (binaryChange) =>
        runInNewContext(
          `new Uint8Array([${Array.from(binaryChange).join(',')}])`,
        ) as Uint8Array,
    );
    expect(crossRealm[0]).not.toBeInstanceOf(Uint8Array);
    const receiver = new AutomergeKeychain();
    receiver.prepareMerge(crossRealm).commit();
    expect((await receiver.keys()).map(([keyID]) => keyID)).toEqual([id]);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const shared = new Uint8Array(
        new SharedArrayBuffer(history[0].byteLength),
      );
      shared.set(history[0]);
      expect(() => new AutomergeKeychain().prepareMerge([shared])).toThrow(
        'Automerge keychain change has an invalid length or backing buffer',
      );
    }
  });

  test('merge coalesces independently authored identical histories and rejects material conflicts', async () => {
    const epochId = new Uint8Array(32).fill(0x44);
    const epochKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const left = new AutomergeKeychain();
    const right = new AutomergeKeychain();
    await left.addEpochKey(epochId, epochKey);
    await right.addEpochKey(epochId, epochKey);
    const originalLeftHistory = left.history();
    const originalRightHistory = right.history();
    expect(originalLeftHistory).not.toEqual(originalRightHistory);
    expect(await left.stateCommitment()).toEqual(
      await right.stateCommitment(),
    );
    left.merge(originalRightHistory);
    right.merge(originalLeftHistory);
    expect(await left.keys()).toHaveLength(1);
    expect(await right.keys()).toHaveLength(1);
    expect(left.history()).toEqual(right.history());
    const nextId = new Uint8Array(32).fill(0x55);
    await right.addEpochKey(nextId, epochKey);

    left.merge(right.history());
    expect((await left.keys()).map(([id]) => id)).toEqual([epochId, nextId]);

    const conflicting = new AutomergeKeychain();
    const conflictingKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    await conflicting.addEpochKey(epochId, conflictingKey);
    expect(() => left.prepareMerge(conflicting.history())).toThrow(
      /Duplicate keychain key ID|append/,
    );
    expect((await left.keys()).map(([id]) => id)).toEqual([epochId, nextId]);
  });

  test('requires full history after independently authored epoch operations diverge', async () => {
    const founder = new AutomergeKeychain();
    await founder.add();
    const sender = new AutomergeKeychain();
    const receiver = new AutomergeKeychain();
    sender.merge(founder.history());
    receiver.merge(founder.history());
    const epochId = new Uint8Array(32).fill(0x66);
    const epochKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    await sender.addEpochKey(epochId, epochKey);
    await receiver.addEpochKey(epochId, epochKey);
    expect(sender.history()).not.toEqual(receiver.history());
    expect(await sender.stateCommitment()).toEqual(
      await receiver.stateCommitment(),
    );
    const [, , incremental] = await sender.add();

    expect(() => receiver.prepareMerge(incremental)).toThrow(
      /unresolved|Invalid Automerge keychain (?:operation history|document)/,
    );
    receiver.merge(sender.history());
    expect(await receiver.keys()).toHaveLength(3);
  });

  test('context-gated standalone append rejects rollback and binds predecessor and new ID', async () => {
    const keyA = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const keyB = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const keyC = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const idA = new Uint8Array(32).fill(0xa1);
    const idB = new Uint8Array(32).fill(0xb2);
    const idC = new Uint8Array(32).fill(0xc3);
    const receiver = new AutomergeKeychain();
    await receiver.addEpochKey(idA, keyA);
    const projectionSource = new AutomergeKeychain();
    const stagedB = await projectionSource.prepareEpochKey(idB, keyB);
    const projectionB = stagedB.currentKeyChange!;

    expect(() => receiver.prepareMerge(projectionB)).toThrow(
      'Standalone keychain history is not an append-only view',
    );
    expect(() =>
      receiver.prepareAppend([projectionB[1]], {
        expectedPreviousKeyId: idA,
        expectedNewKeyId: idB,
      }),
    ).toThrow('canonical standalone single-key projection');
    expect(() =>
      receiver.prepareAppend([...projectionB].reverse(), {
        expectedPreviousKeyId: idA,
        expectedNewKeyId: idB,
      }),
    ).toThrow('canonical standalone single-key projection');
    expect(() =>
      receiver.prepareAppend([...projectionB, projectionB[1]], {
        expectedPreviousKeyId: idA,
        expectedNewKeyId: idB,
      }),
    ).toThrow('canonical standalone single-key projection');
    expect(() =>
      (receiver.prepareMerge as (...args: unknown[]) => unknown)(projectionB, {
        expectedPreviousKeyId: idA,
        expectedNewKeyId: idB,
      }),
    ).toThrow('Standalone keychain history is not an append-only view');
    expect(() =>
      receiver.prepareAppend(projectionB, {
        expectedPreviousKeyId: idC,
        expectedNewKeyId: idB,
      }),
    ).toThrow('Keychain append predecessor does not match current key');
    expect(() =>
      receiver.prepareAppend(projectionB, {
        expectedPreviousKeyId: idA,
        expectedNewKeyId: idC,
      }),
    ).toThrow('Keychain projection does not match expected new key');
    expect(() =>
      receiver.prepareAppend(projectionB, {
        expectedPreviousKeyId: new Uint8Array(31),
        expectedNewKeyId: idB,
      }),
    ).toThrow('Key ID has an invalid length or backing buffer');
    expect(() =>
      receiver.prepareAppend(projectionB, {
        expectedPreviousKeyId: {
          byteLength: 32,
          buffer: new ArrayBuffer(32),
        } as Uint8Array,
        expectedNewKeyId: idB,
      }),
    ).toThrow('Key ID must be a genuine Uint8Array');

    const stale = receiver.prepareAppend(projectionB, {
      expectedPreviousKeyId: idA,
      expectedNewKeyId: idB,
    });
    receiver.prepareMerge(receiver.history()).commit();
    expect(() => stale.commit()).toThrow(
      'Keychain changed while merge was staged',
    );

    const previousIntent = runInNewContext(
      `new Uint8Array(32).fill(${idA[0]})`,
    ) as Uint8Array;
    const newIntent = runInNewContext(
      `new Uint8Array(32).fill(${idB[0]})`,
    ) as Uint8Array;
    expect(previousIntent).not.toBeInstanceOf(Uint8Array);
    expect(newIntent).not.toBeInstanceOf(Uint8Array);
    const valid = receiver.prepareAppend(projectionB, {
      expectedPreviousKeyId: previousIntent,
      expectedNewKeyId: newIntent,
    });
    const appendCommitment = await valid.stateCommitment!();
    previousIntent.fill(0);
    newIntent.fill(0);
    valid.commit();
    expect((await receiver.keys()).map(([id]) => id)).toEqual([idA, idB]);
    expect(await receiver.stateCommitment()).toEqual(appendCommitment);

    receiver.prepareMerge(projectionB).commit();
    const replayedCommitment = await receiver.stateCommitment();
    const replay = receiver.prepareAppend(projectionB, {
      expectedPreviousKeyId: idA,
      expectedNewKeyId: idB,
    });
    expect(replay.keyIds).toEqual([idA, idB]);
    expect(replay.currentKeyId).toEqual(idB);
    expect(await replay.stateCommitment!()).toEqual(replayedCommitment);
    replay.commit();
    expect((await receiver.keys()).map(([id]) => id)).toEqual([idA, idB]);

    const conflictingB = await new AutomergeKeychain().prepareEpochKey(
      idB,
      keyC,
    );
    expect(() =>
      receiver.prepareAppend(conflictingB.currentKeyChange!, {
        expectedPreviousKeyId: idA,
        expectedNewKeyId: idB,
      }),
    ).toThrow('Keychain append replay does not match live history');

    const stagedC = await new AutomergeKeychain().prepareEpochKey(idC, keyC);
    receiver
      .prepareAppend(stagedC.currentKeyChange!, {
        expectedPreviousKeyId: idB,
        expectedNewKeyId: idC,
      })
      .commit();
    expect(() =>
      receiver.prepareAppend(projectionB, {
        expectedPreviousKeyId: idA,
        expectedNewKeyId: idB,
      }),
    ).toThrow('Keychain append predecessor does not match current key');
    expect((await receiver.current())[0]).toEqual(idC);
  });

  test('enforces the keychain epoch limit before over-limit mutations', async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const serialized = await serializeKey(key);
    let source = newTestKeychainDoc();
    for (let index = 0; index < MAX_KEYCHAIN_EPOCHS; index++) {
      source = appendTestKeychainEntry(source, [
        index.toString(16).padStart(64, '0'),
        serialized,
      ]);
    }
    const receiver = new AutomergeKeychain();
    const atLimit = receiver.prepareMerge(getAllAutomergeChanges(source));
    expect(atLimit.keyIds).toHaveLength(MAX_KEYCHAIN_EPOCHS);
    atLimit.commit();
    const before = receiver.history();

    const overflow = appendTestKeychainEntry(automergeClone(source), [
      MAX_KEYCHAIN_EPOCHS.toString(16).padStart(64, '0'),
      serialized,
    ]);
    expect(() =>
      receiver.prepareMerge(getAutomergeChanges(source, overflow)),
    ).toThrow('Keychain exceeds the supported epoch limit');
    await expect(
      receiver.addEpochKey(new Uint8Array(32).fill(0xff), key),
    ).rejects.toThrow('Keychain exceeds the supported epoch limit');
    await expect(receiver.prepareKey()).rejects.toThrow(
      'Keychain exceeds the supported epoch limit',
    );
    const previousId = new Uint8Array(32);
    const overflowId = new Uint8Array(32);
    new DataView(previousId.buffer).setUint32(
      28,
      MAX_KEYCHAIN_EPOCHS - 1,
    );
    new DataView(overflowId.buffer).setUint32(28, MAX_KEYCHAIN_EPOCHS);
    const overflowProjection = await new AutomergeKeychain().prepareEpochKey(
      overflowId,
      key,
    );
    expect(() =>
      receiver.prepareAppend(overflowProjection.currentKeyChange!, {
        expectedPreviousKeyId: previousId,
        expectedNewKeyId: overflowId,
      }),
    ).toThrow('Keychain exceeds the supported epoch limit');
    expect(receiver.history()).toEqual(before);
  });

  test('addEpochKey() output merges into a fresh keychain and getKey() works there too', async () => {
    // Models the surviving-reader case: writer installs the new
    // key via addEpochKey on their local keychain AND propagates
    // the keychain CRDT changes to peers. After a peer merges the
    // change, `getKey()` for the same 32-byte epoch ID must succeed
    // -- this is what unblocks post-rotation decrypt on the
    // surviving-reader side.
    const sender = new AutomergeKeychain();
    const epochId = crypto.getRandomValues(new Uint8Array(32));
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const changes = await sender.addEpochKey(epochId, key);

    const receiver = new AutomergeKeychain();
    receiver.merge(changes);

    // Touch keys() so the deserialized AES-GCM key is imported and
    // cached -- getKey() is a pure cache lookup (see jsdoc).
    const receiverKeys = await receiver.keys();
    expect(receiverKeys).toHaveLength(1);
    expect(Array.from(receiverKeys[0][0])).toEqual(Array.from(epochId));

    const retrieved = receiver.getKey(epochId);
    expect(retrieved).toBeDefined();

    // Same raw key material on both sides: this is the BeeKEM-rotation
    // invariant the test is here to defend.
    const rawSender = new Uint8Array(
      await crypto.subtle.exportKey('raw', key),
    );
    const rawReceiver = new Uint8Array(
      await crypto.subtle.exportKey('raw', retrieved!),
    );
    expect(rawReceiver).toEqual(rawSender);
  });
});

describe('AutomergeKeychainProvider', () => {
  test('initialize() returns a new AutomergeKeychain with keyIDLength=32', () => {
    const provider = new AutomergeKeychainProvider();
    const keychain = provider.initialize();
    expect(keychain).toBeInstanceOf(AutomergeKeychain);
    expect(provider.keyIDLength).toBe(32);
  });
});

// ─── AutomergeJSONSerializer ────────────────────────────────────────

describe('AutomergeJSONSerializer', () => {
  const serializer = new AutomergeJSONSerializer();
  const SHALLOW_HISTORY_NODE_COUNT = 4_096;

  function nestedTree(depth: number): CRDTChangeNode<BinaryChange[]> {
    const root: CRDTChangeNode<BinaryChange[]> = { kind: 'document' };
    let cursor = root;
    for (let index = 1; index < depth; index++) {
      const child: CRDTChangeNode<BinaryChange[]> = { kind: 'document' };
      cursor.children = { [`cid-${index}`]: child };
      cursor = child;
    }
    return root;
  }

  function shallowTree(nodeCount: number): CRDTChangeNode<BinaryChange[]> {
    const root: CRDTChangeNode<BinaryChange[]> = { kind: 'document' };
    const children: Record<string, CRDTChangeNode<BinaryChange[]>> = {};
    for (let index = 1; index < nodeCount; index++) {
      children[`cid-${index}`] = { kind: 'document' };
    }
    root.children = children;
    return root;
  }

  test('preserves nested sync-message signing bytes across the wire', () => {
    const unsignedMessage = {
      documentId: 'signed-doc',
      changeId: 'root-cid',
      changes: {
        kind: 'document' as const,
        change: [new Uint8Array([1, 2, 3])],
        children: {
          'parent-cid': {
            kind: 'writer' as const,
            change: [new Uint8Array([4, 5, 6])],
          },
        },
      },
    };
    const senderSigningBytes = serializer.serializeSyncMessage(unsignedMessage);
    const wire = serializer.serializeSyncMessage({
      ...unsignedMessage,
      signature: 'test-signature',
    });
    const received = serializer.deserializeSyncMessage(wire);
    const { signature: _signature, ...receivedUnsignedMessage } = received;
    const receiverVerificationBytes = serializer.serializeSyncMessage(
      receivedUnsignedMessage,
    );

    expect(receiverVerificationBytes).toEqual(senderSigningBytes);
  });

  test('round-trips the maximum accepted nesting without overflowing JSON serialization', () => {
    const genericSerialize = jest.spyOn(serializer, 'serialize');
    const wire = serializer.serializeSyncMessage({
      documentId: 'maximum-depth',
      changes: nestedTree(MAX_MERKLE_DAG_DEPTH),
    });
    const restored = serializer.deserializeSyncMessage(wire);

    expect(serializer.serializeSyncMessage(restored)).toEqual(wire);
    expect(genericSerialize).not.toHaveBeenCalled();
    genericSerialize.mockRestore();
    expect(() =>
      serializer.serializeSyncMessage({
        documentId: 'over-maximum-depth',
        changes: nestedTree(MAX_MERKLE_DAG_DEPTH + 1),
      }),
    ).toThrow(/maximum depth/);
  });

  test('round-trips 4096 shallow history nodes with stable wire bytes', () => {
    const wire = serializer.serializeSyncMessage({
      documentId: 'wide-history',
      changes: shallowTree(SHALLOW_HISTORY_NODE_COUNT),
    });
    const restored = serializer.deserializeSyncMessage(wire);

    expect(serializer.serializeSyncMessage(restored)).toEqual(wire);
    expect(
      Object.keys(
        restored.changes!.children as Record<
          string,
          CRDTChangeNode<BinaryChange[]>
        >,
      ),
    ).toHaveLength(SHALLOW_HISTORY_NODE_COUNT - 1);
  });

  test('preserves the existing sync-message wire bytes', () => {
    const wire = serializer.serializeSyncMessage({
      documentId: 'wire-compatibility',
      changes: {
        kind: 'document',
        change: [new Uint8Array([1, 2])],
        children: { cid: { kind: 'writer' } },
      },
    });

    expect(new TextDecoder().decode(wire)).toBe(
      '{"documentId":"wire-compatibility","changes":{"kind":"document","change":["AQI="],"children":{"cid":{"kind":"writer"}}}}',
    );
  });

  test('serializeChangeBlock/deserializeChangeBlock round-trip with keyID', () => {
    const provider = new AutomergeProvider<{ title: string }>();
    const doc = provider.newDocument();
    const [, changes] = provider.localChange(doc, '', (d) => {
      d.title = 'test';
    });
    const block = {
      changes,
      nonce: new Uint8Array([10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]),
      keyID: 'epoch-key-abc-123',
    };
    const serialized = serializer.serializeChangeBlock(block);
    const deserialized = serializer.deserializeChangeBlock(serialized);
    expect(deserialized.keyID).toBe('epoch-key-abc-123');
    expect(deserialized.nonce).toEqual(block.nonce);
    expect(deserialized.changes).toHaveLength(changes.length);
  });

  test('serializeChangeBlock/deserializeChangeBlock round-trip with blindIndexTokens', () => {
    const provider = new AutomergeProvider<{ title: string }>();
    const doc = provider.newDocument();
    const [, changes] = provider.localChange(doc, '', (d) => {
      d.title = 'test';
    });
    const block = {
      changes,
      nonce: new Uint8Array([10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]),
      blindIndexTokens: { 'field.name': 'hmac-token-abc', 'field.email': 'hmac-token-def' },
    };
    const serialized = serializer.serializeChangeBlock(block);
    const deserialized = serializer.deserializeChangeBlock(serialized);
    expect(deserialized.blindIndexTokens).toEqual({
      'field.name': 'hmac-token-abc',
      'field.email': 'hmac-token-def',
    });
  });

  test('serializeChangeBlock/deserializeChangeBlock round-trip with empty blindIndexTokens', () => {
    const provider = new AutomergeProvider<{ title: string }>();
    const doc = provider.newDocument();
    const [, changes] = provider.localChange(doc, '', (d) => {
      d.title = 'test';
    });
    const block = {
      changes,
      nonce: new Uint8Array([10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]),
      blindIndexTokens: {},
    };
    const serialized = serializer.serializeChangeBlock(block);
    const deserialized = serializer.deserializeChangeBlock(serialized);
    expect(deserialized.blindIndexTokens).toEqual({});
  });

  test('deserializeChangeBlock sanitizes dangerous keys in blindIndexTokens', () => {
    const provider = new AutomergeProvider<{ title: string }>();
    const doc = provider.newDocument();
    const [, changes] = provider.localChange(doc, '', (d) => {
      d.title = 'test';
    });
    // Serialize normally first to get valid changes encoding
    const validBlock = {
      changes,
      nonce: new Uint8Array([10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]),
    };
    const validSerialized = serializer.serializeChangeBlock(validBlock);
    // Parse, inject dangerous blindIndexTokens, re-serialize
    const parsed = JSON.parse(validSerialized);
    parsed.blindIndexTokens = {
      '__proto__': 'evil',
      'constructor': 'evil',
      'prototype': 'evil',
      'safe-key': 'safe-value',
    };
    const malicious = JSON.stringify(parsed);
    const deserialized = serializer.deserializeChangeBlock(malicious);
    expect(deserialized.blindIndexTokens).toEqual({ 'safe-key': 'safe-value' });
    expect(Object.prototype.hasOwnProperty.call(deserialized.blindIndexTokens, '__proto__')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(deserialized.blindIndexTokens, 'constructor')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(deserialized.blindIndexTokens, 'prototype')).toBe(false);
  });

  test('deserializeChangeBlock without keyID or blindIndexTokens omits them', () => {
    const provider = new AutomergeProvider<{ title: string }>();
    const doc = provider.newDocument();
    const [, changes] = provider.localChange(doc, '', (d) => {
      d.title = 'test';
    });
    const block = {
      changes,
      nonce: new Uint8Array([10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]),
    };
    const serialized = serializer.serializeChangeBlock(block);
    const deserialized = serializer.deserializeChangeBlock(serialized);
    expect(deserialized.keyID).toBeUndefined();
    expect(deserialized.blindIndexTokens).toBeUndefined();
  });

  // Build a sync-message Uint8Array wire payload directly from a JS object,
  // bypassing `serializeSyncMessage`'s type-safety so we can test that
  // `deserializeSyncMessage` rejects every defined-but-malformed shape of
  // `changes` rather than silently passing the falsy value through.
  function buildWire(obj: unknown): Uint8Array {
    return new TextEncoder().encode(JSON.stringify(obj));
  }

  test('deserializeSyncMessage rejects "changes: null" (validation bypass regression)', () => {
    const wire = buildWire({ documentId: 'doc', changes: null });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /expected a plain object.*got null/,
    );
  });

  test('deserializeSyncMessage rejects "changes: 0"', () => {
    const wire = buildWire({ documentId: 'doc', changes: 0 });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /expected a plain object.*got number/,
    );
  });

  test('deserializeSyncMessage rejects "changes: \\"\\"" (empty string)', () => {
    const wire = buildWire({ documentId: 'doc', changes: '' });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /expected a plain object.*got string/,
    );
  });

  test('deserializeSyncMessage accepts omitted "changes" field', () => {
    const wire = buildWire({ documentId: 'doc' });
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.changes).toBeUndefined();
  });

  test('preserves signed V4 full-load bytes across deserialize and reserialize', () => {
    // Mirror the intended V4 response construction order: signature already
    // has an insertion slot from the cached sync message, while
    // keychainChanges is appended after the V4 challenge.
    const message: any = {
      documentId: '/signed-load',
      changeId: 'ROOT',
      changes: {
        kind: 'document' as const,
        keyID: 'epoch-7',
        change: [new Uint8Array([1])],
        children: {
          PARENT: {
            kind: 'writer' as const,
            change: [new Uint8Array([2])],
          },
        },
      },
      signature: undefined,
    };
    message.tips = ['ROOT'];
    message.loadSecurityState = {
      version: 1 as const,
      controlHead: new Uint8Array(32),
      groupId: 'group',
      epoch: 1n,
      treeHash: new Uint8Array(32),
      confirmedTranscriptHash: new Uint8Array(32),
    };
    message.loadChallenge = new Uint8Array(32);
    message.keychainChanges = [new Uint8Array([3])];

    const { signature: _unsigned, ...signedPayload } = message;
    const expectedSignedBytes = serializer.serializeSyncMessage(signedPayload);
    message.signature = 'signature';
    const decoded = serializer.deserializeSyncMessage(
      serializer.serializeSyncMessage(message),
    );
    const { signature: _received, ...verificationPayload } = decoded;
    const detachedVerificationPayload =
      snapshotDeepEnumerableData(verificationPayload);

    expect(
      serializer.serializeSyncMessage(detachedVerificationPayload),
    ).toEqual(expectedSignedBytes);
  });

  test('serializeSyncMessage/deserializeSyncMessage preserves welcomeEpochId for BeeKEM Welcome', () => {
    const epochId = new Uint8Array(32);
    for (let i = 0; i < epochId.length; i++) epochId[i] = (i * 11) & 0xff;
    const message = {
      documentId: 'welcome-doc',
      welcomeEpochId: epochId,
    };
    const wire = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.welcomeEpochId).toEqual(epochId);
  });

  test('deserializeSyncMessage omits welcomeEpochId when absent on wire', () => {
    const message = { documentId: 'no-welcome-doc' };
    const wire = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.welcomeEpochId).toBeUndefined();
  });

  test('serializeSyncMessage/deserializeSyncMessage preserves welcomeRecipient', () => {
    const message = {
      documentId: 'welcome-doc',
      welcomeRecipient: 'recipient-serialized-pubkey-base64',
    };
    const wire = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.welcomeRecipient).toBe(
      'recipient-serialized-pubkey-base64',
    );
  });

  test('deserializeSyncMessage omits welcomeRecipient when absent on wire', () => {
    const message = { documentId: 'no-welcome-doc' };
    const wire = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.welcomeRecipient).toBeUndefined();
  });

  test('deserializeSyncMessage rejects non-string welcomeRecipient', () => {
    const wire = buildWire({
      documentId: 'doc',
      welcomeRecipient: 42,
    });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /welcomeRecipient/,
    );
  });

  test('serializeSyncMessage/deserializeSyncMessage preserves welcomeRecipientKemPublicKey', () => {
    const kemPub = new Uint8Array(65);
    for (let i = 0; i < kemPub.length; i++) kemPub[i] = (i * 11) & 0xff;
    const message = {
      documentId: 'welcome-doc',
      welcomeRecipientKemPublicKey: kemPub,
    };
    const wire = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.welcomeRecipientKemPublicKey).toEqual(kemPub);
  });

  test('serializeSyncMessage/deserializeSyncMessage preserves eciesSealed', () => {
    const sealed = new Uint8Array(160);
    for (let i = 0; i < sealed.length; i++) sealed[i] = (i * 17) & 0xff;
    const message = {
      documentId: 'welcome-doc',
      eciesSealed: sealed,
    };
    const wire = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.eciesSealed).toEqual(sealed);
  });

  test('serializeSyncMessage/deserializeSyncMessage preserves pathUpdate for BeeKEM revocation', () => {
    // Synthetic `SerializedPathUpdate` shape -- the wire layer
    // shouldn't care about cryptographic validity, only that the
    // structure round-trips faithfully.
    const pathUpdate = {
      senderLeafIndex: 0,
      senderLeafPublicKey: 'AAAA',
      nodes: [
        { nodeIndex: 1, publicKey: 'AQID', encryptedPrivateKey: 'BAUG' },
        { nodeIndex: 3, publicKey: 'BwgJ', encryptedPrivateKey: 'CgsM' },
      ],
    };
    const message = {
      documentId: 'pathupdate-doc',
      pathUpdate,
    };
    const wire = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.pathUpdate).toEqual(pathUpdate);
  });

  test('serializeSyncMessage/deserializeSyncMessage preserves PathUpdate v2 fields', () => {
    const pathUpdate = {
      version: 2 as const,
      generation: 7,
      numLeaves: 2,
      senderLeafIndex: 0,
      senderLeafPublicKey: 'AAAA',
      nodes: [{
        nodeIndex: 1,
        publicKey: 'AQID',
        encryptedPrivateKey: 'BAUG',
        encryptedPathKeyBundles: [
          { recipientNodeIndex: 2, ciphertext: 'BwgJ' },
        ],
      }],
      treeNodePublicKeys: [
        { nodeIndex: 0, publicKey: 'AAAA' },
        { nodeIndex: 1, publicKey: 'AQID' },
        { nodeIndex: 2, publicKey: 'CgsM' },
      ],
      treeHash: 'DQ4P',
    };
    const wire = serializer.serializeSyncMessage({
      documentId: 'pathupdate-v2-doc',
      pathUpdate,
    });
    expect(serializer.deserializeSyncMessage(wire).pathUpdate).toEqual(
      pathUpdate,
    );
  });

  test('deserializeSyncMessage omits pathUpdate when absent on wire', () => {
    const message = { documentId: 'no-pathupdate-doc' };
    const wire = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.pathUpdate).toBeUndefined();
  });

  test('serializeSyncMessage/deserializeSyncMessage preserves pathUpdateEpochId', () => {
    const epochId = new Uint8Array(32);
    for (let i = 0; i < epochId.length; i++) epochId[i] = (i * 7) & 0xff;
    const message = {
      documentId: 'pathupdate-doc',
      pathUpdateEpochId: epochId,
    };
    const wire = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.pathUpdateEpochId).toEqual(epochId);
  });

  test('deserializeSyncMessage rejects pathUpdate that is not an object', () => {
    const wire = buildWire({
      documentId: 'doc',
      pathUpdate: 'not-an-object',
    });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /pathUpdate/,
    );
  });

  test('deserializeSyncMessage rejects pathUpdate that is null', () => {
    const wire = buildWire({
      documentId: 'doc',
      pathUpdate: null,
    });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /pathUpdate/,
    );
  });

  test('deserializeSyncMessage rejects non-string pathUpdateEpochId', () => {
    const wire = buildWire({
      documentId: 'doc',
      pathUpdateEpochId: 42,
    });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /pathUpdateEpochId/,
    );
  });

  // Round-trip for the initial-load quorum tip-set hash (#189 §5.4.2).
  // Table-driven: covers a deterministic-pattern hash and the all-zeros
  // boundary (base64 leading-zero handling is a common regression source).
  test.each([
    [
      'deterministic-pattern',
      (() => {
        const h = new Uint8Array(32);
        for (let i = 0; i < h.length; i++) h[i] = (i * 7 + 3) & 0xff;
        return h;
      })(),
    ],
    ['all-zeros', new Uint8Array(32)],
  ])(
    'serializeSyncMessage/deserializeSyncMessage preserves tipsHash (quorum, %s)',
    (_label, hash) => {
      const wire = serializer.serializeSyncMessage({
        documentId: 'quorum-doc',
        tipsHash: hash,
      });
      const deserialized = serializer.deserializeSyncMessage(wire);
      expect(deserialized.tipsHash).toEqual(hash);
    },
  );

  test('deserializeSyncMessage omits tipsHash when absent on wire', () => {
    const message = { documentId: 'no-quorum-doc' };
    const wire = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.tipsHash).toBeUndefined();
  });

  // Left as a standalone `test` (not folded into the round-trip table) because
  // it builds a malformed wire payload via `buildWire` to exercise the
  // deserialize-side validator -- different setup from the round-trip cases.
  test('deserializeSyncMessage rejects non-string tipsHash', () => {
    const wire = buildWire({
      documentId: 'doc',
      tipsHash: 42,
    });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /tipsHash/,
    );
  });

  // `tipsHash` is defined as a fixed 32-byte
  // SHA-256 digest; the deserializer previously accepted any base64-decoded
  // length and let downstream quorum logic mis-bucket the value. Reject
  // wrong-length payloads at the wire boundary.
  test.each([
    ['empty', new Uint8Array(0)],
    ['short (16 bytes)', new Uint8Array(16)],
    ['long (64 bytes)', new Uint8Array(64)],
  ])(
    'deserializeSyncMessage rejects tipsHash that is not exactly 32 bytes (%s)',
    (_label, malformedHash) => {
      const b64 = Buffer.from(malformedHash).toString('base64');
      const wire = buildWire({ documentId: 'doc', tipsHash: b64 });
      expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
        /tipsHash.*32 bytes/,
      );
    },
  );

  // Quorum frontier binding wire-encoding (#186 / #189 §5.4.2). The `tips`
  // field carries an explicit string[] of CIDs on load responses so the
  // loader can bind the served state to the responder's frontier hash.
  test.each([
    ['typical', ['bafy1', 'bafy2', 'bafy3']],
    ['single-tip', ['bafyOnly']],
    ['empty-frontier', [] as string[]],
  ])(
    'serializeSyncMessage/deserializeSyncMessage preserves tips (%s)',
    (_label, tips) => {
      const wire = serializer.serializeSyncMessage({
        documentId: 'frontier-doc',
        tips,
      });
      const deserialized = serializer.deserializeSyncMessage(wire);
      expect(deserialized.tips).toEqual(tips);
    },
  );

  test('deserializeSyncMessage omits tips when absent on wire', () => {
    const wire = serializer.serializeSyncMessage({
      documentId: 'no-frontier-doc',
    });
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.tips).toBeUndefined();
  });

  test('deserializeSyncMessage rejects non-array tips', () => {
    const wire = buildWire({ documentId: 'doc', tips: 'not-an-array' });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(/tips/);
  });

  test('deserializeSyncMessage rejects non-string tips entries', () => {
    const wire = buildWire({ documentId: 'doc', tips: ['ok', 42] });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(/tips/);
  });

  // Regression: prior to the upfront object guard, a malformed peer payload
  // like JSON `null` flowed straight to `raw.snapshot` access and threw a
  // bare `TypeError: Cannot read properties of null`. The guard mirrors
  // `YjsJSONSerializer.deserializeSyncMessage` and produces a descriptive
  // `Error` so the malformed payload can be attributed back to the peer
  // instead of crashing the deserializer (a trivial DoS vector).
  test('deserializeSyncMessage rejects a top-level JSON null payload', () => {
    const wire = buildWire(null);
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(Error);
    expect(() => serializer.deserializeSyncMessage(wire)).not.toThrow(
      TypeError,
    );
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*expected a plain object.*got null/,
    );
  });

  test('deserializeSyncMessage rejects a top-level JSON array payload', () => {
    const wire = buildWire([1, 2, 3]);
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*expected a plain object.*got array/,
    );
  });

  test('deserializeSyncMessage rejects a top-level JSON number payload', () => {
    const wire = buildWire(42);
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*expected a plain object.*got number/,
    );
  });

  test('deserializeSyncMessage rejects a top-level JSON string payload', () => {
    const wire = buildWire('not-an-object');
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*expected a plain object.*got string/,
    );
  });

  // Regression: prior to validating `documentId`, a malformed peer payload
  // missing the field (or sending a non-string value) would propagate
  // `documentId: undefined`/non-string downstream and violate the required
  // field contract of `CRDTSyncMessage`. The fix rejects the payload with a
  // descriptive error attributable back to the peer.
  test('deserializeSyncMessage rejects payload missing documentId', () => {
    const wire = buildWire({ changeId: 'c1' });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'documentId' must be a string.*got undefined/,
    );
  });

  test('deserializeSyncMessage rejects payload with non-string documentId (number)', () => {
    const wire = buildWire({ documentId: 42 });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'documentId' must be a string.*got number/,
    );
  });

  test('deserializeSyncMessage rejects payload with null documentId', () => {
    const wire = buildWire({ documentId: null });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'documentId' must be a string.*got null/,
    );
  });

  test('deserializeSyncMessage rejects payload with object documentId', () => {
    const wire = buildWire({ documentId: { id: 'doc' } });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'documentId' must be a string.*got object/,
    );
  });

  test('deserializeSyncMessage rejects non-string changeId', () => {
    const wire = buildWire({ documentId: 'doc', changeId: 7 });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'changeId' must be a string when present.*got number/,
    );
  });

  test('deserializeSyncMessage rejects non-string signature', () => {
    const wire = buildWire({ documentId: 'doc', signature: 7 });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'signature' must be a string when present.*got number/,
    );
  });

  test('deserializeSyncMessage rejects non-array keychainChanges', () => {
    const wire = buildWire({ documentId: 'doc', keychainChanges: 'not-an-array' });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'keychainChanges' must be an array when present.*got string/,
    );
  });

  test('deserializeSyncMessage rejects array snapshot', () => {
    const wire = buildWire({ documentId: 'doc', snapshot: [1, 2, 3] });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'snapshot' must be an object when present.*got array/,
    );
  });

  // Regression: a truthy guard (`if (raw.snapshot)`) silently dropped
  // defined-but-falsy snapshot values rather than rejecting the malformed
  // payload. The fix routes any non-`undefined` value through the validator
  // so peers can't bypass it by sending `snapshot: null/0/""`.
  test('deserializeSyncMessage rejects "snapshot: null" (validation bypass regression)', () => {
    const wire = buildWire({ documentId: 'doc', snapshot: null });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'snapshot' must be an object when present.*got null/,
    );
  });

  test('deserializeSyncMessage rejects "snapshot: 0"', () => {
    const wire = buildWire({ documentId: 'doc', snapshot: 0 });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'snapshot' must be an object when present.*got number/,
    );
  });

  test('deserializeSyncMessage rejects "snapshot: \\"\\"" (empty string)', () => {
    const wire = buildWire({ documentId: 'doc', snapshot: '' });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'snapshot' must be an object when present.*got string/,
    );
  });

  test('deserializeSyncMessage accepts omitted "snapshot" field', () => {
    const wire = buildWire({ documentId: 'doc' });
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.snapshot).toBeUndefined();
  });

  // Regression: prior to building the returned object explicitly, the
  // deserializer spread `...raw` straight onto the result. A malicious peer
  // could append junk keys (or attempt prototype-pollution-style keys) and
  // they would leak through to downstream consumers. The fix only propagates
  // fields declared on `CRDTSyncMessage`.
  test('deserializeSyncMessage strips peer-supplied junk keys', () => {
    const wire = buildWire({
      documentId: 'doc',
      changeId: 'cid',
      somethingExtra: 'evil',
      anotherJunkField: { nested: true },
      __evilNonProtoKey: 'still-junk',
    });
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.documentId).toBe('doc');
    expect(deserialized.changeId).toBe('cid');
    expect((deserialized as Record<string, unknown>).somethingExtra).toBeUndefined();
    expect((deserialized as Record<string, unknown>).anotherJunkField).toBeUndefined();
    expect((deserialized as Record<string, unknown>).__evilNonProtoKey).toBeUndefined();
  });

  test('deserializeSyncMessage round-trips a minimal valid payload', () => {
    const wire = buildWire({ documentId: 'doc' });
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.documentId).toBe('doc');
    expect(deserialized.changes).toBeUndefined();
    expect(deserialized.changeId).toBeUndefined();
    expect(deserialized.signature).toBeUndefined();
    expect(deserialized.keychainChanges).toBeUndefined();
    expect(deserialized.snapshot).toBeUndefined();
  });
});

describe('bounded initial invitation profile', () => {
  test('all bundled Automerge components declare the same profile', () => {
    expect(new AutomergeProvider().initialInvitationCapacityProfile).toBe(
      INITIAL_INVITATION_CAPACITY_PROFILE,
    );
    expect(new AutomergeACLProvider().initialInvitationCapacityProfile).toBe(
      INITIAL_INVITATION_CAPACITY_PROFILE,
    );
    expect(
      new AutomergeKeychainProvider().initialInvitationCapacityProfile,
    ).toBe(INITIAL_INVITATION_CAPACITY_PROFILE);
    expect(
      new AutomergeJSONSerializer().initialInvitationCapacityProfile,
    ).toBe(INITIAL_INVITATION_CAPACITY_PROFILE);
  });

  test('founder-plus-editor ACL publication stays within the serialized growth bound', async () => {
    const founderPair = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    const recipientPair = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    const readers = new AutomergeACL();
    const writers = new AutomergeACL();
    const founderChanges = await writers.add(founderPair.publicKey);
    const membershipChanges: Array<
      readonly ['reader' | 'writer', Uint8Array[]]
    > = [
      ['reader', await readers.add(recipientPair.publicKey)],
      ['writer', await writers.add(recipientPair.publicKey)],
      ['reader', readers.current()],
      ['writer', writers.current()],
    ];
    const serializer = new AutomergeJSONSerializer();
    const cid = (label: string) => `bafy${label.repeat(55).slice(0, 55)}`;
    const founderCid = cid('f');
    const signature = 'A'.repeat(128);
    const baseline: CRDTSyncMessage<Uint8Array[], CryptoKey> = {
      documentId: '/capacity-growth',
      changeId: founderCid,
      changes: { kind: 'writer', change: founderChanges },
      tips: [founderCid],
      signature,
    };
    const baselineBytes =
      serializer.serializeSyncMessage(baseline).byteLength;
    let previousCid = founderCid;
    let previousNode = baseline.changes!;
    const deferredTips: string[] = [];

    for (let index = 0; index < membershipChanges.length; index++) {
      const [kind, change] = membershipChanges[index]!;
      const nextCid = cid(String(index));
      const children: Record<string, CRDTChangeNode<Uint8Array[]>> = {
        [previousCid]: previousNode,
      };
      const nextNode: CRDTChangeNode<Uint8Array[]> = {
        kind,
        change,
        children,
      };
      for (let crossLink = 0; crossLink < 3; crossLink++) {
        const crossLinkCid = cid(`${index}${crossLink}`);
        children[crossLinkCid] = { kind: 'document' };
        deferredTips.push(crossLinkCid);
      }
      previousCid = nextCid;
      previousNode = nextNode;
    }

    const afterMembership: CRDTSyncMessage<Uint8Array[], CryptoKey> = {
      documentId: baseline.documentId,
      changeId: previousCid,
      changes: previousNode,
      tips: [previousCid, ...deferredTips],
      signature,
    };
    const membershipGrowth =
      serializer.serializeSyncMessage(afterMembership).byteLength -
      baselineBytes;

    expect(membershipGrowth).toBeGreaterThan(0);
    expect(membershipGrowth).toBeLessThanOrEqual(4 * 1024);
    expect(membershipGrowth).toBeLessThanOrEqual(
      INITIAL_INVITATION_MAX_MEMBERSHIP_GROWTH_BYTES,
    );
  });

  test('real bundled signature, encryption, and sealed Welcome overheads stay bounded', async () => {
    const signingPair = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    const serializer = new AutomergeJSONSerializer();
    const crdt = new AutomergeProvider<{ value: string }>();
    const [document, changes] = crdt.localChange(
      crdt.newDocument(),
      'capacity payload',
      (draft) => {
        draft.value = 'founder plus one';
      },
    );
    expect(document.value).toBe('founder plus one');
    const plaintext = serializer.serializeSyncMessage({
      documentId: '/real-overheads',
      changes: { kind: 'document', change: changes },
    });
    const signature = await new SubtleCrypto().sign(
      plaintext,
      signingPair.privateKey,
    );
    expect(signature.byteLength).toBe(96);
    expect(signature.byteLength).toBeLessThanOrEqual(
      INITIAL_INVITATION_MAX_SIGNATURE_BYTES,
    );

    const auth = new SubtleCrypto();
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const measuredOverheads: number[] = [];
    for (const sample of [plaintext, new Uint8Array(16)]) {
      const encrypted = await auth.encrypt(sample, key);
      const framedBytes =
        32 + encrypted.nonce.byteLength + encrypted.data.byteLength;
      measuredOverheads.push(framedBytes - sample.byteLength);
    }
    expect(Math.max(...measuredOverheads)).toBe(60);
    expect(Math.max(...measuredOverheads)).toBeLessThanOrEqual(
      INITIAL_INVITATION_MAX_ENCRYPTED_BOOTSTRAP_OVERHEAD_BYTES,
    );

    const founderKemPair = (await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    )) as CryptoKeyPair;
    const recipientKemPair = (await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    )) as CryptoKeyPair;
    const beekem = new BeeKEM();
    await beekem.initialize(
      founderKemPair.privateKey,
      founderKemPair.publicKey,
    );
    const { welcome } = await beekem.addMember(recipientKemPair.publicKey);
    const keychain = new AutomergeKeychain();
    await keychain.add();
    const keychainBytes = serializer.serializeChanges(keychain.history());
    const withoutBeeKEM = encodeWelcomeSealedPayload({
      keychainChanges: keychainBytes,
      beekemWelcome: null,
    });
    const sealedWelcome = await eciesSeal(
      encodeWelcomeSealedPayload({
        keychainChanges: keychainBytes,
        beekemWelcome: welcome,
      }),
      recipientKemPair.publicKey,
    );

    const sealedWelcomeGrowth =
      sealedWelcome.byteLength - withoutBeeKEM.byteLength;
    expect(sealedWelcomeGrowth).toBe(845);
    expect(sealedWelcomeGrowth).toBeLessThanOrEqual(
      INITIAL_INVITATION_MAX_SEALED_WELCOME_GROWTH_BYTES,
    );
  });
});
