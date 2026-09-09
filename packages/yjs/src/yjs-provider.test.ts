import { describe, expect, test, beforeAll, jest } from '@jest/globals';
import { runInNewContext } from 'node:vm';
import {
  applyUpdateV2,
  Doc,
  encodeStateAsUpdateV2,
  encodeStateVector,
} from 'yjs';
import {
  MAX_KEYCHAIN_EPOCHS,
  snapshotDeepEnumerableData,
  type CRDTChangeNode,
  MAX_MERKLE_DAG_DEPTH,
} from '@peerborne/core';
import {
  YjsProvider,
  YjsACL,
  YjsACLProvider,
  YjsKeychain,
  YjsKeychainProvider,
  YjsJSONSerializer,
  serializeKey,
} from './peerborne-yjs.js';

// ECDSA P-384 test keys (extractable, verify-only)
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

let key1: CryptoKey;
let key2: CryptoKey;

beforeAll(async () => {
  key1 = await crypto.subtle.importKey(
    'jwk',
    publicKeyData1,
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['verify'],
  );
  key2 = await crypto.subtle.importKey(
    'jwk',
    publicKeyData2,
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['verify'],
  );
});

describe('YjsProvider', () => {
  test('newDocument returns a valid Yjs Doc', () => {
    const provider = new YjsProvider();
    const doc = provider.newDocument();
    expect(doc).toBeInstanceOf(Doc);
  });

  test('localChange applies change function and returns [doc, changes]', () => {
    const provider = new YjsProvider();
    const doc = provider.newDocument();
    const [resultDoc, changes] = provider.localChange(
      doc,
      'set greeting',
      (d) => {
        d.getMap('test').set('hello', 'world');
      },
    );
    expect(resultDoc).toBe(doc);
    expect(resultDoc.getMap('test').get('hello')).toBe('world');
    expect(changes).toBeInstanceOf(Uint8Array);
    expect(changes.length).toBeGreaterThan(0);
  });

  test('remoteChange applies encoded update to document', () => {
    const provider = new YjsProvider();
    const doc1 = provider.newDocument();
    const [, changes] = provider.localChange(doc1, 'set value', (d) => {
      d.getMap('data').set('key', 42);
    });

    const doc2 = provider.newDocument();
    const resultDoc = provider.remoteChange(doc2, changes);
    expect(resultDoc).toBe(doc2);
    expect(resultDoc.getMap('data').get('key')).toBe(42);
  });

  test('getHistory returns encoded state', () => {
    const provider = new YjsProvider();
    const doc = provider.newDocument();
    provider.localChange(doc, 'add data', (d) => {
      d.getMap('m').set('a', 1);
    });
    const history = provider.getHistory(doc);
    expect(history).toBeInstanceOf(Uint8Array);
    expect(history.length).toBeGreaterThan(0);
  });

  test('round-trip: localChange on doc1, remoteChange on doc2 syncs data', () => {
    const provider = new YjsProvider();
    const doc1 = provider.newDocument();
    const doc2 = provider.newDocument();

    const [, changes] = provider.localChange(doc1, 'edit', (d) => {
      d.getMap('shared').set('x', 'synced');
      d.getArray('list').push(['item1']);
    });

    provider.remoteChange(doc2, changes);
    expect(doc2.getMap('shared').get('x')).toBe('synced');
    expect(doc2.getArray('list').get(0)).toBe('item1');
  });
});

describe('YjsProvider delta encoding', () => {
  test('localChange returns delta smaller than full state after first change', () => {
    const provider = new YjsProvider();
    const doc = provider.newDocument();

    // Make initial change
    provider.localChange(doc, 'init', (d) => {
      d.getMap('data').set('key1', 'value1');
    });

    // Make second change -- should return only the delta
    const [, changes2] = provider.localChange(doc, 'update', (d) => {
      d.getMap('data').set('key2', 'value2');
    });

    const fullState = encodeStateAsUpdateV2(doc);
    expect(changes2.byteLength).toBeLessThan(fullState.byteLength);
  });

  test('delta from localChange applies correctly to a synced peer', () => {
    const provider = new YjsProvider();
    const doc1 = provider.newDocument();

    // Initial change
    provider.localChange(doc1, 'init', (d) => {
      d.getMap('data').set('key1', 'value1');
    });

    // Sync doc2 with full history
    const doc2 = provider.newDocument();
    provider.remoteChange(doc2, provider.getHistory(doc1));
    expect(doc2.getMap('data').get('key1')).toBe('value1');

    // Second change on doc1 -- returns delta
    const [, changes2] = provider.localChange(doc1, 'update', (d) => {
      d.getMap('data').set('key2', 'value2');
    });

    // Apply delta to doc2
    provider.remoteChange(doc2, changes2);
    expect(doc2.getMap('data').get('key1')).toBe('value1');
    expect(doc2.getMap('data').get('key2')).toBe('value2');
  });
});

describe('YjsACL delta encoding', () => {
  test('add returns delta that merges correctly into another ACL', async () => {
    const acl1 = new YjsACL();
    const changes1 = await acl1.add(key1);
    expect(changes1.byteLength).toBeGreaterThan(0);
    const changes2 = await acl1.add(key2);

    // Delta should merge correctly
    const acl2 = new YjsACL();
    acl2.merge(changes1);
    acl2.merge(changes2);
    expect(await acl2.check(key1)).toBe(true);
    expect(await acl2.check(key2)).toBe(true);
  });

  test('remove no-op produces delta that is a no-op when merged', async () => {
    const acl = new YjsACL();
    // Remove a key that was never added -- should produce a no-op delta
    const changes = await acl.remove(key1);
    // Applying a no-op delta should not add any users
    const acl2 = new YjsACL();
    acl2.merge(changes);
    const users = await acl2.users();
    expect(users).toHaveLength(0);
  });
});

describe('YjsACL', () => {
  test('add() adds user and check() returns true', async () => {
    const acl = new YjsACL();
    const changes = await acl.add(key1);
    expect(changes).toBeInstanceOf(Uint8Array);
    expect(changes.length).toBeGreaterThan(0);
    expect(await acl.check(key1)).toBe(true);
  });

  test('remove() removes user and check() returns false', async () => {
    const acl = new YjsACL();
    await acl.add(key1);
    expect(await acl.check(key1)).toBe(true);
    const removeChanges = await acl.remove(key1);
    expect(removeChanges).toBeInstanceOf(Uint8Array);
    expect(await acl.check(key1)).toBe(false);
  });

  test('check() returns false for unknown key', async () => {
    const acl = new YjsACL();
    expect(await acl.check(key1)).toBe(false);
  });

  test('users() returns all added keys', async () => {
    const acl = new YjsACL();
    await acl.add(key1);
    await acl.add(key2);
    const users = await acl.users();
    expect(users).toHaveLength(2);

    // Verify the exported raw bytes match both test keys
    const rawKeys = await Promise.all(
      users.map((k) => crypto.subtle.exportKey('raw', k)),
    );
    const rawKey1 = await crypto.subtle.exportKey('raw', key1);
    const rawKey2 = await crypto.subtle.exportKey('raw', key2);

    const rawSet = new Set(
      rawKeys.map((buf) =>
        Array.from(new Uint8Array(buf))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join(''),
      ),
    );
    const hex1 = Array.from(new Uint8Array(rawKey1))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    const hex2 = Array.from(new Uint8Array(rawKey2))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    expect(rawSet.has(hex1)).toBe(true);
    expect(rawSet.has(hex2)).toBe(true);
  });

  test('current() and merge() export and sync between ACLs', async () => {
    const acl1 = new YjsACL();
    await acl1.add(key1);

    const snapshot = acl1.current();
    expect(snapshot).toBeInstanceOf(Uint8Array);

    const acl2 = new YjsACL();
    acl2.merge(snapshot);
    expect(await acl2.check(key1)).toBe(true);
  });

  test('YjsACLProvider.initialize() returns a new YjsACL', () => {
    const provider = new YjsACLProvider();
    const acl = provider.initialize();
    expect(acl).toBeInstanceOf(YjsACL);
  });
});

async function testDocumentKey(fill: number): Promise<{
  key: CryptoKey;
  serialized: string;
}> {
  const key = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(32).fill(fill),
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );
  return { key, serialized: await serializeKey(key) };
}

function yjsKeychainUpdate(entries: unknown[]): Uint8Array {
  const doc = new Doc();
  doc.getArray<unknown>('keys').push(entries);
  return encodeStateAsUpdateV2(doc);
}

describe('YjsKeychain', () => {
  test('add() returns [keyIDBytes, CryptoKey, changes]', async () => {
    const keychain = new YjsKeychain();
    const [keyIDBytes, key, changes] = await keychain.add();
    expect(keyIDBytes).toBeInstanceOf(Uint8Array);
    // 32 bytes -- matches `keyIDLength` and the BeeKEM-derived epoch
    // ID width from `deriveEpochIdFromRootSecret`. A single fixed
    // width across both provisioning paths means the wire-format
    // key-ID prefix never needs to be truncated.
    expect(keyIDBytes.length).toBe(32);
    expect(key).toBeDefined();
    expect(key.type).toBe('secret');
    expect(changes).toBeInstanceOf(Uint8Array);
    expect(changes.length).toBeGreaterThan(0);
  });

  test('prepareKey() stages a bounded random key without live mutation', async () => {
    const keychain = new YjsKeychain();
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

    const independent = new YjsKeychain();
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
    const keychain = new YjsKeychain();
    const prepared = await keychain.prepareKey();
    await keychain.add();

    expect(() => prepared.commit()).toThrow(
      'Keychain changed while epoch key was staged',
    );
    expect(await keychain.keys()).toHaveLength(1);
  });

  test('keys() returns all added keys', async () => {
    const keychain = new YjsKeychain();
    await keychain.add();
    await keychain.add();
    const allKeys = await keychain.keys();
    expect(allKeys).toHaveLength(2);
    for (const [idBytes, key] of allKeys) {
      expect(idBytes).toBeInstanceOf(Uint8Array);
      expect(idBytes.length).toBe(32);
      expect(key.type).toBe('secret');
    }
  });

  test('getKey() retrieves cached key by ID bytes', async () => {
    const keychain = new YjsKeychain();
    const [keyIDBytes, originalKey] = await keychain.add();
    const retrieved = keychain.getKey(keyIDBytes);
    expect(retrieved).toBe(originalKey);
  });

  test('getKey() returns undefined for unknown ID', () => {
    const keychain = new YjsKeychain();
    const unknownID = new Uint8Array(32);
    expect(keychain.getKey(unknownID)).toBeUndefined();
  });

  test('currentKeyChange() reuses replay-safe history for a one-key keychain', async () => {
    const source = new YjsKeychain();
    const [id] = await source.add();

    const first = await source.currentKeyChange();
    const repeated = await source.currentKeyChange();
    expect(repeated).toEqual(first);
    const restored = new YjsKeychain();
    restored.merge(source.history());
    expect(await restored.currentKeyChange()).toEqual(first);

    const receiver = new YjsKeychain();
    receiver.merge(first);
    receiver.merge(repeated);
    expect(await receiver.currentKeyChange()).toEqual(first);
    expect((await receiver.keys()).map(([keyID]) => keyID)).toEqual([id]);
  });

  test('currentKeyChange() rejects a later key rather than synthesizing a fresh client', async () => {
    const source = new YjsKeychain();
    await source.add();
    await source.add();
    const before = source.history();

    await expect(source.currentKeyChange()).rejects.toThrow(
      'Yjs cannot export the current key replay-safely',
    );
    expect(source.history()).toEqual(before);
  });

  test('current() throws on empty keychain', async () => {
    const keychain = new YjsKeychain();
    await expect(keychain.current()).rejects.toThrow(
      "Can't get an empty keychain's current value",
    );
  });

  test('current() returns last added key', async () => {
    const keychain = new YjsKeychain();
    await keychain.add();
    const [keyIDBytes2, key2] = await keychain.add();
    const [currentID, currentKey] = await keychain.current();
    // Compare UUID bytes
    expect(Array.from(currentID)).toEqual(Array.from(keyIDBytes2));
    // Same raw key material
    const rawCurrent = await crypto.subtle.exportKey('raw', currentKey);
    const rawKey2 = await crypto.subtle.exportKey('raw', key2);
    expect(new Uint8Array(rawCurrent)).toEqual(new Uint8Array(rawKey2));
  });

  test('history() and merge() export and sync between keychains', async () => {
    const kc1 = new YjsKeychain();
    const [keyIDBytes] = await kc1.add();

    const snapshot = kc1.history();
    expect(snapshot).toBeInstanceOf(Uint8Array);

    const kc2 = new YjsKeychain();
    kc2.merge(snapshot);
    const kc2Keys = await kc2.keys();
    expect(kc2Keys).toHaveLength(1);
    expect(Array.from(kc2Keys[0][0])).toEqual(Array.from(keyIDBytes));
  });

  test('YjsKeychainProvider.initialize() returns YjsKeychain with keyIDLength=32', () => {
    const provider = new YjsKeychainProvider();
    const keychain = provider.initialize();
    expect(keychain).toBeInstanceOf(YjsKeychain);
    expect(provider.keyIDLength).toBe(32);
  });

  test('historySince() reuses replay-safe history at the first key', async () => {
    const source = new YjsKeychain();
    const [id1] = await source.add();
    const [id2] = await source.add();
    const [id3] = await source.add();

    const first = await source.historySince(id1);
    const repeated = await source.historySince(id1);
    expect(repeated).toEqual(first);
    const restored = new YjsKeychain();
    restored.merge(source.history());
    const restoredHistory = await restored.historySince(id1);
    expect(restoredHistory).toEqual(first);

    const receiver = new YjsKeychain();
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
    const source = new YjsKeychain();
    await source.add();
    await source.add();
    const before = source.history();

    const unknownID = new Uint8Array(32).fill(0xff);
    await expect(source.historySince(unknownID)).rejects.toThrow(
      'Unknown keychain history boundary',
    );
    await expect(source.historySince(unknownID)).rejects.toThrow(
      'Unknown keychain history boundary',
    );
    expect(source.history()).toEqual(before);
  });

  test('historySince() rejects a later boundary rather than synthesizing fresh clients', async () => {
    const source = new YjsKeychain();
    await source.add();
    const [laterID] = await source.add();

    await expect(source.historySince(laterID)).rejects.toThrow(
      'Yjs cannot export this keychain suffix replay-safely',
    );
  });

  test('addEpochKey() rejects a duplicate ID without poisoning its cache', async () => {
    const source = new YjsKeychain();
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
    const keychain = new YjsKeychain();
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
      const keychain = new YjsKeychain();
      const historyBefore = new Uint8Array(keychain.history());
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
    const keychain = new YjsKeychain();
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
      const keychain = new YjsKeychain();
      const historyBefore = new Uint8Array(keychain.history());
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
    const keychain = new YjsKeychain();
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
    const keychain = new YjsKeychain();
    const historyBefore = new Uint8Array(keychain.history());
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
    const keychain = new YjsKeychain();
    const historyBefore = new Uint8Array(keychain.history());
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

  test('prepareEpochKey() commits its private bytes after returned changes are mutated', async () => {
    const keychain = new YjsKeychain();
    const epochId = crypto.getRandomValues(new Uint8Array(32));
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const prepared = await keychain.prepareEpochKey(epochId, key);

    prepared.changes.fill(0);
    prepared.commit();

    const keys = await keychain.keys();
    expect(keys).toHaveLength(1);
    expect(keys[0][0]).toEqual(epochId);
    expect(keychain.getKey(epochId)).toBe(key);
  });

  test('prepareEpochKey() exposes an exact replay-safe current projection', async () => {
    const keychain = new YjsKeychain();
    const firstId = crypto.getRandomValues(new Uint8Array(32));
    const firstKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const first = await keychain.prepareEpochKey(firstId, firstKey);
    expect(first.currentKeyChange).toBeDefined();
    const receiver = new YjsKeychain();
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
    const narrowReceiver = new YjsKeychain();
    narrowReceiver.merge(next.currentKeyChange!);
    narrowReceiver.merge(next.currentKeyChange!);
    expect((await narrowReceiver.keys()).map(([id]) => id)).toEqual([nextId]);
  });

  test('prepareMerge() commits its private bytes after returned changes are mutated', async () => {
    const source = new YjsKeychain();
    const [epochId] = await source.add();
    const receiver = new YjsKeychain();
    const prepared = receiver.prepareMerge(source.history());

    prepared.changes.fill(0);
    prepared.commit();

    const keys = await receiver.keys();
    expect(keys).toHaveLength(1);
    expect(keys[0][0]).toEqual(epochId);
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
      const receiver = new YjsKeychain();
      expect(() =>
        receiver.prepareMerge(yjsKeychainUpdate([entry])),
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
    const firstSerialized = await serializeKey(firstKey);
    const secondSerialized = await serializeKey(secondKey);
    const receiver = new YjsKeychain();

    expect(() =>
      receiver.prepareMerge(
        yjsKeychainUpdate([
          [idHex, firstSerialized],
          [idHex, secondSerialized],
        ]),
      ),
    ).toThrow('Duplicate keychain key ID');
    expect(await receiver.keys()).toHaveLength(0);
    expect(receiver.getKey(id)).toBeUndefined();
  });

  test('prepareMerge() rejects delete, rewrite, and reorder attempts', async () => {
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

    const deleted = new Doc();
    deleted.getArray<[string, string]>('keys').push([firstEntry, secondEntry]);
    deleted.getArray('keys').delete(0, 1);
    expect(() =>
      new YjsKeychain().prepareMerge(encodeStateAsUpdateV2(deleted)),
    ).toThrow('Keychain history must not contain deletions');

    const rewritten = new Doc();
    rewritten.getArray<[string, string]>('keys').push([firstEntry]);
    rewritten.getArray('keys').delete(0, 1);
    rewritten.getArray<[string, string]>('keys').push([secondEntry]);
    expect(() =>
      new YjsKeychain().prepareMerge(encodeStateAsUpdateV2(rewritten)),
    ).toThrow('Keychain history must not contain deletions');

    const source = new Doc();
    source.getArray<[string, string]>('keys').push([firstEntry]);
    const receiver = new YjsKeychain();
    receiver.merge(encodeStateAsUpdateV2(source));
    const beforeInsert = encodeStateVector(source);
    source.getArray<[string, string]>('keys').insert(0, [secondEntry]);
    const reorder = encodeStateAsUpdateV2(source, beforeInsert);
    expect(() => receiver.prepareMerge(reorder)).toThrow(
      /unrelated operation|append without rewriting entries/,
    );
    expect((await receiver.keys()).map(([id]) => id)).toEqual([
      new Uint8Array(32).fill(0x11),
    ]);
  });

  test('prepareMerge() rejects unrelated and dependency-incomplete Yjs operations', async () => {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const entry: [string, string] = [
      '33'.repeat(32),
      await serializeKey(key),
    ];
    const unrelated = new Doc();
    unrelated.getMap<unknown>('other').set('hidden', entry);
    expect(() =>
      new YjsKeychain().prepareMerge(encodeStateAsUpdateV2(unrelated)),
    ).toThrow('Keychain history contains an unrelated operation');

    const dependent = new Doc();
    dependent.getArray<[string, string]>('keys').push([entry]);
    const beforeSecond = encodeStateVector(dependent);
    dependent.getArray<[string, string]>('keys').push([
      ['44'.repeat(32), await serializeKey(key)],
    ]);
    const missingPredecessor = encodeStateAsUpdateV2(dependent, beforeSecond);
    expect(() =>
      new YjsKeychain().prepareMerge(missingPredecessor),
    ).toThrow('Keychain history has unresolved update dependencies');

    const concurrentLeft = new Doc();
    const concurrentRight = new Doc();
    concurrentLeft.getArray<[string, string]>('keys').push([entry]);
    concurrentRight.getArray<[string, string]>('keys').push([
      ['55'.repeat(32), await serializeKey(key)],
    ]);
    const concurrent = new Doc();
    applyUpdateV2(concurrent, encodeStateAsUpdateV2(concurrentLeft));
    applyUpdateV2(concurrent, encodeStateAsUpdateV2(concurrentRight));
    expect(() =>
      new YjsKeychain().prepareMerge(encodeStateAsUpdateV2(concurrent)),
    ).toThrow('Keychain history contains an unrelated operation');
  });

  test('delete-only updates reject and replay-only commits invalidate older staging', async () => {
    const keychain = new YjsKeychain();
    await keychain.add();
    const nextId = new Uint8Array(32).fill(9);
    const nextKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const stagedEpoch = await keychain.prepareEpochKey(nextId, nextKey);

    const replica = new Doc();
    applyUpdateV2(replica, keychain.history());
    const beforeDelete = encodeStateVector(replica);
    replica.getArray('keys').delete(0, 1);
    expect(encodeStateVector(replica)).toEqual(beforeDelete);
    const deletionOnly = encodeStateAsUpdateV2(replica, beforeDelete);
    expect(() => keychain.prepareMerge(deletionOnly)).toThrow(
      'Keychain history must not contain deletions',
    );

    const replay = keychain.prepareMerge(keychain.history());
    replay.commit();
    expect(() => stagedEpoch.commit()).toThrow(
      'Keychain changed while epoch key was staged',
    );
  });

  test('history projections reject tombstoned historical key material', async () => {
    const { serialized } = await testDocumentKey(0x71);
    const tombstoned = new Doc();
    tombstoned.getArray<[string, string]>('keys').push([
      ['11'.repeat(32), serialized],
    ]);
    tombstoned.getArray('keys').delete(0, 1);
    tombstoned.getArray<[string, string]>('keys').push([
      ['22'.repeat(32), serialized],
    ]);
    const compromised = new YjsKeychain();
    Object.defineProperty(compromised, '_keychain', {
      value: tombstoned,
      writable: true,
    });

    expect(() => compromised.history()).toThrow(
      'Keychain history must not contain deletions',
    );
    await expect(compromised.stateCommitment()).rejects.toThrow(
      'Keychain history must not contain deletions',
    );
    await expect(compromised.currentKeyChange()).rejects.toThrow(
      'Keychain history must not contain deletions',
    );
    await expect(
      compromised.historySince(new Uint8Array(32).fill(0x22)),
    ).rejects.toThrow('Keychain history must not contain deletions');
    await expect(compromised.keys()).rejects.toThrow(
      'Keychain history must not contain deletions',
    );
  });

  test('prepareMerge() hydrates detached staged keys and transfers them only on commit', async () => {
    const source = new YjsKeychain();
    const [firstId] = await source.add();
    const [currentId] = await source.add();
    const receiver = new YjsKeychain();
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
    const source = new YjsKeychain();
    const [id] = await source.add();
    const history = source.history();
    const crossRealm = runInNewContext(
      `new Uint8Array([${Array.from(history).join(',')}])`,
    ) as Uint8Array;
    expect(crossRealm).not.toBeInstanceOf(Uint8Array);
    const receiver = new YjsKeychain();
    receiver.prepareMerge(crossRealm).commit();
    expect((await receiver.keys()).map(([keyID]) => keyID)).toEqual([id]);

    if (typeof SharedArrayBuffer !== 'undefined') {
      const shared = new Uint8Array(new SharedArrayBuffer(history.byteLength));
      shared.set(history);
      expect(() => new YjsKeychain().prepareMerge(shared)).toThrow(
        'Yjs keychain change has an invalid length or backing buffer',
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
    const left = new YjsKeychain();
    const right = new YjsKeychain();
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

    const conflicting = new YjsKeychain();
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
    const founder = new YjsKeychain();
    await founder.add();
    const sender = new YjsKeychain();
    const receiver = new YjsKeychain();
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
      'Keychain history has unresolved update dependencies',
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
    const receiver = new YjsKeychain();
    await receiver.addEpochKey(idA, keyA);
    const projectionSource = new YjsKeychain();
    const stagedB = await projectionSource.prepareEpochKey(idB, keyB);
    const projectionB = stagedB.currentKeyChange!;

    expect(() => receiver.prepareMerge(projectionB)).toThrow(
      'Standalone keychain history is not an append-only view',
    );
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

    const conflictingB = await new YjsKeychain().prepareEpochKey(idB, keyC);
    expect(() =>
      receiver.prepareAppend(conflictingB.currentKeyChange!, {
        expectedPreviousKeyId: idA,
        expectedNewKeyId: idB,
      }),
    ).toThrow('Keychain append replay does not match live history');

    const stagedC = await new YjsKeychain().prepareEpochKey(idC, keyC);
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
    const entries: [string, string][] = Array.from(
      { length: MAX_KEYCHAIN_EPOCHS },
      (_, index) => [index.toString(16).padStart(64, '0'), serialized],
    );
    const source = new Doc();
    source.getArray<[string, string]>('keys').push(entries);
    const receiver = new YjsKeychain();
    const atLimit = receiver.prepareMerge(encodeStateAsUpdateV2(source));
    expect(atLimit.keyIds).toHaveLength(MAX_KEYCHAIN_EPOCHS);
    atLimit.commit();
    const before = receiver.history();

    const beforeOverflow = encodeStateVector(source);
    source.getArray<[string, string]>('keys').push([
      [MAX_KEYCHAIN_EPOCHS.toString(16).padStart(64, '0'), serialized],
    ]);
    expect(() =>
      receiver.prepareMerge(encodeStateAsUpdateV2(source, beforeOverflow)),
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
    const overflowProjection = await new YjsKeychain().prepareEpochKey(
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
    const sender = new YjsKeychain();
    const epochId = crypto.getRandomValues(new Uint8Array(32));
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const changes = await sender.addEpochKey(epochId, key);

    const receiver = new YjsKeychain();
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

  // Replicates PeerborneDocument._keychainChangesForVisibility so the
  // per-visibility-mode behaviour can be exercised without standing up a
  // full document + libp2p stack. Production code lives in
  // PeerborneDocument (peerborne-document.ts) -- if you change the
  // visibility semantics there, mirror the change here.
  async function keychainChangesForVisibility(
    kc: YjsKeychain,
    visibility: 'full_history' | 'since_invited' | 'current_only',
    invitationEpoch: Uint8Array | undefined,
  ): Promise<Uint8Array> {
    switch (visibility) {
      case 'full_history':
        return kc.history();
      case 'since_invited':
        // When the local boundary is unknown (founding member),
        // default to `current_only` rather than full history. Mirrors
        // the production fallback in
        // `PeerborneDocument._keychainChangesForVisibility`.
        if (!invitationEpoch) return await kc.currentKeyChange();
        return await kc.historySince(invitationEpoch);
      case 'current_only':
      default:
        return await kc.currentKeyChange();
    }
  }

  test('since_invited visibility rejects a suffix the provider cannot export replay-safely', async () => {
    const sender = new YjsKeychain();
    const [id1] = await sender.add();
    const [id2] = await sender.add();
    const [id3] = await sender.add();

    // Simulate the receiver having been invited at id2.
    const invitationEpoch = id2;
    await expect(
      keychainChangesForVisibility(sender, 'since_invited', invitationEpoch),
    ).rejects.toThrow(
      'Yjs cannot export this keychain suffix replay-safely',
    );
    void id1;
    void id3;
  });

  test('since_invited visibility rejects an unsafe current-only projection when invitation epoch is unset', async () => {
    const sender = new YjsKeychain();
    const [id1] = await sender.add();
    const [id2] = await sender.add();
    void id1;
    await expect(
      keychainChangesForVisibility(sender, 'since_invited', undefined),
    ).rejects.toThrow('Yjs cannot export the current key replay-safely');
    void id2;
  });

  test('current_only visibility rejects an unsafe multi-key projection', async () => {
    const sender = new YjsKeychain();
    await sender.add();
    await sender.add();
    await expect(
      keychainChangesForVisibility(sender, 'current_only', undefined),
    ).rejects.toThrow('Yjs cannot export the current key replay-safely');
  });

  test('full_history visibility returns all keys', async () => {
    const sender = new YjsKeychain();
    const [id1] = await sender.add();
    const [id2] = await sender.add();
    const [id3] = await sender.add();
    const changes = await keychainChangesForVisibility(
      sender,
      'full_history',
      undefined,
    );
    const receiver = new YjsKeychain();
    receiver.merge(changes);
    const ids = (await receiver.keys()).map(([id]) => Array.from(id));
    expect(ids).toHaveLength(3);
    expect(ids).toContainEqual(Array.from(id1));
    expect(ids).toContainEqual(Array.from(id2));
    expect(ids).toContainEqual(Array.from(id3));
  });
});

describe('YjsJSONSerializer', () => {
  const SHALLOW_HISTORY_NODE_COUNT = 4_096;

  function nestedTree(depth: number): CRDTChangeNode<Uint8Array> {
    const root: CRDTChangeNode<Uint8Array> = { kind: 'document' };
    let cursor = root;
    for (let index = 1; index < depth; index++) {
      const child: CRDTChangeNode<Uint8Array> = { kind: 'document' };
      cursor.children = { [`cid-${index}`]: child };
      cursor = child;
    }
    return root;
  }

  function shallowTree(nodeCount: number): CRDTChangeNode<Uint8Array> {
    const root: CRDTChangeNode<Uint8Array> = { kind: 'document' };
    const children: Record<string, CRDTChangeNode<Uint8Array>> = {};
    for (let index = 1; index < nodeCount; index++) {
      children[`cid-${index}`] = { kind: 'document' };
    }
    root.children = children;
    return root;
  }

  test('serializeChanges/deserializeChanges are identity (passthrough)', () => {
    const serializer = new YjsJSONSerializer();
    const data = new Uint8Array([10, 20, 30, 40]);
    expect(serializer.serializeChanges(data)).toBe(data);
    expect(serializer.deserializeChanges(data)).toBe(data);
  });

  test('serializeChangeBlock/deserializeChangeBlock round-trip', () => {
    const serializer = new YjsJSONSerializer();
    const block = {
      changes: new Uint8Array([1, 2, 3, 4, 5]),
      nonce: new Uint8Array([10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]),
    };
    const serialized = serializer.serializeChangeBlock(block);
    expect(typeof serialized).toBe('string');

    const deserialized = serializer.deserializeChangeBlock(serialized);
    expect(deserialized.changes).toEqual(block.changes);
    expect(deserialized.nonce).toEqual(block.nonce);
  });

  test('serializeSyncMessage/deserializeSyncMessage round-trip with Merkle DAG', () => {
    const serializer = new YjsJSONSerializer();
    const message = {
      documentId: 'test-doc-123',
      changeId: 'cid-abc',
      changes: {
        kind: 'document' as const,
        change: new Uint8Array([100, 101, 102]),
        children: {
          'child-hash-1': {
            kind: 'writer' as const,
            change: new Uint8Array([200, 201]),
          },
        },
      },
      keychainChanges: new Uint8Array([50, 51, 52]),
    };

    const serialized = serializer.serializeSyncMessage(message);
    expect(serialized).toBeInstanceOf(Uint8Array);

    const deserialized = serializer.deserializeSyncMessage(serialized);
    expect(deserialized.documentId).toBe('test-doc-123');
    expect(deserialized.changeId).toBe('cid-abc');
    expect(deserialized.changes).toBeDefined();
    expect(deserialized.changes!.kind).toBe('document');
    expect(deserialized.changes!.change).toEqual(new Uint8Array([100, 101, 102]));
    expect(deserialized.changes!.children).toBeDefined();
    const children = deserialized.changes!.children as {
      [hash: string]: { kind: string; change?: Uint8Array };
    };
    expect(children['child-hash-1'].kind).toBe('writer');
    expect(children['child-hash-1'].change).toEqual(new Uint8Array([200, 201]));
    expect(deserialized.keychainChanges).toEqual(new Uint8Array([50, 51, 52]));
  });

  test('round-trips the maximum accepted nesting without overflowing JSON serialization', () => {
    const serializer = new YjsJSONSerializer();
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
    const serializer = new YjsJSONSerializer();
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
          CRDTChangeNode<Uint8Array>
        >,
      ),
    ).toHaveLength(SHALLOW_HISTORY_NODE_COUNT - 1);
  });

  test('preserves the existing sync-message wire bytes', () => {
    const serializer = new YjsJSONSerializer();
    const wire = serializer.serializeSyncMessage({
      documentId: 'wire-compatibility',
      changes: {
        kind: 'document',
        change: new Uint8Array([1, 2]),
        children: { cid: { kind: 'writer' } },
      },
    });

    expect(new TextDecoder().decode(wire)).toBe(
      '{"documentId":"wire-compatibility","changes":{"kind":"document","change":"AQI=","children":{"cid":{"kind":"writer"}}}}',
    );
  });

  test('preserves signed V4 full-load bytes across deserialize and reserialize', () => {
    const serializer = new YjsJSONSerializer();
    // Mirror the intended V4 response construction order: signature already
    // has an insertion slot from the cached sync message, while
    // keychainChanges is appended after the V4 challenge.
    const message: any = {
      documentId: '/signed-load',
      changeId: 'ROOT',
      changes: {
        kind: 'document' as const,
        keyID: 'epoch-7',
        change: new Uint8Array([1]),
        children: {
          PARENT: { kind: 'writer' as const, change: new Uint8Array([2]) },
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
    message.keychainChanges = new Uint8Array([3]);

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
    const serializer = new YjsJSONSerializer();
    const epochId = new Uint8Array(32);
    for (let i = 0; i < epochId.length; i++) epochId[i] = i * 7;
    const message = {
      documentId: 'welcome-doc',
      welcomeEpochId: epochId,
      keychainChanges: new Uint8Array([1, 2, 3]),
    };
    const serialized = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(serialized);
    expect(deserialized.welcomeEpochId).toEqual(epochId);
    expect(deserialized.keychainChanges).toEqual(new Uint8Array([1, 2, 3]));
  });

  test('deserializeSyncMessage omits welcomeEpochId when absent on wire', () => {
    const serializer = new YjsJSONSerializer();
    const message = {
      documentId: 'no-welcome-doc',
    };
    const serialized = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(serialized);
    expect(deserialized.welcomeEpochId).toBeUndefined();
  });

  test('serializeSyncMessage/deserializeSyncMessage preserves welcomeRecipient', () => {
    const serializer = new YjsJSONSerializer();
    const message = {
      documentId: 'welcome-doc',
      welcomeRecipient: 'recipient-serialized-pubkey-base64',
    };
    const serialized = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(serialized);
    expect(deserialized.welcomeRecipient).toBe(
      'recipient-serialized-pubkey-base64',
    );
  });

  test('deserializeSyncMessage omits welcomeRecipient when absent on wire', () => {
    const serializer = new YjsJSONSerializer();
    const message = {
      documentId: 'no-welcome-doc',
    };
    const serialized = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(serialized);
    expect(deserialized.welcomeRecipient).toBeUndefined();
  });

  test('serializeSyncMessage/deserializeSyncMessage preserves welcomeRecipientKemPublicKey', () => {
    const serializer = new YjsJSONSerializer();
    const kemPub = new Uint8Array(65);
    for (let i = 0; i < kemPub.length; i++) kemPub[i] = (i * 11) & 0xff;
    const message = {
      documentId: 'welcome-doc',
      welcomeRecipientKemPublicKey: kemPub,
    };
    const serialized = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(serialized);
    expect(deserialized.welcomeRecipientKemPublicKey).toEqual(kemPub);
  });

  test('serializeSyncMessage/deserializeSyncMessage preserves eciesSealed', () => {
    const serializer = new YjsJSONSerializer();
    const sealed = new Uint8Array(200);
    for (let i = 0; i < sealed.length; i++) sealed[i] = (i * 13) & 0xff;
    const message = {
      documentId: 'welcome-doc',
      eciesSealed: sealed,
    };
    const serialized = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(serialized);
    expect(deserialized.eciesSealed).toEqual(sealed);
  });

  test('serializeSyncMessage/deserializeSyncMessage preserves pathUpdate for BeeKEM revocation', () => {
    const serializer = new YjsJSONSerializer();
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
    const serialized = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(serialized);
    expect(deserialized.pathUpdate).toEqual(pathUpdate);
  });

  test('serializeSyncMessage/deserializeSyncMessage preserves PathUpdate v2 fields', () => {
    const serializer = new YjsJSONSerializer();
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
    const serializer = new YjsJSONSerializer();
    const message = { documentId: 'no-pathupdate-doc' };
    const serialized = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(serialized);
    expect(deserialized.pathUpdate).toBeUndefined();
  });

  test('serializeSyncMessage/deserializeSyncMessage preserves pathUpdateEpochId', () => {
    const serializer = new YjsJSONSerializer();
    const epochId = new Uint8Array(32);
    for (let i = 0; i < epochId.length; i++) epochId[i] = (i * 3) & 0xff;
    const message = {
      documentId: 'pathupdate-doc',
      pathUpdateEpochId: epochId,
    };
    const serialized = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(serialized);
    expect(deserialized.pathUpdateEpochId).toEqual(epochId);
  });

  test('deserializeSyncMessage rejects non-object pathUpdate', () => {
    const serializer = new YjsJSONSerializer();
    // Construct the wire payload directly so we can violate type safety.
    const wire = new TextEncoder().encode(
      JSON.stringify({ documentId: 'doc', pathUpdate: 'oops' }),
    );
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(/pathUpdate/);
  });

  test('deserializeSyncMessage rejects null pathUpdate', () => {
    const serializer = new YjsJSONSerializer();
    const wire = new TextEncoder().encode(
      JSON.stringify({ documentId: 'doc', pathUpdate: null }),
    );
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(/pathUpdate/);
  });

  test('deserializeSyncMessage rejects non-string pathUpdateEpochId', () => {
    const serializer = new YjsJSONSerializer();
    const wire = new TextEncoder().encode(
      JSON.stringify({ documentId: 'doc', pathUpdateEpochId: 42 }),
    );
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /pathUpdateEpochId/,
    );
  });

  test('serializeChangeBlock/deserializeChangeBlock round-trip with keyID', () => {
    const serializer = new YjsJSONSerializer();
    const block = {
      changes: new Uint8Array([1, 2, 3]),
      nonce: new Uint8Array([10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]),
      keyID: 'epoch-key-abc-123',
    };
    const serialized = serializer.serializeChangeBlock(block);
    const deserialized = serializer.deserializeChangeBlock(serialized);
    expect(deserialized.changes).toEqual(block.changes);
    expect(deserialized.nonce).toEqual(block.nonce);
    expect(deserialized.keyID).toBe('epoch-key-abc-123');
  });

  test('serializeChangeBlock/deserializeChangeBlock round-trip with blindIndexTokens', () => {
    const serializer = new YjsJSONSerializer();
    const block = {
      changes: new Uint8Array([5, 6, 7]),
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
    const serializer = new YjsJSONSerializer();
    const block = {
      changes: new Uint8Array([8, 9]),
      nonce: new Uint8Array([10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]),
      blindIndexTokens: {},
    };
    const serialized = serializer.serializeChangeBlock(block);
    const deserialized = serializer.deserializeChangeBlock(serialized);
    expect(deserialized.blindIndexTokens).toEqual({});
  });

  test('deserializeChangeBlock sanitizes dangerous keys in blindIndexTokens', () => {
    const serializer = new YjsJSONSerializer();
    // Manually construct JSON with dangerous keys
    const malicious = JSON.stringify({
      changes: 'AQID', // base64 for [1,2,3]
      nonce: 'ChsMDQ4PEBESExQV', // base64 for 12-byte nonce
      blindIndexTokens: {
        '__proto__': 'evil',
        'constructor': 'evil',
        'prototype': 'evil',
        'safe-key': 'safe-value',
      },
    });
    const deserialized = serializer.deserializeChangeBlock(malicious);
    expect(deserialized.blindIndexTokens).toEqual({ 'safe-key': 'safe-value' });
    expect(Object.prototype.hasOwnProperty.call(deserialized.blindIndexTokens, '__proto__')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(deserialized.blindIndexTokens, 'constructor')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(deserialized.blindIndexTokens, 'prototype')).toBe(false);
  });

  test('deserializeChangeBlock without keyID or blindIndexTokens omits them', () => {
    const serializer = new YjsJSONSerializer();
    const block = {
      changes: new Uint8Array([1, 2, 3]),
      nonce: new Uint8Array([10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]),
    };
    const serialized = serializer.serializeChangeBlock(block);
    const deserialized = serializer.deserializeChangeBlock(serialized);
    expect(deserialized.keyID).toBeUndefined();
    expect(deserialized.blindIndexTokens).toBeUndefined();
  });

  test('serializeSyncMessage handles message without optional fields', () => {
    const serializer = new YjsJSONSerializer();
    const message = {
      documentId: 'minimal-doc',
    };

    const serialized = serializer.serializeSyncMessage(message);
    const deserialized = serializer.deserializeSyncMessage(serialized);
    expect(deserialized.documentId).toBe('minimal-doc');
    expect(deserialized.changes).toBeUndefined();
    expect(deserialized.keychainChanges).toBeUndefined();
  });

  // Build a sync-message Uint8Array wire payload directly from a JS object,
  // bypassing `serializeSyncMessage`'s type-safety so we can test that
  // `deserializeSyncMessage` rejects every defined-but-malformed shape of
  // `changes` rather than silently passing the falsy value through.
  function buildWire(obj: unknown): Uint8Array {
    return new TextEncoder().encode(JSON.stringify(obj));
  }

  test('deserializeSyncMessage rejects "changes: null" (validation bypass regression)', () => {
    const serializer = new YjsJSONSerializer();
    const wire = buildWire({ documentId: 'doc', changes: null });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /expected a plain object.*got null/,
    );
  });

  test('deserializeSyncMessage rejects "changes: 0"', () => {
    const serializer = new YjsJSONSerializer();
    const wire = buildWire({ documentId: 'doc', changes: 0 });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /expected a plain object.*got number/,
    );
  });

  test('deserializeSyncMessage rejects "changes: \\"\\"" (empty string)', () => {
    const serializer = new YjsJSONSerializer();
    const wire = buildWire({ documentId: 'doc', changes: '' });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /expected a plain object.*got string/,
    );
  });

  test('deserializeSyncMessage accepts omitted "changes" field', () => {
    const serializer = new YjsJSONSerializer();
    const wire = buildWire({ documentId: 'doc' });
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.changes).toBeUndefined();
  });

  // Regression: prior to validating `documentId`, a malformed peer payload
  // missing the field (or sending a non-string value) would propagate
  // `documentId: undefined`/non-string downstream and violate the required
  // field contract of `CRDTSyncMessage`. The fix rejects the payload with a
  // descriptive error attributable back to the peer.
  test('deserializeSyncMessage rejects payload missing documentId', () => {
    const serializer = new YjsJSONSerializer();
    const wire = buildWire({ changeId: 'c1' });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'documentId' must be a string.*got undefined/,
    );
  });

  test('deserializeSyncMessage rejects payload with non-string documentId (number)', () => {
    const serializer = new YjsJSONSerializer();
    const wire = buildWire({ documentId: 42 });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'documentId' must be a string.*got number/,
    );
  });

  test('deserializeSyncMessage rejects payload with null documentId', () => {
    const serializer = new YjsJSONSerializer();
    const wire = buildWire({ documentId: null });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'documentId' must be a string.*got null/,
    );
  });

  test('deserializeSyncMessage rejects payload with object documentId', () => {
    const serializer = new YjsJSONSerializer();
    const wire = buildWire({ documentId: { id: 'doc' } });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'documentId' must be a string.*got object/,
    );
  });

  test('deserializeSyncMessage rejects non-string changeId', () => {
    const serializer = new YjsJSONSerializer();
    const wire = buildWire({ documentId: 'doc', changeId: 7 });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'changeId' must be a string when present.*got number/,
    );
  });

  test('deserializeSyncMessage rejects non-string signature', () => {
    const serializer = new YjsJSONSerializer();
    const wire = buildWire({ documentId: 'doc', signature: 7 });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'signature' must be a string when present.*got number/,
    );
  });

  test('deserializeSyncMessage rejects non-string keychainChanges', () => {
    const serializer = new YjsJSONSerializer();
    const wire = buildWire({ documentId: 'doc', keychainChanges: [1, 2, 3] });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'keychainChanges' must be a string when present.*got array/,
    );
  });

  test('deserializeSyncMessage rejects array snapshot', () => {
    const serializer = new YjsJSONSerializer();
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
    const serializer = new YjsJSONSerializer();
    const wire = buildWire({ documentId: 'doc', snapshot: null });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'snapshot' must be an object when present.*got null/,
    );
  });

  test('deserializeSyncMessage rejects "snapshot: 0"', () => {
    const serializer = new YjsJSONSerializer();
    const wire = buildWire({ documentId: 'doc', snapshot: 0 });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'snapshot' must be an object when present.*got number/,
    );
  });

  test('deserializeSyncMessage rejects "snapshot: \\"\\"" (empty string)', () => {
    const serializer = new YjsJSONSerializer();
    const wire = buildWire({ documentId: 'doc', snapshot: '' });
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*'snapshot' must be an object when present.*got string/,
    );
  });

  test('deserializeSyncMessage accepts omitted "snapshot" field', () => {
    const serializer = new YjsJSONSerializer();
    const wire = buildWire({ documentId: 'doc' });
    const deserialized = serializer.deserializeSyncMessage(wire);
    expect(deserialized.snapshot).toBeUndefined();
  });

  // Regression: prior to the upfront object guard, top-level non-object
  // payloads (null/array/primitive) threw a bare `TypeError: Cannot read
  // properties of null` instead of a descriptive error. Mirrors the
  // equivalent automerge guard.
  test('deserializeSyncMessage rejects a top-level JSON null payload', () => {
    const serializer = new YjsJSONSerializer();
    const wire = buildWire(null);
    expect(() => serializer.deserializeSyncMessage(wire)).not.toThrow(
      TypeError,
    );
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*expected a plain object.*got null/,
    );
  });

  test('deserializeSyncMessage rejects a top-level JSON array payload', () => {
    const serializer = new YjsJSONSerializer();
    const wire = buildWire([1, 2, 3]);
    expect(() => serializer.deserializeSyncMessage(wire)).toThrow(
      /Invalid sync message.*expected a plain object.*got array/,
    );
  });

  // Regression: prior to building the returned object explicitly, the
  // deserializer spread `...deserialized` straight onto the result. A
  // malicious peer could append junk keys and they would leak through to
  // downstream consumers. The fix only propagates fields declared on
  // `CRDTSyncMessage`.
  test('deserializeSyncMessage strips peer-supplied junk keys', () => {
    const serializer = new YjsJSONSerializer();
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
});
