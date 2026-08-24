import { describe, expect, test, beforeAll } from '@jest/globals';
import { Doc, encodeStateAsUpdateV2 } from 'yjs';
import {
  YjsProvider,
  YjsACL,
  YjsACLProvider,
  YjsKeychain,
  YjsKeychainProvider,
  YjsJSONSerializer,
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

  test('historySince() returns only keys from the given key ID onward', async () => {
    const source = new YjsKeychain();
    const [id1] = await source.add();
    const [id2] = await source.add();
    const [id3] = await source.add();

    // Slice from the second key: receiver should observe ids 2 and 3 only.
    const slice = await source.historySince(id2);

    const receiver = new YjsKeychain();
    receiver.merge(slice);
    const keys = await receiver.keys();
    expect(keys).toHaveLength(2);
    const ids = keys.map(([id]) => Array.from(id));
    expect(ids).toContainEqual(Array.from(id2));
    expect(ids).toContainEqual(Array.from(id3));
    expect(ids).not.toContainEqual(Array.from(id1));
  });

  test('historySince() falls back to full history when the boundary key is unknown', async () => {
    const source = new YjsKeychain();
    const [id1] = await source.add();
    const [id2] = await source.add();

    const unknownID = new Uint8Array(32).fill(0xff);
    const slice = await source.historySince(unknownID);

    const receiver = new YjsKeychain();
    receiver.merge(slice);
    const keys = await receiver.keys();
    expect(keys).toHaveLength(2);
    const ids = keys.map(([id]) => Array.from(id));
    expect(ids).toContainEqual(Array.from(id1));
    expect(ids).toContainEqual(Array.from(id2));
  });

  test('historySince() with the current key returns only the current key', async () => {
    const source = new YjsKeychain();
    await source.add();
    await source.add();
    const [currentID] = await source.current();
    const slice = await source.historySince(currentID);

    const receiver = new YjsKeychain();
    receiver.merge(slice);
    const keys = await receiver.keys();
    expect(keys).toHaveLength(1);
    expect(Array.from(keys[0][0])).toEqual(Array.from(currentID));
  });

  // ───────────────────────────────────────────────────────────────────
  // PR #285 round 6 regression coverage: BeeKEM PathUpdate flow installs
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
    // A failure here surfaces the round-6 cache-key-format mismatch.
    const retrieved = keychain.getKey(epochId);
    expect(retrieved).toBe(key);

    // current() must report the same 32-byte ID (and key) so
    // `_makeChange` writes the correct wire-format key-ID prefix.
    const [currentID, currentKey] = await keychain.current();
    expect(currentID.length).toBe(32);
    expect(Array.from(currentID)).toEqual(Array.from(epochId));
    expect(currentKey).toBe(key);
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

  test('since_invited visibility returns only keys from _invitationEpoch onward', async () => {
    const sender = new YjsKeychain();
    const [id1] = await sender.add();
    const [id2] = await sender.add();
    const [id3] = await sender.add();

    // Simulate the receiver having been invited at id2.
    const invitationEpoch = id2;
    const changes = await keychainChangesForVisibility(
      sender,
      'since_invited',
      invitationEpoch,
    );
    const receiver = new YjsKeychain();
    receiver.merge(changes);
    const ids = (await receiver.keys()).map(([id]) => Array.from(id));
    expect(ids).toHaveLength(2);
    expect(ids).toContainEqual(Array.from(id2));
    expect(ids).toContainEqual(Array.from(id3));
    expect(ids).not.toContainEqual(Array.from(id1));
  });

  test('since_invited visibility falls back to current_only when invitation epoch unset', async () => {
    const sender = new YjsKeychain();
    const [id1] = await sender.add();
    const [id2] = await sender.add();
    void id1;
    const changes = await keychainChangesForVisibility(
      sender,
      'since_invited',
      undefined,
    );
    const receiver = new YjsKeychain();
    receiver.merge(changes);
    const ids = (await receiver.keys()).map(([id]) => Array.from(id));
    expect(ids).toHaveLength(1);
    expect(ids).toContainEqual(Array.from(id2));
  });

  test('current_only visibility returns only the most recent key', async () => {
    const sender = new YjsKeychain();
    await sender.add();
    await sender.add();
    const [currentID] = await sender.current();
    const changes = await keychainChangesForVisibility(
      sender,
      'current_only',
      undefined,
    );
    const receiver = new YjsKeychain();
    receiver.merge(changes);
    const keys = await receiver.keys();
    expect(keys).toHaveLength(1);
    expect(Array.from(keys[0][0])).toEqual(Array.from(currentID));
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
