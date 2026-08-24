import { describe, expect, test, beforeAll, jest } from '@jest/globals';
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
});

describe('AutomergeACLProvider', () => {
  test('initialize() returns a new AutomergeACL', () => {
    const provider = new AutomergeACLProvider();
    const acl = provider.initialize();
    expect(acl).toBeInstanceOf(AutomergeACL);
  });
});

// ─── AutomergeKeychain ──────────────────────────────────────────────

describe('AutomergeKeychain', () => {
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

  // The keychain doc's initial empty `keys: []` op is written under the
  // shared KEYCHAIN_SEED_ACTOR (see newKeychainDoc()), so slices produced
  // by historySince()/currentKeyChange() can be merged into any fresh
  // receiver keychain without a root-array actor conflict.
  test('historySince() returns only keys from the given key ID onward', async () => {
    const source = new AutomergeKeychain();
    const [id1] = await source.add();
    const [id2] = await source.add();
    const [id3] = await source.add();

    const slice = await source.historySince(id2);

    const receiver = new AutomergeKeychain();
    receiver.merge(slice);
    const keys = await receiver.keys();
    expect(keys).toHaveLength(2);
    const ids = keys.map(([id]) => Array.from(id));
    expect(ids).toContainEqual(Array.from(id2));
    expect(ids).toContainEqual(Array.from(id3));
    expect(ids).not.toContainEqual(Array.from(id1));
  });

  test('historySince() falls back to full history when the boundary key is unknown', async () => {
    const source = new AutomergeKeychain();
    const [id1] = await source.add();
    const [id2] = await source.add();

    const unknownID = new Uint8Array(32).fill(0xff);
    const slice = await source.historySince(unknownID);

    // The unknown-boundary path should return the full change list,
    // and (thanks to the deterministic seed actor) that slice should
    // merge cleanly into a fresh receiver keychain carrying both keys.
    const fullHistory = source.history();
    expect(slice.length).toBe(fullHistory.length);

    const receiver = new AutomergeKeychain();
    receiver.merge(slice);
    const ids = (await receiver.keys()).map(([id]) => Array.from(id));
    expect(ids).toContainEqual(Array.from(id1));
    expect(ids).toContainEqual(Array.from(id2));
  });

  test('historySince() with the current key returns only the current key', async () => {
    const source = new AutomergeKeychain();
    await source.add();
    const [id2] = await source.add();
    const [currentID] = await source.current();
    expect(Array.from(currentID)).toEqual(Array.from(id2));

    const slice = await source.historySince(currentID);
    // The slice is built on a doc seeded with KEYCHAIN_SEED_ACTOR, so it
    // merges cleanly into a fresh receiver keychain (whose empty `keys`
    // array shares the same seed actor).
    const receiver = new AutomergeKeychain();
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
    const keychain = new AutomergeKeychain();
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

  // PR #284 r24 Copilot review: `tipsHash` is defined as a fixed 32-byte
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
