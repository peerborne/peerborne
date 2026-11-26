import { webcrypto } from 'node:crypto';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { MemoryBlockstore } from 'blockstore-core/memory';
import * as Y from 'yjs';
import {
  beekemPathUpdateV2,
  Peerborne,
  PeerborneDocument,
  SubtleCrypto,
  generateEciesKeyPair,
  deserializeBeeKEMWelcomeV2FromWire,
  documentCheckpointCommitment,
  activateDocumentReplacement,
  createCRDTActorNonce,
  crdtActorRegistrationPayload,
  crdtChangeAuthorPayload,
  deriveCRDTActorDigest,
  documentRecoveryContentDigest,
  encodeCRDTChangeAuthor,
  type BeeKEMForkRecord,
  type DurableBeeKEMForkStore,
  type DocumentRecoveryApproval,
  type DocumentRecoveryLocator,
} from '@peerborne/core';
import {
  YjsProvider,
  YjsACLProvider,
  YjsKeychainProvider,
  YjsJSONSerializer,
  type YjsKeychain,
} from '@peerborne/yjs';
import {
  INVITATION_ID_LENGTH,
  signInvitationOffer,
} from '../../../packages/core/src/invitation-wire.js';

Object.defineProperty(globalThis, 'crypto', {
  value: webcrypto,
  configurable: true,
});

async function fixture(forkStore?: DurableBeeKEMForkStore) {
  const signing = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['sign', 'verify'],
  );
  const kem = await generateEciesKeyPair();
  const blocks = new MemoryBlockstore();
  const traffic = new WeakMap<
    object,
    { broadcasts: Uint8Array[]; updates: Uint8Array[]; keychain: YjsKeychain }
  >();
  function document(
    path = '/checkpoint-fixture',
    identity = signing,
    scopeStore: DurableBeeKEMForkStore | null = forkStore ?? null,
  ) {
    const serializer = new YjsJSONSerializer();
    const registry = new Map();
    const broadcasts: Uint8Array[] = [];
    const updates: Uint8Array[] = [];
    const keychainProvider = new YjsKeychainProvider();
    let keychain: YjsKeychain;
    const swarm = {
      config: { enableSigning: true, enableTopicValidators: false },
      beekemForkStore: scopeStore ?? undefined,
      heliaNode: {
        blockstore: blocks,
        libp2p: {
          services: {
            pubsub: {
              addEventListener() {},
              removeEventListener() {},
              subscribe() {},
              unsubscribe() {},
              async publish(_topic: string, data: Uint8Array) {
                broadcasts.push(new Uint8Array(data));
              },
            },
          },
          getConnections: () => [{ remoteAddr: '/memory/checkpoint-fixture' }],
          async dialProtocol(_peer: unknown, protocols: string[]) {
            return {
              send(chunk: Uint8Array) {
                if (protocols.includes(beekemPathUpdateV2)) {
                  const pathBytes = new DataView(
                    chunk.buffer,
                    chunk.byteOffset,
                  ).getUint32(0);
                  updates.push(chunk.slice(4 + pathBytes));
                }
                return true;
              },
              async close() {},
            };
          },
        },
      },
      registerDocument(path: string, doc: unknown) {
        if (registry.has(path)) throw new Error('Already registered');
        registry.set(path, doc);
      },
      unregisterDocument(path: string, doc: unknown) {
        if (registry.get(path) === doc) registry.delete(path);
      },
    };
    const doc = new PeerborneDocument(
      swarm as never,
      path,
      identity.privateKey,
      identity.publicKey,
      new YjsProvider(),
      new SubtleCrypto(),
      new YjsACLProvider(),
      {
        keyIDLength: keychainProvider.keyIDLength,
        initialize: () => (keychain = keychainProvider.initialize()),
      },
      serializer,
      serializer,
      serializer,
    );
    traffic.set(doc, {
      broadcasts,
      updates,
      get keychain() {
        return keychain;
      },
    });
    return doc;
  }
  const created = document();
  if (forkStore) assert.equal(await created.provisionBeeKEMForkStore(), true);
  await created.setKemKeyPair(kem);
  await created.create();
  await created.change((doc) => {
    doc.getText('fixture').insert(0, 'before restart');
  });
  return { document, created, signing, kem, traffic };
}

// addReader cannot onboard a new identity, so register the member's BeeKEM
// leaf through the onboarding step that invitations use.
async function registerReader(
  document: object,
  reader: CryptoKey,
  kemPublicKey: CryptoKey,
) {
  const internal = document as {
    _runStateMutation<T>(operation: () => Promise<T>): Promise<T>;
    _addReaderUnlocked(
      reader: CryptoKey,
      serializedReader: string,
      kemPublicKey: Uint8Array,
      broadcastWelcome: boolean,
    ): Promise<unknown>;
  };
  const serializedReader = await new SubtleCrypto().serializePublicKey(reader);
  const kem = new Uint8Array(
    await crypto.subtle.exportKey('raw', kemPublicKey),
  );
  await internal._runStateMutation(() =>
    internal._addReaderUnlocked(reader, serializedReader, kem, false),
  );
}

const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';

// A canonical CIDv1 (raw, sha2-256) whose digest encodes `index`.
function syntheticCid(index: number): string {
  const bytes = new Uint8Array(36);
  bytes.set([0x01, 0x55, 0x12, 0x20]);
  new DataView(bytes.buffer).setUint32(32, index);
  let encoded = 'b';
  let bits = 0;
  let value = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      encoded += BASE32[(value >>> bits) & 31];
    }
    value &= (1 << bits) - 1;
  }
  return bits > 0 ? encoded + BASE32[(value << (5 - bits)) & 31] : encoded;
}

// Record known, already-referenced changes as a long edit history leaves
// them, without creating each change.
function learnHistory(document: object, from: number, count: number) {
  const known = document as {
    _hashes: Set<string>;
    _referencedAncestors: Set<string>;
  };
  for (let index = from; index < from + count; index++) {
    const cid = syntheticCid(index);
    known._hashes.add(cid);
    known._referencedAncestors.add(cid);
  }
}

function decryptBroadcast(frame: Uint8Array, key: CryptoKey) {
  const auth = new SubtleCrypto();
  const nonceStart = new YjsKeychainProvider().keyIDLength;
  const dataStart = nonceStart + auth.nonceBytes;
  return auth.decrypt(
    frame.slice(dataStart),
    key,
    frame.slice(nonceStart, dataStart),
  );
}

async function signPathUpdateWithDifferentCommitment(
  update: Uint8Array,
  field: 'parentTreeHash' | 'treeHash',
  signer: CryptoKey,
) {
  const serializer = new YjsJSONSerializer();
  const { signature: _signature, ...message } =
    serializer.deserializeSyncMessage(update);
  const pathUpdate = message.pathUpdate!;
  const differentHash = Buffer.from(pathUpdate[field], 'base64');
  differentHash[0] ^= 1;
  message.pathUpdate = {
    ...pathUpdate,
    [field]: differentHash.toString('base64'),
  };
  const signature = await new SubtleCrypto().sign(
    serializer.serializeSyncMessage(message),
    signer,
  );
  return serializer.serializeSyncMessage({
    ...message,
    signature: Buffer.from(signature).toString('base64'),
  });
}

test('restores authenticated Yjs state, keys, history, and writer access before opening', async () => {
  const { document, created, kem } = await fixture();
  const checkpoint = await created.exportCheckpoint();
  const restored = document();
  await restored.setKemKeyPair(kem);
  await restored.restoreCheckpoint(checkpoint);
  assert.equal(
    restored.document.getText('fixture').toString(),
    'before restart',
  );
  assert.equal(restored.historySize(), created.historySize());
  assert.equal((await restored.getWriters()).length, 1);
  await restored.open();
  await restored.change((doc) => {
    doc.getText('fixture').insert(doc.getText('fixture').length, ' and after');
  });
  assert.equal(
    restored.document.getText('fixture').toString(),
    'before restart and after',
  );
  await assert.rejects(
    restored.restoreCheckpoint(checkpoint),
    /fresh document/,
  );
});

test('rejects tampering, another identity, and another document before installing state', async () => {
  const { document, created } = await fixture();
  const checkpoint = await created.exportCheckpoint();
  const damaged = {
    payload: new Uint8Array(checkpoint.payload),
    signature: checkpoint.signature,
  };
  damaged.payload[damaged.payload.length - 1] ^= 1;
  const candidate = document();
  await assert.rejects(
    candidate.restoreCheckpoint(damaged),
    /authentication failed/,
  );
  assert.equal(candidate.historySize(), 0);
  const other = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['sign', 'verify'],
  );
  await assert.rejects(
    document(undefined, other).restoreCheckpoint(checkpoint),
    /authentication failed/,
  );
  await assert.rejects(
    document('/another').restoreCheckpoint(checkpoint),
    /another document/,
  );
  await candidate.restoreCheckpoint(checkpoint);
  assert.equal(candidate.historySize(), created.historySize());
});

test('rejects malformed signed state atomically and permits a subsequent valid restore', async () => {
  const { document, created, signing } = await fixture();
  const checkpoint = await created.exportCheckpoint();
  const state = JSON.parse(new TextDecoder().decode(checkpoint.payload));
  state.hashes = [];
  const payload = new TextEncoder().encode(JSON.stringify(state));
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-384' },
      signing.privateKey,
      payload,
    ),
  );
  const candidate = document();
  await assert.rejects(
    candidate.restoreCheckpoint({ payload, signature }),
    /no document history/,
  );
  assert.equal(candidate.historySize(), 0);
  await candidate.restoreCheckpoint(checkpoint);
  assert.equal((await candidate.getWriters()).length, 1);
});

test('a document that has seen more than 100,000 changes still exports and restores', async () => {
  const { document, created, kem } = await fixture();
  // A writer that keeps editing snapshots every 128 changes at the latest.
  learnHistory(created, 0, 100_001);
  await created.change((doc) => doc.getText('fixture').insert(0, 'one '));
  await created.snapshot();
  // One more generation (1,024 CIDs) lets the next snapshot forget the first.
  learnHistory(created, 100_001, 1_025);
  await created.change((doc) => doc.getText('fixture').insert(0, 'two '));
  await created.snapshot();

  const checkpoint = await created.exportCheckpoint();
  const restored = document();
  await restored.setKemKeyPair(kem);
  await restored.restoreCheckpoint(checkpoint);
  assert.equal(
    restored.document.getText('fixture').toString(),
    'two one before restart',
  );
  assert.ok(created.historySize() < 2_048);
  assert.equal(created.hasChange(syntheticCid(0)), false);
  assert.equal(created.hasChange(syntheticCid(100_001)), true);
  assert.equal(restored.historySize(), created.historySize());
  await restored.open();
  await restored.change((doc) => doc.getText('fixture').insert(0, 'three '));
  const reopened = document();
  await reopened.setKemKeyPair(kem);
  await reopened.restoreCheckpoint(await restored.exportCheckpoint());
  assert.equal(
    reopened.document.getText('fixture').toString(),
    'three two one before restart',
  );
});

test('refuses to export a checkpoint that could not be restored', async () => {
  const { document, created, kem } = await fixture();
  const saved = await created.exportCheckpoint();
  learnHistory(created, 0, 100_001);
  await assert.rejects(
    created.exportCheckpoint(),
    /Invalid checkpoint collection/,
  );
  const restored = document();
  await restored.setKemKeyPair(kem);
  await restored.restoreCheckpoint(saved);
  assert.equal(restored.document.getText('fixture').toString(), 'before restart');
});

test('rejects a signed checkpoint that forgot its change root', async () => {
  const { document, created, signing } = await fixture();
  await created.change((doc) => doc.getText('fixture').insert(0, 'next '));
  const checkpoint = await created.exportCheckpoint();
  const state = JSON.parse(new TextDecoder().decode(checkpoint.payload));
  const message = new YjsJSONSerializer().deserializeSyncMessage(
    Buffer.from(state.message, 'base64'),
  );
  state.hashes = state.hashes.filter(
    (cid: string) => cid !== message.changeId,
  );
  state.recentTips = state.recentTips.filter(
    ([cid]: [string, string]) => cid !== message.changeId,
  );
  const payload = new TextEncoder().encode(JSON.stringify(state));
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-384' },
      signing.privateKey,
      payload,
    ),
  );
  const candidate = document();
  await assert.rejects(
    candidate.restoreCheckpoint({ payload, signature }),
    /Invalid checkpoint change root/,
  );
  assert.equal(candidate.historySize(), 0);
  await candidate.restoreCheckpoint(checkpoint);
  assert.equal(
    candidate.document.getText('fixture').toString(),
    'next before restart',
  );
});

test('a document that adopts a tree naming forgotten ancestors still exports and restores', async () => {
  const { document, created, signing, kem, traffic } = await fixture();
  for (let index = 0; index < 60; index++)
    await created.change((doc) => doc.getText('fixture').insert(0, '.'));
  const serializer = new YjsJSONSerializer();
  const { broadcasts, keychain } = traffic.get(created)!;
  const [, key] = await keychain.current();
  const messages = [];
  for (const frame of broadcasts) {
    const message = serializer.deserializeSyncMessage(
      await decryptBroadcast(frame, key),
    );
    if (message.signatureContext === 'ordinary-sync-v1' && message.changes)
      messages.push(message);
  }
  // Snapshots prune the tree to its 50 newest changes and trim twice.
  learnHistory(created, 0, 1_025);
  await created.snapshot();
  learnHistory(created, 1_025, 1_025);
  await created.snapshot();

  const cids = (node: { children?: unknown }): string[] =>
    node.children && typeof node.children === 'object'
      ? Object.entries(
          node.children as Record<string, { children?: unknown }>,
        ).flatMap(([cid, child]) => [cid, ...cids(child)])
      : [];
  const known = messages.find(
    (message) =>
      created.hasChange(message.changeId!) &&
      cids(message.changes!).some((cid) => !created.hasChange(cid)),
  );
  assert.ok(known, 'a retained change must name forgotten ancestors');
  const head = messages.at(-1)!.changeId!;
  // Another device of this writer publishes a change whose primary parent is
  // its own older head and that cross-links this replica's head.
  const auth = new SubtleCrypto();
  const author = {
    signer: await auth.serializePublicKey(signing.publicKey),
    nonce: createCRDTActorNonce(),
  };
  const binding = new YjsProvider().actorBinding;
  const other = new Y.Doc();
  other.clientID = Number(
    binding.actorFromDigest(
      await deriveCRDTActorDigest(created.documentPath, author),
    ),
  );
  other.getText('fixture').insert(0, 'other device ');
  const otherChange = Y.encodeStateAsUpdateV2(other);
  const authored = binding.attach(
    otherChange,
    encodeCRDTChangeAuthor({
      ...author,
      registrationSignature: await auth.sign(
        crdtActorRegistrationPayload(created.documentPath, author),
        signing.privateKey,
      ),
      signature: await auth.sign(
        crdtChangeAuthorPayload(created.documentPath, author, otherChange),
        signing.privateKey,
      ),
    }),
  );
  const unsigned = {
    documentId: created.documentPath,
    signatureContext: 'ordinary-sync-v1' as const,
    changeId: syntheticCid(9_000_000),
    changes: {
      kind: 'document' as const,
      change: authored,
      children: {
        [known.changeId!]: known.changes!,
        [head]: { kind: 'document' as const },
      },
    },
  };
  const signature = Buffer.from(
    await new SubtleCrypto().sign(
      serializer.serializeSyncMessage(unsigned),
      signing.privateKey,
    ),
  ).toString('base64');
  const message = serializer.deserializeSyncMessage(
    serializer.serializeSyncMessage({ ...unsigned, signature } as never),
  );
  assert.equal(await created.sync(message as never), true);
  assert.equal(created.hasChange(unsigned.changeId), true);

  const restored = document();
  await restored.setKemKeyPair(kem);
  await restored.restoreCheckpoint(await created.exportCheckpoint());
  const text = created.document.getText('fixture').toString();
  assert.ok(text.includes('other device'));
  assert.equal(restored.document.getText('fixture').toString(), text);
  await restored.open();
  await restored.change((doc) => doc.getText('fixture').insert(0, 'after '));
  const reopened = document();
  await reopened.setKemKeyPair(kem);
  await reopened.restoreCheckpoint(await restored.exportCheckpoint());
  assert.equal(
    reopened.document.getText('fixture').toString(),
    'after ' + text,
  );
});

test('a restored document ignores a replay of a change it still knows after trimming', async () => {
  const { document, created, kem, traffic } = await fixture();
  learnHistory(created, 0, 1_025);
  await created.change((doc) => doc.getText('fixture').insert(0, 'one '));
  await created.snapshot();
  learnHistory(created, 1_025, 1_025);
  await created.change((doc) => doc.getText('fixture').insert(0, 'two '));
  await created.snapshot();
  assert.equal(created.hasChange(syntheticCid(0)), false);
  const { broadcasts, keychain } = traffic.get(created)!;
  const [, key] = await keychain.current();
  const replay = new YjsJSONSerializer().deserializeSyncMessage(
    await decryptBroadcast(broadcasts.at(-1)!, key),
  );

  const restored = document();
  await restored.setKemKeyPair(kem);
  await restored.restoreCheckpoint(await created.exportCheckpoint());
  await restored.open();
  const historySize = restored.historySize();
  let updates = 0;
  restored.subscribe('replay', () => updates++, 'all');
  assert.equal(await restored.sync(replay as never), true);
  assert.equal(restored.historySize(), historySize);
  assert.equal(updates, 0);
  assert.equal(
    restored.document.getText('fixture').toString(),
    'two one before restart',
  );
});

test('preserves membership state so a restored founder can remove an existing reader', async () => {
  const { document, created, kem } = await fixture();
  const member = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['sign', 'verify'],
  );
  const memberKem = await generateEciesKeyPair();
  await registerReader(created, member.publicKey, memberKem.publicKey);
  const checkpoint = await created.exportCheckpoint();
  const localWelcome = JSON.parse(new TextDecoder().decode(checkpoint.payload))
    .beekem.welcome;
  assert.throws(
    () => deserializeBeeKEMWelcomeV2FromWire(localWelcome),
    /appended rightmost leaf/,
  );
  const restored = document();
  await restored.setKemKeyPair(kem);
  await restored.restoreCheckpoint(checkpoint);
  await restored.open();
  assert.equal(
    (await restored.getReaders()).length,
    (await created.getReaders()).length,
  );
  await restored.removeReader(member.publicKey);
  assert.equal(
    (await restored.getReaders()).length,
    (await created.getReaders()).length - 1,
  );
  const afterRemoval = document();
  await afterRemoval.setKemKeyPair(kem);
  await afterRemoval.restoreCheckpoint(await restored.exportCheckpoint());
  await afterRemoval.open();
  await afterRemoval.change((doc) => {
    doc.getText('fixture').insert(0, 'current ');
  });
  assert.equal(
    afterRemoval.document.getText('fixture').toString(),
    'current before restart',
  );
});

test('pinned restart preserves revocation of readers and former editors', async () => {
  for (const schedule of [0, 1, 2, 3, 4, 5, 6, 7]) {
    const { document, created, kem, traffic } = await fixture();
    async function start(
      checkpoint: Awaited<ReturnType<typeof created.exportCheckpoint>>,
    ) {
      const fresh = document();
      await fresh.setKemKeyPair(kem);
      await fresh.restoreCheckpoint(
        checkpoint,
        await documentCheckpointCommitment(checkpoint),
      );
      await fresh.open();
      return fresh;
    }
    const beforeInvitation = await created.exportCheckpoint();
    let live = schedule & 1 ? await start(beforeInvitation) : created;
    const member = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      false,
      ['sign', 'verify'],
    );
    const memberKem = await generateEciesKeyPair();
    await registerReader(live, member.publicKey, memberKem.publicKey);
    const promoted = (schedule & 4) !== 0;
    if (promoted) await live.addWriter(member.publicKey);
    const beforeRemoval = await live.exportCheckpoint();
    if (schedule & 2) live = await start(beforeRemoval);
    assert.equal((await live.getReaders()).length, 2);
    assert.equal((await live.getWriters()).length, promoted ? 2 : 1);
    if (promoted) await live.removeWriter(member.publicKey);
    const beforeTraffic = traffic.get(live)!;
    const [priorEpoch, priorKey] = await beforeTraffic.keychain.current();
    await live.removeReader(member.publicKey);
    const removalFrame = beforeTraffic.broadcasts.at(-1)!;
    assert.deepEqual(removalFrame.slice(0, priorEpoch.length), priorEpoch);
    await decryptBroadcast(removalFrame, priorKey);

    const checkpoint = await live.exportCheckpoint();
    const trustedCommitment = await documentCheckpointCommitment(checkpoint);
    const restarted = document();
    await restarted.setKemKeyPair(kem);
    for (const older of [beforeInvitation, beforeRemoval]) {
      await assert.rejects(
        restarted.restoreCheckpoint(older, trustedCommitment),
        /checkpoint commitment mismatch/,
      );
      assert.equal(restarted.historySize(), 0);
      assert.equal((await restarted.getReaders()).length, 0);
    }
    await restarted.restoreCheckpoint(checkpoint, trustedCommitment);
    assert.equal((await restarted.getReaders()).length, 1);
    assert.equal((await restarted.getWriters()).length, 1);
    await restarted.open();
    await restarted.change((doc) =>
      doc.getText('fixture').insert(0, 'current '),
    );
    const afterTraffic = traffic.get(restarted)!;
    const [currentEpoch, currentKey] = await afterTraffic.keychain.current();
    const currentFrame = afterTraffic.broadcasts.at(-1)!;
    assert.notDeepEqual(currentEpoch, priorEpoch);
    assert.deepEqual(currentFrame.slice(0, currentEpoch.length), currentEpoch);
    await decryptBroadcast(currentFrame, currentKey);
    await assert.rejects(decryptBroadcast(currentFrame, priorKey));
    const resumed = await start(await restarted.exportCheckpoint());
    assert.equal(
      resumed.document.getText('fixture').toString(),
      'current before restart',
    );
    assert.equal((await resumed.getReaders()).length, 1);
  }
});

test('same-predecessor signed removal forks stop either branch, including after pinned restore', async () => {
  for (const restartMask of [0, 1, 2, 3]) {
    const { document, created, signing, kem, traffic } = await fixture();
    async function start(
      checkpoint: Awaited<ReturnType<typeof created.exportCheckpoint>>,
    ) {
      const replica = document();
      await replica.setKemKeyPair(kem);
      await replica.restoreCheckpoint(
        checkpoint,
        await documentCheckpointCommitment(checkpoint),
      );
      await replica.open();
      return replica;
    }
    const member = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      false,
      ['sign', 'verify'],
    );
    const memberKem = await generateEciesKeyPair();
    await registerReader(created, member.publicKey, memberKem.publicKey);
    const first = created;
    const second = await start(await first.exportCheckpoint());
    await first.removeReader(member.publicKey);
    await second.removeReader(member.publicKey);
    const firstUpdate = traffic.get(first)!.updates.at(-1)!;
    const secondUpdate = traffic.get(second)!.updates.at(-1)!;
    const replicas = [
      restartMask & 1 ? await start(await first.exportCheckpoint()) : first,
      restartMask & 2 ? await start(await second.exportCheckpoint()) : second,
    ];
    for (const [index, replica] of replicas.entries()) {
      const { keychain, broadcasts } = traffic.get(replica)!;
      const [epochBefore, keyBefore] = await keychain.current();
      const ownUpdate = index === 0 ? firstUpdate : secondUpdate;
      const rivalUpdate = index === 0 ? secondUpdate : firstUpdate;

      await replica.handleBeeKEMPathUpdateRequestData(ownUpdate);
      assert.equal(replica.competingBeeKEMGeneration, undefined);
      for (const field of ['parentTreeHash', 'treeHash'] as const) {
        const inconsistentClaim = await signPathUpdateWithDifferentCommitment(
          rivalUpdate,
          field,
          signing.privateKey,
        );
        await replica.handleBeeKEMPathUpdateRequestData(inconsistentClaim);
        assert.equal(replica.competingBeeKEMGeneration, undefined);
        assert.deepEqual((await keychain.current())[0], epochBefore);
        const count = broadcasts.length;
        await replica.change((doc) => doc.getText('fixture').insert(0, '+'));
        assert.equal(broadcasts.length, count + 1);
        await decryptBroadcast(broadcasts.at(-1)!, keyBefore);
      }

      const countBefore = broadcasts.length;
      await replica.handleBeeKEMPathUpdateRequestData(rivalUpdate);
      assert.equal(replica.competingBeeKEMGeneration, 2);
      assert.deepEqual((await keychain.current())[0], epochBefore);
      assert.throws(() => replica.document, /indeterminate authorization/);
      await assert.rejects(
        replica.exportCheckpoint(),
        /indeterminate authorization/,
      );
      await assert.rejects(
        replica.change(() => {}),
        /indeterminate authorization/,
      );
      assert.equal(broadcasts.length, countBefore);
    }
  }
});

function forkAnchorFixture(
  interrupt: 'none' | 'before-write' | 'after-write' = 'none',
) {
  const records = new Map<string, BeeKEMForkRecord>();
  const store: DurableBeeKEMForkStore = {
    async load(scope) {
      return records.get(JSON.stringify(scope));
    },
    async compareAndSwap(scope, expected, next) {
      const key = JSON.stringify(scope);
      if (JSON.stringify(records.get(key)) !== JSON.stringify(expected))
        return false;
      if (next.phase === 'quarantined' && interrupt === 'before-write') {
        throw new Error('Interrupted before fork stop was persisted');
      }
      records.set(key, next);
      if (next.phase === 'quarantined' && interrupt === 'after-write') {
        throw new Error('Interrupted before fork stop acknowledgment');
      }
      return true;
    },
  };
  return { records, store };
}

test('guarded clean close permits pinned restore on a fresh document handle', async () => {
  const { records, store } = forkAnchorFixture();
  const { created, document, kem } = await fixture(store);
  const checkpoint = await created.exportCheckpoint();
  const pin = await documentCheckpointCommitment(checkpoint);
  const concurrent = document();
  await assert.rejects(
    concurrent.restoreCheckpoint(checkpoint, pin),
    /fork anchor blocks/,
  );
  await assert.rejects(document('/missing-scope').open(), /not provisioned/);
  await created.close();
  assert.throws(() => created.document, /fork guard blocks/);
  assert.deepEqual(
    [...records.values()],
    [{ phase: 'available', revision: 2 }],
  );
  const restarted = document();
  await restarted.setKemKeyPair(kem);
  await restarted.restoreCheckpoint(checkpoint, pin);
  assert.equal(await restarted.open(), true);
  assert.equal(
    restarted.document.getText('fixture').toString(),
    'before restart',
  );
  await restarted.close();
});

test('guarded invitation acceptance acquires an enrolled scope before dialing', async () => {
  const { records, store } = forkAnchorFixture();
  const auth = new SubtleCrypto();
  let dials = 0;
  async function swarm(forkStore?: DurableBeeKEMForkStore) {
    const signing = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      false,
      ['sign', 'verify'],
    );
    const serializer = new YjsJSONSerializer();
    const node = new Peerborne(
      signing.privateKey,
      signing.publicKey,
      new YjsProvider(),
      serializer,
      serializer,
      serializer,
      auth,
      new YjsACLProvider(),
      new YjsKeychainProvider(),
    );
    Object.defineProperties(node, {
      beekemForkStore: { value: forkStore },
      heliaNode: {
        value: {
          blockstore: new MemoryBlockstore(),
          libp2p: {
            services: {
              pubsub: {
                addEventListener() {},
                removeEventListener() {},
                subscribe() {},
                unsubscribe() {},
                async publish() {},
              },
            },
            async dialProtocol() {
              dials++;
              assert.deepEqual(
                [...records.values()].map((record) => record.phase),
                ['active'],
              );
              throw new Error('Fixture stopped before remote onboarding');
            },
          },
        },
      },
    });
    return node;
  }

  const founder = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['sign', 'verify'],
  );
  const now = Date.now();
  const offer = await signInvitationOffer(
    {
      version: 1,
      invitationId: crypto.getRandomValues(new Uint8Array(INVITATION_ID_LENGTH)),
      documentId: '/guarded-invitation',
      issuer: await auth.serializePublicKey(founder.publicKey),
      role: 'reader',
      issuedAtMs: now,
      expiresAtMs: now + 120_000,
      rendezvous: ['/ip4/127.0.0.1/tcp/14444'],
    },
    founder.privateKey,
    founder.publicKey,
    auth,
  );
  const recipient = await swarm(store);
  const recipientKem = await generateEciesKeyPair();
  await assert.rejects(
    recipient.acceptInvitation(offer, recipientKem),
    /not provisioned/,
  );
  assert.equal(dials, 0);
  assert.equal(
    await recipient.doc(offer.documentId).provisionBeeKEMForkStore(),
    true,
  );
  await assert.rejects(
    recipient.acceptInvitation(offer, recipientKem),
    /fixture stopped/i,
  );
  assert.equal(dials, 1);
  assert.deepEqual(
    [...records.values()],
    [{ phase: 'available', revision: 2 }],
  );
});

for (const interrupt of ['none', 'before-write', 'after-write'] as const) {
  test(`an authenticated BeeKEM fork fences pinned restore after restart (${interrupt})`, async () => {
    const { records, store } = forkAnchorFixture(interrupt);
    const { created, document, kem, traffic } = await fixture(store);
    const member = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      false,
      ['sign', 'verify'],
    );
    const memberKem = await generateEciesKeyPair();
    await registerReader(created, member.publicKey, memberKem.publicKey);
    const common = await created.exportCheckpoint();
    const otherDevice = document(undefined, undefined, null);
    await otherDevice.setKemKeyPair(kem);
    await otherDevice.restoreCheckpoint(
      common,
      await documentCheckpointCommitment(common),
    );
    await otherDevice.open();
    await created.removeReader(member.publicKey);
    await otherDevice.removeReader(member.publicKey);
    const checkpoint = await created.exportCheckpoint();
    const pin = await documentCheckpointCommitment(checkpoint);

    let streamActive = true;
    let closing: Promise<void> | undefined;
    await created.handleBeeKEMPathUpdateRequestData(
      traffic.get(otherDevice)!.updates.at(-1)!,
      {
        isActive() {
          queueMicrotask(() => {
            streamActive = false;
            closing ??= created.close();
          });
          return streamActive;
        },
        async runMutation(operation) {
          if (!streamActive) return { admitted: false };
          return { admitted: true, value: await operation() };
        },
      },
    );
    assert.equal(streamActive, false);
    assert.equal(created.competingBeeKEMGeneration, 2);
    await closing;
    assert.throws(() => created.document, /fork guard blocks/);
    assert.equal(
      [...records.values()][0]?.phase,
      interrupt === 'before-write' ? 'active' : 'quarantined',
    );

    const restarted = document();
    assert.equal(await restarted.provisionBeeKEMForkStore(), false);
    await assert.rejects(
      restarted.restoreCheckpoint(checkpoint, pin),
      /fork anchor blocks/,
    );
    assert.equal(
      restarted.competingBeeKEMGeneration,
      interrupt === 'before-write' ? undefined : 2,
    );
    assert.throws(() => restarted.document, /fork guard blocks/);
    await assert.rejects(document().open(), /fork anchor blocks/);
    await assert.rejects(document().create(), /fork anchor blocks/);
    await otherDevice.close();
  });
}

test('provider decoding failures do not install staged ACLs or document keys', async () => {
  const { document, created, signing } = await fixture();
  const checkpoint = await created.exportCheckpoint();
  const state = JSON.parse(new TextDecoder().decode(checkpoint.payload));
  state.document = Buffer.from('invalid Yjs state').toString('base64');
  const payload = new TextEncoder().encode(JSON.stringify(state));
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-384' },
      signing.privateKey,
      payload,
    ),
  );
  const candidate = document();
  await assert.rejects(candidate.restoreCheckpoint({ payload, signature }));
  assert.equal(candidate.historySize(), 0);
  assert.equal((await candidate.getWriters()).length, 0);
  await candidate.restoreCheckpoint(checkpoint);
  assert.equal(
    candidate.document.getText('fixture').toString(),
    'before restart',
  );
});

test('recovers selected content into a fresh document after an authenticated fork', async () => {
  const { document, created, kem, traffic } = await fixture();
  await created.change((doc) => {
    doc.getText('unselected').insert(0, 'keep this on the old document');
  });
  const member = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['sign', 'verify'],
  );
  const memberKem = await generateEciesKeyPair();
  await registerReader(created, member.publicKey, memberKem.publicKey);
  const common = await created.exportCheckpoint();
  const competingReplica = document();
  await competingReplica.setKemKeyPair(kem);
  await competingReplica.restoreCheckpoint(
    common,
    await documentCheckpointCommitment(common),
  );
  await competingReplica.open();
  await created.removeReader(member.publicKey);
  await competingReplica.removeReader(member.publicKey);
  const oldCheckpoint = await created.exportCheckpoint();
  const oldContext = Buffer.from(
    await documentCheckpointCommitment(oldCheckpoint),
  ).toString('hex');
  const [oldEpoch] = await traffic.get(created)!.keychain.current();
  await created.handleBeeKEMPathUpdateRequestData(
    traffic.get(competingReplica)!.updates.at(-1)!,
  );
  assert.equal(created.competingBeeKEMGeneration, 2);

  const replacementKem = await generateEciesKeyPair();
  const replacementPublic = new Uint8Array(
    await crypto.subtle.exportKey('raw', replacementKem.publicKey),
  );
  const selected = new TextEncoder().encode('approved replacement text');
  let locator: DocumentRecoveryLocator = {
    revision: 1,
    documentPath: created.documentPath,
    context: oldContext,
    receipt: null,
  };
  const approval: DocumentRecoveryApproval = {
    logicalDocumentId: 'checkpoint-recovery-fixture',
    base: locator,
    replacementPath: '/checkpoint-fixture/replacement',
    replacementContext: await documentRecoveryContentDigest(replacementPublic),
    contentDigest: await documentRecoveryContentDigest(selected),
  };
  const staged = new Map<
    string,
    {
      checkpoint: Awaited<ReturnType<typeof created.exportCheckpoint>>;
      pin: Uint8Array;
    }
  >();
  let publications = 0;
  let staging = 0;
  let acknowledgmentLost = true;
  function openRecovery() {
    return {
      authorize(approved: DocumentRecoveryApproval) {
        assert.deepEqual(approved, approval);
        return true;
      },
      async stage(next: DocumentRecoveryLocator, content: Uint8Array) {
        const receipt = next.receipt!;
        if (staged.has(receipt)) return true;
        staging++;
        const candidate = document(next.documentPath);
        await candidate.setKemKeyPair(replacementKem);
        await candidate.create();
        await candidate.change((draft) => {
          draft.getText('fixture').insert(0, new TextDecoder().decode(content));
        });
        const checkpoint = await candidate.exportCheckpoint();
        const pin = await documentCheckpointCommitment(checkpoint);
        await candidate.close();
        if (!staged.has(receipt)) staged.set(receipt, { checkpoint, pin });
        return true;
      },
      locator: {
        async load(id: string) {
          assert.equal(id, approval.logicalDocumentId);
          return { ...locator };
        },
        async compareAndSwap(
          id: string,
          expected: DocumentRecoveryLocator,
          next: DocumentRecoveryLocator,
        ) {
          assert.equal(id, approval.logicalDocumentId);
          assert.deepEqual(locator, expected);
          assert.ok(staged.has(next.receipt!));
          locator = { ...next };
          publications++;
          if (acknowledgmentLost) {
            acknowledgmentLost = false;
            throw new Error('Interrupted after locator commit');
          }
          return true;
        },
      },
    };
  }

  await assert.rejects(
    activateDocumentReplacement(approval, selected, openRecovery()),
    /Interrupted after locator commit/,
  );
  const accepted = await activateDocumentReplacement(
    approval,
    selected,
    openRecovery(),
  );
  assert.equal(accepted.status, 'already-active');
  assert.equal(staging, 1);
  assert.equal(publications, 1);

  const reopened = document(accepted.locator.documentPath);
  await reopened.setKemKeyPair(replacementKem);
  const ready = staged.get(accepted.locator.receipt!)!;
  await reopened.restoreCheckpoint(ready.checkpoint, ready.pin);
  await reopened.open();
  assert.equal(
    reopened.document.getText('fixture').toString(),
    'approved replacement text',
  );
  assert.equal(reopened.document.share.has('unselected'), false);
  assert.throws(() => created.document, /indeterminate authorization/);
  assert.notDeepEqual(
    (await traffic.get(reopened)!.keychain.current())[0],
    oldEpoch,
  );
});
