import { webcrypto } from 'node:crypto';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { MemoryBlockstore } from 'blockstore-core/memory';
import {
  beekemPathUpdateV2,
  PeerborneDocument,
  SubtleCrypto,
  generateEciesKeyPair,
  deserializeBeeKEMWelcomeV2FromWire,
  documentCheckpointCommitment,
  activateDocumentReplacement,
  documentRecoveryContentDigest,
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

Object.defineProperty(globalThis, 'crypto', {
  value: webcrypto,
  configurable: true,
});

async function fixture() {
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
  function document(path = '/checkpoint-fixture', identity = signing) {
    const serializer = new YjsJSONSerializer();
    const registry = new Map();
    const broadcasts: Uint8Array[] = [];
    const updates: Uint8Array[] = [];
    const keychainProvider = new YjsKeychainProvider();
    let keychain: YjsKeychain;
    const swarm = {
      config: { enableSigning: true, enableTopicValidators: false },
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
  await created.setKemKeyPair(kem);
  await created.create();
  await created.change((doc) => {
    doc.getText('fixture').insert(0, 'before restart');
  });
  return { document, created, signing, kem, traffic };
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

test('preserves membership state so a restored founder can remove an existing reader', async () => {
  const { document, created, kem } = await fixture();
  const member = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['sign', 'verify'],
  );
  const memberKem = await generateEciesKeyPair();
  await created.addReader(
    member.publicKey,
    new Uint8Array(await crypto.subtle.exportKey('raw', memberKem.publicKey)),
  );
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
    await live.addReader(
      member.publicKey,
      new Uint8Array(await crypto.subtle.exportKey('raw', memberKem.publicKey)),
    );
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
    const { document, created, kem, traffic } = await fixture();
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
    await created.addReader(
      member.publicKey,
      new Uint8Array(await crypto.subtle.exportKey('raw', memberKem.publicKey)),
    );
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
      const [epochBefore] = await keychain.current();
      const countBefore = broadcasts.length;
      const ownUpdate = index === 0 ? firstUpdate : secondUpdate;
      const rivalUpdate = index === 0 ? secondUpdate : firstUpdate;

      await replica.handleBeeKEMPathUpdateRequestData(ownUpdate);
      assert.equal(replica.competingBeeKEMGeneration, undefined);
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
  await created.addReader(
    member.publicKey,
    new Uint8Array(await crypto.subtle.exportKey('raw', memberKem.publicKey)),
  );
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
