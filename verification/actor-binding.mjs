import assert from 'node:assert/strict';
import test from 'node:test';
import { MemoryBlockstore } from 'blockstore-core/memory';
import {
  CRDTActorBindingError,
  PeerborneDocument,
  SubtleCrypto,
  createCRDTActorNonce,
  crdtChangeAuthorPayload,
  decodeCRDTChangeAuthor,
  deriveCRDTActorDigest,
  encodeCRDTActorManifest,
  encodeCRDTChangeAuthor,
} from '@peerborne/core';

const hex = (bytes) => Buffer.from(bytes).toString('hex');

function generateIdentity() {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify'],
  );
}

/**
 * Real documents with distinct signers, joined over an in-memory transport.
 * `adapter` supplies the providers and native edits of one CRDT:
 * `provider()`, `acl()`, `keychain()`, `serializer()`, `write(key)` (a
 * change function), `forge(document, actor, key)` (bare changes that add
 * `key` under `actor`), `json(document)`, `actor(document)`,
 * `hasActor(document, actor)` and optionally `squat(actor, key)`, a change
 * function that switches the document to `actor` before writing.
 */
export function actorBindingScenarios(adapter) {
  const path = `/${adapter.name}-actor-binding`;
  const collisions = new Map();

  function replica(identity) {
    const frames = [];
    const serializer = adapter.serializer();
    const provider = adapter.provider();
    const binding = provider.actorBinding;
    provider.actorBinding = {
      ...binding,
      actorFromDigest: (digest) =>
        collisions.get(hex(digest)) ?? binding.actorFromDigest(digest),
    };
    const swarm = {
      config: {
        enableSigning: true,
        enableTopicValidators: false,
        loadQuorumEnabled: false,
      },
      heliaNode: {
        blockstore: new MemoryBlockstore(),
        libp2p: {
          services: {
            pubsub: {
              addEventListener() {},
              removeEventListener() {},
              subscribe() {},
              unsubscribe() {},
              async publish(_topic, data) {
                frames.push(new Uint8Array(data));
              },
            },
          },
          getConnections: () => [],
        },
      },
      registerDocument() {},
      unregisterDocument() {},
    };
    const document = new PeerborneDocument(
      swarm,
      path,
      identity.privateKey,
      identity.publicKey,
      provider,
      new SubtleCrypto(),
      adapter.acl(),
      adapter.keychain(),
      serializer,
      serializer,
      serializer,
    );
    return { document, frames, identity };
  }

  async function lastMessage(source) {
    const bytes = source.frames.at(-1);
    const raw = await source.document._decryptBlock(
      bytes.slice(0, 32),
      bytes.slice(32, 44),
      bytes.slice(44),
    );
    return source.document._syncMessageSerializer.deserializeSyncMessage(raw);
  }

  async function admit(founder, identity) {
    const joined = replica(identity);
    joined.document._writers.merge(founder.document._writers.current());
    joined.document._keychain.merge(founder.document._keychain.history());
    await joined.document._keychain.keys();
    return joined;
  }

  async function join(founder, identity) {
    const joined = await admit(founder, identity);
    assert.equal(await joined.document.sync(await lastMessage(founder)), true);
    await joined.document.open();
    return joined;
  }

  async function network() {
    const [a, b, m] = await Promise.all([
      generateIdentity(),
      generateIdentity(),
      generateIdentity(),
    ]);
    const alice = replica(a);
    await alice.document.create();
    for (const writer of [b, m])
      await alice.document._writers.add(writer.publicKey);
    alice.document._invalidateWriterKeyCache();
    await alice.document.change(adapter.write('a'));
    return { alice, bob: await join(alice, b), mallory: await join(alice, m) };
  }

  async function registration(from) {
    return {
      signer: await from.document._localSignerAuthority(),
      nonce: createCRDTActorNonce(),
    };
  }

  async function authored(from, bare, author) {
    const signature = await from.document._authProvider.sign(
      crdtChangeAuthorPayload(
        path,
        author,
        from.document._changesSerializer.serializeChanges(bare),
      ),
      from.identity.privateKey,
    );
    return from.document._crdtProvider.actorBinding.attach(
      bare,
      encodeCRDTChangeAuthor({ ...author, signature }),
    );
  }

  async function send(from, to, change) {
    const message = {
      documentId: path,
      signatureContext: 'ordinary-sync-v1',
      changeId: await from.document._putBlock(change, 'document'),
      changes: { kind: 'document', change },
    };
    message.signature = await from.document._signAsWriter(message);
    return to.document.sync(message);
  }

  const json = (replica) => adapter.json(replica.document.document);
  const actorOf = (replica) => adapter.actor(replica.document.document);

  async function exchange(left, right) {
    await left.document.change(adapter.write(`left-${left.frames.length}`));
    assert.equal(await right.document.sync(await lastMessage(left)), true);
    await right.document.change(adapter.write(`right-${right.frames.length}`));
    assert.equal(await left.document.sync(await lastMessage(right)), true);
    assert.deepEqual(json(left), json(right));
  }

  const bindingError = (pattern) => (error) =>
    error instanceof CRDTActorBindingError &&
    (pattern === undefined || pattern.test(error.message));

  test(`${adapter.name}: a writer cannot add operations under another writer's actor`, async () => {
    const { alice, bob, mallory } = await network();
    await bob.document.change(adapter.write('bob'));
    const bobMessage = await lastMessage(bob);
    const bobActor = actorOf(bob);
    const before = json(alice);
    const forged = adapter.forge(alice.document.document, bobActor, 'forged');

    await assert.rejects(
      send(
        mallory,
        alice,
        await authored(mallory, forged, await registration(mallory)),
      ),
      bindingError(/does not own/),
    );
    if (adapter.squat)
      await assert.rejects(
        mallory.document.change(adapter.squat(bobActor, 'forged')),
        bindingError(/own actor/),
      );
    assert.deepEqual(json(alice), before);
    assert.equal(adapter.hasActor(alice.document.document, bobActor), false);

    assert.equal(await alice.document.sync(bobMessage), true);
    await exchange(alice, bob);
    assert.equal(json(alice).bob, 1);
    assert.equal(json(alice).forged, undefined);
  });

  test(`${adapter.name}: re-wrapping another writer's change is rejected and an intact relay is accepted`, async () => {
    const { alice, bob, mallory } = await network();
    await bob.document.change(adapter.write('bob'));
    const bobMessage = await lastMessage(bob);
    const [prefix, bare] = bob.document._crdtProvider.actorBinding.detach(
      bobMessage.changes.change,
    );
    const bobAuthor = decodeCRDTChangeAuthor(prefix);

    await assert.rejects(
      send(
        mallory,
        alice,
        await authored(mallory, bare, await registration(mallory)),
      ),
      bindingError(/does not own/),
    );
    await assert.rejects(
      send(mallory, alice, await authored(mallory, bare, bobAuthor)),
      bindingError(/signature/),
    );
    assert.equal(json(alice).bob, undefined);

    assert.equal(await send(mallory, alice, bobMessage.changes.change), true);
    assert.equal(json(alice).bob, 1);
    assert.equal(await alice.document.sync(bobMessage), true);
    await exchange(alice, bob);
  });

  test(`${adapter.name}: snapshots and checkpoints keep the first registration of an actor`, async () => {
    const { alice, bob, mallory } = await network();
    await bob.document.change(adapter.write('bob'));
    assert.equal(await alice.document.sync(await lastMessage(bob)), true);
    const bobActor = actorOf(bob);
    const colliding = await registration(mallory);
    collisions.set(hex(await deriveCRDTActorDigest(path, colliding)), bobActor);

    const snapshot = await alice.document.snapshot();
    const carol = await admit(alice, await generateIdentity());
    const message = { ...(await lastMessage(alice)), snapshot };
    delete message.signature;
    message.signature = await alice.document._signAsWriter(message);
    assert.equal(await carol.document.sync(message), true);
    assert.deepEqual(json(carol), json(alice));

    const restored = replica(alice.identity);
    await restored.document.restoreCheckpoint(
      await alice.document.exportCheckpoint(),
    );
    await restored.document.open();

    const squat = await authored(
      mallory,
      adapter.forge(alice.document.document, bobActor, 'forged'),
      colliding,
    );
    for (const target of [alice, carol, restored]) {
      await assert.rejects(
        send(mallory, target, squat),
        bindingError(/already bound/),
      );
      assert.equal(json(target).forged, undefined);
    }

    await bob.document.change(adapter.write('bob2'));
    const bobNext = await lastMessage(bob);
    for (const target of [alice, carol, restored])
      assert.equal(await target.document.sync(bobNext), true);
    await exchange(restored, bob);
    assert.notEqual(actorOf(restored), actorOf(alice));
  });

  test(`${adapter.name}: a replica holding another writer's orphaned change keeps publishing its own operations`, async () => {
    const { alice, bob } = await network();
    await bob.document.change(adapter.write('b1'));
    const first = await lastMessage(bob);
    await bob.document.change(adapter.write('b2'));
    const second = await lastMessage(bob);
    const orphan = {
      documentId: path,
      signatureContext: 'ordinary-sync-v1',
      changeId: second.changeId,
      changes: { kind: 'document', change: second.changes.change },
    };
    orphan.signature = await bob.document._signAsWriter(orphan);
    assert.equal(await alice.document.sync(orphan), true);
    assert.equal(json(alice).b2, undefined);

    await alice.document.change(adapter.write('a2'));
    const aliceMessage = await lastMessage(alice);
    const [, bare] = alice.document._crdtProvider.actorBinding.detach(
      aliceMessage.changes.change,
    );
    assert.deepEqual(
      [...alice.document._crdtProvider.actorBinding.changeActors(bare)],
      [actorOf(alice)],
    );
    assert.equal(await bob.document.sync(aliceMessage), true);
    assert.equal(await alice.document.sync(first), true);
    assert.equal(json(alice).b2, 1);
    await exchange(alice, bob);
  });

  test(`${adapter.name}: a snapshot whose manifest does not bind its state is not applied`, async () => {
    const { alice, bob } = await network();
    await bob.document.change(adapter.write('bob'));
    assert.equal(await alice.document.sync(await lastMessage(bob)), true);
    const snapshot = await alice.document.snapshot();
    const binding = alice.document._crdtProvider.actorBinding;
    const [, state] = binding.detach(snapshot.state);
    const own = alice.document._actorBindings.registrations([actorOf(alice)]);
    const tampered = {
      ...snapshot,
      state: binding.attach(state, encodeCRDTActorManifest(own)),
    };
    tampered.signature = await alice.document._authProvider.sign(
      alice.document._buildSnapshotSignPayload(
        alice.document._changesSerializer.serializeChanges(tampered.state),
        tampered.lastChangeNodeCID,
        tampered.timestamp,
        tampered.compactedCount,
      ),
      alice.identity.privateKey,
    );
    const carol = await admit(alice, await generateIdentity());
    const message = { ...(await lastMessage(alice)), snapshot: tampered };
    delete message.signature;
    message.signature = await alice.document._signAsWriter(message);
    await carol.document.sync(message);
    assert.equal(carol.document.latestSnapshot, undefined);
    assert.equal(json(carol).bob, undefined);
  });

  return { network, lastMessage, json };
}
