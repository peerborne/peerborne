import assert from 'node:assert/strict';
import test from 'node:test';
import { MemoryBlockstore } from 'blockstore-core/memory';
import {
  CRDTActorBindingError,
  PeerborneDocument,
  SubtleCrypto,
  createCRDTActorNonce,
  crdtActorRegistrationPayload,
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
 * function that switches the document to `actor` before writing, and
 * `hashDependencies`, set when changes depend on their predecessors by hash,
 * and `garbage()`, bare changes the provider cannot decode.
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
      hasLocalDocument: () => false,
      recordFoundedDocument() {},
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
    const raw = await source.document._decryptGossipFrame(bytes);
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

  async function signRegistration(from, author) {
    return {
      ...author,
      registrationSignature: await from.document._authProvider.sign(
        crdtActorRegistrationPayload(path, author),
        from.identity.privateKey,
      ),
    };
  }

  async function authored(from, bare, author) {
    const signed =
      author.registrationSignature === undefined
        ? await signRegistration(from, author)
        : author;
    const signature = await from.document._authProvider.sign(
      crdtChangeAuthorPayload(
        path,
        signed,
        from.document._changesSerializer.serializeChanges(bare),
      ),
      from.identity.privateKey,
    );
    return from.document._crdtProvider.actorBinding.attach(
      bare,
      encodeCRDTChangeAuthor({ ...signed, signature }),
    );
  }

  async function signed(from, fields) {
    const message = {
      documentId: path,
      signatureContext: 'ordinary-sync-v1',
      ...fields,
    };
    message.signature = await from.document._signAsWriter(message);
    return message;
  }

  async function send(from, to, change, children) {
    return to.document.sync(
      await signed(from, {
        changeId: await from.document._putBlock(change, 'document'),
        changes: {
          kind: 'document',
          change,
          ...(children ? { children } : {}),
        },
      }),
    );
  }

  async function withSnapshot(from, snapshot) {
    const message = { ...(await lastMessage(from)), snapshot };
    delete message.signature;
    message.signature = await from.document._signAsWriter(message);
    return message;
  }

  async function resignSnapshot(from, snapshot, manifest) {
    const binding = from.document._crdtProvider.actorBinding;
    const [, state] = binding.detach(snapshot.state);
    const tampered = { ...snapshot, state: binding.attach(state, manifest) };
    tampered.signature = await from.document._authProvider.sign(
      from.document._buildSnapshotSignPayload(
        from.document._changesSerializer.serializeChanges(tampered.state),
        tampered.lastChangeNodeCID,
        tampered.timestamp,
        tampered.compactedCount,
      ),
      from.identity.privateKey,
    );
    return tampered;
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
    assert.deepEqual(json(alice), before);
    assert.equal(adapter.hasActor(alice.document.document, bobActor), false);

    assert.equal(await alice.document.sync(bobMessage), true);
    await exchange(alice, bob);
    assert.equal(json(alice).bob, 1);
    assert.equal(json(alice).forged, undefined);
  });

  if (adapter.squat)
    test(`${adapter.name}: a local change under another actor is refused and retires the instance`, async () => {
      const { alice, bob, mallory } = await network();
      await bob.document.change(adapter.write('bob'));
      const bobActor = actorOf(bob);
      await assert.rejects(
        mallory.document.change(adapter.squat(bobActor, 'forged')),
        (error) =>
          /retired/.test(error.message) &&
          error.cause instanceof CRDTActorBindingError,
      );
      await assert.rejects(
        mallory.document.change(adapter.write('later')),
        /retired/,
      );
      assert.equal(await alice.document.sync(await lastMessage(bob)), true);
      await exchange(alice, bob);
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

  test(`${adapter.name}: a relayed change that fails binding is skipped without blocking the relayer`, async () => {
    const { alice, bob, mallory } = await network();
    const carol = await join(alice, await generateIdentity());
    await bob.document.change(adapter.write('bob'));
    assert.equal(await carol.document.sync(await lastMessage(bob)), true);
    const colliding = await registration(mallory);
    collisions.set(
      hex(await deriveCRDTActorDigest(path, colliding)),
      actorOf(bob),
    );
    const head = await lastMessage(alice);
    const squat = await authored(
      mallory,
      adapter.forge(alice.document.document, actorOf(bob), 'squat'),
      colliding,
    );
    const squatMessage = await signed(mallory, {
      changeId: await mallory.document._putBlock(squat, 'document'),
      changes: {
        kind: 'document',
        change: squat,
        children: { [head.changeId]: head.changes },
      },
    });
    assert.equal(await alice.document.sync(squatMessage), true);
    await alice.document.change(adapter.write('honest'));
    const relayed = await lastMessage(alice);
    assert.ok(squatMessage.changeId in relayed.changes.children);
    assert.equal(await carol.document.sync(relayed), true);
    assert.equal(json(carol).squat, undefined);
    assert.equal(carol.document._isWaiting(squatMessage.changeId), true);
    assert.equal(carol.document.hasChange(relayed.changeId), false);
    // Automerge changes depend on their predecessors by hash, so Alice's later
    // change waits for the change Carol refused. Its 128-bit actors make the
    // collision this test simulates infeasible.
    if (!adapter.hashDependencies) assert.equal(json(carol).honest, 1);
    assert.equal(json(carol).bob, 1);
  });

  test(`${adapter.name}: a forged child under a valid root waits, and other failures reject the message`, async () => {
    const { alice, bob, mallory } = await network();
    await bob.document.change(adapter.write('bob'));
    const forged = await authored(
      mallory,
      adapter.forge(alice.document.document, actorOf(bob), 'forged'),
      await registration(mallory),
    );
    const forgedId = await mallory.document._putBlock(forged, 'document');
    await mallory.document.change(adapter.write('mroot'));
    const root = await lastMessage(mallory);
    const tree = (child) =>
      signed(mallory, {
        changeId: root.changeId,
        changes: {
          kind: 'document',
          change: root.changes.change,
          children: { [forgedId]: { kind: 'document', change: child } },
        },
      });

    const garbled = await authored(
      mallory,
      adapter.garbage(),
      await registration(mallory),
    );
    await assert.rejects(
      alice.document.sync(await tree(garbled)),
      (error) => !(error instanceof CRDTActorBindingError),
    );
    assert.equal(json(alice).mroot, undefined);

    assert.equal(await alice.document.sync(await tree(forged)), true);
    assert.equal(json(alice).forged, undefined);
    assert.equal(alice.document._isWaiting(forgedId), true);
    assert.equal(alice.document.hasChange(root.changeId), false);
    if (!adapter.hashDependencies) assert.equal(json(alice).mroot, 1);
    assert.equal(await alice.document.sync(await lastMessage(bob)), true);
    assert.equal(await bob.document.sync(await tree(forged)), true);
    await exchange(alice, bob);
    assert.equal(json(bob).forged, undefined);
  });

  test(`${adapter.name}: reservations are refused past the limit, never forgotten`, async () => {
    const { alice } = await network();
    const reserved = [];
    for (let index = 0; index < 64; index++)
      reserved.push(await alice.document.reserveActor());
    await assert.rejects(
      alice.document.reserveActor(),
      bindingError(/Release one of 64/),
    );
    assert.equal(alice.document._reservedActors.has(reserved[0]), true);
    alice.document.releaseActor(reserved[0]);
    assert.equal(typeof (await alice.document.reserveActor()), 'string');
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
    assert.equal(
      await carol.document.sync(await withSnapshot(alice, snapshot)),
      true,
    );
    assert.deepEqual(json(carol), json(alice));

    const restored = replica(alice.identity);
    await restored.document.restorePlaintextCheckpoint(
      await alice.document.exportPlaintextCheckpoint(),
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

  test(`${adapter.name}: a replica whose first write follows another writer's orphaned change publishes only its own operations`, async () => {
    const { alice, bob } = await network();
    await alice.document.change(adapter.write('a1'));
    const first = await lastMessage(alice);
    await alice.document.change(adapter.write('a2'));
    const second = await lastMessage(alice);
    const orphan = await signed(alice, {
      changeId: second.changeId,
      changes: { kind: 'document', change: second.changes.change },
    });
    assert.equal(await bob.document.sync(orphan), true);
    assert.equal(json(bob).a2, undefined);

    await bob.document.change(adapter.write('b1'));
    const bobMessage = await lastMessage(bob);
    const [, bare] = bob.document._crdtProvider.actorBinding.detach(
      bobMessage.changes.change,
    );
    assert.deepEqual(
      [...bob.document._crdtProvider.actorBinding.changeActors(bare)],
      [actorOf(bob)],
    );
    assert.equal(await alice.document.sync(bobMessage), true);
    assert.equal(await bob.document.sync(first), true);
    assert.equal(json(bob).a2, 1);
    await exchange(alice, bob);
  });

  test(`${adapter.name}: a snapshot manifest needs each signer's own registration signature`, async () => {
    const { alice, bob, mallory } = await network();
    await bob.document.change(adapter.write('bob'));
    assert.equal(await alice.document.sync(await lastMessage(bob)), true);
    const snapshot = await alice.document.snapshot();
    const registrations = alice.document._actorBindings.registrations();
    const bobSigner = await bob.document._localSignerAuthority();
    const outside = await signRegistration(mallory, {
      ...(await registration(mallory)),
    });
    const borrowed = {
      signer: bobSigner,
      nonce: createCRDTActorNonce(),
    };
    for (const manifest of [
      registrations.map((entry) =>
        entry.signer === bobSigner
          ? { ...entry, registrationSignature: new Uint8Array([1, 2, 3]) }
          : entry,
      ),
      [...registrations, outside],
      [
        ...registrations,
        {
          ...borrowed,
          registrationSignature: (await signRegistration(mallory, borrowed))
            .registrationSignature,
        },
      ],
    ]) {
      const carol = await admit(alice, await generateIdentity());
      await carol.document.sync(
        await withSnapshot(
          alice,
          await resignSnapshot(
            alice,
            snapshot,
            encodeCRDTActorManifest(manifest),
          ),
        ),
      );
      assert.equal(carol.document.latestSnapshot, undefined);
      assert.equal(json(carol).bob, undefined);
      assert.equal(carol.document._actorBindings.get(actorOf(bob)), undefined);
    }

    const carol = await admit(alice, await generateIdentity());
    const partial = registrations.filter((entry) => entry.signer === bobSigner);
    assert.equal(
      await carol.document.sync(
        await withSnapshot(
          alice,
          await resignSnapshot(
            alice,
            snapshot,
            encodeCRDTActorManifest(partial),
          ),
        ),
      ),
      true,
    );
    assert.equal(json(carol).bob, 1);
    assert.notEqual(carol.document._actorBindings.get(actorOf(bob)), undefined);
  });

  return {
    network,
    lastMessage,
    json,
    admit,
    join,
    registration,
    authored,
    signed,
    send,
    actorOf,
    exchange,
    bindingError,
    generateIdentity,
    path,
  };
}
