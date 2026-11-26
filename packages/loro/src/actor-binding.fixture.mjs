import assert from 'node:assert/strict';
import test from 'node:test';
import { LoroDoc } from 'loro-crdt';
import { deriveCRDTActorDigest } from '@peerborne/core';
import { LoroProvider } from '@peerborne/loro';
import {
  YjsACLProvider,
  YjsJSONSerializer,
  YjsKeychainProvider,
} from '@peerborne/yjs';
import { actorBindingScenarios } from '../../../verification/actor-binding.mjs';

const h = actorBindingScenarios({
  name: 'loro',
  provider: () => new LoroProvider(),
  acl: () => new YjsACLProvider(),
  keychain: () => new YjsKeychainProvider(),
  serializer: () => new YjsJSONSerializer(),
  write: (key) => (doc) => doc.getMap('m').set(key, 1),
  forge(document, actor, key) {
    const forger = new LoroDoc();
    forger.import(document.export({ mode: 'snapshot' }));
    forger.setPeerId(BigInt(actor));
    const from = forger.oplogVersion();
    forger.getMap('m').set(key, 1);
    forger.commit();
    return forger.export({ mode: 'update', from });
  },
  json: (document) => document.getMap('m').toJSON(),
  actor: (document) => document.peerIdStr,
  hasActor: (document, actor) => document.oplogVersion().toJSON().has(actor),
  squat: (actor, key) => (doc) => {
    doc.setPeerId(BigInt(actor));
    doc.getMap('m').set(key, 1);
  },
});

for (const mode of ['shallow-snapshot', 'snapshot'])
  test(`loro: a ${mode} blob cannot stand in for a change`, async () => {
    const { alice, bob, mallory } = await h.network();
    await bob.document.change((doc) => doc.getMap('m').set('bob', 1));
    assert.equal(await alice.document.sync(await h.lastMessage(bob)), true);
    const reg = await h.registration(mallory);
    const malloryActor =
      mallory.document._crdtProvider.actorBinding.actorFromDigest(
        await deriveCRDTActorDigest(h.path, reg),
      );
    const forger = new LoroDoc();
    forger.import(alice.document.document.export({ mode: 'snapshot' }));
    forger.setPeerId(BigInt(h.actorOf(bob)));
    forger.getMap('m').set('forged', 1);
    forger.commit();
    forger.setPeerId(BigInt(malloryActor));
    forger.getMap('m').set('m0', 1);
    forger.commit();
    const root = forger.oplogFrontiers();
    forger.getMap('m').set('m1', 1);
    forger.commit();
    const blob =
      mode === 'snapshot'
        ? forger.export({ mode })
        : forger.export({ mode, frontiers: root });
    const crafted = await h.authored(mallory, blob, reg);
    await assert.rejects(
      h.send(mallory, alice, crafted),
      h.bindingError(/Loro update required/),
    );

    const carol = await h.admit(alice, await h.generateIdentity());
    const tip = await h.lastMessage(alice);
    await assert.rejects(
      carol.document.sync(
        await h.signed(mallory, {
          changeId: await mallory.document._putBlock(crafted, 'document'),
          changes: {
            kind: 'document',
            change: crafted,
            children: { [tip.changeId]: tip.changes },
          },
        }),
      ),
      h.bindingError(/Loro update required/),
    );
    assert.deepEqual(h.json(carol), {});
    assert.equal(await carol.document.sync(tip), true);
    await bob.document.change((doc) => doc.getMap('m').set('bob2', 1));
    const next = await h.lastMessage(bob);
    for (const target of [alice, carol])
      assert.equal(await target.document.sync(next), true);
    assert.deepEqual(h.json(carol), h.json(alice));
    assert.equal(h.json(carol).forged, undefined);
    assert.equal(h.json(carol).bob2, 1);
  });
