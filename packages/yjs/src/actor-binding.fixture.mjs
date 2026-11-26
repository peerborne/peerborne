import assert from 'node:assert/strict';
import test from 'node:test';
import {
  Doc,
  applyUpdate,
  applyUpdateV2,
  encodeStateAsUpdate,
  encodeStateAsUpdateV2,
  encodeStateVector,
} from 'yjs';
import {
  YjsACLProvider,
  YjsJSONSerializer,
  YjsKeychainProvider,
  YjsProvider,
  createYjsEditorBridge,
} from '@peerborne/yjs';
import { actorBindingScenarios } from '../../../verification/actor-binding.mjs';

const { network, lastMessage, json, exchange } = actorBindingScenarios({
  name: 'yjs',
  provider: () => new YjsProvider(),
  acl: () => new YjsACLProvider(),
  keychain: () => new YjsKeychainProvider(),
  serializer: () => new YjsJSONSerializer(),
  garbage: () => new Uint8Array([255, 255, 255]),
  write: (key) => (doc) => doc.getMap('m').set(key, 1),
  forge(document, actor, key) {
    const forger = new Doc();
    applyUpdateV2(forger, encodeStateAsUpdateV2(document));
    forger.clientID = Number(actor);
    const before = encodeStateVector(forger);
    forger.getMap('m').set(key, 1);
    return encodeStateAsUpdateV2(forger, before);
  },
  json: (document) => document.getMap('m').toJSON(),
  actor: (document) => String(document.clientID),
  hasActor: (document, actor) => document.store.clients.has(Number(actor)),
  squat: (actor, key) => (doc) => {
    doc.clientID = Number(actor);
    doc.getMap('m').set(key, 1);
  },
});

test('yjs: an editor bridge mirror writes under an actor bound to its signer', async () => {
  const { alice, bob } = await network();
  const bridge = await createYjsEditorBridge(alice.document);
  bridge.document.getMap('m').set('edited', 1);
  await bridge.flush();
  assert.equal(await bob.document.sync(await lastMessage(alice)), true);
  assert.equal(json(bob).edited, 1);
  await alice.document.change((doc) => doc.getMap('m').set('direct', 1));
  assert.equal(await bob.document.sync(await lastMessage(alice)), true);
  assert.equal(json(bob).direct, 1);
  await bridge.destroy();
});

test('yjs: content seeded from another document is refused unless it uses a reserved actor', async () => {
  const { alice, bob } = await network();
  const seed = new Doc();
  seed.getMap('m').set('template', 1);
  await assert.rejects(
    alice.document.change((doc) => applyUpdate(doc, encodeStateAsUpdate(seed))),
    /retired/,
  );
  await assert.rejects(
    alice.document.change((doc) => doc.getMap('m').set('typed', 1)),
    /retired/,
  );
  await bob.document.change((doc) => doc.getMap('m').set('bob', 1));

  const fresh = await network();
  const reserved = new Doc();
  reserved.clientID = Number(await fresh.alice.document.reserveActor());
  reserved.getMap('m').set('template', 1);
  await fresh.alice.document.change((doc) =>
    applyUpdate(doc, encodeStateAsUpdate(reserved)),
  );
  assert.equal(
    await fresh.bob.document.sync(await lastMessage(fresh.alice)),
    true,
  );
  assert.equal(json(fresh.bob).template, 1);
  await exchange(fresh.alice, fresh.bob);
  await fresh.alice.document.snapshot();
});
