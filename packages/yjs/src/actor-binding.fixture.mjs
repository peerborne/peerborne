import assert from 'node:assert/strict';
import test from 'node:test';
import {
  Doc,
  applyUpdateV2,
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

const { network, lastMessage, json } = actorBindingScenarios({
  name: 'yjs',
  provider: () => new YjsProvider(),
  acl: () => new YjsACLProvider(),
  keychain: () => new YjsKeychainProvider(),
  serializer: () => new YjsJSONSerializer(),
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
