import assert from 'node:assert/strict';
import test from 'node:test';
import 'fake-indexeddb/auto';
import { generateKeyPair } from '@libp2p/crypto/keys';
import { peerIdFromPrivateKey } from '@libp2p/peer-id';
import { MemoryDatastore } from 'datastore-core/memory';
import { IDBDatastore } from 'datastore-idb';
import { createAndStartHeliaNode } from './helia-node.ts';
import { acquirePeerIdentity } from './peer-identity.ts';
import { defaultBootstrapConfig, defaultConfig } from './peerborne-config.ts';
import { closeHeliaStores } from './store-lifecycle.ts';

async function start(config = defaultConfig(defaultBootstrapConfig([]))) {
  const started = await createAndStartHeliaNode(config.helia);
  return {
    peerId: started.heliaNode.libp2p.peerId.toString(),
    async stop() {
      await started.heliaNode.stop();
      await closeHeliaStores(started.openedStores);
    },
  };
}

test('a default-config instance keeps the persisted PeerId across restarts', async () => {
  const first = await start();
  await first.stop();
  const second = await start();
  await second.stop();

  assert.equal(second.peerId, first.peerId);
});

test('a concurrent default-config instance gets its own PeerId until the holder stops', async () => {
  const holder = await start();
  const concurrent = await start();
  const another = await start();
  assert.notEqual(concurrent.peerId, holder.peerId);
  assert.notEqual(another.peerId, holder.peerId);
  assert.notEqual(another.peerId, concurrent.peerId);
  await holder.stop();

  const next = await start();
  try {
    assert.equal(next.peerId, holder.peerId);
  } finally {
    await Promise.all([next.stop(), concurrent.stop(), another.stop()]);
  }
});

test('starting does not mutate a reused config object', async () => {
  const config = defaultConfig(defaultBootstrapConfig([]));
  const libp2p = config.helia.libp2p;
  const keys = Object.keys(libp2p);
  const first = await start(config);
  const second = await start(config);
  try {
    assert.notEqual(second.peerId, first.peerId);
    assert.equal(config.helia.libp2p, libp2p);
    assert.deepEqual(Object.keys(libp2p), keys);
    assert.equal(libp2p.privateKey, undefined);
    assert.equal(libp2p.datastore, undefined);
  } finally {
    await Promise.all([first.stop(), second.stop()]);
  }
});

test('a configured libp2p private key sets the PeerId without claiming the persisted one', async () => {
  const reference = await start();
  await reference.stop();
  const privateKey = await generateKeyPair('Ed25519');
  const config = defaultConfig(defaultBootstrapConfig([]));
  config.helia.libp2p.privateKey = privateKey;
  const configured = await start(config);
  const persisted = await start();
  try {
    assert.equal(
      configured.peerId,
      peerIdFromPrivateKey(privateKey).toString(),
    );
    assert.equal(persisted.peerId, reference.peerId);
  } finally {
    await Promise.all([configured.stop(), persisted.stop()]);
  }
});

test('a shared IndexedDB datastore gets a fresh key without Web Locks', async () => {
  const lease = await acquirePeerIdentity(
    new IDBDatastore('/peer-identity-no-locks'),
    null,
  );
  assert.ok(lease.privateKey);
});

test('another datastore is claimed by one instance in this realm', async () => {
  const datastore = new MemoryDatastore();
  const holder = await acquirePeerIdentity(datastore);
  const concurrent = await acquirePeerIdentity(datastore);
  assert.equal(holder.privateKey, undefined);
  assert.ok(concurrent.privateKey);

  holder.release();
  const next = await acquirePeerIdentity(datastore);
  holder.release();
  const afterStaleRelease = await acquirePeerIdentity(datastore);
  assert.equal(next.privateKey, undefined);
  assert.ok(afterStaleRelease.privateKey);
  next.release();
});
