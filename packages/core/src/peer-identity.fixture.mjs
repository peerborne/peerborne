import assert from 'node:assert/strict';
import test from 'node:test';
import 'fake-indexeddb/auto';
import { generateKeyPair } from '@libp2p/crypto/keys';
import { peerIdFromPrivateKey } from '@libp2p/peer-id';
import { Key } from 'interface-datastore';
import { createAndStartHeliaNode } from './helia-node.ts';
import { defaultBootstrapConfig, defaultConfig } from './peerborne-config.ts';
import { closeHeliaStores } from './store-lifecycle.ts';

async function start(config) {
  const started = await createAndStartHeliaNode(config.helia);
  return {
    ...started,
    async stop() {
      await started.heliaNode.stop();
      await closeHeliaStores(started.openedStores);
    },
  };
}

test('two default-config instances on one origin get distinct PeerIds', async () => {
  const first = await start(defaultConfig(defaultBootstrapConfig([])));
  try {
    const second = await start(defaultConfig(defaultBootstrapConfig([])));
    try {
      assert.notEqual(
        first.heliaNode.libp2p.peerId.toString(),
        second.heliaNode.libp2p.peerId.toString(),
      );
      assert.equal(
        await second.heliaNode.datastore.has(new Key('/pkcs8/self')),
        false,
      );
    } finally {
      await second.stop();
    }
  } finally {
    await first.stop();
  }
});

test('a default-config restart gets a new PeerId', async () => {
  const first = await start(defaultConfig(defaultBootstrapConfig([])));
  const firstPeerId = first.heliaNode.libp2p.peerId.toString();
  await first.stop();
  const second = await start(defaultConfig(defaultBootstrapConfig([])));
  try {
    assert.notEqual(second.heliaNode.libp2p.peerId.toString(), firstPeerId);
  } finally {
    await second.stop();
  }
});

test('a configured libp2p private key sets the PeerId', async () => {
  const privateKey = await generateKeyPair('Ed25519');
  const config = defaultConfig(defaultBootstrapConfig([]));
  config.helia.libp2p.privateKey = privateKey;
  const started = await start(config);
  try {
    assert.equal(
      started.heliaNode.libp2p.peerId.toString(),
      peerIdFromPrivateKey(privateKey).toString(),
    );
  } finally {
    await started.stop();
  }
});
