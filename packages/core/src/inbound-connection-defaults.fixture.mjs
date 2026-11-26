import assert from 'node:assert/strict';
import test from 'node:test';
import 'fake-indexeddb/auto';
import { generateKeyPair } from '@libp2p/crypto/keys';
import { peerIdFromPrivateKey } from '@libp2p/peer-id';
import { multiaddr } from '@multiformats/multiaddr';
import { createLibp2p } from 'libp2p';
import {
  DEFAULT_INBOUND_CONNECTION_THRESHOLD,
  defaultBootstrapConfig,
  defaultConfig,
} from './peerborne-config.ts';
import { defaultNodeConfig } from './peerborne-node.ts';

const PEERS = 12;

async function peerId() {
  return peerIdFromPrivateKey(await generateKeyPair('Ed25519'));
}

async function arrivals() {
  const relay = await peerId();
  return Promise.all(
    Array.from({ length: PEERS }, async () =>
      multiaddr(
        `/ip4/192.0.2.1/tcp/443/wss/p2p/${relay}/p2p-circuit/p2p/${await peerId()}`,
      ),
    ),
  );
}

// The inbound gate is internal to libp2p, so it is driven directly to check
// how it attributes relayed connections.
async function acceptedInOneBurst(connectionManager, addresses) {
  const node = await createLibp2p({ start: false, connectionManager });
  const gate = node.components.connectionManager;
  let accepted = 0;
  for (const remoteAddr of addresses) {
    if (!gate.acceptIncomingConnection({ remoteAddr })) continue;
    accepted++;
    gate.afterUpgradeInbound();
  }
  return accepted;
}

test('libp2p counts peers arriving through one relay against the relay host', async () => {
  assert.equal(await acceptedInOneBurst({}, await arrivals()), 5);
});

test('browser and Node builders accept a burst of peers arriving through one relay', async () => {
  const bootstrap = defaultBootstrapConfig([]);
  for (const config of [
    defaultConfig(bootstrap),
    defaultNodeConfig(bootstrap),
  ]) {
    const { connectionManager } = config.helia.libp2p;
    assert.equal(
      connectionManager.inboundConnectionThreshold,
      DEFAULT_INBOUND_CONNECTION_THRESHOLD,
    );
    assert.equal(
      await acceptedInOneBurst(connectionManager, await arrivals()),
      PEERS,
    );
  }
});
