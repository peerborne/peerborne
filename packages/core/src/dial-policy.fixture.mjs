import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import test from 'node:test';
import 'fake-indexeddb/auto';
import { noise } from '@chainsafe/libp2p-noise';
import { yamux } from '@chainsafe/libp2p-yamux';
import { generateKeyPair } from '@libp2p/crypto/keys';
import { peerIdFromPrivateKey } from '@libp2p/peer-id';
import { webSockets } from '@libp2p/websockets';
import { multiaddr } from '@multiformats/multiaddr';
import { createLibp2p } from 'libp2p';
import { denyLocalNetworkDial, isLocalNetworkAddress } from './dial-policy.ts';
import { defaultBootstrapConfig, defaultConfig } from './peerborne-config.ts';
import { defaultNodeConfig } from './peerborne-node.ts';

const peerId = async () =>
  peerIdFromPrivateKey(await generateKeyPair('Ed25519'));
const RELAY = await peerId();
const PEER = await peerId();

const LOCAL = [
  '/ip4/127.0.0.1/tcp/4001/ws',
  '/ip4/127.1.2.3/tcp/4001',
  '/ip4/10.0.0.8/tcp/4001',
  '/ip4/172.16.5.4/tcp/4001',
  '/ip4/192.168.1.1/tcp/443/wss',
  '/ip4/169.254.169.254/tcp/80',
  '/ip4/100.64.0.1/tcp/4001',
  '/ip4/0.0.0.0/tcp/4001',
  '/ip6/::1/tcp/4001',
  '/ip6/fe80::1/tcp/4001',
  '/ip6/fd00:ec2::254/tcp/80',
  '/ip6/::ffff:127.0.0.1/tcp/4001',
  '/ip6/::ffff:169.254.169.254/tcp/80',
  '/ip6zone/eth0/ip6/fe80::1/tcp/4001',
  '/unix/%2Ftmp%2Fp2p.sock',
  '/dns4/localhost/tcp/4001/ws',
  '/dns4/LOCALHOST./tcp/4001',
  '/dns4/api.localhost/tcp/4001',
  '/dns4/printer.local/tcp/4001',
  '/dns4/metadata.google.internal/tcp/80',
  '/dns4/router.home.arpa/tcp/4001',
  '/dns4/relay/tcp/9001/ws',
  '/dns4/127.0.0.1/tcp/4001',
  '/dns4/127.1/tcp/4001',
  '/dns4/2130706433/tcp/4001',
  '/dns4/0x7f000001/tcp/4001',
  '/dns6/::1/tcp/4001',
  '/dnsaddr/localhost',
  `/ip4/127.0.0.1/tcp/4001/ws/p2p/${RELAY}/p2p-circuit/p2p/${PEER}`,
  `/dns4/relay/tcp/9001/ws/p2p/${RELAY}/p2p-circuit/webrtc/p2p/${PEER}`,
];

const PUBLIC = [
  '/ip4/93.184.215.14/tcp/443/wss',
  '/ip4/8.8.8.8/tcp/4001',
  '/ip6/2606:4700:4700::1111/tcp/443/wss',
  '/dns4/relay.example.com/tcp/443/wss',
  '/dns6/relay.example.com/tcp/443/wss',
  '/dns/relay.peerborne.io/tcp/443/wss',
  '/dns4/8.8.8.8/tcp/4001',
  `/ip4/93.184.215.14/tcp/443/wss/p2p/${RELAY}/p2p-circuit/webrtc/p2p/${PEER}`,
  `/p2p/${RELAY}/p2p-circuit/p2p/${PEER}`,
];

const bootstrap = defaultBootstrapConfig([]);

test('classifies local-network and public addresses', async () => {
  for (const text of LOCAL) {
    assert.equal(isLocalNetworkAddress(multiaddr(text)), true, text);
    assert.equal(await denyLocalNetworkDial(multiaddr(text)), true, text);
  }
  for (const text of PUBLIC) {
    assert.equal(isLocalNetworkAddress(multiaddr(text)), false, text);
    assert.equal(await denyLocalNetworkDial(multiaddr(text)), false, text);
  }
});

test('the Node default config refuses local-network dials unless opted in', async () => {
  const strict = defaultNodeConfig(bootstrap);
  const deny = strict.helia.libp2p.connectionGater.denyDialMultiaddr;
  assert.equal(strict.allowLocalNetworkDials, undefined);
  for (const text of LOCAL)
    assert.equal(await deny(multiaddr(text)), true, text);
  for (const text of PUBLIC)
    assert.equal(await deny(multiaddr(text)), false, text);

  const lan = defaultNodeConfig(bootstrap, undefined, {
    allowLocalNetworkDials: true,
  });
  assert.equal(lan.allowLocalNetworkDials, true);
  for (const text of [...LOCAL, ...PUBLIC])
    assert.equal(
      await lan.helia.libp2p.connectionGater.denyDialMultiaddr(multiaddr(text)),
      false,
      text,
    );
});

test('the browser default config keeps libp2p browser dial gating', async () => {
  const strict = defaultConfig(bootstrap);
  assert.equal(strict.allowLocalNetworkDials, undefined);
  assert.equal(
    strict.helia.libp2p.connectionGater.denyDialMultiaddr,
    undefined,
  );

  const { connectionGater } = await import(
    new URL(
      './config/connection-gater.browser.js',
      import.meta.resolve('libp2p'),
    ).href
  );
  const browser = connectionGater(strict.helia.libp2p.connectionGater);
  for (const text of [
    '/ip4/127.0.0.1/tcp/4001/wss',
    '/ip4/192.168.1.1/tcp/443/wss',
    '/ip4/169.254.169.254/tcp/443/wss',
    '/ip6/::1/tcp/443/wss',
    '/dns4/localhost/tcp/443/wss',
    '/dns4/relay.example.com/tcp/9001/ws',
  ])
    assert.equal(await browser.denyDialMultiaddr(multiaddr(text)), true, text);
  assert.equal(
    await browser.denyDialMultiaddr(
      multiaddr('/dns4/relay.example.com/tcp/443/wss'),
    ),
    false,
  );

  const lan = defaultConfig(bootstrap, undefined, {
    allowLocalNetworkDials: true,
  });
  assert.equal(lan.allowLocalNetworkDials, true);
  assert.equal(
    await connectionGater(lan.helia.libp2p.connectionGater).denyDialMultiaddr(
      multiaddr('/ip4/127.0.0.1/tcp/4001/ws'),
    ),
    false,
  );
});

async function loopbackListener(t) {
  const accepted = { count: 0 };
  const server = createServer((socket) => {
    accepted.count++;
    socket.destroy();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return {
    accepted,
    address: multiaddr(`/ip4/127.0.0.1/tcp/${server.address().port}/ws`),
  };
}

async function dialAdvertised(t, config, address) {
  const node = await createLibp2p({
    transports: [webSockets()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    connectionGater: config.helia.libp2p.connectionGater,
  });
  t.after(() => node.stop());
  const peer = await peerId();
  await node.peerStore.merge(peer, { multiaddrs: [address] });
  return node.dial(peer, { signal: AbortSignal.timeout(10_000) });
}

test('a Node default node does not connect to a loopback address a peer advertises', async (t) => {
  const { accepted, address } = await loopbackListener(t);

  await assert.rejects(
    dialAdvertised(t, defaultNodeConfig(bootstrap), address),
    { name: 'DialDeniedError' },
  );
  assert.equal(accepted.count, 0);

  await assert.rejects(
    dialAdvertised(
      t,
      defaultNodeConfig(bootstrap, undefined, { allowLocalNetworkDials: true }),
      address,
    ),
  );
  assert.ok(accepted.count >= 1);
});
