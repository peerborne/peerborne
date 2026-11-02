import { createLibp2p } from 'libp2p'
import { tcp } from '@libp2p/tcp'
import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { identify } from '@libp2p/identify'
import { gossipsub } from '@libp2p/gossipsub'
import { loadConfig, relayPubsubOptions } from './config.js'

const topic = '/peerborne/document/v3/proxy-reconnect-regression'

async function waitFor(condition: () => boolean): Promise<void> {
  const deadline = Date.now() + 3000
  while (!condition()) {
    if (Date.now() >= deadline) throw new Error('Pubsub subscription or delivery did not complete')
    await new Promise(resolve => setTimeout(resolve, 20))
  }
}

function createPeer(listener = false) {
  const config = loadConfig({
    WS_LISTEN: '/ip4/127.0.0.1/tcp/0/ws',
    TCP_LISTEN: '/ip4/127.0.0.1/tcp/0',
  })
  return createLibp2p({
    addresses: { listen: listener ? [config.tcpListen] : [] },
    transports: [tcp()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    // Allow the test's bounded turnover sequence without artificial delays.
    connectionManager: { inboundConnectionThreshold: 100 },
    services: {
      identify: identify(),
      pubsub: gossipsub(listener ? relayPubsubOptions(config) : {
        allowPublishToZeroTopicPeers: true,
      }),
    },
  })
}

it('continues subscriptions and signed delivery after 20 loopback-proxied identities', async () => {
  const relay = await createPeer(true)
  relay.services.pubsub.subscribe(topic)
  const received: number[] = []
  relay.services.pubsub.addEventListener('message', event => {
    if (event.detail.topic === topic) received.push(event.detail.data[0])
  })
  try {
    for (let iteration = 0; iteration < 20; iteration++) {
      const peer = await createPeer()
      try {
        peer.services.pubsub.subscribe(topic)
        await peer.dial(relay.getMultiaddrs()[0])
        await waitFor(() =>
          relay.services.pubsub.getSubscribers(topic).some(id => id.equals(peer.peerId)) &&
          peer.services.pubsub.getSubscribers(topic).some(id => id.equals(relay.peerId)),
        )
        const returned: number[] = []
        peer.services.pubsub.addEventListener('message', event => {
          if (event.detail.topic === topic) returned.push(event.detail.data[0])
        })
        await peer.services.pubsub.publish(topic, Uint8Array.of(iteration))
        await relay.services.pubsub.publish(topic, Uint8Array.of(iteration + 100))
        await waitFor(() => received.includes(iteration) && returned.includes(iteration + 100))
      } finally {
        await peer.stop()
      }
    }
    expect(received).toEqual(Array.from({ length: 20 }, (_, index) => index))
  } finally {
    await relay.stop()
  }
}, 30_000)

it('retains IP scoring for public listeners and exempts only proxy loopback addresses', () => {
  expect(relayPubsubOptions(loadConfig({})).scoreParams).toBeUndefined()
  const proxy = loadConfig({
    WS_LISTEN: '/ip4/127.0.0.1/tcp/9001/ws',
    TCP_LISTEN: '/ip4/127.0.0.1/tcp/9002',
  })
  const options = relayPubsubOptions(proxy)
  expect(options.scoreParams?.IPColocationFactorWhitelist).toEqual(new Set(['127.0.0.1', '::1']))
  expect(options.scoreParams?.IPColocationFactorWeight).toBeUndefined()
  expect(relayPubsubOptions({ ...proxy, ipv6Enabled: true }).scoreParams).toBeUndefined()
})
