import { readFileSync } from 'node:fs'
import { createLibp2p } from 'libp2p'
import { tcp } from '@libp2p/tcp'
import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { identify } from '@libp2p/identify'
import { gossipsub } from '@libp2p/gossipsub'
import { PUBSUB_PEER_DISCOVERY_TOPIC, loadConfig, relayPubsubOptions } from './config.js'

const topic = '/peerborne/document/v3/proxy-reconnect-regression'

async function waitFor(condition: () => boolean): Promise<void> {
  const deadline = Date.now() + 3000
  while (!condition()) {
    if (Date.now() >= deadline) throw new Error('Pubsub subscription or delivery did not complete')
    await new Promise(resolve => setTimeout(resolve, 20))
  }
}

const loopbackProxy = {
  WS_LISTEN: '/ip4/127.0.0.1/tcp/0/ws',
  TCP_LISTEN: '/ip4/127.0.0.1/tcp/0',
}

// A public WebSocket listener disables the loopback inference, while the test
// peers still dial the loopback TCP listener as a proxy on 127.0.0.1 would.
const publicListener = {
  WS_LISTEN: '/ip4/0.0.0.0/tcp/0/ws',
  TCP_LISTEN: '/ip4/127.0.0.1/tcp/0',
}

function createPeer(listener = false, env: NodeJS.ProcessEnv = loopbackProxy) {
  const config = loadConfig(env)
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

it.each([
  ['loopback-only listeners', loopbackProxy],
  ['a public listener with the proxy IP trusted', { ...publicListener, TRUSTED_PROXY_IPS: '127.0.0.1' }],
  ['a public listener with every connection proxied', { ...publicListener, TRUSTED_PROXY_IPS: '*' }],
])('continues subscriptions and signed delivery after 20 proxied identities with %s', async (_mode, env) => {
  const relay = await createPeer(true, env)
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

it('exempts configured proxy addresses or disables colocation scoring behind any proxy', () => {
  const trusted = relayPubsubOptions(loadConfig({ TRUSTED_PROXY_IPS: '172.16.0.2,fdaa::3' }))
  expect(trusted.scoreParams?.IPColocationFactorWhitelist).toEqual(new Set(['172.16.0.2', 'fdaa::3']))
  expect(trusted.scoreParams?.IPColocationFactorWeight).toBeUndefined()
  const combined = relayPubsubOptions(loadConfig({ ...loopbackProxy, TRUSTED_PROXY_IPS: '10.0.0.5' }))
  expect(combined.scoreParams?.IPColocationFactorWhitelist).toEqual(new Set(['10.0.0.5', '127.0.0.1', '::1']))
  const everyConnection = relayPubsubOptions(loadConfig({ TRUSTED_PROXY_IPS: '*' }))
  expect(everyConnection.scoreParams).toEqual({ IPColocationFactorWeight: 0 })
})

function renderEnvironment(): NodeJS.ProcessEnv {
  const blueprint = readFileSync(new URL('../../render.yaml', import.meta.url), 'utf8')
  return Object.fromEntries(
    [...blueprint.matchAll(/- key: (\w+)\n\s+value: '([^']*)'/g)].map(([, key, value]) => [key, value]),
  )
}

it('records every subscription within the Render per-peer auto-topic allowance', async () => {
  const render = renderEnvironment()
  expect(render).toMatchObject({
    GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER: expect.stringMatching(/^\d+$/),
    MAX_AUTO_TOPICS_PER_PEER: expect.stringMatching(/^\d+$/),
  })
  const relay = await createPeer(true, {
    ...loopbackProxy,
    GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER: render.GOSSIPSUB_MAX_TOPIC_BYTES_PER_PEER,
  })
  const peer = await createPeer()
  const documents = Array.from(
    { length: Number(render.MAX_AUTO_TOPICS_PER_PEER) },
    (_, index) => `peerborne/coordinated/v1/${index.toString(16).padStart(64, '0')}`,
  )
  const topics = [PUBSUB_PEER_DISCOVERY_TOPIC, ...documents]
  try {
    for (const topic of topics) peer.services.pubsub.subscribe(topic)
    await peer.dial(relay.getMultiaddrs()[0])
    await waitFor(() => topics.every(topic =>
      relay.services.pubsub.getSubscribers(topic).some(id => id.equals(peer.peerId)),
    ))
  } finally {
    await peer.stop()
    await relay.stop()
  }
}, 15_000)
