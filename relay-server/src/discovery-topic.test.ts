import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { generateKeyPair, publicKeyToProtobuf } from '@libp2p/crypto/keys'
import { gossipsub, TopicValidatorResult, type Message } from '@libp2p/gossipsub'
import { identify } from '@libp2p/identify'
import type { PeerId } from '@libp2p/interface'
import type { Multiaddr } from '@multiformats/multiaddr'
import { peerIdFromPrivateKey } from '@libp2p/peer-id'
import { pubsubPeerDiscovery } from '@libp2p/pubsub-peer-discovery'
import { tcp } from '@libp2p/tcp'
import { createLibp2p } from 'libp2p'
import { loadConfig, PUBSUB_PEER_DISCOVERY_TOPIC, relayPubsubOptions } from './config.js'
import { DiscoveryTopicGuard, discoveryTopicLimits, guardDiscoveryTopic } from './discovery-topic.js'

const topic = PUBSUB_PEER_DISCOVERY_TOPIC

function field(tag: number, value: Uint8Array): Uint8Array {
  const length: number[] = []
  let rest = value.length
  while (rest >= 0x80) {
    length.push((rest & 0x7f) | 0x80)
    rest >>>= 7
  }
  return Uint8Array.from([tag, ...length, rest, ...value])
}

function record(publicKey: Uint8Array, ...addresses: Uint8Array[]): Uint8Array {
  return Buffer.concat([field(0x0a, publicKey), ...addresses.map(address => field(0x12, address))])
}

async function signer() {
  const privateKey = await generateKeyPair('Ed25519')
  return { peerId: peerIdFromPrivateKey(privateKey), publicKey: publicKeyToProtobuf(privateKey.publicKey) }
}

function signed(from: PeerId, data: Uint8Array): Message {
  return {
    type: 'signed', from, topic, data, sequenceNumber: 1n, signature: new Uint8Array(64), key: from.publicKey!,
  }
}

async function waitFor(condition: () => boolean, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (!condition()) {
    if (Date.now() >= deadline) throw new Error('Condition was not reached in time')
    await new Promise(resolve => setTimeout(resolve, 20))
  }
}

describe('peer-discovery topic guard', () => {
  let now: number
  beforeEach(() => { now = 0 })

  it('accepts a signer\'s own record up to the size limit', async () => {
    const guard = new DiscoveryTopicGuard({ ...discoveryTopicLimits, burst: 100 }, () => now)
    const { peerId, publicKey } = await signer()
    const sized = (bytes: number) => {
      for (let address = bytes; address > 0; address--) {
        const data = record(publicKey, new Uint8Array(address))
        if (data.length === bytes) return data
      }
      throw new Error('No record of that size')
    }
    expect(guard.validate(peerId, signed(peerId, record(publicKey)))).toBe(TopicValidatorResult.Accept)
    expect(guard.validate(peerId, signed(peerId, record(publicKey, Uint8Array.of(4, 127, 0, 0, 1)))))
      .toBe(TopicValidatorResult.Accept)
    expect(guard.validate(peerId, signed(peerId, sized(discoveryTopicLimits.maxRecordBytes))))
      .toBe(TopicValidatorResult.Accept)
    expect(guard.validate(peerId, signed(peerId, sized(discoveryTopicLimits.maxRecordBytes + 1))))
      .toBe(TopicValidatorResult.Reject)
  })

  it('rejects anything but a signer\'s own discovery record', async () => {
    const guard = new DiscoveryTopicGuard({ ...discoveryTopicLimits, burst: 100 }, () => now)
    const { peerId, publicKey } = await signer()
    const other = await signer()
    const valid = record(publicKey, Uint8Array.of(4, 127, 0, 0, 1))
    const invalid = [
      crypto.getRandomValues(new Uint8Array(10 * 1024)),
      crypto.getRandomValues(new Uint8Array(64)),
      new Uint8Array(0),
      record(other.publicKey),
      record(Uint8Array.of(1, 2, 3)),
      Buffer.concat([valid, field(0x1a, Uint8Array.of(1))]),
      Buffer.concat([valid, field(0x0a, publicKey)]),
      valid.subarray(0, valid.length - 1),
      Uint8Array.of(0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f),
    ]
    for (const data of invalid) {
      expect(guard.validate(peerId, signed(peerId, data))).toBe(TopicValidatorResult.Reject)
    }
    expect(guard.validate(peerId, { type: 'unsigned', topic, data: valid }))
      .toBe(TopicValidatorResult.Reject)
    expect(guard.validate(peerId, signed(peerId, valid))).toBe(TopicValidatorResult.Accept)
  })

  it('lets each delivering peer send a small burst that refills at twice the broadcast rate', async () => {
    const guard = new DiscoveryTopicGuard(discoveryTopicLimits, () => now)
    const flooder = await signer()
    const honest = await signer()
    const flood = signed(flooder.peerId, record(flooder.publicKey))
    for (let index = 0; index < discoveryTopicLimits.burst; index++) {
      expect(guard.validate(flooder.peerId, flood)).toBe(TopicValidatorResult.Accept)
    }
    expect(guard.validate(flooder.peerId, flood)).toBe(TopicValidatorResult.Ignore)
    now = discoveryTopicLimits.refillMs - 1
    expect(guard.validate(flooder.peerId, flood)).toBe(TopicValidatorResult.Ignore)
    now = discoveryTopicLimits.refillMs
    expect(guard.validate(flooder.peerId, flood)).toBe(TopicValidatorResult.Accept)
    expect(guard.validate(flooder.peerId, flood)).toBe(TopicValidatorResult.Ignore)

    const broadcast = signed(honest.peerId, record(honest.publicKey))
    for (let second = 0; second < 60 * 60; second += 10) {
      now = discoveryTopicLimits.refillMs + second * 1000 + (second % 20 === 0 ? 400 : -400)
      expect(guard.validate(honest.peerId, broadcast)).toBe(TopicValidatorResult.Accept)
    }
  })

  it('charges rejected messages to the peer that delivered them', async () => {
    const guard = new DiscoveryTopicGuard(discoveryTopicLimits, () => now)
    const { peerId, publicKey } = await signer()
    for (let index = 0; index < discoveryTopicLimits.burst; index++) {
      expect(guard.validate(peerId, signed(peerId, new Uint8Array(16)))).toBe(TopicValidatorResult.Reject)
    }
    expect(guard.validate(peerId, signed(peerId, record(publicKey)))).toBe(TopicValidatorResult.Ignore)
  })

  it('forgets disconnected or refilled peers but keeps limited ones when its table is full', async () => {
    const guard = new DiscoveryTopicGuard({ ...discoveryTopicLimits, maxTrackedPeers: 2 }, () => now)
    const [limited, refilled, arriving] = await Promise.all([signer(), signer(), signer()])
    const message = (peer: typeof limited) => signed(peer.peerId, record(peer.publicKey))
    for (let index = 0; index < discoveryTopicLimits.burst; index++) guard.validate(limited.peerId, message(limited))
    guard.validate(refilled.peerId, message(refilled))
    now = discoveryTopicLimits.refillMs
    expect(guard.validate(arriving.peerId, message(arriving))).toBe(TopicValidatorResult.Accept)
    expect(guard.validate(limited.peerId, message(limited))).toBe(TopicValidatorResult.Accept)
    expect(guard.validate(limited.peerId, message(limited))).toBe(TopicValidatorResult.Ignore)
    guard.forget(limited.peerId)
    expect(guard.validate(limited.peerId, message(limited))).toBe(TopicValidatorResult.Accept)
  })
})

describe('peer-discovery topic through a relay', () => {
  const stops: Array<() => Promise<void>> = []
  afterEach(async () => {
    await Promise.all(stops.splice(0).map(stop => stop()))
  })

  async function relay(guard?: DiscoveryTopicGuard) {
    const config = loadConfig({ WS_LISTEN: '/ip4/127.0.0.1/tcp/0/ws', TCP_LISTEN: '/ip4/127.0.0.1/tcp/0' })
    const node = await createLibp2p({
      addresses: { listen: [config.tcpListen] },
      transports: [tcp()],
      connectionEncrypters: [noise()],
      streamMuxers: [yamux()],
      connectionManager: { inboundConnectionThreshold: 100 },
      services: { identify: identify(), pubsub: gossipsub(relayPubsubOptions(config)) },
    })
    stops.push(() => node.stop())
    if (guard) guardDiscoveryTopic(node, topic, guard)
    node.services.pubsub.subscribe(topic)
    return node
  }

  function meshSize(hub: Awaited<ReturnType<typeof relay>>): number {
    return (hub.services.pubsub as unknown as { mesh: Map<string, Set<string>> }).mesh.get(topic)?.size ?? 0
  }

  async function client(relayAddress: Multiaddr, discoveryIntervalMs?: number) {
    const privateKey = await generateKeyPair('Ed25519')
    const node = await createLibp2p({
      privateKey,
      transports: [tcp()],
      connectionEncrypters: [noise()],
      streamMuxers: [yamux()],
      services: {
        identify: identify(),
        pubsub: gossipsub({ allowPublishToZeroTopicPeers: true }),
        ...(discoveryIntervalMs
          ? { discovery: pubsubPeerDiscovery({ interval: discoveryIntervalMs, topics: [topic] }) }
          : {}),
      },
    })
    stops.push(() => node.stop())
    node.services.pubsub.subscribe(topic)
    const received = new Map<string, number>()
    node.services.pubsub.addEventListener('message', event => {
      if (event.detail.topic !== topic || event.detail.type !== 'signed') return
      const author = event.detail.from.toString()
      received.set(author, (received.get(author) ?? 0) + 1)
    })
    await node.dial(relayAddress)
    return { node, received, publicKey: publicKeyToProtobuf(privateKey.publicKey) }
  }

  it.each([
    ['without the guard', undefined, 30],
    ['with the guard', new DiscoveryTopicGuard(), discoveryTopicLimits.burst],
  ])('forwards a flood from one peer to each subscriber %s', async (_mode, guard, delivered) => {
    const hub = await relay(guard)
    const subscribers = await Promise.all([0, 1, 2].map(() => client(hub.getMultiaddrs()[0])))
    const flooder = await client(hub.getMultiaddrs()[0])
    await waitFor(() => meshSize(hub) === 4 && flooder.node.services.pubsub.getSubscribers(topic)
      .some(id => id.equals(hub.peerId)), 10_000)

    for (let index = 0; index < 20; index++) {
      await flooder.node.services.pubsub.publish(topic, record(flooder.publicKey))
    }
    for (let index = 0; index < 10; index++) {
      await flooder.node.services.pubsub.publish(topic, crypto.getRandomValues(new Uint8Array(10 * 1024)))
    }
    const author = flooder.node.peerId.toString()
    const counts = () => subscribers.map(peer => peer.received.get(author) ?? 0)
    await waitFor(() => counts().every(count => count >= delivered))
    await new Promise(resolve => setTimeout(resolve, 500))
    expect(counts()).toEqual([delivered, delivered, delivered])
  }, 20_000)

  it('keeps forwarding every pubsub-peer-discovery broadcast from honest peers', async () => {
    const intervalMs = 250
    const hub = await relay(new DiscoveryTopicGuard({ ...discoveryTopicLimits, refillMs: intervalMs / 2 }))
    const validate = hub.services.pubsub.topicValidators.get(topic)!
    const results: TopicValidatorResult[] = []
    hub.services.pubsub.topicValidators.set(topic, async (peer, message) => {
      const result = await validate(peer, message)
      results.push(result)
      return result
    })
    const peers = await Promise.all([0, 1, 2].map(() => client(hub.getMultiaddrs()[0], intervalMs)))
    const pairs = peers.flatMap(listener => peers
      .filter(speaker => speaker !== listener)
      .map(speaker => () => listener.received.get(speaker.node.peerId.toString()) ?? 0))
    await waitFor(() => pairs.every(heard => heard() > 0), 10_000)
    const before = pairs.map(heard => heard())
    const windowMs = 4000
    await new Promise(resolve => setTimeout(resolve, windowMs))
    const during = pairs.map((heard, index) => heard() - before[index])
    for (const count of during) expect(count).toBeGreaterThanOrEqual(windowMs / intervalMs - 2)
    expect(results.length).toBeGreaterThanOrEqual(peers.length * (windowMs / intervalMs - 2))
    expect(results.filter(result => result !== TopicValidatorResult.Accept)).toEqual([])
  }, 20_000)
})
