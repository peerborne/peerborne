import { performance } from 'node:perf_hooks'
import { publicKeyFromProtobuf } from '@libp2p/crypto/keys'
import { TopicValidatorResult, type GossipSub, type TopicValidatorFn } from '@libp2p/gossipsub'
import type { Libp2p, PeerId } from '@libp2p/interface'
import { RefillingBucket } from './refilling-bucket.js'

/**
 * Bounds for the shared peer-discovery topic. Peers broadcast their record
 * every 10 seconds; a Peerborne Note tab's record is about 600 bytes.
 */
export const discoveryTopicLimits = {
  maxRecordBytes: 4096,
  burst: 3,
  refillMs: 5000,
  maxTrackedPeers: 1024,
}

export type DiscoveryTopicLimits = typeof discoveryTopicLimits

const PUBLIC_KEY_TAG = 0x0a
const ADDRESS_TAG = 0x12

function readVarint(data: Uint8Array, offset: number): [number, number] | undefined {
  let value = 0
  for (let shift = 0; shift < 28; shift += 7) {
    if (offset >= data.length) return undefined
    const byte = data[offset++]
    value += (byte & 0x7f) * 2 ** shift
    if (byte < 0x80) return [value, offset]
  }
  return undefined
}

/**
 * Returns the public key of a pubsub-peer-discovery `Peer` record that holds
 * only a public key and addresses, or undefined for anything else.
 */
function recordPublicKey(data: Uint8Array): Uint8Array | undefined {
  let publicKey: Uint8Array | undefined
  let offset = 0
  while (offset < data.length) {
    const tag = readVarint(data, offset)
    if (!tag || (tag[0] !== PUBLIC_KEY_TAG && tag[0] !== ADDRESS_TAG)) return undefined
    const length = readVarint(data, tag[1])
    if (!length || length[1] + length[0] > data.length) return undefined
    offset = length[1] + length[0]
    if (tag[0] === PUBLIC_KEY_TAG) {
      if (publicKey) return undefined
      publicKey = data.subarray(length[1], offset)
    }
  }
  return publicKey
}

function isOwnRecord(data: Uint8Array, signer: PeerId): boolean {
  const publicKey = recordPublicKey(data)
  if (!publicKey) return false
  try {
    const recorded = publicKeyFromProtobuf(publicKey).toMultihash().bytes
    return Buffer.compare(recorded, signer.toMultihash().bytes) === 0
  } catch {
    return false
  }
}

/**
 * Validates the shared peer-discovery topic before the relay forwards it to
 * every subscriber. A record must be its signer's own bounded record, and each
 * peer that delivers records may send a small burst that refills at twice the
 * default broadcast rate. Ignored and rejected messages are not forwarded.
 */
export class DiscoveryTopicGuard {
  private readonly sources = new Map<string, RefillingBucket>()

  constructor(
    readonly limits: DiscoveryTopicLimits = discoveryTopicLimits,
    private readonly now: () => number = () => performance.now(),
  ) {}

  readonly validate: TopicValidatorFn = (source, message) => {
    if (!this.take(source.toString())) return TopicValidatorResult.Ignore
    if (
      message.type !== 'signed' ||
      message.data.byteLength > this.limits.maxRecordBytes ||
      !isOwnRecord(message.data, message.from)
    ) {
      return TopicValidatorResult.Reject
    }
    return TopicValidatorResult.Accept
  }

  forget(source: PeerId): void {
    this.sources.delete(source.toString())
  }

  private take(source: string): boolean {
    const now = this.now()
    let bucket = this.sources.get(source)
    if (!bucket) {
      if (this.sources.size >= this.limits.maxTrackedPeers) this.evict(now)
      bucket = new RefillingBucket(this.limits.burst, 1 / this.limits.refillMs, now)
      this.sources.set(source, bucket)
    }
    if (bucket.available(now) < 1) return false
    bucket.spend(1, now)
    return true
  }

  private evict(now: number): void {
    for (const [source, bucket] of this.sources) {
      if (bucket.available(now) >= bucket.capacity) this.sources.delete(source)
    }
    const oldest = this.sources.keys().next()
    if (this.sources.size >= this.limits.maxTrackedPeers && !oldest.done) {
      this.sources.delete(oldest.value)
    }
  }
}

export function guardDiscoveryTopic(
  libp2p: Libp2p<{ pubsub: GossipSub }>,
  topic: string,
  guard = new DiscoveryTopicGuard(),
): DiscoveryTopicGuard {
  libp2p.services.pubsub.topicValidators.set(topic, guard.validate)
  libp2p.addEventListener('peer:disconnect', (event) => guard.forget(event.detail))
  return guard
}
