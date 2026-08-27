import type {
  AutoSubscribePolicy,
  AutoSubscribeSkipReason,
} from './topic-policy.js'
import { shouldAutoSubscribe } from './topic-policy.js'

export type AutoTopicAction =
  | { readonly action: 'subscribe'; readonly topic: string }
  | { readonly action: 'unsubscribe'; readonly topic: string }
  | {
      readonly action: 'skip'
      readonly topic: string
      readonly reason?: AutoSubscribeSkipReason
    }

interface AutoTopicRegistryOptions {
  readonly permanentTopics: Iterable<string>
  readonly allowlist: readonly string[] | null
  readonly maxAutoTopics: number
  readonly maxAutoTopicsPerPeer: number
}

/**
 * Tracks the remote peers that caused each dynamic relay subscription.
 *
 * GossipSub does not emit an unsubscribe event for every topic when a peer
 * disconnects, so relying on subscription-change alone can strand dynamic
 * subscriptions forever. This registry keeps the reverse peer/topic index
 * needed to reclaim them on peer:disconnect. Its topic cardinality is bounded
 * by maxAutoTopics.
 */
export class AutoTopicRegistry {
  readonly #permanentTopics: Set<string>
  readonly #allowlist: readonly string[] | null
  readonly #maxAutoTopics: number
  readonly #maxAutoTopicsPerPeer: number
  readonly #topicPeers = new Map<string, Set<string>>()
  readonly #peerTopics = new Map<string, Set<string>>()

  constructor(options: AutoTopicRegistryOptions) {
    this.#permanentTopics = new Set(options.permanentTopics)
    this.#allowlist = options.allowlist
    this.#maxAutoTopics = options.maxAutoTopics
    this.#maxAutoTopicsPerPeer = options.maxAutoTopicsPerPeer
  }

  get size(): number {
    return this.#topicPeers.size
  }

  topics(): IterableIterator<string> {
    return this.#topicPeers.keys()
  }

  subscriptionChanged(
    peerId: string,
    topic: string,
    subscribe: boolean,
  ): AutoTopicAction {
    if (!subscribe) {
      return this.#removePeerFromTopic(peerId, topic)
    }

    const existingPeers = this.#topicPeers.get(topic)
    if (existingPeers !== undefined) {
      if (existingPeers.has(peerId)) {
        return { action: 'skip', topic, reason: 'AlreadyTracked' }
      }
      if (!this.#peerHasCapacity(peerId)) {
        return { action: 'skip', topic, reason: 'PeerCapReached' }
      }
      this.#recordPeerTopic(peerId, topic, existingPeers)
      return { action: 'skip', topic, reason: 'AlreadyTracked' }
    }

    const decision = shouldAutoSubscribe(topic, this.#policy())
    if (decision.action === 'skip') {
      return { action: 'skip', topic, reason: decision.reason }
    }
    if (!this.#peerHasCapacity(peerId)) {
      return { action: 'skip', topic, reason: 'PeerCapReached' }
    }

    const peers = new Set<string>()
    this.#topicPeers.set(topic, peers)
    this.#recordPeerTopic(peerId, topic, peers)
    return { action: 'subscribe', topic }
  }

  peerDisconnected(peerId: string): AutoTopicAction[] {
    const topics = this.#peerTopics.get(peerId)
    if (topics === undefined) {
      return []
    }

    const actions: AutoTopicAction[] = []
    for (const topic of [...topics]) {
      const action = this.#removePeerFromTopic(peerId, topic)
      if (action.action === 'unsubscribe') {
        actions.push(action)
      }
    }
    return actions
  }

  /**
   * Forget a topic after GossipSub confirms it has no remote subscribers.
   * This periodic reconciliation bounds stale state if an event is missed.
   */
  reconcileTopic(
    topic: string,
    remotePeerIds: Iterable<string>,
  ): AutoTopicAction {
    if (!this.#topicPeers.has(topic)) {
      return { action: 'skip', topic }
    }

    const actualPeers = new Set<string>()
    const previousPeers = this.#topicPeers.get(topic) ?? new Set<string>()
    for (const peerId of remotePeerIds) {
      if (previousPeers.has(peerId) || this.#peerHasCapacity(peerId)) {
        actualPeers.add(peerId)
      }
    }
    this.#replaceTopicPeers(topic, actualPeers)
    if (actualPeers.size > 0) {
      return { action: 'skip', topic }
    }

    this.#topicPeers.delete(topic)
    return { action: 'unsubscribe', topic }
  }

  #policy(): AutoSubscribePolicy {
    return {
      allowlist: this.#allowlist,
      maxAutoTopics: this.#maxAutoTopics,
      autoTopicCount: this.#topicPeers.size,
      isTracked: (topic) =>
        this.#permanentTopics.has(topic) || this.#topicPeers.has(topic),
    }
  }

  #recordPeerTopic(peerId: string, topic: string, peers: Set<string>): void {
    peers.add(peerId)
    const topics = this.#peerTopics.get(peerId) ?? new Set<string>()
    topics.add(topic)
    this.#peerTopics.set(peerId, topics)
  }

  #peerHasCapacity(peerId: string): boolean {
    return (this.#peerTopics.get(peerId)?.size ?? 0) < this.#maxAutoTopicsPerPeer
  }

  #removePeerFromTopic(peerId: string, topic: string): AutoTopicAction {
    const peers = this.#topicPeers.get(topic)
    if (peers === undefined || !peers.delete(peerId)) {
      return { action: 'skip', topic }
    }

    const topics = this.#peerTopics.get(peerId)
    topics?.delete(topic)
    if (topics?.size === 0) {
      this.#peerTopics.delete(peerId)
    }

    if (peers.size > 0) {
      return { action: 'skip', topic }
    }

    this.#topicPeers.delete(topic)
    return { action: 'unsubscribe', topic }
  }

  #replaceTopicPeers(topic: string, actualPeers: Set<string>): void {
    const previousPeers = this.#topicPeers.get(topic) ?? new Set<string>()
    for (const peerId of previousPeers) {
      const topics = this.#peerTopics.get(peerId)
      topics?.delete(topic)
      if (topics?.size === 0) {
        this.#peerTopics.delete(peerId)
      }
    }

    if (actualPeers.size === 0) {
      return
    }

    this.#topicPeers.set(topic, actualPeers)
    for (const peerId of actualPeers) {
      const topics = this.#peerTopics.get(peerId) ?? new Set<string>()
      topics.add(topic)
      this.#peerTopics.set(peerId, topics)
    }
  }
}
