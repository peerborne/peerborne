import { createLibp2p } from 'libp2p'
import { autoNAT } from '@libp2p/autonat'
import { identify } from '@libp2p/identify'
import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { gossipsub } from '@libp2p/gossipsub'
import { webSockets } from '@libp2p/websockets'
import { tcp } from '@libp2p/tcp'
import { pubsubPeerDiscovery } from '@libp2p/pubsub-peer-discovery'
import { circuitRelayServer } from '@libp2p/circuit-relay-v2'
import * as fs from 'node:fs'
import * as path from 'node:path'

import { AutoTopicRegistry } from './auto-topic-registry.js'
import {
  circuitRelayServerOptions,
  listenAddresses,
  loadConfig,
} from './config.js'
import { loadOrCreateRelayIdentity } from './identity.js'
import { IntervalGate } from './interval-gate.js'
import { startReadinessServer } from './readiness.js'

async function main() {
  const config = loadConfig()
  const {
    peerDiscoveryTopic,
    documentPublishPath,
    topicAllowlist,
    maxAutoTopics,
    maxAutoTopicsPerPeer,
    gossipsubMaxTopicBytesPerPeer,
    extraTopics,
    maxConnections,
    relayLimits,
  } = config
  const readiness = await startReadinessServer(config.readinessPort)

  try {
    const privateKey = await loadOrCreateRelayIdentity(config.identityKeyPath)
    const libp2p = await createLibp2p({
      privateKey,
      addresses: {
        listen: listenAddresses(config),
      },
      transports: [
        webSockets(),
        tcp(),
      ],
      connectionEncrypters: [noise()],
      streamMuxers: [yamux()],
      connectionGater: {
        denyDialMultiaddr: async () => false,
      },
      connectionManager: {
        maxConnections,
      },
      services: {
        identify: identify(),
        autoNat: autoNAT(),
        relay: circuitRelayServer(circuitRelayServerOptions(config)),
        pubsub: gossipsub({
          allowPublishToZeroTopicPeers: true,
          canRelayMessage: true,
          floodPublish: true,
          maxTopicBytesPerPeer: gossipsubMaxTopicBytesPerPeer,
        }),
        pubsubPeerDiscovery: pubsubPeerDiscovery({
          topics: [peerDiscoveryTopic],
        }),
      },
    })

    // Seed and operator-configured topics are permanent subscriptions.
    // The relay must be subscribed to these topics to forward messages between
    // browser peers that are connected to the relay but not yet to each other.
    libp2p.services.pubsub.subscribe(peerDiscoveryTopic)
    libp2p.services.pubsub.subscribe(documentPublishPath)
    for (const topic of extraTopics) {
      if (topic !== peerDiscoveryTopic && topic !== documentPublishPath) {
        libp2p.services.pubsub.subscribe(topic)
      }
    }

    // Auto-subscribe to document topics as peers join them. The safe default
    // allows only /document/ and /documents. Set TOPIC_ALLOWLIST=* explicitly
    // to allow every non-system topic.
    const permanentTopics = new Set<string>([
      peerDiscoveryTopic,
      documentPublishPath,
      ...extraTopics,
    ])
    const autoTopics = new AutoTopicRegistry({
      permanentTopics,
      allowlist: topicAllowlist,
      maxAutoTopics,
      maxAutoTopicsPerPeer,
    })
    const autoTopicLimitWarning = new IntervalGate(60_000)

    const unsubscribeDynamicTopic = (topic: string): void => {
      libp2p.services.pubsub.unsubscribe(topic)
      console.log('Auto-unsubscribed from an inactive dynamic topic', {
        autoTopicCount: autoTopics.size,
      })
    }

    const reconcileDynamicTopic = (topic: string): void => {
      const subscribers = libp2p.services.pubsub.getSubscribers(topic)
      const action = autoTopics.reconcileTopic(
        topic,
        subscribers.map((peerId) => peerId.toString()),
      )
      if (action.action === 'unsubscribe') {
        unsubscribeDynamicTopic(topic)
      }
    }

    libp2p.services.pubsub.addEventListener(
      'subscription-change',
      (event: any) => {
        const { peerId, subscriptions } = event.detail
        for (const sub of subscriptions) {
          const action = autoTopics.subscriptionChanged(
            peerId.toString(),
            sub.topic,
            sub.subscribe,
          )
          if (action.action === 'skip') {
            if (
              action.reason === 'CapReached' ||
              action.reason === 'PeerCapReached'
            ) {
              if (autoTopicLimitWarning.open()) {
                console.warn('Auto-subscribe limit reached; requests ignored', {
                  reason: action.reason,
                  autoTopicCount: autoTopics.size,
                  maxAutoTopics,
                  maxAutoTopicsPerPeer,
                })
              }
            }
            continue
          }
          if (action.action === 'subscribe') {
            libp2p.services.pubsub.subscribe(sub.topic)
            console.log('Auto-subscribed to a dynamic topic', {
              autoTopicCount: autoTopics.size,
              maxAutoTopics,
            })
          } else if (action.action === 'unsubscribe') {
            unsubscribeDynamicTopic(sub.topic)
          }
        }
      },
    )

    // Reconcile against GossipSub as a bounded backstop for missed
    // subscription-change events. autoTopics can contain at most
    // MAX_AUTO_TOPICS entries.
    const topicReconciliation = setInterval(() => {
      for (const topic of [...autoTopics.topics()]) {
        reconcileDynamicTopic(topic)
      }
    }, 30_000)
    topicReconciliation.unref()

    console.log('Subscribed to configured relay topics', {
      seedTopicCount: 2,
      extraTopicCount: extraTopics.length,
    })

    const peerId = libp2p.peerId.toString()
    const multiaddrs = libp2p.getMultiaddrs().map((ma) => ma.toString())
    const wsMultiaddr = multiaddrs.find((ma) => ma.includes('/ws/')) ?? multiaddrs[0]

    console.log('PeerId:', peerId)
    console.log('Multiaddrs:', multiaddrs)
    console.log('Circuit Relay limits:', {
      ...relayLimits,
      maxCircuitDataBytes: relayLimits.maxCircuitDataBytes.toString(),
    })

    const relayInfo = {
      peerId,
      multiaddrs,
      wsMultiaddr,
    }

    const sharedDir = '/shared'
    const outputPath = fs.existsSync(sharedDir)
      ? path.join(sharedDir, 'relay-info.json')
      : path.join(process.cwd(), 'relay-info.json')

    fs.writeFileSync(outputPath, JSON.stringify(relayInfo, null, 2))
    console.log('Relay info written to:', outputPath)
    readiness.markReady(peerId)

    // Peer IDs and connection timing are metadata; never log payloads or keys.
    libp2p.addEventListener('peer:connect', () => {
      console.log('Peer connected')
    })
    libp2p.addEventListener('peer:disconnect', (event) => {
      const peerId = event.detail.toString()
      console.log('Peer disconnected')
      for (const action of autoTopics.peerDisconnected(peerId)) {
        if (action.action === 'unsubscribe') {
          unsubscribeDynamicTopic(action.topic)
        }
      }
    })

    let stopping = false
    const shutdown = async () => {
      if (stopping) return
      stopping = true
      clearInterval(topicReconciliation)
      readiness.markNotReady()
      console.log('Shutting down relay server...')
      await libp2p.stop()
      await readiness.close()
      process.exit(0)
    }

    process.once('SIGTERM', shutdown)
    process.once('SIGINT', shutdown)
  } catch (error) {
    readiness.markNotReady()
    await readiness.close()
    throw error
  }
}

main().catch((err) => {
  console.error('Failed to start relay server:', err)
  process.exit(1)
})
