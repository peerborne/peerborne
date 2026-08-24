import { createLibp2p } from 'libp2p'
import { webRTC } from '@libp2p/webrtc'
import { webSockets } from '@libp2p/websockets'
import { webTransport } from '@libp2p/webtransport'
import { circuitRelayTransport } from '@libp2p/circuit-relay-v2'
import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { identify } from '@libp2p/identify'
// libp2p v3 migration: the chainsafe gossipsub package was renamed to
// `@libp2p/gossipsub`. package.json already pins the new name; the import
// here was still pointing at the legacy chainsafe-scoped path, which is
// no longer installed.
import { gossipsub } from '@libp2p/gossipsub'
import { bootstrap } from '@libp2p/bootstrap'
import { pubsubPeerDiscovery } from '@libp2p/pubsub-peer-discovery'

const SYNC_TOPIC = '/peerborne/integration-test/sync'
const DISCOVERY_TOPIC = 'swarmdb._peer-discovery._p2p._pubsub'

// UI elements
const statusEl = document.getElementById('status')
const peerIdEl = document.getElementById('peer-id')
const peersEl = document.getElementById('peers')
const connectionTypesEl = document.getElementById('connection-types')
const messagesEl = document.getElementById('messages')
const messageInput = document.getElementById('message-input')
const sendBtn = document.getElementById('send-btn')

// State
window.__messages = []
window.__peers = new Set()
window.__status = 'initializing'
window.__connectionTypes = new Map()

function updateStatus(status) {
  window.__status = status
  statusEl.textContent = status
  console.log('STATUS_CHANGE:', status)
}

function updatePeersUI() {
  const peers = Array.from(window.__peers)
  peersEl.textContent = ''
  const label = document.createElement('strong')
  label.textContent = `Connected Peers (${peers.length}):`
  peersEl.appendChild(label)
  for (const p of peers) {
    const div = document.createElement('div')
    div.className = 'peer'
    div.textContent = p
    peersEl.appendChild(div)
  }
}

function updateConnectionTypesUI() {
  const types = Array.from(window.__connectionTypes.entries())
  connectionTypesEl.textContent = ''
  const label = document.createElement('strong')
  label.textContent = 'Connection Types:'
  connectionTypesEl.appendChild(label)
  for (const [peer, type] of types) {
    const div = document.createElement('div')
    div.textContent = `${peer}: ${type}`
    connectionTypesEl.appendChild(div)
  }
}

function addMessageToUI(msg) {
  const div = document.createElement('div')
  div.className = 'message'
  div.textContent = `[${new Date(msg.timestamp).toLocaleTimeString()}] ${msg.from}: ${msg.text}`
  div.dataset.from = msg.from
  div.dataset.text = msg.text
  messagesEl.appendChild(div)
}

async function getRelayMultiaddr() {
  // Check window global first
  if (window.__RELAY_MULTIADDR) {
    return window.__RELAY_MULTIADDR
  }

  // Check meta tag
  const meta = document.querySelector('meta[name="relay-multiaddr"]')
  if (meta && meta.content) {
    return meta.content
  }

  // Fetch from config.json
  try {
    const resp = await fetch('/config.json')
    const config = await resp.json()
    if (config.relayMultiaddr) {
      return config.relayMultiaddr
    }
  } catch (e) {
    console.warn('CONFIG_FETCH_FAILED:', e.message)
  }

  return null
}

async function init() {
  const relayAddr = await getRelayMultiaddr()
  if (!relayAddr) {
    updateStatus('error-no-relay')
    console.error('INIT_ERROR: No relay multiaddr configured')
    return
  }

  console.log('RELAY_ADDR:', relayAddr)

  const peerDiscovery = [
    pubsubPeerDiscovery({
      interval: 1000,
      topics: [DISCOVERY_TOPIC],
    }),
  ]

  peerDiscovery.push(bootstrap({ list: [relayAddr] }))

  const node = await createLibp2p({
    addresses: {
      listen: ['/p2p-circuit', '/webrtc'],
    },
    transports: [
      webSockets(),
      webRTC(),
      webTransport(),
      circuitRelayTransport(),
    ],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    peerDiscovery,
    services: {
      identify: identify(),
      pubsub: gossipsub({
        allowPublishToZeroTopicPeers: true,
        emitSelf: false,
        canRelayMessage: true,
        floodPublish: true,
        globalSignaturePolicy: 'StrictSign',
      }),
    },
    connectionGater: {
      denyDialMultiaddr: async () => false,
    },
  })

  window.__libp2p = node

  // Display our peer ID
  const myPeerId = node.peerId.toString()
  peerIdEl.textContent = myPeerId
  console.log('PEER_ID:', myPeerId)

  // Listen for peer events
  node.addEventListener('peer:connect', (evt) => {
    const peerId = evt.detail.toString()
    window.__peers.add(peerId)
    updatePeersUI()
    console.log('PEER_CONNECTED:', peerId)

    if (window.__peers.size === 1) {
      updateStatus('peer-discovered')
    }
  })

  node.addEventListener('peer:disconnect', (evt) => {
    const peerId = evt.detail.toString()
    window.__peers.delete(peerId)
    window.__connectionTypes.delete(peerId)
    updatePeersUI()
    updateConnectionTypesUI()
    console.log('PEER_DISCONNECTED:', peerId)
  })

  node.addEventListener('connection:open', (evt) => {
    const conn = evt.detail
    const remotePeer = conn.remotePeer.toString()
    const transport = conn.remoteAddr.toString()
    window.__connectionTypes.set(remotePeer, transport)
    updateConnectionTypesUI()
    console.log('CONNECTION_OPEN:', remotePeer, transport)
  })

  // Subscribe to sync topic
  node.services.pubsub.subscribe(SYNC_TOPIC)
  console.log('SUBSCRIBED:', SYNC_TOPIC)

  node.services.pubsub.addEventListener('message', (evt) => {
    if (evt.detail.topic !== SYNC_TOPIC) return

    try {
      const data = new TextDecoder().decode(evt.detail.data)
      const msg = JSON.parse(data)
      console.log('PUBSUB_MESSAGE:', evt.detail.topic, JSON.stringify(msg))

      window.__messages.push(msg)
      addMessageToUI(msg)

      updateStatus('syncing')
    } catch (e) {
      console.error('MESSAGE_PARSE_ERROR:', e.message)
    }
  })

  // Enable send button
  sendBtn.disabled = false
  sendBtn.addEventListener('click', () => {
    const text = messageInput.value.trim()
    if (!text) return

    const msg = {
      from: myPeerId,
      text,
      timestamp: Date.now(),
    }

    const data = new TextEncoder().encode(JSON.stringify(msg))
    try {
      const result = node.services.pubsub.publish(SYNC_TOPIC, data)
      if (result && typeof result.then === 'function') {
        result.then((r) => console.log('PUBLISH_RESULT:', JSON.stringify(r)))
          .catch((e) => console.error('PUBLISH_ERROR:', e.message))
      }
    } catch (e) {
      console.error('PUBLISH_SYNC_ERROR:', e.message)
    }
    // Log gossipsub topic peers
    try {
      const topicPeers = node.services.pubsub.getSubscribers(SYNC_TOPIC)
      console.log('TOPIC_PEERS:', SYNC_TOPIC, topicPeers.map(p => p.toString()))
    } catch(e) {
      console.error('GET_SUBSCRIBERS_ERROR:', e.message)
    }
    console.log('MESSAGE_SENT:', JSON.stringify(msg))

    // Add to our own message list and UI
    window.__messages.push(msg)
    addMessageToUI(msg)

    messageInput.value = ''
  })

  // Also allow sending with Enter key
  messageInput.addEventListener('keydown', (evt) => {
    if (evt.key === 'Enter') {
      sendBtn.click()
    }
  })

  updateStatus('connected-to-relay')
  console.log('INIT_COMPLETE')
}

init().catch((err) => {
  console.error('INIT_ERROR:', err)
  updateStatus('error')
})
