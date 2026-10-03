// @ts-check
import { createLibp2p } from 'libp2p'
import { autoNAT } from '@libp2p/autonat'
import { identify } from '@libp2p/identify'
import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { gossipsub } from '@libp2p/gossipsub'
import { webSockets } from '@libp2p/websockets'
import { tcp } from '@libp2p/tcp'
import { circuitRelayServer } from '@libp2p/circuit-relay-v2'

const PUBSUB_PEER_DISCOVERY = 'peerborne._peer-discovery._p2p._pubsub'

async function main() {
  // enable('*')
  const libp2p = await createLibp2p({
    addresses: {
      listen: [
        '/ip4/0.0.0.0/tcp/9001/ws',
        '/ip4/0.0.0.0/tcp/9002',
        // IPv6 listeners omitted by default — on platforms where :: is
        // dual-stack, binding both on the same port causes EADDRINUSE.
        // Add '/ip6/::/tcp/9001/ws' and '/ip6/::/tcp/9002' if needed.
      ],
    },
    transports: [
      webSockets(),
      tcp(),
    ],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    connectionGater: {
      // Allow private addresses for local testing
      denyDialMultiaddr: async () => false,
    },
    services: {
      identify: identify(),
      autoNat: autoNAT(),
      relay: circuitRelayServer(),
      pubsub: gossipsub(),
    },
  })

  libp2p.services.pubsub.subscribe(PUBSUB_PEER_DISCOVERY)

  console.log('PeerID: ', libp2p.peerId.toString())
  console.log('Multiaddrs: ', libp2p.getMultiaddrs())
}

main()
