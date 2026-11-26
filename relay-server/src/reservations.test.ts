import { createLibp2p } from 'libp2p'
import { tcp } from '@libp2p/tcp'
import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { identify } from '@libp2p/identify'
import {
  RELAY_V2_HOP_CODEC,
  circuitRelayServer,
  circuitRelayTransport,
} from '@libp2p/circuit-relay-v2'
import { generateKeyPair } from '@libp2p/crypto/keys'
import type { Libp2p, PrivateKey } from '@libp2p/interface'
import { circuitRelayServerOptions, loadConfig } from './config.js'
import { releaseReservationsOnDisconnect } from './reservations.js'

async function waitFor(condition: () => boolean, description: string): Promise<void> {
  const deadline = Date.now() + 5000
  while (!condition()) {
    if (Date.now() >= deadline) throw new Error(`Timed out waiting for ${description}`)
    await new Promise(resolve => setTimeout(resolve, 20))
  }
}

async function createRelay(ttlMs: number) {
  const relay = await createLibp2p({
    addresses: { listen: ['/ip4/127.0.0.1/tcp/0'] },
    transports: [tcp()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    services: {
      identify: identify(),
      relay: circuitRelayServer(circuitRelayServerOptions(loadConfig({
        RELAY_MAX_RESERVATIONS: '1',
        RELAY_RESERVATION_TTL_MS: String(ttlMs),
      }))),
    },
  })
  releaseReservationsOnDisconnect(relay)
  return relay
}

function createClient(relayAddress: string, privateKey?: PrivateKey) {
  return createLibp2p({
    privateKey,
    addresses: { listen: [`${relayAddress}/p2p-circuit`] },
    transports: [tcp(), circuitRelayTransport()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    services: { identify: identify() },
  })
}

const sleepUntil = (time: number) =>
  new Promise(resolve => setTimeout(resolve, Math.max(0, time - Date.now())))

// A length-prefixed HopMessage { type: RESERVE }, as a client sends to reserve
// or refresh a slot.
const reserveRequest = Uint8Array.of(2, 0x08, 0)

async function requestReservation(
  client: Libp2p,
  relayAddress: Parameters<Libp2p['dialProtocol']>[0],
): Promise<void> {
  const stream = await client.dialProtocol(relayAddress, RELAY_V2_HOP_CODEC)
  stream.send(reserveRequest)
  for await (const _reply of stream) {
    // Drain the STATUS reply until the relay closes its side.
  }
  await stream.close()
}

describe('Circuit Relay reservations', () => {
  it('keeps a connected peer reservation through repeated refreshes', async () => {
    const ttlMs = 3000
    const relay = await createRelay(ttlMs)
    const reservations = relay.services.relay.reservations
    const client = await createLibp2p({
      transports: [tcp()],
      connectionEncrypters: [noise()],
      streamMuxers: [yamux()],
      services: { identify: identify() },
    })
    try {
      const relayAddress = relay.getMultiaddrs()[0]
      await requestReservation(client, relayAddress)
      expect(reservations.has(client.peerId)).toBe(true)
      await sleepUntil(Date.now() + ttlMs / 6)
      await requestReservation(client, relayAddress)
      const firstRefreshed = Date.now()
      await sleepUntil(firstRefreshed + ttlMs / 3)
      const secondRequested = Date.now()
      await requestReservation(client, relayAddress)

      // Wait past the first refresh's expiry but not the second's.
      await sleepUntil((firstRefreshed + secondRequested) / 2 + ttlMs)
      expect(reservations.has(client.peerId)).toBe(true)
    } finally {
      await client.stop()
      await relay.stop()
    }
  }, 20_000)

  it('returns a disconnected client slot to the next client before the TTL', async () => {
    const relay = await createRelay(600_000)
    const reservations = relay.services.relay.reservations
    try {
      const address = relay.getMultiaddrs()[0].toString()
      const first = await createClient(address)
      await waitFor(() => reservations.has(first.peerId), 'the first reservation')
      await first.stop()
      await waitFor(() => reservations.size === 0, 'the released reservation')

      const second = await createClient(address)
      try {
        await waitFor(() => reservations.has(second.peerId), 'the second reservation')
      } finally {
        await second.stop()
      }
    } finally {
      await relay.stop()
    }
  }, 20_000)

  it('keeps a reconnected peer reservation past the released reservation expiry', async () => {
    const ttlMs = 2000
    const relay = await createRelay(ttlMs)
    const reservations = relay.services.relay.reservations
    try {
      const address = relay.getMultiaddrs()[0].toString()
      const privateKey = await generateKeyPair('Ed25519')
      const first = await createClient(address, privateKey)
      await waitFor(() => reservations.has(first.peerId), 'the first reservation')
      const reservedBy = Date.now()
      await first.stop()
      await waitFor(() => reservations.size === 0, 'the released reservation')

      // Reconnect late enough that the new reservation outlives the check.
      await sleepUntil(reservedBy + ttlMs / 2)
      const reconnected = await createClient(address, privateKey)
      try {
        await waitFor(() => reservations.has(reconnected.peerId), 'the renewed reservation')
        await sleepUntil(reservedBy + ttlMs + 300)
        expect(reservations.has(reconnected.peerId)).toBe(true)
      } finally {
        await reconnected.stop()
      }
    } finally {
      await relay.stop()
    }
  }, 20_000)
})
