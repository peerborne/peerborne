import type { CircuitRelayService } from '@libp2p/circuit-relay-v2'
import type { Libp2p } from '@libp2p/interface'

/**
 * Circuit Relay v2 keys reservations by peer and frees them only when their
 * TTL expires. Expire a reservation as soon as its holder has no connection
 * left to accept relayed streams on, so closed tabs and reloads return their
 * slot to new clients.
 */
export function releaseReservationsOnDisconnect(
  libp2p: Libp2p<{ relay: CircuitRelayService }>,
): void {
  libp2p.addEventListener('peer:disconnect', (event) => {
    if (libp2p.getConnections(event.detail).length > 0) return
    // Fire the reservation's own expiry signal so the store's listener removes
    // it. Deleting the entry directly would leave that listener armed to
    // remove a newer reservation from the same peer at the old expiry.
    libp2p.services.relay.reservations.get(event.detail)?.signal.reset(0)
  })
}
