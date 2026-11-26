import { isPeerId } from '@libp2p/interface';
import type { Connection, Libp2p } from '@libp2p/interface';
import { isMultiaddr } from '@multiformats/multiaddr';

type ReusableLibp2p = Pick<
  Libp2p,
  'dialProtocol' | 'getConnections' | 'peerStore'
>;
type DialTarget = Parameters<Libp2p['dialProtocol']>[0];

interface Address {
  getComponents(): ReadonlyArray<{
    readonly name: string;
    readonly value?: string;
  }>;
}

interface Target {
  readonly connections: readonly Connection[];
  readonly addresses: () => Promise<readonly Address[]>;
}

function dialTarget(
  libp2p: ReusableLibp2p,
  target: DialTarget,
): Target | undefined {
  if (isPeerId(target)) {
    return {
      connections: libp2p.getConnections(target),
      addresses: async () =>
        (await libp2p.peerStore.get(target)).addresses.map(
          ({ multiaddr }) => multiaddr,
        ),
    };
  }
  if (!isMultiaddr(target)) return undefined;
  const last = target.getComponents().at(-1);
  if (last?.name !== 'p2p' || last.value === undefined) return undefined;
  return {
    connections: libp2p
      .getConnections()
      .filter(({ remotePeer }) => remotePeer.toString() === last.value),
    addresses: async () => [target],
  };
}

function isRelayOnly(address: Address): boolean {
  const names = address.getComponents().map(({ name }) => name);
  return names.includes('p2p-circuit') && !names.includes('webrtc');
}

function openLimitedConnection(
  connections: readonly Connection[],
): Connection | undefined {
  const open = connections.filter(({ status }) => status === 'open');
  if (open.some(({ limits }) => limits == null)) return undefined;
  return open.sort((a, b) => a.timeline.open - b.timeline.open)[0];
}

async function hasUpgradeAddress(target: Target): Promise<boolean> {
  try {
    return (await target.addresses()).some((address) => !isRelayOnly(address));
  } catch {
    return false;
  }
}

/**
 * Open streams that accept limited connections on an open relayed connection.
 *
 * libp2p reuses only connections without relay limits, so each
 * `dialProtocol(peer, protocols, { runOnLimitedConnection: true })` to a peer
 * reachable only through a relay dials another circuit and then drops it as a
 * duplicate (libp2p/js-libp2p#3698). The remote rate-limits inbound
 * connections per host, and every relayed connection comes from the relay's
 * host, so a burst of Bitswap messages gets refused and the stream fails while
 * the first circuit is still open.
 *
 * A target with an address that could give a better connection still gets the
 * libp2p dial once per relayed connection, and falls back to that connection
 * if the dial fails.
 */
export function reuseLimitedConnections(libp2p: ReusableLibp2p): void {
  const dialProtocol = libp2p.dialProtocol.bind(libp2p);
  const failedUpgrades = new WeakSet<Connection>();
  libp2p.dialProtocol = async (peer, protocols, options = {}) => {
    const target =
      options.runOnLimitedConnection === true && options.force !== true
        ? dialTarget(libp2p, peer)
        : undefined;
    const connection = target && openLimitedConnection(target.connections);
    if (target === undefined || connection === undefined) {
      return dialProtocol(peer, protocols, options);
    }
    if (!failedUpgrades.has(connection) && (await hasUpgradeAddress(target))) {
      try {
        return await dialProtocol(peer, protocols, options);
      } catch (error) {
        if (options.signal?.aborted === true || connection.status !== 'open') {
          throw error;
        }
        failedUpgrades.add(connection);
        return connection.newStream(protocols, options);
      }
    }
    try {
      return await connection.newStream(protocols, options);
    } catch (error) {
      if (options.signal?.aborted === true || connection.status === 'open') {
        throw error;
      }
      return dialProtocol(peer, protocols, options);
    }
  };
}
