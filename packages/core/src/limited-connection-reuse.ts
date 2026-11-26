import { isPeerId } from '@libp2p/interface';
import type { Connection, Libp2p } from '@libp2p/interface';
import { isMultiaddr } from '@multiformats/multiaddr';
import type { Multiaddr } from '@multiformats/multiaddr';

type ReusableLibp2p = Pick<
  Libp2p,
  'dial' | 'dialProtocol' | 'getConnections' | 'isDialable' | 'peerStore'
>;
type DialTarget = Parameters<Libp2p['dialProtocol']>[0];

interface Target {
  readonly connections: readonly Connection[];
  readonly addresses: () => Promise<readonly Multiaddr[]>;
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

function isRelayOnly(address: Multiaddr): boolean {
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

async function canUpgrade(
  libp2p: ReusableLibp2p,
  target: Target,
): Promise<boolean> {
  try {
    const upgrades = (await target.addresses()).filter(
      (address) => !isRelayOnly(address),
    );
    return upgrades.length > 0 && (await libp2p.isDialable(upgrades));
  } catch {
    return false;
  }
}

/**
 * Open streams that accept limited connections on an open relayed connection.
 *
 * libp2p reuses only connections without relay limits, so each
 * `dialProtocol(peer, protocols, { runOnLimitedConnection: true })` to a peer
 * with only a relayed connection dials the peer again (libp2p/js-libp2p#3698).
 * A direct or WebRTC address that fails is followed by another circuit, which
 * is dropped as a duplicate. The remote rate-limits inbound connections per
 * host and counts every relayed connection against the relay's host, so a
 * burst of Bitswap messages gets refused, and each stream can wait for a
 * failing upgrade dial.
 *
 * Such streams now open on the open relayed connection at once. When the peer
 * has an address this node can dial directly, including WebRTC, one libp2p
 * dial per relayed connection runs in the background to upgrade it, and later
 * streams use the unlimited connection if it succeeds. Streams that need an
 * unlimited connection and forced dials always go to libp2p.
 */
export function reuseLimitedConnections(libp2p: ReusableLibp2p): void {
  const dialProtocol = libp2p.dialProtocol.bind(libp2p);
  const upgrading = new WeakSet<Connection>();
  const upgrade = async (
    connection: Connection,
    peer: DialTarget,
    target: Target,
  ): Promise<void> => {
    if (upgrading.has(connection) || !(await canUpgrade(libp2p, target))) {
      return;
    }
    if (upgrading.has(connection) || connection.status !== 'open') return;
    upgrading.add(connection);
    await libp2p.dial(peer).catch(() => undefined);
  };
  libp2p.dialProtocol = async (peer, protocols, options = {}) => {
    const target =
      options.runOnLimitedConnection === true && options.force !== true
        ? dialTarget(libp2p, peer)
        : undefined;
    const connection = target && openLimitedConnection(target.connections);
    if (target === undefined || connection === undefined) {
      return dialProtocol(peer, protocols, options);
    }
    void upgrade(connection, peer, target);
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
