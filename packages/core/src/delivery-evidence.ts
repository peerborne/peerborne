import {
  type CRDTChangeNode,
  crdtChangeNodeDeferred,
} from './crdt-change-node.js';
import { MAX_CHANGE_TREE_NODES } from './change-tree-walk.js';

/**
 * A change's frame was published, but GossipSub sent it to no peer known to
 * serve a document member: no topic peer at all, as by default offline, or
 * only peers that never proved membership, such as a relay subscribed to the
 * topic. The change stays committed locally, as for any other delivery
 * failure.
 */
export class NoDeliveryPeersError extends Error {
  constructor() {
    super('The frame reached no peer known to serve a document member');
    this.name = 'NoDeliveryPeersError';
  }
}

/**
 * The recipients of a GossipSub `publish()` result other than this node, or
 * `undefined` when the result lists none, which proves nothing either way.
 */
export function publicationRecipients(
  result: unknown,
  localPeerId: string | undefined,
): string[] | undefined {
  if (typeof result !== 'object' || result === null) return undefined;
  const { recipients } = result as { recipients?: unknown };
  if (!Array.isArray(recipients)) return undefined;
  return recipients
    .map((peer) => String(peer))
    .filter((peer) => peer !== localPeerId);
}

export const MEMBER_PEER_TTL_MS = 60 * 60 * 1000;
export const MAX_MEMBER_PEERS = 256;

/**
 * PeerIds that recently proved they serve a document member: each published
 * a sync request signed by a member's key that names it as the requester. A
 * writer-signed frame is no proof, because any peer can republish one under
 * its own PeerId, so a relay that only forwards or republishes frames is
 * never one.
 */
export class MemberPeers {
  private readonly seen = new Map<string, number>();

  constructor(private readonly now: () => number = Date.now) {}

  note(peer: string): void {
    if (peer === '') return;
    this.seen.delete(peer);
    this.seen.set(peer, this.now());
    if (this.seen.size > MAX_MEMBER_PEERS)
      this.seen.delete(this.seen.keys().next().value!);
  }

  includesAny(peers: readonly string[]): boolean {
    const now = this.now();
    return peers.some((peer) => {
      const seen = this.seen.get(peer);
      return seen !== undefined && now - seen < MEMBER_PEER_TTL_MS;
    });
  }
}

/**
 * Whether a sync message's head, snapshot, or inline change tree names
 * `changeId`, so that its author holds that change. The walk visits at most
 * `MAX_CHANGE_TREE_NODES` nodes.
 */
export function syncMessageReferences<ChangesType>(
  message: {
    readonly changeId?: string;
    readonly changes?: CRDTChangeNode<ChangesType>;
    readonly snapshot?: { readonly lastChangeNodeCID?: string };
  },
  changeId: string,
): boolean {
  if (
    message.changeId === changeId ||
    message.snapshot?.lastChangeNodeCID === changeId
  )
    return true;
  const pending = message.changes === undefined ? [] : [message.changes];
  for (
    let visited = 0;
    pending.length > 0 && visited < MAX_CHANGE_TREE_NODES;
    visited++
  ) {
    const children = pending.pop()!.children;
    if (children === undefined || children === crdtChangeNodeDeferred) continue;
    for (const [cid, child] of Object.entries(children)) {
      if (cid === changeId) return true;
      pending.push(child);
    }
  }
  return false;
}
