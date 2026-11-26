import {
  type CRDTChangeNode,
  crdtChangeNodeDeferred,
  crdtDocumentChangeNode,
} from './crdt-change-node.js';
import type { CRDTSyncMessage } from './crdt-sync-message.js';
import { MAX_SHARED_PROTOCOL_REQUEST_BYTES } from './utils.js';

/**
 * Largest serialized sync message one GossipSub document frame carries.
 *
 * `@libp2p/gossipsub` length-prefixes every outbound RPC with
 * `it-length-prefixed`'s fixed 4 MiB limit, and the receiver applies the same
 * default. A longer RPC is not sent: `publish()` resolves with no recipients.
 * The remaining 512 KiB covers encryption, the GossipSub envelope and topic,
 * and control messages piggybacked on the same RPC.
 */
export const MAX_GOSSIP_SYNC_MESSAGE_BYTES = 3.5 * 1024 * 1024;

/**
 * Largest serialized sync message sent directly over `syncFrameV1` when it does
 * not fit a GossipSub frame. The margin covers the path header and encryption.
 */
export const MAX_DIRECT_SYNC_MESSAGE_BYTES =
  MAX_SHARED_PROTOCOL_REQUEST_BYTES - 64 * 1024;

/** A sync message cannot fit one frame even with every change sent by CID. */
export class GossipFrameLimitError extends RangeError {
  constructor(limit = MAX_GOSSIP_SYNC_MESSAGE_BYTES) {
    super(`Sync message exceeds the ${limit}-byte frame limit`);
    this.name = 'GossipFrameLimitError';
  }
}

export interface BoundedSyncMessage<ChangesType> {
  readonly message: CRDTSyncMessage<ChangesType>;
  readonly bytes: Uint8Array;
  /** Distinct document changes sent by CID only. */
  readonly deferredChanges: number;
}

type Node<ChangesType> = CRDTChangeNode<ChangesType>;

function payloadDepths<ChangesType>(
  rootId: string | undefined,
  root: Node<ChangesType>,
): Map<string | undefined, number> {
  const depths = new Map<string | undefined, number>();
  const pending: [string | undefined, Node<ChangesType>, number][] = [
    [rootId, root, 0],
  ];
  while (pending.length > 0) {
    const [id, node, depth] = pending.pop()!;
    if (node.kind === crdtDocumentChangeNode && node.change !== undefined) {
      const known = depths.get(id);
      if (known === undefined || depth < known) depths.set(id, depth);
    }
    const children = node.children;
    if (children === undefined || children === crdtChangeNodeDeferred) continue;
    for (const [childId, child] of Object.entries(children)) {
      pending.push([childId, child, depth + 1]);
    }
  }
  return depths;
}

/**
 * Copy a change tree, sending each document change whose shallowest inline
 * occurrence is deeper than `keepDepth` by CID only. Every occurrence of a CID
 * is treated alike, so aliases stay consistent for receivers.
 */
function deferDeepPayloads<ChangesType>(
  rootId: string | undefined,
  root: Node<ChangesType>,
  depths: ReadonlyMap<string | undefined, number>,
  keepDepth: number,
): Node<ChangesType> {
  const copy = (id: string | undefined, node: Node<ChangesType>) => {
    const result: Node<ChangesType> = { kind: node.kind };
    const depth = depths.get(id);
    if (
      node.change !== undefined &&
      (depth === undefined || depth <= keepDepth)
    ) {
      result.change = node.change;
    }
    return result;
  };
  const rootCopy = copy(rootId, root);
  const pending: [Node<ChangesType>, Node<ChangesType>][] = [[root, rootCopy]];
  while (pending.length > 0) {
    const [source, target] = pending.pop()!;
    const children = source.children;
    if (children === undefined) continue;
    if (children === crdtChangeNodeDeferred) {
      target.children = crdtChangeNodeDeferred;
      continue;
    }
    const copied: Record<string, Node<ChangesType>> = Object.create(null);
    for (const [childId, child] of Object.entries(children)) {
      const childCopy = copy(childId, child);
      copied[childId] = childCopy;
      pending.push([child, childCopy]);
    }
    target.children = copied;
  }
  return rootCopy;
}

/**
 * Fit a signed sync message into one GossipSub frame. A message that fits is
 * returned unchanged. Otherwise the oldest document-change payloads, and as a
 * last resort the root payload, are replaced by CID-only nodes that receivers
 * fetch from the blockstore. Tree structure, ACL payloads and the snapshot are
 * kept. Returns `undefined` when even the fully deferred tree is too large.
 */
export async function boundSyncMessage<ChangesType>(
  message: CRDTSyncMessage<ChangesType>,
  maxBytes: number,
  serialize: (message: CRDTSyncMessage<ChangesType>) => Uint8Array,
  sign: (message: CRDTSyncMessage<ChangesType>) => Promise<string>,
): Promise<BoundedSyncMessage<ChangesType> | undefined> {
  const bytes = serialize(message);
  if (bytes.byteLength <= maxBytes) {
    return { message, bytes, deferredChanges: 0 };
  }
  const root = message.changes;
  if (root === undefined) return undefined;

  const depths = payloadDepths(message.changeId, root);
  let deepest = -1;
  for (const depth of depths.values()) deepest = Math.max(deepest, depth);
  const signatureAllowance = (message.signature?.length ?? 0) + 64;
  const candidate = (keepDepth: number): CRDTSyncMessage<ChangesType> => ({
    ...message,
    signature: undefined,
    changes: deferDeepPayloads(message.changeId, root, depths, keepDepth),
  });
  const fits = (keepDepth: number) =>
    serialize(candidate(keepDepth)).byteLength + signatureAllowance <= maxBytes;

  // keepDepth -1 defers every document payload, including the root's.
  let low = -1;
  let high = deepest - 1;
  if (!fits(low)) return undefined;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (fits(middle)) low = middle;
    else high = middle - 1;
  }

  for (let keepDepth = low; keepDepth >= -1; keepDepth--) {
    const bounded = candidate(keepDepth);
    bounded.signature = await sign(bounded);
    const boundedBytes = serialize(bounded);
    if (boundedBytes.byteLength > maxBytes) continue;
    let deferredChanges = 0;
    for (const depth of depths.values())
      if (depth > keepDepth) deferredChanges++;
    return { message: bounded, bytes: boundedBytes, deferredChanges };
  }
  return undefined;
}
