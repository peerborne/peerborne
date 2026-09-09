import {
  CRDTChangeNode,
  CRDTChangeNodeKind,
  crdtChangeNodeDeferred,
} from './crdt-change-node.js';
import { copyUnsharedUint8Array } from './utils.js';

/**
 * Maximum number of recent tips to track for Merkle-CRDT cross-linking
 * (paper §VI.B.e). When a new change is published, up to `MAX_CROSS_LINKS`
 * cross-links to other recent tips are attached alongside the primary parent
 * link. This bounds per-message overhead while still giving peers with
 * partial DAG views additional anchor points to discover and fetch missing
 * blocks from. Cross-links are emitted as deferred children (no embedded
 * payload), so each adds only one CID key plus a small `{ kind }` tag in
 * the `children` map -- bounded and small per cross-link.
 *
 * `MAX_CROSS_LINKS` is chosen as 3 (so up to 3 cross-links plus the primary
 * parent per outgoing message):
 *   - small enough to keep gossip messages compact;
 *   - large enough that bursty concurrent writes from 2-3 peers can be
 *     cross-linked together within a few messages.
 *
 * `MAX_RECENT_TIPS` is one larger than `MAX_CROSS_LINKS` so the immediate
 * primary parent and up to `MAX_CROSS_LINKS` additional candidates can all
 * be retained at once.
 */
export const MAX_RECENT_TIPS = 4;
export const MAX_CROSS_LINKS = 3;

/**
 * A recently-known DAG tip used by `selectCrossLinks` / `trackTipInList`.
 * `cid` is a Helia CID string; `kind` is preserved so receivers can route
 * a deferred-fetch result through the correct merge path (document /
 * reader-ACL / writer-ACL).
 */
export type RecentTip = {
  cid: string;
  kind: CRDTChangeNodeKind;
};

/**
 * Pure helper: select up to `maxCrossLinks` cross-link tips from
 * `recentTips`, excluding the primary parent and the new CID itself.
 *
 * Iterates newest -> oldest so the most recent tips are preferred when
 * the cap is reached (more likely to be reachable on the peer side, since
 * gossip ordering tends to deliver recent messages first to most peers).
 *
 * Returns a new array; does not mutate `recentTips`.
 */
export function selectCrossLinks<Tip extends { cid: string }>(
  recentTips: ReadonlyArray<Tip>,
  primaryParentId: string | undefined,
  newCid: string,
  maxCrossLinks: number = MAX_CROSS_LINKS,
): Tip[] {
  const out: Tip[] = [];
  const seen = new Set<string>();
  for (let i = recentTips.length - 1; i >= 0; i--) {
    if (out.length >= maxCrossLinks) break;
    const tip = recentTips[i]!;
    if (tip.cid === primaryParentId) continue;
    if (tip.cid === newCid) continue;
    if (seen.has(tip.cid)) continue;
    seen.add(tip.cid);
    out.push(tip);
  }
  return out;
}

/**
 * A flattened entry produced by walking a remote sync tree: a CID, the kind
 * of node (document/reader/writer), and the inline `change` payload if the
 * remote included one. An `undefined` payload means the entry is a deferred
 * leaf (cross-link or other deferred reference) and the receiver must fetch
 * the block from the blockstore by CID.
 */
export type MergedSyncEntry<ChangesType> = [
  string,
  CRDTChangeNodeKind,
  ChangesType | undefined,
];

const MAX_REMOTE_SYNC_PAYLOAD_COMPARISON_ITEMS = 16 * 1024 * 1024;
const intrinsicArrayBufferIsView = ArrayBuffer.isView;

type ComparableByteView =
  | { readonly kind: 'not-view' }
  | { readonly kind: 'invalid-view' }
  | { readonly kind: 'bytes'; readonly bytes: Uint8Array };

function snapshotComparableByteView(value: object): ComparableByteView {
  if (!Reflect.apply(intrinsicArrayBufferIsView, ArrayBuffer, [value])) {
    return { kind: 'not-view' };
  }
  try {
    return {
      kind: 'bytes',
      bytes: copyUnsharedUint8Array(
        value,
        0,
        MAX_REMOTE_SYNC_PAYLOAD_COMPARISON_ITEMS,
        'remote sync tree change payload',
      ),
    };
  } catch {
    return { kind: 'invalid-view' };
  }
}

type RemoteNodeDescription<ChangesType> = {
  readonly node: CRDTChangeNode<ChangesType>;
  readonly kind: CRDTChangeNodeKind;
  readonly keyID: string | undefined;
  readonly hasChange: boolean;
  readonly childrenMode: 0 | 1 | 2;
  readonly childIds: readonly string[];
  readonly sparseReference: boolean;
};

function describeRemoteNode<ChangesType>(
  node: CRDTChangeNode<ChangesType>,
): RemoteNodeDescription<ChangesType> {
  if (node === null || typeof node !== 'object' || Array.isArray(node)) {
    throw new TypeError('remote sync tree node must be an object');
  }
  let childrenMode: 0 | 1 | 2 = 0;
  let childIds: string[] = [];
  if (node.children === crdtChangeNodeDeferred) {
    childrenMode = 1;
  } else if (node.children !== undefined) {
    if (
      node.children === null ||
      typeof node.children !== 'object' ||
      Array.isArray(node.children)
    ) {
      throw new TypeError(
        'remote sync tree children must be an object, false, or undefined',
      );
    }
    childrenMode = 2;
    childIds = Object.keys(node.children).sort();
  }
  return {
    node,
    kind: node.kind,
    keyID: node.keyID,
    hasChange: node.change !== undefined,
    childrenMode,
    childIds,
    sparseReference: node.change === undefined && node.children === undefined,
  };
}

function consumeComparisonBudget(
  budget: { remaining: number },
  amount = 1,
): void {
  budget.remaining -= amount;
  if (budget.remaining < 0) {
    throw new RangeError(
      `remote sync tree exceeds ${MAX_REMOTE_SYNC_PAYLOAD_COMPARISON_ITEMS} payload comparison items`,
    );
  }
}

function sameChangePayload(
  first: unknown,
  second: unknown,
  budget: { remaining: number },
): boolean {
  const pending: Array<readonly [unknown, unknown]> = [[first, second]];
  const seen = new WeakMap<object, WeakSet<object>>();

  while (pending.length > 0) {
    const [left, right] = pending.pop()!;
    consumeComparisonBudget(budget);
    if (
      left === null ||
      right === null ||
      typeof left !== 'object' ||
      typeof right !== 'object'
    ) {
      if (Object.is(left, right)) continue;
      return false;
    }

    let rightValues = seen.get(left);
    if (rightValues?.has(right)) continue;
    if (rightValues === undefined) {
      rightValues = new WeakSet<object>();
      seen.set(left, rightValues);
    }
    rightValues.add(right);

    const leftByteView = snapshotComparableByteView(left);
    const rightByteView = snapshotComparableByteView(right);
    if (
      leftByteView.kind === 'invalid-view' ||
      rightByteView.kind === 'invalid-view'
    ) {
      return false;
    }
    if (
      leftByteView.kind === 'bytes' ||
      rightByteView.kind === 'bytes'
    ) {
      if (
        leftByteView.kind !== 'bytes' ||
        rightByteView.kind !== 'bytes'
      ) {
        return false;
      }
      const leftBytes = leftByteView.bytes;
      const rightBytes = rightByteView.bytes;
      if (leftBytes.byteLength !== rightBytes.byteLength) return false;
      consumeComparisonBudget(budget, leftBytes.byteLength);
      for (let index = 0; index < leftBytes.byteLength; index++) {
        if (leftBytes[index] !== rightBytes[index]) return false;
      }
      continue;
    }

    if (Array.isArray(left) || Array.isArray(right)) {
      if (!Array.isArray(left) || !Array.isArray(right)) return false;
      if (left.length !== right.length) return false;
      consumeComparisonBudget(budget, left.length);
      for (let index = 0; index < left.length; index++) {
        pending.push([left[index], right[index]]);
      }
      continue;
    }

    const leftPrototype = Object.getPrototypeOf(left);
    const rightPrototype = Object.getPrototypeOf(right);
    const leftIsPlain =
      leftPrototype === Object.prototype || leftPrototype === null;
    const rightIsPlain =
      rightPrototype === Object.prototype || rightPrototype === null;
    if (!leftIsPlain || !rightIsPlain) return false;
    const leftKeys = Object.keys(left).sort();
    const rightKeys = Object.keys(right).sort();
    if (
      leftKeys.length !== rightKeys.length ||
      leftKeys.some((key, index) => key !== rightKeys[index])
    ) {
      return false;
    }
    consumeComparisonBudget(budget, leftKeys.length);
    const leftRecord = left as Record<string, unknown>;
    const rightRecord = right as Record<string, unknown>;
    for (const key of leftKeys) {
      pending.push([leftRecord[key], rightRecord[key]]);
    }
  }

  return true;
}

function sameChildIds(
  first: readonly string[],
  second: readonly string[],
): boolean {
  return (
    first.length === second.length &&
    first.every((childId, index) => childId === second[index])
  );
}

function validateRemoteSyncTreeAliases<ChangesType>(
  remoteRootId: string | undefined,
  remoteRoot: CRDTChangeNode<ChangesType>,
): void {
  const canonical = new Map<string, RemoteNodeDescription<ChangesType>>();
  const visiting = new Set<string>();
  const comparisonBudget = {
    remaining: MAX_REMOTE_SYNC_PAYLOAD_COMPARISON_ITEMS,
  };
  const conflict = (cid: string): never => {
    throw new TypeError(
      `remote sync tree contains conflicting descriptions for CID ${cid}`,
    );
  };

  type RemoteWalkFrame =
    | {
        readonly phase: 'enter';
        readonly cid: string | undefined;
        readonly node: CRDTChangeNode<ChangesType>;
      }
    | { readonly phase: 'leave'; readonly cid: string };
  const pending: RemoteWalkFrame[] = [
    { phase: 'enter', cid: remoteRootId, node: remoteRoot },
  ];

  while (pending.length > 0) {
    const frame = pending.pop()!;
    if (frame.phase === 'leave') {
      visiting.delete(frame.cid);
      continue;
    }

    const { cid, node } = frame;
    if (cid !== undefined && visiting.has(cid)) {
      throw new TypeError(`remote sync tree contains a cycle at CID ${cid}`);
    }
    const description = describeRemoteNode(node);

    if (cid !== undefined) {
      const existing = canonical.get(cid);
      if (existing === undefined) {
        canonical.set(cid, description);
      } else {
        if (existing.kind !== description.kind) conflict(cid);
        if (
          existing.keyID !== undefined &&
          description.keyID !== undefined &&
          existing.keyID !== description.keyID
        ) {
          conflict(cid);
        }
        if (!existing.sparseReference && !description.sparseReference) {
          if (
            existing.keyID !== description.keyID ||
            existing.hasChange !== description.hasChange ||
            existing.childrenMode !== description.childrenMode ||
            !sameChildIds(existing.childIds, description.childIds) ||
            (existing.hasChange &&
              !sameChangePayload(
                existing.node.change,
                description.node.change,
                comparisonBudget,
              ))
          ) {
            conflict(cid);
          }
        } else if (existing.sparseReference && !description.sparseReference) {
          canonical.set(cid, description);
        }
      }
    }

    if (
      node.children === undefined ||
      node.children === crdtChangeNodeDeferred
    ) {
      continue;
    }
    if (cid !== undefined) {
      visiting.add(cid);
      pending.push({ phase: 'leave', cid });
    }
    for (let index = description.childIds.length - 1; index >= 0; index--) {
      const childId = description.childIds[index]!;
      pending.push({
        phase: 'enter',
        cid: childId,
        node: node.children[childId]!,
      });
    }
  }
}

/**
 * Pure helper: walk a remote sync tree and return the entries that are new
 * relative to `localHashes` and `localRootId`, deduplicated per traversal.
 *
 * **Per-message dedup (paper §VI.B.e cross-links):** cross-link entries can
 * legitimately reference an ancestor CID that is already embedded in the
 * primary parent's inline subtree (e.g. linear history where a cross-link
 * targets an older ancestor). Without per-message dedup, the same CID would
 * appear twice in the returned entries -- once with the inline payload (via
 * the parent subtree) and once as a deferred leaf -- causing the receiver
 * to apply or fetch+apply the same change twice, which can corrupt CRDT
 * state and double-fire local handlers/counters.
 *
 * Dedup strategy:
 *   - Skip any CID already present in `localHashes` (already applied locally).
 *   - During traversal, accumulate entries in a per-CID map. When the same
 *     CID is encountered more than once within a single sync message, the
 *     entry that carries an inline `change` payload is preferred over a
 *     deferred-leaf entry. This is robust regardless of traversal order
 *     (inline-first or deferred-first).
 *   - Track whether a CID's children have been walked. If a CID is first
 *     encountered as a deferred leaf (no `children`) and later encountered
 *     inline with a populated `children` map (possible if serializer or key
 *     ordering varies), upgrade the stored entry AND walk the
 *     newly-discovered children. Skipping the walk in this case would drop
 *     the inline descendants entirely.
 *   - A CID whose children have already been walked is not re-walked --
 *     safe because CIDs are content-addressed: the same CID always names
 *     the same subtree.
 *
 * Returns a new array; does not mutate the inputs.
 */
export function mergeRemoteSyncTree<ChangesType>(
  remoteRootId: string | undefined,
  remoteRoot: CRDTChangeNode<ChangesType>,
  localRootId: string | undefined,
  localHashes: ReadonlySet<string>,
): MergedSyncEntry<ChangesType>[] {
  // Preserve the traversal's root-level no-op semantics: none of these paths
  // reads the supplied tree, so alias validation must not inspect it either.
  if (
    remoteRootId === undefined ||
    remoteRootId === localRootId ||
    localHashes.has(remoteRootId)
  ) {
    return [];
  }
  validateRemoteSyncTreeAliases(remoteRootId, remoteRoot);

  // CID -> winning entry for this message. Entries with an inline `change`
  // payload beat deferred-leaf entries; otherwise the first-seen entry wins.
  const byCid = new Map<string, MergedSyncEntry<ChangesType>>();
  // CIDs whose `children` have already been walked. A CID may be in `byCid`
  // without being in `walked` if it was first seen as a deferred leaf
  // (no `children`). When the same CID later appears inline with children,
  // we must descend into those children even though the entry already exists.
  const walked = new Set<string>();
  const pending: Array<
    readonly [string | undefined, CRDTChangeNode<ChangesType>]
  > = [[remoteRootId, remoteRoot]];

  while (pending.length > 0) {
    const [nodeId, node] = pending.pop()!;
    if (nodeId === undefined) continue;
    // The remote root matches our local head: nothing new under it.
    if (nodeId === localRootId) continue;
    // Already applied locally (or marked seen via a snapshot boundary).
    if (localHashes.has(nodeId)) continue;

    const existing = byCid.get(nodeId);
    if (existing) {
      // Same CID seen earlier in this traversal. Upgrade a deferred-leaf
      // entry to an inline-payload entry if this visit carries the payload.
      if (existing[2] === undefined && node.change !== undefined) {
        byCid.set(nodeId, [nodeId, node.kind, node.change]);
      }
      // Fall through to the children walk below: if the prior visit was a
      // deferred leaf (no children) and this visit carries children, we must
      // still descend so we don't drop the inline descendants.
    } else {
      byCid.set(nodeId, [nodeId, node.kind, node.change]);
    }

    // Don't re-walk children we've already walked. Content addressing means
    // the same CID names the same subtree, so once we've descended through
    // a CID's children we know its full inline subtree.
    if (walked.has(nodeId)) continue;

    if (node.children === undefined) continue;
    if (node.children === crdtChangeNodeDeferred) {
      throw new Error('IPLD dereferencing is not supported yet!');
    }
    // Mark as walked BEFORE descending so cycles (shouldn't happen with
    // content addressing, but defensively) don't traverse forever.
    walked.add(nodeId);
    const entries = Object.entries(node.children);
    for (let index = entries.length - 1; index >= 0; index--) {
      pending.push(entries[index]!);
    }
  }
  return Array.from(byCid.values());
}

/**
 * Pure helper: walk a sync tree and record every CID that appears as a
 * `children` key -- i.e. every CID that some node in the tree points to
 * as a parent (or as a cross-link target, which is also a parent in the
 * Merkle-CRDT DAG; cross-links reference *predecessor* CIDs).
 *
 * Used by `PeerborneDocument._currentFrontier()` to compute the set of
 * heads as `(all known CIDs) \ (referenced ancestors)`. A CID is a "head"
 * iff no node we've ever seen references it as a parent. This gives the
 * leaves of the merged DAG (the CIDs the responder would attest to as the
 * current frontier), which is the correct semantic for the initial-load
 * quorum binding -- two honest peers with the same logical state but
 * different sync histories converge on the same head set even though
 * their full `_hashes` cardinality differs.
 *
 * The root CID (`rootId`, if provided) is intentionally NOT added to the
 * referenced set -- the root of a tree is the head, not a child of anything
 * in this traversal. Descendants reached via `node.children` keys ARE
 * referenced.
 *
 * Walks defensively:
 *   - Skips a deferred `children` sentinel (`crdtChangeNodeDeferred`); IPLD
 *     dereferencing happens elsewhere and isn't required to enumerate the
 *     in-memory parent relationships we already have.
 *   - Tracks CIDs whose enumerable children have been walked so cycles
 *     (shouldn't happen with content addressing, but defensively) don't
 *     traverse forever. A sparse occurrence does not mark a CID walked: a
 *     later canonical full occurrence may reveal its children.
 *
 * Mutates `out` in place and returns it for convenience.
 */
export function collectReferencedAncestors<ChangesType>(
  rootId: string | undefined,
  root: CRDTChangeNode<ChangesType>,
  out: Set<string>,
): Set<string> {
  const walked = new Set<string>();
  const pending: Array<{
    nodeId: string | undefined;
    node: CRDTChangeNode<ChangesType>;
    referencedByParent: boolean;
  }> = [{ nodeId: rootId, node: root, referencedByParent: false }];

  while (pending.length > 0) {
    const { nodeId, node, referencedByParent } = pending.pop()!;
    if (referencedByParent && nodeId !== undefined) out.add(nodeId);
    if (
      node.children === undefined ||
      node.children === crdtChangeNodeDeferred
    ) {
      continue;
    }
    if (nodeId !== undefined) {
      if (walked.has(nodeId)) continue;
      walked.add(nodeId);
    }
    const entries = Object.entries(node.children);
    for (let index = entries.length - 1; index >= 0; index--) {
      const [childId, childNode] = entries[index]!;
      pending.push({
        nodeId: childId,
        node: childNode,
        referencedByParent: true,
      });
    }
  }
  return out;
}

/**
 * Pure helper: derive the served frontier of a load-response payload
 * STRUCTURALLY, without applying any of it to local state.
 *
 * The initial-load quorum binding (#186 / #189 §5.4.2) needs to verify that
 * the full-load response a peer serves actually corresponds to the
 * tip-set hash that peer voted for in the probe round. Previously the
 * loader hashed the responder-supplied `message.tips` array and compared
 * to the quorum-agreed hash -- which trusted the responder's own
 * attestation as the source of truth. A malicious peer could vote hash
 * X, put X's tip CIDs in `message.tips`, and then serve a `changes`
 * payload describing a completely different state; the binding would
 * still pass.
 *
 * This helper closes that gap: given the served `changes` tree (rooted
 * at `changeId`) plus an optional `snapshotBoundaryCid` from
 * `message.snapshot.lastChangeNodeCID`, it computes the frontier as a
 * function of the payload's structure -- the set of CIDs that appear in
 * the served tree but are NOT referenced as a parent (child-key) of any
 * node in the same tree. Hashing this set with `tipsHash` and comparing
 * to `winningHashHex` produces a binding decision that does not depend
 * on the responder's own attestation.
 *
 * Algorithm:
 *   - Initialise `cids = {}` and `referenced = {}`.
 *   - If `changes` is present, walk the tree:
 *       - Record `changeId` (if defined) into `cids` (it is a node in
 *         the served tree, even if it has no children).
 *       - For every `(childId, childNode)` pair encountered in any
 *         `children` map, record `childId` into BOTH `cids` (the child
 *         is a node in the served tree) AND `referenced` (the child is
 *         a parent of the current node, so it is NOT a head).
 *       - Traverse the child's own children (if not deferred).
 *   - If `snapshotBoundaryCid` is provided and non-empty, record it
 *     into `cids`. The snapshot boundary is a node the responder
 *     attests to (post-sync the loader adds it to `_hashes`); whether
 *     it ends up in the frontier depends on whether any post-snapshot
 *     change in `changes` references it as a parent.
 *   - Return `cids \ referenced` -- the heads (CIDs nobody points to).
 *
 * Edge cases:
 *   - Both `changes` undefined AND `snapshotBoundaryCid` empty: the
 *     responder is brand new / has no state. Returns `[]`. The loader
 *     can compare against the canonical hash of `[]` to detect a
 *     responder that voted for a non-empty state but serves nothing.
 *   - `changeId === undefined` with `changes` defined: the served tree
 *     is anonymous (no root CID). Pure helpers in this module already
 *     tolerate `nodeId === undefined`; we record nothing for the
 *     anonymous root, so an anonymous served tree contributes only its
 *     children-keys to the analysis.
 *   - Deferred children sentinel: treated identically to
 *     `collectReferencedAncestors` -- the children of a deferred node
 *     are unknown; we do not traverse them. Any CIDs that appear as keys
 *     leading INTO a deferred child are still recorded as referenced
 *     (we saw them as a child-key before the deferred indicator).
 *   - Cycles: defensively guarded by a set of node CIDs whose enumerable
 *     children have been walked. Sparse occurrences remain eligible for a
 *     later full occurrence to reveal children.
 *
 * This is structurally identical to applying the served payload and
 * then computing `_hashes \ _referencedAncestors` on an EMPTY pre-sync
 * loader, except it works in pure form (no I/O, no Helia blockstore
 * fetch, no document state mutation). The returned array is unsorted;
 * `tipsHash` performs its own canonical sort.
 */
export function computeServedFrontier<ChangesType>(
  changeId: string | undefined,
  changes: CRDTChangeNode<ChangesType> | undefined,
  snapshotBoundaryCid: string | undefined,
): string[] {
  const cids = new Set<string>();
  const referenced = new Set<string>();
  const walked = new Set<string>();

  if (changes !== undefined) {
    const pending: Array<{
      nodeId: string | undefined;
      node: CRDTChangeNode<ChangesType>;
      referencedByParent: boolean;
    }> = [{ nodeId: changeId, node: changes, referencedByParent: false }];
    while (pending.length > 0) {
      const { nodeId, node, referencedByParent } = pending.pop()!;
      if (nodeId !== undefined) {
        cids.add(nodeId);
        if (referencedByParent) referenced.add(nodeId);
      }
      if (
        node.children === undefined ||
        node.children === crdtChangeNodeDeferred
      ) {
        continue;
      }
      if (nodeId !== undefined) {
        if (walked.has(nodeId)) continue;
        walked.add(nodeId);
      }
      const entries = Object.entries(node.children);
      for (let index = entries.length - 1; index >= 0; index--) {
        const [childId, childNode] = entries[index]!;
        pending.push({
          nodeId: childId,
          node: childNode,
          referencedByParent: true,
        });
      }
    }
  }
  if (snapshotBoundaryCid) {
    cids.add(snapshotBoundaryCid);
  }

  const frontier: string[] = [];
  for (const cid of cids) {
    if (!referenced.has(cid)) {
      frontier.push(cid);
    }
  }
  return frontier;
}

/**
 * Pure helper: walk a sync tree and report whether `targetCid` appears
 * anywhere in it -- as the root CID, as a `children` map key, or as a
 * descendant. Used by `PeerborneDocument._refreshLastSyncMessageFromSync`
 * to decide whether an incoming sync tree subsumes the locally-cached
 * `_lastSyncMessage` (i.e. embeds its root), in which case the cache can
 * be safely replaced without losing served-frontier coverage.
 *
 * Walks defensively:
 *   - Skips a deferred `children` sentinel; we cannot enumerate descendants
 *     of a deferred node, so we conservatively return `false` if the target
 *     would only have been found beneath that sentinel.
 *   - Tracks node CIDs only after their enumerable children are walked so
 *     cycles do not traverse forever while a sparse occurrence can still be
 *     upgraded by a later full occurrence.
 *
 * Returns `true` if `targetCid` is found, `false` otherwise. Treats
 * empty / undefined `targetCid` as "not found" so callers can pass an
 * optional value without a separate guard.
 */
export function treeContainsCid<ChangesType>(
  rootId: string | undefined,
  root: CRDTChangeNode<ChangesType> | undefined,
  targetCid: string | undefined,
): boolean {
  if (!targetCid) return false;
  if (root === undefined) return false;
  const walked = new Set<string>();
  const pending: Array<
    readonly [string | undefined, CRDTChangeNode<ChangesType>]
  > = [[rootId, root]];
  while (pending.length > 0) {
    const [nodeId, node] = pending.pop()!;
    if (nodeId === targetCid) return true;
    if (
      node.children === undefined ||
      node.children === crdtChangeNodeDeferred
    ) {
      continue;
    }
    if (nodeId !== undefined) {
      if (walked.has(nodeId)) continue;
      walked.add(nodeId);
    }
    const entries = Object.entries(node.children);
    for (let index = entries.length - 1; index >= 0; index--) {
      pending.push(entries[index]!);
    }
  }
  return false;
}

/**
 * Pure helper: append `entry` to `recentTips` with LRU semantics
 * (most-recently-used to the back), evicting the oldest entries when the
 * list exceeds `maxRecentTips`. If `entry.cid` is already present, it is
 * moved to the back without growing the list. Mutates `recentTips` in
 * place and returns it for convenience.
 *
 * Entries with empty `cid` are ignored (defensive guard for the initial
 * sync-message state before any change has been published).
 */
export function trackTipInList<Tip extends { cid: string }>(
  recentTips: Tip[],
  entry: Tip,
  maxRecentTips: number = MAX_RECENT_TIPS,
): Tip[] {
  if (!entry.cid) return recentTips;
  // Clamp `maxRecentTips` to non-negative so a misconfigured zero or
  // negative cap clears the list instead of looping forever (the eviction
  // loop below uses `> cap`, which would never become false against an
  // empty array if `cap` were negative).
  const cap = Math.max(0, maxRecentTips);
  if (cap === 0) {
    recentTips.length = 0;
    return recentTips;
  }
  const existingIdx = recentTips.findIndex((t) => t.cid === entry.cid);
  if (existingIdx !== -1) {
    recentTips.splice(existingIdx, 1);
  }
  recentTips.push(entry);
  while (recentTips.length > cap) {
    recentTips.shift();
  }
  return recentTips;
}

/**
 * Iteratively strip inline `change` content from a `CRDTChangeNode` tree
 * by setting `change: undefined` on every node, leaving the CID-keyed
 * `children` structure intact. Mutates the passed tree in-place; returns
 * the same root for chaining convenience.
 *
 * Used by `PeerborneDocument._sendLoadRequestAndSync` on quorum-bound
 * loads as a defense-in-depth against inline-content forgery. The
 * structural quorum bind proves Q peers agree
 * on the FRONTIER CIDs, but a Byzantine peer that voted for the agreed
 * frontier can still serve a tree whose `children` map uses those CIDs
 * as keys but whose inline `change` values are forged. Stripping inline
 * content forces each change to flow through Helia's CID-addressed
 * blockstore (`_getBlock(cid) -> heliaNode.blockstore.get(cid)`), which
 * content-validates the fetched bytes against the CID intrinsically.
 * Bitswap retrieves from any peer in the swarm that holds the legitimate
 * block, including honest peers in the agreeing cohort.
 *
 * Skips a deferred `children` sentinel (already empty by definition).
 * Walks every other node so a partially-deferred tree is fully stripped.
 *
 * Pure (no I/O, no clock); an explicit stack avoids call-stack growth.
 * Returned as a free function so the unit tests can exercise the helper
 * without standing up a full `PeerborneDocument` instance.
 */
export function stripInlineChanges<ChangesType>(
  node: CRDTChangeNode<ChangesType> | undefined,
): CRDTChangeNode<ChangesType> | undefined {
  if (!node) return node;
  const pending = [node];
  const visited = new Set<CRDTChangeNode<ChangesType>>();
  while (pending.length > 0) {
    const current = pending.pop()!;
    if (visited.has(current)) continue;
    visited.add(current);
    current.change = undefined;
    if (
      current.children !== undefined &&
      current.children !== crdtChangeNodeDeferred
    ) {
      const children = Object.values(current.children);
      for (let index = children.length - 1; index >= 0; index--) {
        pending.push(children[index]!);
      }
    }
  }
  return node;
}

/**
 * Iteratively collect every CID that appears in a `CRDTChangeNode` tree
 * (the optional root CID, every node-id appearing in any `children` map
 * key). Returns the CIDs in insertion order, deduplicated via the
 * underlying `Set`. Used by `PeerborneDocument._sendLoadRequestAndSync`
 * on quorum-bound loads as the basis for the post-`sync()` "did every
 * stripped block actually arrive?" check:
 *
 *   1. Collect all CIDs from the served tree BEFORE `stripInlineChanges`
 *      reduces it to a CID-keyed shell.
 *   2. Strip inline content; call `sync()`.
 *   3. Verify every collected CID is now in `_hashes`. If any is missing,
 *      the load is reported as a per-peer bind failure so the loader can
 *      retry the next peer in the agreeing cohort. Without this check, a
 *      transient bitswap/blockstore miss would let `sync()` return `true`
 *      with only a partially-applied document and `load()` report success.
 *
 * Skips a deferred `children` sentinel (we cannot enumerate descendants
 * beneath a deferred node; defensively bounded by a set of node CIDs whose
 * enumerable children have been walked). Sparse occurrences remain eligible
 * for a later full occurrence to reveal children.
 *
 * Pure (no I/O); an explicit stack avoids call-stack growth.
 */
export function collectAllCidsInTree<ChangesType>(
  rootId: string | undefined,
  root: CRDTChangeNode<ChangesType> | undefined,
): string[] {
  if (!root) return rootId ? [rootId] : [];
  const cids = new Set<string>();
  const walked = new Set<string>();
  const pending: Array<
    readonly [string | undefined, CRDTChangeNode<ChangesType>]
  > = [[rootId, root]];
  while (pending.length > 0) {
    const [nodeId, node] = pending.pop()!;
    if (nodeId !== undefined) {
      cids.add(nodeId);
    }
    if (
      node.children === undefined ||
      node.children === crdtChangeNodeDeferred
    ) {
      continue;
    }
    if (nodeId !== undefined) {
      if (walked.has(nodeId)) continue;
      walked.add(nodeId);
    }
    const entries = Object.entries(node.children);
    for (let index = entries.length - 1; index >= 0; index--) {
      pending.push(entries[index]!);
    }
  }
  return [...cids];
}
