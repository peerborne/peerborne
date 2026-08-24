import {
  CRDTChangeNode,
  CRDTChangeNodeKind,
  crdtChangeNodeDeferred,
} from './crdt-change-node.js';

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
  // CID -> winning entry for this message. Entries with an inline `change`
  // payload beat deferred-leaf entries; otherwise the first-seen entry wins.
  const byCid = new Map<string, MergedSyncEntry<ChangesType>>();
  // CIDs whose `children` have already been walked. A CID may be in `byCid`
  // without being in `walked` if it was first seen as a deferred leaf
  // (no `children`). When the same CID later appears inline with children,
  // we must descend into those children even though the entry already exists.
  const walked = new Set<string>();

  function walk(
    nodeId: string | undefined,
    node: CRDTChangeNode<ChangesType>,
  ): void {
    if (nodeId === undefined) return;
    // The remote root matches our local head: nothing new under it.
    if (nodeId === localRootId) return;
    // Already applied locally (or marked seen via a snapshot boundary).
    if (localHashes.has(nodeId)) return;

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
    if (walked.has(nodeId)) return;

    if (node.children === undefined) return;
    if (node.children === crdtChangeNodeDeferred) {
      throw new Error('IPLD dereferencing is not supported yet!');
    }
    // Mark as walked BEFORE descending so cycles (shouldn't happen with
    // content addressing, but defensively) don't infinitely recurse.
    walked.add(nodeId);
    for (const [childId, childNode] of Object.entries(node.children)) {
      walk(childId, childNode);
    }
  }

  walk(remoteRootId, remoteRoot);
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
 *   - Tracks visited node CIDs so cycles (shouldn't happen with content
 *     addressing, but defensively) don't recurse forever.
 *
 * Mutates `out` in place and returns it for convenience.
 */
export function collectReferencedAncestors<ChangesType>(
  rootId: string | undefined,
  root: CRDTChangeNode<ChangesType>,
  out: Set<string>,
): Set<string> {
  const visited = new Set<string>();

  function walk(
    nodeId: string | undefined,
    node: CRDTChangeNode<ChangesType>,
  ): void {
    if (nodeId !== undefined) {
      if (visited.has(nodeId)) return;
      visited.add(nodeId);
    }

    if (node.children === undefined) return;
    if (node.children === crdtChangeNodeDeferred) return;

    for (const [childId, childNode] of Object.entries(node.children)) {
      // The `children` map keys are CIDs the current node references as
      // parents (primary parent + cross-links). They are ancestors by
      // definition -- record them as referenced.
      out.add(childId);
      walk(childId, childNode);
    }
  }

  walk(rootId, root);
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
 *       - Recurse into the child's own children (if not deferred).
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
 *     are unknown; we do not recurse. Any CIDs that appear as keys
 *     leading INTO a deferred child are still recorded as referenced
 *     (we saw them as a child-key before the deferred indicator).
 *   - Cycles: defensively guarded by a `visited` set on node CIDs.
 *
 * This is structurally identical to applying the served payload and
 * then computing `_hashes \ _referencedAncestors` on an EMPTY pre-sync
 * loader, except it works in pure form (no I/O, no Helia blockstore
 * fetch, no document state mutation). The returned array is unsorted;
 * `tipsHash` performs its own canonical sort. See PR #284 r7 Copilot
 * review for the design discussion.
 */
export function computeServedFrontier<ChangesType>(
  changeId: string | undefined,
  changes: CRDTChangeNode<ChangesType> | undefined,
  snapshotBoundaryCid: string | undefined,
): string[] {
  const cids = new Set<string>();
  const referenced = new Set<string>();
  const visited = new Set<string>();

  function walk(
    nodeId: string | undefined,
    node: CRDTChangeNode<ChangesType>,
  ): void {
    if (nodeId !== undefined) {
      if (visited.has(nodeId)) return;
      visited.add(nodeId);
      cids.add(nodeId);
    }
    if (node.children === undefined) return;
    if (node.children === crdtChangeNodeDeferred) return;
    for (const [childId, childNode] of Object.entries(node.children)) {
      cids.add(childId);
      referenced.add(childId);
      walk(childId, childNode);
    }
  }

  if (changes !== undefined) {
    walk(changeId, changes);
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
 *   - Tracks visited node CIDs so cycles do not recurse forever (content
 *     addressing rules these out in practice; defensive nonetheless).
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
  if (rootId === targetCid) return true;

  const visited = new Set<string>();

  function walk(
    nodeId: string | undefined,
    node: CRDTChangeNode<ChangesType>,
  ): boolean {
    if (nodeId !== undefined) {
      if (visited.has(nodeId)) return false;
      visited.add(nodeId);
    }
    if (node.children === undefined) return false;
    if (node.children === crdtChangeNodeDeferred) return false;
    for (const [childId, childNode] of Object.entries(node.children)) {
      if (childId === targetCid) return true;
      if (walk(childId, childNode)) return true;
    }
    return false;
  }

  return walk(rootId, root);
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
 * Recursively strip inline `change` content from a `CRDTChangeNode` tree
 * by setting `change: undefined` on every node, leaving the CID-keyed
 * `children` structure intact. Mutates the passed tree in-place; returns
 * the same root for chaining convenience.
 *
 * Used by `PeerborneDocument._sendLoadRequestAndSync` on quorum-bound
 * loads as a defense-in-depth against inline-content forgery (PR #284
 * r17 Copilot review). The structural quorum bind proves Q peers agree
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
 * Pure (no I/O, no clock); the recursion is bounded by the tree size.
 * Returned as a free function so the unit tests can exercise the helper
 * without standing up a full `PeerborneDocument` instance.
 */
export function stripInlineChanges<ChangesType>(
  node: CRDTChangeNode<ChangesType> | undefined,
): CRDTChangeNode<ChangesType> | undefined {
  if (!node) return node;
  node.change = undefined;
  if (
    node.children !== undefined &&
    node.children !== crdtChangeNodeDeferred
  ) {
    for (const child of Object.values(node.children)) {
      stripInlineChanges(child);
    }
  }
  return node;
}

/**
 * Recursively collect every CID that appears in a `CRDTChangeNode` tree
 * (the optional root CID, every node-id appearing in any `children` map
 * key). Returns the CIDs in insertion order, deduplicated via the
 * underlying `Set`. Used by `PeerborneDocument._sendLoadRequestAndSync`
 * on quorum-bound loads as the basis for the post-`sync()` "did every
 * stripped block actually arrive?" check (PR #284 r18 Copilot review):
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
 * beneath a deferred node; defensively bounded by a `visited` set on
 * node CIDs).
 *
 * Pure (no I/O); the recursion is bounded by the tree size.
 */
export function collectAllCidsInTree<ChangesType>(
  rootId: string | undefined,
  root: CRDTChangeNode<ChangesType> | undefined,
): string[] {
  if (!root) return rootId ? [rootId] : [];
  const cids = new Set<string>();
  const visited = new Set<string>();
  function walk(
    nodeId: string | undefined,
    node: CRDTChangeNode<ChangesType>,
  ): void {
    if (nodeId !== undefined) {
      if (visited.has(nodeId)) return;
      visited.add(nodeId);
      cids.add(nodeId);
    }
    if (node.children === undefined) return;
    if (node.children === crdtChangeNodeDeferred) return;
    for (const [childId, childNode] of Object.entries(node.children)) {
      cids.add(childId);
      walk(childId, childNode);
    }
  }
  walk(rootId, root);
  return [...cids];
}
