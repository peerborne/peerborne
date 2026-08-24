/**
 * Deterministic tip-set hash used by the initial-load quorum protocol.
 *
 * When a new node opens a document, it asks K peers in parallel for a
 * lightweight "tip advertisement" -- the responder's current view of the
 * document's tip set, summarized as a single 32-byte SHA-256 digest. The
 * loader counts how many peers returned the *same* hash and only proceeds
 * with a full document-load against a peer that participated in the
 * agreeing majority. See `load-quorum.ts` for the decision logic and
 * `PeerborneDocument.load()` for how the gate is wired in.
 *
 * Closes the "no quorum protocol for verifying initial document state" gap
 * tracked under issue #189 §5.4 item 2 (and listed as a bullet under #186).
 *
 * The hash is deterministic across peers that share the same tip set
 * because:
 *   - the input CIDs are sorted lexicographically (the input order from
 *     `Set` iteration or array-passed order is irrelevant);
 *   - each CID is UTF-8 encoded with an explicit `\n` separator to avoid
 *     prefix-ambiguity between adjacent CIDs (`["ab", "c"]` vs
 *     `["a", "bc"]`).
 *
 * An empty tip set hashes to the SHA-256 of the empty string. This is
 * intentional: peers that have never seen any changes (founding member,
 * brand-new document) all agree on the empty-set hash, so a quorum can be
 * met cleanly in the bootstrapping case.
 */

/**
 * 32-byte SHA-256 length, used by the hash function and by callers that
 * need to validate wire-encoded tip-hash bytes.
 */
export const TIPS_HASH_LENGTH = 32;

/**
 * Compute the canonical tip-set hash for a document's set of known change
 * CIDs.
 *
 * # Input contract: pass the SERVED FRONTIER, NOT `_hashes` or the local DAG frontier
 *
 * The caller **MUST** pass the **served frontier** -- the heads of the
 * change tree the responder would actually ship in a `documentLoadV3`
 * / `snapshotLoadV3` round. The reference implementation is
 * `PeerborneDocument._servedFrontier()` in `peerborne-document.ts`,
 * which computes this via `computeServedFrontier` over
 * `_lastSyncMessage.changes` (the served tree) plus
 * `_latestSnapshot?.lastChangeNodeCID` (the snapshot boundary, if any).
 *
 * # Why "served frontier" and not "current local frontier"?
 *
 * A peer's `_currentFrontier()` (`_hashes \ _referencedAncestors`) is the
 * heads of EVERYTHING this peer has seen. That set is correct for "the
 * logical state of my local document" but it is the WRONG input for
 * `tipsHash` when used by the initial-load quorum protocol. The load
 * response only carries ONE change tree (rooted at
 * `_lastSyncMessage.changeId`); remote heads received via GossipSub but
 * not yet cross-linked into a local change are in `_currentFrontier()`
 * but NOT in the served payload. Hashing `_currentFrontier()` therefore
 * advertises a frontier the responder cannot actually serve, and the
 * loader's structural bind check
 * (`computeServedFrontier(message.changes, ...)` over the received
 * payload) hashes to a different value -- rejecting the honest peer.
 * Round 8 of the PR #284 Copilot review caught this exact bug.
 *
 * # Implementer warning: do NOT hash `_hashes` directly
 *
 * Implementers **MUST NOT** hash the full set of observed/merged CIDs
 * (e.g. the peer's entire `_hashes` set). Two honest peers with the same
 * logical document state can have different observed-CID sets when their
 * history depths differ (history compaction, snapshot-loads that don't
 * restore ancestor CIDs, different join times). Hashing the full set
 * would cause those honest peers to produce different hashes and the
 * quorum gate (see `load-quorum.ts`) would never agree. Round 3 of the
 * PR #284 Copilot review caught this earlier variant of the bug; the
 * previous wording of this docstring ("typically a peer's `_hashes`")
 * was misleading and has been corrected.
 *
 * Passing the served frontier makes the hash deterministic across honest
 * peers whose `_lastSyncMessage` / `_latestSnapshot` describe the same
 * logical state -- regardless of differing pruning / sync histories or
 * unrelated concurrent heads held only in their local DAG.
 *
 * @param hashes The served frontier (heads of the served change tree).
 *   Accepts either a `Set<string>` or a plain `string[]` (more convenient
 *   for tests). Order within the collection is irrelevant -- the
 *   implementation sorts lexicographically before hashing.
 * @returns A 32-byte `Uint8Array` containing the SHA-256 digest of the
 *   canonicalized frontier.
 */
export async function tipsHash(
  hashes: Set<string> | readonly string[],
): Promise<Uint8Array> {
  const sorted = Array.from(hashes).slice().sort();
  // Use `\n` (0x0A) as a CID separator. Real CIDs are base32/base58/base64
  // text and never contain raw `\n`, so this is unambiguous. Encoding the
  // separator (rather than concatenating bytes directly) prevents two
  // different tip sets from colliding via a shared boundary, e.g.
  // `["ab", "c"]` vs `["a", "bc"]`.
  const canonical = sorted.join('\n');
  const encoded = new TextEncoder().encode(canonical);
  // Cast required: `Uint8Array<ArrayBufferLike>` does not strictly satisfy
  // WebCrypto's `BufferSource` (excludes `SharedArrayBuffer`-backed views).
  const digest = await crypto.subtle.digest(
    'SHA-256',
    encoded as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(digest);
}

/**
 * Encode a tips-hash byte array as a lowercase hex string. Used to key the
 * agreement map in `decideLoadQuorum` and to log/diagnose hash mismatches.
 *
 * Mirrors the canonical encoding so two callers comparing serialized hashes
 * over the wire always produce identical strings for identical inputs.
 */
export function tipsHashToHex(hash: Uint8Array): string {
  let out = '';
  for (let i = 0; i < hash.length; i++) {
    out += hash[i].toString(16).padStart(2, '0');
  }
  return out;
}
