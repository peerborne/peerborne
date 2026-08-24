import { CRDTChangeNode } from './crdt-change-node.js';
import { SerializedPathUpdate } from './path-update-wire.js';
import { CRDTSnapshotNode } from './snapshot-node.js';

/**
 * CRDTSyncMessage is the message sent over both GossipSub pubsub topics and in response to
 * load document requests.
 *
 * @typeParam ChangesType A block of CRDT change(s).
 */
export type CRDTSyncMessage<ChangesType, PublicKey = unknown> = {
  /**
   * ID of a peerborne document.
   */
  documentId: string;

  /**
   * CID of the root change node.
   */
  changeId?: string;

  /**
   * Root of the Merkle-DAG change tree. Each `CRDTChangeNode` contains a change
   * payload and optional `children` linking to prior nodes. A node whose `change`
   * is `undefined` (deferred) should be fetched from the Helia blockstore by CID.
   *
   * Changes are decrypted via `ChangesSerializer` and sync messages via
   * `SyncMessageSerializer`.
   */
  changes?: CRDTChangeNode<ChangesType>;

  /**
   * Optional snapshot for fast sync.
   * When present, peers can load from the snapshot state instead of replaying
   * the full change history. Post-snapshot changes are still included in `changes`.
   */
  snapshot?: CRDTSnapshotNode<ChangesType, PublicKey>;

  /**
   * Optional document keys list. Populated by **load responses** (doc-load and
   * snapshot-load) where the entire sync message is encrypted under the current
   * document key on a stream to an already-authorized peer. BeeKEM Welcome
   * messages do **not** populate this field directly -- their keychain delta
   * is delivered via the recipient-encrypted `eciesSealed` field below so it
   * is opaque to non-recipient peers.
   *
   * The keychain delta is decrypted via the CRDT-specific `ChangesSerializer`
   * (yjs/automerge) and the sync message itself via `SyncMessageSerializer`.
   */
  keychainChanges?: ChangesType;

  /**
   * Optional invitation epoch ID for BeeKEM Welcome messages. When the
   * recipient processes a Welcome, this is the key ID the recipient should
   * record as their `_invitationEpoch`, gating subsequent `since_invited`
   * history filtering. The field is base64-encoded for JSON-safe transport
   * by the sync-message serializers.
   */
  welcomeEpochId?: Uint8Array;

  /**
   * Optional recipient binding for BeeKEM Welcome messages. The inviter
   * cannot identify the new reader's libp2p connection directly, so
   * Welcomes are broadcast to every connected peer; without a binding, a
   * well-behaved non-member peer would still process a writer-signed
   * Welcome and install the document key. The receiver MUST drop a
   * Welcome whose `welcomeRecipient` does not match its own local user
   * public key. The field is the serialized public key of the intended
   * recipient (same encoding as the readers ACL) and is included in the
   * signed payload, so a legitimate writer attests to the recipient.
   * JSON-safe (a string) because the serialized public key is already a
   * string.
   *
   * NOTE: this is the **authorization** binding (which identity the
   * Welcome was meant for). Confidentiality is provided separately by
   * the `eciesSealed` payload, which only the recipient holding the
   * matching `welcomeRecipientKemPublicKey` private key can decrypt.
   */
  welcomeRecipient?: string;

  /**
   * Optional recipient ECDH public key for BeeKEM Welcome messages. Raw
   * SEC1-uncompressed P-256 public key bytes (65 bytes) of the
   * recipient's encryption key, encoded as base64 on the wire by the
   * sync-message serializers. The inviter seals `eciesSealed` against
   * this public key; the recipient opens it with the matching private
   * key.
   *
   * Bound to the recipient identity by the writer signature (covers
   * both `welcomeRecipient` and `welcomeRecipientKemPublicKey`), so an
   * authorized writer must commit to a specific KEM public key for a
   * specific recipient identity. A recipient that holds the matching
   * KEM private key but observes a different `welcomeRecipient` MUST
   * drop the Welcome (the writer asserted the Welcome is for a
   * different identity).
   */
  welcomeRecipientKemPublicKey?: Uint8Array;

  /**
   * Sealed payload for BeeKEM Welcome messages. Output of `eciesSeal`
   * over the inviter-side serialized keychain delta, encrypted under
   * the recipient's ECDH public key
   * (`welcomeRecipientKemPublicKey`). The plaintext is the
   * provider-specific serialized keychain changes (the same bytes the
   * CRDT-specific `ChangesSerializer` would emit for those changes);
   * the recipient opens the sealed payload with their KEM private key
   * and routes the result through the provider deserializer before
   * merging into the local keychain.
   *
   * The sealed bytes are base64-encoded on the wire for JSON
   * transport.
   *
   * SECURITY: the writer signature covers the sealed bytes, not the
   * plaintext, so a replayed/altered sealed payload fails signature
   * verification. AES-GCM authenticates the ciphertext under the
   * derived per-message key, so a non-recipient cannot read or alter
   * the plaintext without detection.
   */
  eciesSealed?: Uint8Array;

  /**
   * Optional BeeKEM ratchet-tree `PathUpdate` carried by the
   * `beekemPathUpdateV1` wire protocol. Populated when a writer revokes
   * a reader via `PeerborneDocument.removeReader`: the writer calls
   * `BeeKEM.removeMember(leafIdx)`, serializes the resulting
   * `PathUpdate` via `serializePathUpdateForWire`, and broadcasts it
   * here so surviving readers can re-derive the new document
   * encryption key. (`removeMember` already blanks the removed leaf
   * and re-derives fresh key material along the writer's path to
   * root; no follow-up `BeeKEM.update()` call is needed.) Receivers
   * feed the deserialized `PathUpdate` into `BeeKEM.processPathUpdate`
   * to advance their local ratchet state.
   *
   * Only populated on the BeeKEM PathUpdate v1 wire path; absent on
   * sync messages flowing over GossipSub / document-load / Welcome.
   */
  pathUpdate?: SerializedPathUpdate;

  /**
   * Optional 32-byte epoch identifier paired with `pathUpdate`. The
   * sender derives this from the new BeeKEM root secret via
   * `deriveEpochIdFromRootSecret`; the receiver re-derives it after
   * `BeeKEM.processPathUpdate` and validates that the two match
   * byte-for-byte before installing the new key. Mismatch means the
   * receiver derived a different root than the sender (e.g. stale
   * local tree state) and the PathUpdate is rejected rather than
   * installing a key under the wrong epoch ID.
   *
   * Both ends key the on-wire encrypted-block prefix on this exact
   * 32-byte ID -- the keychain providers' `keyIDLength` is 32,
   * matching the HKDF output width, so there is no truncation step
   * between the epoch-ID gate and the keychain install.
   *
   * Base64-encoded by the sync-message serializers (yjs / automerge)
   * for JSON-safe transport, mirroring `welcomeEpochId`.
   */
  pathUpdateEpochId?: Uint8Array;

  /**
   * Optional canonical hash of the responder's served tip set, used by the
   * initial-load quorum protocol (`tipAdvertiseV1`, see `wire-protocols.ts`
   * and `tips-hash.ts`).
   *
   * When a new node opens a document it queries up to K peers in parallel
   * via `tipAdvertiseV1`; each peer responds with a `CRDTSyncMessage` whose
   * only populated payload field is `tipsHash`. The loader counts how many
   * peers returned the same hash and proceeds with a full
   * documentLoadV3/snapshotLoadV3 against one of the agreeing peers only
   * when at least Q peers agree.
   *
   * # Protocol contract: WHAT to hash
   *
   * `tipsHash` is computed over the **served frontier** -- the heads of
   * the change tree the responder would actually ship in a load response
   * (NOT the full local DAG frontier). The reference implementation is
   * `PeerborneDocument._servedFrontier()` in `peerborne-document.ts`,
   * which computes this via `computeServedFrontier` over
   * `_lastSyncMessage.changes` plus `_latestSnapshot?.lastChangeNodeCID`
   * -- exactly the inputs `handleLoadRequestData` /
   * `handleSnapshotLoadRequestData` populate into the load response.
   *
   * Hashing this set produces a value the loader can reproduce
   * structurally from the served payload via `computeServedFrontier`,
   * which is exactly the binding `_sendLoadRequestAndSync` uses.
   *
   * # Implementer warning: do NOT hash `_currentFrontier()` or `_hashes`
   *
   * Implementers **MUST NOT** hash `_currentFrontier()` (the full local
   * DAG frontier). A peer that has remotely-applied heads not yet
   * cross-linked into `_lastSyncMessage.changes` produces a
   * `_currentFrontier()` larger than the served frontier, so the
   * advertised hash would not match what the load response actually
   * contains. The loader's structural bind check derives the served
   * frontier from the received `changes` tree and rejects honest peers
   * whose advertise hash disagrees. Round 8 of the PR #284 Copilot
   * review caught this exact bug.
   *
   * Implementers **MUST NOT** hash the full `_hashes` set either. Two
   * honest peers with the same logical document state can have DIFFERENT
   * observed-CID sets when their history depths differ (history
   * compaction, snapshot-loads that don't restore ancestors, different
   * join times). Round 3 of the PR #284 Copilot review caught and fixed
   * that earlier variant of the bug.
   *
   * Hashing the served frontier makes the hash deterministic across
   * honest peers whose `_lastSyncMessage` / `_latestSnapshot` describe
   * the same logical state.
   *
   * The field is also tolerated (but optional) on regular load responses,
   * so a future optimization can fold quorum into the full load. It is
   * base64-encoded for JSON-safe transport by the sync-message serializers
   * (same pattern as `welcomeEpochId`).
   *
   * Closes the gap tracked under issue #189 §5.4 item 2.
   */
  tipsHash?: Uint8Array;

  /**
   * Explicit tip-set advertisement, populated by load responses
   * (documentLoadV3 and snapshotLoadV3) to bind the served full state to
   * the responder's served frontier. **Part of the signed payload** on v3
   * load responses -- changing the wire shape from v2 is why the protocol
   * id was bumped (see `wire-protocols.ts`).
   *
   * "Frontier" here means the **served frontier** -- the heads of the
   * change tree this load response actually carries (computed by
   * `PeerborneDocument._servedFrontier()` via `computeServedFrontier`
   * over `_lastSyncMessage.changes` plus `_latestSnapshot?.lastChangeNodeCID`).
   * This is the set the responder attests it is shipping in THIS payload,
   * not the full set of heads the responder has in its local DAG.
   *
   * # Why served frontier (not local DAG frontier)
   *
   * A load response only carries one change tree (rooted at
   * `changeId`), plus an optional snapshot. A peer that has multiple
   * concurrent heads -- e.g. one local head plus a remotely-applied head
   * not yet cross-linked into `_lastSyncMessage.changes` -- can only
   * serve one of them in a single load response. Advertising the full
   * local DAG frontier in `tips` would not match the structurally-derived
   * frontier of the served payload, so the loader's bind check would
   * reject honest peers. Round 8 of the PR #284 Copilot review caught
   * this; advertising the served frontier closes the gap.
   *
   * # Why this field exists at all (defense-in-depth)
   *
   * The loader's PRIMARY binding (PR #284 r7) is derived structurally
   * from `message.changes` / `message.snapshot` via
   * `computeServedFrontier`, so a malicious peer that lies in `tips`
   * cannot bypass the gate by simply claiming the agreed CIDs. The
   * `tips` field is verified as a defense-in-depth attestation: if
   * present, it MUST hash to the same value as the
   * structurally-derived served frontier -- catching responders that
   * equivocate between their attested heads and the actual served
   * payload (e.g. tampered `changes` with a still-correct-looking
   * `tips` array).
   *
   * Recomputing `tipsHash(loader._hashes)` after sync is unreliable
   * because:
   *   - on a snapshot-load, only the snapshot boundary CID is added to
   *     `_hashes` -- the ancestor CIDs the snapshot compacts away are NOT
   *     restored, so `_hashes` does not represent the responder's full
   *     history;
   *   - on a regular doc-load, the loader's pre-existing local CIDs (if
   *     any) inflate `_hashes` beyond what the responder advertised;
   *   - on a compacted/pruned peer, the responder's `_hashes` includes
   *     referenced ancestors which two honest peers can have differently
   *     based on sync history -- which is exactly the bug round 3 of the
   *     Copilot review flagged.
   *
   * Because the load response is signed by the responder, `tips` is a
   * responder-signed attestation of "the heads of what I am serving";
   * a peer that voted hash X but then serves a load with a `tips` array
   * that hashes to anything other than the served-payload frontier is
   * caught by the defense-in-depth check.
   *
   * `tips` is REQUIRED on v3 load responses (responder always populates,
   * loader rejects absence when the quorum gate is enabled). The field
   * remains optional in the TypeScript type because the same
   * `CRDTSyncMessage` shape is also used for pubsub-broadcast change
   * messages, which do not carry a frontier advertisement.
   */
  tips?: string[];

  /**
   * Signature of the sync message.
   */
  signature?: string;
};
