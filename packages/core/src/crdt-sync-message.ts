import { CRDTChangeNode } from './crdt-change-node.js';
import {
  SerializedPathUpdate,
  SerializedPathUpdateV2,
} from './path-update-wire.js';
import { CRDTSnapshotNode } from './snapshot-node.js';
import type { LoadSecurityCommitments } from './load-security-state.js';

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
   * Generic JSON wire codecs traverse this tree iteratively so legacy V1/V3
   * and GossipSub histories are not subject to the V4 load manifest's
   * 512-node root-to-leaf policy. Ingress remains bounded by aggregate wire,
   * object, property, and decoded-value budgets before state mutation.
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
   * Sealed payload for BeeKEM Welcome messages. The wire field carries the
   * output of `eciesSeal` over a Welcome envelope encrypted under the
   * recipient's ECDH public key (`welcomeRecipientKemPublicKey`). V1 permits a
   * missing/null legacy bootstrap; the separate V2 envelope requires a
   * non-null generation- and leaf-count-bearing Welcome. Integrations MUST
   * select the decoder from the negotiated protocol rather than infer a
   * version from payload contents.
   *
   * The sealed bytes are base64-encoded on the wire for JSON
   * transport.
   *
   * SECURITY: the writer signature covers the sealed bytes, not the
   * plaintext, so alteration fails signature verification. Exact replay
   * retains a valid signature; V2 integrations MUST also enforce the Welcome
   * generation transition. AES-GCM authenticates the ciphertext under the
   * derived per-message key, so a non-recipient cannot read or alter the
   * plaintext without detection.
   */
  eciesSealed?: Uint8Array;

  /**
   * Optional BeeKEM ratchet-tree update reserved for the distinct V1 and V2
   * PathUpdate wire protocols. V1 carries `SerializedPathUpdate`; V2 carries
   * the explicit generation, tree snapshot, and resolution bundles in
   * `SerializedPathUpdateV2`. Integrations MUST select the decoder from the
   * negotiated protocol; neither version may be reinterpreted as the other.
   *
   * Only populated on a BeeKEM PathUpdate wire path; absent on
   * sync messages flowing over GossipSub / document-load / Welcome.
   */
  pathUpdate?: SerializedPathUpdate | SerializedPathUpdateV2;

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
   * On legacy V3, `tipsHash` is computed over the **served frontier** --
   * the heads of the change tree the responder would actually ship in a
   * (NOT the full local DAG frontier). The reference implementation is
   * `PeerborneDocument._servedFrontier()` in `peerborne-document.ts`,
   * which computes this via `computeServedFrontier` over
   * `_lastSyncMessage.changes` plus `_latestSnapshot?.lastChangeNodeCID`
   * -- exactly the inputs `handleLoadRequestData` /
   * `handleSnapshotLoadRequestData` populate into the load response.
   *
   * On security-aware V4, the 32-byte value additionally commits to a
   * canonical manifest derived from the complete response plan: root identity,
   * every node CID/kind/directed edge and deferred marker, snapshot content and
   * metadata, and serialized keychain changes. The loader recomputes that
   * manifest from the actual selected response before any sync mutation. Thus
   * reproducing only the served frontier is sufficient for V3 but deliberately
   * insufficient for V4.
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
   * whose advertise hash disagrees.
   *
   * Implementers **MUST NOT** hash the full `_hashes` set either. Two
   * honest peers with the same logical document state can have DIFFERENT
   * observed-CID sets when their history depths differ (history
   * compaction, snapshot-loads that don't restore ancestors, different
   * join times), so hashing the full set creates false disagreement.
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
   * reject honest peers. Advertising the served frontier closes the gap.
   *
   * # Why this field exists at all (defense-in-depth)
   *
   * The loader's V3 primary binding is derived structurally from
   * `message.changes` / `message.snapshot` via `computeServedFrontier`.
   * V4 strengthens that check by hashing the complete response manifest as
   * described on `tipsHash`; a same-frontier payload with extra ancestors or
   * altered classifications, snapshot, or keychain data is rejected before
   * sync. In both families, `tips` remains a signed defense-in-depth
   * attestation and must agree with the structurally derived frontier.
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
   *     based on sync history, making the hash history-dependent.
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
   * Control-log and group-state commitments bound to V4 initial-load
   * responses and security-aware quorum advertisements. The advertised digest
   * combines this tuple/frontier commitment with the canonical complete
   * response-manifest digest. The strict JSON wire codec preserves `epoch` as
   * an unsigned decimal string and rejects unknown or malformed fields.
   */
  loadSecurityState?: LoadSecurityCommitments;

  /**
   * Exact echo of the requester's fresh V4 initial-load challenge. Required on
   * security-aware advertisements and full/snapshot responses and covered by
   * the writer envelope signature. Legacy V3 messages omit it.
   */
  loadChallenge?: Uint8Array;

  /**
   * Signature of the sync message.
   */
  signature?: string;
};
