/**
 * Document  is just for opening documents right now
 * @remarks
 *   A document is part of a Swarm.
 *   Document keys are attached to a single document.
 */

import { pipe } from 'it-pipe';
import { Libp2p } from 'libp2p';
import { Peerborne, MAX_DOCUMENT_PATH_LENGTH } from './peerborne.js';
import {
  concatUint8Arrays,
  firstTrue,
  readUint8Iterable,
  shuffleArray,
} from './utils.js';
import { wrapStream } from './stream-adapter.js';
import { CRDTProvider } from './crdt-provider.js';
import { AuthProvider, requireSerializePublicKey } from './auth-provider.js';
import {
  CRDTChangeNode,
  crdtChangeNodeDeferred,
  CRDTChangeNodeKind,
  crdtDocumentChangeNode,
  crdtReaderChangeNode,
  crdtWriterChangeNode,
} from './crdt-change-node.js';
import {
  collectReferencedAncestors,
  collectAllCidsInTree,
  computeServedFrontier,
  stripInlineChanges,
  MAX_CROSS_LINKS,
  MAX_RECENT_TIPS,
  mergeRemoteSyncTree,
  RecentTip,
  selectCrossLinks,
  trackTipInList,
  treeContainsCid,
} from './merkle-cross-links.js';
import { CRDTSyncMessage } from './crdt-sync-message.js';
import { ChangesSerializer } from './changes-serializer.js';
import { SyncMessageSerializer } from './sync-message-serializer.js';
import { evaluateBeeKEMWelcome } from './beekem-welcome-handler.js';
import { validateAndExportKemKeyPair } from './kem-key-pair.js';
import {
  eciesSeal,
  eciesOpen,
  importEciesPublicKey,
  ECIES_P256_PUBLIC_KEY_LENGTH,
} from './ecies.js';
import {
  beekemPathUpdateV1,
  beekemWelcomeV1,
  documentKeyUpdateV2,
  documentLoadV3,
  snapshotLoadV3,
  tipAdvertiseV1,
} from './wire-protocols.js';
import { BeeKEM } from './beekem/beekem.js';
import { BeeKEMWelcome, PathUpdate } from './beekem/types.js';
import {
  deserializePathUpdateFromWire,
  serializePathUpdateForWire,
} from './path-update-wire.js';
import {
  decodeWelcomeSealedPayload,
  encodeWelcomeSealedPayload,
} from './welcome-sealed-payload.js';
import {
  deriveDocumentKeyFromRootSecret,
  deriveEpochIdFromRootSecret,
} from './derive-doc-key.js';
import { tipsHash, tipsHashToHex, TIPS_HASH_LENGTH } from './tips-hash.js';
import {
  constantTimeHexEquals,
  dedupePeersByPeerId,
  LoadQuorumFailedError,
} from './load-quorum.js';
import { runLoadQuorum } from './load-quorum-orchestrator.js';
import { CRDTSnapshotNode } from './snapshot-node.js';
import { CompactionConfig, defaultCompactionConfig } from './compaction-config.js';
import {
  filterDeletableCIDs,
  loadChangeBlock as lazyLoadChangeBlock,
} from './blockstore-gc.js';
import { documentTopic } from './document-topic.js';
import { ACLProvider } from './acl-provider.js';
import { KeychainProvider } from './keychain-provider.js';
import { keychainHistorySinceOrFull } from './keychain.js';
import { LoadMessageSerializer } from './load-request-serializer.js';
import { CRDTLoadRequest } from './crdt-load-request.js';
import { Base64 } from 'js-base64';
import { Uint8ArrayList } from 'uint8arraylist';
import { CID } from 'multiformats';
import { UnixFS, unixfs } from '@helia/unixfs';
// libp2p v3 moved the `PubSubBaseProtocol` shim out of `@libp2p/pubsub` (the
// package has been removed). Use the concrete `GossipSub` service interface
// from `@libp2p/gossipsub` instead -- it is what `helia` actually wires up via
// `services.pubsub` and exposes the same publish/subscribe/event surface we
// rely on. `Message` (the pubsub message shape) likewise moved here.
import { TopicValidatorResult } from '@libp2p/gossipsub';
import type { GossipSub, Message } from '@libp2p/gossipsub';
import { EventHandler, PeerId } from '@libp2p/interface';

/**
 * Constant-time byte-array equality. Used by the BeeKEM PathUpdate
 * receive path to compare epoch IDs without leaking which prefix
 * matched. Returns `false` for mismatched lengths (also in constant
 * time across same-length inputs).
 */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Controls what historical data new members receive when joining a document.
 *
 * - `current_only` (default): New member receives only a CRDT state snapshot.
 *   No historical epoch keys are included. Most private option.
 * - `full_history`: All epoch keys included in Welcome message.
 *   Suitable for audit trails and regulatory compliance.
 * - `since_invited`: Epoch keys from the invitation epoch onward.
 *   Partial history access.
 */
export type HistoryVisibility = 'current_only' | 'full_history' | 'since_invited';

/**
 * Handler type for local-change (changes made on the current computer) and remote-change (changes made by a remote peer) events.
 *
 * Subscribe functions that match this type signature to track local-change/remote-change events.
 */
export type PeerborneDocumentChangeHandler<DocType, PublicKey> = (
  current: DocType,
  readers: PublicKey[],
  writers: PublicKey[],
  hashes: string[],
) => void;

/**
 * A peerborne "document" represents a single CRDT document.
 *
 * A new peerborne document undergoes the following process when it is first opened:
 * - Connect to the document pubsub topic
 * - Send a load-document request to any peer (and keep trying with different peers if one fails) (`.load()`)
 * - Use load-document response from peer (if any) to update existing document with any new hashes (`.sync()`)
 *
 * A new local change (made on the current computer) causes the following:
 * - The delta between the current document and the new document is calculated
 * - A sync message is constructed and sent to all peers on the document pubsub topic (`.change(...)`)
 *
 * A new remote change (made on a peer's computer) causes the following:
 * - New change hashes are used to update exising document with any new changes (`.sync()`)
 *
 * Any edits made to the document should go through its corresponding PeerborneDocument's
 * `.change(...)` method:
 *
 * @example Automerge usage
 * ```ts
 * // Open a document (Automerge-based peerborne instance).
 * const doc1 = peerborne.doc("/my-doc1-path");
 * await doc1.open();
 *
 * await doc1.change(doc => {
 *   doc.field1 = "new-value";
 * });
 * ```
 *
 * @example Yjs usage
 * ```ts
 * // Open a document (Yjs-based peerborne instance).
 * const doc2 = peerborneYjs.doc("/my-doc2-path");
 * await doc2.open();
 *
 * await doc2.change(doc => {
 *   doc.getMap('data').set('field1', 'new-value');
 * });
 * ```
 * @typeParam DocType The CRDT document type
 * @typeParam ChangesType A block of CRDT change(s)
 * @typeParam ChangeFnType A function for applying changes to a document
 * @typeParam PrivateKey The type of secret key used to identify a user (for writing)
 * @typeParam PublicKey The type of key used to identify a user publicly
 * @typeParam DocumentKey The type of key used to encrypt/decrypt document changes
 */

/**
 * Maximum size (in bytes) of a `tipAdvertiseV1` probe response read. A
 * legitimate response is a single encrypted `CRDTSyncMessage` carrying
 * the `documentId` (pre-encryption path of up to `MAX_DOCUMENT_PATH_LENGTH`
 * bytes; this is BIGGER than the tipsHash + signature payload combined),
 * a 32-byte `tipsHash`, and an optional writer signature.
 *
 * Bound derivation:
 *   - documentId: up to `MAX_DOCUMENT_PATH_LENGTH` bytes UTF-8.
 *   - JSON framing + Base64 expansion of the encrypted body: ~256 bytes.
 *   - Writer signature: ECDSA P-384 ≈ 96 raw bytes, Base64 ≈ 128 bytes,
 *     plus the field's JSON key/quotes — round to 256 bytes.
 *   - tipsHash: 32 raw bytes → Base64 ≈ 44 bytes.
 *   - AES-GCM nonce: 12 raw bytes → Base64 ≈ 16 bytes.
 *   - AES-GCM auth tag: 16 bytes.
 *   - Plus slack for the encrypted-payload header (keyID prefix) and any
 *     additional JSON overhead.
 *
 * The previous 2 KiB cap was tighter than `MAX_DOCUMENT_PATH_LENGTH`
 * alone, so a document opened at a maximal path would always blow the cap
 * and be recorded as a non-vote — quorum would never pass for such
 * documents. 6 KiB comfortably covers a maximum-length path plus all of
 * the overheads above while still bounding what a malicious peer can
 * force the loader to buffer before being rejected as a non-vote.
 * See PR #284 r4/r5 Copilot review.
 */
const MAX_TIP_ADVERTISE_RESPONSE_SIZE = 6 * 1024;

/**
 * Bound on the number of parallel Helia `blockstore.get(cid)` fetches
 * issued by the quorum-bound load pre-fetch (`_sendLoadRequestAndSync`).
 *
 * A bound is needed because the served `changes` tree can be large
 * under an adversary-shaped response (the agreeing peer voted for the
 * expected frontier but stuffed the tree with many additional CIDs that
 * must still be retrieved to satisfy the post-sync coverage check).
 * Without a cap, the prefetch would issue every fetch in parallel and
 * each fetch holds a libp2p bitswap stream + buffers the retrieved
 * payload via `readUint8Iterable`; for very large responses this can
 * exhaust per-connection stream quotas and pressure memory. The cap is
 * chosen large enough to overlap WAN-latency-bound bitswap fetches and
 * keep the load fast (8 inflight is comfortably more than typical mesh
 * peer counts) but small enough to bound peak resource use on the
 * loader. See PR #284 r24 Copilot review.
 */
const LOAD_PREFETCH_MAX_CONCURRENCY = 8;

/**
 * Module-private sentinel thrown by `_sendLoadRequestAndSync` when the
 * quorum frontier binding check fails on a single peer's load response
 * (either the responder omitted `tips` or the served `tips` hashed to a
 * value other than the agreed `winningHashHex`). Caught by the `load()`
 * loop, which records the failure against the responsible peer and
 * proceeds to the NEXT peer in the agreeing cohort.
 *
 * Critical to the DoS fix from PR #284 r6: previously
 * `_sendLoadRequestAndSync` threw `LoadQuorumFailedError` on bind
 * mismatch and `load()` re-raised it, aborting the entire load. A
 * single malicious peer in the agreeing cohort could vote for the
 * majority hash (passing quorum) and then serve a mismatched full load
 * (failing the bind check), unilaterally preventing the loader from
 * trying any other honest agreeing peer.
 *
 * Public callers never see this type; `load()` catches it internally
 * and only escalates to `LoadQuorumFailedError(reason:
 * 'bind-check-failed-all-agreeing-peers')` once EVERY peer in the
 * narrowed cohort has bind-failed.
 *
 * The `advertisedHex` field carries the hash the responder's served
 * `tips` actually hashed to (or the sentinel `'(missing tips)'` when the
 * response omitted the `tips` field entirely) so the outer loop can
 * thread it into the final error's `agreeingPeerBindFailures` map.
 */
class _QuorumBindCheckFailedError extends Error {
  public readonly advertisedHex: string;
  constructor(advertisedHex: string, message: string) {
    super(message);
    this.name = '_QuorumBindCheckFailedError';
    this.advertisedHex = advertisedHex;
  }
}

export class PeerborneDocument<
  DocType,
  ChangesType,
  ChangeFnType,
  PrivateKey,
  PublicKey,
  DocumentKey,
> {
  /**
   * CORE STATE ===============================================================
   */

  // Only store/cache the full automerge document.
  private _document: DocType;
  get document(): DocType {
    return this._document;
  }

  // Document readers ACL.
  private _readers;

  // Document writers ACL.
  private _writers;

  // Cached snapshot of `_writers.users()` for hot-path signature verification.
  // Document-scoped (not per-DAG-node): every signature check needs the current
  // trusted writer set, so a single lazy cache is sufficient. Invalidated by
  // bumping `_writerKeysVersion` whenever `_writers` is mutated via
  // `_mergeWriters` / `_addWriter` / `_removeWriter`. All ACL mutations must
  // go through those helpers. The version counter is what makes invalidation
  // race-safe: `_getWriterKeys` captures the version before awaiting and only
  // commits the result if the version is still current, so an in-flight fetch
  // that races with an invalidation cannot overwrite the new null state with
  // a stale list (which could otherwise admit signatures from a revoked writer).
  // Typed `ReadonlyArray` so an accidental mutation by an internal caller is
  // a type error rather than a silent cache corruption that would affect
  // later signature verification.
  private _cachedWriterKeys: ReadonlyArray<PublicKey> | null = null;
  private _writerKeysVersion = 0;
  // Counter of in-flight `_writers` mutations (add/remove/merge). Some ACL
  // implementations (e.g. UCANACL.remove, YjsACL.remove) mutate their
  // backing state *before* their returned Promise resolves, so during the
  // mutation window `_writers.users()` may already reflect the new state
  // even though the helper has not yet reached its post-await invalidation
  // line. While this counter is nonzero, `_getWriterKeys` bypasses the
  // cache entirely and always re-fetches, so a signature check that races
  // a mutation cannot observe the stale pre-mutation list.
  private _writerMutationsInFlight = 0;

  // List of document encryption keys. Lower index numbers mean more recent.
  // Since the document is created from change history, all keys are needed.
  private _keychain;

  // Controls what historical data new members receive when joining.
  private _historyVisibility: HistoryVisibility = 'current_only';

  // Tracks the epoch at which this node was invited to the document.
  // Used by `since_invited` history visibility (`_keychainChangesForVisibility`)
  // to filter keychain history. Set by `handleBeeKEMWelcomeRequestData` when
  // this node receives a Welcome message from an inviting writer; remains
  // `undefined` for the founding member of a document (who has no
  // invitation epoch).
  private _invitationEpoch: Uint8Array | undefined;

  // Pending BeeKEM Welcomes parked while the recipient is not yet a reader.
  //
  // KNOWN RACE: the inviter publishes
  // the readers-ACL update over pubsub and sends the Welcome over a
  // direct libp2p stream. The Welcome can arrive before the ACL update
  // has been applied on the recipient; without buffering, the
  // `not-in-readers-acl` gate in `evaluateBeeKEMWelcome` would drop the
  // Welcome permanently because `_sendBeeKEMWelcome` is fire-and-forget
  // (no retry / no ack). Buffering closes the race: when a Welcome is
  // dropped solely because the local user is not yet a reader, we park
  // it here keyed by hex(welcomeEpochId), and re-evaluate buffered
  // Welcomes after every readers-ACL `merge` (`_drainPendingWelcomes`).
  //
  // Bounding:
  //  - `_PENDING_WELCOMES_MAX_ENTRIES` (16): caps memory usage so a
  //    flood of misaddressed or hostile Welcomes cannot grow the buffer
  //    without bound. Older entries are evicted in insertion order
  //    (Map iteration order) when the bound is reached.
  //  - `_PENDING_WELCOMES_TTL_MS` (5 min): caps how long any Welcome
  //    sits unresolved. Entries past their TTL are discarded on the
  //    next drain attempt. Five minutes is well above the worst-case
  //    GossipSub mesh propagation we observe in `e2e/integration/`
  //    (~10s through a relay) while remaining short enough that stale
  //    Welcomes don't linger indefinitely after a legitimate
  //    re-invite.
  //
  // The key is the lower-case hex encoding of `welcomeEpochId` (a
  // `Uint8Array`), chosen so the buffer's identity matches the
  // canonical epoch identifier used elsewhere in the receive path and
  // so duplicate Welcomes (same epoch) coalesce automatically.
  private _pendingWelcomes = new Map<
    string,
    { message: CRDTSyncMessage<ChangesType, PublicKey>; bufferedAtMs: number }
  >();
  private static readonly _PENDING_WELCOMES_MAX_ENTRIES = 16;
  private static readonly _PENDING_WELCOMES_TTL_MS = 5 * 60 * 1000;

  // Recipient-side ECIES (P-256 ECDH) key pair for opening BeeKEM Welcome
  // sealed payloads. The inviter sends `eciesSealed` -- the keychain delta
  // encrypted to this public key (see `_sendBeeKEMWelcome`); the recipient
  // opens it with the matching private key (see
  // `_evaluateAndApplyBeeKEMWelcome`). When `undefined`, sealed Welcomes
  // addressed to us cannot be opened and are dropped (the recipient must
  // fall back to a fresh document load against an authorized peer). The
  // application is responsible for plumbing in a stable KEM key pair via
  // `setKemKeyPair` and sharing the matching raw public key with inviters
  // out-of-band so they can pass it to `addReader`.
  private _kemKeyPair: CryptoKeyPair | undefined;

  // Cached raw SEC1-uncompressed bytes for `_kemKeyPair.publicKey`,
  // populated eagerly inside `setKemKeyPair` so the receive path
  // (`_evaluateAndApplyBeeKEMWelcome`) never has to await an `exportKey`
  // call -- and so a non-exportable public key surfaces as a clear
  // error at installation time rather than as a generic WebCrypto
  // exception inside the Welcome handler.
  private _kemPublicKeyRaw: Uint8Array | undefined;

  /**
   * Install the recipient-side ECDH (P-256) key pair used to open
   * incoming BeeKEM Welcome sealed payloads. The application is
   * responsible for persisting and re-supplying this key pair across
   * sessions; the matching raw public key (see
   * `getKemPublicKeyRaw`) must be communicated out-of-band to any
   * writer who will invite this user, so they can pass it to
   * `addReader(reader, readerKemPublicKey)`.
   *
   * Idempotent: calling with the same key pair more than once is
   * fine. Pass `undefined` to clear (subsequent Welcomes will be
   * dropped).
   *
   * Validation: the key pair MUST be an ECDH P-256 pair, and the
   * private key MUST have `'deriveBits'` in its key usages so
   * `eciesOpen` can perform the ECDH step. The public key MUST be
   * raw-exportable (the inviter-side flow ships those bytes as the
   * `welcomeRecipientKemPublicKey` field). Mismatches are rejected
   * here with a descriptive error rather than silently accepted and
   * surfaced as a generic WebCrypto failure later in the Welcome
   * receive path.
   *
   * Async because it eagerly exports the public key to raw bytes via
   * `crypto.subtle.exportKey` and caches them for the receive path.
   */
  public async setKemKeyPair(
    keyPair: CryptoKeyPair | undefined,
  ): Promise<void> {
    if (keyPair === undefined) {
      this._kemKeyPair = undefined;
      this._kemPublicKeyRaw = undefined;
      return;
    }

    // Algorithm/curve/usages validation + eager raw-export, kept in
    // a standalone helper so the validation surface can be unit-tested
    // without standing up the full document dependency graph.
    // Throws a clear, install-time error on misconfiguration.
    const rawPublic = await validateAndExportKemKeyPair(keyPair);

    this._kemKeyPair = keyPair;
    // Defensive copy: ensure the cached bytes are isolated from the
    // buffer returned by the helper so callers (and the helper's own
    // internal state) cannot mutate `_kemPublicKeyRaw` after the fact.
    this._kemPublicKeyRaw = new Uint8Array(rawPublic);
  }

  /**
   * Returns the raw SEC1-uncompressed bytes (65 bytes) of the
   * installed ECDH public key, or `undefined` if no key pair has been
   * set via `setKemKeyPair`. The bytes are what inviters pass to
   * `addReader(reader, readerKemPublicKey)`.
   *
   * The raw bytes are cached on `setKemKeyPair`, so this is a
   * synchronous lookup. A defensive copy of the cached `Uint8Array` is
   * returned so callers cannot accidentally mutate the document's
   * internal state (e.g. `raw[0] = ...`), which would otherwise cause
   * hard-to-debug Welcome drops/mismatches on the receive path.
   */
  public getKemPublicKeyRaw(): Uint8Array | undefined {
    return this._kemPublicKeyRaw && new Uint8Array(this._kemPublicKeyRaw);
  }

  // BeeKEM ratchet-tree state for cryptographic reader revocation.
  //
  // `removeReader` blanks the removed reader's BeeKEM leaf, re-keys the
  // path, and broadcasts a `PathUpdate` over `beekemPathUpdateV1`.
  // Surviving readers feed the update into `processPathUpdate` and
  // re-derive the document encryption key from the fresh root secret
  // (see `derive-doc-key.ts`). The removed reader's leaf is blanked,
  // so they cannot recompute the root secret -- this closes the
  // revocation-latency gap of the previous "encrypt the new key under
  // the old key" rotation scheme.
  //
  // The tree is initialized in one of two ways:
  //
  //  1. **Founder**: a writer who creates a new document calls
  //     `_initializeBeeKEMAsFounder()` (driven by `addReader` the first
  //     time it runs on a fresh document, or eagerly by a future
  //     "create document" API). This seeds leaf 0 with the local KEM
  //     key pair from `setKemKeyPair`.
  //
  //  2. **Joiner**: a peer that receives an `eciesSealed` BeeKEM
  //     Welcome from an inviting writer calls `processWelcome` on a
  //     fresh `BeeKEM` instance, populating their leaf and the path
  //     keys from the inviter's tree state.
  //
  // The PathUpdate receive handler MUST NOT initialize a fresh founder
  // tree on a peer that has not gone through either path: a
  // freshly-initialized tree would produce a different root secret
  // than the writer's, and the epoch-ID mismatch gate would drop the
  // PathUpdate anyway. Surface that as a clean drop-with-warning so a
  // future fresh document-load can recover keychain state.
  private _beekem: BeeKEM | null = null;
  private _beekemInitPromise: Promise<BeeKEM> | null = null;
  // `true` iff `_beekem` was set via `_initializeBeeKEMAsFounder` or
  // `processWelcome`. Distinguishes a legitimate local BeeKEM state
  // from "we have never received a Welcome and we are not the
  // founder", which is the gate `handleBeeKEMPathUpdateRequestData`
  // uses to drop PathUpdates that arrive before bootstrap.
  private _beekemInitialized = false;

  // pubkey (serialized) -> BeeKEM leaf index, populated by `addReader`
  // (writer side) so `removeReader` can look up the leaf to blank.
  // **Fast-path cache only**: `removeReader` falls back to a BeeKEM
  // tree scan (`BeeKEM.findLeafByPublicKey`) on cache miss, so a cache
  // wipe (in-process restart, different replica) does not block
  // revocation as long as the BeeKEM tree itself is initialized and
  // the reader's KEM public key is still known (see
  // `_readerKemPublicKeys`).
  // Joiner-side population requires Welcome plumbing that is out of
  // scope here and tracked alongside the BeeKEM Welcome work.
  private _readerLeafIndices = new Map<string, number>();

  // pubkey (serialized identity) -> raw SEC1-uncompressed P-256 ECDH
  // public key bytes (the reader's KEM public key as passed to
  // `addReader`). Used by `removeReader` as the lookup key when the
  // `_readerLeafIndices` fast-path cache misses: we know the
  // identity but need the KEM key to query the BeeKEM tree via
  // `BeeKEM.findLeafByPublicKey`. Persistence is out of scope for
  // this PR -- on a restart this map is empty and `removeReader`
  // surfaces the gap with a clear error.
  private _readerKemPublicKeys = new Map<string, Uint8Array>();

  // BeeKEM leaf node index -> the `BeeKEMWelcome` produced when that
  // leaf was first registered via `_registerBeeKEMReader`. Used by
  // `addReader` to re-emit a Welcome when a previous invitation was
  // dropped: re-invoking `addReader(reader, kemPub)` for an existing
  // reader is now a re-send, not a silent no-op.
  //
  // Cleared when the leaf is blanked via `removeReader`, so a
  // recipient that was revoked cannot later re-derive the original
  // Welcome (which would re-deliver the keychain delta at the leaf's
  // original epoch).
  //
  // In-memory only; on writer restart this map is empty and a
  // re-emit attempt will see the cache miss and the no-op early-out
  // in `_registerBeeKEMReader`. Recipients in that state should
  // recover via a fresh document load (which delivers keychain state
  // via the existing sealed-Welcome envelope or the load response).
  private _beekemWelcomeByLeaf = new Map<number, BeeKEMWelcome>();

  /**
   * Set the history visibility for this document.
   * Controls what data new members receive when they join.
   */
  public set historyVisibility(value: HistoryVisibility) {
    this._historyVisibility = value;
  }

  public get historyVisibility(): HistoryVisibility {
    return this._historyVisibility;
  }

  /**
   * /CORE STATE ==============================================================
   */

  // Last sync message (for populating load requests).
  private _lastSyncMessage?: CRDTSyncMessage<ChangesType, PublicKey>;

  // Set of already-merged change blocks.
  private _hashes = new Set<string>();

  // Set of CIDs that have been seen as a `children` key in any sync tree we
  // have processed (locally created or remotely received) -- i.e. every CID
  // some node references as a parent / cross-link target. These are
  // *referenced ancestors*: by definition they are NOT heads of the local
  // DAG, because at least one node points to them as a predecessor.
  //
  // `_currentFrontier()` returns `_hashes \ _referencedAncestors` -- the set
  // of CIDs that no node we've ever seen has referenced. That is the actual
  // "frontier" / "heads" of the merged-changes DAG, which is what the
  // initial-load quorum tip-set advertisement is supposed to attest to.
  //
  // Critically, this set converges across honest peers: two peers with the
  // same logical state but different sync histories (e.g. one loaded from a
  // snapshot, the other has been merging changes since founding) will have
  // *different* `_hashes` cardinality but the same head set, hence the same
  // `_hashes \ _referencedAncestors`. Drawing the quorum probe from
  // `_hashes` alone (the prior buggy implementation) would have made the
  // probe pessimistically diverge on irrelevant sync history.
  //
  // Populated in:
  //   - `_makeChange()`: every newly-attached `changeNode.children` key
  //     is recorded -- the new change references those parents.
  //   - `_syncDocumentChanges()`: every received sync tree is walked once
  //     and its `children` keys are recorded -- the receiver now knows the
  //     same parent relationships the sender did.
  //
  // Snapshot boundaries: when a snapshot is applied, `lastChangeNodeCID` is
  // added to `_hashes` as a sentinel for dedup, but its ancestor chain is
  // pruned -- those ancestors are not added to `_referencedAncestors`,
  // which is correct: the snapshot boundary IS the local "oldest" head
  // from the loader's view of the DAG.
  private _referencedAncestors = new Set<string>();

  // Bounded list of recently-known change CIDs paired with their node kind.
  // Used by `_makeChange()` to attach Merkle-CRDT cross-links (paper §VI.B.e)
  // in addition to the primary parent link. Cross-links improve consistency
  // and availability when peers have partial views of the DAG: a peer that
  // missed an earlier message can still discover and fetch the corresponding
  // block via a later change that references it.
  //
  // Populated by both local changes (in `_makeChange`) and remote-applied
  // changes (in `_syncDocumentChanges`), since cross-linking to a freshly-
  // received remote tip helps third peers that haven't yet received it.
  //
  // Kept small (`MAX_RECENT_TIPS`) to bound per-message overhead. Insertion-
  // ordered so the oldest entry is at index 0 and the newest at the end;
  // eviction uses `Array.prototype.shift()` (O(n) on n=`MAX_RECENT_TIPS`,
  // which is a small constant -- effectively O(1) in practice).
  private _recentTips: RecentTip[] = [];

  // Compaction state.
  private _compactionConfig: CompactionConfig;
  private _latestSnapshot?: CRDTSnapshotNode<ChangesType, PublicKey>;
  private _changesSinceSnapshot = 0;
  private _compactionInProgress = false;
  private _snapshotUnsupported = false;
  // Counts only document-kind changes (excludes ACL reader/writer changes).
  // Used by _maybeCompact() for the minChangesBeforeSnapshot threshold.
  // Incremented for both local changes (in _makeChange) and remote changes
  // (in _syncDocumentChanges). Compaction triggers from both paths, so relay-only
  // nodes that never make local changes will still compact via remote change processing.
  private _documentChangeCount = 0;

  // Handler for listening for sync messages on the document topic. Is `undefined` until
  // the document is `.open()`-ed.
  private _pubsubHandler: EventHandler<CustomEvent<Message>> | undefined;

  // Whether this instance has successfully subscribed to the pubsub topic.
  // Used in close() to avoid unsubscribing when open() failed before subscribing,
  // which would break other instances listening on the same topic.
  private _subscribed = false;

  // Cached pubsub topic string. Initialized in constructor via _computeTopic()
  // so that callers that invoke _makeChange() before open() (e.g. via load())
  // publish to a valid topic. open() recomputes this with the configured prefix.
  private _topic: string;

  // Transaction state for batching multiple changes atomically.
  private _pendingChangeFns: ChangeFnType[] = [];
  private _inTransaction = false;
  private _committing = false;

  // Handlers registered by users of `PeerborneDocument` that fire on remote changes.
  private _remoteHandlers: {
    [id: string]: PeerborneDocumentChangeHandler<DocType, PublicKey>;
  } = {};

  // Handlers registered by users of `PeerborneDocument` that fire on local changes.
  private _localHandlers: {
    [id: string]: PeerborneDocumentChangeHandler<DocType, PublicKey>;
  } = {};

  public get libp2p(): Libp2p {
    return this.swarm.heliaNode.libp2p;
  }

  private heliaFs: UnixFS;

  constructor(
    /**
     * Peerborne swarm that this document belongs to.
     */
    public readonly swarm: Peerborne<
      DocType,
      ChangesType,
      ChangeFnType,
      PrivateKey,
      PublicKey,
      DocumentKey
    >,

    /**
     * Path of the document.
     */
    public readonly documentPath: string,

    /**
     * Private key identifying the current user.
     */
    private readonly _userKey: PrivateKey,

    /**
     * Private key identifying the current user.
     */
    private readonly _userPublicKey: PublicKey,

    /**
     * CRDTProvider handles reading/writing CRDT document data and metadata.
     */
    private readonly _crdtProvider: CRDTProvider<
      DocType,
      ChangesType,
      ChangeFnType
    >,

    /**
     * AuthProvider handles signing/verification and encryption/decryption.
     */
    private readonly _authProvider: AuthProvider<
      PrivateKey,
      PublicKey,
      DocumentKey
    >,

    /**
     * ACLProvider handles read/write ACL operations.
     */
    private readonly _aclProvider: ACLProvider<ChangesType, PublicKey>,

    /**
     * KeychainProvider handles read/write ACL operations.
     */
    private readonly _keychainProvider: KeychainProvider<
      ChangesType,
      DocumentKey
    >,

    /**
     * ChangesSerializer is responsible for serializing/deserializing CRDTChangeBlocks.
     */
    private readonly _changesSerializer: ChangesSerializer<ChangesType>,

    /**
     * SyncMessageSerializer is responsible for serializing/deserializing CRDTSyncMessages.
     */
    private readonly _syncMessageSerializer: SyncMessageSerializer<ChangesType, PublicKey>,

    /**
     * LoadMessageSerializer is responsible for serializing/deserializing CRDTLoadMessages.
     */
    private readonly _loadMessageSerializer: LoadMessageSerializer,
  ) {
    this.heliaFs = unixfs(this.swarm.heliaNode);

    this._document = this._crdtProvider.newDocument();
    this._readers = this._aclProvider.initialize();
    this._writers = this._aclProvider.initialize();
    this._keychain = this._keychainProvider.initialize();
    this._compactionConfig = {
      ...defaultCompactionConfig,
      ...(this.swarm.config?.compaction ?? {}),
    };

    // Provide a valid default topic so that _makeChange() works even before
    // open() is called (e.g. when load() triggers a change). open() will
    // recompute this with the configured prefix.
    this._topic = this._computeTopic();
  }

  // Helpers ------------------------------------------------------------------

  /**
   * Computes the pubsub topic for this document by applying the configured
   * prefix to the document path. Called once in open() to populate the
   * cached _topic field.
   */
  private _computeTopic(): string {
    const prefix = this.swarm.config?.pubsubDocumentPrefix;
    return prefix !== undefined
      ? documentTopic(this.documentPath, prefix)
      : documentTopic(this.documentPath);
  }

  private async _shuffledPeers() {
    const peers = this.swarm.heliaNode.libp2p
      .getConnections()
      ?.map((x) => x.remoteAddr);
    if (peers.length === 0) {
      return peers;
    }

    // Shuffle peer array.
    const shuffledPeers = [...peers];
    shuffleArray(shuffledPeers);
    return shuffledPeers;
  }

  private async _decryptBlock(
    blockKeyID: Uint8Array,
    nonce: Uint8Array,
    data: Uint8Array,
  ) {
    try {
      const key = this._keychain.getKey(blockKeyID);
      if (key) {
        return this._authProvider.decrypt(data, key, nonce);
      } else {
        console.warn(
          `Failed to find document key!`,
          this._hexEncode(blockKeyID),
          this._keychain,
        );
      }
    } catch (e) {
      console.warn(`Failed to decrypt block!`, e);
    }
  }

  private async _getBlock(hash: CID): Promise<ChangesType> {
    // Helia v6 / interface-blockstore v6 changed `Blockstore#get(cid)` to
    // return an `AwaitGenerator<Uint8Array>` (a generator of byte chunks)
    // rather than a single `Uint8Array`. Consume the generator into a
    // contiguous buffer here before slicing the encryption header off.
    const block = await readUint8Iterable(this.swarm.heliaNode.blockstore.get(hash));
    const blockKeyID = block.slice(0, this._keychainProvider.keyIDLength);
    const blockNonce = block.slice(
      this._keychainProvider.keyIDLength,
      this._keychainProvider.keyIDLength + this._authProvider.nonceBits,
    );
    const blockData = block.slice(
      this._keychainProvider.keyIDLength + this._authProvider.nonceBits,
    );
    const content = await this._decryptBlock(blockKeyID, blockNonce, blockData);
    if (!content) {
      throw new Error(`Failed to decrypt block (CID: ${hash})`);
    }
    return this._changesSerializer.deserializeChanges(content);
  }

  private async _putBlock(block: ChangesType): Promise<string> {
    const [documentKeyID, documentKey] = await this._keychain.current();
    if (!documentKey) {
      throw new Error(`Document ${this.documentPath} has an empty keychain!`);
    }
    const content = this._changesSerializer.serializeChanges(block);
    const { nonce, data } = await this._authProvider.encrypt(
      content,
      documentKey,
    );
    if (!nonce) {
      throw new Error(`Failed to encrypt change block! Nonce cannot be empty`);
    }
    const blockData = concatUint8Arrays(documentKeyID, nonce, data);
    const newFileResult = await this.heliaFs.addBytes(blockData);
    return newFileResult.toString();
  }

  /**
   * Walk the remote sync tree and return entries that are new relative to
   * `localHashes` / `localRootId`. Delegates to the pure `mergeRemoteSyncTree`
   * helper, which also performs per-message dedup so a cross-link CID that
   * coincides with an inline ancestor in the same sync tree is not applied
   * (or fetched + applied) twice -- see paper §VI.B.e.
   */
  private async _mergeSyncTree(
    remoteRootId: string | undefined,
    remoteRoot: CRDTChangeNode<ChangesType>,

    localRootId: string | undefined,
    localHashes: Set<string>,
  ): Promise<[string, CRDTChangeNodeKind, ChangesType | undefined][]> {
    return mergeRemoteSyncTree<ChangesType>(
      remoteRootId,
      remoteRoot,
      localRootId,
      localHashes,
    );
  }

  private async _fireRemoteUpdateHandlers(hashes: string[]) {
    for (const handler of Object.values(this._remoteHandlers)) {
      handler(
        this.document,
        await this.getReaders(),
        await this.getWriters(),
        hashes,
      );
    }
  }
  private async _fireLocalUpdateHandlers(hashes: string[]) {
    for (const handler of Object.values(this._localHandlers)) {
      handler(
        this.document,
        await this.getReaders(),
        await this.getWriters(),
        hashes,
      );
    }
  }

  private _createSyncMessage(): CRDTSyncMessage<ChangesType, PublicKey> {
    const message: CRDTSyncMessage<ChangesType, PublicKey> = {
      ...(this._lastSyncMessage || {
        documentId: this.documentPath,
      }),
    };
    return message;
  }

  /**
   * Returns this peer's structural local-DAG frontier as a plain
   * string[] of CIDs -- the heads of EVERYTHING this peer has seen.
   *
   * NOTE: this is NOT the value advertised in a `tipAdvertiseV1` probe
   * and NOT the value the responder commits to on a v3 load response.
   * Both of those use `_servedFrontier()` instead -- the heads of the
   * change tree this peer can actually ship in a single load round.
   * See `_servedFrontier()`'s docstring for why the two differ (short
   * version: a load response only carries the tree rooted at
   * `_lastSyncMessage.changeId`, so concurrent local heads that aren't
   * cross-linked into that tree don't appear in what's served).
   *
   * `_currentFrontier()` is retained for callers that need the
   * structural truth of "what heads do I have locally?" rather than
   * "what would I advertise / serve?":
   *
   *   - `_makeChange()` cross-link selection (so a new local change
   *     can reference concurrent remote heads that landed since the
   *     last cached sync message).
   *   - Diagnostics / introspection paths.
   *
   * The frontier is the set of heads of the local merged-changes DAG:
   * CIDs that this peer has seen but that no other change references
   * as a parent or cross-link target. Computed as `_hashes \
   * _referencedAncestors`. See the `_referencedAncestors` field
   * docstring for why this matters: it is the part of the local DAG
   * that converges across honest peers regardless of differing sync
   * histories or pruning levels.
   *
   * Edge cases:
   *   - Empty DAG (founding member, brand-new document): `_hashes` is
   *     empty, the returned frontier is `[]`.
   *   - Just-loaded from snapshot: `_hashes` holds the snapshot
   *     boundary CID (and any post-snapshot changes). The boundary CID
   *     is NOT in `_referencedAncestors`, so it correctly appears as a
   *     head.
   *   - Pruned ancestors: irrelevant. Pruning removes CIDs from the
   *     in-memory change tree but leaves them in `_hashes` for dedup;
   *     they were already in `_referencedAncestors`, so they remain
   *     marked as non-heads.
   *
   * Returns a fresh array so callers can't mutate internal state;
   * `tipsHash` sorts independently, so we don't sort here.
   *
   * @internal
   */
  private _currentFrontier(): string[] {
    const out: string[] = [];
    for (const cid of this._hashes) {
      if (!this._referencedAncestors.has(cid)) {
        out.push(cid);
      }
    }
    return out;
  }

  /**
   * Returns the frontier this peer would *advertise as part of a load
   * response* -- the heads of the change tree this peer can actually ship
   * in a single `documentLoadV3` / `snapshotLoadV3` round.
   *
   * # Why this is NOT the same as `_currentFrontier()`
   *
   * `_currentFrontier()` returns the heads of the local DAG (`_hashes \
   * _referencedAncestors`) -- the structural truth of EVERYTHING this peer
   * has seen. That set is the right answer for "what is the logical state
   * of my local document?", but it is the WRONG answer for "what hash
   * should I advertise in a `tipAdvertiseV1` probe?".
   *
   * A load response only carries ONE change tree (rooted at
   * `_lastSyncMessage.changeId`), plus optionally `_latestSnapshot`.
   * `_lastSyncMessage` is refreshed by `_makeChange()` (its tree is
   * rooted at *this peer's* last locally-produced change) AND by
   * `_syncDocumentChanges()` (when an incoming remote tree subsumes the
   * cached root -- the round-14 fix for relay peers that never make
   * local changes; see `_refreshLastSyncMessageFromSync()`). When the
   * incoming root is concurrent with the cached root, the cache is left
   * alone so served-frontier coverage cannot shrink; the next local
   * change re-bundles concurrent heads via cross-links from
   * `_recentTips` (`selectCrossLinks`).
   *
   * So when a peer has multiple concurrent heads (e.g. its own last local
   * change H1 plus remotely-applied changes H2, H3 that aren't yet
   * cross-linked from any local change), `_currentFrontier()` returns
   * `{H1, H2, H3}` but the load response only contains H1's subtree.
   * Round 8 of the PR #284 Copilot review caught the resulting
   * inconsistency: the tip-advertise probe would hash `{H1, H2, H3}` and
   * win the quorum vote, but the served payload's structural frontier
   * (`computeServedFrontier(...)` on the loader side) hashes only `{H1}`,
   * causing the loader's bind check to reject the honest peer.
   *
   * # What this returns
   *
   * The heads of the served payload, computed via `computeServedFrontier`
   * over EXACTLY the same inputs the load response will carry:
   *   - `_lastSyncMessage?.changeId` -- root CID of the served tree (if any);
   *   - `_lastSyncMessage?.changes` -- the served tree itself (if any);
   *   - `_latestSnapshot?.lastChangeNodeCID` -- snapshot boundary CID (if any).
   *
   * This mirrors the loader's `_sendLoadRequestAndSync` binding check:
   * both sides hash the structurally-derived served frontier, so an
   * honest responder advertises a hash the loader can reproduce from the
   * payload it received. Two honest peers in the same logical state with
   * the same `_lastSyncMessage` / `_latestSnapshot` advertise the same
   * hash regardless of any unrelated concurrent heads they happen to be
   * holding in `_currentFrontier()`.
   *
   * # Trade-off (acknowledged)
   *
   * The quorum no longer verifies that a responder has all of its
   * logical heads -- only the ones it would actually serve. A peer with
   * un-served concurrent heads can pass quorum on the subset it ships
   * via load. This matches the existing load semantics (the load only
   * ever ships what `_lastSyncMessage` covers anyway) and is reconciled
   * by post-load GossipSub sync; the alternative (Option B in the design
   * notes) would require the load response itself to carry every head's
   * subtree, a larger protocol change. See PR #284 r8 review.
   *
   * @internal
   */
  private _servedFrontier(): string[] {
    return computeServedFrontier(
      this._lastSyncMessage?.changeId,
      this._lastSyncMessage?.changes,
      this._latestSnapshot?.lastChangeNodeCID,
    );
  }

  /**
   * Record a CID as a recently-known tip for Merkle-CRDT cross-linking
   * (paper §VI.B.e). Called for both locally-generated and remote-applied
   * change nodes -- a peer A that just received B's change can cross-link
   * to it on A's next outgoing change, helping a third peer C that missed
   * B's broadcast discover the missing block. Cross-links to deferred CIDs
   * are emitted as leaf nodes with only `kind` set; the receiver fetches
   * the block from Helia when needed (see `_syncDocumentChanges`).
   *
   * Bounded to `MAX_RECENT_TIPS` entries (oldest evicted). If the CID is
   * already tracked, move it to the back so it remains a high-priority
   * cross-link candidate.
   */
  private _trackTip(cid: string, kind: CRDTChangeNodeKind): void {
    trackTipInList(this._recentTips, { cid, kind }, MAX_RECENT_TIPS);
  }

  private async _syncDocumentChanges(
    changeId: string | undefined,
    changes: CRDTChangeNode<ChangesType>,
  ) {
    // Walk the incoming sync tree once and record every CID that appears
    // as a `children` key. Those CIDs are referenced ancestors -- by
    // definition no longer heads of the local DAG. Doing this BEFORE the
    // merge keeps `_currentFrontier()` correct regardless of whether the
    // referenced parent ends up applied inline or fetched lazily from the
    // blockstore: either way, the receiver now knows the parent relationship
    // the sender had.
    //
    // Idempotent and inexpensive: the helper walks at most the size of the
    // delivered tree (bounded by the sender's compaction config); duplicates
    // are no-ops in a Set.
    collectReferencedAncestors(changeId, changes, this._referencedAncestors);

    // Only process hashes that we haven't seen yet.
    const newChangeEntries = await this._mergeSyncTree(
      changeId,
      changes,
      this._lastSyncMessage && this._lastSyncMessage.changeId,
      this._hashes,
    );

    // First apply changes that were sent directly.
    let newDocument = this.document;
    const newDocumentHashes: string[] = [];
    const newDocumentTips: Array<[string, CRDTChangeNodeKind]> = [];
    const missingDocumentHashes: [string, CRDTChangeNodeKind][] = [];
    for (const [sentHash, sentChangeKind, sentChanges] of newChangeEntries) {
      if (sentChanges) {
        switch (sentChangeKind) {
          case crdtDocumentChangeNode: {
            // Apply the changes that were sent directly.
            newDocument = this._crdtProvider.remoteChange(
              newDocument,
              sentChanges,
            );
            newDocumentHashes.push(sentHash);
            newDocumentTips.push([sentHash, sentChangeKind]);
            this._documentChangeCount++;
            this._changesSinceSnapshot++;
            break;
          }
          case crdtReaderChangeNode: {
            // Apply the changes that were sent directly. Use the
            // `_mergeReaders` wrapper so pending BeeKEM Welcomes are
            // drained immediately after the ACL update lands.
            this._mergeReaders(sentChanges);
            newDocumentHashes.push(sentHash);
            newDocumentTips.push([sentHash, sentChangeKind]);
            break;
          }
          case crdtWriterChangeNode: {
            // Apply the changes that were sent directly.
            this._mergeWriters(sentChanges);
            newDocumentHashes.push(sentHash);
            newDocumentTips.push([sentHash, sentChangeKind]);
            break;
          }
        }
      } else {
        missingDocumentHashes.push([sentHash, sentChangeKind]);
      }
    }
    if (newDocumentHashes.length) {
      this._document = newDocument;
      for (const newHash of newDocumentHashes) {
        this._hashes.add(newHash);
      }
      // Track applied tips for Merkle-CRDT cross-linking (paper §VI.B.e)
      // *before* firing remote update handlers. Recording remote-applied
      // CIDs lets this peer cross-link to them on its next outgoing change,
      // helping other peers that may have missed the original broadcast.
      // The ordering matters: if a handler synchronously triggers a local
      // `change()`, `_makeChange()` must see the just-received remote tips
      // in `_recentTips` to cross-link to them. This matches the ordering
      // used in the missing-block fetch path below.
      //
      // `newDocumentTips` is populated in `mergeRemoteSyncTree`'s traversal
      // order, which is root-first (the remote head is the first entry, its
      // ancestors follow). `_trackTip` appends to the back of `_recentTips`
      // with LRU semantics, so pushing in root-first order would make the
      // head the *oldest* entry -- and when more than MAX_RECENT_TIPS new
      // entries arrive in one sync, the head would be evicted first. Walk
      // in reverse so the remote head ends up at the back (most-recent),
      // matching the intent of LRU tracking.
      for (let i = newDocumentTips.length - 1; i >= 0; i--) {
        const [cid, kind] = newDocumentTips[i]!;
        this._trackTip(cid, kind);
      }
      await this._fireRemoteUpdateHandlers(newDocumentHashes);
    }

    // Then apply missing hashes by fetching them from the blockstore.
    // Track all fetch promises so we can compact only after all complete,
    // avoiding premature snapshots of incomplete state.
    const fetchPromises: Promise<void>[] = [];
    for (const [missingHash, missingHashKind] of missingDocumentHashes) {
      const cid = CID.parse(missingHash);
      fetchPromises.push(
        this._getBlock(cid)
          .then(async (missingChanges) => {
            if (missingChanges) {
              switch (missingHashKind) {
                case crdtDocumentChangeNode: {
                  this._document = this._crdtProvider.remoteChange(
                    this._document,
                    missingChanges,
                  );
                  this._hashes.add(missingHash);
                  this._documentChangeCount++;
                  this._changesSinceSnapshot++;
                  this._trackTip(missingHash, missingHashKind);
                  await this._fireRemoteUpdateHandlers([missingHash]);
                  return;
                }
                case crdtReaderChangeNode: {
                  // Go through `_mergeReaders` to drain any pending
                  // BeeKEM Welcomes parked while waiting for this ACL
                  // update.
                  this._mergeReaders(missingChanges);
                  this._hashes.add(missingHash);
                  this._trackTip(missingHash, missingHashKind);
                  await this._fireRemoteUpdateHandlers([missingHash]);
                  return;
                }
                case crdtWriterChangeNode: {
                  this._mergeWriters(missingChanges);
                  this._hashes.add(missingHash);
                  this._trackTip(missingHash, missingHashKind);
                  await this._fireRemoteUpdateHandlers([missingHash]);
                  return;
                }
              }
            } else {
              console.error(
                `Block '${missingHash}' returned nothing`,
                missingChanges,
              );
            }
          })
          .catch((err) => {
            console.error(
              'Failed to fetch missing change from blockstore:',
              missingHash,
              err,
            );
          }),
      );
    }

    // Wait for all missing block fetches to complete before checking compaction.
    // This ensures the snapshot reflects the full document state rather than
    // a partial view from incomplete fetches.
    if (fetchPromises.length > 0) {
      await Promise.all(fetchPromises);
    }

    // Refresh `_lastSyncMessage` so the served frontier reflects what we now
    // hold. Without this, a relay peer that joined via `load()` (or that has
    // only ever applied remote changes via GossipSub) would keep
    // `_lastSyncMessage` undefined and `_servedFrontier()` would return `[]`,
    // making the peer advertise `tipsHash([])` in the initial-load quorum
    // probe AND ship an empty load response. Two such relay peers would
    // agree on the empty-set hash, satisfying quorum, and an honest newcomer
    // would accept an empty document while the mesh actually had data
    // (#284 r14 Copilot review).
    //
    // We update only when the incoming tree subsumes our prior root --
    // i.e., `_lastSyncMessage.changeId` appears as a CID somewhere in the
    // received tree -- so the served-frontier coverage never shrinks. The
    // undefined-prior and same-root cases are also "subsumes" (vacuously
    // and trivially); concurrent independent roots are intentionally left
    // alone (matches the existing single-tree load semantics documented on
    // `_servedFrontier()`). The next local `_makeChange()` cross-links
    // through `_recentTips` regardless, so concurrent heads are recovered
    // on the next local write.
    this._refreshLastSyncMessageFromSync(changeId, changes);

    await this._maybeCompact();
  }

  /**
   * Update `_lastSyncMessage` so it reflects the served frontier of a
   * just-applied remote sync tree. Called by `_syncDocumentChanges()`
   * after the merge has succeeded.
   *
   * Replacement policy: only swap the cached message when the incoming
   * tree *subsumes* the prior cached root, so the served frontier the
   * loader binds against can only grow, never shrink:
   *   - `_lastSyncMessage` is `undefined` (relay peer, no local change
   *     yet): adopt the incoming directly. This is the round-14 bug case
   *     -- prior to the fix the relay peer's served frontier was empty.
   *   - prior `changeId` appears anywhere in the incoming tree (root or
   *     descendant): the incoming tree includes the prior root's coverage
   *     by construction, so it is safe to replace.
   *   - prior `changeId` is independent of the incoming tree (concurrent
   *     heads, neither subsumes the other): leave the cached message in
   *     place. The next local `_makeChange()` will bundle both heads via
   *     cross-links from `_recentTips`. This matches the trade-off
   *     documented on `_servedFrontier()` -- a load response only ever
   *     carries one tree, so accepting a single root is the existing
   *     contract.
   *
   * The cached message's `documentId` / `keychainChanges` fields are
   * preserved across the swap. Response-specific fields
   * (`signature`, `tips`, `tipsHash`) are dropped because they are
   * regenerated per-response by the load / tip-advertise handlers; leaving
   * a stale value would be misleading at best, a wire-protocol violation
   * at worst.
   *
   * Idempotent and inexpensive: the subsumption check walks the incoming
   * tree once (bounded by sender compaction config); the field-level
   * replacement is O(1) reference swaps.
   *
   * @internal
   */
  private _refreshLastSyncMessageFromSync(
    receivedChangeId: string | undefined,
    receivedChanges: CRDTChangeNode<ChangesType>,
  ): void {
    // Defensive: if the incoming carries no root CID we cannot meaningfully
    // refresh the served frontier with it. (`computeServedFrontier` will
    // produce `[]` for the resulting `_lastSyncMessage` and we would simply
    // re-introduce the empty-served-frontier bug.)
    if (!receivedChangeId) return;

    const priorChangeId = this._lastSyncMessage?.changeId;

    // Case 1: no prior cached message -- adopt the incoming. This is the
    // round-14 fix path: a relay peer with no local changes was previously
    // serving an empty payload because `_lastSyncMessage` was `undefined`.
    if (!priorChangeId) {
      this._lastSyncMessage = {
        ...(this._lastSyncMessage || { documentId: this.documentPath }),
        changeId: receivedChangeId,
        changes: receivedChanges,
        // Drop response-specific fields; they are regenerated per-response.
        signature: undefined,
        tips: undefined,
        tipsHash: undefined,
      };
      return;
    }

    // Case 2: same root -- already up to date, nothing to do. (CIDs are
    // content-addressed so equal `changeId` implies the same subtree.)
    if (priorChangeId === receivedChangeId) return;

    // Case 3: prior root is embedded in the incoming tree -- the incoming
    // subsumes the prior. Replace.
    if (treeContainsCid(receivedChangeId, receivedChanges, priorChangeId)) {
      this._lastSyncMessage = {
        ...this._lastSyncMessage!,
        changeId: receivedChangeId,
        changes: receivedChanges,
        signature: undefined,
        tips: undefined,
        tipsHash: undefined,
      };
      return;
    }

    // Case 4: concurrent / independent roots. Leave the cached message
    // alone so we do not shrink served-frontier coverage. The next local
    // `_makeChange()` cross-links via `_recentTips`, recovering both heads.
  }

  /**
   * Walk the change tree and apply only ACL (reader/writer) nodes.
   * This is a lightweight pre-pass used before snapshot verification to
   * ensure writer keys are populated without applying document changes.
   * ACL merges are idempotent, so re-applying them in the subsequent
   * full _syncDocumentChanges() call is safe.
   */
  private _applyACLFromTree(node: CRDTChangeNode<ChangesType>) {
    if (node.change) {
      if (node.kind === crdtWriterChangeNode) {
        this._mergeWriters(node.change);
      } else if (node.kind === crdtReaderChangeNode) {
        this._mergeReaders(node.change);
      }
    }
    if (node.children !== undefined && node.children !== crdtChangeNodeDeferred) {
      for (const child of Object.values(node.children)) {
        this._applyACLFromTree(child);
      }
    }
  }


  /**
   * Sanctioned wrapper around `_readers.merge` that also drains any
   * pending BeeKEM Welcomes parked by `handleBeeKEMWelcomeRequestData`
   * because the local user was not yet a reader. Centralizing the
   * post-merge drain here closes the readers-ACL / Welcome reordering
   * race regardless of which code path applied the ACL change.
   *
   * All ACL-merge call sites for the readers ACL must go through this
   * helper -- a bare `_readers.merge(...)` would silently skip the
   * drain, leaving a Welcome parked until the next merge (or TTL
   * eviction) and re-introducing the readers-ACL / Welcome reordering
   * wedge that this buffering / drain pair is designed to close.
   *
   * Drain is fire-and-forget because it must not block the synchronous
   * ACL-merge call sites (`_syncDocumentChanges`, `_applyACLFromTree`)
   * on async keychain/signature work. Errors during drain are caught
   * and logged so a bug in one buffered Welcome cannot starve the
   * receive path.
   *
   * @internal
   */
  private _mergeReaders(changes: ChangesType): void {
    this._readers.merge(changes);
    if (this._pendingWelcomes.size > 0) {
      void this._drainPendingWelcomes().catch((err) => {
        console.error(
          `Failed to drain pending BeeKEM Welcomes for ${this.documentPath}:`,
          err,
        );
      });
    }
  }

  /**
   * Whether application-level signing is enabled for this document's swarm.
   * Centralizes the `enableSigning` config check to avoid drift across many call sites.
   */
  private _isSigningEnabled(): boolean {
    return this.swarm.config?.enableSigning !== false;
  }

  /**
   * Returns the current list of authorized writer public keys, populating
   * the document-scoped cache on miss. Callers must not mutate the result.
   * The cache is invalidated by `_mergeWriters`, `_addWriter`, and
   * `_removeWriter` -- the only sanctioned mutation paths for `_writers`.
   *
   * Race-safety has two layers:
   *  - Mutation-in-flight bypass: while `_writerMutationsInFlight > 0`,
   *    skip the cache entirely. Some ACLs mutate their backing state
   *    before their `add`/`remove` Promise resolves, so the cached list
   *    can be stale even though the post-await invalidation has not yet
   *    run. Bypassing forces a fresh `users()` read each call until all
   *    mutations have finished and the cache is re-populated by a clean
   *    miss.
   *  - Version check on cache fill: capture `_writerKeysVersion` before
   *    awaiting. If the version advances mid-fetch, the fetched list
   *    reflects the *pre*-invalidation ACL and is unsafe to return --
   *    discard it and loop. The loop converges once a fetch completes
   *    with no intervening invalidation; under continuous invalidation
   *    it would spin, but invalidations are bounded (one per ACL
   *    mutation) and not adversarial.
   */
  private async _getWriterKeys(): Promise<ReadonlyArray<PublicKey>> {
    while (true) {
      if (
        this._writerMutationsInFlight === 0 &&
        this._cachedWriterKeys !== null
      ) {
        return this._cachedWriterKeys;
      }
      const versionAtStart = this._writerKeysVersion;
      const fetched = await this._writers.users();
      // Only commit to the cache if (a) the version is still current AND
      // (b) no mutations are in flight. Either condition means the fetch
      // could be racing a still-incomplete mutation; in that case return
      // the freshly fetched list to the caller but leave the cache null
      // so the next caller re-fetches.
      if (
        this._writerKeysVersion === versionAtStart &&
        this._writerMutationsInFlight === 0
      ) {
        this._cachedWriterKeys = fetched;
        return fetched;
      }
      if (this._writerKeysVersion !== versionAtStart) {
        // Version advanced during fetch -- the fetched list reflects the
        // pre-invalidation ACL. Discard it and retry with the post-
        // invalidation state to avoid handing a stale list to signature
        // verification.
        continue;
      }
      // Mutation still in flight but version unchanged: the fetched list
      // reflects whatever the ACL exposed at this moment, which is the
      // best the caller can get. Don't cache (so subsequent reads see
      // the post-mutation state once it lands), but return the value.
      return fetched;
    }
  }

  /** Bump the writer-keys version so any in-flight `_getWriterKeys` aborts
   *  its assignment, and clear the cache for the next caller. */
  private _invalidateWriterKeyCache(): void {
    this._cachedWriterKeys = null;
    this._writerKeysVersion++;
  }

  /**
   * Run a writer-ACL mutation under a guard that closes the gap between
   * "underlying ACL state has changed" and "_getWriterKeys reflects the
   * change." We invalidate the cache *before* the mutation (so any
   * concurrent `_getWriterKeys` re-fetches against whatever state the
   * ACL exposes at that moment) AND set a mutation-in-flight flag that
   * forces `_getWriterKeys` to bypass the cache entirely while the
   * mutation runs. Both bookkeeping operations live in the prelude/
   * finally so they cannot drift out of sync with the underlying call.
   */
  private async _runWriterMutation<T>(op: () => Promise<T> | T): Promise<T> {
    this._writerMutationsInFlight++;
    this._invalidateWriterKeyCache();
    try {
      return await op();
    } finally {
      this._writerMutationsInFlight--;
      // Invalidate again post-mutation: the underlying ACL is now
      // authoritative and any value that landed in the cache during the
      // window must be discarded. Idempotent and cheap.
      this._invalidateWriterKeyCache();
    }
  }

  /** Apply a writer ACL change and invalidate the cached key list. */
  private _mergeWriters(changes: ChangesType): void {
    // Synchronous mutation: increment-mutate-decrement around the
    // `merge()` call so any concurrent `_getWriterKeys` running on
    // another microtask sees the in-flight flag. Both invalidations
    // (pre and post) match the async helper's behavior.
    this._writerMutationsInFlight++;
    this._invalidateWriterKeyCache();
    try {
      this._writers.merge(changes);
    } finally {
      this._writerMutationsInFlight--;
      this._invalidateWriterKeyCache();
    }
  }

  /** Add a writer and invalidate the cached key list. */
  private async _addWriter(publicKey: PublicKey): Promise<ChangesType> {
    return this._runWriterMutation(() => this._writers.add(publicKey));
  }

  /** Remove a writer and invalidate the cached key list. */
  private async _removeWriter(publicKey: PublicKey): Promise<ChangesType> {
    return this._runWriterMutation(() => this._writers.remove(publicKey));
  }

  private async _verifyWriterSignature(raw: Uint8Array, signature: string) {
    if (!this._isSigningEnabled()) {
      return true;
    }

    const writerKeys = await this._getWriterKeys();
    // Short-circuit: with no writers, no signature can verify. Avoids the
    // base64 decode for an unverifiable input.
    if (writerKeys.length === 0) {
      return false;
    }
    // Malformed base64 throws inside js-base64. A bad signature must surface
    // as a verification failure, not an exception -- the topic validator path
    // turns thrown errors into Ignore (effectively dropping the message
    // silently), which is a DoS surface for malformed input. Treat decode
    // failure as `false`.
    let signatureBytes: Uint8Array;
    try {
      signatureBytes = this._deserializeSignature(signature);
    } catch {
      return false;
    }
    const verificationTasks: Promise<boolean>[] = [];
    for (const writerKey of writerKeys) {
      verificationTasks.push(
        this._authProvider.verify(raw, writerKey, signatureBytes),
      );
    }
    return firstTrue(verificationTasks);
  }

  /**
   * Verify a snapshot signature by trying all authorized writers.
   * Unlike sync message signatures (which are string-encoded), snapshot
   * signatures are raw Uint8Array. This avoids depending on the snapshot's
   * embedded publicKey field which may not survive serialization for all
   * key types (e.g. CryptoKey).
   */
  private async _verifySnapshotSignature(payload: Uint8Array, signature: Uint8Array) {
    if (!this._isSigningEnabled()) {
      return true;
    }

    const writerKeys = await this._getWriterKeys();
    const verificationTasks: Promise<boolean>[] = [];
    for (const writerKey of writerKeys) {
      verificationTasks.push(
        this._authProvider.verify(payload, writerKey, signature),
      );
    }
    return firstTrue(verificationTasks);
  }

  private async _signAsWriter(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
  ): Promise<string> {
    if (!this._isSigningEnabled()) {
      return '';
    }

    return this._signAsWriterUnconditional(message);
  }

  /**
   * Sign a sync message as a writer **regardless of the swarm-wide
   * `enableSigning` config**. Used exclusively by paths that always
   * require writer-auth (currently BeeKEM Welcomes); see
   * `_signWelcomeAsWriter` below.
   *
   * SECURITY: callers that go through `_signAsWriter` should keep doing
   * so -- it preserves the existing `enableSigning` toggle for normal
   * sync-message signing. Only paths that have a documented "writer-auth
   * is mandatory" requirement should use the unconditional variant.
   */
  private async _signAsWriterUnconditional(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
  ): Promise<string> {
    const { signature: oldSignature, ...messageWithoutSignature } = message;

    const raw = this._syncMessageSerializer.serializeSyncMessage(
      messageWithoutSignature,
    );
    const rawSignature = await this._authProvider.sign(raw, this._userKey);
    return this._serializeSignature(rawSignature);
  }

  /**
   * Sign a BeeKEM Welcome as a writer. Unlike `_signAsWriter`, this is
   * NOT gated on the swarm-wide `enableSigning` config: Welcomes are
   * always writer-authenticated, regardless of whether document-change
   * signing is enabled (see `beekem-welcome-handler.ts` for the receive
   * side and the SECURITY NOTE there for the threat model).
   */
  private async _signWelcomeAsWriter(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
  ): Promise<string> {
    return this._signAsWriterUnconditional(message);
  }

  /**
   * Verify a writer signature on a BeeKEM Welcome. Unlike
   * `_verifyWriterSignature`, this is NOT gated on the swarm-wide
   * `enableSigning` config -- Welcomes are always writer-authenticated.
   */
  private async _verifyWelcomeWriterSignature(
    raw: Uint8Array,
    signature: string,
  ): Promise<boolean> {
    const writerKeys = await this._getWriterKeys();
    if (writerKeys.length === 0) {
      return false;
    }
    let signatureBytes: Uint8Array;
    try {
      signatureBytes = this._deserializeSignature(signature);
    } catch {
      return false;
    }
    const verificationTasks: Promise<boolean>[] = [];
    for (const writerKey of writerKeys) {
      verificationTasks.push(
        this._authProvider.verify(raw, writerKey, signatureBytes),
      );
    }
    return firstTrue(verificationTasks);
  }

  private _encoder = new TextEncoder();

  private _deserializeSignature(signature: string): Uint8Array {
    return Base64.toUint8Array(signature);
  }

  private _serializeSignature(signature: Uint8Array): string {
    return Base64.fromUint8Array(signature);
  }

  private async _makeChange(
    changes: ChangesType,
    kind: CRDTChangeNodeKind = crdtDocumentChangeNode,
  ) {
    // Store changes in blockstore.
    const hash = await this._putBlock(changes);
    this._hashes.add(hash);

    // Send new message.
    let updateMessage = this._createSyncMessage();
    const changeNode: CRDTChangeNode<ChangesType> = { kind, change: changes };
    const primaryParentId = updateMessage.changeId;
    if (primaryParentId && updateMessage.changes) {
      // Primary back-pointer: include the previous head's subtree inline so
      // peers can apply our change without an extra round-trip for the parent.
      changeNode.children = {};
      changeNode.children[primaryParentId] = updateMessage.changes;

      // Cross-links (Merkle CRDT paper §VI.B.e): additionally reference other
      // recent tips so a peer who missed an intermediate message can still
      // discover the missing CID via a later message. Cross-link entries
      // are emitted as *deferred* nodes (no `change` payload, no `children`)
      // -- they carry only the CID + kind. Receivers that don't already have
      // the block trigger a blockstore fetch in `_syncDocumentChanges`.
      // Receivers that already have the block treat the entry as a no-op
      // (deduplicated via `_hashes`).
      const crossLinkTips = selectCrossLinks(
        this._recentTips,
        primaryParentId,
        hash,
        MAX_CROSS_LINKS,
      );
      for (const tip of crossLinkTips) {
        // Skip if the tip is already a direct child of the new change node.
        if (changeNode.children[tip.cid]) continue;
        // Deferred leaf: no `change` payload, no `children`. Receivers fetch
        // the block from Helia if they don't already have it.
        changeNode.children[tip.cid] = { kind: tip.kind };
      }
    }
    updateMessage.changeId = hash;
    updateMessage.changes = changeNode;

    // Record every CID this new change references as a parent / cross-link
    // target. The primary parent and all cross-link tips become *referenced
    // ancestors* and drop out of `_currentFrontier()`. Walks just the new
    // `changeNode` (not the full inherited subtree below it) because the
    // inherited subtree's ancestor relationships were already recorded
    // when each of those nodes was created or applied.
    if (changeNode.children) {
      for (const childCid of Object.keys(changeNode.children)) {
        this._referencedAncestors.add(childCid);
      }
    }

    // Track this new tip for future cross-linking. The primary parent is
    // also retained -- it's the immediate predecessor of *this* tip and may
    // still be useful as a cross-link target for the *next* change if a
    // later remote sync arrives in between.
    this._trackTip(hash, kind);

    // Sign new message.
    updateMessage.signature = await this._signAsWriter(updateMessage);

    this._lastSyncMessage = updateMessage;
    const serializedUpdate =
      this._syncMessageSerializer.serializeSyncMessage(updateMessage);

    // Encrypt sync message.
    const [documentKeyID, documentKey] = await this._keychain.current();
    if (!documentKey) {
      throw new Error(`Document ${this.documentPath} has an empty keychain!`);
    }
    const { nonce, data } = await this._authProvider.encrypt(
      serializedUpdate,
      documentKey,
    );
    if (!nonce) {
      throw new Error(`Failed to encrypt sync message! Nonce cannot be empty`);
    }
    await this.swarm.heliaNode.libp2p.services.pubsub.publish(
      this._topic,
      concatUint8Arrays(documentKeyID, nonce, data),
    );

    // Fire change handlers.
    await this._fireLocalUpdateHandlers([hash]);

    // Track document changes for compaction.
    if (kind === crdtDocumentChangeNode) {
      this._documentChangeCount++;
      this._changesSinceSnapshot++;
      await this._maybeCompact();
    }
  }

  /**
   * Returns the keychain changes to include in a load response based on
   * the document's history visibility setting.
   *
   * `since_invited` requires `_invitationEpoch` to be set (typically by the
   * BeeKEM Welcome flow when the local node joined). When it is unset --
   * e.g. for the original group creator that never received a Welcome --
   * the call falls back to `current_only` semantics rather than full
   * history. The intent of `since_invited` is to bound what *new joiners*
   * receive; emitting the full keychain whenever the local boundary is
   * unknown undermines that goal (and leaks every prior epoch to any
   * peer the local node responds to). Operators that genuinely want
   * founders to share full history should configure the document with
   * `historyVisibility: 'full_history'` explicitly.
   */
  private async _keychainChangesForVisibility(): Promise<ChangesType> {
    switch (this._historyVisibility) {
      case 'full_history':
        // Send ALL epoch keys -- for audit trails and regulatory compliance.
        return this._keychain.history();
      case 'since_invited':
        if (this._invitationEpoch === undefined) {
          // No recorded invitation epoch (founding member, or a node
          // that joined before Welcome wiring landed). Default to the
          // most-private interpretation -- the current key only -- so a
          // missing boundary cannot silently widen the disclosure
          // window. Future rotations propagate via key-update.
          return await this._keychain.currentKeyChange();
        }
        // `historySince` is optional on the Keychain interface for
        // backwards compatibility; fall back to full history when the
        // active provider has not implemented it (matches the
        // documented "boundary unknown" recovery path).
        return await keychainHistorySinceOrFull(this._keychain)(
          this._invitationEpoch,
        );
      case 'current_only':
      default:
        // Only send the current key -- most private option.
        return await this._keychain.currentKeyChange();
    }
  }

  /**
   * Returns the keychain changes to include in a BeeKEM Welcome to a
   * newly-added reader.
   *
   * The visibility computation here is from the **recipient's**
   * perspective, not the inviter's:
   *
   * - `current_only`: send only the current key. Identical to the load
   *   response path.
   * - `since_invited`: send only the current key. From the recipient's
   *   perspective, "since I was invited" is the current epoch
   *   (`welcomeEpochId`) onward, so the Welcome itself should carry
   *   exactly the current key (subsequent rotations arrive via the
   *   key-update protocol). Using `_keychainChangesForVisibility()` here
   *   would instead leak the *inviter's* post-invite slice (or, for
   *   founders, the full history), violating the recipient's intended
   *   join boundary.
   * - `full_history`: send the full keychain so the recipient can audit
   *   or replay all prior blocks (matches the inviter-side visibility
   *   semantics).
   */
  private async _keychainChangesForWelcome(): Promise<ChangesType> {
    switch (this._historyVisibility) {
      case 'full_history':
        return this._keychain.history();
      case 'since_invited':
      case 'current_only':
      default:
        return await this._keychain.currentKeyChange();
    }
  }

  /**
   * Check if automatic compaction should be triggered based on the config.
   */
  private async _maybeCompact() {
    if (!this._compactionConfig.enabled || this._snapshotUnsupported) {
      return;
    }

    // Prevent overlapping snapshot() calls from concurrent async paths.
    if (this._compactionInProgress) {
      return;
    }

    // Check cheap thresholds before the async writer ACL check to avoid
    // repeated crypto/ACL work on every change.
    if (this._documentChangeCount < this._compactionConfig.minChangesBeforeSnapshot) {
      return;
    }
    if (this._changesSinceSnapshot < this._compactionConfig.snapshotInterval) {
      return;
    }

    // Only writers can create snapshots; read-only peers must not attempt compaction.
    if (!(await this._writers.check(this._userPublicKey))) {
      return;
    }
    this._compactionInProgress = true;
    try {
      await this.snapshot();
    } finally {
      this._compactionInProgress = false;
    }
  }

  /**
   * Prune the change tree in the last sync message. After a BFS traversal
   * retains `keepCount` document nodes, remaining children are removed.
   * Note: in branching histories, nodes already enqueued in the BFS before
   * the limit is reached are also retained, so the actual count may exceed
   * `keepCount`.
   *
   * @param keepCount Maximum number of change nodes to retain in the sync tree.
   * @returns Set of CID strings for document nodes that were pruned from the tree.
   *   ACL node CIDs are never included (they are always preserved).
   */
  private _pruneChanges(keepCount: number): Set<string> {
    const prunedCIDs = new Set<string>();

    if (keepCount <= 0) {
      // Pruning everything (including root) is destructive and nonsensical; skip.
      return prunedCIDs;
    }
    if (!this._lastSyncMessage?.changes || !this._lastSyncMessage.changeId) {
      return prunedCIDs;
    }

    // Recursively collect all ACL nodes from a subtree that is about to be pruned.
    // Re-attached ACL nodes are stored as leaf nodes (children stripped) so they
    // don't keep nested children subtrees alive after pruning.
    // Non-ACL (document) node CIDs are added to the prunedCIDs set.
    const collectACLNodes = (
      children: Record<string, CRDTChangeNode<ChangesType>>,
      out: Record<string, CRDTChangeNode<ChangesType>>,
    ) => {
      for (const [childHash, childNode] of Object.entries(children)) {
        if (
          childNode.kind === crdtReaderChangeNode ||
          childNode.kind === crdtWriterChangeNode
        ) {
          // Shallow copy without children to avoid retaining the full subtree.
          const { children: _dropped, ...leafNode } = childNode;
          out[childHash] = leafNode as CRDTChangeNode<ChangesType>;
        } else {
          // Document node being pruned -- record its CID.
          prunedCIDs.add(childHash);
        }
        if (
          childNode.children !== undefined &&
          childNode.children !== crdtChangeNodeDeferred
        ) {
          collectACLNodes(childNode.children, out);
        }
      }
    };

    // BFS traversal to collect nodes up to the limit.
    // ACL nodes (reader/writer) are always preserved regardless of keepCount.
    //
    // When a document node at the boundary is pruned, ACL nodes from the
    // entire pruned subtree are collected and re-attached. This prevents
    // losing ACL state during pruning.
    //
    // For branching histories (DAG with multiple branches), keepCount is applied
    // globally across all branches. Once the limit is reached, all further
    // document nodes in any branch are pruned.
    const queue: Array<CRDTChangeNode<ChangesType>> = [
      this._lastSyncMessage.changes,
    ];
    let documentNodesVisited = 0;
    let qi = 0;

    while (qi < queue.length) {
      const current = queue[qi++]!;

      // ACL nodes are always kept -- never count them toward the limit.
      const isACLNode =
        current.kind === crdtReaderChangeNode ||
        current.kind === crdtWriterChangeNode;

      if (!isACLNode) {
        documentNodesVisited++;
      }

      if (
        current.children !== undefined &&
        current.children !== crdtChangeNodeDeferred
      ) {
        if (!isACLNode && documentNodesVisited >= keepCount) {
          // This document node is at the boundary -- prune its children,
          // but preserve any ACL nodes within the entire subtree.
          const preservedACL: Record<string, CRDTChangeNode<ChangesType>> = {};
          collectACLNodes(current.children, preservedACL);
          if (Object.keys(preservedACL).length > 0) {
            current.children = preservedACL;
          } else {
            delete current.children;
          }
        } else {
          for (const [, childNode] of Object.entries(current.children)) {
            queue.push(childNode);
          }
        }
      }
    }

    console.log(
      `Pruned change tree for ${this.documentPath}: kept ${documentNodesVisited} document nodes, pruned ${prunedCIDs.size} blocks`,
    );

    return prunedCIDs;
  }

  /**
   * Delete pruned blocks from the Helia blockstore. Unpins each block first
   * (if pinned), then deletes the raw block data. CIDs are intentionally
   * kept in `_hashes` so that `_mergeSyncTree()` still deduplicates if a
   * peer re-sends the same change block.
   *
   * Errors on individual blocks are logged but do not abort the overall GC pass.
   */
  private async _gcPrunedBlocks(prunedCIDs: Set<string>): Promise<void> {
    if (prunedCIDs.size === 0) {
      return;
    }

    const blockstore = this.swarm.heliaNode.blockstore;
    const pins = this.swarm.heliaNode.pins;
    let deleted = 0;

    for (const cidStr of prunedCIDs) {
      try {
        const cid = CID.parse(cidStr);

        // Unpin first -- pins.rm is an AsyncGenerator, drain it.
        try {
          for await (const _ of pins.rm(cid)) { /* drain */ }
        } catch (unpinErr) {
          const msg = String(unpinErr);
          if (!msg.includes('not pinned') && !msg.includes('is not pinned')) {
            throw unpinErr;
          }
          console.debug(`Unpin skipped for ${cidStr} (not pinned)`);
        }

        // Delete the raw block from the blockstore.
        // Note: we intentionally keep the CID in _hashes so that
        // _mergeSyncTree() still deduplicates if a peer re-sends
        // the same change block (e.g., a peer that hasn't compacted).
        await blockstore.delete(cid);
        deleted++;
      } catch (err) {
        console.error(`Failed to GC block ${cidStr}:`, err);
      }
    }

    console.log(
      `Blockstore GC for ${this.documentPath}: deleted ${deleted}/${prunedCIDs.size} blocks`,
    );
  }

  /**
   * Handles a doc-load request with pre-read stream data. Called by the
   * shared protocol handler in Peerborne after reading and routing.
   *
   * @internal
   * @param message The deserialized load request (already parsed by the shared handler).
   * @param stream The stream object for sending the response.
   */
  public async handleLoadRequestData(
    message: CRDTLoadRequest,
    stream: { sink: (data: Iterable<Uint8Array>) => Promise<void> },
  ): Promise<void> {
    try {
      console.log(
        `received doc-load request for ${this.documentPath}:`,
        message,
      );

      if (message.documentId !== this.documentPath) {
        console.warn(
          `Received a load request for the wrong document (${message.documentId} !== ${this.documentPath})`,
        );
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }

      // Authorize the requestor. When signing is disabled, skip ACL/signature
      // checks entirely -- any peer is treated as authorized.
      let authorized = false;
      if (!this._isSigningEnabled()) {
        // Bypass: signing disabled, no signature verification needed.
        authorized = true;
      } else {
        if (!message.signature) {
          // Reject requests with missing/empty signatures (e.g. from peers
          // that have signing disabled -- they cannot interoperate).
          console.warn(
            `Rejected load request for ${message.documentId}: missing signature`,
          );
          await stream.sink([] as Iterable<Uint8Array>);
          return;
        }
        const readers = (
          await Promise.all([this._readers.users(), this._writers.users()])
        ).flat();
        for (const reader of readers) {
          if (
            await this._authProvider.verify(
              this._encoder.encode(message.documentId),
              reader,
              this._deserializeSignature(message.signature),
            )
          ) {
            authorized = true;
            break;
          }
        }
      }

      if (!authorized) {
        console.warn(
          `Detected an unauthorized load request for ${message.documentId}`,
        );
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }

      // Construct load response based on history visibility setting.
      const loadMessage = this._createSyncMessage();

      loadMessage.keychainChanges = await this._keychainChangesForVisibility();

      // Include the latest snapshot if available, to accelerate initial sync.
      if (this._latestSnapshot) {
        loadMessage.snapshot = this._latestSnapshot;
      }

      // Attach an explicit tip-set advertisement so the loader can apply
      // a defense-in-depth consistency check against this responder's
      // self-attested served frontier (issue #186 / #189 §5.4.2).
      //
      // NOTE: as of PR #284 r7, the loader's PRIMARY binding is derived
      // STRUCTURALLY from the served `changes`/`snapshot` payload via
      // `computeServedFrontier`; the responder's `tips` array is NOT
      // trusted as the source of truth (a Byzantine peer can populate
      // it with the agreed CIDs while serving a divergent payload).
      // `tips` is still emitted by honest responders because the loader
      // ALSO verifies that the responder's own attestation hashes to
      // the same value as the structurally-derived served frontier --
      // a peer whose `tips` contradicts their own served payload is
      // caught at the secondary check.
      //
      // PR #284 r8: `tips` is now the *served* frontier
      // (`_servedFrontier()`) -- i.e. the heads of the change tree this
      // load response actually carries -- NOT the full local DAG
      // frontier (`_currentFrontier()`). The two differ when this peer
      // has multiple concurrent heads but `_lastSyncMessage` only roots
      // at one of them (the load wire shape only ships a single tree).
      // The tip-advertise handler hashes the same served frontier, so
      // the probe and the load round bind against a byte-identical tip
      // set even when the responder is holding remotely-applied heads
      // that aren't yet cross-linked into `_lastSyncMessage.changes`.
      // This field is part of the SIGNED v3 payload; see
      // `wire-protocols.ts` for the version-bump rationale.
      loadMessage.tips = this._servedFrontier();

      // Sign new message.
      loadMessage.signature = await this._signAsWriter(loadMessage);

      const serializedLoad =
        this._syncMessageSerializer.serializeSyncMessage(loadMessage);

      // Encrypt the load response so keychain is not sent in plaintext.
      // NOTE: This uses the current key, which works for existing peers requesting
      // a reload (they already have the key). For NEW members being onboarded for
      // the first time, the key must be delivered out-of-band via BeeKEM Welcome
      // message -- they cannot decrypt this load response without the key.
      const [documentKeyID, documentKey] = await this._keychain.current();
      if (!documentKey) {
        throw new Error(`Document ${this.documentPath} has an empty keychain!`);
      }
      const { nonce, data } = await this._authProvider.encrypt(
        serializedLoad,
        documentKey,
      );
      if (!nonce) {
        throw new Error(`Failed to encrypt sync message! Nonce cannot be empty`);
      }
      const assembled = concatUint8Arrays(documentKeyID, nonce, data);
      console.log(
        `sending doc-load response (encrypted) for ${this.documentPath}`,
      );

      await stream.sink([assembled] as Iterable<Uint8Array>);
    } catch (err: unknown) {
      console.error(`Error handling doc-load request for ${this.documentPath}:`, err);
      // Ensure the stream is closed so the requester doesn't hang.
      try { await stream.sink([] as Iterable<Uint8Array>); } catch { /* already closed */ }
    }
  }

  /**
   * Handles a snapshot-load request with pre-read stream data. Called by
   * the shared protocol handler in Peerborne after reading and routing.
   *
   * @internal
   * @param message The deserialized load request (already parsed by the shared handler).
   * @param stream The stream object for sending the response.
   */
  public async handleSnapshotLoadRequestData(
    message: CRDTLoadRequest,
    stream: { sink: (data: Iterable<Uint8Array>) => Promise<void> },
  ): Promise<void> {
    try {
      console.log(
        `received snapshot-load request for ${this.documentPath}:`,
        message,
      );

      if (message.documentId !== this.documentPath) {
        console.warn(
          `Received a snapshot load request for the wrong document (${message.documentId} !== ${this.documentPath})`,
        );
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }

      // Authorize the requestor. When signing is disabled, skip ACL/signature
      // checks entirely -- any peer is treated as authorized.
      let authorized = false;
      if (!this._isSigningEnabled()) {
        // Bypass: signing disabled, no signature verification needed.
        authorized = true;
      } else {
        if (!message.signature) {
          // Reject requests with missing/empty signatures (e.g. from peers
          // that have signing disabled -- they cannot interoperate).
          console.warn(
            `Rejected snapshot load request for ${message.documentId}: missing signature`,
          );
          await stream.sink([] as Iterable<Uint8Array>);
          return;
        }
        const readers = (
          await Promise.all([this._readers.users(), this._writers.users()])
        ).flat();
        for (const reader of readers) {
          if (
            await this._authProvider.verify(
              this._encoder.encode(message.documentId),
              reader,
              this._deserializeSignature(message.signature),
            )
          ) {
            authorized = true;
            break;
          }
        }
      }

      if (!authorized) {
        console.warn(
          `Detected an unauthorized snapshot load request for ${message.documentId}`,
        );
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }

      if (!this._latestSnapshot) {
        // No snapshot available -- respond with empty payload so the peer
        // can fall back to the normal doc-load protocol.
        console.log(
          `No snapshot available for ${this.documentPath}, sending empty response`,
        );
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }

      // Build a complete sync message with the snapshot, post-snapshot
      // changes, and keychain so the peer can fully catch up.
      const snapshotMessage = this._createSyncMessage();
      snapshotMessage.snapshot = this._latestSnapshot;
      snapshotMessage.keychainChanges = await this._keychainChangesForVisibility();
      // Tip-set advertisement for the pre-apply structural binding check
      // (see the doc-load handler above and the in-line check in
      // `_sendLoadRequestAndSync` for the rationale).
      //
      // PR #284 r8: this is the *served* frontier (`_servedFrontier()`)
      // -- the heads of the served payload (`_lastSyncMessage.changes`
      // tree plus the snapshot boundary) -- NOT the full local DAG
      // frontier (`_currentFrontier()`). When this peer holds concurrent
      // heads that `_lastSyncMessage` does not yet root over, the
      // load response only carries one head's subtree, so the
      // advertised `tips` must match that subset to satisfy the
      // loader's structural bind check. Part of the signed v3 payload
      // -- the version bump (snapshotLoadV2 -> snapshotLoadV3) is
      // required because `tips` is now covered by the writer signature.
      snapshotMessage.tips = this._servedFrontier();
      snapshotMessage.signature = await this._signAsWriter(snapshotMessage);

      const serialized =
        this._syncMessageSerializer.serializeSyncMessage(snapshotMessage);

      // Encrypt the response.
      const [documentKeyID, documentKey] = await this._keychain.current();
      if (!documentKey) {
        throw new Error(`Document ${this.documentPath} has an empty keychain!`);
      }
      const { nonce, data } = await this._authProvider.encrypt(
        serialized,
        documentKey,
      );
      if (!nonce) {
        throw new Error(`Failed to encrypt snapshot response! Nonce cannot be empty`);
      }
      const assembled = concatUint8Arrays(documentKeyID, nonce, data);
      console.log(
        `sending snapshot-load response (encrypted) for ${this.documentPath}`,
      );

      await stream.sink([assembled] as Iterable<Uint8Array>);
    } catch (err: unknown) {
      console.error(
        `Error handling snapshot-load request for ${this.documentPath}:`,
        err,
      );
      // Ensure the stream is closed so the requester doesn't hang.
      try { await stream.sink([] as Iterable<Uint8Array>); } catch { /* already closed */ }
    }
  }

  /**
   * Handles an initial-load quorum tip-advertise request with pre-read
   * stream data. Called by the shared protocol handler in Peerborne
   * after reading and routing.
   *
   * Closes the "no quorum protocol for verifying initial document state"
   * gap tracked under issue #189 §5.4 item 2 (also bulleted in #186).
   * The wire protocol is `tipAdvertiseV1` (see `wire-protocols.ts`);
   * this method returns either an empty payload (decline) or an
   * encrypted `CRDTSyncMessage` whose only populated payload field is
   * `tipsHash`. The loader on the other side compares hashes across
   * multiple peers and requires Q-of-K agreement before accepting any
   * peer's full document state. See `load-quorum.ts` for the decision
   * logic.
   *
   * Authorization mirrors the doc-load / snapshot-load handlers: when
   * signing is enabled the requester must sign the document path with
   * a key that appears in the readers or writers ACL. The response is
   * encrypted under the document's current key so a peer that does
   * not already possess the key cannot use the tip hash as an oracle
   * (key delivery is handled by the BeeKEM Welcome path).
   *
   * @internal
   * @param message The deserialized load request (already parsed by the shared handler).
   * @param stream The stream object for sending the response.
   */
  public async handleTipAdvertiseRequestData(
    message: CRDTLoadRequest,
    stream: { sink: (data: Iterable<Uint8Array>) => Promise<void> },
  ): Promise<void> {
    try {
      // Tip-advertise runs on every `open()` from every peer that opens
      // this document, so a per-request log line scales with mesh size.
      // Drop the unconditional log entirely; the only field the handler
      // would have logged is attacker-controlled (`message`), and the
      // mismatch/unauthorized branches below already emit targeted
      // warnings when they fail. See PR #284 r27 Copilot review.

      if (message.documentId !== this.documentPath) {
        console.warn(
          `Received a tip-advertise request for the wrong document (${message.documentId} !== ${this.documentPath})`,
        );
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }

      // Authorize the requestor. When signing is disabled, skip ACL/signature
      // checks entirely -- any peer is treated as authorized. Mirrors the
      // load handlers above so the gate is symmetrical: a deployment that
      // disables signing keeps the same trust posture across all protocols.
      let authorized = false;
      if (!this._isSigningEnabled()) {
        authorized = true;
      } else {
        if (!message.signature) {
          console.warn(
            `Rejected tip-advertise request for ${message.documentId}: missing signature`,
          );
          await stream.sink([] as Iterable<Uint8Array>);
          return;
        }
        const readers = (
          await Promise.all([this._readers.users(), this._writers.users()])
        ).flat();
        for (const reader of readers) {
          if (
            await this._authProvider.verify(
              this._encoder.encode(message.documentId),
              reader,
              this._deserializeSignature(message.signature),
            )
          ) {
            authorized = true;
            break;
          }
        }
      }

      if (!authorized) {
        console.warn(
          `Detected an unauthorized tip-advertise request for ${message.documentId}`,
        );
        await stream.sink([] as Iterable<Uint8Array>);
        return;
      }

      // Compute the canonical tip-set hash from the document's *served*
      // frontier — the heads of the payload this peer would actually ship
      // in a `documentLoadV3` / `snapshotLoadV3` round (computed via
      // `computeServedFrontier` over `_lastSyncMessage.changes` plus
      // `_latestSnapshot?.lastChangeNodeCID`, the exact same sources
      // `handleLoadRequestData` / `handleSnapshotLoadRequestData` populate
      // into the load response).
      //
      // PR #284 r8: this used to hash `_currentFrontier()` -- the full
      // local DAG frontier (`_hashes \ _referencedAncestors`). That
      // produces a hash an honest peer cannot bind against if it holds
      // multiple concurrent heads: `_currentFrontier()` returns every
      // head (including remotely-applied tips not yet cross-linked into
      // `_lastSyncMessage.changes`), but the load response only carries
      // one head's tree, so the loader's structural derivation of the
      // served frontier produces a different (smaller) set. Hashing the
      // served frontier here closes that gap -- a probe-then-load
      // round-trip from this responder always binds against a
      // byte-identical tip set. See `_servedFrontier()` for the
      // full rationale.
      //
      // Two peers with the same `_lastSyncMessage` / `_latestSnapshot`
      // produce byte-identical hashes; see `tips-hash.ts` for the
      // canonicalization (sort + `\n` separator + SHA-256).
      const hash = await tipsHash(this._servedFrontier());

      const advertisement: CRDTSyncMessage<ChangesType, PublicKey> = {
        documentId: this.documentPath,
        tipsHash: hash,
      };

      // Sign the advertisement so the loader can verify the responder is
      // an authorized writer (the same trust bar applied to load responses
      // above). `_signAsWriter` returns '' when signing is disabled, in
      // which case the loader's pre-load verification block is also a
      // no-op -- mirrors the doc-load / snapshot-load handlers' pattern.
      advertisement.signature = await this._signAsWriter(advertisement);

      const serialized =
        this._syncMessageSerializer.serializeSyncMessage(advertisement);

      // Encrypt the response with the document's current key so that an
      // unauthorized peer that managed to connect to us but does not have
      // the key cannot read (or use as an oracle) the tip hash.
      const [documentKeyID, documentKey] = await this._keychain.current();
      if (!documentKey) {
        throw new Error(`Document ${this.documentPath} has an empty keychain!`);
      }
      const { nonce, data } = await this._authProvider.encrypt(
        serialized,
        documentKey,
      );
      if (!nonce) {
        throw new Error(`Failed to encrypt tip-advertise response! Nonce cannot be empty`);
      }
      const assembled = concatUint8Arrays(documentKeyID, nonce, data);
      console.log(
        `sending tip-advertise response (encrypted) for ${this.documentPath}`,
      );

      await stream.sink([assembled] as Iterable<Uint8Array>);
    } catch (err: unknown) {
      console.error(
        `Error handling tip-advertise request for ${this.documentPath}:`,
        err,
      );
      // Ensure the stream is closed so the requester doesn't hang.
      try { await stream.sink([] as Iterable<Uint8Array>); } catch { /* already closed */ }
    }
  }

  /**
   * Build the deterministic binary payload used for snapshot signing/verification.
   *
   * Binary layout (big-endian integers):
   *   [0]       uint8   version (1)
   *   [1..8]    uint64  timestamp
   *   [9..12]   uint32  compactedCount
   *   [13..16]  uint32  cidLen
   *   [17..]    bytes   UTF-8(lastChangeNodeCID)
   *   [..]      uint32  stateLen
   *   [..]      bytes   stateBytes
   */
  private _buildSnapshotSignPayload(
    stateBytes: Uint8Array,
    lastChangeNodeCID: string,
    timestamp: number,
    compactedCount: number,
  ): Uint8Array {
    // Validate inputs to prevent runtime errors (e.g. BigInt(NaN) throws TypeError)
    // and silent uint32 overflow/truncation via DataView.setUint32.
    if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
      throw new Error(`Invalid snapshot timestamp: ${timestamp}`);
    }
    if (!Number.isInteger(compactedCount) || compactedCount < 0 || compactedCount > 0xFFFFFFFF) {
      throw new Error(`Invalid snapshot compactedCount: ${compactedCount}`);
    }
    const cidBytes = this._encoder.encode(lastChangeNodeCID);
    if (cidBytes.length > 0xFFFFFFFF) {
      throw new Error(`lastChangeNodeCID too large: ${cidBytes.length} bytes`);
    }
    if (stateBytes.length > 0xFFFFFFFF) {
      throw new Error(`Snapshot state too large: ${stateBytes.length} bytes`);
    }
    // 1 (version) + 8 (timestamp) + 4 (compactedCount) + 4 (cidLen) + cidBytes + 4 (stateLen) + stateBytes
    const totalLen = 1 + 8 + 4 + 4 + cidBytes.length + 4 + stateBytes.length;
    const buf = new ArrayBuffer(totalLen);
    const view = new DataView(buf);
    const out = new Uint8Array(buf);
    let offset = 0;

    // version
    view.setUint8(offset, 1);
    offset += 1;

    // timestamp as uint64
    view.setBigUint64(offset, BigInt(timestamp), false);
    offset += 8;

    // compactedCount as uint32
    view.setUint32(offset, compactedCount, false);
    offset += 4;

    // lastChangeNodeCID (length-prefixed)
    view.setUint32(offset, cidBytes.length, false);
    offset += 4;
    out.set(cidBytes, offset);
    offset += cidBytes.length;

    // stateBytes (length-prefixed)
    view.setUint32(offset, stateBytes.length, false);
    offset += 4;
    out.set(stateBytes, offset);

    return out;
  }

  private async _ensureCurrentUserCanWrite() {
    // Check that we are a writer (allowed to write to this document).
    if (!(await this._writers.check(this._userPublicKey))) {
      throw new Error(
        `Current user does not have write permissions for: ${this.documentPath}`,
      );
    }
  }

  /**
   * Send a load request over the given stream and apply the response.
   *
   * @returns `true` if a non-empty response was received and successfully synced.
   *   Returns `false` when:
   *   - The peer responded with an empty payload (e.g., peer has no snapshot).
   *   - The response payload is too short to contain a valid encrypted header.
   *   - The encryption keyID is not recognized (key not in our keychain).
   *   - The response documentId did not match the expected document.
   *   - Writer signature verification failed (when signing is enabled).
   *   - `sync()` rejected the response (e.g., invalid inner signatures or auth failure).
   *
   * @throws When `decrypt()` itself fails (i.e., the keyID was recognized but
   *   decryption produced no output), or on other unexpected protocol errors.
   *   Callers (e.g., `load()`) should wrap calls in a try/catch and handle both a
   *   `false` return value (by trying the next available peer) and thrown errors.
   */
  private async _sendLoadRequestAndSync(
    stream: { sink: (data: Iterable<Uint8Array>) => Promise<void>; source: AsyncIterable<Uint8ArrayList | Uint8Array> },
    serializedRequest: Uint8Array,
    expectedTipsHashHex: string | null = null,
  ): Promise<boolean> {
    await pipe([serializedRequest], stream.sink);
    return await pipe(
      stream.source,
      async (source: AsyncIterable<Uint8ArrayList | Uint8Array>) => {
        const assembled = await readUint8Iterable(source);

        // Empty response means the peer couldn't serve this request.
        if (assembled.length === 0) {
          return false;
        }

        // Decrypt the response. Extract the keyID from the header and
        // look it up in the keychain. Responses shorter than the encryption
        // header are treated as malformed and rejected.
        const headerLength = this._keychainProvider.keyIDLength + this._authProvider.nonceBits;
        let rawContent: Uint8Array;
        if (assembled.length <= headerLength) {
          // Too short to contain a valid encrypted payload -- reject.
          console.warn(
            `Load response for ${this.documentPath}: payload too short (${assembled.length} <= ${headerLength}), skipping peer`,
          );
          return false;
        }

        const blockKeyID = assembled.slice(0, this._keychainProvider.keyIDLength);
        const key = this._keychain.getKey(blockKeyID);
        if (key) {
          const blockNonce = assembled.slice(this._keychainProvider.keyIDLength, headerLength);
          const blockData = assembled.slice(headerLength);
          const decrypted = await this._authProvider.decrypt(blockData, key, blockNonce);
          if (!decrypted) {
            throw new Error(
              `Failed to decrypt load response for ${this.documentPath}`,
            );
          }
          rawContent = decrypted;
        } else {
          // KeyID not recognized -- peer sent encrypted data with a key we
          // don't have. Fail and let the caller try the next peer.
          console.warn(
            `Load response for ${this.documentPath}: unrecognized keyID, skipping peer`,
          );
          return false;
        }

        const message = this._syncMessageSerializer.deserializeSyncMessage(rawContent);
        if (message.documentId !== this.documentPath) {
          console.warn(
            `Load response documentId mismatch: expected ${this.documentPath}, got ${message.documentId}`,
          );
          return false;
        }
        // Verify the outer message signature before applying changes.
        // On subsequent loads (writers already known), verify against the
        // existing trusted writer set BEFORE sync() mutates state. This
        // prevents a malicious peer from injecting ACL changes that add
        // its own key.
        // On first load (_writers is empty / bootstrapping), we cannot
        // verify -- trust relies on the encrypted channel (only peers
        // with the document key can decrypt the response).
        if (this._isSigningEnabled()) {
          const preLoadWriters = await this._getWriterKeys();
          if (preLoadWriters.length > 0) {
            if (!message.signature) {
              console.warn(
                `Load response for ${this.documentPath}: missing signature, skipping peer`,
              );
              return false;
            }
            const { signature, ...messageWithoutSignature } = message;
            const raw = this._syncMessageSerializer.serializeSyncMessage(
              messageWithoutSignature,
            );
            // Mirror `_verifyWriterSignature`: a malformed/non-string signature
            // can cause `js-base64` to throw. Treat decode failure as a
            // verification failure for this peer (skip and let the caller try
            // the next one) rather than letting the exception escape -- the
            // outer snapshot-load attempt swallows errors via a blanket
            // catch{}, which would hide the malformed input entirely.
            let signatureBytes: Uint8Array;
            try {
              signatureBytes = this._deserializeSignature(signature);
            } catch {
              console.warn(
                `Load response for ${this.documentPath}: malformed signature, skipping peer`,
              );
              return false;
            }
            const verifyTasks = preLoadWriters.map((writerKey) =>
              this._authProvider.verify(raw, writerKey, signatureBytes),
            );
            if (!(await firstTrue(verifyTasks))) {
              console.warn(
                `Load response for ${this.documentPath} failed writer signature verification, skipping peer`,
              );
              return false;
            }
          }
        }

        // Quorum frontier binding (#186 / #189 §5.4.2). When the loader
        // ran a quorum probe round, the served full-load payload must
        // structurally describe the same tip set the responder voted
        // for. Done BEFORE `this.sync(...)` so a Byzantine peer that
        // voted hash X but serves a load with a different frontier
        // never gets to mutate the in-memory document.
        //
        // CRITICAL: the bind decision is derived from the ACTUAL served
        // payload, NOT from the responder-supplied `message.tips`.
        // Trusting `message.tips` -- as previous rounds did -- was a
        // hole: a Byzantine peer could vote hash X, put the matching
        // tip CIDs in `message.tips`, and then serve a `changes` /
        // `snapshot` payload describing a completely different state.
        // The advertised-vs-claimed check would pass even though the
        // application would receive divergent content. PR #284 r7
        // Copilot review caught this; the fix delegates frontier
        // computation to the pure helper `computeServedFrontier`, which
        // walks the served `changes` tree (plus the snapshot boundary
        // CID) and returns the set of payload CIDs that no other node
        // in the same payload references as a parent -- i.e. the heads
        // of what was actually served. We then hash that frontier and
        // compare to `winningHashHex`.
        //
        // We additionally REQUIRE `message.tips` on every v3 quorum-
        // enabled load response (PR #284 r9 Copilot review, issue #1).
        // The v3 load-response contract mandates the responder commit
        // to an explicit frontier attestation; a responder that omits
        // `tips` is recorded as a per-peer bind failure so the loader
        // retries the next agreeing peer. The structural check above
        // is the primary defense; the explicit `tips` requirement
        // ensures protocol compliance AND that the defense-in-depth
        // check below (verifying `tips` matches the structurally-
        // derived served frontier) actually runs. Catches the
        // responder-equivocation mode where `tips` and `changes` were
        // assembled inconsistently — e.g. a peer that claims extra
        // heads in `tips` that are not present in the served tree.
        //
        // Throws the module-private `_QuorumBindCheckFailedError` on
        // mismatch so the surrounding `load()` loop can record this
        // peer as a bind-failure and proceed to the NEXT peer in the
        // agreeing cohort. Previously this site threw
        // `LoadQuorumFailedError` directly, which `load()` re-raised --
        // letting a single malicious peer in the agreeing cohort vote
        // for the majority hash, serve a mismatched full load, and
        // unilaterally DoS the entire load by aborting before the
        // honest agreeing peers could be tried. See PR #284 r6 Copilot
        // review. `load()` only escalates to a structured
        // `LoadQuorumFailedError(bind-check-failed-all-agreeing-peers)`
        // when EVERY narrowed peer fails the bind step.
        if (expectedTipsHashHex !== null) {
          // Derive the served frontier STRUCTURALLY from the payload
          // the responder is asking us to apply -- not from the
          // responder's own `tips` attestation.
          const servedFrontier = computeServedFrontier(
            message.changeId,
            message.changes,
            message.snapshot?.lastChangeNodeCID,
          );
          const servedBytes = await tipsHash(servedFrontier);
          const servedHex = tipsHashToHex(servedBytes);
          if (!constantTimeHexEquals(expectedTipsHashHex, servedHex)) {
            console.warn(
              `[${this.documentPath}] Quorum frontier binding FAILED: ` +
                `expected tipsHash=${expectedTipsHashHex.slice(0, 12)}... but ` +
                `served payload's frontier hashes to ${servedHex.slice(0, 12)}.... ` +
                `An agreeing peer voted for one tip set and served a ` +
                `different one; treating as Byzantine equivocation.`,
            );
            throw new _QuorumBindCheckFailedError(
              servedHex,
              `Quorum frontier binding mismatch (served payload): expected ` +
                `${expectedTipsHashHex.slice(0, 12)}... got ${servedHex.slice(0, 12)}...`,
            );
          }
          // Protocol compliance: under the v3 load-response contract,
          // a quorum-enabled load REQUIRES `message.tips` to be present
          // on the response so the responder commits to an explicit
          // frontier attestation alongside the served payload. The
          // structural-frontier check above is the primary defense; this
          // explicit `Array.isArray(message.tips)` guard ensures a v3
          // responder that omits `tips` is recorded as a per-peer bind
          // failure (so the loader retries the NEXT agreeing peer)
          // rather than silently passing on the structural-hash check
          // alone. Without this guard, a responder could violate the
          // protocol contract — and a defense-in-depth check that
          // catches contradictions between `tips` and the served payload
          // would never run because the `Array.isArray` branch would
          // simply skip. See PR #284 r9 Copilot review (issue #1).
          if (!Array.isArray(message.tips)) {
            console.warn(
              `[${this.documentPath}] Quorum frontier binding FAILED: ` +
                `quorum-enabled load response omitted required \`tips\` ` +
                `attestation (v3 protocol violation). Recording peer as ` +
                `bind-failed; loader will try the next agreeing peer.`,
            );
            throw new _QuorumBindCheckFailedError(
              '(missing tips)',
              `Quorum frontier binding: responder omitted required \`tips\` ` +
                `attestation on v3 quorum-enabled load response.`,
            );
          }
          // Defense-in-depth: the responder-supplied `tips` must hash
          // to the same value as the structurally-derived served
          // frontier. A peer whose attested `tips` contradicts their
          // own served payload (e.g. claims extra heads that are not
          // present in the served tree) is misbehaving.
          const advertisedBytes = await tipsHash(message.tips);
          const advertisedHex = tipsHashToHex(advertisedBytes);
          if (!constantTimeHexEquals(servedHex, advertisedHex)) {
            console.warn(
              `[${this.documentPath}] Quorum frontier binding FAILED: ` +
                `served payload frontier hashes to ${servedHex.slice(0, 12)}... ` +
                `but responder advertised tips hashing to ${advertisedHex.slice(0, 12)}.... ` +
                `Responder's own attestation contradicts the served payload.`,
            );
            throw new _QuorumBindCheckFailedError(
              advertisedHex,
              `Quorum frontier binding mismatch (advertised vs served): ` +
                `advertised ${advertisedHex.slice(0, 12)}... served ` +
                `${servedHex.slice(0, 12)}...`,
            );
          }

          // Content-address verification (PR #284 r17 Copilot review).
          //
          // The structural bind above proves Q peers agree on the
          // FRONTIER CIDs and that those CIDs appear as keys in the
          // served tree. It does NOT prove the inline `change` content
          // for each CID actually hashes back to that CID -- a Byzantine
          // peer could vote for the agreed frontier and then serve a
          // tree whose `children` map uses the agreed CIDs as keys but
          // whose inline `change` values are forged.
          //
          // On a FIRST load (`_writers` empty), per-change signature
          // verification inside the CRDT merge cannot fire -- there are
          // no writer keys to verify against -- so forged inline content
          // would otherwise reach `_crdtProvider.remoteChange`/
          // `_mergeWriters`/`_mergeReaders` unchecked.
          //
          // Defense: strip inline `change` content from every node in
          // the served tree before applying. `sync()` then routes each
          // CID through `missingDocumentHashes -> _getBlock(cid) ->
          // helia.blockstore.get(cid)`, which content-validates the
          // fetched bytes against the CID intrinsically (a Byzantine
          // peer cannot serve bytes that hash to a CID they did not
          // produce, and bitswap will retrieve from an honest peer in
          // the agreeing cohort that does hold the legitimate block).
          //
          // Cost: N bitswap roundtrips instead of one inline load. Paid
          // only on quorum-bound loads; the legacy `winningHashHex ===
          // null` path is untouched.
          //
          // Snapshots: `CRDTSnapshotNode.state` is NOT CID-addressed --
          // the snapshot's `lastChangeNodeCID` only identifies the
          // boundary, not the snapshot bytes. Defense is the writer
          // signature (`_verifySnapshotSignature`), which fails on
          // first load (writers empty) and rejects the snapshot
          // automatically. On subsequent loads writers are known and
          // the signature is the source of truth. We drop the snapshot
          // entirely on first load below so a malicious snapshot
          // signature forged with an attacker-controlled key (which
          // would be admitted if the inline ACL pre-pass were trusted)
          // never reaches `applySnapshot`.
          // Capture every CID that appears in the served tree BEFORE
          // stripping. `_syncDocumentChanges` swallows per-block fetch
          // failures (logs + returns); without a post-sync verification
          // step a transient bitswap/blockstore miss would let this
          // method return `true` with only a partially-applied document
          // and `load()` report success. After `sync()` we re-check that
          // every captured CID is now in `_hashes`; any missing CID is
          // surfaced as a per-peer bind failure so the loader can retry
          // the next peer in the agreeing cohort. See PR #284 r18
          // Copilot review.
          const expectedCids = collectAllCidsInTree(
            message.changeId,
            message.changes,
          );

          stripInlineChanges(message.changes);
          const preLoadWriterCount = (await this._writers.users()).length;
          if (preLoadWriterCount === 0 && message.snapshot) {
            console.warn(
              `[${this.documentPath}] Dropping snapshot from quorum-bound ` +
                `first load: writers ACL is not yet populated so the ` +
                `snapshot signature cannot be verified. The receiver will ` +
                `rebuild state from individual change blocks via Helia ` +
                `(each block content-validated against its CID).`,
            );
            message.snapshot = undefined;
          }

          // Snapshot-only first-load detection: after the snapshot drop
          // above, if the response now carries NO changes tree AND NO
          // snapshot, the responder served us nothing usable. Without
          // this guard the path falls through to `sync(message, false)`
          // (which returns `true` for a vacuously-empty message because
          // there is nothing to merge / reject) and this method reports
          // success — `load()` then returns `true` with neither state
          // applied nor an opportunity to retry. Treat as a per-peer
          // bind failure so the agreeing-cohort load loop tries the
          // next peer (which may serve a real changes tree). See
          // PR #284 r18 Copilot review.
          if (
            message.changes === undefined &&
            message.snapshot === undefined
          ) {
            console.warn(
              `[${this.documentPath}] Quorum-bound first-load response ` +
                `carries neither a changes tree nor a snapshot after the ` +
                `defensive snapshot drop. Treating as bind failure so the ` +
                `loader tries the next agreeing peer.`,
            );
            throw new _QuorumBindCheckFailedError(
              '(snapshot-only first-load)',
              `Quorum-bound first-load response had only a snapshot (now ` +
                `dropped because writers are not yet populated) and no ` +
                `changes tree; no state can be applied.`,
            );
          }

          // PRE-FETCH gate (PR #284 r20 Copilot review).
          //
          // Round 19 added a POST-sync `_hashes`-coverage check, but
          // `sync()` mutates the document as each fetched block lands
          // -- so a missing CID would still leave the document
          // partially mutated by the time the post-check threw a bind
          // failure. To keep a failed quorum-bound load from altering
          // local state at all, pull every required block from Helia
          // here (BEFORE `sync()` is allowed to mutate). Helia's
          // blockstore content-validates each fetch against its CID
          // intrinsically; bitswap retrieves from any peer in the swarm
          // that holds the legitimate block. If ANY fetch fails (CID
          // not retrievable from any peer, content/CID mismatch, or
          // timeout inside Helia), throw a per-peer bind failure with
          // ZERO state mutation -- the load loop can cleanly retry the
          // next peer in the agreeing cohort, or escalate to
          // `bind-check-failed-all-agreeing-peers` if every peer
          // exhausts.
          //
          // Run via a bounded worker pool so a single slow peer cannot
          // pessimize the load AND a large load response (many CIDs)
          // cannot trigger a burst of parallel `blockstore.get()` fetches
          // that exhaust libp2p/Helia per-connection stream quotas or
          // pressure memory by buffering N inline payloads at once. The
          // previous implementation used `Promise.allSettled` over the
          // full `expectedCids` list with no concurrency cap, which
          // worked fine for typical loads but scaled linearly with the
          // worst-case adversary-shaped response. `LOAD_PREFETCH_MAX_CONCURRENCY`
          // (8) is a balance: large enough to overlap WAN-latency-bound
          // bitswap fetches, small enough to bound peak resource use on
          // the loader. Block bytes are cached locally on success; the
          // subsequent `sync()` call only does local lookups for those
          // CIDs and applies them. See PR #284 r24 Copilot review.
          if (expectedCids.length > 0) {
            const missingCids: string[] = [];
            let nextIndex = 0;
            const workerCount = Math.min(
              LOAD_PREFETCH_MAX_CONCURRENCY,
              expectedCids.length,
            );
            const worker = async (): Promise<void> => {
              while (true) {
                const i = nextIndex++;
                if (i >= expectedCids.length) return;
                const cidStr = expectedCids[i]!;
                try {
                  const cid = CID.parse(cidStr);
                  // Force the blockstore to retrieve the block. Helia
                  // validates content vs CID on `get`; draining the
                  // returned async-iterable triggers the actual fetch.
                  // Discard the chunks (no concat) — we only need
                  // content-validation here, not the bytes.
                  for await (const _chunk of this.swarm.heliaNode.blockstore.get(
                    cid,
                  )) {
                    void _chunk;
                  }
                } catch {
                  missingCids.push(cidStr);
                }
              }
            };
            await Promise.all(
              Array.from({ length: workerCount }, () => worker()),
            );
            if (missingCids.length > 0) {
              console.warn(
                `[${this.documentPath}] Quorum-bound load pre-fetch ` +
                  `failed: ${missingCids.length} of ${expectedCids.length} ` +
                  `expected CIDs were not retrievable from Helia (e.g. ` +
                  `${missingCids
                    .slice(0, 3)
                    .map((c) => c.slice(0, 12) + '...')
                    .join(', ')}). Recording peer as bind-failed BEFORE ` +
                  `any state mutation; the loader will try the next ` +
                  `agreeing peer with a clean document.`,
              );
              throw new _QuorumBindCheckFailedError(
                '(prefetch-missing-blocks)',
                `Quorum-bound load pre-fetch could not retrieve ` +
                  `${missingCids.length} of ${expectedCids.length} expected ` +
                  `CIDs from Helia; aborting before sync() so document ` +
                  `state is unchanged.`,
              );
            }
          }

          const syncResult = await this.sync(message, false);
          if (!syncResult) {
            console.warn(
              `sync rejected message during load for ${this.documentPath}`,
            );
            // Return false so the caller tries the next peer.
            return false;
          }

          // Post-sync verification (PR #284 r18 Copilot review): every
          // CID we expected from the (stripped) served tree must have
          // landed in `_hashes` via either inline application (for the
          // non-stripped path this branch never reaches) or via the
          // `_getBlock(cid)` Helia fetch path inside
          // `_syncDocumentChanges`. A missing CID means bitswap could
          // not retrieve that block; without surfacing this the load
          // would silently report success with a partial document.
          const missingCids: string[] = [];
          for (const cid of expectedCids) {
            if (!this._hashes.has(cid)) missingCids.push(cid);
          }
          if (missingCids.length > 0) {
            console.warn(
              `[${this.documentPath}] Quorum-bound load did not complete: ` +
                `${missingCids.length} of ${expectedCids.length} expected ` +
                `CIDs were not fetched from Helia (e.g. ${missingCids
                  .slice(0, 3)
                  .map((c) => c.slice(0, 12) + '...')
                  .join(', ')}). Recording peer as bind-failed so the ` +
                `loader tries the next agreeing peer.`,
            );
            throw new _QuorumBindCheckFailedError(
              '(missing-blocks)',
              `Quorum-bound load completed sync() but ${missingCids.length} ` +
                `of ${expectedCids.length} expected CIDs were not retrievable; ` +
                `served tree had stripped inline content and bitswap could ` +
                `not retrieve the missing blocks.`,
            );
          }

          return true;
        }

        const syncResult = await this.sync(message, false);
        if (!syncResult) {
          console.warn(
            `sync rejected message during load for ${this.documentPath}`,
          );
          // Return false so the caller tries the next peer.
          return false;
        }
        return true;
      },
    );
  }

  /**
   * Send a single `tipAdvertiseV1` probe to one peer and decrypt the
   * response to extract the peer's `tipsHash`. Returns one of:
   *
   *   - `Uint8Array` -- the peer's advertised `tipsHash` (32 bytes).
   *   - `'unknown-doc'` -- the peer explicitly disclaimed the document
   *     (returned the 1-byte `0xFF` UNKNOWN_DOC sentinel). This is the
   *     signal `Peerborne.tipAdvertiseHandler` emits when no document
   *     is registered for the requested path. Distinguishing this from
   *     `null` lets the orchestrator tally `'unknown-doc'` exactly like
   *     a tip-hash vote so that when a Q-of-K majority of peers all
   *     disclaim the document, `load()` returns `false` to let a fresh
   *     `open()` create the document on top of an existing swarm. The
   *     previous design returned `null` for the unknown-doc case, which
   *     was indistinguishable from a partition / timeout and made
   *     new-document creation in an existing mesh fail with
   *     `LoadQuorumFailedError`. See PR #284 r16 Copilot review.
   *   - `null` -- any other non-vote outcome: empty response, decryption
   *     failure with an unknown key (peer has a different keychain),
   *     missing/invalid signature, deserialization failure, document-id
   *     mismatch, missing/short tip hash, or thrown errors. Timeouts are
   *     handled at the caller level via Promise.race.
   *
   * Returns rather than throws so the caller can record this peer as a
   * non-vote (NOT a disagreement) and `decideLoadQuorum` can apply the
   * correct quorum semantics. See `load-quorum.ts` for the
   * timeout-vs-disagreement-vs-unknown-doc distinction.
   *
   * @internal
   */
  private async _probeTipAdvertise(
    peer: import('@multiformats/multiaddr').Multiaddr,
    serializedRequest: Uint8Array,
    signal?: AbortSignal,
  ): Promise<Uint8Array | 'unknown-doc' | null> {
    // Capture the underlying v3 Stream so the abort path below can call
    // `abort()` on it directly (the wrapped DuplexStream only exposes the
    // write-side half-close via `close()`, not a full bidirectional tear-
    // down). Without this, a probe that loses the Promise.race to the
    // timeout would leak its stream until the libp2p connection itself
    // closed -- on partitioned/slow peers, each `load()` could leak K
    // streams, exhausting per-connection stream quotas. See PR #284 r2
    // CodeRabbit comment on this method.
    let rawStream: import('@libp2p/interface').Stream;
    let stream: { sink: (data: Iterable<Uint8Array>) => Promise<void>; source: AsyncIterable<Uint8ArrayList | Uint8Array> };
    try {
      rawStream = await this.libp2p.dialProtocol(peer, [tipAdvertiseV1], {
        runOnLimitedConnection: true,
      });
      stream = wrapStream(rawStream);
    } catch {
      // Peer doesn't support tip-advertise or dial failed -- treat as non-vote.
      return null;
    }
    // Abort handler: tear down the v3 stream bidirectionally so a timed-out
    // probe doesn't strand the libp2p resource. `abort()` is the v3 full
    // teardown ("close stream for reading and writing"); `close()` would
    // only half-close the write side. Re-checking `signal?.aborted` after
    // attaching handles the race where the signal fired between dial and
    // listener attach. The handler also resolves `pipe()` / read promises
    // below with `AbortError`, which we swallow in the outer catch.
    const onAbort = () => {
      try {
        rawStream.abort(new Error('tip-advertise probe aborted'));
      } catch {
        // Already torn down -- nothing to do.
      }
    };
    if (signal) {
      if (signal.aborted) {
        try {
          rawStream.abort(new Error('tip-advertise probe aborted'));
        } catch {
          /* already torn down */
        }
        return null;
      }
      signal.addEventListener('abort', onAbort, { once: true });
    }
    try {
      await pipe([serializedRequest], stream.sink);
      // Size-bound the tip-advertise response read. A `tipAdvertiseV1`
      // body is an encrypted `CRDTSyncMessage` carrying the `documentId`
      // (up to `MAX_DOCUMENT_PATH_LENGTH` bytes BEFORE encryption — this
      // dominates the size), a 32-byte `tipsHash`, and (optionally) a
      // writer signature. The cap is derived from
      // `MAX_DOCUMENT_PATH_LENGTH` plus JSON / Base64 / AES-GCM / signature
      // overheads (see `MAX_TIP_ADVERTISE_RESPONSE_SIZE` docstring above
      // for the breakdown). The previous 2 KiB cap was smaller than the
      // `documentId` field alone, so any document with a maximal path was
      // surfaced as a non-vote and quorum could never pass for it. 6 KiB
      // is generous for legitimate peers but prevents a malicious peer
      // from streaming an unbounded payload to force `load()` to buffer
      // it all before returning a non-vote. If the read overruns the cap,
      // `readUint8Iterable` throws a `RangeError` that is caught by the
      // surrounding `try { ... } catch { return null; }` — surfacing as a
      // non-vote (same outcome as a timeout), NOT a quorum disagreement.
      // See PR #284 r4/r5 Copilot review.
      const assembled = await readUint8Iterable(
        stream.source,
        MAX_TIP_ADVERTISE_RESPONSE_SIZE,
      );
      if (assembled.length === 0) {
        // Peer declined (unauthorized, decryption failure, document-id
        // mismatch, etc.). Distinct from the 1-byte UNKNOWN_DOC sentinel
        // handled below, which signals "I don't have this document at all"
        // (a distinguishable case used to let new-doc creation succeed
        // in an existing swarm; see method docstring).
        return null;
      }
      // 1-byte UNKNOWN_DOC sentinel response: `Peerborne.tipAdvertiseHandler`
      // emits this when no document is registered for the requested path.
      // The orchestrator counts these toward a separate "unknown-doc"
      // tally so a Q-of-K majority of disclaims becomes a clean
      // new-doc-creation signal rather than a `LoadQuorumFailedError`.
      // See `_probeTipAdvertise`'s docstring and PR #284 r16 Copilot
      // review for the rationale.
      if (assembled.length === 1 && assembled[0] === 0xff) {
        return 'unknown-doc';
      }
      const headerLength = this._keychainProvider.keyIDLength + this._authProvider.nonceBits;
      if (assembled.length <= headerLength) {
        // Too short to be a valid encrypted payload.
        return null;
      }
      const blockKeyID = assembled.slice(0, this._keychainProvider.keyIDLength);
      const key = this._keychain.getKey(blockKeyID);
      if (!key) {
        // Responder used a key we don't have. Treat as non-vote rather than
        // an attack: a freshly-onboarded reader may legitimately not have
        // every historical key yet. The decryption-side check on the full
        // load that follows will still gate trust on the actual state.
        return null;
      }
      const blockNonce = assembled.slice(this._keychainProvider.keyIDLength, headerLength);
      const blockData = assembled.slice(headerLength);
      const decrypted = await this._authProvider.decrypt(blockData, key, blockNonce);
      if (!decrypted) {
        return null;
      }
      let message: CRDTSyncMessage<ChangesType, PublicKey>;
      try {
        message = this._syncMessageSerializer.deserializeSyncMessage(decrypted);
      } catch {
        return null;
      }
      if (message.documentId !== this.documentPath) {
        return null;
      }
      // Verify the writer signature on the advertisement when possible.
      // On first load (_writers empty) we cannot verify -- trust falls
      // back to the encryption envelope (only a peer that already holds
      // the current key could produce this response) plus the quorum
      // requirement that multiple such peers agree. This matches the
      // bootstrapping behaviour of `_sendLoadRequestAndSync`.
      if (this._isSigningEnabled()) {
        const preLoadWriters = await this._getWriterKeys();
        if (preLoadWriters.length > 0) {
          if (!message.signature) {
            return null;
          }
          const { signature, ...messageWithoutSignature } = message;
          const raw = this._syncMessageSerializer.serializeSyncMessage(
            messageWithoutSignature,
          );
          let signatureBytes: Uint8Array;
          try {
            signatureBytes = this._deserializeSignature(signature);
          } catch {
            return null;
          }
          const verifyTasks = preLoadWriters.map((writerKey) =>
            this._authProvider.verify(raw, writerKey, signatureBytes),
          );
          if (!(await firstTrue(verifyTasks))) {
            return null;
          }
        }
      }
      if (!(message.tipsHash instanceof Uint8Array) || message.tipsHash.length !== TIPS_HASH_LENGTH) {
        return null;
      }
      return message.tipsHash;
    } catch {
      return null;
    } finally {
      // Always detach the abort listener and release the libp2p stream.
      // The normal success path drops through to here after `return` runs,
      // so we still need to close the stream to release per-connection
      // stream quota (the response read consumed the read side but the
      // write side is half-open until close() runs). On the abort path
      // `rawStream.abort()` has already been called by `onAbort`; calling
      // `close()` again is a no-op the libp2p impls tolerate.
      if (signal) {
        signal.removeEventListener('abort', onAbort);
      }
      try {
        await rawStream.close();
      } catch {
        /* already torn down */
      }
    }
  }

  /**
   * Run a single tip-advertise probe with a hard timeout. The probe itself
   * never throws (`_probeTipAdvertise` returns `null` on any failure
   * mode); a timeout also resolves to `null` so the caller can treat the
   * peer as a non-vote rather than a disagreement.
   *
   * Stream cancellation: when the timeout wins the race, the underlying
   * probe's libp2p stream is torn down via an AbortController so the
   * pending probe doesn't keep the resource alive in the background. Prior
   * to this fix, every timed-out probe leaked one libp2p stream per
   * `load()` call; under partitions or slow peers, K such leaks per load
   * could exhaust per-connection stream quotas. See PR #284 r2 review.
   *
   * @internal
   */
  private async _raceTipAdvertiseProbe(
    peer: import('@multiformats/multiaddr').Multiaddr,
    serializedRequest: Uint8Array,
    timeoutMs: number,
  ): Promise<Uint8Array | 'unknown-doc' | null> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<null>((resolve) => {
      timer = setTimeout(() => resolve(null), timeoutMs);
    });
    try {
      return await Promise.race([
        this._probeTipAdvertise(peer, serializedRequest, controller.signal),
        timeout,
      ]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      // Whether the probe won or the timeout won, abort the controller so
      // any in-flight probe (loser of the race, still pending on the event
      // loop) tears down its stream. Aborting AFTER the probe has already
      // resolved is a no-op: the probe's finally block will have already
      // detached the listener and closed the stream itself.
      controller.abort();
    }
  }

  /**
   * Extract the remote peer-id portion of a Multiaddr in a form suitable
   * for keying the quorum decision map. For relay-circuit multiaddrs (e.g.
   * `.../p2p/<relay>/p2p-circuit/p2p/<remote>`), the remote peer-id is the
   * LAST `/p2p/<id>` segment. Falls back to the full multiaddr string when
   * no `/p2p/<id>` segment is present so two responses from the same peer
   * always collide on the same map key.
   *
   * @internal
   */
  private _peerIdOf(peer: import('@multiformats/multiaddr').Multiaddr): string {
    const str = peer.toString();
    const matches = [...str.matchAll(/\/p2p\/([^/]+)/g)];
    return matches.length > 0 ? matches[matches.length - 1][1] : str;
  }

  // API Methods --------------------------------------------------------------

  // https://gist.github.com/alanshaw/591dc7dd54e4f99338a347ef568d6ee9#duplex-it
  /**
   * Load sends a new load request to any connected peer (each peer is tried one at a time). The expected
   * response from a load request is a sync message containing all document change hashes.
   *
   * Load is used to fetch any new changes that a connecting node is missing.
   *
   * @param preferredPeer Optional peer to try first (typically a PeerId from a
   *   pubsub message sender). Matched against peers by extracting the `/p2p/<id>`
   *   substring from each peer's `Multiaddr.toString()` (the canonical string
   *   form), since `@multiformats/multiaddr` v13 dropped the `getPeerId()`
   *   helper and `getComponents()` may surface the `/p2p` value as bytes.
   * **Initial-load quorum gate.** When
   * `PeerborneConfig.loadQuorumEnabled` is `true` (the default), `load()`
   * first queries up to `loadQuorumK` peers in parallel via the
   * `tipAdvertiseV1` protocol for a lightweight tip-set hash. The full
   * document-load only proceeds against a peer that participated in a
   * majority (`loadQuorumQ`-of-K) agreement on the tip set, defending
   * against a single malicious or partitioned peer unilaterally serving a
   * stale or maliciously-crafted initial state. The gate runs uniformly
   * regardless of local `_hashes` state (an empty local `_hashes` is the
   * exact state the gate must defend on first `open()` of an existing
   * document — bypassing it then would be unsafe). If quorum is not met,
   * `load()` rejects with a `LoadQuorumFailedError` (see
   * `load-quorum.ts`). The gate can be disabled wholesale via
   * `loadQuorumEnabled: false` for single-peer dev/test scenarios; the
   * single-peer edge case is covered by `loadQuorumAllowSinglePeer`. Tip-
   * advertise responses with an unknown encryption key, missing/invalid
   * writer signature, document-id mismatch, or short/missing tip hash are
   * recorded as non-votes (NOT disagreements) so a stale peer cache does
   * not flip a partition into a Byzantine-failure verdict. The probe
   * round dedupes peers by libp2p PeerId so a single peer with multiple
   * open connections cannot cast multiple votes. The legacy load loop
   * (when `loadQuorumEnabled: false`) keeps the ORIGINAL un-deduped
   * peer list so it can retry across multiple multiaddrs for the same
   * peer id (e.g. a direct connection + a relay-circuit fallback). See
   * PR #284 r7 Copilot review for the dedup-scope rationale.
   *
   * After quorum passes, the served full state is bound to the agreed
   * hash STRUCTURALLY -- the loader derives the responder's served
   * frontier from the actual `changes`/`snapshot` payload via
   * `computeServedFrontier`, hashes that, and verifies it equals
   * `winningHashHex` BEFORE applying the response. The
   * responder-supplied `message.tips` array is NO LONGER trusted as the
   * source of truth (previous rounds did, which let a Byzantine peer
   * vote hash X, put X's tips in `message.tips`, and serve a divergent
   * payload). When present, `message.tips` is additionally checked to
   * hash to the same value as the structurally-derived served
   * frontier; this catches the responder-internal-equivocation case
   * where the served `changes` and the advertised `tips` were
   * assembled inconsistently. See PR #284 r7 Copilot review. An
   * agreeing peer whose served payload's structural frontier hashes to
   * something other than `winningHashHex` is treated as a PER-PEER bind
   * failure: the loader records the offending peer in
   * `agreeingPeerBindFailures`, skips it, and tries the next peer in
   * the agreeing cohort. This prevents a single malicious peer in the
   * agreeing cohort from DoS'ing the entire load by voting for the
   * majority hash (passing quorum) and then serving a mismatched full
   * load. Only after EVERY peer in the agreeing cohort has bind-failed
   * does the loader throw `LoadQuorumFailedError(reason: 'bind-check-
   * failed-all-agreeing-peers')`, with `agreeingPeerBindFailures`
   * recording per-peer what each Byzantine peer served instead.
   * Closes the gap tracked under issue #189 §5.4 item 2 (and bulleted
   * in #186). See PR #284 r6 Copilot review for the DoS rationale on
   * the per-peer retry.
   *
   * @returns `true` if the document was successfully loaded from a peer.
   *   `false` if no peer could provide the document -- this is ambiguous: it
   *   may mean the document is brand new (no peers have it) OR that all peers
   *   failed to respond, failed to decrypt, or failed signature verification.
   *   Note: `open()` treats `false` as "new document" only when no existing
   *   document state has already been loaded.
   * @throws {LoadQuorumFailedError} When the initial-load quorum gate is
   *   enabled and fewer than `loadQuorumQ` peers agreed on the same tip
   *   hash within the configured timeout. Callers can `instanceof`-check
   *   this error to distinguish quorum failure from other I/O errors
   *   raised inside `load()`. The original single-peer
   *   "return false on no peers" behaviour is preserved when the quorum
   *   gate is disabled (`loadQuorumEnabled: false`).
   */
  // Key exchange happens during:
  // - Load messages.
  // - ACL updates via /collabswarm/key-update/1.0.0 protocol
  public async load(preferredPeer?: PeerId | string): Promise<boolean> {
    // Pick a peer. All peers come from getConnections() so they already have
    // open connections. dialProtocol reuses existing connections internally,
    // so no additional connection management is needed here.
    const shuffledPeers = await this._shuffledPeers();
    if (shuffledPeers.length === 0) {
      return false;
    }

    const orderedPeers = [...shuffledPeers];

    // If a preferred peer is specified, move it to the front.
    // The peer list contains Multiaddrs while preferredPeer is typically a PeerId,
    // so we compare by extracting the PeerId component from each Multiaddr.
    if (preferredPeer) {
      const preferredId = preferredPeer.toString();
      const preferredIdx = orderedPeers.findIndex(p => {
        // Only compare against the PeerId component of the Multiaddr.
        // Falling back to a full-string equality check would compare against
        // the full multiaddr string (e.g. "/ip4/.../p2p/<id>") which will
        // never match a plain PeerId string.
        //
        // `@multiformats/multiaddr` v13 (bundled by libp2p v3) dropped the
        // `getPeerId()` helper. `getComponents()` exists, but its component
        // `value` field can be either a string or bytes depending on how the
        // multiaddr was parsed, so a direct `=== preferredId` comparison is
        // unreliable. `Multiaddr.toString()` always returns the canonical
        // string form, so extract the `/p2p/<id>` substring from there.
        //
        // For relay-circuit multiaddrs (e.g.
        // `.../p2p/<relay>/p2p-circuit/p2p/<remote>`), there are multiple
        // `/p2p/<id>` segments; the remote peer id is always the LAST one,
        // so iterate all matches and use the final occurrence.
        const matches = [...p.toString().matchAll(/\/p2p\/([^/]+)/g)];
        const peerId = matches.length > 0 ? matches[matches.length - 1][1] : null;
        return peerId != null && peerId === preferredId;
      });
      if (preferredIdx > 0) {
        const [preferred] = orderedPeers.splice(preferredIdx, 1);
        orderedPeers.unshift(preferred);
      }
    }

    let signature = '';
    if (this._isSigningEnabled()) {
      const signatureBytes = await this._authProvider.sign(
        this._encoder.encode(this.documentPath),
        this._userKey,
      );
      signature = this._serializeSignature(signatureBytes);
    }
    const loadRequest: CRDTLoadRequest = {
      documentId: this.documentPath,
      signature,
    };
    const serializedRequest = this._loadMessageSerializer.serializeLoadRequest(loadRequest);

    // Dedupe peers by peer id ONLY for the quorum probe round.
    // `getConnections()` returns one entry per OPEN connection, and libp2p
    // maintains separate connections per multiaddr / per transport — so a
    // single remote peer with two open connections (e.g. direct +
    // relay-circuit) shows up twice. Without dedup, that peer would cast
    // two votes in the quorum tally, allowing a single malicious peer with
    // multiple connections to dominate the agreement count. Dedup by
    // `_peerIdOf` (which extracts the LAST `/p2p/<id>` segment, i.e. the
    // remote peer's libp2p PeerId for both direct and circuit-relay
    // multiaddrs). Preserves first-seen order so the preferredPeer (placed
    // at index 0 above) remains first.
    //
    // IMPORTANT: dedup applies only to `quorumPeers`. The legacy
    // single-peer load path (when `loadQuorumEnabled: false`) keeps the
    // ORIGINAL `orderedPeers` so it can retry across multiple multiaddrs
    // for the same peer id -- e.g. a direct connection + a relay-circuit
    // fallback. Collapsing those to one entry pre-quorum would silently
    // break the legacy fallback even when the quorum gate is off. See PR
    // #284 r7 Copilot review.
    const quorumPeers = dedupePeersByPeerId(
      orderedPeers,
      (p) => this._peerIdOf(p),
    );

    // Initial-load quorum gate (#189 §5.4.2 / #186).
    //
    // Run BEFORE the existing single-peer snapshot/doc-load loop so that a
    // failed quorum aborts the load entirely (the caller cannot accidentally
    // accept a single peer's response). When the gate is disabled we fall
    // through to the legacy loop unchanged so existing callers see the same
    // behaviour.
    //
    // `winningHashHex` (set when quorum passes) is also used below as the
    // per-peer binding check inside `_sendLoadRequestAndSync`. The check
    // is purely structural and runs BEFORE the served state is applied:
    // the loader hashes `computeServedFrontier(message.changeId,
    // message.changes, message.snapshot?.lastChangeNodeCID)` and compares
    // to `winningHashHex`. If they disagree, an agreeing peer voted for
    // one tip set and served a different one (Byzantine equivocation):
    // the peer is recorded as a bind failure and the loader retries the
    // next agreeing peer without ever mutating in-memory state. The
    // pre-apply ordering is the load-bearing property -- a Byzantine peer
    // cannot poison the in-memory document because the bind decision
    // happens before `sync()` runs. See PR #284 r7 Copilot review.
    // NOTE: previously this block bypassed the gate when `_hashes.size === 0`
    // on the assumption it identified a "founding-member" brand-new document.
    // That bypass was unsafe: `_hashes` is ALSO empty on the first `open()`
    // of an EXISTING document (before load populates it), which is exactly
    // the case the gate is meant to protect. We no longer special-case empty
    // local state; the gate runs uniformly. New-document creation in an
    // EXISTING swarm is handled by the `'unknown-doc'` probe sentinel: each
    // peer that does not have the document responds with the 1-byte UNKNOWN_DOC
    // marker (see `Peerborne.tipAdvertiseHandler`), the orchestrator tallies
    // these alongside tip-hash votes, and a Q-of-K majority of disclaims
    // surfaces as `{ newDoc: true }` here -- the loader returns `false` and
    // `open()` proceeds to create the doc fresh. True founders (no peers in
    // the mesh) are still handled by the `peers.length === 0` short-circuit
    // at the top of `load()` plus the `k === 0` branch inside `runLoadQuorum`
    // (which returns `{ skipped: true }`). See PR #284 r16 Copilot review.
    //
    // The K-of-Q decision logic itself lives in `runLoadQuorum`
    // (`load-quorum-orchestrator.ts`) so the orchestration can be unit-tested
    // without standing up a libp2p/Helia stack. The orchestrator is given a
    // probe-fn closure that captures this document's `_raceTipAdvertiseProbe`
    // (the only network-touching call); narrowing, agreement counting, and
    // single-peer fallback all happen in pure code with the same control
    // flow as before the extraction. See PR #284 r4 Copilot review for the
    // test-coverage rationale.
    const timeoutMs = this.swarm.config?.loadQuorumTimeoutMs ?? 5000;
    const quorumResult = await runLoadQuorum({
      peers: quorumPeers,
      peerIdOf: (p) => this._peerIdOf(p),
      probeFn: (peer) =>
        this._raceTipAdvertiseProbe(peer, serializedRequest, timeoutMs),
      documentPath: this.documentPath,
      config: {
        enabled: this.swarm.config?.loadQuorumEnabled ?? true,
        k: this.swarm.config?.loadQuorumK ?? 3,
        q: this.swarm.config?.loadQuorumQ,
        timeoutMs,
        allowSinglePeer:
          this.swarm.config?.loadQuorumAllowSinglePeer ?? false,
      },
    });

    let winningHashHex: string | null = null;
    if ('skipped' in quorumResult) {
      // `runLoadQuorum` returns `{ skipped: true }` in two cases: (a) the
      // gate is disabled wholesale (`loadQuorumEnabled: false`), or (b) the
      // effective K resolved to 0 because no peers were known. For (a) we
      // fall through to the legacy single-peer load loop unchanged --
      // `orderedPeers` is intentionally NOT deduped here so the loop can
      // retry across multiple multiaddrs for the same peer id (e.g. a
      // direct connection + a relay-circuit fallback). For (b) there is
      // nothing to load against — treat as new document. The peer-list
      // empty short-circuit at the top of `load()` already covers the
      // trivial "no peers" path; this branch is reached when quorum is
      // enabled with a valid K but the post-dedup `quorumPeers` happens
      // to be empty.
      //
      // Note: a misconfigured `loadQuorumK <= 0` no longer reaches this
      // branch — `runLoadQuorum` throws `LoadQuorumFailedError(invalid-
      // config)` for that case so the misconfiguration is loud at
      // `open()` time instead of silently forking the document. See PR
      // #284 r5 Copilot review.
      const quorumWasEnabled = this.swarm.config?.loadQuorumEnabled ?? true;
      if (quorumWasEnabled && quorumPeers.length === 0) {
        return false;
      }
      // Else: gate disabled. Fall through with the original (un-deduped)
      // `orderedPeers` so the legacy loop can retry per-multiaddr.
    } else if ('newDoc' in quorumResult) {
      // A Q-of-K majority of probed peers explicitly disclaimed the
      // document via the `'unknown-doc'` sentinel. Return `false` so
      // `open()` can create the document fresh on top of the existing
      // swarm. Without this branch, the previous design conflated
      // unknown-doc with partition / timeout and surfaced
      // `LoadQuorumFailedError` -- preventing new-document creation in
      // any swarm with online peers. See PR #284 r16 Copilot review.
      return false;
    } else {
      winningHashHex = quorumResult.winningHashHex;
      // Quorum succeeded: narrow the load loop to the agreeing cohort.
      // The narrowed list is already deduped (it is a filter of
      // `quorumPeers`), so we replace `orderedPeers` wholesale.
      orderedPeers.length = 0;
      orderedPeers.push(...quorumResult.narrowedPeers);
    }

    // Capture the post-narrow cohort size so the failure-reason decision
    // below can distinguish "every agreeing peer bind-failed" (coordinated
    // Byzantine equivocation on the load step -- the dedicated
    // `bind-check-failed-all-agreeing-peers` reason) from "some agreeing
    // peers bind-failed, others failed for transport/protocol reasons"
    // (mixed failure -- caller should treat as transient and retry, the
    // `agreeing-peers-unreachable` reason). The previous logic used
    // `bind-check-failed-all-agreeing-peers` whenever ANY bind failure was
    // recorded, which contradicted the reason's public name and could
    // make callers treat a mixed transient retrieval failure as
    // coordinated Byzantine behaviour. See PR #284 r17 Copilot review.
    // For the legacy non-quorum path (`winningHashHex === null`), this
    // value is unused -- the failure block guards on `winningHashHex`.
    const narrowedCohortSize = orderedPeers.length;

    // Try snapshot-load first for faster initial sync.
    // If the peer returns an empty response (no snapshot available),
    // fall back to the regular doc-load protocol.
    //
    // Quorum frontier binding: when `winningHashHex` is non-null,
    // `_sendLoadRequestAndSync` derives the responder's served frontier
    // STRUCTURALLY from the actual `changes`/`snapshot` payload via
    // `computeServedFrontier`, hashes that, and verifies it equals
    // `winningHashHex` BEFORE applying the sync, so a Byzantine peer
    // that voted for one tip set and serves a different one never gets
    // to mutate in-memory document state. The responder-supplied
    // `message.tips` is checked as a defense-in-depth consistency
    // requirement but is NOT the source of truth -- previous rounds
    // trusted it as such, which let a Byzantine peer game the binding
    // by populating `tips` with the agreed CIDs while serving a
    // divergent `changes` payload. See PR #284 r7 Copilot review.
    //
    // Per-peer bind failures (`_QuorumBindCheckFailedError`) are NOT
    // fatal to the whole load -- they only disqualify the offending
    // peer. The loop records the failure and continues to the NEXT
    // peer in the agreeing cohort, so a single malicious peer that
    // voted for the majority hash and then served a mismatched full
    // load cannot DoS the entire load. Only after every peer in the
    // narrowed cohort has bind-failed does `load()` escalate to
    // `LoadQuorumFailedError(bind-check-failed-all-agreeing-peers)`.
    // See PR #284 r6 Copilot review.
    //
    // The `agreeingPeerBindFailures` map records, per peer, the hex
    // hash the served payload's structural frontier actually hashed to
    // (or the hex of the responder's contradicting `tips` attestation
    // when the defense-in-depth secondary check fails). This is
    // threaded into the final error so callers / operators can see
    // which peers in the agreeing cohort equivocated between the
    // probe round and the load round and what they served instead.
    const agreeingPeerBindFailures = new Map<string, string>();
    for (const peer of orderedPeers) {
      let peerBindFailed = false;
      // An explicitly disabled compaction policy cannot produce snapshots in
      // this swarm. Avoid an empty request/response round-trip—especially on
      // limited circuit-relay connections—before the real document load.
      if (this._compactionConfig.enabled) {
        try {
          console.log('Trying snapshot-load from peer:', peer.toString());
          // dialProtocol returns a libp2p v3 `Stream` (event-driven, with a
          // `send()`/iterator pair). Wrap it into the v2 `{ source, sink }`
          // duplex shape that `_sendLoadRequestAndSync` (and the legacy
          // `it-pipe` calls inside it) still expects.
          const snapshotStream = wrapStream(await this.libp2p.dialProtocol(peer, [
            snapshotLoadV3,
          ], { runOnLimitedConnection: true }));
          const loaded = await this._sendLoadRequestAndSync(
            snapshotStream,
            serializedRequest,
            winningHashHex,
          );
          if (loaded) {
            return true;
          }
          // Empty response -- peer has no snapshot, try doc-load below.
        } catch (err) {
          if (err instanceof _QuorumBindCheckFailedError) {
            // This peer voted hash X in the probe round but the structural
            // frontier of their served payload hashes to something else
            // (or their advertised `tips` contradicts the served payload).
            // Record the failure and skip the doc-load fallback for this
            // peer -- a peer that equivocated once is not given a second
            // chance on the same load round.
            console.warn(
              `[${this.documentPath}] Agreeing peer ${peer.toString()} failed ` +
                `quorum frontier bind on snapshot-load (offending hash ${err.advertisedHex}); ` +
                `marking peer as Byzantine for this load and trying next peer in agreeing cohort.`,
            );
            agreeingPeerBindFailures.set(this._peerIdOf(peer), err.advertisedHex);
            peerBindFailed = true;
          }
          // Else: peer doesn't support snapshot-load protocol, or some
          // other transient error -- fall through to doc-load below.
        }
      }

      if (peerBindFailed) {
        // Don't retry doc-load against a peer that already equivocated
        // on snapshot-load -- continue to the next peer in the cohort.
        continue;
      }

      try {
        console.log('Trying doc-load from peer:', peer.toString());
        // See snapshot-load above for why we wrap the v3 Stream here.
        const docStream = wrapStream(await this.libp2p.dialProtocol(peer, [
          documentLoadV3,
        ], { runOnLimitedConnection: true }));
        const loaded = await this._sendLoadRequestAndSync(
          docStream,
          serializedRequest,
          winningHashHex,
        );
        if (loaded) {
          return true;
        }
      } catch (err) {
        if (err instanceof _QuorumBindCheckFailedError) {
          console.warn(
            `[${this.documentPath}] Agreeing peer ${peer.toString()} failed ` +
              `quorum frontier bind on doc-load (offending hash ${err.advertisedHex}); ` +
              `marking peer as Byzantine for this load and trying next peer in agreeing cohort.`,
          );
          agreeingPeerBindFailures.set(this._peerIdOf(peer), err.advertisedHex);
          continue;
        }
        console.warn(
          `Failed to load document via ${documentLoadV3}:`,
          peer.toString(),
          err,
        );
      }
    }

    // If quorum was actually run (`winningHashHex !== null`) but the
    // load loop is exhausted, the cohort agreed the document exists
    // yet none of them could serve it. Three sub-cases:
    //
    //   a) `agreeingPeerBindFailures.size === narrowedCohortSize` --
    //      EVERY peer in the agreeing cohort voted for the agreed
    //      hash and then served a divergent payload. Coordinated
    //      Byzantine behaviour is the only explanation; we escalate
    //      with the dedicated `bind-check-failed-all-agreeing-peers`
    //      reason whose public docs say exactly this.
    //
    //   b) `agreeingPeerBindFailures.size > 0` but less than the
    //      cohort size -- MIXED failure: some peers bind-failed
    //      (suspicious) and others failed for transport/protocol
    //      reasons (likely transient). We can't conclude coordinated
    //      Byzantine equivocation across the whole cohort, so we
    //      report `'agreeing-peers-unreachable'` and let the caller
    //      retry. Using `bind-check-failed-all-agreeing-peers` here
    //      would contradict the reason's public name/docs and could
    //      make callers wrongly treat a mixed transient failure as
    //      coordinated Byzantine behaviour. The `agreeingPeerBindFailures`
    //      map is still threaded through for diagnostics so operators
    //      can see which peers in the cohort did bind-fail.
    //      See PR #284 r17 Copilot review.
    //
    //   c) `agreeingPeerBindFailures.size === 0` -- every agreeing
    //      peer failed for a transport/protocol reason; we surface
    //      the failure with `'agreeing-peers-unreachable'` so the
    //      caller decides whether to retry or surface to the user.
    //      We MUST NOT fall through to `return false` -- that would
    //      let `open()` initialize a brand-new document despite
    //      quorum just attesting that the document exists.
    //
    // Only after a TRUE no-quorum-was-run outcome (winningHashHex
    // is null -- legacy non-quorum load or quorum disabled / no
    // peers / etc.) is `return false` the right answer.
    if (winningHashHex !== null) {
      if (
        narrowedCohortSize > 0 &&
        agreeingPeerBindFailures.size === narrowedCohortSize
      ) {
        throw new LoadQuorumFailedError({
          documentPath: this.documentPath,
          reason: 'bind-check-failed-all-agreeing-peers',
          respondingCount: 0,
          requiredQ: 0,
          agreement: new Map([[winningHashHex, 0]]),
          agreeingPeerBindFailures,
        });
      }
      throw new LoadQuorumFailedError({
        documentPath: this.documentPath,
        reason: 'agreeing-peers-unreachable',
        respondingCount: 0,
        requiredQ: 0,
        agreement: new Map([[winningHashHex, 0]]),
        agreeingPeerBindFailures,
      });
    }

    // No peer could provide the document -- assume new document.
    console.log('Failed to open document on any nodes.', this);
    return false;
  }

  /**
   * Opens this peerborne document. The sequence of operations is:
   *
   * 1. Call `.load()` to fetch the document from an existing peer via direct dial.
   * 2. If the document is new (load returned false), run `validateDocumentPath`
   *    (if configured) to ensure the path is allowed before proceeding.
   * 3. Assign the pubsub message handler, subscribe to the document's GossipSub
   *    pubsub topic, and register protocol handlers for load, key-update, and
   *    snapshot-load requests.
   * 4. If `enableTopicValidators` is set, register a GossipSub topic validator
   *    that rejects messages that fail signature verification.
   * 5. For new documents, add the current user as a writer and generate an
   *    initial document encryption key.
   *
   * Once opened, a document can be closed with `.close()`.
   *
   * **Design note:** `load()` runs before protocol handlers are registered, so
   * this node cannot serve incoming load/key-update requests for *this* document
   * during the load window. This is intentional -- validation must complete before
   * subscribing to pubsub to prevent briefly joining an unauthorized topic, and
   * the document is not yet fully open so it has nothing to serve.
   *
   * **Race window:** Messages published by peers between the `load()` response
   * and the `pubsub.subscribe()` call will be missed. This is a deliberate
   * trade-off: validation must complete before subscribing to prevent briefly
   * joining an unauthorized topic. The window is mitigated by the fact that
   * subsequent messages will arrive once subscribed, and the underlying CRDT
   * guarantees eventual consistency. Callers who need to ensure no messages
   * were missed should call `load()` again after `open()` resolves to re-sync
   * the latest state from a peer.
   *
   * @returns `false` when `load()` returned `false` and no existing state had
   *   already been loaded. In that case `open()` treats the document as new by
   *   adding the current user as a writer and generating an initial encryption
   *   key. Note that `load()` returning `false` is ambiguous: it may also mean
   *   all peers failed (see `load()` docs for details).
   * @throws {Error} If `validateDocumentPath` is configured and rejects the path
   *   for a new document. Validation runs before subscribing to pubsub or
   *   registering protocol handlers, so no cleanup is needed on rejection.
   */
  public async open(): Promise<boolean> {
    // Cache the topic once so that subscribe and unsubscribe always target
    // the same string, even if config.pubsubDocumentPrefix changes later.
    this._topic = this._computeTopic();

    // Load initial document from peers via direct dial (no subscription needed).
    const loadedFromPeer = await this.load();
    const isExisting = loadedFromPeer || this._hashes.size > 0;

    // Validate document path BEFORE subscribing to pubsub or registering
    // protocol handlers. This prevents temporarily joining an unauthorized topic.
    // _pubsubHandler is not yet assigned, so if validation throws, close() will
    // not attempt to unsubscribe from a subscription that was never created.
    if (!isExisting) {
      const validateFn = this.swarm.config?.validateDocumentPath;
      if (validateFn) {
        let allowed: boolean;
        try {
          allowed = await validateFn(this.documentPath, this._userPublicKey);
        } catch (err) {
          throw err instanceof Error ? err : new Error(String(err));
        }
        if (!allowed) {
          throw new Error(
            `Document path "${this.documentPath}" is not allowed for the current user`,
          );
        }
      }
    }

    // Assign pubsub handler AFTER validation succeeds. This ensures close()
    // won't try to unsubscribe if open() failed during validation.
    this._pubsubHandler = (rawMessage) => {
      // Decrypt sync message.
      const blockKeyID = rawMessage.detail.data.slice(
        0,
        this._keychainProvider.keyIDLength,
      );
      const blockNonce = rawMessage.detail.data.slice(
        this._keychainProvider.keyIDLength,
        this._keychainProvider.keyIDLength + this._authProvider.nonceBits,
      );
      const blockData = rawMessage.detail.data.slice(
        this._keychainProvider.keyIDLength + this._authProvider.nonceBits,
      );
      this._decryptBlock(blockKeyID, blockNonce, blockData).then(
        (rawContent) => {
          if (!rawContent) {
            // If we're unable to decrypt the document, try a fresh document load.
            console.warn(
              'Trying to re-load document... Unable to decrypt incoming message',
            );
            // Prefer loading from the sending peer -- they created this change
            // and should have the document key(s) needed to read it.
            const senderPeer = rawMessage.detail.type === 'signed' ? rawMessage.detail.from : undefined;
            return this.load(senderPeer);
          }

          const message =
            this._syncMessageSerializer.deserializeSyncMessage(rawContent);

          return this.sync(message);
        },
      );
    };

    // All registration and subscription steps are inside try/catch so that
    // close() cleans up any partially-registered state on failure.
    const pubsub = this.swarm.heliaNode.libp2p.services
      .pubsub as GossipSub;

    try {
      // Register this document with the swarm BEFORE subscribing to pubsub.
      // registerDocument() throws on duplicate document paths; doing this first
      // avoids subscribing to a topic that would then be unsubscribed by close()
      // on failure, which could disrupt an already-open instance for the same path.
      this.swarm.registerDocument(this.documentPath, this);

      // Subscribe to pubsub topic.
      // Cast required: EventHandler<CustomEvent<Message>> is incompatible with PubSubBaseProtocol's
      // addEventListener due to duplicate @libp2p/interface versions in the dependency tree
      pubsub.addEventListener('message', this._pubsubHandler as EventListener);
      pubsub.subscribe(this._topic);
      this._subscribed = true;

      // Register GossipSub topic validator for authorization enforcement.
      // When enabled, messages from unauthorized peers are rejected at the
      // transport layer with a P4 penalty in peer scoring.
      // Skip entirely when signing is disabled to avoid unnecessary per-message decryption.
      if (this.swarm.config?.enableTopicValidators && this._isSigningEnabled()) {
        if (typeof pubsub.topicValidators?.set === 'function') {
          pubsub.topicValidators.set(
            this._topic,
            async (
              _peerId: PeerId,
              message: Message,
            ): Promise<TopicValidatorResult> => {
              try {
                // Decrypt the message to access the signature.
                const blockKeyID = message.data.slice(
                  0,
                  this._keychainProvider.keyIDLength,
                );
                const blockNonce = message.data.slice(
                  this._keychainProvider.keyIDLength,
                  this._keychainProvider.keyIDLength + this._authProvider.nonceBits,
                );
                const blockData = message.data.slice(
                  this._keychainProvider.keyIDLength + this._authProvider.nonceBits,
                );
                const rawContent = await this._decryptBlock(
                  blockKeyID,
                  blockNonce,
                  blockData,
                );
                if (!rawContent) {
                  // Decryption failed -- key may not be in keychain yet
                  console.warn(`[${this.documentPath}] Topic validator: decryption failed, ignoring message`);
                  return TopicValidatorResult.Ignore;
                }

                const syncMessage =
                  this._syncMessageSerializer.deserializeSyncMessage(rawContent);

                if (!syncMessage.signature) {
                  return TopicValidatorResult.Reject;
                }

                const { signature, ...messageWithoutSignature } = syncMessage;
                const raw =
                  this._syncMessageSerializer.serializeSyncMessage(
                    messageWithoutSignature,
                  );

                // Verify the message was signed by an authorized writer for this document
                if (await this._verifyWriterSignature(raw, signature)) {
                  return TopicValidatorResult.Accept;
                }
                return TopicValidatorResult.Reject;
              } catch {
                console.warn(`[${this.documentPath}] Topic validator: unexpected error, ignoring message`);
                return TopicValidatorResult.Ignore;
              }
            },
          );
        }
      }

      if (!isExisting) {
        // Add current user as a writer.
        const founderWriterChanges = await this._addWriter(this._userPublicKey);

        // Add initial document key.
        console.log(`Adding a key to ${this.documentPath}`);
        await this._keychain.add();

        // The founder ACL must be part of the replicated change DAG. Keeping
        // it only in the creator's in-memory ACL lets first-load peers decrypt
        // document state but leaves them unable to authenticate later writer
        // updates (or write as the same restored identity).
        await this._makeChange(founderWriterChanges, crdtWriterChangeNode);
      }
    } catch (err) {
      // Clean up any partially-registered state to avoid leaked handlers,
      // subscriptions, or registry entries.
      await this.close().catch(() => {});
      throw err;
    }

    return isExisting;
  }

  /**
   * Disconnects from this peerborne document. Running this method disconnects from the
   * document pubsub topic.
   *
   * **Limitation:** Multiple `PeerborneDocument` instances sharing the same
   * `documentPath` are not supported. Calling `close()` on one instance will
   * remove the GossipSub topic validator and unsubscribe from the pubsub topic,
   * breaking any other instance using the same path.
   */
  public async close() {
    // Use the cached topic for cleanup; it is initialized in the constructor.
    const topic = this._topic;

    if (this._pubsubHandler) {
      const pubsub = this.swarm.heliaNode.libp2p.services
        .pubsub as GossipSub;

      // Only unsubscribe if this instance actually subscribed. If open()
      // failed before pubsub.subscribe() completed, unsubscribing here
      // would remove a subscription belonging to another instance.
      if (this._subscribed) {
        pubsub.unsubscribe(topic);
        this._subscribed = false;
      }

      // Cast required: see addEventListener comment above
      pubsub.removeEventListener('message', this._pubsubHandler as EventListener);

      // Always attempt to remove the GossipSub topic validator. This is safe
      // even if none was registered (Map.delete is a no-op for missing keys),
      // and ensures cleanup regardless of config changes between open() and close().
      pubsub.topicValidators?.delete(topic);
    }

    // Unregister this document from the shared V2 protocol handler registry.
    // Pass `this` so only this instance is removed (instance-safe).
    this.swarm.unregisterDocument(this.documentPath, this);
  }

  /**
   * Given a sync message containing a list of hashes:
   * - Fetch new changes that are only hashes (missing change itself) from the blockstore (using the hash).
   * - Apply new changes to the existing CRDT document.
   *
   * @param message A sync message to apply.
   * @param verifySignature Whether to verify the message signature (default: true).
   * @returns `true` if the message was applied successfully, `false` if rejected due to auth failure.
   *
   * **BREAKING CHANGE:** Return type changed from `Promise<void>` to
   * `Promise<boolean>`. TypeScript callers with explicit `Promise<void>` type
   * annotations will need to update. Callers should now check the returned
   * boolean to determine whether the message was applied successfully.
   */
  public async sync(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
    verifySignature = true,
  ): Promise<boolean> {
    const { signature, ...messageWithoutSignature } = message;
    const signingEnabled = this._isSigningEnabled();
    if (signingEnabled && !signature) {
      return false;
    }

    // Only serialize for signature verification -- skip when signing is disabled
    // to avoid expensive serialization of large messages.
    if (signingEnabled && verifySignature) {
      const raw = this._syncMessageSerializer.serializeSyncMessage(
        messageWithoutSignature,
      );
      if (!(await this._verifyWriterSignature(raw, signature!))) {
        console.warn(
          `Received a sync message with an invalid signature for ${message.documentId}`,
        );
        return false;
      }
    }

    // Update/replace list of document keys (if provided).
    if (message.keychainChanges) {
      try {
        this._keychain.merge(message.keychainChanges);
        console.log(`Updated keychain in ${this.documentPath}`);
      } catch (e) {
        console.error(
          `Failed to merge keychain changes in ${this.documentPath}`,
          e,
        );
        throw e;
      }
    }

    // Pre-pass: apply only ACL nodes from the change tree to populate
    // _writers/_readers. This is needed before snapshot verification since
    // _verifySnapshotSignature() requires writer keys. ACL merges are
    // idempotent, so re-applying them in _syncDocumentChanges() is safe.
    if (message.changes) {
      this._applyACLFromTree(message.changes);
    }

    // Apply snapshot if present and more recent than ours.
    // Happens before full change sync so document changes that are already
    // covered by the snapshot don't need to be applied first (CRDTs handle
    // duplicate application correctly, but this avoids unnecessary work).
    if (message.snapshot) {
      const incoming = message.snapshot;
      if (
        !this._latestSnapshot ||
        incoming.compactedCount > this._latestSnapshot.compactedCount ||
        (incoming.compactedCount === this._latestSnapshot.compactedCount &&
          String(incoming.lastChangeNodeCID ?? '') >
            String(this._latestSnapshot.lastChangeNodeCID ?? ''))
      ) {
        // Verify the snapshot signature against the deterministic payload
        // by trying all authorized writers (publicKey may not survive
        // serialization for all key types, e.g. CryptoKey).
        // When signing is disabled, skip serialization and signature
        // verification -- accept the snapshot unconditionally.
        // WARNING: This means any peer can inject arbitrary snapshot state when
        // signing is disabled. Only disable signing in trusted or development
        // environments where all peers are known and authenticated by other means.
        let snapshotSignatureValid = !signingEnabled;
        if (signingEnabled) {
          try {
            const stateBytes = this._changesSerializer.serializeChanges(incoming.state);
            const signPayload = this._buildSnapshotSignPayload(
              stateBytes, incoming.lastChangeNodeCID, incoming.timestamp, incoming.compactedCount,
            );
            snapshotSignatureValid = await this._verifySnapshotSignature(
              signPayload, incoming.signature,
            );
          } catch (e) {
            console.warn(
              `Rejected snapshot for ${this.documentPath}: malformed snapshot fields`,
              e,
            );
          }
        }
        if (!snapshotSignatureValid) {
          console.warn(
            `Rejected snapshot for ${this.documentPath}: no authorized writer produced a valid signature`,
          );
        } else {
          // Apply the snapshot state. Use applySnapshot when available (e.g.
          // Automerge save format differs from incremental changes), otherwise
          // fall back to remoteChange (works for Yjs where snapshots are valid updates).
          this._document = this._crdtProvider.applySnapshot
            ? this._crdtProvider.applySnapshot(this._document, incoming.state)
            : this._crdtProvider.remoteChange(this._document, incoming.state);
          this._latestSnapshot = incoming;
          // Ensure our local document change count is at least as high as
          // the snapshot's compactedCount. This prevents re-triggering
          // compaction below the threshold after applying a remote snapshot.
          this._documentChangeCount = Math.max(
            this._documentChangeCount,
            incoming.compactedCount,
          );
          this._changesSinceSnapshot = 0;
          // Mark the snapshot boundary CID as seen so _mergeSyncTree skips
          // it and all ancestor nodes. This prevents re-applying pre-snapshot
          // changes (which the snapshot already covers) and avoids inflating
          // _documentChangeCount / _changesSinceSnapshot.
          if (incoming.lastChangeNodeCID) {
            this._hashes.add(incoming.lastChangeNodeCID);
          }
          console.log(
            `Applied remote snapshot for ${this.documentPath}: ${incoming.compactedCount} nodes compacted`,
          );
        }
      }
    }

    // Full change sync: process all nodes (document + ACL) from the DAG.
    // ACL nodes applied in the pre-pass above will be re-merged idempotently.
    if (message.changes) {
      await this._syncDocumentChanges(message.changeId, message.changes);
    }

    return true;
  }

  /**
   * Subscribes a change handler to the document. Use this method to receive real-time
   * updates to the document.
   *
   * @param id A unique id for this handler. Used to unsubscribe this handler.
   * @param handler A function that is called when a change is received.
   * @param originFilter Determines what kinds of change events trigger the handler.
   *     'remote' indicates that the change was received from a remote peer.
   *     'local' indicates that the change was received from the local document.
   *     'all' indicates that all changes should be handled.
   */
  public subscribe(
    id: string,
    handler: PeerborneDocumentChangeHandler<DocType, PublicKey>,
    originFilter: 'all' | 'remote' | 'local' = 'all',
  ) {
    switch (originFilter) {
      case 'all': {
        this._remoteHandlers[id] = handler;
        this._localHandlers[id] = handler;
        break;
      }
      case 'remote': {
        this._remoteHandlers[id] = handler;
        break;
      }
      case 'local': {
        this._localHandlers[id] = handler;
        break;
      }
    }
  }

  /**
   * Unsubscribes a change handler from the document.
   *
   * @param id The id of the handler to unsubscribe.
   */
  public unsubscribe(id: string) {
    if (this._remoteHandlers[id]) {
      delete this._remoteHandlers[id];
    }
    if (this._localHandlers[id]) {
      delete this._localHandlers[id];
    }
  }

  // TODO: Unit tests for PeerborneDocument require mocking libp2p, Helia,
  // and all providers -- deferred to integration testing (see e2e/).

  /**
   * Start a change transaction. Changes made via `addChange()` will be batched
   * and applied atomically when `endChange()` is called.
   */
  public startChange() {
    if (this._inTransaction) {
      throw new Error('Transaction already in progress');
    }
    this._inTransaction = true;
    this._pendingChangeFns = [];
  }

  /**
   * Queue a change function within an active transaction.
   * Must be called between `startChange()` and `endChange()`.
   */
  public addChange(changeFn: ChangeFnType) {
    if (!this._inTransaction) {
      throw new Error('No transaction in progress. Call startChange() first.');
    }
    if (this._committing) {
      throw new Error('Cannot add changes while endChange() is committing.');
    }
    this._pendingChangeFns.push(changeFn);
  }

  /**
   * End the transaction and apply all queued changes atomically.
   * This sends a single sync message for all batched changes.
   *
   * On failure (from any step: write check, CRDT apply, or network publish),
   * the transaction is aborted and the document reference is rolled back.
   * For immutable CRDT providers (e.g. Automerge), rollback is reliable
   * because `localChange()` returns a new document object.
   *
   * **Known limitation -- in-place mutating providers:** For CRDT providers
   * that mutate in place (e.g. Yjs), rollback does NOT undo mutations.
   * Yjs's `localChange()` mutates the document object directly and returns
   * the same reference, so restoring the saved reference after failure has
   * no effect -- the mutations have already been applied to the shared
   * Y.Doc. Callers using Yjs should treat a failed transaction as leaving
   * the local document in a potentially inconsistent state and consider
   * re-syncing from peers.
   *
   * **Known limitation -- concurrent remote changes during rollback:** The
   * rollback sets `_document` back to the snapshot captured when
   * `endChange()` is called (before applying the pending change functions).
   * Because `_makeChange()` is async and the node remains
   * subscribed to pubsub throughout, remote sync messages may arrive and be
   * applied to `_document` between the start of the transaction and the
   * point of failure. Rolling back to the original snapshot **reverts those
   * remote changes as well**, not just the local batch. This is acceptable
   * because the CRDT layer guarantees eventual consistency -- the reverted
   * remote changes will be re-applied on the next sync cycle or document
   * load. If transaction failure is critical, callers should re-sync the
   * document after a failed transaction (e.g. call `load()` or wait for
   * the next pubsub round) to ensure remote state is promptly restored.
   *
   * **Known limitation -- partial internal state on failure:** If
   * `_makeChange()` fails partway through (e.g. encryption succeeds but
   * pubsub publish throws), `_hashes` may retain CIDs for the rolled-back
   * change (see below). Other counters and bookkeeping fields
   * (`_lastSyncMessage`, `_documentChangeCount`, `_changesSinceSnapshot`,
   * `_recentTips`) ARE restored from snapshots captured before
   * `_makeChange()` -- see the "Internal metadata rollback" section below
   * for details.
   *
   * **Specifically, `_hashes` may retain CIDs for the rolled-back change.**
   * Because `_hashes` is used to skip already-seen changes during sync,
   * any CID added before the failure will cause that change to be silently
   * skipped if it arrives again via pubsub or `load()`. This means the
   * rolled-back change is effectively "lost" from this peer's perspective
   * until `_hashes` is rebuilt. **Callers should call `load()` after a
   * failed transaction** to re-sync the full document state from a peer
   * and restore consistency. A new transaction must be started after a
   * failure.
   *
   * **Internal metadata rollback:** On failure, `_lastSyncMessage`,
   * `_documentChangeCount`, `_changesSinceSnapshot`, and `_recentTips`
   * are restored from snapshots captured before `_makeChange()`.
   * (`_recentTips` is bounded to `MAX_RECENT_TIPS` entries so the snapshot
   * is a cheap shallow array copy.) For `_hashes` and
   * `_referencedAncestors`, all entries added to each Set after its
   * pre-attempt size are removed. Because the node remains
   * subscribed to pubsub during the async transaction, this may include
   * CIDs appended by concurrent remote syncs, not just local ones.
   * This is acceptable because CRDT convergence guarantees those remote
   * CIDs will be re-added on the next sync cycle or document load.
   * The approach is O(n) iteration but O(delta) memory -- no full
   * array clone -- and avoids disrupting any concurrent sync iteration
   * that `clear()` would break. A new transaction must be started after
   * a failure.
   *
   * @throws {Error} If any step in the commit pipeline fails.
   */
  public async endChange(message?: string) {
    if (!this._inTransaction) {
      throw new Error('No transaction in progress. Call startChange() first.');
    }
    if (this._committing) {
      throw new Error('endChange() is already in progress. Await the previous call.');
    }

    // Snapshot pending fns so late addChange() calls during await don't
    // unpredictably modify the batch being committed.
    const pendingFns = [...this._pendingChangeFns];
    if (pendingFns.length === 0) {
      this._inTransaction = false;
      this._pendingChangeFns = [];
      return;
    }

    const originalDocument = this.document;
    // Snapshot internal metadata so we can restore on failure.
    // Only track the Set size (O(1)) instead of cloning the entire Set (O(n)):
    // _makeChange adds at most one CID, and JS Sets iterate in insertion order,
    // so on rollback we remove only entries appended after this point.
    const hashSizeBefore = this._hashes.size;
    const referencedAncestorsSizeBefore = this._referencedAncestors.size;
    const lastSyncSnapshot = this._lastSyncMessage;
    const changeCountSnapshot = this._documentChangeCount;
    const compactionCountSnapshot = this._changesSinceSnapshot;
    // Bounded copy (max MAX_RECENT_TIPS entries) -- cheap to snapshot.
    const recentTipsSnapshot = [...this._recentTips];

    this._committing = true;
    try {
      await this._ensureCurrentUserCanWrite();

      // Compose all queued change functions into a single localChange call
      // to produce one atomic delta. This ensures providers like Automerge
      // (which return incremental deltas) don't drop earlier changes.
      const composedFn = ((doc: any) => {
        for (const fn of pendingFns) {
          (fn as any)(doc);
        }
      }) as ChangeFnType;

      // Note: YjsProvider.localChange mutates the document in-place and returns
      // the same reference, so rollback on failure is best-effort for Yjs.
      // Automerge returns a new immutable document, so rollback is reliable.
      const [newDocument, changes] = this._crdtProvider.localChange(
        this.document,
        message || '',
        composedFn,
      );
      this._document = newDocument;

      await this._makeChange(changes);

      // Success -- clear transaction state.
      this._inTransaction = false;
      this._pendingChangeFns = [];
    } catch (err) {
      // Abort transaction on ANY error (ensureWrite, localChange, or makeChange).
      // Roll back document and internal metadata (best-effort for in-place
      // mutating providers like Yjs).
      this._document = originalDocument;
      // Remove only the CIDs appended by _makeChange instead of clearing and
      // re-populating the entire Set. This avoids mutating the Set during
      // concurrent sync (clear() would disrupt any in-progress iteration)
      // and is O(delta) instead of O(n).
      // Iterate the Set (O(n)) but only collect entries past the snapshot
      // threshold into a small buffer (O(delta) memory) -- avoids cloning
      // the entire Set into an array via spread.
      if (this._hashes.size > hashSizeBefore) {
        const toRemove: string[] = [];
        let i = 0;
        for (const hash of this._hashes) {
          if (i >= hashSizeBefore) {
            toRemove.push(hash);
          }
          i++;
        }
        for (const hash of toRemove) {
          this._hashes.delete(hash);
        }
      }
      // Mirror the `_hashes` rollback for `_referencedAncestors`: remove
      // only entries appended past the pre-attempt size. Same rationale --
      // insertion-ordered Set iteration plus O(delta) memory -- and same
      // best-effort caveat for concurrent sync that may have inserted into
      // either set in parallel.
      if (this._referencedAncestors.size > referencedAncestorsSizeBefore) {
        const toRemoveRefs: string[] = [];
        let j = 0;
        for (const cid of this._referencedAncestors) {
          if (j >= referencedAncestorsSizeBefore) {
            toRemoveRefs.push(cid);
          }
          j++;
        }
        for (const cid of toRemoveRefs) {
          this._referencedAncestors.delete(cid);
        }
      }
      this._lastSyncMessage = lastSyncSnapshot;
      this._documentChangeCount = changeCountSnapshot;
      this._changesSinceSnapshot = compactionCountSnapshot;
      this._recentTips = recentTipsSnapshot;
      this._inTransaction = false;
      this._pendingChangeFns = [];
      throw err;
    } finally {
      this._committing = false;
    }
  }

  /**
   * Applies a new local change (defined by `changeFn`) to the peerborne document and updates
   * all peers.
   *
   * @param changeFn A function that makes changes to the current CRDT document.
   * @param message An optional change message/description to include.
   */
  public async change(changeFn: ChangeFnType, message?: string) {
    if (this._inTransaction) {
      throw new Error('Cannot call change() during an active transaction. Use addChange() instead.');
    }
    await this._ensureCurrentUserCanWrite();

    const [newDocument, changes] = this._crdtProvider.localChange(
      this.document,
      message || '',
      changeFn,
    );
    // Apply local change w/ automerge.
    this._document = newDocument;

    await this._makeChange(changes);
  }

  /**
   * Returns the total number of change nodes (including ACL nodes) tracked
   * in the current document history. This is a count of all known CIDs,
   * not the depth of the longest path in the DAG.
   */
  public historySize(): number {
    return this._hashes.size;
  }

  /**
   * Returns the current snapshot, if one exists.
   */
  public get latestSnapshot(): CRDTSnapshotNode<ChangesType, PublicKey> | undefined {
    return this._latestSnapshot;
  }

  /**
   * Lazy-load a historical change block by CID.
   *
   * Used to fetch change data on demand for history-visibility consumers (e.g.
   * audit UI, diff viewers) when the change has been pruned from the in-memory
   * sync tree but the block is still present in the Helia blockstore. The
   * returned `ChangesType` is the deserialized, decrypted payload.
   *
   * Returns `undefined` when:
   * - The CID is not in `_hashes` (we have never seen this change).
   * - The block is missing from the blockstore (e.g. it was GC'd locally and
   *   no peer has re-served it yet). Callers that need stronger guarantees can
   *   fall back to dialing peers via the existing sync protocols.
   *
   * Throws when:
   * - The CID is malformed.
   * - The block is present locally but decryption fails (wrong/missing
   *   keychain entry) or the payload fails to deserialize (corrupted data).
   *   These are treated as hard errors so callers can distinguish a recoverable
   *   "missing block" condition from a stronger data-integrity issue.
   *
   * @param cid CID string of the change block to load.
   * @returns The deserialized change payload, or `undefined` if unavailable.
   */
  public async loadChangeBlock(cid: string): Promise<ChangesType | undefined> {
    return lazyLoadChangeBlock<CID, ChangesType>(
      cid,
      this._hashes,
      (c) => CID.parse(c),
      (parsedCID) => this._getBlock(parsedCID),
      // Intentionally no-op onMissing: missing-after-GC is an expected outcome
      // for the lazy-load path (audit UIs, diff viewers) and should not spam
      // logs. Callers that want visibility can detect `undefined` themselves.
    );
  }

  /**
   * Check whether a CID is known to this document (i.e. present in the
   * in-memory `_hashes` set). Useful for callers that want to confirm a
   * change exists before attempting a lazy load.
   *
   * Note: returning `true` only proves the CID has been observed (it is
   * tracked in `_hashes` for sync-message dedup). It does NOT guarantee the
   * underlying block is locally available -- after `gcAfterPrune` runs, the
   * CID remains in `_hashes` even though the block has been removed from the
   * blockstore. Callers should therefore still handle `loadChangeBlock(cid)`
   * resolving to `undefined` (and may need to fall back to dialing peers).
   */
  public hasChange(cid: string): boolean {
    return this._hashes.has(cid);
  }

  /**
   * Creates a snapshot of the current document state.
   *
   * The snapshot compacts all current change nodes into a single state representation.
   * Requires `CRDTProvider.getSnapshot()` to be implemented.
   *
   * @returns The created snapshot node, or undefined if the provider does not support snapshots.
   * @throws {Error} If the current user does not have write access to this document.
   *   Only writers are authorized to create snapshots.
   */
  public async snapshot(): Promise<CRDTSnapshotNode<ChangesType, PublicKey> | undefined> {
    await this._ensureCurrentUserCanWrite();

    if (!this._crdtProvider.getSnapshot) {
      console.warn('CRDTProvider does not implement getSnapshot(); compaction disabled.');
      this._snapshotUnsupported = true;
      return undefined;
    }

    const state = this._crdtProvider.getSnapshot(this._document);
    const lastChangeNodeCID = this._lastSyncMessage?.changeId ?? '';
    const timestamp = Date.now();

    // Create a deterministic, unambiguous binary payload to sign.
    // Use _documentChangeCount (document-kind changes only) rather than
    // _hashes.size (which includes ACL nodes) to keep the semantic consistent.
    // Binary layout with length prefixes avoids ambiguity and is efficient
    // for large state blobs (no JSON/Array.from overhead).
    const compactedCount = this._documentChangeCount;
    const stateBytes = this._changesSerializer.serializeChanges(state);
    let signature: Uint8Array;
    if (this._isSigningEnabled()) {
      const signPayload = this._buildSnapshotSignPayload(
        stateBytes, lastChangeNodeCID, timestamp, compactedCount,
      );
      signature = await this._authProvider.sign(signPayload, this._userKey);
    } else {
      signature = new Uint8Array(0);
    }

    const snapshotNode: CRDTSnapshotNode<ChangesType, PublicKey> = {
      state,
      lastChangeNodeCID,
      compactedCount,
      signature,
      publicKey: this._userPublicKey,
      timestamp,
    };

    this._latestSnapshot = snapshotNode;
    this._changesSinceSnapshot = 0;

    // Prune old change nodes from the in-memory sync tree if configured.
    // The snapshot is NOT stored on _lastSyncMessage -- it is only included
    // in load/snapshot-load responses via _latestSnapshot, to avoid bloating
    // every incremental pubsub sync message with the full snapshot state.
    if (this._lastSyncMessage && this._compactionConfig.pruneAfterSnapshot) {
      const prunedCIDs = this._pruneChanges(this._compactionConfig.keepRecentNodes);

      // Delete pruned blocks from the Helia blockstore asynchronously, but only
      // when explicitly opted-in via `gcAfterPrune`. Filter out any CIDs that
      // remain reachable from the post-prune sync tree (e.g. ACL nodes that
      // were re-attached as leaves) and the snapshot boundary CID itself.
      // Fire-and-forget: GC errors are logged but don't block snapshot creation.
      if (
        this._compactionConfig.gcAfterPrune &&
        prunedCIDs.size > 0 &&
        this._lastSyncMessage?.changes &&
        this._lastSyncMessage.changeId
      ) {
        const protectedCIDs = lastChangeNodeCID
          ? [lastChangeNodeCID]
          : [];
        const deletable = filterDeletableCIDs(
          prunedCIDs,
          this._lastSyncMessage.changeId,
          this._lastSyncMessage.changes,
          protectedCIDs,
        );
        if (deletable.size > 0) {
          this._gcPrunedBlocks(deletable).catch((err) => {
            console.error(`Blockstore GC failed for ${this.documentPath}:`, err);
          });
        }
      }
    }

    console.log(
      `Created snapshot for ${this.documentPath}: ${snapshotNode.compactedCount} nodes compacted`,
    );

    return snapshotNode;
  }

  /**
   * Get list of writers.
   *
   * @return List of public keys with write access.
   */
  public async getWriters(): Promise<PublicKey[]> {
    return await this._writers.users();
  }

  /**
   * Add a new user as a valid writer. Users are identified by their public keys
   *
   * @param writer User's public key
   */
  public async addWriter(writer: PublicKey) {
    await this._ensureCurrentUserCanWrite();

    // Check that the writer is not already a writer.
    if (await this._writers.check(writer)) {
      return;
    }

    // Construct a new writer ACL change.
    const changes = await this._addWriter(writer);

    await this._makeChange(changes, crdtWriterChangeNode);
  }

  /**
   * Remove a user as a valid writer. Users are identified by their public keys
   *
   * @param writer User's public key
   */
  public async removeWriter(writer: PublicKey) {
    await this._ensureCurrentUserCanWrite();

    // Check that the writer is already a writer.
    if (!(await this._writers.check(writer))) {
      return;
    }

    // Construct a new writer ACL change.
    const changes = await this._removeWriter(writer);

    await this._makeChange(changes, crdtWriterChangeNode);

    // Save the current (soon-to-be-previous) key before rotation.
    // This key is what peers currently have and can use to decrypt the update.
    const previousKey = await this._keychain.current();

    // Rotate the document key (required after removing any member with access).
    const [keyID, key, keychainChanges] = await this._keychain.add();

    // Distribute the new key to all remaining members, encrypted with the previous key.
    await this._distributeKeyUpdate(keychainChanges, previousKey);
  }

  /**
   * Returns a list of all public keys with read access.
   *
   * Deduplicates users that appear in both reader and writer ACLs,
   * which can occur due to concurrent edits or manual addition to both lists.
   *
   * @return List of public keys with read access.
   */
  public async getReaders(): Promise<PublicKey[]> {
    const [readers, writers] = await Promise.all([
      this._readers.users(),
      this._writers.users(),
    ]);
    // Filter out any writers that also appear in the readers list to avoid duplicates.
    // Run checks in parallel to avoid sequential async overhead with many writers.
    const checkResults = await Promise.all(
      writers.map(writer => this._readers.check(writer))
    );
    const filteredWriters = writers.filter((_, i) => !checkResults[i]);
    return [...readers, ...filteredWriters];
  }

  /**
   * Add a new user as a valid reader. Users are identified by their public keys.
   *
   * After updating the readers ACL, this attempts to send a BeeKEM Welcome
   * to the new reader so they receive (a) the keychain changes appropriate
   * for the document's `historyVisibility` setting (so they can decrypt at
   * least the current state), and (b) the invitation epoch ID they should
   * record for subsequent `since_invited` history filtering. The Welcome
   * is delivered via the `beekemWelcomeV1` protocol to every
   * currently-connected peer; the receiving document ignores Welcomes
   * addressed to a different reader.
   *
   * CONFIDENTIALITY: the Welcome's keychain delta is sealed with ECIES
   * (P-256 ECDH + AES-256-GCM) under `readerKemPublicKey`, so only the
   * intended recipient can decrypt it. The recipient binding
   * (`welcomeRecipient`) is the **authorization** gate; the sealed
   * payload is the **confidentiality** gate. See `_sendBeeKEMWelcome`
   * for the full construction.
   *
   * @param reader User's identity (signing) public key.
   * @param readerKemPublicKey Optional raw SEC1-uncompressed P-256
   *   ECDH public key (65 bytes) of the reader's KEM key pair. The
   *   reader must hold the matching private key (see
   *   `setKemKeyPair`). When this is `undefined`, the readers-ACL
   *   update is still broadcast but **no Welcome is sent**: the new
   *   reader can join the document but must recover keychain state
   *   via a fresh document load against an authorized peer. (The
   *   library refuses to broadcast an un-sealed Welcome to all peers
   *   because that would leak document key material in plaintext.)
   */
  public async addReader(
    reader: PublicKey,
    readerKemPublicKey?: Uint8Array,
  ) {
    await this._ensureCurrentUserCanWrite();

    // Validate prerequisites BEFORE mutating any ACL state. The founder
    // (writer who created the document) MUST have called `setKemKeyPair`
    // before they can seed the BeeKEM tree. The leaf key pair must be a
    // real ECDH key pair the founder controls so future joiners that
    // decrypt path-key encryptions against this node land on consistent
    // key material. A founder that calls `addReader` before
    // `setKemKeyPair` is misconfigured -- surface the error before any
    // ACL change is committed, so a half-applied state (ACL row added
    // but no BeeKEM seeding / Welcome sent) is impossible.
    if (!this._beekemInitialized && !this._kemKeyPair) {
      throw new Error(
        `[${this.documentPath}] addReader: cannot seed the BeeKEM ratchet ` +
          `tree because the local user has not installed a KEM key pair ` +
          `via setKemKeyPair. Call setKemKeyPair with a P-256 ECDH key ` +
          `pair before adding readers.`,
      );
    }

    // Mirror the length check that `_registerBeeKEMReader` enforces, but
    // up here BEFORE the ACL change is committed. `_registerBeeKEMReader`
    // is invoked AFTER `_makeChange`, so without this upfront gate a
    // malformed `readerKemPublicKey` would surface as a registration
    // error AFTER the ACL row was already broadcast -- leaving the ACL
    // with a reader whose BeeKEM leaf could not be seeded and no Welcome
    // delivered. The downstream check still runs in
    // `_registerBeeKEMReader` (defense in depth for any future caller),
    // but the SAME bytes are validated here so the upfront precondition
    // is what determines whether the call will succeed.
    if (
      readerKemPublicKey !== undefined &&
      readerKemPublicKey.byteLength !== ECIES_P256_PUBLIC_KEY_LENGTH
    ) {
      throw new Error(
        `[${this.documentPath}] addReader: readerKemPublicKey must be ` +
          `${ECIES_P256_PUBLIC_KEY_LENGTH} bytes (SEC1-uncompressed P-256), ` +
          `got ${readerKemPublicKey.byteLength}`,
      );
    }

    // Founder-vs-joined-writer gate. The BeeKEM tree is rooted in
    // exactly one of two ways (see the long comment on `_beekem`):
    //   - **Founder**: a writer who CREATED the document. They have
    //     no prior document state (`_hashes.size === 0`) and seed
    //     leaf 0 with their local KEM key pair via
    //     `_initializeBeeKEMAsFounder`.
    //   - **Joined writer**: a writer who was added to an existing
    //     document by another writer. They MUST receive a BeeKEM
    //     Welcome (which bootstraps their tree via `processWelcome`)
    //     before they can manipulate the tree.
    //
    // Without this gate, a joined writer whose `_beekemInitialized`
    // is still false (no Welcome received yet) would fall through to
    // `_registerBeeKEMReader` -> `_initializeBeeKEMAsFounder`, silently
    // spawning a NEW divergent founder tree from a non-empty document
    // state. Their subsequent PathUpdates and Welcomes would come from
    // a tree shape that no other peer shares, so revocations from this
    // writer would never converge with anyone else's view -- a silent
    // correctness bug that this gate closes.
    //
    // The probe is `_hashes.size > 0`: any entry in `_hashes` means we
    // have applied at least one change (local or remote), so we are
    // not on the fresh-creation path. A founder reaching this point
    // for the first time has `_hashes.size === 0` (the readers-ACL
    // change is appended by `_makeChange` BELOW this gate). The check
    // also fires when a joined writer has received zero changes after
    // a Welcome is dropped, which is the recovery message we want.
    if (!this._beekemInitialized && this._hashes.size > 0) {
      throw new Error(
        `[${this.documentPath}] addReader: cannot register a reader -- ` +
          `this writer has document state but no BeeKEM tree bootstrapped ` +
          `from a Welcome. A joined writer must complete a fresh document ` +
          `load against a BeeKEM-bootstrapped peer (which seeds the local ` +
          `tree via a Welcome) before they can add or remove readers ` +
          `cryptographically. Initializing a fresh founder tree here would ` +
          `silently diverge from every other peer's tree state.`,
      );
    }

    // Idempotent on the ACL side, but if the caller has only now obtained
    // the recipient's KEM public key (e.g. a previous `addReader` call
    // skipped the Welcome because the key was unknown), still emit the
    // Welcome so the existing ACL row can be paired with keychain
    // material. Without this branch the warning emitted below on the
    // first call would point at a recovery path that is itself a no-op.
    const alreadyReader = await this._readers.check(reader);
    if (!alreadyReader) {
      // Send change over network.
      const changes = await this._readers.add(reader);
      await this._makeChange(changes, crdtReaderChangeNode);
    }

    // Record the new reader in the BeeKEM ratchet tree so:
    //   a) a future `removeReader` call can cryptographically revoke
    //      them (their leaf is blanked and the path re-keyed), and
    //   b) the inviter can ship the resulting BeeKEM `Welcome` (the
    //      path keys encrypted under the joiner's leaf public key)
    //      inside the sealed Welcome payload so the joiner can
    //      bootstrap their local BeeKEM state and apply subsequent
    //      PathUpdates.
    //
    // The leaf is seeded with `readerKemPublicKey` -- the reader's own
    // KEM public key, also used as the ECIES recipient for the sealed
    // payload. The reader holds the matching private key, so they can
    // decrypt the path-key chain in the Welcome (see
    // `BeeKEM.processWelcome`).
    //
    // When `readerKemPublicKey` is absent the leaf is left
    // UNALLOCATED: an unrelated placeholder key would let
    // `removeReader` find a leaf to blank, but the joiner could
    // never bootstrap their own BeeKEM state without the private
    // material that matches the placeholder. The library refuses
    // that ambiguous half-onboarded state and surfaces the warning
    // below directing the caller to re-invoke with the KEM key.
    //
    // If `_registerBeeKEMReader` throws we PROPAGATE the failure
    // rather than fall through to a half-Welcome. A Welcome with
    // `beekemWelcomeForJoiner = null` would still let the joiner
    // decrypt the *current* document key (via the sealed keychain
    // delta), but their BeeKEM tree would be uninitialized -- so the
    // NEXT `removeReader` rotation would silently lock them out
    // (their leaf has no key material to derive the new root from).
    // The ACL change has already been broadcast and the caller can
    // retry once the underlying issue is fixed (e.g. by re-invoking
    // `addReader` with the same KEM public key, or by recovering
    // BeeKEM state via `setKemKeyPair` + a fresh document load).
    let beekemWelcomeForJoiner: BeeKEMWelcome | null = null;
    if (readerKemPublicKey) {
      beekemWelcomeForJoiner = await this._registerBeeKEMReader(
        reader,
        readerKemPublicKey,
      );
    }

    // Without the recipient's KEM public key we cannot seal the
    // Welcome payload, and we will NEVER send an un-sealed Welcome --
    // that would broadcast `keychainChanges` to every connected peer.
    if (!readerKemPublicKey) {
      if (!alreadyReader) {
        console.warn(
          `[${this.documentPath}] addReader: BeeKEM Welcome skipped because ` +
            `the caller did not provide \`readerKemPublicKey\`. The reader ` +
            `has been added to the readers ACL, but to deliver the document ` +
            `key the caller must either (a) re-invoke \`addReader(reader, ` +
            `readerKemPublicKey)\` once the recipient's raw SEC1 P-256 ECDH ` +
            `public key is available, or (b) have the recipient perform a ` +
            `fresh document load against an authorized peer to recover ` +
            `keychain state.`,
        );
      }
      return;
    }

    // Send a BeeKEM Welcome with the document key + BeeKEM bootstrap
    // payload so the new reader can decrypt subsequent (and, per
    // visibility, prior) messages and apply future PathUpdates.
    // Failures are logged but do not abort -- the ACL change has
    // already been broadcast and the reader can also recover via a
    // fresh document load.
    try {
      await this._sendBeeKEMWelcome(
        reader,
        readerKemPublicKey,
        beekemWelcomeForJoiner,
      );
    } catch (err) {
      console.warn(
        `Failed to send BeeKEM Welcome for ${this.documentPath}:`,
        err,
      );
    }
  }

  /**
   * Build and send a BeeKEM Welcome message to a newly-added reader.
   *
   * The Welcome payload is a `CRDTSyncMessage` carrying:
   * - `welcomeEpochId`: the current keychain key ID, which the recipient
   *   records as their `_invitationEpoch` for later `since_invited` history
   *   filtering.
   * - `welcomeRecipient`: serialized public key of the intended recipient.
   *   The inviter cannot identify which connected peer is the new reader,
   *   so Welcomes are broadcast to every peer; the recipient binding
   *   ensures a *well-behaved* non-target peer drops the Welcome rather
   *   than installing the document key. The binding is covered by the
   *   writer signature, so a non-writer cannot redirect a Welcome to a
   *   different recipient.
   * - `welcomeRecipientKemPublicKey`: raw SEC1 P-256 ECDH public key of
   *   the recipient. Also covered by the writer signature -- the writer
   *   commits to a specific encryption key for a specific identity, so
   *   an attacker that owns one of those two values alone cannot
   *   redirect the sealed payload.
   * - `eciesSealed`: the inviter-side serialized keychain delta
   *   encrypted under the recipient's ECDH key via ECIES (see
   *   `ecies.ts`). This is the confidentiality control: a
   *   non-recipient peer that receives the broadcast cannot decrypt
   *   the keychain delta. The keychain plaintext is filtered per the
   *   document's `historyVisibility` **from the recipient's
   *   perspective** (see `_keychainChangesForWelcome()`).
   * - `signature`: writer signature over the message so the receiver can
   *   confirm a legitimate writer is the inviter (and ignore forgeries).
   *   Crucially, the signature covers the **sealed** bytes, not the
   *   plaintext, so a replayed or tampered sealed payload fails
   *   signature verification.
   *
   * Confidentiality: the keychain delta is end-to-end encrypted to the
   * recipient at the application layer. libp2p's Noise/TLS transport
   * still protects on-wire bytes against off-path observers, but the
   * application-layer ECIES seal is the primary confidentiality
   * guarantee against on-path connected peers.
   *
   * Wire format (mirrors `documentKeyUpdateV2`):
   *   [4-byte BE doc-path length] [UTF-8 doc-path] [serialized sync message]
   */
  private async _sendBeeKEMWelcome(
    reader: PublicKey,
    readerKemPublicKey: Uint8Array,
    beekemWelcome: BeeKEMWelcome | null,
  ): Promise<void> {
    // Validate the recipient KEM public key length up front so a
    // malformed caller fails fast at the call site rather than deep
    // inside the WebCrypto import.
    if (readerKemPublicKey.byteLength !== ECIES_P256_PUBLIC_KEY_LENGTH) {
      throw new Error(
        `BeeKEM Welcome for ${this.documentPath}: readerKemPublicKey ` +
          `must be ${ECIES_P256_PUBLIC_KEY_LENGTH} raw SEC1 bytes (P-256 ` +
          `uncompressed), got ${readerKemPublicKey.byteLength}`,
      );
    }

    // Defensive copy: snapshot the recipient's KEM public key bytes once
    // at the entry point so a caller that reuses or mutates the same
    // buffer (or shares it across async tasks) after `addReader` returns
    // cannot corrupt the in-flight Welcome. Both the signed message
    // field (`welcomeRecipientKemPublicKey`) and the WebCrypto import
    // must observe the *same* byte sequence; otherwise the receiver
    // would see a signature/payload mismatch.
    const kemPub = new Uint8Array(readerKemPublicKey);

    // Build the welcome message.
    const welcomeMessage: CRDTSyncMessage<ChangesType, PublicKey> = {
      documentId: this.documentPath,
    };

    // The invitation epoch is the *current* keychain key ID at the time
    // of invitation -- the boundary between "before I joined" and "from
    // when I joined". `_keychain.current()` throws on an empty keychain;
    // in practice that cannot happen here because the inviter is in the
    // group (and so has at least one key), but if it ever does we surface
    // the error to the caller of `addReader` rather than silently sending
    // a Welcome with no epoch ID.
    const [currentKeyID] = await this._keychain.current();
    welcomeMessage.welcomeEpochId = currentKeyID;

    // Recipient binding: serialize the new reader's public key so
    // recipients that aren't this reader can drop the broadcast Welcome.
    // The signed payload covers this field, so only an authorized writer
    // can claim a specific recipient. `serializePublicKey` is optional
    // on `AuthProvider` for backwards compatibility, but Welcome
    // onboarding cannot function without it.
    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'BeeKEM Welcome onboarding',
    );
    welcomeMessage.welcomeRecipient = await serializePublicKey(reader);
    welcomeMessage.welcomeRecipientKemPublicKey = kemPub;

    // Visibility-filtered keychain so the new reader can decrypt the
    // appropriate window of document history. Note: this uses
    // `_keychainChangesForWelcome()` (recipient's perspective), NOT
    // `_keychainChangesForVisibility()` (sender's perspective) -- the
    // latter would, in `since_invited` mode, leak the inviter's
    // post-invite slice (or, for founders, the full history) to a
    // reader whose invitation epoch starts at this moment.
    const keychainPlaintext = await this._keychainChangesForWelcome();
    const keychainPlaintextBytes =
      this._changesSerializer.serializeChanges(keychainPlaintext);

    // Build the structured sealed-payload envelope. The plaintext
    // inside `eciesSealed` is now a JSON envelope carrying both the
    // keychain delta and (when available) the BeeKEM `Welcome` the
    // joiner needs to bootstrap their local ratchet state. The
    // wire-level field on `CRDTSyncMessage` is still a single
    // `Uint8Array`; only its decoded shape grows. See
    // `welcome-sealed-payload.ts` for the envelope format.
    //
    // `beekemWelcome` is `null` here only on a re-emit path where
    // `addReader` was invoked without the KEM key on a previous
    // call -- the recipient will still recover the document key but
    // cannot apply future PathUpdates without an out-of-band BeeKEM
    // bootstrap.
    const sealedPayloadBytes = encodeWelcomeSealedPayload({
      keychainChanges: keychainPlaintextBytes,
      beekemWelcome,
    });

    // Seal the envelope to the recipient's ECDH public key. Only the
    // recipient holding the matching ECDH private key can recover the
    // plaintext; every other connected peer that observes the
    // broadcast sees only opaque ciphertext + ephemeral public key +
    // nonce + AES-GCM tag.
    const recipientKemKey = await importEciesPublicKey(kemPub);
    welcomeMessage.eciesSealed = await eciesSeal(
      sealedPayloadBytes,
      recipientKemKey,
    );

    // Sign so the receiver can verify the inviter is an authorized
    // writer. Welcomes are ALWAYS writer-authenticated, regardless of
    // the swarm-wide `enableSigning` toggle that gates normal
    // sync-message signing (see SECURITY NOTE in
    // `beekem-welcome-handler.ts`). The signature covers the sealed
    // bytes (`eciesSealed`) and the recipient bindings
    // (`welcomeRecipient` + `welcomeRecipientKemPublicKey`), so an
    // attacker cannot redirect or substitute the sealed payload
    // without invalidating the signature.
    welcomeMessage.signature = await this._signWelcomeAsWriter(welcomeMessage);

    const serialized =
      this._syncMessageSerializer.serializeSyncMessage(welcomeMessage);

    // Build the V1 path-prefixed payload that the shared handler routes.
    const pathBytes = this._encoder.encode(this.documentPath);
    if (pathBytes.length === 0 || pathBytes.length > MAX_DOCUMENT_PATH_LENGTH) {
      throw new Error(
        `Document path "${this.documentPath}" encoded length (${pathBytes.length}) exceeds ` +
          `the maximum allowed path length (${MAX_DOCUMENT_PATH_LENGTH} bytes) for the BeeKEM Welcome v1 protocol`,
      );
    }
    const pathHeader = new Uint8Array(4);
    pathHeader[0] = (pathBytes.length >> 24) & 0xff;
    pathHeader[1] = (pathBytes.length >> 16) & 0xff;
    pathHeader[2] = (pathBytes.length >> 8) & 0xff;
    pathHeader[3] = pathBytes.length & 0xff;

    const payload = concatUint8Arrays(pathHeader, pathBytes, serialized);

    // Best-effort fan-out to all connected peers. Each peer will either
    // process the Welcome (if it identifies as the new reader) or drop it.
    // We do not have a way to know which peer is the new reader from the
    // libp2p connection alone, so broadcasting is the conservative choice.
    const peers = this.swarm.heliaNode.libp2p
      .getConnections()
      ?.map((x) => x.remoteAddr) ?? [];

    const failedPeers: string[] = [];
    for (const peer of peers) {
      try {
        const stream = wrapStream(
          await this.libp2p.dialProtocol(peer, [beekemWelcomeV1], {
            runOnLimitedConnection: true,
          }),
        );
        await pipe([payload], stream.sink);
      } catch (err) {
        failedPeers.push(peer.toString());
        console.warn(
          `Failed to send BeeKEM Welcome to peer:`,
          peer.toString(),
          err,
        );
      }
    }

    if (failedPeers.length > 0) {
      console.warn(
        `BeeKEM Welcome for ${this.documentPath} failed to reach ${failedPeers.length} peer(s):`,
        failedPeers,
      );
    }
  }

  /**
   * Handles an incoming BeeKEM Welcome message with pre-read payload. Called
   * by the shared protocol handler in Peerborne after the document path
   * header has been stripped and the document looked up in the registry.
   *
   * Verifies the writer signature on the message, merges the included
   * keychain changes so future blocks can be decrypted, and records the
   * `welcomeEpochId` as `_invitationEpoch` so subsequent `since_invited`
   * history responses are correctly filtered.
   *
   * @internal
   * @param payload The serialized sync message (without the document path
   *   header that the shared handler already stripped).
   */
  public async handleBeeKEMWelcomeRequestData(
    payload: Uint8Array,
  ): Promise<void> {
    try {
      const message = this._syncMessageSerializer.deserializeSyncMessage(payload);
      await this._evaluateAndApplyBeeKEMWelcome(message, {
        fromBuffer: false,
      });
    } catch (err: unknown) {
      console.error(
        `Error handling BeeKEM Welcome for document ${this.documentPath}:`,
        err,
      );
    }
  }

  /**
   * Shared receive-path body for both freshly-arrived Welcomes (called
   * from `handleBeeKEMWelcomeRequestData`) and Welcomes replayed from the
   * pending-welcomes buffer (called from `_drainPendingWelcomes` after a
   * readers-ACL update unblocks a previously-dropped Welcome).
   *
   * @param message The deserialized sync message.
   * @param opts.fromBuffer When `true`, the message is being replayed from
   *   the pending-welcomes buffer; we suppress re-buffering on
   *   `not-in-readers-acl` to avoid an infinite drain loop and instead
   *   leave the entry in place for the next drain cycle (or TTL
   *   eviction).
   * @returns `true` iff the Welcome was accepted and applied.
   *
   * @internal
   */
  private async _evaluateAndApplyBeeKEMWelcome(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
    opts: { fromBuffer: boolean },
  ): Promise<boolean> {
    // Run the pure validation gates (extracted to
    // `beekem-welcome-handler.ts` so they can be unit-tested without
    // a full libp2p/Helia stack). On `accept` we apply the keychain
    // merge + invitation-epoch assignment below. `serializePublicKey`
    // is required on the AuthProvider for the recipient-binding gate;
    // we surface a clear error instead of silently dropping
    // every Welcome for misconfigured providers.
    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'BeeKEM Welcome onboarding',
    );
    const decision = await evaluateBeeKEMWelcome(message, {
      documentPath: this.documentPath,
      localUserPublicKey: this._userPublicKey,
      serializePublicKey,
      isReader: (pk) => this._readers.check(pk),
      // Welcomes always require writer-auth, independent of the
      // swarm-wide `enableSigning` toggle -- wire the unconditional
      // verifier so the validator can't be downgraded by config.
      verifyWriterSignature: (raw, signature) =>
        this._verifyWelcomeWriterSignature(raw, signature),
      syncMessageSerializer: this._syncMessageSerializer,
    });

    if (decision.kind !== 'accept') {
      switch (decision.kind) {
        case 'drop-not-for-us':
          // Legitimate Welcome to another peer flowing past our
          // connection -- silently ignore.
          return false;
        case 'drop-malformed':
          console.warn(
            `Dropping malformed BeeKEM Welcome for ${this.documentPath}: ${decision.reason}`,
          );
          return false;
        case 'drop-unauthorized':
          // If the Welcome was dropped solely because the local user is
          // not yet a reader (ACL update + Welcome can reorder;
          // `_sendBeeKEMWelcome` is fire-and-forget), park the Welcome
          // in a small bounded buffer and replay it after the next
          // readers-ACL merge. Without this buffer, a transiently-late
          // ACL update would permanently wedge onboarding.
          if (
            decision.reason === 'not-in-readers-acl' &&
            !opts.fromBuffer &&
            message.welcomeEpochId &&
            message.welcomeEpochId.length > 0
          ) {
            this._bufferPendingWelcome(message);
          } else if (
            opts.fromBuffer &&
            decision.reason === 'not-in-readers-acl'
          ) {
            // A buffered Welcome that is still blocked by
            // `not-in-readers-acl` on a drain cycle is the expected
            // steady state until the readers-ACL catches up. The
            // first-arrival case (above) already logged via
            // `_bufferPendingWelcome`; emitting `console.warn` on every
            // subsequent drain produces noisy spam (and is
            // attacker-triggerable via repeated ACL merges). Use
            // `console.debug` so operators can still trace if needed.
            console.debug(
              `Buffered BeeKEM Welcome for ${this.documentPath} still blocked: ${decision.reason}`,
            );
          } else {
            console.warn(
              `Dropping unauthorized BeeKEM Welcome for ${this.documentPath}: ${decision.reason}`,
            );
          }
          return false;
      }
    }

    // Open the sealed keychain delta. We must hold the matching ECDH
    // private key (see `setKemKeyPair`); without it, even a Welcome
    // that addresses us by identity and KEM public key cannot be
    // applied. Drop in that case -- the recipient must recover via a
    // fresh document load against an authorized peer.
    //
    // Defense in depth: if the writer-signed `welcomeRecipientKemPublicKey`
    // does NOT match the local installed KEM public key, the writer
    // is claiming a different encryption key than the one we hold.
    // Refuse to attempt decryption: this prevents an attacker who
    // somehow registered a fake KEM key (e.g. via a parallel
    // out-of-band channel) from getting us to silently install
    // keychain state under a key we don't actually control. A
    // legitimate writer who follows the documented onboarding flow
    // will always echo back the recipient's own KEM public key.
    if (!this._kemKeyPair || !this._kemPublicKeyRaw) {
      console.warn(
        `Dropping BeeKEM Welcome for ${this.documentPath}: no local KEM ` +
          `key pair installed via setKemKeyPair; cannot open sealed payload.`,
      );
      return false;
    }
    // Use the eagerly-cached raw bytes from `setKemKeyPair` rather
    // than re-exporting on every Welcome.
    const localKemPublicRaw = this._kemPublicKeyRaw;
    const messageKemPublic = message.welcomeRecipientKemPublicKey;
    if (
      !messageKemPublic ||
      messageKemPublic.byteLength !== localKemPublicRaw.byteLength ||
      !this._constantTimeEquals(messageKemPublic, localKemPublicRaw)
    ) {
      console.warn(
        `Dropping BeeKEM Welcome for ${this.documentPath}: ` +
          `welcomeRecipientKemPublicKey does not match the locally-installed ` +
          `KEM public key.`,
      );
      return false;
    }

    let keychainPlaintext: ChangesType;
    let bootstrapWelcome: BeeKEMWelcome | null = null;
    try {
      const sealed = message.eciesSealed as Uint8Array;
      const plaintextBytes = await eciesOpen(
        sealed,
        this._kemKeyPair.privateKey,
      );
      // The plaintext is now a structured envelope carrying the
      // keychain delta AND (optionally) a BeeKEM `Welcome` so the
      // joiner can bootstrap their local ratchet state. The
      // wire-level field remains a single `Uint8Array`; only the
      // decoded shape grows. See `welcome-sealed-payload.ts`.
      const envelope = decodeWelcomeSealedPayload(plaintextBytes);
      keychainPlaintext = this._changesSerializer.deserializeChanges(
        envelope.keychainChanges,
      );
      bootstrapWelcome = envelope.beekemWelcome;
    } catch (err) {
      // ECIES open failure typically means: the sealed payload is
      // tampered (AES-GCM tag check fails), or the writer encrypted
      // under a different ECDH public key than the one we hold (so
      // ECDH produces a different shared secret and the HKDF-derived
      // AES key cannot decrypt). Decode failure means the inviter
      // emitted a malformed envelope (e.g. a legacy unstructured
      // plaintext from a non-upgraded peer). Both are
      // security-relevant; log and drop.
      console.warn(
        `Failed to open sealed BeeKEM Welcome payload for ${this.documentPath}:`,
        err,
      );
      return false;
    }

    // Merge the keychain changes before recording the invitation epoch,
    // so a recipient handling concurrent Welcomes is not left with an
    // _invitationEpoch pointing at a key that hasn't been installed.
    try {
      this._keychain.merge(keychainPlaintext);
    } catch (err) {
      console.error(
        `Failed to merge keychain changes from BeeKEM Welcome for ${this.documentPath}:`,
        err,
      );
      return false;
    }

    // Bootstrap our local BeeKEM ratchet state from the inviter's
    // Welcome payload. Without this step the joiner has no leaf
    // index in the tree and no private key material on their direct
    // path; subsequent PathUpdates broadcast on `removeReader` would
    // fail to apply at `processPathUpdate`, locking the joiner out
    // of the new document key. Initialize-once: a peer that
    // re-receives a Welcome (e.g. a re-invite after being removed)
    // gets a fresh `BeeKEM` instance for the new epoch.
    if (bootstrapWelcome !== null) {
      try {
        const beekem = new BeeKEM();
        await beekem.processWelcome(
          bootstrapWelcome,
          this._kemKeyPair.privateKey,
          this._kemKeyPair.publicKey,
        );
        this._beekem = beekem;
        this._beekemInitialized = true;
      } catch (err) {
        // BeeKEM bootstrap failure is non-fatal at this layer: the
        // keychain merge has already succeeded so the joiner can
        // decrypt CURRENT document traffic. They will, however, be
        // unable to apply future PathUpdates and may need a fresh
        // Welcome / document load to recover ratchet state on the
        // next rotation. Surface a warning so this is visible.
        console.warn(
          `BeeKEM bootstrap via processWelcome failed for ${this.documentPath}: ` +
            `local ratchet state was not installed and future PathUpdates ` +
            `cannot be applied until a fresh Welcome arrives.`,
          err,
        );
      }
    }

    // Record the invitation epoch -- this gates `since_invited` history
    // filtering on subsequent doc-load / snapshot-load responses we send.
    // `evaluateBeeKEMWelcome` guarantees `welcomeEpochId` is set when
    // it returns `accept`.
    //
    // MONOTONIC UPDATE: if we already have an
    // `_invitationEpoch`, only advance it forward in keychain order --
    // never regress to an earlier epoch.
    //
    // The threat model: a writer could (maliciously or via reordering)
    // send a later writer-signed Welcome that nominally addresses this
    // node but carries an *earlier* `welcomeEpochId`. If we
    // unconditionally overwrote `_invitationEpoch`, this would shrink
    // the recipient's join boundary, broadening the set of keys
    // returned by future `since_invited` history responses we send
    // (leaking more history than the original invitation granted).
    //
    // Comparison strategy: `_keychain.keys()` returns entries in the
    // insertion order used by Yjs/Automerge keychain implementations
    // (`keychain.keys.push(...)`). Position in that array is the
    // canonical "later means later" relation -- the same one
    // `historySince` relies on to slice the suffix. We compare the
    // positions of the existing and incoming epoch IDs; if the new
    // one is strictly later we advance, otherwise we keep the
    // existing anchor.
    //
    // Fallback: if either ID is not present in `keys()` after the
    // merge above (e.g. the merge dropped the entry, or the local
    // keychain implementation does not expose insertion order), we
    // conservatively keep the existing `_invitationEpoch` -- it is
    // already known-good. The only path that loses fidelity is the
    // first-Welcome-ever case (no existing anchor) which is handled
    // by the simple assignment branch.
    const newEpochId = message.welcomeEpochId as Uint8Array;
    if (this._invitationEpoch === undefined) {
      this._invitationEpoch = newEpochId;
      console.log(
        `Recorded BeeKEM Welcome invitation epoch for ${this.documentPath}`,
      );
    } else {
      const advanced = await this._shouldAdvanceInvitationEpoch(
        this._invitationEpoch,
        newEpochId,
      );
      if (advanced) {
        this._invitationEpoch = newEpochId;
        console.log(
          `Recorded BeeKEM Welcome invitation epoch for ${this.documentPath}`,
        );
      } else {
        // Byte-equality check distinguishes benign duplicate Welcomes
        // (same epoch ID arriving more than once -- expected with
        // gossipsub fanout) from genuine out-of-order or regression
        // cases (different epoch ID that is not strictly later than
        // the current anchor). Only the latter is worth warning about;
        // duplicates are silently ignored to avoid log noise.
        let isDuplicate = false;
        if (this._invitationEpoch.byteLength === newEpochId.byteLength) {
          let diff = 0;
          for (let i = 0; i < this._invitationEpoch.byteLength; i++) {
            diff |= this._invitationEpoch[i] ^ newEpochId[i];
          }
          isDuplicate = diff === 0;
        }
        if (!isDuplicate) {
          console.warn(
            `Ignoring out-of-order BeeKEM Welcome for ${this.documentPath}: ` +
              `incoming epoch is not later than current invitation epoch`,
          );
        }
      }
    }
    return true;
  }

  /**
   * Buffer a Welcome that was dropped solely because the local user is
   * not yet in the readers ACL. The entry is keyed by
   * `hex(welcomeEpochId)` so duplicate Welcomes for the same epoch
   * coalesce automatically. Bounded by
   * `_PENDING_WELCOMES_MAX_ENTRIES` (oldest evicted in insertion
   * order); replayed by `_drainPendingWelcomes()` after the next
   * readers-ACL merge.
   *
   * Idempotent and safe to call repeatedly with the same epoch ID --
   * the buffer is conceptually a set keyed on epoch ID, with
   * insertion-order eviction.
   *
   * @internal
   */
  private _bufferPendingWelcome(
    message: CRDTSyncMessage<ChangesType, PublicKey>,
  ): void {
    const epochId = message.welcomeEpochId;
    if (!epochId || epochId.length === 0) return;
    const key = this._hexEncode(epochId);
    // Refresh recency for duplicate Welcomes: delete-then-set so the
    // Map iteration order puts this entry at the back, matching the
    // intent of insertion-order eviction.
    this._pendingWelcomes.delete(key);

    // Bound: if at capacity, evict the oldest entry (first in Map
    // iteration order).
    if (
      this._pendingWelcomes.size >=
      PeerborneDocument._PENDING_WELCOMES_MAX_ENTRIES
    ) {
      const oldestKey = this._pendingWelcomes.keys().next().value;
      if (oldestKey !== undefined) {
        this._pendingWelcomes.delete(oldestKey);
        console.warn(
          `Pending BeeKEM Welcomes buffer for ${this.documentPath} ` +
            `at capacity (${PeerborneDocument._PENDING_WELCOMES_MAX_ENTRIES}); ` +
            `evicting oldest entry to make room.`,
        );
      }
    }

    this._pendingWelcomes.set(key, {
      message,
      bufferedAtMs: this._now(),
    });
    console.log(
      `Buffered BeeKEM Welcome for ${this.documentPath} pending readers-ACL update ` +
        `(epoch=${key.slice(0, 16)}..., buffer size=${this._pendingWelcomes.size})`,
    );
  }

  /**
   * Replay buffered BeeKEM Welcomes whose recipient is now in the
   * readers ACL. Called after every readers-ACL `merge` so a Welcome
   * that arrived ahead of the ACL update on this node is unblocked as
   * soon as the ACL catches up. Also discards entries past their TTL
   * (`_PENDING_WELCOMES_TTL_MS`) so the buffer cannot retain stale
   * Welcomes indefinitely.
   *
   * Each accepted Welcome is removed from the buffer; entries that
   * still return `not-in-readers-acl` (e.g. the ACL merge didn't
   * add this user; the merge added someone else) stay in the buffer
   * until they either resolve or expire.
   *
   * @internal
   */
  private async _drainPendingWelcomes(): Promise<void> {
    if (this._pendingWelcomes.size === 0) return;
    const now = this._now();
    // Iterate over a snapshot of entries because we mutate the Map
    // during iteration (delete on accept / TTL).
    const entries = Array.from(this._pendingWelcomes.entries());
    for (const [key, entry] of entries) {
      if (now - entry.bufferedAtMs > PeerborneDocument._PENDING_WELCOMES_TTL_MS) {
        this._pendingWelcomes.delete(key);
        console.warn(
          `Discarding stale buffered BeeKEM Welcome for ${this.documentPath} ` +
            `(epoch=${key.slice(0, 16)}..., age=${now - entry.bufferedAtMs}ms ` +
            `exceeds TTL=${PeerborneDocument._PENDING_WELCOMES_TTL_MS}ms)`,
        );
        continue;
      }
      const accepted = await this._evaluateAndApplyBeeKEMWelcome(entry.message, {
        fromBuffer: true,
      });
      if (accepted) {
        this._pendingWelcomes.delete(key);
        console.log(
          `Replayed buffered BeeKEM Welcome for ${this.documentPath} ` +
            `after readers-ACL update (epoch=${key.slice(0, 16)}...)`,
        );
      }
    }
  }

  /** Indirection so unit tests can stub the wall clock. */
  private _now(): number {
    return Date.now();
  }

  /** Lower-case hex encoding of a `Uint8Array`. */
  private _hexEncode(bytes: Uint8Array): string {
    let s = '';
    for (let i = 0; i < bytes.length; i++) {
      s += bytes[i].toString(16).padStart(2, '0');
    }
    return s;
  }

  /**
   * Constant-time byte-equality check. Used by the BeeKEM Welcome
   * receive path to compare the writer-signed
   * `welcomeRecipientKemPublicKey` against the locally-installed KEM
   * public key without leaking byte-position timing on a mismatch.
   * Callers must supply equal-length buffers.
   */
  private _constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff === 0;
  }

  /**
   * Test/inspection helper: number of BeeKEM Welcomes currently parked
   * in the pending-welcomes buffer awaiting a readers-ACL update.
   *
   * @internal exposed only for unit tests.
   */
  public get pendingWelcomesCount(): number {
    return this._pendingWelcomes.size;
  }

  /**
   * Test/inspection helper: returns a copy of the recorded invitation
   * epoch, or `undefined` if no Welcome has been processed (e.g.
   * founding member). The returned `Uint8Array` is a defensive copy so
   * external callers cannot mutate the document's internal state and
   * alter subsequent `since_invited` filtering behavior.
   */
  public get invitationEpoch(): Uint8Array | undefined {
    return this._invitationEpoch === undefined
      ? undefined
      : new Uint8Array(this._invitationEpoch);
  }

  /**
   * Decide whether an incoming BeeKEM Welcome's `welcomeEpochId` is
   * strictly later than the existing `_invitationEpoch`. Used by
   * `handleBeeKEMWelcomeRequestData` to enforce a monotonic-forward
   * update on the invitation-epoch anchor.
   *
   * Comparison is performed by looking up both IDs in the
   * post-merge `_keychain.keys()` ordering. Yjs and Automerge keychain
   * implementations append entries in insertion order, so the array
   * position is the canonical "later means later" ordering -- the
   * same relation `historySince` slices on.
   *
   * Returns `true` iff the new epoch is strictly later than the
   * existing one. Returns `false` if:
   *   - the two IDs are byte-equal (no-op, do not log a regression),
   *   - the new epoch is at an earlier position than the existing one
   *     (would regress the anchor),
   *   - either ID is not present in the keychain after the merge
   *     (we cannot establish ordering; conservatively keep the
   *     known-good existing anchor).
   *
   * @internal exposed only for unit tests.
   */
  public async _shouldAdvanceInvitationEpoch(
    existing: Uint8Array,
    incoming: Uint8Array,
  ): Promise<boolean> {
    // Byte-equal: no advancement needed and not a regression.
    if (
      existing.length === incoming.length &&
      existing.every((b, i) => b === incoming[i])
    ) {
      return false;
    }

    let allKeys: [Uint8Array, unknown][];
    try {
      allKeys = await this._keychain.keys();
    } catch {
      // Keychain refused to enumerate keys (empty keychain, transient
      // error). Conservatively keep the known-good anchor.
      return false;
    }

    const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => {
      if (a.length !== b.length) return false;
      for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
      return true;
    };

    const existingIdx = allKeys.findIndex(([id]) => sameBytes(id, existing));
    const incomingIdx = allKeys.findIndex(([id]) => sameBytes(id, incoming));
    if (existingIdx === -1 || incomingIdx === -1) {
      // One of the IDs is not in the keychain -- cannot establish
      // ordering. Keep the existing anchor.
      return false;
    }
    return incomingIdx > existingIdx;
  }

  /**
   * Remove a user as a valid reader. Users are identified by their public keys.
   *
   * ## Atomicity contract
   *
   * Pre-validates all preconditions before mutating BeeKEM state. The
   * BeeKEM `removeMember` call is the atomicity boundary:
   *
   *   - BEFORE the BeeKEM mutation: every check that can fail
   *     synchronously / cheaply (writer authorization, ACL membership,
   *     tree initialization, leaf lookup) runs first. If any of these
   *     throws, no state has been mutated and the caller can retry
   *     without leaking a half-applied revocation.
   *   - AT the BeeKEM mutation: `BeeKEM.removeMember(leafIndex)` blanks
   *     the leaf and re-derives the writer's path key material. This
   *     advances local BeeKEM state. The CRDT-mutating ACL build step
   *     (`_readers.remove(reader)` -- not just a "compute change",
   *     both the Yjs and Automerge providers mutate their internal
   *     doc state in `remove`) and the PathUpdate signing step (which
   *     requires the new 32-byte epoch ID derived from the new root
   *     secret) cannot be hoisted ABOVE the BeeKEM mutation: building
   *     the ACL change without applying it is not part of the ACL
   *     interface, and the PathUpdate signature includes the new
   *     epoch ID by construction.
   *   - AFTER the BeeKEM mutation succeeds, every subsequent step is
   *     attempted on a BEST-EFFORT basis: broadcast and ACL-commit
   *     failures are logged but do not unwind the BeeKEM advance. The
   *     writer is always left in a consistent state -- BeeKEM advanced,
   *     local keychain updated with the new epoch key, outgoing traffic
   *     encrypted under the new key. Surviving readers may need to
   *     re-sync via a fresh document load if the ACL change or
   *     PathUpdate broadcast was dropped.
   *
   * ## Ordering on the wire
   *
   * The ACL-change broadcast must be encryptable by surviving readers
   * using a key they ALREADY have, not the post-rotation key (which
   * they only learn about once they process the PathUpdate). The
   * ACL-change pubsub message and the PathUpdate unicast stream are
   * delivered independently and can arrive in any order; each must be
   * independently decryptable to keep the receive path order-
   * insensitive. This is why `addEpochKey` (which flips
   * `_keychain.current()` to the new key) is deferred until AFTER
   * both broadcasts: while `_makeChange` runs, `_keychain.current()`
   * still returns the **previous** key, which surviving readers can
   * still decrypt with.
   *
   * ## Steps
   *
   *   1. Verify the caller is a writer and look up the BeeKEM leaf
   *      assigned to the removed reader. A missing leaf is a hard
   *      error (see `@throws` below). Both ECDH-keypair and leaf-
   *      lookup preconditions are checked here, BEFORE step 2.
   *   2. Blank the leaf and re-key our path via
   *      `BeeKEM.removeMember(leafIndex)`, which returns the
   *      `PathUpdate` to broadcast and the new root secret. We do
   *      NOT run a follow-up `BeeKEM.update()`: `removeMember`
   *      already generates fresh key material along the entire path,
   *      and re-rotating immediately would discard that material in
   *      favour of yet-another rotation, doubling the work without
   *      improving the cryptographic property. **This is the atomicity
   *      boundary: every subsequent step is best-effort.**
   *   3. Derive the new document key + 32-byte epoch ID from the root
   *      secret via HKDF (see `derive-doc-key.ts`). **Hold locally;
   *      the keychain is NOT updated yet.**
   *   4. Commit the ACL removal and broadcast it via `_makeChange`,
   *      still encrypted under the **previous** keychain key (so
   *      surviving readers can decrypt regardless of PathUpdate
   *      arrival order). On failure: log a warning and fall through;
   *      surviving readers can recover the new ACL via a fresh
   *      document load.
   *   5. Broadcast the signed `PathUpdate` over `beekemPathUpdateV1`
   *      to every connected peer. Surviving readers feed it into
   *      `BeeKEM.processPathUpdate` and re-derive the same document
   *      key + epoch ID. On failure: log a warning and fall through;
   *      surviving readers can recover via a fresh document load.
   *      The local keychain install in step 6 still runs so the
   *      WRITER transitions to the new key.
   *   6. Install the new key into the LOCAL keychain. From this
   *      point on every subsequent outgoing message is encrypted
   *      under the new key. This step ALWAYS runs (even if steps
   *      4 or 5 logged failures) so the writer never gets stuck
   *      encrypting under the previous key while the BeeKEM tree
   *      has advanced.
   *
   * The revoked reader can still decrypt the step-4 ACL change (they
   * have the previous key) -- which is fine: they just learn they've
   * been removed. They CANNOT derive the new key from the step-5
   * PathUpdate because their leaf is blanked, so all future writer-
   * originated traffic remains opaque to them.
   *
   * If step 6 itself fails (local IO / WebCrypto error) the writer is
   * in a partially-rotated state -- BeeKEM has advanced but the local
   * keychain still holds only the previous key. The call throws so the
   * caller can recover (the simplest recovery is to re-open the
   * document, which re-loads keychain state). `addEpochKey` is a
   * local-only call in both shipped keychain providers (no pubsub
   * side-effects, no remote IO), so this branch is rare in practice.
   *
   * Unlike the previous "encrypt the new key under the old key" scheme,
   * the removed reader cannot derive the new key even if they were
   * connected at the moment of revocation: their leaf is blanked and
   * the new path key material is encrypted to subtrees they no longer
   * occupy. This closes the revocation-latency gap (#189 §5.4 item 5).
   *
   * @param reader User's public key.
   * @throws If the BeeKEM tree has no record of this reader (e.g.
   *   `addReader` did not seed a leaf for them, or BeeKEM membership
   *   was lost). Callers must surface this rather than silently
   *   degrading: a removeReader that "succeeded" without rotating the
   *   key would leave the removed reader with full ongoing access.
   * @throws If the local keychain install fails (step 6). Steps 1-3
   *   (pre-validation + BeeKEM rotation + key derivation) throwing
   *   leaves the ACL unchanged so the caller can retry; broadcast
   *   failures in steps 4-5 do NOT throw (they log warnings).
   */
  public async removeReader(reader: PublicKey) {
    // ---------------------------------------------------------------
    // Pre-validation: every check that can fail synchronously and
    // does not mutate state runs BEFORE the BeeKEM `removeMember`
    // call. Once that call has run, the BeeKEM tree has advanced
    // and we no longer have a clean rollback point.
    // ---------------------------------------------------------------
    await this._ensureCurrentUserCanWrite();

    // Check that the reader is already a reader.
    if (!(await this._readers.check(reader))) {
      return;
    }

    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'BeeKEM reader revocation',
    );
    const serializedReader = await serializePublicKey(reader);

    // The BeeKEM tree must be initialized before we can revoke
    // anything: leaf-derivation, key rotation, and PathUpdate
    // generation all require live tree state. A fresh-start replica
    // that has never received a Welcome (and is not the founder)
    // cannot revoke; surface that clearly rather than fail later
    // with a confusing leaf-lookup error.
    if (!this._beekemInitialized || !this._beekem) {
      throw new Error(
        `Cannot remove reader from "${this.documentPath}": BeeKEM tree has ` +
          `not been initialized. This is only possible if the local user is ` +
          `neither the founder nor has received a BeeKEM Welcome -- in either ` +
          `case the user should not be calling removeReader.`,
      );
    }
    const beekem = this._beekem;

    // Look up the BeeKEM leaf for the removed reader. Fast-path: an
    // in-memory cache populated by `addReader` on this same writer
    // process. Slow-path: derive the leaf from BeeKEM tree state by
    // matching the reader's KEM public key against every leaf via
    // `BeeKEM.findLeafByPublicKey`. The slow path is what makes
    // revocation survive a cache wipe (e.g. an in-process clear of
    // `_readerLeafIndices` for testing, or a hypothetical sibling
    // replica with the BeeKEM tree but without the cache).
    //
    // Both lookups are in-memory only: BeeKEM tree state is itself
    // not persisted across writer restarts (tracked separately --
    // see PR body for the known-limitation note). A fully restarted
    // writer that loses both BeeKEM state and `_readerKemPublicKeys`
    // hits the "BeeKEM tree not initialized" error above OR the
    // "no leaf found" error below, both with actionable messaging.
    let leafIndex = this._readerLeafIndices.get(serializedReader);
    if (leafIndex === undefined) {
      const kemPub = this._readerKemPublicKeys.get(serializedReader);
      if (kemPub) {
        leafIndex = await beekem.findLeafByPublicKey(kemPub);
        if (leafIndex !== undefined) {
          // Re-populate the fast-path cache so subsequent
          // revocations for the same reader (within this process)
          // skip the tree scan. Harmless if the reader gets removed
          // immediately below: the entry is deleted again as part
          // of cleanup.
          this._readerLeafIndices.set(serializedReader, leafIndex);
        } else {
          // Pubkey is recorded but the BeeKEM tree has no matching
          // non-blanked leaf. Distinguishing this case from "no
          // pubkey at all" (below) lets operators tell apart a
          // local-state gap (reader never registered) from a
          // tree-state gap (leaf already blanked, or this replica
          // never received the Welcome that placed the reader).
          throw new Error(
            `Cannot remove reader from "${this.documentPath}": the reader's ` +
              `KEM public key is recorded locally but the BeeKEM tree has ` +
              `no matching non-blanked leaf. The tree state may have ` +
              `diverged (leaf already blanked, or this replica never ` +
              `received the Welcome that placed the reader). A fresh ` +
              `document load against an authorized peer can re-bootstrap ` +
              `the local tree.`,
          );
        }
      }
    }
    if (leafIndex === undefined) {
      throw new Error(
        `Cannot remove reader from "${this.documentPath}": no BeeKEM leaf ` +
          `recorded for this reader, and the local replica has no KEM public ` +
          `key recorded to scan the BeeKEM tree with. The reader must have ` +
          `been added via addReader (which seeds the BeeKEM tree and records ` +
          `the KEM public key) before they can be cryptographically revoked.`,
      );
    }

    // ---------------------------------------------------------------
    // Atomicity boundary: every step from here on advances BeeKEM
    // state OR is best-effort relative to it.
    // ---------------------------------------------------------------

    // 1. Blank the leaf and re-key our path. `removeMember` re-derives
    //    key material along the entire path and returns the
    //    `PathUpdate` to broadcast plus the new root secret. We use
    //    those return values directly -- no follow-up `update()` is
    //    needed (it would only discard `removeMember`'s fresh
    //    material in favour of yet-another rotation).
    const { pathUpdate, rootSecret } = await beekem.removeMember(leafIndex);

    // 2. Derive the new document key + 32-byte epoch ID from the root
    //    secret. **Hold these locally; do NOT install in the keychain
    //    yet.** Installing now would flip `_keychain.current()` to the
    //    new key, and the ACL-change broadcast in step 3 (which goes
    //    through `_makeChange`) would then encrypt the readers-ACL
    //    removal under the **new** key. Surviving readers would not
    //    yet have the new key (they get it from the PathUpdate in
    //    step 4, delivered separately and possibly out of order
    //    relative to the gossipsub-broadcast ACL change), and so
    //    would be unable to decrypt the ACL change.
    //
    //    The full 32-byte ID is both what we put on the wire AND what
    //    the keychain stores: `keyIDLength` is now 32 in the shipped
    //    providers (matches `deriveEpochIdFromRootSecret`), so there is
    //    no truncation step. Earlier revisions truncated to 16 bytes
    //    here, which collided with the keychain providers' UUID-style
    //    cache-key encoding for 16-byte inputs and produced a
    //    deterministic post-rotation decrypt failure on the receiver
    //    side (key stored under hex, looked up under UUID format).
    const [newKey, derivedEpochId32] = await Promise.all([
      deriveDocumentKeyFromRootSecret(rootSecret),
      deriveEpochIdFromRootSecret(rootSecret),
    ]);

    // 3. Commit the ACL removal and broadcast it -- still encrypted
    //    under the **previous** keychain key (the new key hasn't been
    //    installed yet; see step 5). Surviving readers can decrypt
    //    this with the key they already have, regardless of whether
    //    the PathUpdate in step 4 arrives before or after the ACL
    //    change. The revoked reader can also decrypt the ACL change
    //    (they still hold the previous key), which is fine -- the
    //    ACL change just tells them they've been removed. They can't
    //    derive the **new** key from step 4's PathUpdate because
    //    their leaf is blanked.
    //
    //    Best-effort relative to the BeeKEM mutation: if `_makeChange`
    //    or the underlying `_readers.remove(reader)` throws (signing,
    //    serialization, pubsub publish failure, IPFS write error,
    //    etc.) we log + fall through. The BeeKEM tree has already
    //    advanced; unwinding it is not possible. Surviving readers
    //    can re-sync the ACL via a fresh document load. We deliberately
    //    do not retry: a failed pubsub publish typically indicates a
    //    transport-level issue that the caller is better placed to
    //    diagnose than this routine.
    try {
      const changes = await this._readers.remove(reader);
      await this._makeChange(changes, crdtReaderChangeNode);
    } catch (err) {
      console.warn(
        `[${this.documentPath}] removeReader: ACL-removal broadcast failed; ` +
          `BeeKEM state has advanced locally and the new epoch key will be ` +
          `installed in the local keychain. Surviving readers may need to ` +
          `re-load the document to observe the ACL change.`,
        err,
      );
      // Fall through: still distribute the PathUpdate and install
      // the new local key so outgoing writer traffic is on the
      // post-revocation epoch.
    }

    // 4. Forget the removed reader's per-reader state so subsequent
    //    `removeReader` calls for the same key (idempotency) take
    //    the "already not a reader" early return instead of trying
    //    to re-revoke a blank leaf, and a future `addReader` for
    //    this identity is a fresh registration -- not a re-emit of
    //    the now-invalid pre-revocation Welcome.
    //
    //    Critically, we also clear the cached `BeeKEMWelcome` for
    //    this leaf: leaving the stale entry would let a future
    //    `_registerBeeKEMReader` re-invocation for an unrelated
    //    reader who happens to land on the same blanked slot
    //    re-emit a Welcome that bootstraps the new joiner against
    //    the **revoked reader's** pre-revocation tree state.
    //
    //    Runs unconditionally (independent of the ACL-change branch
    //    above) so the in-memory caches stay consistent with the
    //    advanced BeeKEM tree.
    this._readerLeafIndices.delete(serializedReader);
    this._readerKemPublicKeys.delete(serializedReader);
    this._beekemWelcomeByLeaf.delete(leafIndex);

    // 5. Broadcast the PathUpdate to every connected peer. Carries
    //    the full 32-byte epoch ID; the receiver matches it against
    //    its own locally-derived 32-byte value, then installs under
    //    that same 32-byte ID. No truncation step on either side --
    //    `keyIDLength` and `deriveEpochIdFromRootSecret` both use 32.
    //
    //    Best-effort relative to the BeeKEM mutation: if the
    //    PathUpdate distribution throws (signing failure, payload
    //    serialization error, all dials failed in a way the inner
    //    fan-out propagated) we log + fall through to `addEpochKey`
    //    so the writer still transitions to the new key for
    //    outgoing encryption. Surviving readers that miss the
    //    PathUpdate can recover via a fresh document load (the new
    //    epoch key is part of the keychain CRDT once the next ACL
    //    or document change is broadcast and observed).
    try {
      await this._distributeBeeKEMPathUpdate(pathUpdate, derivedEpochId32);
    } catch (err) {
      console.warn(
        `[${this.documentPath}] removeReader: PathUpdate broadcast failed; ` +
          `BeeKEM state has advanced locally and the new key will be installed. ` +
          `Surviving readers may need to re-load the document.`,
        err,
      );
      // Fall through to addEpochKey so the writer transitions to
      // the new key.
    }

    // 6. Install the new key into our LOCAL keychain. From this
    //    point on, `_keychain.current()` returns the new key and
    //    every subsequent `_makeChange` encrypts under it.
    //
    //    This step always runs (even if steps 3 or 5 above logged
    //    failures) so the writer never gets stuck on the previous
    //    key after BeeKEM has advanced -- subsequent local writes
    //    would otherwise encrypt under a key that surviving readers
    //    (post-PathUpdate) no longer accept.
    //
    //    Failure mode: if `addEpochKey` itself throws (local IO /
    //    WebCrypto error), the writer is in a partially-rotated state
    //    -- BeeKEM has advanced but the local keychain still holds
    //    only the previous key. We surface the failure loudly here
    //    so operators can intervene (re-open the document to
    //    recover keychain state). `addEpochKey` is a local-only
    //    call in both shipped keychain providers (no pubsub
    //    side-effects, no remote IO), so this branch is rare in
    //    practice; the publish-then-commit shape is deliberate
    //    to keep the on-wire ordering correct.
    try {
      await this._keychain.addEpochKey(
        derivedEpochId32,
        newKey as unknown as DocumentKey,
      );
    } catch (err) {
      // Don't suppress -- let the caller see the failure -- but
      // log first so the operator-visible diagnostic doesn't get
      // lost in the rethrow path.
      console.error(
        `[${this.documentPath}] removeReader: ACL change + PathUpdate broadcast succeeded, ` +
          `but local keychain install of the new epoch key failed. The local writer cannot ` +
          `encrypt under the new key until keychain state is recovered (e.g. re-open the ` +
          `document). Surviving readers will have installed the new key from the PathUpdate. ` +
          `Underlying error:`,
        err,
      );
      throw err;
    }
  }

  /**
   * Lazily initialize the per-document BeeKEM ratchet tree **as the
   * founder**. The founder is the writer who creates a fresh document
   * and runs the first `addReader` call; their leaf-0 KEM key pair
   * roots the tree.
   *
   * Returns the singleton `BeeKEM` instance for this document. The
   * initialization is funnelled through a single in-flight promise
   * (`_beekemInitPromise`) so concurrent callers don't race two
   * `initialize` calls against the same instance.
   *
   * PRECONDITION: the caller must have installed a KEM key pair via
   * `setKemKeyPair` -- the founder's leaf-0 key pair is that same
   * P-256 ECDH pair. A founder that calls `addReader` without first
   * calling `setKemKeyPair` is misconfigured and `addReader` throws
   * before reaching here.
   *
   * Non-founder peers MUST NOT enter this path. They initialize their
   * BeeKEM state by receiving a Welcome from the inviter (see
   * `_evaluateAndApplyBeeKEMWelcome` -> `BeeKEM.processWelcome`).
   */
  private async _initializeBeeKEMAsFounder(): Promise<BeeKEM> {
    if (this._beekem) return this._beekem;
    if (this._beekemInitPromise) return this._beekemInitPromise;

    if (!this._kemKeyPair) {
      throw new Error(
        `[${this.documentPath}] BeeKEM founder initialization requires a KEM ` +
          `key pair installed via setKemKeyPair.`,
      );
    }
    const kemKeyPair = this._kemKeyPair;

    const init = (async () => {
      const beekem = new BeeKEM();
      await beekem.initialize(kemKeyPair.privateKey, kemKeyPair.publicKey);
      this._beekem = beekem;
      this._beekemInitialized = true;
      return beekem;
    })();

    this._beekemInitPromise = init;
    try {
      return await init;
    } finally {
      // Clear the gate whether init succeeded or threw so a retry can
      // re-attempt. On success `_beekem` is set and the next call
      // short-circuits before reading the promise.
      this._beekemInitPromise = null;
    }
  }

  /**
   * Register a newly-added reader in the BeeKEM ratchet tree.
   *
   * Called from `addReader` after the readers-ACL update. Imports the
   * reader's own KEM public key as the new leaf, records the
   * resulting leaf index in `_readerLeafIndices` so `removeReader`
   * can later look up the leaf to blank, caches the
   * `BeeKEMWelcome` produced by `BeeKEM.addMember` so it can be
   * re-emitted on a subsequent `addReader` call (covering the case
   * where the initial Welcome was dropped on the wire), and returns
   * the Welcome so the inviter can ship it inside the sealed
   * Welcome envelope to the joiner.
   *
   * **Idempotency / re-send**: if the same reader is registered
   * again (`addReader` invoked twice with the same KEM key), the
   * method does NOT re-call `BeeKEM.addMember` (which would mutate
   * the tree and produce a Welcome that no longer matches the
   * joiner's actual leaf index). Instead it returns the cached
   * Welcome from `_beekemWelcomeByLeaf`, so `addReader` can re-send
   * the same Welcome bytes. If the cache is empty for the existing
   * leaf (writer restarted), `null` is returned and the caller falls
   * back to the existing "no BeeKEM bootstrap available, recipient
   * must recover via a fresh document load" path.
   *
   * The path update produced by `BeeKEM.addMember` is intentionally
   * not broadcast here: that broadcast would only help joiners that
   * are already in the tree, but new joiners come up via Welcome and
   * existing peers don't need the add-side state for their own
   * future PathUpdate applications. (Existing peers' BeeKEM state
   * may diverge from the inviter's tree shape after each add;
   * `removeReader` reseals against the updated tree, so the wire
   * path on revoke re-syncs everyone via the sender's
   * `PathUpdate.senderLeafIndex` + intersection logic.)
   */
  private async _registerBeeKEMReader(
    reader: PublicKey,
    readerKemPublicKey: Uint8Array,
  ): Promise<BeeKEMWelcome | null> {
    // Validate the recipient KEM public key length BEFORE any state
    // mutation. Without this gate a malformed buffer would still be
    // recorded in `_readerKemPublicKeys` and seeded into the BeeKEM
    // leaf (via `crypto.subtle.importKey`), at which point WebCrypto
    // surfaces a low-signal `DataError` after we have already mutated
    // identity-keyed state. Fail fast here so callers (and `addReader`)
    // see a precise, actionable error before any commitment.
    if (readerKemPublicKey.byteLength !== ECIES_P256_PUBLIC_KEY_LENGTH) {
      throw new Error(
        `[${this.documentPath}] _registerBeeKEMReader: readerKemPublicKey ` +
          `must be ${ECIES_P256_PUBLIC_KEY_LENGTH} bytes (SEC1-uncompressed ` +
          `P-256), got ${readerKemPublicKey.byteLength}`,
      );
    }

    const serializePublicKey = requireSerializePublicKey(
      this._authProvider,
      'BeeKEM reader revocation',
    );
    const serializedReader = await serializePublicKey(reader);

    // Record the KEM public key bytes alongside the identity so
    // `removeReader` can recover the leaf assignment from BeeKEM
    // tree state when the `_readerLeafIndices` fast-path cache
    // misses (e.g. cache wipe, different writer replica). Defensive
    // copy: the caller may reuse the buffer after `addReader`
    // returns; we want our snapshot to be immutable.
    this._readerKemPublicKeys.set(
      serializedReader,
      new Uint8Array(readerKemPublicKey),
    );

    // Idempotency: if a leaf is already recorded (e.g. addReader was
    // re-invoked because the initial Welcome was dropped), we do NOT
    // call `BeeKEM.addMember` again -- that would mutate the tree
    // and produce a Welcome that no longer matches the joiner's
    // actual leaf index. Instead we return the cached Welcome (if
    // any) so the caller can re-send. A miss means the writer
    // restarted between the original `addReader` and this re-invoke;
    // we surface that as `null` so the caller falls through to the
    // existing recovery messaging.
    const existingLeaf = this._readerLeafIndices.get(serializedReader);
    if (existingLeaf !== undefined) {
      return this._beekemWelcomeByLeaf.get(existingLeaf) ?? null;
    }

    // Bootstrap the local BeeKEM tree if needed. On the founder's
    // first `addReader` this initializes leaf 0 with the founder's
    // KEM key pair. On a non-founder writer this branch is invalid
    // (writers other than the founder must themselves have been
    // bootstrapped via a Welcome before they can call `addReader`).
    //
    // Defense-in-depth gate: the caller path through `addReader`
    // already rejects "joined writer with existing document state"
    // BEFORE running `_makeChange`, so by the time we reach here we
    // have either (a) a genuine founder with empty `_hashes`, or
    // (b) a founder mid-first-addReader whose just-emitted ACL
    // change is sitting in `_hashes` (size === 1). Anything else
    // (e.g. a future caller that invokes `_registerBeeKEMReader`
    // outside `addReader`, or a `_hashes` that has been advanced by
    // pubsub before the founder's first `addReader`) would silently
    // create a divergent founder tree on a peer that already has
    // shared state. Throw rather than spawn the rogue tree; the
    // upstream `addReader` gate's recovery message points at the
    // right path.
    if (!this._beekemInitialized) {
      if (this._hashes.size > 1) {
        throw new Error(
          `[${this.documentPath}] _registerBeeKEMReader: cannot ` +
            `initialize a fresh founder BeeKEM tree because the local ` +
            `replica already has ${this._hashes.size} merged changes. A ` +
            `joined writer must bootstrap via a BeeKEM Welcome (delivered ` +
            `over the initial document load) before they can register ` +
            `readers cryptographically.`,
        );
      }
      await this._initializeBeeKEMAsFounder();
    }
    const beekem = this._beekem;
    if (!beekem) {
      throw new Error(
        `[${this.documentPath}] BeeKEM tree is not initialized; ` +
          `cannot register a new reader.`,
      );
    }

    // Import the reader's own KEM public key as their leaf. This is
    // critical for joiner-side decryption: `BeeKEM.processWelcome`
    // uses the leaf private key (held by the joiner) to decrypt the
    // first path-key encryption in the Welcome. If the leaf were
    // seeded with a placeholder key the joiner could never bootstrap.
    //
    // Imported as `extractable=true`: BeeKEM's tree-hash computation
    // (`_computeTreeHash`) calls `exportKey('raw', publicKey)` over
    // every non-blanked tree node, so a non-extractable leaf public
    // key would crash subsequent `addMember` / `removeMember` calls.
    // `importEciesPublicKey` defaults to non-extractable for ECIES
    // recipient-key use, where extractability is wasted; for BeeKEM
    // leaf use we need the extractable variant.
    const memberPublicKey = await crypto.subtle.importKey(
      'raw',
      readerKemPublicKey as unknown as BufferSource,
      { name: 'ECDH', namedCurve: 'P-256' },
      true, // extractable
      [],
    );
    const result = await beekem.addMember(memberPublicKey);
    // `BeeKEMWelcome.leafIndex` is the node index of the new leaf
    // (even-numbered slot in the tree-math layout), which is exactly
    // what `removeMember` consumes.
    this._readerLeafIndices.set(serializedReader, result.welcome.leafIndex);
    // Cache the Welcome under its leaf index so a subsequent
    // `addReader` re-invocation can re-emit it without mutating the
    // tree. Keyed by leaf index (not identity) so revocation can
    // clear the cache atomically when the leaf is blanked.
    this._beekemWelcomeByLeaf.set(result.welcome.leafIndex, result.welcome);
    return result.welcome;
  }

  /**
   * Broadcast a BeeKEM `PathUpdate` to every connected peer over the
   * `beekemPathUpdateV1` protocol. Used by `removeReader` after a
   * successful `removeMember` rotation (the leaf-blank + path re-key
   * are both performed inside `removeMember`; no follow-up
   * `BeeKEM.update()` call is involved).
   *
   * Wire format mirrors `documentKeyUpdateV2`: a 4-byte big-endian
   * document-path length, the UTF-8 path bytes, then the serialized
   * sync message body (which carries the `pathUpdate` /
   * `pathUpdateEpochId` / `signature` fields). The message is
   * **writer-signed unconditionally** (independent of the swarm-wide
   * `enableSigning` toggle) so a malicious peer cannot inject a
   * forged PathUpdate that steers surviving readers onto an
   * attacker-controlled ratchet state.
   *
   * Best-effort fan-out: each failed dial is logged but does not
   * abort the broadcast. A surviving reader that misses the
   * PathUpdate falls back to a fresh document load to recover key
   * state, matching the legacy `_distributeKeyUpdate` posture.
   */
  private async _distributeBeeKEMPathUpdate(
    pathUpdate: PathUpdate,
    pathUpdateEpochId: Uint8Array,
  ): Promise<void> {
    const message: CRDTSyncMessage<ChangesType, PublicKey> = {
      documentId: this.documentPath,
      pathUpdate: serializePathUpdateForWire(pathUpdate),
      pathUpdateEpochId,
    };

    // Always writer-sign (mirrors the BeeKEM Welcome flow). Signing
    // is mandatory here: an unsigned PathUpdate would let any
    // connected peer rewrite every surviving reader's BeeKEM state.
    message.signature = await this._signAsWriterUnconditional(message);

    const serialized = this._syncMessageSerializer.serializeSyncMessage(message);

    const pathBytes = this._encoder.encode(this.documentPath);
    if (pathBytes.length === 0 || pathBytes.length > MAX_DOCUMENT_PATH_LENGTH) {
      throw new Error(
        `Document path "${this.documentPath}" encoded length (${pathBytes.length}) exceeds ` +
          `the maximum allowed path length (${MAX_DOCUMENT_PATH_LENGTH} bytes) for the BeeKEM PathUpdate v1 protocol`,
      );
    }
    const pathHeader = new Uint8Array(4);
    pathHeader[0] = (pathBytes.length >> 24) & 0xff;
    pathHeader[1] = (pathBytes.length >> 16) & 0xff;
    pathHeader[2] = (pathBytes.length >> 8) & 0xff;
    pathHeader[3] = pathBytes.length & 0xff;

    const payload = concatUint8Arrays(pathHeader, pathBytes, serialized);

    const peers =
      this.swarm.heliaNode.libp2p
        .getConnections()
        ?.map((x) => x.remoteAddr) ?? [];

    const failedPeers: string[] = [];
    for (const peer of peers) {
      try {
        const stream = wrapStream(
          await this.libp2p.dialProtocol(peer, [beekemPathUpdateV1], {
            runOnLimitedConnection: true,
          }),
        );
        await pipe([payload], stream.sink);
      } catch (err) {
        failedPeers.push(peer.toString());
        console.warn(
          `Failed to send BeeKEM PathUpdate to peer:`,
          peer.toString(),
          err,
        );
      }
    }

    if (failedPeers.length > 0) {
      console.warn(
        `BeeKEM PathUpdate for ${this.documentPath} failed to reach ${failedPeers.length} peer(s):`,
        failedPeers,
        'Affected peers may be unable to decrypt subsequent messages until they reload the document.',
      );
    }
  }

  /**
   * Handle an inbound `beekemPathUpdateV1` payload (already
   * de-framed of the path-prefix header by the shared handler in
   * `peerborne.ts`).
   *
   * Validates the writer signature, deserializes the carried
   * `PathUpdate`, applies it to the local BeeKEM tree via
   * `processPathUpdate`, and installs the resulting document key
   * under the supplied epoch ID. Mirrors the wire framing used by
   * `handleKeyUpdateRequestData` and `handleBeeKEMWelcomeRequestData`.
   *
   * SECURITY: the writer signature is **always** verified, regardless
   * of the swarm-wide `enableSigning` toggle. An unsigned or
   * invalid-signature PathUpdate is dropped without applying any
   * state change. The receiver also validates that the epoch ID it
   * derives locally matches the sender's `pathUpdateEpochId` -- a
   * mismatch indicates either a peer with stale local BeeKEM state
   * or a tampered payload, and is treated as a hard error.
   *
   * @internal Invoked by the shared protocol handler in `peerborne.ts`.
   */
  public async handleBeeKEMPathUpdateRequestData(
    payload: Uint8Array,
  ): Promise<void> {
    try {
      let message: CRDTSyncMessage<ChangesType, PublicKey>;
      try {
        message = this._syncMessageSerializer.deserializeSyncMessage(payload);
      } catch (err) {
        console.warn(
          `Dropping malformed BeeKEM PathUpdate for ${this.documentPath}:`,
          err,
        );
        return;
      }

      // Defense-in-depth against misrouted payloads (the shared
      // handler already routes by document path).
      if (message.documentId && message.documentId !== this.documentPath) {
        console.warn(
          `Ignoring BeeKEM PathUpdate for wrong document ` +
            `(${message.documentId} !== ${this.documentPath})`,
        );
        return;
      }

      // Writer signature is mandatory.
      if (!message.signature) {
        console.warn(
          `Dropping BeeKEM PathUpdate for ${this.documentPath}: missing signature`,
        );
        return;
      }
      const { signature, ...messageWithoutSignature } = message;
      const raw = this._syncMessageSerializer.serializeSyncMessage(
        messageWithoutSignature,
      );
      if (!(await this._verifyWelcomeWriterSignature(raw, signature))) {
        console.warn(
          `Dropping BeeKEM PathUpdate for ${this.documentPath}: invalid signature`,
        );
        return;
      }

      if (!message.pathUpdate) {
        console.warn(
          `Dropping BeeKEM PathUpdate for ${this.documentPath}: missing pathUpdate field`,
        );
        return;
      }
      if (!message.pathUpdateEpochId) {
        console.warn(
          `Dropping BeeKEM PathUpdate for ${this.documentPath}: missing pathUpdateEpochId field`,
        );
        return;
      }

      let pathUpdate: PathUpdate;
      try {
        pathUpdate = deserializePathUpdateFromWire(message.pathUpdate);
      } catch (err) {
        console.warn(
          `Dropping malformed BeeKEM PathUpdate for ${this.documentPath}:`,
          err,
        );
        return;
      }

      // Apply the path update to the local BeeKEM tree. Two failure
      // modes need different handling here:
      //
      //  - **No local BeeKEM state at all**: this peer has not gone
      //    through founder bootstrap or processed a Welcome yet, so
      //    initializing a fresh founder tree on the fly would only
      //    produce a different root than the sender's. The
      //    epoch-ID gate further down would reject it, but that
      //    would also do unnecessary cryptographic work and (worse)
      //    leave a stranded fresh tree behind for the next
      //    PathUpdate to confuse. Drop the message explicitly and
      //    log: the user will recover keychain state via a fresh
      //    document load against an authorized peer.
      //
      //  - **Stale local state**: `processPathUpdate` throws (the
      //    sender's path doesn't intersect our blanked path, or
      //    our tree state has drifted). Surface the failure but
      //    do not crash the inbound handler.
      if (!this._beekemInitialized || !this._beekem) {
        console.warn(
          `Dropping BeeKEM PathUpdate for ${this.documentPath}: local BeeKEM ` +
            `state is not initialized (no Welcome received). Recover by ` +
            `performing a fresh document load against an authorized peer.`,
        );
        return;
      }
      const beekem = this._beekem;
      let rootSecret: Uint8Array;
      try {
        rootSecret = await beekem.processPathUpdate(pathUpdate);
      } catch (err) {
        console.warn(
          `Failed to apply BeeKEM PathUpdate for ${this.documentPath}: ` +
            `local tree state could not process the update. ` +
            `Falling back to a fresh document load may be required to ` +
            `recover keychain state.`,
          err,
        );
        return;
      }

      // Validate the sender's epoch ID against our locally-derived
      // value. The wire carries the FULL 32-byte HKDF output and the
      // keychain installs under the same 32-byte ID -- no truncation
      // step on either side, so the wire-format and storage key are
      // byte-identical to what both ends will key on for future
      // encrypted-block lookups.
      const localEpochId32 = await deriveEpochIdFromRootSecret(rootSecret);
      const senderEpochId32 = message.pathUpdateEpochId;
      if (!constantTimeEqual(localEpochId32, senderEpochId32)) {
        console.warn(
          `BeeKEM PathUpdate epoch-ID mismatch for ${this.documentPath}: ` +
            `local derivation diverged from sender. PathUpdate dropped.`,
        );
        return;
      }

      const newKey = await deriveDocumentKeyFromRootSecret(rootSecret);
      try {
        await this._keychain.addEpochKey(
          localEpochId32,
          newKey as unknown as DocumentKey,
        );
      } catch (err) {
        console.error(
          `Failed to install BeeKEM-derived epoch key in keychain for ${this.documentPath}:`,
          err,
        );
        return;
      }

      console.log(
        `Installed BeeKEM-derived epoch key for ${this.documentPath} via PathUpdate`,
      );
    } catch (err: unknown) {
      console.error(
        `Error handling BeeKEM PathUpdate for document ${this.documentPath}:`,
        err,
      );
    }
  }

  /**
   * Distribute keychain changes to all connected peers via the
   * legacy `documentKeyUpdateV2` protocol (encrypts the new key under
   * the previous key).
   *
   * `removeReader` no longer uses this path: it rotates the document
   * key via BeeKEM's ratchet tree and broadcasts a signed
   * `PathUpdate` over `beekemPathUpdateV1` instead, which closes the
   * revocation-latency gap where a removed-but-still-connected
   * reader could decrypt the rotation message (#189 §5.4 item 5).
   *
   * `removeWriter` continues to use this method: writer revocation
   * has different threat properties (the removed writer no longer
   * has write capability, even if they retain read access through
   * the old key until the next BeeKEM rotation), and the BeeKEM
   * tree currently models reader membership only. A follow-up
   * change will fold writer revocation into the BeeKEM path too.
   *
   * @param keychainChanges The keychain CRDT changes containing the new key.
   * @param previousKey The previous document key to encrypt the update with.
   *   Peers already have this key and can decrypt the message to learn about the new key.
   *   This avoids the chicken-and-egg problem of encrypting with a key peers don't have yet.
   */
  private async _distributeKeyUpdate(
    keychainChanges: ChangesType,
    previousKey: [Uint8Array, DocumentKey],
  ) {
    const keyUpdateMessage: CRDTSyncMessage<ChangesType, PublicKey> = {
      documentId: this.documentPath,
      keychainChanges,
    };

    // Sign the key update message.
    keyUpdateMessage.signature = await this._signAsWriter(keyUpdateMessage);

    const serialized =
      this._syncMessageSerializer.serializeSyncMessage(keyUpdateMessage);

    // Encrypt with the PREVIOUS key so that existing peers can decrypt the message.
    // Peers don't have the new key yet -- that's what this message delivers to them.
    const [previousKeyID, previousDocumentKey] = previousKey;
    const { nonce, data } = await this._authProvider.encrypt(
      serialized,
      previousDocumentKey,
    );
    if (!nonce) {
      throw new Error(`Failed to encrypt key update! Nonce cannot be empty`);
    }

    // Send to all connected peers via the V2 key-update protocol.
    // V2 payload format: 4-byte big-endian path length + UTF-8 path + encrypted payload
    const peers = this.swarm.heliaNode.libp2p
      .getConnections()
      ?.map((x) => x.remoteAddr);

    const pathBytes = this._encoder.encode(this.documentPath);
    if (pathBytes.length === 0 || pathBytes.length > MAX_DOCUMENT_PATH_LENGTH) {
      throw new Error(
        `Document path "${this.documentPath}" encoded length (${pathBytes.length}) exceeds ` +
        `the maximum allowed path length (${MAX_DOCUMENT_PATH_LENGTH} bytes) for the V2 key-update protocol`,
      );
    }
    const pathHeader = new Uint8Array(4);
    pathHeader[0] = (pathBytes.length >> 24) & 0xff;
    pathHeader[1] = (pathBytes.length >> 16) & 0xff;
    pathHeader[2] = (pathBytes.length >> 8) & 0xff;
    pathHeader[3] = pathBytes.length & 0xff;

    const v2Payload = concatUint8Arrays(pathHeader, pathBytes, previousKeyID, nonce, data);

    // WARNING: If some peers fail to receive this update, they will be unable
    // to decrypt future messages encrypted with the new key. They will need to
    // perform a fresh document load to recover the keychain state.
    const failedPeers: string[] = [];
    for (const peer of peers) {
      try {
        // Wrap the v3 stream so we can keep using the legacy `pipe(..., sink)`
        // pattern below; see snapshot-load above for the rationale.
        const stream = wrapStream(await this.libp2p.dialProtocol(peer, [
          documentKeyUpdateV2,
        ], { runOnLimitedConnection: true }));
        await pipe(
          [v2Payload],
          stream.sink,
        );
      } catch (err) {
        const peerAddr = peer.toString();
        failedPeers.push(peerAddr);
        console.warn(
          `Failed to send key update to peer:`,
          peerAddr,
          err,
        );
      }
    }

    if (failedPeers.length > 0) {
      console.warn(
        `Key update for ${this.documentPath} failed to reach ${failedPeers.length} peer(s):`,
        failedPeers,
        'These peers may be unable to decrypt future messages until they reload the document.',
      );
    }
  }

  /**
   * Handles a key-update request with pre-read payload data. Called by
   * the shared protocol handler in Peerborne after reading the document
   * path header and routing.
   *
   * @internal
   * @param payload The encrypted key-update payload (without the document
   *   path header that was already stripped by the shared handler).
   */
  public async handleKeyUpdateRequestData(
    payload: Uint8Array,
  ): Promise<void> {
    try {
      // Decrypt the key update message.
      const blockKeyID = payload.slice(
        0,
        this._keychainProvider.keyIDLength,
      );
      const blockNonce = payload.slice(
        this._keychainProvider.keyIDLength,
        this._keychainProvider.keyIDLength + this._authProvider.nonceBits,
      );
      const blockData = payload.slice(
        this._keychainProvider.keyIDLength + this._authProvider.nonceBits,
      );

      let rawContent: Uint8Array | undefined;
      try {
        rawContent = await this._decryptBlock(
          blockKeyID,
          blockNonce,
          blockData,
        );
      } catch (e) {
        console.warn('Failed to decrypt key update message:', e);
      }

      if (!rawContent) {
        console.warn(
          `Unable to decrypt key update for ${this.documentPath}`,
        );
        return;
      }

      const message =
        this._syncMessageSerializer.deserializeSyncMessage(rawContent);

      // The shared V2 key-update handler already routes by the
      // length-prefixed document-path header and drops invalid headers;
      // this check is kept as a defense-in-depth guard against malformed
      // or misrouted messages.
      if (message.documentId && message.documentId !== this.documentPath) {
        console.warn(
          `Ignoring key-update for wrong document ` +
          `(${message.documentId} !== ${this.documentPath})`,
        );
        return;
      }

      // Verify the sender is an authorized writer.
      if (this._isSigningEnabled()) {
        if (message.signature) {
          const { signature, ...messageWithoutSignature } = message;
          const raw =
            this._syncMessageSerializer.serializeSyncMessage(
              messageWithoutSignature,
            );
          if (!(await this._verifyWriterSignature(raw, signature))) {
            console.warn(
              `Received key update with invalid signature for ${this.documentPath}`,
            );
            return;
          }
        } else {
          console.warn(
            `Received unsigned key update for ${this.documentPath}`,
          );
          return;
        }
      }

      console.log(`received key-update for ${this.documentPath}`);

      // Merge keychain changes.
      if (message.keychainChanges) {
        try {
          this._keychain.merge(message.keychainChanges);
          console.log(
            `Updated keychain via key-update protocol in ${this.documentPath}`,
          );
        } catch (e) {
          console.error(
            'Failed to merge keychain changes from key update:',
            e,
          );
        }
      }
    } catch (err: unknown) {
      console.error(
        `Error handling key update request for document ${this.documentPath}:`,
        err,
      );
    }
  }

}
