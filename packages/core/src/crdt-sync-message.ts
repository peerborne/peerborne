import { CRDTChangeNode } from './crdt-change-node.js';
import {
  SerializedPathUpdateV2,
} from './path-update-wire.js';
import { CRDTSnapshotNode } from './snapshot-node.js';
import type { LoadSecurityCommitments } from './load-security-state.js';

const signatureContexts = [
  'ordinary-sync-v1',
  'load-response-v4',
  'security-advertisement-v1',
  'invitation-bootstrap-v1',
  'invitation-catch-up-v1',
  'beekem-welcome-v2',
  'beekem-path-update-v2',
] as const;
const signatureContextSet = new Set<string>(signatureContexts);

/** Wire-purpose tag signed by authenticated sync-message operations. */
export type SyncMessageSignatureContext = (typeof signatureContexts)[number];

/** Return whether an untrusted value is one exact supported signature tag. */
export function isSyncMessageSignatureContext(
  value: unknown,
): value is SyncMessageSignatureContext {
  return typeof value === 'string' && signatureContextSet.has(value);
}

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
   * Exact wire purpose of this message. Every network admission path requires
   * this value to match its local context. For authenticated operations, the
   * field is serialized with the unsigned body, so a writer signature binds
   * the payload to one protocol purpose instead of authenticating reusable
   * context-free bytes.
   *
   */
  signatureContext: SyncMessageSignatureContext;

  /**
   * CID of the root change node.
   */
  changeId?: string;

  /**
   * Root of the Merkle-DAG change tree. Each `CRDTChangeNode` contains a change
   * payload and optional `children` linking to prior nodes. A node whose `change`
   * is `undefined` (deferred) should be fetched from the Helia blockstore by CID.
   * Generic JSON wire codecs traverse this tree iteratively. Load manifests
   * additionally enforce a 512-node root-to-leaf policy. Ingress remains bounded by aggregate wire,
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
   * Recipient-encrypted BeeKEM Welcome V2 and keychain delta. The generation-
   * and leaf-count-bearing Welcome is mandatory. The writer envelope signs
   * these sealed bytes; recipients additionally enforce tree and replay checks.
   */
  eciesSealed?: Uint8Array;

  /**
   * Parent-bound BeeKEM V2 ratchet-tree update. Only the PathUpdate protocol
   * carries this value; document sync, load, and Welcome messages omit it.
   */
  pathUpdate?: SerializedPathUpdateV2;

  /**
   * Optional 32-byte epoch identifier paired with `pathUpdate`. The
   * sender derives this from the new BeeKEM root secret via
   * `deriveEpochIdFromRootSecret`; the receiver re-derives it after
   * `BeeKEM.processPathUpdate` and validates that the two match
   * byte-for-byte before installing the new key. Mismatch means the
   * receiver derived a different root than the sender (e.g. stale
   * local tree state) and the PathUpdateV2 is rejected rather than
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
   * SHA-256 digest of the complete V4 response plan: document identity,
   * served frontier, locally trusted control/group commitments, and canonical
   * response manifest. Security advertisements carry this digest with a
   * fresh challenge and writer signature. The loader derives the same digest
   * from the selected response before applying state. Votes are deduplicated
   * by canonical signing authority, independently of transport PeerIds.
   */
  tipsHash?: Uint8Array;

  /**
   * Served change-tree frontier, required on full/snapshot load responses
   * and invitation bootstrap/catch-up messages. V4 loading derives this
   * frontier from the actual tree and snapshot boundary and rejects a
   * contradictory attestation, including when quorum selection is disabled.
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
   * Exact echo of the requester's fresh 32-byte challenge, covered by the
   * writer envelope signature. Required on V4 advertisements, full/snapshot
   * responses, and issuer-pinned invitation catch-up responses.
   */
  loadChallenge?: Uint8Array;

  /**
   * Signature of the sync message.
   */
  signature?: string;
};
