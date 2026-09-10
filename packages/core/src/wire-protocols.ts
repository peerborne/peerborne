export const bloomFilterUpdateV1 = '/collabswarm/bloom-index/1.0.0';

/** Version selector shared by BeeKEM Welcome and PathUpdate handlers. */
export type BeeKEMWireVersion = 1 | 2;

// V3 doc-load and snapshot-load handlers use a shared handler model where
// a single handler serves all documents. They include an explicit `tips`
// field in the SIGNED `CRDTSyncMessage` payload so the loader can bind the
// served state to the responder's current frontier and complete the
// initial-load quorum check (see `tipAdvertiseV1` and #189 §5.4.2).
//
// Why v3 (not "v2 with an extra optional field")? Including `tips` inside
// the signed payload changes the bytes the signer authenticated. A
// receiver whose serializer doesn't recognise `tips` would: (1) deserialize
// the message dropping `tips`, (2) re-serialize for signature verification,
// (3) get bytes that differ from what the sender signed -> signature check
// fails. Versioning the protocol id forces incompatible peers to dial a
// protocol they don't have a handler for and fail loudly instead of
// silently dropping the binding. This alpha format does not retain a v2
// alias; persisted/deployed v2 peers require an explicit migration plan.
//
// `documentKeyUpdateV2` is not bumped by the load-quorum work because that
// payload adds neither `tips` nor `tipsHash`. This name does not imply
// compatibility across the repository's earlier 16-to-32-byte key-ID break:
// that change also affected unversioned encrypted blocks/pubsub framing and has
// no dual-width decoder. See MIGRATING.md.
export const documentLoadV3 = '/collabswarm/doc-load/3.0.0';
// V4 load responses add a signed `loadSecurityState` tuple. Its quorum digest
// binds the control/group tuple and served frontier together with a canonical
// complete response manifest (root, CID/kind/edge graph, deferred markers,
// snapshot content/metadata, and keychain delta). Each request also signs a
// fresh 32-byte challenge that every writer-signed advertisement/full response
// must echo, preventing a complete older quorum transcript from being replayed
// in a later load round. The loader recomputes the manifest from the actual
// response before sync. V4 is a separate family because older serializers
// cannot verify the same signed bytes or binding; strict clients select it
// atomically and never downgrade to V3.
export const documentLoadV4 = '/collabswarm/doc-load/4.0.0';
export const documentKeyUpdateV2 = '/collabswarm/key-update/2.0.0';
export const snapshotLoadV3 = '/collabswarm/snapshot-load/3.0.0';
export const snapshotLoadV4 = '/collabswarm/snapshot-load/4.0.0';

// Tip-advertise v1: lightweight initial-load quorum probe.
//
// Closes the "no quorum protocol for verifying initial document state" gap
// tracked under issue #189 §5.4 item 2 (also a bullet under #186). When a
// node opens a document, it asks up to `loadQuorumK` peers in parallel for
// a 32-byte SHA-256 digest of their current tip set (see `tips-hash.ts`)
// and proceeds with a full document-load only if at least `loadQuorumQ`
// peers agree on the same hash. This defends against a single malicious or
// partitioned peer serving a stale/maliciously-crafted initial state.
//
// Wire format (request and response are length-delimited single frames):
//
//   Request:  serialized `CRDTLoadRequest` (same shape as documentLoadV3 --
//             reuses the existing load-request serializer so a writer can
//             sign just the document id and the responder can authorize
//             via the standard ACL/signature check).
//
//   Response: ONE of three wire shapes -- the loader's probe distinguishes
//             them by the first-byte and length of the response:
//
//               (a) Empty payload (zero bytes) -- the responder declines
//                   without disclosing whether the document exists: the
//                   request was unauthorized, the request's documentId
//                   did not match (signing-on-one-side mismatch), the
//                   responder threw on serialization, etc. The loader
//                   records this as a generic non-vote (`null` from the
//                   probe). NOT used for the "I genuinely don't have
//                   this document" case -- see (b).
//
//               (b) Single-byte `0xff` sentinel (UNKNOWN_DOC) -- the
//                   responder has NO document registered for this path.
//                   Distinguished from (a) so the loader can tally
//                   disclaim votes alongside tip-hash votes via
//                   `decideLoadQuorum` (see `load-quorum.ts`). The
//                   sentinel is intentionally unauthenticated (no
//                   per-doc keychain to sign/encrypt with); the quorum
//                   configured Q-of-K threshold limits a lone lying peer only
//                   when enough independently controlled responders agree.
//                   Tip-hash votes take precedence when their own bucket also
//                   reaches Q. This is not Byzantine consensus or Sybil
//                   resistance.
//
//               (c) Serialized + encrypted `CRDTSyncMessage` whose
//                   only populated payload field is `tipsHash` (plus
//                   `documentId` and optionally `signature`). The
//                   responder does NOT include `changes`, `snapshot`,
//                   or `keychainChanges` -- the heavy state transfer
//                   happens later via documentLoadV3/snapshotLoadV3
//                   against an agreeing peer.
//
// Layered on documentLoadV3's transport semantics, but on a separate
// protocol id so a slow/malicious peer that serves bogus full loads cannot
// also cheaply poison every quorum vote at the same time.
export const tipAdvertiseV1 = '/collabswarm/tip-advertise/1.0.0';
// Reserved security-aware probe contract. Its signed hash covers the served
// frontier, the complete derived load-response manifest, and the same
// `loadSecurityState` tuple required on the subsequent V4 load. It also echoes
// the request's fresh challenge inside the signed envelope. The unauthenticated
// 0xff unknown-document sentinel is never valid here.
export const securityAdvertiseV1 = '/collabswarm/security-advertise/1.0.0';

// Public invitation join v1: a recipient opens a direct stream to an
// inviter advertised by a signed InvitationOffer, sends one canonical signed
// InvitationJoinRequest frame, and receives one canonical signed
// InvitationAcceptance frame. The offer itself is transported out of band
// (for example as a QR code or link). Message codecs, signature domains,
// expiry checks, recipient/KEM binding, and replay guards live in
// `invitation-wire.ts` and `invitation-replay-guard.ts`.
//
// This is the first protocol introduced under the Peerborne name. Existing
// `/collabswarm/*` protocol IDs remain unchanged compatibility boundaries.
export const invitationJoinV1 = '/peerborne/invitation-join/1.0.0';

// BeeKEM Welcome v1: retained for generation-less legacy receive
// compatibility. The inviting writer sends a Welcome containing (a) the
// invitation epoch ID retained as a local audit/ordering anchor, not an
// ordinary-load history boundary or durable ratchet-generation anchor, and (b)
// keychain changes filtered per the document's `HistoryVisibility` setting --
// so the new reader can decrypt (at least) the current document state. The
// payload uses the same shared
// length-prefixed-document-path header as the V2 key-update protocol so
// the shared handler can route incoming Welcomes to the correct document.
//
// =============================================================================
// CONFIDENTIALITY: payload sealed to the recipient (ECIES, P-256 ECDH +
// HKDF-SHA-256 + AES-256-GCM)
// =============================================================================
// The Welcome's keychain delta is **not** broadcast in the clear. The
// `CRDTSyncMessage` carrying a Welcome has a dedicated `eciesSealed` field
// (see `crdt-sync-message.ts` / `ecies.ts`) which is the ECIES sealed-box
// over the serialized keychain changes, encrypted under the recipient's
// ECDH public key (`welcomeRecipientKemPublicKey`). Only the recipient
// holding the matching ECDH private key can recover the plaintext keychain
// delta -- a non-recipient peer that is connected at broadcast time sees
// only the opaque ciphertext + ephemeral public key + nonce + tag.
//
// The writer signature covers the sealed bytes (not the plaintext), so a
// connected peer cannot alter the sealed payload without invalidating the
// signature. The recipient binding (`welcomeRecipient`, also covered by
// the signature) prevents a non-writer or network attacker from re-pointing a
// signed payload at a different identity. An authorized writer chooses both
// the recipient identity and KEM key and therefore remains part of the trust
// boundary.
//
// Defense-in-depth retained from earlier versions of this protocol:
//   - `welcomeRecipient` continues to gate processing: a well-behaved
//     non-target peer drops the Welcome rather than attempting to install
//     the keychain delta. Confidentiality is enforced by ECIES; the
//     recipient binding is the authorization gate.
//   - libp2p's Noise/TLS transport still protects on-wire bytes from
//     off-path observers, on top of the application-layer encryption.
//
// The readers-ACL update and Welcome can arrive in either order. Current
// onboarding treats an exact identity+KEM-bound Welcome authenticated by a
// current ACL writer (or an application-pinned bootstrap writer while the ACL
// is empty) as the bootstrap grant, so the recipient need not decrypt the ACL
// update first. The Welcome is fire-and-forget and is not buffered or retried.
//
// BeeKEM-enabled, KEM-bound `PeerborneDocument.addReader` onboarding requires
// a complete V2 Welcome and never downgrades to this endpoint. The ACL-only
// overload does not establish BeeKEM membership. Writer onboarding that
// piggy-backs on the Welcome flow is not implemented.
export const beekemWelcomeV1 = '/collabswarm/beekem-welcome/1.0.0';

// The project's legacy BeeKEM construction (not MLS) uses Welcome v2 for a
// non-null, versioned, generation- and leaf-count-bearing bootstrap inside the
// recipient-sealed payload. Senders dial one version and never downgrade.
export const beekemWelcomeV2 = '/collabswarm/beekem-welcome/2.0.0';

// The project's legacy BeeKEM construction (not MLS) retains PathUpdate v1
// only for an explicitly opted-in migration of genuinely legacy,
// generation-less local state. Its wire bytes are frozen and carry neither a
// generation nor a parent-tree commitment, so replay can roll legacy ratchet
// and keychain state back. Peerborne therefore does not register this handler
// and rejects direct v1 application by default. Enabling
// `allowInsecureLegacyBeeKEMPathUpdateV1` accepts that replay risk for a
// bounded migration. Generation-bearing state still rejects v1 rather than
// downgrading.
// Earlier peers used PathUpdate v1 to distribute a ratchet-tree update to
// surviving members. Current `PeerborneDocument.removeReader` sends only v2.
// In either version, `BeeKEM.removeMember` blanks the removed leaf AND
// re-keys the writer's path to root in a single step (no separate
// `BeeKEM.update` call is involved -- see the "Wire format" section
// below for why). The resulting `PathUpdate` is broadcast to every
// surviving reader, which applies it with `BeeKEM.processPathUpdate`
// and re-derives the document key from
// the fresh root secret (see `derive-doc-key.ts`). The removed reader
// cannot derive the new key — their leaf is blanked and the new path key
// material is encrypted to subtrees they no longer occupy — which closes
// the revocation-latency gap of the previous "encrypt new key under old
// key" rotation scheme.
//
// =============================================================================
// SAFETY-CRITICAL: writer-only
// =============================================================================
// The PathUpdate body is **writer-signed unconditionally**, mirroring the
// BeeKEM Welcome v1 protocol: peer-reachable signing keys are checked
// regardless of the `enableSigning` document toggle. A malicious peer that
// could forge a PathUpdate would force every surviving reader to switch
// to an attacker-controlled BeeKEM state, making all subsequent
// document traffic readable to the attacker. Receivers MUST drop any
// PathUpdate whose signature is missing or invalid.
//
// =============================================================================
// Wire format (mirrors `documentKeyUpdateV2` / `beekemWelcomeV1` framing)
// =============================================================================
//   [4-byte BE doc-path length] [UTF-8 doc-path] [serialized sync message]
//
// The sync message carries:
//   - `pathUpdate`: the `PathUpdate` produced by
//     `BeeKEM.removeMember(leafIdx)`, serialized via the
//     `SerializedPathUpdate` wire shape (see `path-update-wire.ts`).
//     `removeMember` itself blanks the removed leaf, blanks every
//     internal node on the removed direct path, and re-derives fresh
//     key material along the writer's own path to root -- the path
//     re-derivation is part of `removeMember`, NOT a separate
//     follow-up `BeeKEM.update()` call. (A redundant `update()` would
//     only discard the fresh material `removeMember` just produced.)
//   - `pathUpdateEpochId`: the 32-byte HKDF-derived epoch identifier
//     (output of `deriveEpochIdFromRootSecret`). Receivers compare the
//     full 32 bytes against their locally-derived ID and install the
//     new document key under that same 32-byte ID. The keychain
//     providers' `keyIDLength` is 32 -- byte-identical to the HKDF
//     output width -- so the wire-format key-ID prefix, the
//     `pathUpdateEpochId` field on this protocol, and the keychain's
//     storage key are all the same 32 bytes. No truncation step
//     exists; an earlier (buggy) revision truncated to a narrower
//     keychain key-ID width and produced a deterministic post-rotation
//     decrypt failure on every receiver.
//   - `signature`: writer signature over the canonical
//     (signature-stripped) serialization of the sync message.
//
// =============================================================================
// Confidentiality
// =============================================================================
// PathUpdates carry only public-key material plus key updates encrypted
// to specific subtree resolution keys — no plaintext document secrets —
// so on-wire encryption (Noise/TLS via libp2p) is sufficient. The
// security guarantee comes from BeeKEM itself: only members on the
// non-blanked side of each path-update step can decrypt the corresponding
// encrypted-private-key field. A revoked reader who observes the
// PathUpdate cannot recover the root secret.
//
// =============================================================================
// Failure modes
// =============================================================================
// Surviving readers MUST receive the PathUpdate or complete an authenticated
// membership remove/rejoin to install the new epoch key. Ordinary load cannot
// repair an unknown current key or missing private ratchet path. The PathUpdate
// distribution is fire-and-forget: the library logs each failed
// dial but does not retry, matching the best-effort posture of the
// rest of the document protocol.
//
// If a surviving reader misses the PathUpdate, their local keychain
// state diverges from the writer's. Subsequent writer-originated
// traffic is encrypted under the new epoch key (`pathUpdateEpochId`
// is the wire-format key-ID prefix); the recipient has no entry for
// that ID in their local keychain and the decrypt fails.
//
// Recovery is NOT guaranteed by a vanilla `loadDocument` against an
// arbitrary peer: `handleLoadRequestData` encrypts its response under
// the responder's `_keychain.current()`, so the recipient can
// decrypt the load response only if they ALSO already hold the
// responder's current key. Recovery today requires an authenticated
// membership remove/rejoin; a standalone fresh-state transfer is not exposed.
//
// Future work: implement reliable PathUpdate delivery (e.g. signed
// ACK + retry, or rolling-window resend on libp2p reconnect) so a
// transient dial failure does not require a full re-onboard. Tracked
// as a follow-up; in the meantime, application-level policy should
// treat surviving-reader connectivity at revocation time as a
// liveness requirement.
export const beekemPathUpdateV1 = '/collabswarm/beekem-pathupdate/1.0.0';

// PathUpdate v2 is the explicit compatibility boundary used for current
// revocations and multi-member churn. It binds the exact parent tree,
// consecutive generation, exact leaf count, a shape-bound full public-tree
// snapshot, and one encrypted ancestor-key bundle per copath resolution node.
// V1 must not accept these fields. Missed transitions require persisted current
// ratchet state or an authenticated membership remove/rejoin rather than an
// unrelated higher-generation snapshot; ordinary load cannot restore the tree.
export const beekemPathUpdateV2 = '/collabswarm/beekem-pathupdate/2.0.0';

// The historical protocol namespace is retained as a wire-compatibility boundary.
export const searchIndexAdvertiseV1 = '/collabswarm/search-index-advertise/1.0.0';
export const searchQueryV1 = '/collabswarm/search-query/1.0.0';
