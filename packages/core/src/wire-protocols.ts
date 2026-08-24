export const bloomFilterUpdateV1 = '/collabswarm/bloom-index/1.0.0';

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
// silently dropping the binding. There are no live users of this project,
// so we did NOT retain a v2 alias -- removing legacy handlers keeps the
// codebase clean.
//
// `documentKeyUpdateV2` is intentionally NOT bumped: its wire shape is
// unaffected by the load-quorum work (no `tips` field, no `tipsHash`).
export const documentLoadV3 = '/collabswarm/doc-load/3.0.0';
export const documentKeyUpdateV2 = '/collabswarm/key-update/2.0.0';
export const snapshotLoadV3 = '/collabswarm/snapshot-load/3.0.0';

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
//                   gate's Q-Byzantine threshold defends against
//                   lying-disclaim attacks AND tip-hash votes are
//                   given precedence over disclaim votes so peers WITH
//                   the document outvote unrelated peers in the same
//                   mesh that don't. See PR #284 r16 / r19.
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

// BeeKEM Welcome v1: onboards a new reader into a document. The inviting
// writer sends a Welcome containing (a) the invitation epoch ID the
// recipient should record so subsequent `since_invited` history filtering
// works, and (b) the keychain changes filtered per the document's
// `HistoryVisibility` setting -- so the new reader can decrypt (at least)
// the current document state. The payload uses the same shared
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
// the signature) prevents an authorized writer from re-pointing a sealed
// payload at a different identity than the one the encryption keypair
// belongs to.
//
// Defense-in-depth retained from earlier versions of this protocol:
//   - `welcomeRecipient` continues to gate processing: a well-behaved
//     non-target peer drops the Welcome rather than attempting to install
//     the keychain delta. Confidentiality is enforced by ECIES; the
//     recipient binding is the authorization gate.
//   - libp2p's Noise/TLS transport still protects on-wire bytes from
//     off-path observers, on top of the application-layer encryption.
//
// =============================================================================
// Race mitigation on the receive side
// =============================================================================
// The inviter sends the readers-ACL update over pubsub and the Welcome over
// a direct stream; without coordination these can arrive out of order on the
// recipient. The Welcome itself is fire-and-forget: there is NO ack protocol
// in this version, and the inviter does NOT retry. Instead, the recipient's
// `PeerborneDocument._evaluateAndApplyBeeKEMWelcome` buffers Welcomes
// dropped solely because the local user is not yet in the readers ACL into a
// small bounded `pendingWelcomes` Map (max 16 entries, ~5 min TTL) keyed by
// `hex(welcomeEpochId)`. The buffer is drained on every readers-ACL merge,
// so a Welcome that arrived before its corresponding ACL update gets
// replayed automatically. A Welcome that exhausts the TTL without an
// unblocking ACL update is discarded; the recipient must then rely on a
// fresh document-load against an authorized peer to recover keychain state.
//
// Note: only the reader-onboarding path is wired in this PR
// (`PeerborneDocument.addReader`). A writer-onboarding flow that
// piggy-backs on the same wire format is a future extension; until that
// is wired up the protocol is documented as a reader-only flow.
export const beekemWelcomeV1 = '/collabswarm/beekem-welcome/1.0.0';

// BeeKEM PathUpdate v1: distributes a BeeKEM ratchet-tree path update to
// every surviving member of a document. Used by
// `PeerborneDocument.removeReader` to revoke a reader: the writer
// calls `BeeKEM.removeMember`, which blanks the removed leaf AND
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
// Surviving readers MUST receive the PathUpdate (or an equivalent
// out-of-band Welcome / load that observes the post-rotation
// keychain state) to install the new epoch key. The PathUpdate
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
// responder's current key. The reliable recovery path today is a
// fresh BeeKEM Welcome from an authorized writer (Welcome payloads
// are sealed under the recipient's KEM public key, not under the
// keychain), which both rebootstraps the recipient's BeeKEM ratchet
// state and re-shares the keychain.
//
// Future work: implement reliable PathUpdate delivery (e.g. signed
// ACK + retry, or rolling-window resend on libp2p reconnect) so a
// transient dial failure does not require a full re-onboard. Tracked
// as a follow-up; in the meantime, application-level policy should
// treat surviving-reader connectivity at revocation time as a
// liveness requirement.
export const beekemPathUpdateV1 = '/collabswarm/beekem-pathupdate/1.0.0';
