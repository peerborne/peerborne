// Initial loads bind a fresh signed challenge, a complete response manifest,
// the served frontier, and locally trusted control/group commitments.
export const documentLoadV4 = '/peerborne/doc-load/4.0.0';
export const snapshotLoadV4 = '/peerborne/snapshot-load/4.0.0';
export const securityAdvertiseV1 = '/peerborne/security-advertise/1.0.0';

// Catch-up after a verified invitation is authorized by its pinned issuer.
export const invitationCatchUpV1 = '/peerborne/invitation-catch-up/1.0.0';

// Public invitation join v1: a recipient opens a direct stream to an
// inviter advertised by a signed InvitationOffer, sends one canonical signed
// InvitationJoinRequest frame, and receives one canonical signed
// InvitationAcceptance frame. The offer itself is transported out of band
// (for example as a QR code or link). Message codecs, signature domains,
// expiry checks, recipient/KEM binding, and replay guards live in
// `invitation-wire.ts` and `invitation-replay-guard.ts`.
export const invitationJoinV1 = '/peerborne/invitation-join/1.0.0';

// BeeKEM Welcome v2 onboards a new reader into a document. The inviting
// writer sends the invitation epoch ID, the keychain changes filtered by the
// document's `HistoryVisibility` setting (this filters epoch keys, not retained
// CRDT operations), and a generation- and leaf-count-bearing BeeKEM tree for
// the recipient's leaf. The frame uses the shared length-prefixed document
// path header so the shared handler can route it to the correct document.
//
// The keychain delta and BeeKEM Welcome travel only in the `eciesSealed`
// field, sealed to `welcomeRecipientKemPublicKey` with ECIES (P-256 ECDH,
// HKDF-SHA-256, AES-256-GCM). The writer signature covers the sealed bytes and
// the signed `welcomeRecipient` binding, so a peer cannot alter the payload or
// re-point it at another identity. The receiver commits the keychain delta
// only together with the BeeKEM bootstrap.
//
// The readers-ACL update travels over pubsub and the Welcome over a direct
// stream, so they can arrive out of order. The inviter does not retry. A
// Welcome dropped only because the local user is not yet in the readers ACL
// is retained as a canonical serialized body (at most 16 entries, 20 MiB in
// total, ~5 min each) and replayed through the full authentication path on
// every readers-ACL merge. A Welcome that exceeds a bound or expires is
// discarded; the recipient then needs a fresh recipient-bound Welcome.
export const beekemWelcomeV2 = '/peerborne/beekem-welcome/2.0.0';

// BeeKEM PathUpdate v2 distributes a writer's ratchet-tree path update to
// every surviving member. `PeerborneDocument.removeReader` uses it to revoke a
// reader: `BeeKEM.removeMember` blanks the removed leaf and re-keys the
// writer's path to the root in one step, and receivers derive the new document
// key from the fresh root secret. Each update is bound to its committed parent
// tree and advances exactly one generation. The removed reader cannot derive
// the new key because its leaf is blanked and the new path secrets are
// encrypted only to the remaining subtree resolutions.
//
// The update is writer-signed unconditionally, regardless of the
// `enableSigning` document toggle; receivers drop any update whose signature
// is missing or invalid. Delivery is best-effort: the sender logs failed dials
// and does not retry. A member that misses an update cannot recover the new
// epoch with an ordinary load, because load responses are encrypted under the
// responder's current key; it needs a recipient-bound re-invitation or another
// explicit key-recovery flow.
export const beekemPathUpdateV2 = '/peerborne/beekem-pathupdate/2.0.0';

export const searchIndexAdvertiseV1 = '/peerborne/search-index-advertise/1.0.0';
export const searchQueryV1 = '/peerborne/search-query/1.0.0';
