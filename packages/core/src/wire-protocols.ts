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

// Welcomes require a generation-bearing tree and recipient-sealed keychain.
export const beekemWelcomeV2 = '/peerborne/beekem-welcome/2.0.0';

// Writer-signed updates advance exactly one generation from the committed
// parent tree. Missed updates require ordered delivery or ratchet recovery.
export const beekemPathUpdateV2 = '/peerborne/beekem-pathupdate/2.0.0';

export const searchIndexAdvertiseV1 = '/peerborne/search-index-advertise/1.0.0';
export const searchQueryV1 = '/peerborne/search-query/1.0.0';
