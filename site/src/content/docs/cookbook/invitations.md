---
title: Invite a collaborator
description: Create and accept a signed, recipient-encrypted Peerborne invitation.
---

Peerborne's initial invitation flow lets a document founder invite one active
collaborator with a separate signing identity. The founder and recipient must
both be online and reachable through a Circuit Relay while the invitation is
accepted. Application-level signing must remain enabled on both nodes.

The offer is a bearer capability. It contains public metadata, not a document
key, but anyone who obtains it can claim its reader or editor role first. Send
it through a channel you trust and keep it out of server logs and analytics.
There is no selective cancellation API in the initial release: use a short
lifetime for a link you may need to abandon. Closing the founder document or
stopping its node makes every outstanding offer unavailable, but also disrupts
the active session.

## Founder

Install a P-256 ECDH key pair with a non-extractable private key before creating
the offer. `generateEciesKeyPair()` returns an exportable public half so
Peerborne can encode its raw point. The rendezvous address must end at the
founder through the relay, not at the relay itself.

```ts
import {
  encodeInvitationOffer,
  generateEciesKeyPair,
} from '@peerborne/core';

const founderKem = await generateEciesKeyPair();

const note = peerborne.doc('/notes/launch-plan');
await note.open();
// The initial invitation path intentionally shares the retained document
// history, so this choice must be explicit.
note.historyVisibility = 'full_history';
await note.setKemKeyPair(founderKem);

// Supply the relay's complete, peer-ID-qualified multiaddr from deployment
// configuration, connect, and advertise only a reservation the node reports.
const relayMultiaddr =
  '/dns4/relay.peerborne.io/tcp/443/wss/p2p/REPLACE_WITH_RELAY_PEER_ID';
await peerborne.connect([relayMultiaddr]);

async function waitForCircuitAddress(timeoutMs = 30_000): Promise<string> {
  const suffix = `/p2p-circuit/p2p/${peerborne.peerId}`;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const address = peerborne.libp2p
      .getMultiaddrs()
      .map((value) => value.toString())
      .find((value) =>
        value.includes('/p2p-circuit/') && value.endsWith(suffix),
      );
    if (address) return address;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error('Circuit Relay reservation was not observed');
}

const founderCircuitAddress = await waitForCircuitAddress();

const offer = await note.createInvitation({
  role: 'editor',
  rendezvous: [founderCircuitAddress],
  expiresInMs: 15 * 60 * 1000,
});

const offerBytes = encodeInvitationOffer(offer);
// Encode offerBytes as unpadded Base64url in a URL fragment or QR code.
```

The default lifetime is 15 minutes, the minimum is 60 seconds, and the maximum
is seven days. The founder must keep the same `Peerborne` process, open
document, signing identity, and KEM state alive until acceptance completes.
Each rendezvous attempt has a 30-second deadline; stale addresses are aborted
so the next signed address can be tried. The final founder catch-up stream has
the same deadline. Up to eight addresses are tried sequentially, and the
initial release does not expose caller-driven cancellation.

Offers use absolute wall-clock timestamps. Keep founder and recipient device
clocks reasonably synchronized: verifiers tolerate an issuer timestamp up to
60 seconds in the future, but there is no clock-skew grace after the signed
expiry.

## Recipient

Decode the fragment back to the exact bytes and accept it with the recipient's
own signing identity and a fresh or safely persisted P-256 KEM key pair:

```ts
const recipientKem = await generateEciesKeyPair();

const note = await peerborne.acceptInvitation(offerBytes, recipientKem);

await note.change((draft) => {
  draft.title = 'Shared launch plan';
}, 'Edit note');
```

`acceptInvitation()` verifies the offer signature and expiry, signs a
recipient/KEM-bound join request, verifies the founder's acceptance, opens the
sealed BeeKEM Welcome, authenticates the encrypted document bootstrap, checks
the resulting ACL, requires every advertised bootstrap change to be present,
subscribes, and performs an issuer-signed catch-up load with the same
advertised-change completeness check before returning. It never falls back to
creating a new document when any step fails.

An `editor` is added as both reader and writer. A `reader` can decrypt and
follow updates but cannot publish document changes.

## Trust and recovery boundaries

- The offer exposes its document ID, issuer identity, role, timestamps, and
  rendezvous addresses. URL fragments avoid ordinary HTTP request logs, but
  browser history, extensions, screenshots, and the person receiving the link
  can still reveal it.
- The signature proves that one signing key created the offer; it does not give
  that key a human identity. Verify the issuer fingerprint or deliver the link
  through an already authenticated channel when that distinction matters.
- Initial-release invitations require `historyVisibility = 'full_history'`.
  The recipient can receive the retained CRDT operation history, including
  operations for values later changed or deleted. `current_only` and
  `since_invited` filter epoch keys but are not safe historical-content
  confidentiality boundaries, so the invitation API rejects them.
- One active collaborator per document is enforced in the initial release.
  Add-side BeeKEM updates for larger groups are not implemented. The bounded
  invitation path supports the first collaborator and exact retries for that
  identity; inviting a replacement after revocation is not supported yet.
- Only the online founder process that created the document can issue an
  initial-release offer. Founder and recipient signing identities must be
  distinct, and a `reader` acceptance is rejected if its bootstrap grants
  writer access.
- Offers and replay protection are in memory. An inviter restart invalidates
  outstanding links. A lost response can be retried only from the same
  recipient `Peerborne` process, which reuses the exact signed request. The
  request-cache behavior is unit-tested; a dropped-response retry is not yet a
  browser acceptance test.
- Membership onboarding is not transactional. Once a valid signed request
  begins mutation, a later ACL publication, Welcome sealing, signing,
  encryption, stream, or expiry failure can leave partial or complete founder-
  side membership without returning a usable acceptance. Isolated coordinator
  and membership-repair suites cover the intended exact-retry repair path, but
  it is not yet proven as one end-to-end dropped-response scenario. A different
  request or process restart cannot use that path. Offer expiry remains strict,
  so work that completes after expiry cannot produce a usable acceptance.
- Peerborne does not persist signing or KEM key pairs. The application must
  protect and restore them without logging or exporting private material into
  an invitation.
- The bundled Automerge JSON CRDT, ACL, and keychain adapters plus SubtleCrypto
  declare the tested initial-release capacity profile:
  P-384 ECDSA with SHA-384 and AES-GCM. Other provider
  combinations fail before membership changes unless they deliberately attest
  the same bounds; a custom provider that does so is responsible for preserving
  every size and algorithm invariant in that profile.
- Each sealed Welcome and encrypted bootstrap is limited to 1 MiB. Before
  changing membership, Peerborne conservatively sizes one combined bootstrap
  projection containing the retained sync tree, complete keychain, latest
  snapshot, served tips, signature, founder-plus-one ACL growth, encryption
  framing, and a 128 KiB reserve. The sealed Welcome is projected separately,
  and both exact encrypted fields are checked again after construction. Large
  retained histories or snapshots need a different bootstrap or chunking
  design; there is no streaming fallback.
- Delivery, reconnect, revocation after restart, relay failover, and offline
  acceptance are not guaranteed. See [Limitations](../../concepts/limitations/)
  before using this flow for sensitive or durable data.
