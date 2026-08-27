---
title: Try Peerborne Note
description: Use the bounded initial-release note-sharing demo and understand its identity, invitation, relay, and recovery limits.
---

[Peerborne Note](https://try.peerborne.io/) is the initial-release demo for the
real Peerborne and Automerge path. It creates an encrypted note on the founding
browser before connecting to the configured relay, then lets that browser invite
one online collaborator as a reader or editor.

Peerborne Note is early-stage and not production-ready. Do not put secrets,
irreplaceable work, or other sensitive or durable data into it.

## Share a note

1. Open [try.peerborne.io](https://try.peerborne.io/) in the founding browser.
2. Create a note and make any initial edits. An edit being **applied locally**
   is not an acknowledgment that another browser received it.
3. Choose read-only or editing access and create an invitation.
4. Send the link to one intended collaborator over a confidential,
   authenticated channel. Do not post it publicly: the first eligible claimant
   wins the single collaborator slot.
5. Keep the founding tab open and online. The recipient opens the link, reviews
   the requested role, and explicitly accepts it before onboarding begins.
6. Keep both tabs online while collaborating. A displayed peer connection is
   evidence of a connection, not a durable-delivery guarantee.

The invitation expires after 15 minutes. It cannot be accepted offline, and
restarting the founder invalidates its in-memory offer and retry state. The
initial release supports one founder and one active collaborator, not a larger
group or a replacement invitation after revocation.

## What the link contains

The URL fragment contains a bounded, canonical Base64url-encoded signed offer.
It names the document, role, expiry, inviter identity, and circuit rendezvous;
it does not contain a plaintext document key. The application removes the
fragment from the address bar and current history entry before showing an
acceptance screen, rejects malformed or oversized encodings, and rejects
rendezvous addresses outside its configured relay.

Treat the link as a short-lived bearer invitation. URL fragments are not sent
in the normal HTTP request, but they can still leak through copying, messaging,
screenshots, browser extensions, or a compromised recipient device. Offer
metadata is untrusted until signature and binding checks complete during
explicit acceptance.

Successful acceptance sends a recipient-encrypted bootstrap and grants access
to the retained note history. The current history modes do not safely redact
older CRDT operations, including operations for later-deleted text, so the demo
uses full-history invitations.

## Identity and recovery boundary

The application creates one ECDSA P-384 signing identity and stores its
non-extractable private key in IndexedDB. It validates the key algorithm, usage,
and key-pair match when restoring it. A same-profile Web Lock prevents two tabs
from operating the identity concurrently where that browser API is available.

This is a local browser identity, not an account. Peerborne Note has no login,
key backup, cross-device identity transfer, or collaborator identity directory.
Clearing site data loses the identity. The P-256 invitation KEM keys and
outstanding invitation state remain in memory, and complete note recovery after
a refresh or browser restart is not verified. Persisting the signing key alone
does not preserve the document or its decryption state.

## Relay and privacy boundary

The two browsers normally depend on the configured Circuit Relay. Document
changes are signed and encrypted before publication, so the relay does not
receive note plaintext. It still sees connection and traffic metadata and can
delay, drop, censor, or partition traffic. The initial deployment is a
single-relay design; failover, automatic reconnect, delivery acknowledgments,
durable outbox, capacity, and production availability are not established.

## Run the source workspace

The six `@peerborne/*` libraries remain unpublished, so use the repository
workspace with Node.js 22.19.0 and Yarn 4.5.0:

```sh
corepack enable
yarn install --immutable
yarn workspace @peerborne/peerborne-note test
yarn workspace @peerborne/peerborne-note build
yarn test:e2e:peerborne-note
```

For a local relay, pass its exact secure or local-development multiaddr at build
or startup time:

```sh
VITE_PEERBORNE_RELAY_MULTIADDR='/dns4/relay.example.com/tcp/443/wss/p2p/12D3KooW...' \
  yarn workspace @peerborne/peerborne-note start
```

Hosted builds use the fail-closed deployment target:

```sh
VITE_PEERBORNE_RELAY_MULTIADDR='/dns4/relay.example.com/tcp/443/wss/p2p/12D3KooW...' \
  yarn workspace @peerborne/peerborne-note build:deployment
```

An HTTPS page requires a `wss` relay. The deployment build renders the emitted
`_headers` CSP to allow only the WebSocket origin from that validated relay
multiaddr.

The source smoke tests cover bounded application behavior without treating a
public deployment as verified. A live deployment check must separately exercise
two browser identities, the published WSS multiaddr, explicit acceptance, and
fresh edits in both directions.

Read the [invitation protocol boundaries](../invitations/),
[security model](../../concepts/security/), [networking model](../../concepts/networking/),
and [current limitations](../../concepts/limitations/) before adapting the demo.
