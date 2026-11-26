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
group. The founding tab stores a checkpoint that records the new collaborator
before it releases the document key.

The founder's share panel shows the collaborator's fingerprint and a **Remove
collaborator** control. Removal rotates the note key: the removed browser keeps
what it already received but cannot read later edits, and the founder can then
create a new link. Use it when a recipient's tab closed after accepting but
before its note was saved. That browser then reports the interrupted acceptance,
and the old link cannot be claimed again.

## Edit together

Both editors' typing is merged. Unsaved text in one browser is rebased onto
edits that arrive from the other, and the cursor stays with the surrounding
characters. The status line shows whether the relay is connected, how many
peers are online and whether a local edit failed to reach them. Closing the tab
while **Saving…** is shown asks for confirmation; a pending edit is written
first when the page is hidden.

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
Clearing site data loses the identity and its local recovery material. The
application retains non-extractable signing, P-256 KEM and AES-GCM storage keys
in IndexedDB alongside encrypted checkpoints. Opening a saved note restores
its document and decryption state; the release gate exercises reload, process
relaunch, an acknowledged checkpoint after forced Chromium termination, and
same-epoch two-writer recovery after an owned relay outage. Outstanding
invitation and retry state remains in memory and is lost on founder restart.
There is no account/key backup or recovery after all local state is lost.

## Relay and privacy boundary

The two browsers normally depend on the configured Circuit Relay. Document
changes are signed and encrypted before publication, so the relay does not
receive note plaintext. It still sees connection and traffic metadata and can
delay, drop, censor, or partition traffic. The initial deployment is a
single-relay design. After a saved note is reopened, the application resumes
relay reservations and periodic history requests. The owned-relay release gate
verifies a bounded outage and repair with retained identities. Failover,
delivery acknowledgments, a general durable outbox, capacity and public-service
availability are not established.

## Run the source workspace

The eleven `@peerborne/*` libraries remain unpublished, so use the repository
workspace with Node.js 26.13.1 and Yarn 4.19.0:

```sh
npm install --global corepack@0.36.0
corepack enable
yarn install --immutable
yarn build
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
