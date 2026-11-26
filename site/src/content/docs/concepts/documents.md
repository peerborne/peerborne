---
title: Documents
description: Open a document, change typed state, subscribe to updates, and choose the right document boundary.
---

A Peerborne document is a local CRDT replica plus its encrypted change history,
keys, and reader/writer permissions. Use the Automerge adapter for JSON-like
object mutations or the Yjs adapter for shared maps, arrays, and text.

## The document lifecycle

To create a new local document with an initialized node and the Automerge adapter:

```ts
const document = peerborne.doc('/workspace');
await document.create();
document.subscribe('workspace-ui', (state) => render(state));
await document.change((draft) => {
  draft.title = 'Ready to ship';
});
// When the view is finished:
document.unsubscribe('workspace-ui');
await document.close();
```

`peerborne` and `render` above belong to your application. For complete setup,
use the [React workspace tutorial](../../getting-started/react-workspace/).
Use `open()` for an existing document with its required trust and key material;
see [Open existing documents](#open-existing-documents).
The direct change API returns a promise: handle rejection before telling the
user a save succeeded. A successful local operation is not a durable
acknowledgment from every other replica. A change that is committed locally
but whose frame could not be published, or reached no peer, still resolves
and reaches peers with the next change;
`document.subscribeDeliveryFailures(id, handler)` reports it, and
`document.deliveryFailure` holds the latest one until a later local frame
reaches a peer.

## Open existing documents

`create()` founds a new document without querying peers. It rejects a path that
the node already created or holds open, and an instance with restored or loaded
state, since creating the path again would found a different document with a
new key; open such a path instead. `open()` never creates one. It activates state without a network load only when the same document
instance already holds restored state from `restoreCheckpoint()`.
`peerborne.doc(path)` returns a new, unopened instance on each call, so the
React hook's and Redux thunk's default `'open'` mode always loads from peers.

A load from peers requires locally trusted configuration on the node:

- `resolveLoadSecurityCommitments(documentPath)` returns the current
  `LoadSecurityCommitments` tuple. Every load needs it, including the first,
  and every peer that serves the load needs it too and must return the same
  tuple.
- `resolveTrustedDocumentWriters(documentPath)` returns the trusted writer
  public keys when the instance has no writer ACL yet, which is always the case
  for a fresh instance.

When the load cannot proceed, `open()` rejects in one of two ways:

- If no connected peer offers the document-load protocol (a relay does not),
  it rejects with `No document state is available; use create() to authorize a
  new document`.
- Otherwise it resolves the trusted configuration before requesting any state.
  Without `resolveLoadSecurityCommitments` it rejects with
  `TrustedLoadSecurityCommitmentsError`; without
  `resolveTrustedDocumentWriters` on a fresh instance it rejects with an error
  naming that callback.

Both values must come from an independently trusted application source, never
from a peer's response:

```ts
import {
  defaultBootstrapConfig,
  defaultConfig,
  type PeerborneConfig,
} from '@peerborne/core';

const config: PeerborneConfig = {
  ...defaultConfig(defaultBootstrapConfig([relayMultiaddr])),
  resolveTrustedDocumentWriters: (path) => trustedWritersFor(path),
  resolveLoadSecurityCommitments: (path) => trustedCommitmentsFor(path),
};
await peerborne.initialize(config);
```

`trustedWritersFor` and `trustedCommitmentsFor` belong to your application. See
[Initial-load quorum](../security/#initial-load-quorum) for the tuple fields and
trust model.

To give a document to another identity without this configuration, the founder
creates it and issues an [invitation](../../cookbook/invitations/).
`acceptInvitation()` needs neither resolver and returns an open document. Use
that instance directly, for example through
`createDocumentStore(document, { manageLifecycle: false })`, instead of opening
the path again.

## Paths are names, not credentials

`/workspace` identifies the document. A second client using that path still
needs the appropriate document keys, a trusted identity/ACL, and a route to
peers. Sharing a path or signing identity alone does not deliver encryption
keys. See [Identities](../identities/).

## What concurrent edits mean

The CRDT adapter decides how updates merge. Independent list inserts can both
survive; competing assignments to one scalar have the adapter's conflict
semantics. Convergence means replicas agree after valid updates arrive. It
does not mean every overwritten value remains visible or that your business
rules are automatically preserved.

The landing animation is scripted. The tutorial's in-page exercise runs Yjs
merge and Web Crypto, but neither is evidence of live Peerborne partition/rejoin
behavior. See [CRDTs](../crdts/) for the adapter and evidence boundaries.

## Choose a bounded unit of collaboration

A loaded document materializes CRDT state and associated metadata in memory.
Avoid making one document your application's entire dataset. Group state that
needs the same permissions and editing lifecycle; use several documents when
those boundaries differ. There is no universal safe size or automatic total
memory cap. Follow the [persistence runbook](../../runbooks/offline-persistence/)
and measure realistic edits, deletes, reopen time, and memory use.

Continue with [Identities](../identities/), [Epoch Transitions](../epoch-transitions/),
or the [runtime architecture](../architecture/).
