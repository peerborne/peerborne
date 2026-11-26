# `@peerborne/loro`

Experimental Loro document provider for Peerborne. Alpha source workspace;
unpublished and not production-ready.

```ts
import { LoroProvider } from '@peerborne/loro';

const provider = new LoroProvider();
const document = provider.newDocument();
const [, update] = provider.localChange(document, 'Set title', (doc) => {
  doc.getMap('data').set('title', 'Hello');
});
provider.remoteChange(provider.newDocument(), update);
```

A Loro document cannot be shared with another identity: invitations require
the Automerge provider profile, so only the founder's identity can open it.

This package supplies only the document provider. It uses Loro binary updates
and full-history snapshots. The browser example composes it with the existing
`YjsJSONSerializer`, `YjsACLProvider`, and `YjsKeychainProvider`: application state
uses Loro, while the ACL and keychain retain their existing Yjs formats. No
existing wire, ACL, or keychain format is migrated.

Use a new document path when selecting another engine. Loro updates do not
convert Yjs or Automerge documents. Full-history snapshots retain Loro's
application operation history; they do not provide content-history redaction,
including when an application selects current-only key delivery.

Remote payloads are validated before they reach a document, because Loro's
xxHash32 checksum is not a MAC and an authorized writer's client can alter
update bytes. `remoteChange` accepts only update blobs and `applySnapshot` only
full snapshots. A snapshot contributes its operation history; its encoded state
is never loaded. `getHistory` exports that history as one update, so a
checkpoint restore replays it through the same validation.

An update whose dependencies are missing waits outside the document, and
`hasIntegrated` reports it as not yet integrated, so Peerborne does not record
it as applied and checkpoints omit it. Once it can integrate, it is imported
into a fork together with the waiting updates it releases. The batch is rejected
if an operation writes to an unknown container type, creates a container whose
ID is not its own, writes to a container or deletes elements outside its causal
past, or moves a tree node that does not exist there. Each of these rules
depends only on the change and its causal past, so every replica reaches the
same verdict in any delivery order. As a defence in depth, the batch is also
rejected if any root container reads differently after a snapshot round trip.
Only a batch that passes reaches the document; a rejected one leaves it
unchanged. When a batch fails but the update that released it passes alone, the
waiting updates are validated one at a time, and the ones that fail, with those
that depend on them, are discarded. `hasDiscarded` reports them, so Peerborne
stops waiting for them and passes a later delivery to `remoteChange` again.

A document holds at most 4,096 waiting updates and evicts the oldest update of
the Loro peer holding the most. Writers choose their own Loro peer IDs, so a
writer can still evict other writers' waiting updates; `hasDiscarded` then
reports them, and Peerborne's catch-up delivers them again. An update that once
trapped Loro during validation is rejected without validating it again, because
Loro cannot free the fork it trapped in. After 16 such updates, the document
rejects every further remote update until it is reopened.

Validation reads the whole document, so every integrated remote update costs
O(document). Duplicate and waiting deliveries cost microseconds. The rules cover
the malformation classes that byte-mutation fuzzing and review found; they do
not prove that every operation Loro accepts is harmless. The round trip reads
the visible state, which concurrent changes can alter, so a malformation that
only it catches could be judged differently by replicas that received changes in
different orders; none of the fuzzed classes relies on it alone. Rich-text marks
are not compared, an update that reuses another replica's peer ID is not
detected, and `toJSON()` shows one of two root containers that share a name
depending on arrival order.

Focused tests cover concurrent edits, out-of-order delivery, replay, snapshot
merging, malformed and crafted payloads, and a `PeerborneDocument` fixture where
replicas reject crafted changes and a poisoned snapshot from an authorized
writer. The browser example exercises a local encrypted document mutation.
These do not establish live multi-peer Loro convergence, browser restart
recovery, or long-running performance.

- [Browser example](https://github.com/peerborne/peerborne/blob/main/examples/integrations/README.md)
- [Loro upstream documentation](https://www.loro.dev/docs/tutorial/get_started)
- [Integration status](https://peerborne.io/reference/integration-status/)

MIT licensed.
