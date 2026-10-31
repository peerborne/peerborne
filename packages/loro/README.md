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

This package supplies only the document provider. It uses Loro binary updates
and full-history snapshots. The browser example composes it with the existing
`YjsJSONSerializer`, `YjsACLProvider`, and `YjsKeychainProvider`: application state
uses Loro, while the ACL and keychain retain their existing Yjs formats. No
existing wire, ACL, or keychain format is migrated.

Use a new document path when selecting another engine. Loro updates do not
convert Yjs or Automerge documents. Full-history snapshots retain Loro's
application operation history; they do not provide content-history redaction,
including when an application selects current-only key delivery.

Focused tests cover concurrent edits, out-of-order delivery, replay, snapshot
merging, and malformed payloads. The browser example exercises a local encrypted
document mutation. These do not establish live multi-peer Loro convergence,
hostile-peer security, restart recovery, or long-running performance.

- [Browser example](../../examples/integrations/README.md)
- [Loro upstream documentation](https://www.loro.dev/docs/tutorial/get_started)
- [Integration status](https://peerborne.io/reference/integration-status/)

MIT licensed.
