---
title: Searching encrypted documents
description: Build versioned local indexes and understand the trust boundary for distributed candidate search.
---

![Two-lane Peerborne search architecture: verified local queries run over authorized, decrypted documents, while distributed peers return untrusted candidate references that must pass the requester's normal secure document load and complete local predicate recheck.](../../../assets/diagrams/search-architecture.svg)

**Evidence boundary.** The local lane is implemented over documents already loaded, decrypted, and authorized locally by the requesting peer. The distributed lane represents protocol and orchestration foundations, not an end-to-end network feature: production libp2p handlers, membership and key distribution, and an `AuthorizedDocumentResolver` are not integrated into that path; multi-peer acceptance is not tested, and no global completeness or exact-count guarantee is claimed.

## Local materialized indexes

**Status: Runnable from source.** V2 local schemas, planners, memory/IndexedDB physical keys, cursor pagination, malformed-value handling, and lifecycle integration have focused tests. React bindings continue to use the legacy query API. These APIs index decrypted documents already available to the local application; they are not a network crawler.

Packages are unpublished. Use the repository workspace after following the [quick start](../../getting-started/quick-start/).

Define named physical keys, wait for storage readiness, update the projection, and query with the serializable v2 AST:

```ts
import * as Y from 'yjs';
import {
  IndexDefinition,
  IndexManager,
  MemoryIndexStorage,
} from '@peerborne/index';

const definition: IndexDefinition = {
  version: 2,
  name: 'articles',
  collectionPrefix: '/articles/',
  fields: [
    { path: 'title', type: 'string', required: true },
    { path: 'author', type: 'string', required: true },
  ],
  indexes: [
    { name: 'by_author_title', fields: ['author', 'title'] },
  ],
};
const manager = new IndexManager<Y.Doc>(
  new MemoryIndexStorage(),
  (doc) => doc.getMap('meta').toJSON(),
);
const article = new Y.Doc();
article.getMap('meta').set('title', 'Local-first search');
article.getMap('meta').set('author', 'Alice');

await manager.defineIndex(definition);
await manager.updateIndex('/articles/local-first', article);
const result = await manager.query({
  version: 2,
  indexName: 'articles',
  where: { kind: 'field', path: 'author', operator: 'eq', value: 'Alice' },
  orderBy: [{ path: 'title', direction: 'asc' }],
  first: 20,
  select: ['title', 'author'],
  count: 'none',
  consistency: 'indexed',
});
```

`PeerborneIndexIntegration.trackDocument(docRef)` returns a readiness promise; the first call waits for initial indexing, and a repeated call for the same path waits for work already queued for that document. Await it before the first query. `untrackDocument()` returns the removal promise, and `dispose()` waits for queued index work. Untrack or dispose subscriptions during teardown.

V2 rejects unindexed scans by default. Set `allowScan: true` only when a full local projection scan is an intentional cost. Results include chosen physical keys, scan and sort strategy, rows visited, schema generation, storage mode, cursor state, and explicit count semantics. The legacy `QueryOptions` interface remains available, but it does not provide nested `and`/`or`, cursor binding, projections, scan control, indexed-consistency waiting, or execution metadata.

Every field in a physical key must be `required`. Optional fields remain materialized and can be projected or tested during an explicitly allowed full scan, but are not auto-indexed. This prevents a compound index from silently omitting documents whose trailing key field is absent.

V2 defaults to memory storage. To use `IDBIndexStorage`, set `storageMode: 'cleartext-local'` explicitly: field values and ordering keys are readable at rest even though the source CRDT history is encrypted. Changing the canonical schema or generation clears incompatible persisted rows, but `defineIndex()` cannot repopulate them because it does not own the source documents. Re-track the collection or call `rebuildIndex()` with its current documents before querying. A same-name upgrade from a legacy store backfills valid rows under the declared collection prefix; malformed and wrong-prefix rows are removed. Malformed documents default to exclusion with bounded diagnostics that never include the offending value.

### Gate React queries after definition readiness

Do not call the query hook in the same component before asynchronous definitions are ready. Gate a child component instead:

```tsx
function SearchRoot({ manager }: { manager: IndexManager<Y.Doc> }) {
  const ready = useDefineIndexes(manager, [definition]);
  return ready ? <ReadySearch manager={manager} /> : <p>Preparing index…</p>;
}

function ReadySearch({ manager }: { manager: IndexManager<Y.Doc> }) {
  const result = useIndexQuery(manager, {
    indexName: 'articles',
    filters: [{ path: 'author', operator: 'eq', value: 'Alice' }],
  });
  return <p>{result.totalCount} result(s)</p>;
}
```

`useDefineIndexes` removes its indexes on cleanup, which clears stored entries. Treat the local index as a rebuildable cache, not source data.

## Blind-index primitives

**Status: Illustrative pattern.** `SubtleBlindIndexProvider` and `BlindIndexQuery` implement tested equality-token primitives. The normal document change API does not automatically derive, attach, distribute, rotate, or query tokens.

```ts
import {
  BlindIndexQuery,
  SubtleBlindIndexProvider,
} from '@peerborne/index';
import type { BlindIndexEntry } from '@peerborne/index';

const provider = new SubtleBlindIndexProvider();
const rawKeyMaterial = crypto.getRandomValues(new Uint8Array(32));
const fieldKey = await provider.deriveFieldKeyFromRaw(
  rawKeyMaterial,
  'author',
);
const token = await provider.computeToken(fieldKey, 'Alice');
const entries: BlindIndexEntry[] = [
  {
    documentPath: '/articles/local-first',
    blindIndexTokens: { author: token },
  },
];
const query = new BlindIndexQuery(provider);
const matches = await query.exactMatch(fieldKey, 'author', 'Alice', entries);
```

Applications must define authenticated token transport and key distribution. Deterministic equality tokens leak equality/frequency information and permit confirmation attacks to holders of the field key.

## Distributed candidate search

**Status: Protocol and orchestration primitives implemented; production networking remains incomplete.** The package includes signed collection manifests, signed expiring replacement Bloom advertisements, bounded signed direct-query codecs, replay guards, a transport adapter, and a federation coordinator. Production libp2p handlers, collection search-membership/key distribution, blind-token publication, and an authorized `PeerborneDocument` resolver are not yet wired.

A remote response is an untrusted candidate list, even when signed. The requester must load each nominated document through normal signature, ACL, history, and decryption checks, extract only declared fields, and re-evaluate the complete predicate. Remote ordering, counts, continuations, and exhaustion claims are advisory. Distributed coverage stays partial and counts are verified lower bounds because a malicious or offline peer can omit matches.
Authorized candidate resolution is concurrency-, per-document timeout-, and total-budget-bounded and receives an abort signal; adapters should propagate that signal through document loading.

`PlaintextDistributedQueryEncoder` reveals the AST to the recipient. `BlindEqualityRequestEncoder` sends caller-derived opaque terms but supports equality-style routing only and still leaks equality/frequency information to search-key holders. No encoder is selected implicitly.

Plaintext candidate requests strip the global cursor/projection, request no remote count, and cannot set `allowScan: true`; the responder must still impose its own deadline, stream, byte, and CPU budgets. Exact federated counts are computed only as verified lower bounds after candidate documents pass local authorization.

The older `BloomFilterGossip` grow-only OR merge remains a compatibility primitive, not an authoritative distributed index: it cannot delete terms, and a saturated or stale update persists. The new routing registry instead authenticates source peers, bounds fill/rate/size, enforces monotonic sequences, expires snapshots, and replaces rather than merges state. Neither representation proves that a peer has a matching document.

See the complete [local and distributed indexing design](https://github.com/Peerborne/peerborne/blob/main/docs/indexing-design.md) for planner rules, performance semantics, threat analysis, and the remaining integration sequence.

## Verify

```sh
yarn workspace @peerborne/index test
```

The benchmark runner executes as ESM, and its index-query suite exercises v2 physical keys. Use `--max-documents 100` for a bounded smoke run. Results remain informational and have no pass/fail performance budget. Distributed network integration remains incomplete; see [Limitations](../../concepts/limitations/) and [Designing Yjs schemas](../yjs-schema-design/).
