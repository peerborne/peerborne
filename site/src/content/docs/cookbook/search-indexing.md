---
title: Searching encrypted documents
description: Use tested local index primitives and assess incomplete blind-index and Bloom-gossip integration.
---

## Local materialized indexes

**Status: Runnable from source for the local manager APIs.** `IndexManager`, memory/IndexedDB storage, and field extraction have focused tests. React query bindings are exported, but their effects and cleanup are not render-tested; the current React tests exercise backing manager primitives. These APIs index decrypted documents already available to the local application; they are not a network crawler.

Packages are unpublished. Use the repository workspace after following the [quick start](../../getting-started/quick-start/).

Define the index, wait for storage readiness, update it, and only then query:

```ts
import * as Y from 'yjs';
import {
  IndexDefinition,
  IndexManager,
  MemoryIndexStorage,
} from '@peerborne/index';

const definition: IndexDefinition = {
  name: 'articles',
  collectionPrefix: '/articles/',
  fields: [
    { path: 'title', type: 'string' },
    { path: 'author', type: 'string' },
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
  indexName: 'articles',
  filters: [{ path: 'author', operator: 'eq', value: 'Alice' }],
});
```

`PeerborneIndexIntegration.trackDocument(docRef)` subscribes and starts indexing, but its initial update is fire-and-forget. If the first query must include the document, call and await `manager.updateIndex(docRef.documentPath, docRef.document)` before querying. Untrack or dispose subscriptions during teardown.

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

## Bloom gossip

**Status: Deferred/incomplete integration.** `BloomFilterGossip` returns only candidate peer IDs and can produce false positives. Its publish, subscribe, and unsubscribe callbacks must be wired by the application to actual pubsub; it does not fetch documents or execute a remote query.

Filters use grow-only OR merge state. There is no deletion, reset, or rebuild operation in the gossip API, so removed terms continue to match and repeated state accumulates. Create a new versioned filter/topic in application code if bounded rebuild semantics are required. Never gossip plaintext terms when the privacy design requires blind tokens.

## Verify

```sh
yarn workspace @peerborne/index test
```

Benchmark sources exist, but the current benchmark runner emits ESM and then marks its output directory as CommonJS, so `yarn workspace @peerborne/index benchmark` is not a working verification command at this revision. Even after that runner is fixed, benchmark results are informational and have no pass/fail performance budget. Distributed search remains incomplete; see [Limitations](../../concepts/limitations/) and [Designing Yjs schemas](../yjs-schema-design/).
