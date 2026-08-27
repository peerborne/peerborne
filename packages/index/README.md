# `@peerborne/index`

Client-side indexing and distributed-search protocol primitives for Peerborne documents. Local indexes are rebuildable projections of decrypted, authorized snapshots; remote index data is never authoritative.

## What you get

- **`IndexManager`** — versioned schemas, named compound keys, nested queries, scan control, projections, deterministic cursors, explicit counts, and execution metadata
- **Physical storage** — sorted in-memory keys or real IndexedDB secondary indexes via `MemoryIndexStorage` / `IDBIndexStorage`
- **Blind-index primitives** — deterministic equality tokens for privacy-preserving search without revealing field values
- **Distributed-search primitives** — signed manifests, expiring replacement Bloom snapshots, replay-safe request/response codecs, and bounded candidate federation
- **React hooks** — `useDefineIndexes` and `useIndexQuery` for reactive UI updates from indexed data

## Choose this package

Use this package to build local indexes over documents already available to an application. V2 indexes are memory-only by default; IndexedDB requires the explicit `storageMode: 'cleartext-local'` opt-in because indexed values remain readable at rest. Custom storage implementations must declare `persistent: false` to use the memory default; an unknown persistence capability fails closed. It depends on `@peerborne/core` and `idb`. React is declared as a peer dependency for the optional legacy query hooks.

Distributed APIs currently provide the protocol, authorization, transport-adapter, and federation boundaries. Production libp2p handlers, collection search-key distribution, and a `PeerborneDocument` resolver are not wired end to end. A remote peer can nominate a path only: the requester must load and authorize the document through the normal secure path and re-evaluate the complete predicate locally. Distributed candidate requests cannot opt into full scans or exact remote counts.

## V2 local query

```ts
const manager = new IndexManager(new MemoryIndexStorage(), (document) => document);
await manager.defineIndex({
  version: 2,
  name: 'articles',
  collectionPrefix: '/articles/',
  fields: [
    { path: 'author', type: 'string', required: true },
    { path: 'createdOn', type: 'date', required: true },
  ],
  indexes: [{ name: 'by_author_date', fields: ['author', 'createdOn'] }],
});

const page = await manager.query({
  version: 2,
  indexName: 'articles',
  where: { kind: 'field', path: 'author', operator: 'eq', value: 'Alice' },
  orderBy: [{ path: 'createdOn', direction: 'asc' }],
  first: 20,
  select: ['author', 'createdOn'],
  count: 'none',
  consistency: 'indexed',
});
```

Queries that cannot use a physical key fail unless `allowScan: true`. The returned execution metadata reports the chosen keys, scan/sort behavior, and rows visited.
Every field in a physical key must be marked `required`; optional fields remain available to projections and explicit full scans.

## Entry points

- `@peerborne/index` — local indexing, distributed-search primitives, document integration, blind indexes, and Bloom filters
- `@peerborne/index/react` — `useDefineIndexes` and `useIndexQuery`

## Start here

- [Search indexing guide](https://peerborne.io/cookbook/search-indexing/)
- [API reference](https://peerborne.io/reference/)
- [Current limitations](https://peerborne.io/concepts/limitations/)
- [Local and distributed indexing design](../../docs/indexing-design.md)
- [Documentation index for coding agents](https://peerborne.io/llms.txt)
