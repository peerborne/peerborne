# `@peerborne/index`

Client-side indexing for Peerborne documents. Build local materialized indexes over your encrypted CRDT documents, with optional React query hooks for reactive UIs — no server-side indexing required.

## What you get

- **`IndexManager`** — define indexes over document fields, update incrementally on each change, query with field filters and sort clauses
- **Pluggable storage** — in-memory or IndexedDB-backed via `MemoryIndexStorage` / `IDBIndexStorage`
- **Blind-index primitives** — deterministic equality tokens for privacy-preserving search without revealing field values
- **Bloom-filter gossip** — peer discovery via Bloom filter exchange for candidate routing (deferred integration)
- **React hooks** — `useDefineIndexes` and `useIndexQuery` for reactive UI updates from indexed data

## Choose this package

Use this package to build local memory or IndexedDB indexes over documents already available to an application. It depends on `@peerborne/core` and `idb`. React is declared as a peer dependency for the optional query hooks.

## Entry points

- `@peerborne/index` — index definitions, storage, queries, document integration, blind indexes, and Bloom-filter primitives
- `@peerborne/index/react` — `useDefineIndexes` and `useIndexQuery`

## Start here

- [Search indexing guide](https://peerborne.io/cookbook/search-indexing/)
- [API reference](https://peerborne.io/reference/)
- [Current limitations](https://peerborne.io/concepts/limitations/)
- [Documentation index for coding agents](https://peerborne.io/llms.txt)
