# `@peerborne/tanstack-db`

Experimental TanStack DB collection options over a Peerborne document store.
Alpha source workspace; unpublished. The TanStack DB peer range is
`^1.0.0-rc.1.5`. Repository tests run against `1.0.0-rc.1.5`; TanStack DB is a
release candidate, so a later release can change the collection contract.

`peerborneCollectionOptions` takes an `id`, shared `store`, row `getKey`, document
`select`, and `mutate` function. Pass its result to TanStack DB's
`createCollection`. `select` must return plain structured-cloneable rows with
unique, stable keys. `mutate` translates insert, update, and delete operations
into a document change callback. Apply field changes to CRDT types rather than
replacing entire documents or collections.

Construction performs no I/O. Preload/use the collection in its owning runtime.
The adapter subscribes before opening the document, replaces the complete row
snapshot on each notification, and releases its ownership during cleanup.
Writes await `store.change`; authorization failures propagate to TanStack DB's
transaction rollback. Settlement is local API completion, not a peer delivery
or durability acknowledgement. When the store reports an error or a `retired`
document, the adapter calls `fail()` and stops projecting, so the collection
keeps its last rows and never shows an edit that a retired Yjs or Loro
document discarded. A mutation made before any query or `preload()` started the
collection first preloads it, which opens the document.

This prototype does not implement query-driven network sync, incremental row
diffing, relational persistence, schema migration, or distributed transactions.
Large documents incur a full projection and copy on each notification.

See the [runnable collection](https://github.com/peerborne/peerborne/blob/main/examples/integrations/src/collection.ts),
[upstream adapter contract](https://tanstack.com/db/latest/docs/guides/collection-options-creator),
and [integration status](https://peerborne.io/reference/integration-status/).
MIT licensed; not production-ready.
