# Local and distributed indexing design

This document records the indexing architecture, trust boundaries, performance
semantics, and the remaining integration sequence. It distinguishes implemented
library primitives from network behavior that still needs an end-to-end path.

## Status

Implemented in `@peerborne/index`:

- versioned local index definitions and a data-only v2 query AST;
- named compound physical indexes in memory and IndexedDB;
- equality, membership, range, prefix, bounded `OR` union, compatible index
  ordering, projections, deterministic cursor pagination, and explicit count
  semantics;
- scan rejection unless `allowScan` is set;
- serialized per-document updates, `flush()`/indexed consistency, generation
  identity, persisted-schema invalidation, and legacy IndexedDB row backfill;
- memory-only-by-default v2 projections, with explicit opt-in for persistent
  cleartext projections;
- a federation coordinator that treats every remote response as an untrusted
  candidate and admits it only after authorized document loading and a complete
  local predicate recheck;
- signed and monotonic collection index manifests, signed expiring routing
  snapshots, request/response codecs, replay guards, candidate budgets, and a
  transport-agnostic direct-peer candidate source.

Not yet implemented end to end:

- registration of the search advertisement and direct-query handlers on a
  production libp2p node;
- a collection membership/key-distribution service that implements
  `DistributedSearchAuthorizer` and rotates a dedicated search key epoch;
- a production `AuthorizedDocumentResolver` adapter over `PeerborneDocument`;
- automatic blind-token generation from index updates and advertisement
  publication;
- multi-browser, hostile-peer, partition/rejoin, and restart acceptance tests.

The distributed types are therefore usable protocol and orchestration
primitives, not a claim that Peerborne currently provides complete network
search.

## Non-negotiable invariants

1. The encrypted CRDT history remains source data. Every index is a rebuildable
   materialized projection.
2. Local index rows are derived only from document state the local application
   has already decrypted and authorized.
3. A remote peer can nominate a document path, but cannot make a document a
   query result. The requester must load the document through the normal
   signature, ACL, decryption, and history-validation path, then evaluate the
   complete predicate locally.
4. A signature provides attribution and replay protection, not truth. Signed
   Bloom filters and candidate lists may still lie, omit, reorder, equivocate,
   or waste resources.
5. Distributed completeness and exact global counts are not claimed in an open
   Byzantine network. A malicious peer can omit a document and Sybil identities
   can distort coverage.
6. Search keys are collection-scoped, domain-separated secrets. They must not
   be signing keys, libp2p keys, or raw document encryption keys.
7. Cleartext local persistence and distributed query disclosure require
   explicit choices; neither is an invisible consequence of defining a v2
   index.

## Local architecture

```
authorized decrypted CRDT snapshot
              |
              v
      IndexManager validation
       |                  |
       v                  v
 named compound keys   stored indexed fields
       |                  |
       +------ planner ----+
                 |
                 v
       candidate range/union
                 |
          full predicate recheck
                 |
     deterministic sort/cursor/project
```

An `IndexDefinition` binds a name, collection path prefix, schema generation,
field types, invalid-value policy, local storage policy, and ordered physical
keys. The canonical schema hash covers query/ingestion semantics but excludes
the local storage policy, so memory and explicitly persistent peers remain
compatible. Storage policy is still enforced locally and reported in execution
metadata. A changed hash or generation invalidates persisted rows instead of
silently reading old data under new semantics.

Physical keys currently require every participating field to be marked
`required`. Optional fields remain materialized for projection and explicit
full-scan predicates, but are not auto-indexed; this avoids silently dropping
documents whose compound-key suffix is absent.

Version 2 defaults to `storageMode: 'memory'`. IndexedDB requires
`storageMode: 'cleartext-local'`, because indexed field values and ordering keys
are readable at rest even though the underlying documents are encrypted.
Custom storage backends must explicitly report `persistent: false` to use the
memory default; an unspecified persistence capability fails closed unless the
definition opts into `cleartext-local`.
Applications that need encrypted-at-rest local search require a separate
storage design; the blind-index helpers do not encrypt the current local
materialized stores.

Malformed v2 documents default to `invalidValuePolicy: 'skip-document'`. A bad
required/type/size value removes any stale row and records only bounded metadata
(index, document path, field, reason). `reject` is available for applications
that prefer fail-closed ingestion. Offending values are never included in
diagnostics or error messages.

### Planner rules

For an ordered key such as `['author', 'createdOn']`, the planner can use:

- `eq` or `in` on leading fields;
- at most one following range (`gt`, `gte`, `lt`, `lte`) or `prefix` field;
- an ascending order that exactly consumes the remaining key fields after the
  equality prefix;
- a top-level `OR` when every branch has an indexable plan.

`neq`, `contains`, nested disjunctions that cannot be split, and predicates with
no usable leading key require a full scan. V2 rejects that plan unless
`allowScan: true`. An ordering-only traversal is also a full scan until the
executors support early termination. Every plan, including an exact physical
lookup, rechecks the entire predicate against the stored local projection.

### Query semantics added beyond the legacy API

The legacy `QueryOptions` interface remains available. The v2 `QueryAst` adds:

- nested `and`/`or` expressions instead of an implicit conjunction only;
- opaque schema/generation/query-bound cursors instead of offset-only pagination;
- field projection with `select`;
- `count: 'none' | 'exact'` so callers do not accidentally pay for or claim a
  count they did not compute;
- `allowScan` as an explicit performance decision;
- `consistency: 'indexed'`, which waits for queued index mutations;
- execution metadata: physical keys, scan/sort strategy, residual predicate,
  rows visited, schema hash, generation, and storage mode;
- explicit local coverage metadata.

The index changes what can be planned efficiently; it does not add full-text,
stemming, ranking, arbitrary joins, or server-authoritative global search.

### Current performance semantics

- Memory physical keys are sorted arrays. Lookup begins with binary search, but
  an incremental insert/delete can shift `O(N)` entries per key in the worst
  case.
- IndexedDB uses real compound secondary indexes over normalized key arrays.
  A schema upgrade/backfill visits all stored rows.
- An equality/range query visits the selected key range rather than every row.
  `rowsVisited` reports candidates read from physical storage; union lookups may
  count the same row more than once before deduplication.
- A compatible ascending order can be returned in index order. Reverse or
  incompatible/mixed-direction order currently falls back to an in-memory sort.
- `first` bounds returned results, but the current executors may still exhaust
  the selected range before truncating. It is not yet an early-termination
  guarantee.
- `count: 'exact'` exhausts all candidates. Omit it when a count is unnecessary.
- Cursor pagination is deterministic for a fixed local generation and query,
  using the document path as the final tie-breaker. Concurrent document changes
  can still move items between pages; cursors are not snapshot transactions.
- `consistency: 'indexed'` waits for already queued local mutations. It does not
  create network consistency or wait for untracked documents.

The benchmark runner now emits and executes ESM correctly. The index query
suite uses v2 physical keys, and `--max-documents` supports bounded smoke runs.
The suite is informational: no CI regression budgets exist yet.

## Distributed architecture

```
signed collection manifest (schema hash + generation + search-key epoch)
                                |
             +------------------+------------------+
             |                                     |
     signed expiring Bloom snapshot         signed direct request
       (blind routing tokens only)       (blind tokens or explicit AST)
             |                                     |
             +--------- candidate peer/path claims-+
                                |
                    normal secure document load
                 ACL + signature + decrypt + history
                                |
                       complete local recheck
                                |
                  deterministic bounded page merge
```

### Collection control plane

`DistributedIndexManifestV1` binds the collection ID, local schema hash,
generation, dedicated search-key epoch, discovery mode, filter parameters,
advertisement TTL, and response budget. A collection manager signs it.
`DistributedManifestRegistry` rejects non-manager signatures, expiration, and
non-monotonic sequence numbers.

Collection search membership is separate from each document ACL. An
implementation must decide who may manage the manifest, advertise holdings, and
issue queries. Receiving a collection search key must never imply read access to
an individual document; the final document ACL remains authoritative.

### Discovery

Honest peers derive field/compound equality tokens from a dedicated collection
search key, add only those opaque tokens to a Bloom filter, sign the snapshot,
and publish it on `searchIndexAdvertiseV1`. The receiver validates:

- exact protocol shape and byte bounds;
- manifest hash, schema generation, and key epoch;
- application identity authorization and signature;
- transport source PeerId binding;
- timestamp/TTL, rate, peer-count, and fill-ratio bounds;
- a strictly increasing per-peer sequence.

Accepted filters replace the previous peer snapshot. They are never OR-merged
across time. The legacy `BloomFilterGossip` grow-only merge is suitable only as
an approximate compatibility primitive: it cannot remove terms and an
all-ones/stale update permanently poisons routing. It must not be treated as an
authoritative distributed index.

Bloom filters reveal approximate holdings, fill, update timing, and equality
patterns to anyone who has or observes the relevant tokens. They have honest
false positives and a malicious peer can manufacture both false positives and
false negatives. A fill-ratio cap limits trivial saturation but cannot make a
claim truthful.

### Direct search

`searchQueryV1` is a bounded, signed, direct request/response protocol. Requests
are bound to the manifest, key epoch, request and recipient PeerIds, random
request ID, and short deadline. Responses are bound to the request hash and may
contain only bounded document references, never authoritative snapshots.
The wire subset rejects remote full-scan opt-ins and exact-count requests;
responders must also enforce deadline, stream, byte, and CPU budgets.

Two encoders make disclosure explicit:

- `PlaintextDistributedQueryEncoder` sends a bounded candidate-query AST after
  stripping the global cursor, projection, exact count, and scan opt-in. A
  confidential libp2p Noise stream prevents relay observation, but the
  authorized recipient learns the predicate and values.
- `BlindEqualityRequestEncoder` sends application-derived opaque terms. It
  supports only the equality shapes the application can tokenize and still
  leaks equality/frequency information to search-key holders.

The replay guard must run before executing a verified request. Transport-level
connection, stream, and byte rate limits are still required; signature checks
alone are a CPU denial-of-service surface.

### Federation and result trust

`FederatedSearchCoordinator` contacts a bounded number of candidate sources,
gives each source request a deadline and abort signal, interleaves their
references so one fast peer cannot monopolize the global budget, and resolves
candidates with bounded concurrency, per-document deadlines, a total
resolution budget, and separate abort signals. The
`AuthorizedDocumentResolver` contract requires the normal Peerborne load path.
The coordinator then extracts the declared fields, rejects malformed values,
rechecks the full AST, applies its own cursor, deduplicates, sorts, and projects.

Remote sorting, counts, continuations, revision hints, and `exhausted` flags are
advisory. Federated exact counts are reported only as a verified lower bound.
Coverage remains partial whenever remote sources participate because omission
is possible even if every peer says it is exhausted.

### Malicious-actor outcomes

| Actor behavior | Result |
| --- | --- |
| Forge another member or transport peer | Signature/authorization or PeerId binding rejects it |
| Replay an old manifest, advertisement, or request | Monotonic sequence or request replay cache rejects it |
| Advertise an all-ones filter | Fill-ratio bound rejects the trivial form |
| Return arbitrary or out-of-collection paths | Path/budget checks reject them |
| Claim a non-matching document | Authorized load plus local predicate recheck rejects it |
| Return forged document state | Normal document signature/ACL/decryption/history checks must reject it |
| Omit matching documents or stay offline | Coverage is partial; completeness cannot be claimed |
| Create many identities | Local bounds limit work, but the design is not Sybil-resistant |
| Observe/use blind tokens | Equality/frequency and confirmation leakage remains |
| Flood valid signed requests | Protocol bounds help; transport quotas and peer penalties are still required |

## Remaining implementation sequence

1. Build a collection membership document with manager/advertiser/query roles,
   monotonic manifest updates, and a domain-separated search-root key delivered
   only to current collection search members.
2. Rotate `keyEpoch` and rebuild advertisements on membership/schema changes;
   retain a bounded overlap window only when explicitly required for rollout.
3. Wire signed advertisement publication/receipt to GossipSub and direct search
   to bounded libp2p stream handlers using the exported historical protocol IDs.
4. Implement blind-token materialization alongside local index updates without
   persisting raw search keys or logging values/tokens.
5. Implement `AuthorizedDocumentResolver` over the existing document load path,
   including current ACL and quorum policy, then feed only verified snapshots to
   federation.
6. Add per-peer rate/byte/stream budgets, backoff and reputation as availability
   hints, never as authorization.
7. Add deterministic multi-peer tests for honest search, false positives,
   lies, omission, replay, equivocation, schema/key rotation, revocation,
   partition/rejoin, restart, and NAT/relay transport.
8. Add representative performance baselines and regression budgets for local
   writes, bounded lookups, advertisement verification, fanout, document loads,
   and merge latency.

No later step may relax the invariant that remote index data is only candidate
discovery. If an application needs an authoritative global catalog or complete
counts, it needs a separately trusted service/consensus model and must say so
explicitly.
