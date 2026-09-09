---
title: Limitations
description: Current limitations — what is not yet implemented or verified in Peerborne.
---

Peerborne is under active development. This page catalogs the known gaps between the current implementation and a production-ready system. Every limitation listed here is either not yet implemented or not yet verified in CI.

See the [feature audit](https://github.com/Peerborne/peerborne/blob/main/docs/feature-audit.md) for the evidence backing each claim, and the [roadmap](../../community/roadmap/) for current development priorities.

## Distribution and operations

- **Packages are unpublished.** The `@peerborne/*` packages are source workspaces, not published to npm. Clean local-tarball installation, Node ESM imports, strict NodeNext typechecking, and a Vite build are automated; registry installation, browser runtime behavior, and packaged daemon execution remain unverified. You must clone and build from source.
- **No deployment automation.** There is no CI/CD pipeline for deploying relays, bootstrap nodes, or pinning services.
- **No supported release migration policy.** [`MIGRATING.md`](https://github.com/Peerborne/peerborne/blob/main/MIGRATING.md) records source renames and known compatibility boundaries, but there is no versioned persisted-state or wire-protocol upgrade path, changelog, semver policy, or deprecation period. API and storage changes between commits may require explicit application migration or reprovisioning.

## Offline and durability

- **Offline work has no later-delivery guarantee.** A browser can edit an
  already-loaded replica without a network connection, and legacy non-strict
  configurations can create a new local document offline. In strict
  authenticated-load mode, an empty open with no connected peers is
  founder/partition ambiguous and creates a document only when the captured
  `validateDocumentPath` callback returns exactly `true`. Loading a document
  whose required blocks are not local and onboarding an invited collaborator
  still require reachable peers. Without a durable outbox or delivery
  acknowledgment, later connectivity does not prove that offline changes will
  reach another replica.
- **No durable document-change outbox.** Changes are published to GossipSub and stored locally, but the document runtime has no queue with retry for unreachable peers. If a peer is offline when a change is published, it may never receive it. The protocol-neutral group-security coordinator's separate outbox does not change this behavior.
- **No document-change delivery acknowledgment.** There is no confirmation that remote peers received, verified, or applied a document change. The `document.change()` promise covers the local mutation/storage pipeline and the GossipSub publish call, not remote receipt. The coordinator's focused acknowledgment tests use a trusted callback, not a live authenticated receiver protocol.
- **No durable reconnect-and-replay guarantee.** Libp2p may redial keep-alive peers, and an explicit load or later sync history may catch a peer up, but Peerborne does not durably guarantee connection restoration or replay of every missed update.
- **No guaranteed at-least-once delivery.** GossipSub is best-effort. Messages may be dropped, delayed, or duplicated.
- **Browser restart recovery not verified.** IndexedDB persists blocks locally, but complete browser restart → reopen → verify document state is not proven in CI.
- **Key loss may be unrecoverable.** Signing keys, KEM keys, and document keys are application-managed. Peerborne has no application-facing key backup or recovery service.

## Storage and persistence

- **No replication factor guarantee.** Peerborne does not ensure encrypted payloads are stored on at least N origins. No peer can serve a local copy while every holder is offline, and data is lost if every copy is cleared or otherwise unrecoverable.
- **Pinning is incomplete.** A `PeerborneNode` listener API exists but the normal core commit path does not publish to it. No generic IPFS pinning client exists. See [pinning cookbook](../../cookbook/pinning/).
- **Automatic compaction is off by default.** When enabled, snapshots can prune the in-memory shadow tree; stored blocks are deleted only with opt-in `gcAfterPrune`.
- **Snapshot-only first load depends on an external trust root.** The legacy/non-authenticated quorum path has no prior writer set for snapshot authentication and rejects a response that contains only a snapshot. Strict authenticated initial load can validate a snapshot against application-pinned writer keys, subject to its other security-state and quorum requirements.
- **No size-based garbage collection policy.** Opt-in post-prune GC is destructive for the local copy. There is no TTL, quota, or size-limit-based automatic cleanup.

## Networking and availability

- **Browsers typically need a relay.** Browser peers cannot accept incoming connections directly. A Circuit Relay is needed for initial connectivity and as a fallback; direct WebRTC or WebTransport connections may be possible when NAT traversal succeeds, but this is not yet verified in CI.
- **GossipSub is best-effort.** Message delivery is not guaranteed. Late-joining peers miss earlier announcements.
- **Many transports lack document-path evidence in CI.** The current cross-NAT
  proof verifies invitation acceptance, initial document-history load, and live
  post-join convergence through Circuit Relay. Transport-specific Peerborne
  assertions for direct WebRTC, WebTransport, and DCUtR remain unverified.
- **DHT and AutoNAT have no standalone CI tests.** They are included in the Docker-backed NAT topology but not stress-tested.
- **Relays can censor or drop traffic.** There is no protection against relay-level denial of service. A malicious relay can blackhole all traffic for a peer or topic.
- **Relay identity depends on durable storage.** The standard image persists its libp2p identity under `/shared`; losing the file configured by `RELAY_IDENTITY_KEY_PATH` changes the peer ID and invalidates pinned multiaddrs.
- **No relay meshing or failover.** Each relay operates independently. If your relay goes down, peers cannot reach each other (unless they have a direct connection).
- **Relay readiness is local-only evidence.** `/readyz` proves local startup and seed-topic subscription, not a remote reservation or end-to-end convergence.
- **Custom load serializers need incremental framing for half-open streams.** The shipped JSON serializer provides a per-request completion detector. A custom `LoadMessageSerializer` that omits `createLoadRequestCompletionDetector()` is decoded once after its first chunk and, if incomplete, only once more at EOF. That fail-closed fallback prevents byte-dribble parse amplification, but a fragmented custom request whose sender waits for the response before closing can instead reach the shared-protocol idle deadline. Custom codecs should implement bounded incremental completion detection or use an explicitly framed encoding.

## Authorization and revocation

- **Invitations are online, in-memory bearer links.** The founder must remain
  online with the document open. Restarting either process loses outstanding
  offer or retry state, and whoever obtains an unclaimed offer can claim its
  role first. There is no selective cancellation API; a short expiry is the
  only non-disruptive way to limit an unclaimed link. Closing the founder
  document or stopping its node makes all of its offers unavailable.
- **Initial invitations support founder plus one active collaborator.** A
  second active reader is rejected because add-side BeeKEM PathUpdate delivery
  for larger groups is not implemented or verified. The bounded invitation
  path supports the first collaborator and exact retries for that identity,
  not a replacement invitation after revocation.
- **Initial invitations are founder-process only.** A replica that loaded the
  document later cannot issue an offer, even if its signing identity is a
  writer. Founder and recipient identities must be distinct.
- **Invitation bootstraps are bounded to one attested provider profile.** The
  bundled Automerge JSON CRDT, ACL, and keychain adapters with P-384/SHA-384
  SubtleCrypto declare the profile that Peerborne tests. Other providers reject
  before membership changes unless they explicitly attest the same size and
  algorithm bounds; the custom provider then owns that guarantee. The sealed
  Welcome and encrypted bootstrap are each limited to 1 MiB. Preflight combines
  the retained sync tree, complete keychain, latest snapshot, served tips,
  signature, projected founder-plus-one membership growth, encryption framing,
  and a 128 KiB reserve; exact final payloads are checked again. There is no
  chunked or streaming bootstrap for larger documents.
- **Invitation rendezvous attempts are bounded, not durable.** Each signed
  address gets a 30-second attempt before its stream is fully aborted and the
  next address is tried. There is no background retry after
  `acceptInvitation()` returns an error.
- **Invitation onboarding is not transactional.** A founder starts fresh work
  only while at least 30 seconds remain, but ACL publication, Welcome sealing,
  signing, encryption, stream, or expiry failure after mutation begins can
  leave partial or complete recipient membership without a usable acceptance.
  An exact same-process retry can repair recoverable partial state; a different
  request or process restart cannot. Expiry remains strict and there is no
  automatic rollback.
- **Initial invitations disclose retained history.** Invitation creation
  requires the founder to explicitly choose `historyVisibility = 'full_history'`.
  The other visibility modes filter epoch keys but do not safely redact earlier
  CRDT operations, including operations for later-deleted values, so they are
  rejected by the invitation path.
- **Ordinary document signing is configurable.** With `enableSigning: false`, ordinary sync/load signature gates are disabled for peers holding the needed document key; BeeKEM membership-control messages remain writer-signed.
- **Writer ACL admin is unguarded.** Any existing writer can add or remove other writers. There is no document owner concept or admin-only privilege.
- **Joined writers cannot revoke pre-existing readers by identity.** Reader identity-to-KEM/leaf bindings are retained only in the live writer instance that registered the reader. Processing a Welcome reconstructs the anonymous BeeKEM ratchet tree, not those bindings, so a joined writer—or a writer after restart—can call `removeReader()` only for readers it registered locally. There is no authenticated binding persistence or transfer protocol yet.
- **Writer removal is not confidentiality revocation.** The replacement-key delta and ACL removal share one sync envelope encrypted under the previous document key. With signing enabled, one signature binds both and receivers process the keychain delta before the ACL node, but this is not transactional rollback or guaranteed delivery. A removed writer retaining the previous key can recover the replacement key.
- **Legacy quorum is not Sybil-resistant.** Frontier-only K-of-Q loading can be subverted by a peer controlling multiple bootstrap identities. Security-aware V4 collapses duplicate votes from one verified writer authority, binds the complete state-mutating response plan actually advertised and served (including serialized inline changes), reconciles compatible sparse/full repeated-CID aliases while rejecting conflicts in either traversal order, and rejects recorded cross-round transcripts through a fresh requester-signed challenge. It does not attest to unserved branches or stop an authorized writer from signing stale state again. Q compromised or non-independent pinned writer keys can still collude; authority identity also relies on immutable pinned key objects and deterministic, collision-resistant public-key serialization. The alias and resource-bound evidence is from focused tests, not live hostile peers.
- **Initial-load application is not atomic across providers.** A selected response applies keychain, snapshot, ACL, and document mutations in place. V4 first verifies its signature, trusted tuple, manifest, and prefetch commitments, while legacy paths have narrower gates. On every path, if a later semantic or custom-provider failure is detected after mutation begins, Peerborne permanently retires that document instance and starts best-effort cleanup instead of trying another responder on possibly partial state. Callers must discard the document together with its ACL/keychain provider instances. This fail-closed retirement is not rollback: an applied prefix may remain in those providers, and staged cross-provider rollback is not implemented.
- **BeeKEM v1/v2 is not a mixed-version rollout protocol.** Current membership operations send v2 without downgrade, generation-bearing replicas reject v1 Welcomes and PathUpdates, and v1-only replicas cannot follow a v2 rekey. Generation-less PathUpdate v1 reception is disabled by default; `allowInsecureLegacyBeeKEMPathUpdateV1: true` is an explicitly insecure compatibility mode that accepts replay rollback risk because v1 has no generation or parent-tree binding. There is no automatic in-place upgrade. Upgrade participants first, then use an authorized writer that still holds the current ratchet state and locally retained identity-to-KEM/leaf bindings to perform authenticated removal and rejoin, delivering the resulting writer-authenticated, recipient-sealed v2 Welcome. Create a fresh group/document when no such writer exists or current membership cannot be established. After migration, reinitialize with `allowInsecureLegacyBeeKEMPathUpdateV1: false` or omit the option so v1 PathUpdates are rejected again.
- **Deferred change blocks have a compatibility size limit and a cooperative fetch deadline.** Writers and readers reject a serialized change above 16 MiB or an encrypted/framed block above 16 MiB plus 64 KiB. Custom authentication providers must fit their expansion and framing inside that allowance. Each remote initial-load or invitation catch-up candidate also caps all deferred blocks at 16 MiB decoded and 32 MiB encrypted; decrypt/apply is sequential under that aggregate budget. The configured Helia blockstore must honor the supplied `AbortSignal`; a custom implementation that ignores cancellation can leave a read pending past the deadline, but no later decrypt/apply mutation is allowed after expiry. Older oversized blocks require an application migration with the older source or a fresh document.
- **Custom BeeKEM keychains require transactional staging.** A custom `KeychainProvider` may still implement the base `Keychain` for non-BeeKEM document encryption. Installing a KEM key through `setKemKeyPair`, however, requires the exported `TransactionalKeychain` capability: detached `prepareEpochKey` and `prepareMerge` results whose synchronous `commit()` applies completely or throws before mutation. The shipped Yjs and Automerge keychains implement it.
- **The alpha key-ID width change has no migration path.** Older source snapshots used 16-byte, UUID-formatted document key IDs; current Yjs and Automerge providers use 32-byte, lowercase-hex IDs. The difference affects stored keychains and every encrypted block, pubsub message, load response, and direct key update, so mixed-width peers misparse framing and old persisted replicas do not reopen safely. All peers and storage in a test deployment must use one source generation; upgrading older state requires discarding/re-provisioning it or a separately reviewed application migration, not ordinary document load or a BeeKEM Welcome.
- **BeeKEM replay/rekey state and membership-operation journals are memory-only.** Live v2 state rejects stale or conflicting generations and treats an exact PathUpdate replay as a no-op, but the accepted generation and replay digest are not durably persisted. Independently generated same-generation updates have no fork-choice rule: replicas that accept different branches cannot merge them. Recovery requires a writer that still has the current ratchet plus the affected member's locally retained identity/KEM binding to perform an authenticated removal and rejoin; otherwise create a fresh group/document. In-memory rollback tests restore the BeeKEM tree/generation for selected operation failures; they do not provide restart recovery or one atomic rollback across the ACL, keychain, and network. Founder creation and reader/writer membership changes retain exact successful provider outputs for retry after later preparation, publication, or delivery failure. Because ACL and keychain providers do not promise throw-before-mutation, Peerborne marks each provider call before awaiting it: a provider rejection is never retried and permanently retires the document instance before best-effort `close()` cleanup. Cleanup is not rollback and does not make the instance reusable; callers must discard the document together with its ACL/keychain provider instances. The pending journal and retirement marker are memory-only, so restart after an ambiguous call requires restoring known-good durable state or replacing those providers. After restart, replaying an old valid writer-signed, recipient-sealed Welcome can rebootstrap stale ratchet state. The Welcome's `welcomeEpochId` is only an invitation/history boundary and cannot substitute for a persisted authenticated generation anchor.
- **BeeKEM leaf slots are append-only and bounded.** Removed members leave blank slots rather than being reused. A ratchet tree contains at most 8,192 lifetime leaf slots, including the founder, so its worst-case generated v2 PathUpdate, including encrypted copath bundles, remains within the 10 MiB document-protocol framing budget. `compact()` can discard unreachable blank node objects but does not lower the lifetime leaf count; slot reuse and automatic group migration are not implemented.
- **Reader revocation delivery is best-effort.** There is no guarantee that PathUpdates reach all peers, and `removeReader()` can continue after an ACL-removal broadcast failure.
- **No time-bound or conditional access.** Readers and writers are either in the ACL or not. There is no expiration, usage limit, or context-based access control.
- **UCAN capabilities are standalone.** The UCAN module can issue and verify capability tokens, but the document change path does not check them.
- **No automatic or restart-safe key rotation.** Document keys can be rotated on demand via `removeReader()`, which activates a new document key through BeeKEM, but rotation requires explicit application triggers, accepted BeeKEM control state is not durably anchored, and PathUpdate delivery is best-effort.
- **The group-security coordinator is infrastructure only.** Focused tests cover signed applied-membership-delta/state/Welcome bindings, fake-provider creator/KeyPackage credential-to-member/request mismatch rejection, independently snapshotted encrypted group-bound pending/consumed KeyPackage state, replay metadata, atomic terminal fork poison through the rollback-anchor contract, and removal of an outbox entry only after a matching explicit durable-acceptance value. Fork proof is limited to siblings whose signed record and authorization parent remain in the bounded replay window. The credential/provider and trusted acknowledgment callback are fakes, not RFC 9420, a real application credential authority/revocation policy, or a live authenticated ACK protocol. Tests reconstruct over the same in-memory objects in one process; they do not terminate and restart a process or browser. Only in-memory store and rollback-anchor implementations exist, and the anchor is not rollback-resistant unless an application supplies a separately protected monotonic implementation. There is no browser-persistent backend/keystore or document ACL integration. These seams do not establish MLS, forward secrecy, post-compromise security, or role-only update guarantees.

## Convergence and verification

- **System-level partition/rejoin is not proven.** Single-document convergence works, but multi-document, multi-peer partition/rejoin cycles have no CI coverage.
- **No pass/fail performance budgets.** Benchmark suites exist but have no thresholds. A regression that doubles latency would not be caught in CI.
- **Cross-CRDT convergence is not tested.** A Yjs document and an Automerge document being edited by different peers in the same application has no CI coverage.

## Indexing and distributed search

- **Local indexes are projections, not encrypted source data.** V2 is memory-only by default. Explicit IndexedDB mode stores indexed values and ordering keys in cleartext locally.
- **Pagination is not snapshot isolation.** Cursors are deterministic for one query and generation, but concurrent changes can move rows between pages.
- **Range execution is not yet early-terminating.** `first` limits returned rows, while executors may still exhaust a selected key range; exact counts always do.
- **Distributed search is not wired end to end.** Signed manifests, advertisements, codecs, transport adapters, and candidate federation exist as tested primitives, but production libp2p handlers, collection search-key distribution, automatic advertisement publication, and a secure document-resolver adapter remain unfinished.
- **Remote index claims are not truth.** The coordinator verifies returned candidates through local authorization and predicate checks, but malicious peers can omit results and Sybil identities can distort coverage. Exact global counts and completeness are not claimed.
- **Blind search still leaks metadata.** Equality/frequency and confirmation leakage remains for search-key holders; plaintext mode reveals the entire predicate to recipients.

## Examples and documentation

- **Peerborne Note is a bounded demo, not a complete sharing product.** It adds
  an explicit founder-plus-one invitation UI, non-extractable browser signing
  identity storage, fragment scrubbing, and reader/editor modes. It does not
  provide account recovery, authenticated collaborator discovery, offline
  acceptance, durable invitation/KEM state, automatic reconnect, revocation
  UX, or a delivery guarantee. Its source smoke test is not proof that the
  public relay or deployment will remain available.
- **Cookbook snippets are not validated.** Code examples in documentation may drift from the actual API. There is no CI check that documentation code blocks compile against the current source.
- **Migration notes are not an upgrade guarantee.** [`MIGRATING.md`](https://github.com/Peerborne/peerborne/blob/main/MIGRATING.md) documents known source and compatibility breaks, but Peerborne has no supported, versioned persisted-state or wire-protocol migration between arbitrary commits.
- **No changelog.** Release notes and version history are not published.

## What is verified

CI evidence exists at different scopes:

- **Peerborne distinct-identity cross-NAT acceptance:** one Chromium process
  creates a real document and issues an invitation; a second NAT-isolated
  Chromium process with a separate signing identity accepts it through Circuit
  Relay, loads existing history, and exchanges live bidirectional mutations.
- **Browser smoke:** browser-test opens a document in one Chromium process; the
  wiki, password-manager, and Peerborne Note suites assert startup and rendering.
- **Focused component suites:** cover individual invitation, protocol,
  authorization, encryption, and transport behaviors.
- **Transport integration:** exercises NAT and relay topologies independently of
  complete Peerborne document convergence.

See the feature audit for the per-capability level. A positive component or
transport test does not establish complete multi-peer document behavior.

## Next steps

- [Roadmap](../../community/roadmap/) — current development priorities
- [Help wanted](../../community/help-wanted/) — specific contribution opportunities
- [Feature audit](https://github.com/Peerborne/peerborne/blob/main/docs/feature-audit.md) — capability-to-evidence map
- [FAQ](../../community/faq/) — answers to common questions
