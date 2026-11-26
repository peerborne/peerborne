---
title: Limitations
description: Current limitations — what is not yet implemented or verified in Peerborne.
---

Peerborne is under active development. This page catalogs the known gaps between the current implementation and a production-ready system. Every limitation listed here is either not yet implemented or not yet verified in CI.

See the [feature audit](https://github.com/Peerborne/peerborne/blob/main/docs/feature-audit.md) for the evidence backing each claim, and the [roadmap](../../community/roadmap/) for current development priorities.

## Distribution and operations

- **Packages are unpublished.** The eleven `@peerborne/*` libraries are not on npm yet. The release gate installs exact tarballs in an external npm project and checks imports, strict declarations, production dependency advisories, framework/editor mutations, SSR hydration, and Note sharing/recovery in real browsers. Actual registry bootstrap and packaged daemon behavior remain separate checks.
- **No deployment automation.** There is no CI/CD pipeline for deploying relays, bootstrap nodes, or pinning services.
- **Current formats only.** Release versions are validated as strict SemVer, but alpha API, wire, and storage changes can still break an application. There is no state migration framework or promised upgrade compatibility.

## Offline and durability

- **Offline work has no later-delivery guarantee.** A browser can create a new
  local document or edit an already-loaded replica without a network
  connection. Loading a document whose required blocks are not local and
  onboarding an invited collaborator still require reachable peers. Without a
  durable outbox or delivery acknowledgment, later connectivity does not prove
  that changes made offline will reach another replica.
- **Default publication remains best-effort.** The default BeeKEM path has no durable publication outbox. [Automatic catch-up](../networking/#automatic-catch-up) repairs missed same-epoch edits while a member holding them is online; Note adds retained checkpoints, and the release gate covers a bounded relay outage with two writers and browser restarts. Experimental coordinated mode has a separate bounded journal/outbox. Neither mode provides a remote delivery acknowledgment.
- **No delivery acknowledgment.** There is no confirmation that remote peers received, verified, or applied a change. The `document.change()` promise covers the local mutation and storage pipeline, not the GossipSub publish call or remote receipt. A change that is committed locally but whose frame could not be published still resolves, and the failure is reported to `subscribeDeliveryFailures()` handlers.
- **No general reconnect-and-replay guarantee.** Default documents request missed updates on open, on reconnect, on detected gaps and every 30 to 60 s, but a gap closes only while a member that holds the missing state is online and can answer or serve a load. Note resumes relay reservations after opening a retained note, and release acceptance verifies two writers repairing edits after an owned relay restart and browser-process relaunch. Applications must still reconnect their transport. Membership changes, key loss, multi-document histories and relay failover remain outside that gate.
- **No guaranteed at-least-once delivery.** GossipSub is best-effort. Messages may be dropped, delayed, or duplicated.
- **Ordinary load is not a key-bootstrap or rotation-recovery protocol.** Load responses are encrypted under the responder's current document key. A recipient that misses its sealed Welcome or a key rotation cannot use a normal load to learn that unknown key, and a load response that would add a key is refused. A broadcast Welcome cannot add a key either once the recipient holds one, so the member needs a fresh invitation or an explicit out-of-band recovery path.
- **Recovery requires retained local state.** IndexedDB blocks alone do not reopen a closed document; the application must restore a [checkpoint](../storage/#local-checkpoints) before `open()`. Note and the password-manager example test encrypted checkpoints across reload/relaunch. The installed-package Note gate additionally verifies an acknowledged write after forced Chromium termination, both replicas recovering concurrent same-epoch edits after an owned relay outage, and saved-note catch-up when inbound circuit reservations are exhausted. Note no longer waits for an inbound reservation to request history over its relay connection. Recovery remains experimental across browser/OS combinations; the [release evidence](https://github.com/Peerborne/peerborne/blob/main/verification/release/README.md#boundaries) records an earlier Linux/WebKit timeout whose cause remains unconfirmed. This does not establish crash consistency across every interrupted write, device loss or malicious storage rollback.
- **Key loss may be unrecoverable.** Signing keys, KEM keys, and document keys are application-managed. Peerborne has no application-facing key backup or recovery service.

## Storage and persistence

- **No replication factor guarantee.** Peerborne does not ensure encrypted payloads are stored on at least N origins. No peer can serve a local copy while every holder is offline, and data is lost if every copy is cleared or otherwise unrecoverable.
- **Pinning is not implemented.** There is no authenticated pin-request protocol or core pinning publisher. No generic IPFS pinning client exists. See [pinning cookbook](../../cookbook/pinning/).
- **Automatic compaction is off by default.** When enabled, snapshots can prune the in-memory shadow tree; stored blocks are deleted only with opt-in `gcAfterPrune`. A writer still snapshots and prunes once its retained tree reaches 256 levels, so a peer that misses more than about 128 consecutive changes cannot recover them from later messages and needs `requestSync()` or a reload.
- **A forgotten change is applied again if it is redelivered.** A document forgets the CID of a change outside its retained tree, snapshot boundary, recent tips and newest 1,024 heads once about 1,024 to 2,048 newer CIDs arrive. If that change is delivered again, for example in a replayed GossipSub frame, it is merged again. CRDT, membership and key merges are idempotent, so content, access and what the document serves stay the same. Its change counters, remote-update notifications, recent tips and local frontier treat the change as new, as they already do for a peer that loaded the same snapshot.
- **A change that waits for a missed dependency is recorded late or early.** An Automerge or Loro change whose dependency has not arrived stays unrecorded, and so does any node that references it in a delivered tree, so checkpoints omit them and later messages deliver them again. They are recorded, notified and served once the change integrates. A document keeps at most 4,096 such nodes; an evicted one is applied again if it is delivered again. A change the Loro provider drops, because it fails validation with the change that releases it, stops waiting the same way, while later changes that depend on it keep waiting. Yjs keeps a waiting update pending in its own state, including checkpoints, but Peerborne records, notifies and serves it before it becomes visible.
- **Checkpoints hold document keys.** A checkpoint carries the document's plaintext state and its raw document keys. `exportEncryptedCheckpoint()` seals it under an application AES-GCM key; `exportPlaintextCheckpoint()` does not, and its result must be encrypted before storage. Never transmit either.
- **Checkpoints hold at most 100,000 CIDs per set.** Trimming keeps both sets far below that. If a state ever exceeded a restore limit, a checkpoint export would reject instead of producing a checkpoint that would not restore.
- **Snapshot-only first load can fail.** A quorum-bound first load has no prior writer set for snapshot authentication and rejects a response that contains only a snapshot.
- **No size-based garbage collection policy.** Opt-in post-prune GC is destructive for the local copy. There is no TTL, quota, or size-limit-based automatic cleanup.

## Networking and availability

- **Browsers typically need a relay.** Browser peers cannot accept incoming connections directly. A Circuit Relay is needed for initial connectivity and as a fallback; direct WebRTC or WebTransport connections may be possible when NAT traversal succeeds, but this is not yet verified in CI.
- **GossipSub is best-effort.** Message delivery is not guaranteed. Late-joining peers miss earlier announcements.
- **Receive bursts keep one frame per sender.** Beyond 16 in-flight frames per document, only the latest skipped frame of each of up to eight senders is kept, and only if it decrypts under the current document key. A burst from one writer converges. Any holder of the current key, readers included, can send ordinary-looking frames from more than eight GossipSub identities, or 16 MiB of them, and push out writers' kept frames until their next frame. While shared credits across documents are exhausted, skipped frames are dropped. See [receive capacity](../networking/#receive-capacity).
- **One change is limited to 1.75 MiB on the wire.** A larger change is rejected with `GossipFrameLimitError`. With an in-place provider such as Yjs the instance is then retired and must be reopened. Writers prune their retained history once a frame passes 1.75 MiB, so a peer that misses more than about 512 KiB of recent changes needs `requestSync()` or a load. See [frame size](../networking/#frame-size).
- **Large catch-up needs a load.** A `requestSync()` reply larger than 3.5 MiB, usually because of the snapshot, is not sent; the responder logs a warning. Automatic catch-up then loads from a writer that advertised the newer state, which needs `resolveLoadSecurityCommitments` and the load quorum. See [large catch-up](../networking/#large-catch-up).
- **Custom document topics require coordination.** Every participant sharing a document must use the same runtime and document topic prefix, and a custom prefix must be added to each relay's allowlist. Topic names are routing labels, not authentication or authorization.
- **Many transports lack document-path evidence in CI.** The current cross-NAT
  proof verifies invitation acceptance, initial document-history load, and live
  post-join convergence through Circuit Relay. Transport-specific Peerborne
  assertions for direct WebRTC, WebTransport, and DCUtR remain unverified.
- **DHT and AutoNAT have no standalone CI tests.** They are included in the Docker-backed NAT topology but not stress-tested.
- **Relays can censor or drop traffic.** There is no protection against relay-level denial of service. A malicious relay can blackhole all traffic for a peer or topic.
- **Relay identity depends on durable storage.** The standard image persists its libp2p identity under `/shared`; losing the file configured by `RELAY_IDENTITY_KEY_PATH` changes the peer ID and invalidates pinned multiaddrs.
- **No relay meshing or failover.** Each relay operates independently. If your relay goes down, peers cannot reach each other (unless they have a direct connection).
- **Relay readiness is local-only evidence.** `/readyz` proves local startup and seed-topic subscription, not a remote reservation or end-to-end convergence.
- **Automatic catch-up is periodic, bounded and needs corroboration to load.** Open documents send the `requestSync()` request themselves, and a writer's reply or a load also restores history pruned by the depth bound. A dropped final frame with no later signal is repaired by the next periodic request, 30 to 60 s later, or later when many documents are open. A head only one member advertises is asked for over gossip but never loaded for, so in a two-member document a reader that missed a writer's large changes waits for the writer's next frame. A load needs `resolveLoadSecurityCommitments` and keeps the quorum rules, so with the default quorum a single peer that is ahead of the others is not loaded from, and readers never serve loads. A malicious writer can still make each replica run a few loads per document, spaced by a backoff that doubles to 64 minutes. Loro has no pending-dependency hook. A replica applies a remote snapshot only when its compacted count is higher than its own, so changes that a concurrent writer pruned behind a lower-count snapshot may not be recovered; this follows from the snapshot rule and is not exercised. See [automatic catch-up](../networking/#automatic-catch-up).

## Authorization and revocation

- **Invitations are online, in-memory bearer links.** The founder must remain
  online with the document open. Restarting either process loses outstanding
  offer or retry state, and whoever obtains an unclaimed offer can claim its
  role first. There is no selective cancellation API; a short expiry is the
  only non-disruptive way to limit an unclaimed link. Closing the founder
  document or stopping its node makes all of its offers unavailable.
- **Reader onboarding supports founder plus one active collaborator.** A
  second active reader is rejected because add-side BeeKEM PathUpdate delivery
  for larger groups is not implemented or verified. The bounded invitation path
  supports the first collaborator, exact retries for that identity, and a
  replacement once the founder has removed its only collaborator. The
  replacement joins a fresh founder-plus-one BeeKEM tree; the removal already
  rotated the document key, so the removed member cannot read anything written
  after it. Every offer issued before a completed `removeReader()` becomes
  unavailable, so a stale link cannot claim the freed slot.
- **`addReader()` cannot onboard a new identity.** A recipient that has only a
  KEM key pair cannot authenticate a broadcast Welcome or decrypt the reader
  ACL row that would admit it, so it could never open the document. `addReader`
  therefore rejects any identity that is not already a reader before changing
  the ACL or BeeKEM state, and only resends the Welcome to an existing reader.
  Share a document through an invitation. Invitations require the attested
  Automerge capacity profile, which the bundled Yjs and Loro adapters do not
  declare.
- **Yjs and Loro documents are founder-only.** No supported path shares a
  Yjs or Loro document with another identity, so an application built on them,
  including the password-manager example, can only sync it between devices
  that hold the founder's identity and keys.
- **A removal's key stays on the device that made it.** `removeReader()`
  derives the next key from fresh secrets on the removing device, and remote
  PathUpdates cannot replay it on another device of the same founder. A
  founder device that missed the removal, or that restores a checkpoint taken
  before it, cannot recover that key and can neither read nor be read by
  members using it. Restore a checkpoint taken after the last removal.
- **Initial invitations require founder authority.** Note can restore its
  founding browser from an encrypted local checkpoint and issue a fresh offer
  while the note has no active collaborator. A founder restored from a
  checkpoint that records a collaborator can remove it and then invite a
  replacement. A collaborator that loaded the document cannot issue an offer,
  even if its signing identity is a writer. Founder and recipient identities
  must be distinct.
- **The founder's record of a new member is only as durable as the
  application makes it.** Every offer requires a `beforeAcceptance` callback,
  which runs after the claimant's membership is committed and before the
  acceptance that carries the document key is signed. It must store a
  checkpoint. If the callback stores nothing and the founder stops after the
  acceptance is sent, a founder restored from an earlier checkpoint has no
  record of the collaborator: the collaborator keeps the current key and reads
  every later founder edit, the founder cannot list or remove it, and the
  founder rejects its edits. A checkpoint commitment pin does not help, because
  the last pinned checkpoint predates the acceptance. Without that record, only
  a later key rotation, such as removing another member, excludes the
  collaborator. Note stores its checkpoint in the callback.
- **A failed acceptance holds the collaborator slot until its offer expires.**
  A `beforeAcceptance` rejection or 10-second timeout, a signing failure, or a
  removal that races the acceptance withholds it. The claimant's exact retry
  from the same process can still complete it until the offer expires, even
  inside the last 30 seconds. If no acceptance was produced by expiry, the
  founder removes the claimant, which rotates the document key. A founder that
  restarts before expiry loses that timer; if its checkpoint already recorded
  the claimant, remove it with `removeWriter()` and `removeReader()`. A
  claimant whose acceptance was produced but that stopped before storing the
  note is not removed automatically, and the same identity cannot claim the
  offer again from a new process. Note's founder can remove such a
  collaborator and invite again.
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
  request or process restart cannot. Expiry remains strict. The only automatic
  rollback removes a claimant whose acceptance was never produced; a lost
  response after the acceptance was produced keeps the membership.
- **Initial invitations disclose retained history.** Invitation creation
  requires the founder to explicitly choose `historyVisibility = 'full_history'`.
  The other visibility modes filter epoch keys but do not safely redact earlier
  CRDT operations, including operations for later-deleted values, so they are
  rejected by the invitation path.
- **Ordinary document signing is configurable.** With `enableSigning: false`, ordinary sync and snapshot signature gates are disabled for peers holding the needed document key. Initial loads, security advertisements, and BeeKEM membership-control messages remain writer-signed, and invitation creation and acceptance are rejected.
- **Writer ACL admin is unguarded.** Any existing writer can add or remove other writers. There is no document owner concept or admin-only privilege.
- **Edits made concurrently with your own demotion remain only on your
  replica.** If an editor keeps editing while a partitioned writer removes its
  writer role, every replica that has applied the removal rejects those edits.
  After the partition heals the replicas agree on the ACL, but the demoted
  editor's own replica keeps the rejected edits permanently. Nothing signals
  the divergence and nothing repairs it; the replicas show different content
  from then on.
- **The ACL chain is not wired into document synchronization.** The standalone
  `ACLChain` implementation has focused tests, but `PeerborneDocument` still
  authorizes an outer envelope against its current local writer set before
  merging any enclosed ACL nodes. A stale or partitioned writer can therefore
  race a removal with a signed re-grant. Writer removal is not a globally
  causal cutover and does not protect against a malicious writer equivocating
  across partitions.
- **CRDT actor binding has bounded strength.** Every document change is
  signed by its author, and its Yjs client ID, Automerge actor or Loro peer
  ID must derive from that author's key and a per-instance nonce, so a
  writer cannot write under another writer's actor and cut it off. Yjs and
  Loro actors are 53 and 64 bits: a writer that searches that many nonces can
  derive another writer's actor and use it against a replica that has not
  seen, or has forgotten, the victim's actor. A snapshot's content is attested
  only by its signer. A change function that applies another document's
  operations, such as `Y.applyUpdate` of an unrelated `Y.Doc`, is refused,
  and a Yjs or Loro instance is then retired; seed such content under an
  actor from `document.reserveActor()`. Reader and writer ACL changes are
  bound the same way. Coordinator-backed documents, the keychain CRDT,
  `enableSigning: false`, and devices that share one signer are not covered.
  See [actor binding](../security/#crdt-actors-are-bound-to-change-signers).
- **Quorum is not Sybil-resistant.** Q-of-K frontier agreement can be subverted by one actor controlling multiple connected peer identities.
- **BeeKEM restore depends on the application.** Checkpoints preserve the accepted generation. Rollback protection requires an independent current pin. Revoked readers retain access to content and keys they already received.
- **PathUpdate is best-effort and has no automatic catch-up.** There is no
  acknowledgment or retry. A surviving reader that misses the new epoch cannot
  use an ordinary load response encrypted under that unknown epoch to recover;
  it needs an explicit recipient-bound recovery or re-invitation flow.
- **No time-bound or conditional access.** Readers and writers are either in the ACL or not. There is no expiration, usage limit, or context-based access control.
- **UCAN capabilities are standalone and locally cached.** The UCAN module can
  issue and verify capability tokens, but the document change path does not
  check them and capability metadata is not replicated. Revocation is not
  enforced across replicas through a shared, authenticated membership state.
- **Recovery is explicit.** `removeReader()` rotates the current key and sends a best-effort PathUpdate. If a replica observes a competing signed epoch, it stops. An application can explicitly authorize a fresh replacement and persist that decision in its own locator. The default protocol has no automatic branch selection or old-path reconciliation.

## Convergence and verification

- **Broader partition/rejoin remains unverified.** The installed-package Note gate covers one Automerge note, two retained identities, one owned relay outage and same-epoch concurrent edits across browser restarts. Multi-document/many-peer cycles, concurrent membership changes and missed group-key recovery still need acceptance coverage.
- **No pass/fail performance budgets.** Benchmark suites exist but have no thresholds. A regression that doubles latency would not be caught in CI.
- **Cross-CRDT convergence is not tested.** A Yjs document and an Automerge document being edited by different peers in the same application has no CI coverage.
- **Loro validation is bounded by known malformations and costs O(document).** Loro 1.19 imports operations an unmodified client cannot produce, and its checksum is not a MAC, so the experimental Loro provider validates each remote update on a fork before importing it. It rejects unknown container types, container values whose ID is not their own operation's, writes to containers and deletions outside an operation's causal past, and moves of tree nodes that do not exist there. These rules depend only on the change and its causal past, so replicas agree in any delivery order. A snapshot round trip runs as a defence in depth; because it reads state that concurrent changes can alter, a malformation that only it caught could split replicas, and none of the fuzzed classes relies on it alone. Each integrated update reads the whole document. Rich-text marks are not compared, an update that reuses another replica's peer ID is not detected, and two root containers that share a name are accepted while `toJSON()` shows one of them depending on arrival order.
- **A writer can evict other writers' waiting Loro updates.** The Loro provider holds at most 4,096 updates waiting for a dependency and evicts from the Loro peer holding the most, but writers choose their own Loro peer IDs. Peerborne recovers an evicted update through `hasDiscarded` and catch-up. After 16 remote updates trap Loro during validation, the document rejects further remote updates until it is reopened, because each trap leaks a fork.

## Indexing and distributed search

- **Local indexes are projections, not encrypted source data.** V2 is memory-only by default. Explicit IndexedDB mode stores indexed values and ordering keys in cleartext locally.
- **Pagination is not snapshot isolation.** Cursors are deterministic for one query and generation, but concurrent changes can move rows between pages.
- **Range execution is not yet early-terminating.** `first` limits returned rows, while executors may still exhaust a selected key range; exact counts always do.
- **Distributed search is not wired end to end.** Signed manifests, advertisements, codecs, transport adapters, and candidate federation exist as tested primitives, but production libp2p handlers, collection search-key distribution, automatic advertisement publication, and a secure document-resolver adapter remain unfinished.
- **Remote index claims are not truth.** The coordinator verifies returned candidates through local authorization and predicate checks, but malicious peers can omit results and Sybil identities can distort coverage. Exact global counts and completeness are not claimed.
- **Blind search still leaks metadata.** Equality/frequency and confirmation leakage remains for search-key holders; plaintext mode reveals the entire predicate to recipients.

## Examples and documentation

- **Peerborne Note has a bounded sharing and recovery profile.** It supports
  one founder and one reader/editor, retained signing/KEM/storage keys, encrypted
  checkpoints, automatic relay reconnection after reopening a note, and tested
  same-epoch history repair after a relay outage. Its founder can remove the
  collaborator and invite a replacement. Account/key recovery, authenticated
  collaborator discovery, offline invitation acceptance, larger groups,
  delivery guarantees and public-service availability remain outside that
  profile.
- **Cookbook snippets are not validated.** Code examples in documentation may drift from the actual API. There is no CI check that documentation code blocks compile against the current source.
- **No changelog.** Release notes and version history are not published.

## What is verified

CI evidence exists at different scopes:

- **Peerborne distinct-identity cross-NAT acceptance:** one Chromium process
  creates a real document and issues an invitation; a second NAT-isolated
  Chromium process with a separate signing identity accepts it through Circuit
  Relay, loads existing history, and exchanges live bidirectional mutations.
- **Browser smoke:** browser-test opens a document in one Chromium process; the
  wiki, password-manager, and Peerborne Note suites assert startup, rendering,
  and single-browser local storage behavior.
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
