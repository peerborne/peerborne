# Coordinator-backed documents

`Peerborne.doc(path, { security })` connects the group-security coordinator to
the actual `PeerborneDocument` change, transaction, receive and pubsub paths.
This experimental mode requires a group-security provider and a pinned document
authority. The default BeeKEM document mode remains a separate protocol.
The MLS provider under `verification/mls-provider` is still an experimental
adapter; this change does not promote it to a production cryptographic stack.

## Trust and setup

Use one cryptographic group per document. Group members can derive the group's
exporters; different document paths within the same group do not create separate
confidentiality domains. A signature/AAD binding prevents cross-document mutation
replay even when key material is accidentally reused.

Install `DocumentGroupControlAuthority.authorize` as the coordinator's
`authorizeControl` callback **before** bootstrap or restore. Its constructor takes
the pinned protocol, group ID and initial controller member ID. Then create
`DocumentAuthorityLog` from the authenticated coordinator context, the initial
roster, the controller signing key, the `AuthProvider`, and that control authority.
The log verifies the genesis signature. Distribute its `genesisId` over an
authenticated channel; receiving a hash and roster from the same untrusted peer
does not establish a trust root.

For another replica, restore the signed role records with that pinned genesis
hash and a new control authority. Bind the restored authority before restoring
or joining its coordinator. Control-history verification uses the controller
authorized at each previous control head, including historical controllers after
a transfer. The document rejects a built-in role log paired with a coordinator
using a different group-control authorizer.

Each control head has one immutable controller binding. A later role record must
name a fresh control head, even when it advances the epoch; reusing an older head
is rejected during live application and restoration. The verified roster and
binding policies preserve old controllers and cap the history at 1,024 records.
Rosters are bounded at 256 members and malformed rosters are rejected before
signature verification. Parsing, native cryptography, copied bytes and racing
updates remain covered by generated runtime properties.

The new content format uses 32-byte member IDs. A roster has at most 256 unique
member IDs and canonical public keys, and exactly one controller. Controllers
can write and sign role transitions; writers can change document content;
readers cannot author accepted mutations. The separate signed role log holds
permissions: writing a property named `role` in user data cannot change it.
Optional signed `writePaths` restrict a member's native operations inside
application data. These write scopes do not restrict what a decrypting group
member can read.

Removing a reader uses both a cryptographic group removal and a signed role
update. With `requireGroupRosterMatch: true` in the coordinated document’s
security options, the provider reports member IDs from its authenticated group
state. The SDK requires those IDs to match the built-in signed role log before
exposing content or accepting changes. A survivor pauses protected document use
until both authenticated updates arrive.

If a survivor restarts between the two updates, create a fresh document
instance. When the signed role record arrives, call
`applySecurityAuthorityUpdateBeforeOpen(signedRoleRecord)` and then `open()`.
The first operation installs matching authority without exposing recovered
content. With a configured document journal, the new controller binding becomes
visible after the journal accepts the checkpoint.
The recovered instance reserves its local path until it closes. If the engine
rejects recovery, it closes that instance and releases the path for a fresh one.

Use the document’s authority update APIs for strict transitions so they go
through this journal. Publication retries pause during a roster mismatch and
check current authority again before dispatching each frame.
Change handlers receive updates only while their captured roster stays current
and the document stays open.

This option relies on the provider reporting its actual decrypting membership.
An offline replica retains its earlier keys and roles until it learns the
transition.

Peers in a new group context cannot decrypt a frame from the retired one, even
one the author already published there. When `applySecurityAuthorityUpdate`
installs a new context, the author re-signs its frames from the retired
context that peers may lack, in original write order, as new frames in the new
context with the same native delta. Peers may lack a frame that is still in
the outbox, or one written after the last frame the author accepted from a
peer in that context. Earlier frames reached a reachable group and are not
re-sent, so re-signing does not repeat every epoch. The controller of the
retired context commits its successor itself, so it published all its frames
there while that context was current for every member. It carries only the
frames still in its outbox, and a member that missed one catches up from the
controller's checkpoint. Duplicates are harmless
because native CRDT changes are idempotent. The document keeps every unsent own
frame, and beside them its author's latest sent frames, up to 16,448 frames and
32 MiB of deltas and recorded paths, apart from the shared retention pool. Each
own frame is found inside a coalesced publication by its encryption nonce,
which its journal entry records. After a restart the document rebuilds its own
frames from the journal entries since its last checkpoint and from the
checkpoint itself, which carries every unsent own frame whose entry it folds:
its context, sequence, nonce, native delta and exact recorded paths. The paths
of unsent frames count against 4 MiB as the journal encodes them, so a local
edit that would exceed it fails before commit with
`DocumentPublicationBacklogError`, as a full outbox does.

Re-signed frames join the outbox's tail publication like local edits. A
retired frame leaves the outbox only after its re-signed copy is accepted: its
publication is rewritten in place without it, and removed once it holds no
frame. A retry never sends a retired publication. It keeps it queued while it
holds a frame that can still be re-signed, including before the new roles
arrive, and otherwise drops it and reports its frames. Local edits leave one
of the journal's 16 rows free, and re-signs may use it, so a full retired
outbox drains in order: each re-signed frame joins the new tail publication in
the commit that replaces it, and the retired publication it came from then
shrinks. A frame whose re-sign fails transiently waits. After a restart,
frames whose retired publication is still queued are queued again. A
new local edit natively depends on every waiting frame, so it first re-signs
them, and fails with `DocumentPublicationBacklogError` if it cannot. Any other
failure leaves the queue in place. A re-sign failure never
fails the role update itself, which resolves with
`{ resent, waiting, skipped, dropped, diverged }`.

Every local edit is inspected when it is written, whether or not its author is
restricted, and its operation paths are recorded with the frame and sealed in
its journal entry with the device key. The record is exact. Only duplicates and
paths under a recorded prefix are dropped, so grants cover the record exactly
when they cover every operation. It has the bounds receivers inspect with: at
most 4,096 paths of at most 32 segments, 1,024 units per segment and 1,048,576
units in all. The journal compacts 4 MiB earlier to keep room for a full list.
When an unrestricted author's edit cannot be inspected within those bounds, the
record is the whole document instead of failing the edit. A non-checkpoint
journal entry without a valid path list fails decoding.

When re-signed, a restricted author's frame is checked against its current
grants using those recorded paths, including after a restart and for edits
written before the author was restricted. A whole-document record means the
edit could not be inspected. Receivers of a restricted author inspect within
the same bounds and cannot accept it, so a restricted author treats it as
denied under any grants. An unrestricted author re-signs it unchecked.

- A denied frame that was already published is skipped. Peers have it, or the
  author's later frames are held until a catch-up.
- A denied frame still in the outbox reached no one. It and every later frame,
  which depends on it natively, are dropped, counted and reported to
  `onPublicationsDropped`.
- A reader or removed member keeps its replica readable.
- An author that can still write in that case has `diverged`. Its replica holds
  content the group cannot accept. Before the role update resolves, the
  journal appends an authenticated divergence marker. The marker advances the
  independent rollback anchor, so storage that drops it is rejected as a
  rollback. The journal then takes no further entries. The live document
  rejects every operation with `DocumentDivergedError`, and so does every
  later open of that journal.
- Frames re-signed earlier in the same pass precede the denied one and do not
  depend on it. The diverged document still publishes them through
  `retrySecurityPublications()` while it stays open. A restart before they are
  sent leaves them in the diverged journal.
- To rebuild, open the document with a journal in a new store and a new
  rollback anchor namespace, then request a controller checkpoint. With
  `IndexedDBDocumentJournalStore`, a new store means a new database name, or
  removing the old journal first with `DocumentReplayJournal.deleteDiverged()`
  after restoring it. That refuses while any publication is still unsent,
  unless `discardUnsent: true` drops them. The old anchor still holds the
  diverged head, so it cannot be reused either way. The new journal starts
  without the marker.
- A replica never adopts its own receipt from a checkpoint. A rebuild therefore
  works only while the controller holds none of the author's frames in the
  current context. Once the frames re-signed before the denial reach the
  controller, the rebuilt replica's catch-up conflicts on its own receipt until
  the next epoch.

Receivers admit re-signed frames through normal admission, including their
own field-scope checks. A document opened without a publication outbox does
not re-sign. A document without a journal has no row to spare, so when its
process-local outbox is full a retired publication whose frames are all queued
is removed first and re-signed from memory. A member that joins in the
new context gets earlier content from the controller checkpoint.

## Resume with a controller checkpoint

Set `enableAuthenticatedCatchUp: true` on both strict documents. This profile
requires an encrypted replay journal and an adapter that prepares a detached
snapshot merge. Automerge and Yjs retain accepted local operations in that
merge.

1. Deliver the authenticated group transitions and signed roles in order. Open
   the returning member’s document with the current group state and role head.
2. Relay its `createSecurityCatchUpRequest()` result to the current controller.
   The controller calls `createSecurityCatchUpCheckpoint(request)` and returns
   the encrypted response to the requester.
3. Call `applySecurityCatchUpCheckpoint(checkpoint)` on the returning document.
   The prepared merge becomes visible after journal acceptance and a fresh
   authority check.

Both messages are encrypted and signed. The current epoch, pinned genesis,
document path, role head, recipient and one-shot request challenge bind the
response. Only a current controller with whole-document write authority can
issue it. A replica can import a missing receipt for another current writer.
Overlapping receipts must agree on their sequence and hash, and the requester
keeps its own sequence.

A requester that holds part of another writer's history and missed its tail
can still resume. The request lists the requester's accepted heads, at most
256. For each writer whose head is behind, the controller adds that writer's
signed frames from the requester's head toward its own. The suffix shares the
1 MiB sealed checkpoint with the snapshot and holds at most 256 frames, so a
small snapshot leaves room for at least one maximum-size frame. When a
writer's frames do not all fit, or are not all retained, the controller offers
that writer's receipt only at the last frame it included, or at the
requester's own head, and the requester advances over later rounds. Other
writers are unaffected. A retained frame at the requester's head with a
different hash keeps the controller's head, so a fork still conflicts. The
requester accepts a higher head only after checking each frame: the writer's
signature, this document, genesis, permission head and group context,
consecutive sequences, and a parent hash chain from its own head to the
offered one. An offer below a head the requester accepted after sending the
request is kept when it matches a frame the requester retains. Anything else
conflicts as before.

Each document retains its latest 64 accepted frames per author in the current
context, in memory only, as signed content and ciphertext. A document retains
at most 16 MiB, and all coordinated documents in a process at most 64 MiB.
Over either budget, the author holding the most retained bytes gives up its
oldest frame first, so one writer's large frames do not push out other
writers' tails. Retained frames are dropped at a new group context, at the
receipt reset of a role transition and on close. A requester whose head is
ahead of the controller's, a gap longer than the retained frames, or a
controller restarted since accepting them still requires ordered frame
redelivery. The proved receipt policy is unchanged; these extensions run
beside it at runtime and are outside the formal proof.
The encoded snapshot payload is limited to 512 KiB. Native snapshot generation
and merge costs still depend on the document and adapter.

The application relays the messages and retains identity, trust roots and the
independent rollback anchor across restart. This profile leaves peer discovery,
control-message delivery and recovery
after key or anchor loss to the application.

## Native field write scopes

Set a member's `writePaths` when creating or updating `DocumentAuthorityLog`.
The current v2 authority format signs these grants with the roster, group context
and causal parent. Omit the field for whole-document writes; `[]` allows no
operations, and `[[]]` explicitly grants the whole document. A reader still
cannot write. A grant is an array of map-key segments and covers its subtree.
There is no JSON-pointer parsing, string-prefix matching or numeric-index grant.

For Automerge, `writePaths: [['profiles', 'alice']]` permits writes within
`profiles.alice`. For Yjs, include the root shared-type name:
`writePaths: [['root', 'profiles', 'alice']]`. Provision parent containers before
restricting their writers. Deleting or replacing an ancestor requires a grant
for that ancestor; a child grant cannot replace a parent with a new object.
Lists, arrays and text are indivisible authorization containers, including
objects nested inside a sequence. Their mutations require the container grant.

Both bundled adapters inspect native operations in their detached preparation.
Automerge indexes immutable creation ancestry, including losing/deleted objects;
Yjs inspects integrated items and deletion ranges before native GC. Comparing
only visible JSON would miss hidden concurrent writes. Restricted local Yjs
changes serialize inspectable items before GC. With GC enabled, the private
mirror is pruned after serialization. A GC callback that adds unencoded state
invalidates the preparation. The engine checks every reported target before
local signing, WAL staging and CRDT commit. Missing, unknown or unsupported
inspection fails closed for a restricted member. Permission changes require the
existing fresh-epoch signed role transition.

A Yjs operation can arrive after a replica has accepted and collected the
deletion of its container. Yjs then integrates it as a GC struct with no parent
or content. It cannot become visible, so it uses inspection work but reports no
target. An honest writer's concurrent edit inside a deleted granted container
is admitted at every replica, and its sequence keeps advancing. Replicas that
receive the edit before the deletion check its real path. Keeping GC off in the
private mirror would not fix this. The mirror is rebuilt from the collected
document snapshot after a restart or a discarded preparation, and it would
retain deleted content.

The mirror always collects with the default policy. The application's document
can keep deleted items through a custom `gcFilter`, items an undo manager keeps,
or GC turned off after opening. An operation the mirror collected could then
integrate as a live item in that document. In that case the update is inspected
again against an uncollected copy of the document, which reports the real path.
That copy costs time proportional to the document. A restricted frame cannot
send GC structs directly.

A dishonest writer can still get an out-of-scope edit into a collected container
accepted, but only where it has no effect. Replicas that see the edit first
reject it, so they reject that writer's later frames. Honest members' later
changes that build on what the writer wrote after that point then fail with
missing causal dependencies at those replicas, which stalls their sequences too.
Like equivocation, this can split replicas, but it cannot change protected
state.

Each member has at most 64 grant paths, each with 32 segments of at most 1,024
UTF-16 units. A roster has aggregate caps of 4,096 paths, 32,768 segments and
1,048,576 segment units, and retains the existing authority-record byte bound.
One inspection admits at most 131,072 units of native operation work, 4,096
distinct targets and 1,048,576 retained segment units. Automerge ancestry retains
at most 262,144 object creations with actor identifiers capped at 64 bytes;
Yjs inspection accepts at most 4,096 root shared types and scans their bindings
once per transaction. Restricted operations require a declared root shared type;
an unknown root is refused without changing visible state and can be retried
after the application declares its schema. Text attributes require the text
container grant. Oversized work must be split or explicitly reprovisioned.
These are profile and metadata bounds, not total heap or main-thread latency
guarantees. Native decoding and provenance extraction remain property-tested
boundaries. Legacy BeeKEM and UCAN field-capability strings use a separate path.

## Admission and role transitions

Both bundled Automerge and Yjs providers implement detached document sessions.
Automerge stages an isolated clone. Yjs stages a private reusable mirror and
keeps the visible document unchanged until admission succeeds. The mirror keeps
one actor over accepted edits; it does not clone the complete document for every
keystroke. Missing native causal dependencies are rejected before visible
application with a `DocumentCausalDependencyError`. A direct mutation of the visible Yjs document invalidates its
session. Staging accepts scalar values and shared `Y.Map`, `Y.Array` and `Y.Text`
structures. Opaque object/array/binary values, subdocuments and XML child types
are rejected because they can mutate without a tracked parent update. Application callbacks and the JavaScript environment remain trusted.
Plan validation also rejects open native transactions and pending dependency
queues. Mirrors preserve known root shared types; applications must use the same
root schema on each replica because native Yjs updates do not encode those declarations.

Frames are always signed in coordinated mode, including when the legacy
`enableSigning` option is false. The signed bytes bind the document path, pinned
genesis, signed permission-history head, full authenticated group context/control head, author, safe sequence,
previous content hash and delta kind. AES-GCM additionally binds the document
and group context and permission-history head as AAD. Exporter labels separate the content encryption key
from the opaque epoch routing tag. A guard rechecks group and role authority at
the synchronous CRDT commit boundary.

The binary outer frame exposes a format marker, opaque epoch tag, nonce and
ciphertext length. Document paths, writer keys, counters and change kinds are
inside ciphertext. The pubsub topic uses the authority genesis hash. Topic
correlation, sizes, timing, libp2p identities and signaling metadata remain
observable; this is not a traffic-analysis anonymity claim.

After a coordinator membership transition, document content is blocked until
the controller signs the next role record with `signUpdate`. Each record binds
the previous role-record hash and the new authenticated control context, and
requires a strictly newer epoch and changed control head in the same group.
`document.applySecurityAuthorityUpdate(record)` verifies and applies it through
admission and, when configured, persists a document checkpoint with the role
history before acknowledging success. Concurrent competing role records cannot
both finalize against the same prior revision. History is bounded to 1,024
records and 16 MiB; exceeding it requires explicit new-group provisioning.

The legacy load, checkpoint, invitation, ACL-change and BeeKEM handlers fail
closed in this mode. No fallback decrypts a coordinated frame with the legacy
keychain. Unsupported CRDT providers must implement the staging capability
before they can be used; Loro does not yet implement it.

## Replay persistence and publication

Configure `DocumentReplayJournal` with the document ID, pinned genesis,
nonextractable AES-GCM device key, `IndexedDBDocumentJournalStore`, and a
`DocumentJournalRollbackAnchor`. The anchor must persist independently of the
journal. `InMemoryDocumentJournalRollbackAnchor` is a simulation/reference
implementation and cannot detect a rollback across process loss.

The journal encrypts accepted deltas with the device key, so old accepted state
can be reconstructed after epoch keys have been dropped. Signing private keys,
epoch keys and device keys are not stored in journal entries. Applications own
device-key protection and recovery. Reusing a journal with another document or
genesis is rejected. Use one active document owner per journal.
The document reserves its path before accessing the journal, so a duplicate open
cannot discard the active owner's pending write. Recovery checks every accepted
permission-history head against the configured verified log before exposing
document state. A validly signed competing role fork is rejected.

A write stages a pending encrypted entry before CRDT commit. After successful
admission, the journal creates a separate AEAD acceptance tag bound to that exact
encrypted entry. An atomic IndexedDB transaction stores the authenticated
accepted record and outbound frame. Staging never creates that acceptance tag;
a storage attacker cannot promote pending ciphertext into accepted state. The independent anchor advances before the mutation promise
resolves or publication starts. A pending entry without an accepted marker is
discarded on restart. A committed entry interrupted before anchor advancement
can finish exactly that one authenticated anchor step. Older stores and same
revision substitutions are rejected. An ambiguous post-commit failure poisons
the live document and requires reconstruction; callers must not blindly rerun
the change callback.

Exact per-author sequence/hash receipts survive restart and compaction.
Conflicting author heads are rejected; duplicate frames do not mutate or
rebroadcast the document. Receipt state resets at a new authenticated group
context, keeping it bounded by the roster. A signing identity must have one
document author at a time; independent offline branches using the same member
ID are detected as conflicting prefixes rather than merged.

Received publications wait in their own queue, separate from the 16 local
operations and 16 MiB a document admits. Received work runs the document's
waiting local edits and publication bookkeeping before each frame from another
author, so a received backlog never delays them. Every frame they carry is
charged twice its ciphertext size, covering the plaintext that
pre-authentication keeps for its turn. A document queues at most 49,152 frames and 96 MiB of charged
bytes, and all coordinated documents in a process at most 131,072 frames and
192 MiB. One GossipSub sender may hold 20,480 frames and 40 MiB of a document's
queue, which covers one full outbox backlog plus live edits sent while it
drains, and two senders' shares leave room for everyone else. Each frame's
charge is released once it is processed. A publication that arrives beyond
those bounds is rejected before it is copied. Before it waits behind earlier
work, every frame it carries must carry the current epoch tag and decrypt under
the current document key and authority head, and all of them must come from one
author with consecutive sequences, so input from a non-member is released
within one decryption per frame. Frames below the author's accepted sequence,
the accepted frame itself, and copies of a frame that is already waiting or
held are dropped then, without a signature check, and each releases its charge
as soon as it is recognized. Copies are matched by author, sequence and content
hash, so a member's forged frame cannot shadow the genuine one, and a different
frame at the accepted sequence is still verified and reported as equivocation.
If a waiting frame whose copy was dropped is then neither applied nor held, for
example because it arrived in a slice without its predecessor, it is charged
again and takes another turn after the publications already queued. The decrypted plaintext of the remaining frames is
reused. A refused publication is not retained: the author's later frames wait
as held frames until the missing ones are delivered again.

A frame can arrive before its author's previous frame, or before another
author's change that it natively depends on. After full decryption, signature,
role and context checks, such a frame is held instead of rejected, and
`receive` resolves `false`. Each accepted frame or catch-up merge retries the
held frames whose author prefix is now complete. A frame held for a native
dependency is retried only once the session holds every struct, deletion or
change hash the provider named for it, so unrelated accepted frames cost no
staging; a provider that names nothing is retried after each accepted frame.
Automerge names missing change hashes before it clones the document, and a Yjs
update that integrated nothing keeps the private mirror instead of rebuilding
it from a snapshot. A retried frame goes through the whole admission path
again, including field-scope inspection. A document holds at most 64 frames
and 8 MiB; each author holds at most 32 of those frames and 4 MiB. All
documents in a process hold at most 1,024 frames and 64 MiB, and one author at
most a quarter of that. A held frame expires two minutes after it was held, by
a timer even in a document that receives nothing more; frames that an arriving
predecessor makes admissible are retried before anything expires. When a bound
is reached, the author occupying the largest fraction of its frame or byte
share gives up its farthest-ahead frame, in any document for the process-wide
bound, so one writer's far-ahead frames cannot push out another author's
out-of-order frame. Evictions are planned first and applied only if the new
frame is then admitted; a frame farther ahead than everything its author holds,
or whose author already uses its whole process-wide share, is rejected without
evicting anything. A second frame for a held author sequence with different
content is rejected as equivocation. Held frames are memory-only and are
dropped at a new group context and on close. A held frame whose predecessor
never arrives expires unless redelivery brings it first.

A replica asks peers for the frames it lacks with a redelivery request. The
request lists its accepted heads in the current context (at most 256) and the
frames it already holds (at most 64). It is signed by the member, encrypted
under the epoch key with its own AAD domain, and uses a separate outer format
marker. It also carries a signed issue time and the node's libp2p PeerId. A
responder answers only when:

- GossipSub's signed sender is that PeerId, so a member cannot replay another
  member's request from its own peer;
- the issue time is within 60 s of the responder's clock; and
- the issue time is newer than the last one it accepted from that member, so a
  captured request cannot be replayed later.

Redelivery therefore needs member clocks within 60 s of each other. A member
whose clock is further off gets no answers and answers no one, without an
error; `securityRedeliveryStaleRequests` counts the requests a document
ignored for that reason.

Requests go out about a second after open. One also goes out when a peer
subscribes to the topic (at most once per peer every 30 s), and when a frame
newly starts waiting. While frames stay held, requests back off from 5 s to
30 s. Otherwise one goes out every 30-60 s. `requestSecurityRedelivery()`
sends one at once. A document sends at most one request every 2.5 s.

A request is authenticated outside the document queue and charged against the
received bounds and its sender's share, never the local operation budget, so
requests from outsiders cannot hold up local edits. A fresh request no newer
than the member's last is refused before its signature is checked.

A current member that authenticates the request resends, on the topic, the
exact encrypted frames it retains after each of the requester's heads. It
does so only when it holds the complete suffix, its own frame at that head has
the same hash, and the requester does not already hold the frame. The author
resends its own frames at once. Other members wait in roster order, 200 ms
apart (at most 1.6 s), and skip frames another member or they themselves
resent in the meantime. Each replica
answers a member at most once every 2 s. One answer is at most 64 frames and
4 MiB, and all answers share a budget of 64 frames, refilled at 32 per second.
Resent frames are ordinary frames: receivers admit them through the full path,
and duplicates are no-ops. A requester further behind than the retained 64
frames per author, or behind a restarted peer, still needs the controller
checkpoint. Requests and resends are visible on the topic as traffic.

The WAL holds at most 128 accepted entries and 128 MiB. It periodically replaces
older entries with a native CRDT snapshot and complete replay receipts. Local
snapshots are bounded to 64 MiB. IndexedDB stores head metadata, accepted entries,
pending entries and publications separately. Routine commits read no checkpoint
bytes and write the new delta, rather than rewriting the document's history.
Each entry stores its permission-history head. The full signed history is copied
only at checkpoints or after the accepted authority lease changes. To provision
the authority on restart, restore the latest nonempty `authorityRecords` from the
decrypted journal using the independently pinned genesis, then configure the
coordinator and document with that verified log.
Writable transactions request strict durability and resolve on completion.
Recovery validates the contiguous retained revision index before requesting
entry rows. IndexedDB copies reserve against the declared retained-byte budget;
pending and publication rows must match their indexed sizes before copying.
The built-in IndexedDB recovery capability reads accepted entries and only a
pending discard token from head metadata. It avoids pending bodies entirely and
reads each publication payload once after accepted-state and anchor validation.
Missing or corrupt unaccepted pending bodies are discarded without replaying
them. The full diagnostic snapshot API still loads its requested bodies. Other
backends can provide the optional recovery capability or their full snapshots.
The checked read plan bounds successful recovery to 147 journal row gets;
anchor-provider I/O, writes, browser internals and crypto costs are excluded.
Authenticated replay reuses detached captured entries instead of making another
outer copy. These checks bound owned ciphertext copies, not IndexedDB's internal
structured cloning, decoder buffers or total browser heap use.

The publication outbox has at most 16 publications/16 MiB and survives restart
with the journal. A publication is one or more concatenated signed frames of at
most 1 MiB and 1,024 frames. After a publication failure,
`retrySecurityPublications()` retries the exact ciphertext without rerunning the
change callback. A pubsub publication that reaches at least one topic peer
removes it from the outbox; this is transport handoff, **not** a durable peer
receipt. A publication that reports no topic recipients, as GossipSub does
while no peer has joined the topic, stays in the outbox with every later one.
Each new local frame is appended to the last queued publication while it fits
in a replacement publication, which replaces the superseded one in the commit
that accepts the frame. Local edits leave one of the journal's 16 rows free for
re-signing a retired outbox, so offline editing continues until 15
publications, about 15 MiB of
unsent ciphertext, are queued. Whether a frame fits is decided by its actual
size, and the outbox is read only when its tail is unknown, such as after a
restart or a delivery. Beyond that bound, a change fails before visible commit
with `DocumentPublicationBacklogError`, a `DocumentJournalCapacityError`.
The
document retries publications in order when it opens, when a peer subscribes
to the topic, after the next change, or on `retrySecurityPublications()`, which
reports how many publications it sent, whether any stay queued and how many
frames it dropped. While GossipSub reports no topic subscriber, a retry does
not read or send the outbox. A publication sealed for an earlier group context
or authority head would be rejected by every current member, so a retry never
sends it. It stays queued while its author can still re-sign one of its frames
into the current context; otherwise the retry removes it and counts its frames
as dropped, and those changes stay local. Every drop,
including one in a background retry after a change, at open or on a
subscription, is passed to the `onPublicationsDropped` security option, or
logged as a warning when the application sets none.
Outbox availability is not protected by the replay rollback anchor. Without a journal, receipts and the bounded outbox are process-local.
Outbox reads and acknowledgments run through the document queue; publication
cannot observe an accepted store record before its anchor decision completes.
Concurrent retry calls coalesce behind the active publication batch.
Staged storage contains only a publication hash and size reservation. The
network-ready frame stays in private memory until admission succeeds, then the
journal seals it with the device key under a separate publication domain bound
to its document, genesis, accepted revision, frame hash and a random publication token. That token must occur in the authenticated accepted journal branch. Checkpoints preserve tokens for the pending outbox; an aborted transaction cannot authorize a publication when a revision is reused. Every recovered
publication is authenticated independently of retained history, including after
checkpoint pruning. Storage can suppress or replay previously accepted outbox
records; it cannot turn a rejected preparation into a publishable frame.

The journal builds a detached candidate for publication-token changes and installs
it only after verifying the durable anchor. A failed attempt retains the prior
ledger; checkpoint projection keeps exactly the pending tokens and their original
revisions. Recovery rejects duplicate, future, stale-delta and over-budget binding
records. The retained ledger is bounded to 144 tokens and a checkpoint retains at
most 16 pending tokens, independent of total historical writes.

## Evidence and remaining boundaries

The [formal manifest](../verification/formal/manifest.json) proves admission
phases/budgets, exact sequence/replay/parent/role decisions, epoch advancement,
and journal recovery decisions. Inductive finite-history lemmas establish
monotone accepted prefixes, anchor recovery and publication-token provenance over
arbitrary finite histories. Actual token-map insertion, checkpoint projection and
candidate selection are production functions compiled into these proofs. Native
Map aliasing remains outside the immutable-map model and has explicit property
calibration. Hash equality, signature
verification and context equality are validated runtime inputs to those
policies; the proofs do not establish cryptographic unforgeability or secrecy.

Seeded properties exercise staging, escaped references, wire boundaries,
role/controller histories, queue saturation, native crypto, restart histories,
checkpoint receipts, transaction faults, forged acceptance markers, rollback,
eviction and outbox recovery. Mixed storage-fault histories combine accepted,
aborted and ambiguous writes, acknowledgments, restarts and hostile retained
publications against both the memory and IndexedDB stores.
The IndexedDB cost check places a 2 MiB checkpoint, commits ten small deltas,
and requires zero checkpoint reads and less than 32 KiB of new entry writes.
This is an I/O cost assertion, not a browser latency guarantee.
A second check builds more than 90 KiB of valid signed role history and requires
ten small edits through `CoordinatedDocument` to write less than 32 KiB without
exporting that history again.

The [native MLS suite](../verification/mls-provider/README.md) exercises actual
`Peerborne.doc`, `PeerborneDocument`, Automerge and Yjs, MLS exporters, Ed25519,
AES-GCM and native Chromium IndexedDB. Its pubsub delivery is a deterministic
simulation, not WebRTC or cross-NAT evidence. It checks concurrent author
convergence, batched changes, malformed ciphertext, legacy bypass rejection,
checkpoint reconstruction, durable replay and publication retry.

Redelivery beyond the retained window and epoch-fork reconciliation remain
future work. The controller
checkpoint is an explicit application-relayed recovery path for current
members. A frame under an unknown or stale epoch is rejected. A frame that is
missing its author prefix or native causal context is held only within the
bounds above. The caller must arrange ordered control/role delivery
and content recovery. Role records contain public identities and the document
path; applications must protect that separate control transport. The content
frame header guarantee does not cover application control signaling. This mode does not yet replace default document workflows.
Neither the proof nor these tests establishes 16 ms main-thread execution,
worker offload, 50-peer topology scaling, forward secrecy, post-compromise
security, secure physical erasure, or recovery after loss of both journal and
independent anchor. Peerborne remains alpha software.
