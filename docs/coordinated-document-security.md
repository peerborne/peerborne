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

Applications provision and validate the actual cryptographic group membership.
The role log does not independently enumerate the provider's decrypting members.
Removing a reader therefore requires the real group removal/key transition as
well as the signed role update. A role change alone cannot erase keys or
plaintext already learned by a member.

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
invalidates the preparation. The engine checks every
reported target before local signing, WAL staging and CRDT commit. Missing,
unknown or unsupported inspection fails closed for a restricted member.
Permission changes require the existing fresh-epoch signed role transition.

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
application. A direct mutation of the visible Yjs document invalidates its
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

Exact per-author sequence/hash receipts survive restart and compaction. Gaps
and conflicting author heads are rejected; duplicate frames do not mutate or
rebroadcast the document. Receipt state resets at a new authenticated group
context, keeping it bounded by the roster. A signing identity must have one
document author at a time; independent offline branches using the same member
ID are detected as conflicting prefixes rather than merged.

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

The publication outbox has at most 16 frames/16 MiB and survives restart with
the journal. After a publication failure, `retrySecurityPublications()` retries
the exact ciphertext without rerunning the change callback. Capacity exhaustion
rejects a new change before visible commit. A successful pubsub publication
removes that frame from the outbox; this is transport handoff, **not** a durable
peer receipt. Outbox availability is not protected by the replay rollback
anchor. Without a journal, receipts and the bounded outbox are process-local.
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

Automatic anti-entropy, late-join content snapshots, missing-prefix redelivery,
old-epoch edit rebasing and epoch-fork reconciliation remain future work. An
unknown/stale epoch or missing native causal context is rejected, not silently
buffered without a bound. The caller must arrange ordered control/role delivery
and content recovery. Role records contain public identities and the document
path; applications must protect that separate control transport. The content
frame header guarantee does not cover application control signaling. This mode does not yet replace default document workflows.
Neither the proof nor these tests establishes 16 ms main-thread execution,
worker offload, 50-peer topology scaling, forward secrecy, post-compromise
security, secure physical erasure, or recovery after loss of both journal and
independent anchor. Peerborne remains alpha software.
