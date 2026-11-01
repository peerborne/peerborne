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

The new content format uses 32-byte member IDs. A roster has at most 256 unique
member IDs and canonical public keys, and exactly one controller. Controllers
can write and sign role transitions; writers can change document content;
readers cannot author accepted mutations. The separate signed role log holds
permissions: writing a property named `role` in user data cannot change it.
Field-level permissions inside application data are not enforced by this mode.

Applications provision and validate the actual cryptographic group membership.
The role log does not independently enumerate the provider's decrypting members.
Removing a reader therefore requires the real group removal/key transition as
well as the signed role update. A role change alone cannot erase keys or
plaintext already learned by a member.

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

## Evidence and remaining boundaries

The [formal manifest](../verification/formal/manifest.json) proves admission
phases/budgets, exact sequence/replay/parent/role decisions, epoch advancement,
and journal recovery decisions. Inductive finite-history lemmas establish
monotone accepted prefixes and anchor recovery. Hash equality, signature
verification and context equality are validated runtime inputs to those
policies; the proofs do not establish cryptographic unforgeability or secrecy.

Seeded properties exercise staging, escaped references, wire boundaries,
role/controller histories, queue saturation, native crypto, restart histories,
checkpoint receipts, transaction faults, forged acceptance markers, rollback,
eviction and outbox recovery.
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
