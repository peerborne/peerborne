---
title: "ADR 0001: MLS document security architecture"
description: Proposed control-plane, persistence, key-derivation, compatibility, and acceptance architecture for MLS-secured Peerborne documents.
---

- Status: Proposed
- Date: 2026-08-21
- Tracks: [issue #186](https://github.com/Peerborne/peerborne/issues/186)
- Follow-up evaluation: [ADR 0002](../0002-mls-implementation-dependency/)

## Context

Peerborne currently combines CRDT ACLs, a hash-linked `ACLChain` primitive,
BeeKEM tree state, epoch document keys, encrypted Welcome messages, and an
initial-load quorum. Those components have useful focused tests, but they are
not one authenticated, durable membership state machine. BeeKEM state is
memory-only, membership delivery is best-effort, the ACL chain is not the
runtime authority, and the legacy quorum commits only to the content frontier.
Recent BeeKEM transaction helpers can restore in-memory tree/generation state
after selected operation failures, but they do not persist the accepted
generation/replay anchor or roll ACL, keychain, and network effects back as one
restart-safe transaction.

Issue #186 proposes Messaging Layer Security (MLS), forward secrecy, an ACL
chain of trust, and zero-knowledge proofs. MLS supplies authenticated
asynchronous group-key establishment, but identity, authorization, delivery,
persistence, and concurrent Commit policy remain application responsibilities.
[RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html) defines MLS and
[RFC 9750](https://www.rfc-editor.org/rfc/rfc9750.html) describes those
application responsibilities.

This record defines the target architecture. It is not evidence that MLS is
implemented. Peerborne remains alpha software and must not advertise MLS,
forward secrecy, or post-compromise security until the integrated acceptance
gates pass.

## Decision

### One group per document

Every `mls-v1` document has one group whose random 32-byte group ID is bound to
the document ID in a signed genesis record. Reusing a group across documents is
forbidden because it couples membership and compromise domains.

The group contains every authorized reader or writer client:

```text
group members = reader clients ∪ writer clients
```

A member is a client/device, not an abstract user. An application maps users to
one or more credentials and removes every affected device on revocation. Group
membership grants decryption; the materialized role state determines who may
write content or membership transactions. An identity with neither role must
not remain in the group.

For an MLS document, the CRDT ACL is a cache of the validated control log, not
an independent authority. Direct ACL mutations are invalid, and separate ACL
and group-control heads must not be allowed to diverge.

### Trust root and mandatory authentication

The immutable genesis contains at least:

- security mode and format version (`mls-v1`);
- document ID, group ID, protocol version, and cipher suite;
- founder identity, client ID, credential fingerprint, and signing key;
- initial controller client ID and history-retention policy; and
- a founder signature over a deterministic encoding.

Its identity is:

```text
SHA-256("peerborne/mls-genesis/v1\0" || deterministicDagCbor(payload))
```

The genesis hash is the initial control head. A recipient accepts it only via
an authenticated invitation, an out-of-band fingerprint, or equivalent
application policy. State fetched from an untrusted peer is never a trust root.

The provider authentication adapter binds each protocol credential and
signature key to an application identity and client ID. Unknown, malformed,
expired, revoked, or changed bindings fail closed during create, join, Add,
Update, restored-state validation, and tree revalidation. There is no
accept-all default or empty-writer first-load exception. The first version
permits invitation joins only; external commits and external senders require a
later design.

### Serialized membership control

Document content remains a multi-writer CRDT. Membership and role changes are
serialized by one controller per epoch. Only the current controller may author
the next record. Each accepted transaction advances the group by exactly one
epoch. Add/remove records carry matching group proposals; a role-only change
uses a self-update so its authorization boundary also receives a fresh epoch.
That role-only rule is part of the target MLS integration. The current
protocol-neutral coordinator accepts exactly one provider-applied
cryptographic add/remove/update and deliberately rejects a role-only control
with no applied membership delta.

This prevents honest peers from creating competing Commits. Two valid-looking
children of the same control head are a security fork: clients stop accepting
new control and content state instead of choosing by arrival time, timestamp,
or lexical hash. Controller loss is an availability failure, not permission to
elect one from untrusted network state.

After both same-parent siblings authenticate and authorize, the current
coordinator first writes a terminal poison marker through the separately
protected rollback-anchor contract. The marker commits the fork epoch, parent,
sibling IDs, and a canonical evidence hash; the rollbackable store receives a
best-effort copy of the full audit evidence afterward. Reconstruction rejects
the terminal marker before loading the store or importing provider state.
Focused tests share the in-memory anchor across reconstructed coordinators and
therefore demonstrate only same-process fail-stop behavior; durable restart
protection requires an application-supplied persistent monotonic backend.

### Signed, versioned, hash-linked records

Control records use deterministic DAG-CBOR and strict resource bounds. Unknown
required fields, duplicate map keys, non-canonical encodings, unsafe integers,
trailing data, and over-limit values are rejected before expensive checks. A
version-1 payload contains at least:

```text
version
documentId
groupId
sequenceNumber
parentControlHash
oldEpoch
newEpoch
controllerClientId
controllerCredentialFingerprint
membershipDelta
roleDelta
nextControllerClientId
groupCommit
treeHash
confirmedTranscriptHash
welcomeDigests
```

The document, group, old epoch, and parent must match local accepted state;
sequence and epoch advance by one. The actor must be the authorized active
controller. Membership/role deltas must exactly match the Commit and resulting
member set. The controller signs:

```text
SHA-256("peerborne/mls-control/v1\0" || deterministicDagCbor(payload))
```

Protocol verification, controller signature, parent linkage, operation-ID
conflict checks, and all transition invariants succeed before any new state is
visible. Content changes name the exact accepted control head and epoch. After
revocation, delayed content referencing an older head is not merged
automatically: without a trusted timestamp it cannot be distinguished from a
removed writer producing new content under stale authority.

### Transactional encrypted durability

Cryptography is isolated behind `GroupSecurityProvider`; application code does
not reach into a library's secret tree. The target
`DurableGroupStateStore` persists:

- encrypted serialized provider state and public group commitments;
- current signed control record, head, roles, and credential bindings;
- encrypted, group-bound pending KeyPackages and irreversible consumed-
  reference markers, plus bounded replay metadata;
- accepted epoch-key metadata and bounded pending inbound state; and
- a durable outbound message/acknowledgement queue.

Revision, epoch, control head, and a domain-separated SHA-256 commitment to the
complete canonical store snapshot must also advance through a separately
protected monotonic rollback anchor. Normal advances use compare-and-set; an
atomic terminal poison operation serializes against every advance and records
a terminal marker/commitment after sibling authentication, even during
first-anchor publication. Full audit evidence is only the store's subsequent
best-effort copy. The active snapshot commitment covers the encrypted provider
envelope, pending and consumed KeyPackages, outbox, replay, and stored audit
evidence, so same-revision metadata substitution fails closed before provider
import. The anchor must not share the group database's rollback domain. The
repository requires this contract, but its
`InMemoryGroupSecurityRollbackAnchor` is a same-process test reference and is
not rollback-resistant storage.

The private-state envelope is authenticated and encrypted with a device-local
key. Secret state, signing/KEM keys, document keys, and private payloads must
not enter the replicated datastore, logs, exceptions, analytics, or debug
output. At-rest encryption does not protect an unlocked compromised endpoint.

An outbound transition is ordered as follows:

1. Validate authority, roles, credentials, operation identity, and one-time
   KeyPackages without mutating accepted state.
2. Prepare the Commit against a clone/checkpoint.
3. Construct, sign, and locally verify the complete control record.
4. Apply and validate the Commit, resulting members, epoch, tree/transcript
   commitments, and exporter output.
5. Atomically persist encrypted provider state, signed control state, replay
   metadata, and the durable outbox.
6. Publish only after durability. Remove an outbound entry only after an
   explicit acceptance binds its exact control-record ID and complete unique
   Welcome-recipient KeyPackage-reference set, returned after the receiver's
   authenticated validation and durable commit.

Any pre-durability error restores the provider checkpoint. If rollback fails,
the coordinator is poisoned and stops. In the target persistent
implementation, restart recovery revalidates signed control state before the
outbox resumes. That process/browser restart behavior is not currently tested.
Partial or undecryptable state is a hard recovery error; it never silently
creates a group or falls back to BeeKEM.

The repository's protocol-neutral provider, encrypted envelopes, in-memory
transaction store and rollback anchor, and coordinator are implementation
seams and focused test fixtures. The provider/onboarding tests use a fake
protocol provider. They are not an RFC 9420 implementation, live authenticated
receiver protocol, browser-persistent backend, or persistent keystore.

The provider contract returns the credential-authenticated application member
identity for the creator leaf and exposes a read-only operation that validates
and derives a public KeyPackage's application member identity from its
protocol credential. The coordinator compares those results with the genesis,
pending-package, Add/Update, and invitation subjects. It does not infer an
identity by comparing opaque credential bytes itself. Focused mismatch tests
exercise this contract with a fake provider; a real credential authority,
revocation policy, and RFC 9420 binding remain dependency-selection gates.

Pending KeyPackage private state is stored only in an authenticated encrypted
envelope that binds the intended group and complete public KeyPackage. The
store also binds a caller-stable operation ID to a commitment over the exact
member, credential, extension, group, and protocol request. A commit-then-
timeout retry can therefore return the already pending package, while changed
input for that operation fails closed. The provider derives the authenticated
request commitment from the public KeyPackage, preventing a rollbackable store
from remapping one operation to another same-member package. The store can atomically move a pending
package to a bounded irreversible consumed reference while committing joined
group state, so the same reference cannot be made pending again by eviction.
Pending envelopes and request bindings must form a complete bijection, and
invitation consumption re-authenticates that request commitment from the
public package. Because no group rollback anchor exists yet, an attacker who
can roll back the entire pre-group store can still replace one complete valid
pair with an older complete valid pair unless the application provides a
separate monotonic pre-group mechanism.
This defines a provider/storage seam; the fake provider tests do not demonstrate
RFC 9420 KeyPackage generation, HPKE processing, or real onboarding
interoperability.

An onboarding invitation supplies a complete retained control prefix bounded
by configured record count and a 128 MiB canonical-byte ceiling. No
authenticated checkpoint plus suffix format exists yet for histories beyond
those bounds; silently truncating the prefix is not supported.

Tests described as coordinator restoration construct a new provider and
coordinator over the same live in-memory store and rollback-anchor objects.
They show same-process reconstruction and validation ordering, not process
termination, browser restart, crash consistency, or keystore recovery.

All static initialization entry points serialize lifecycle mutation per
provider lifecycle identity. Forwarding wrappers over the same mutable
provider must expose the same stable `lifecycleIdentity` token; otherwise the
provider object itself is the identity. Bootstrap, join, and restore
permanently claim that identity on success; pending-package creation releases
the transient claim only after it finishes. A provider whose cleanup is
unavailable or fails is retired rather than reused. Lifecycle calls made
directly outside the coordinator cannot be serialized by this contract.

Authenticated same-parent siblings, including competing genesis and join
branches, terminally poison the rollback anchor before the store receives its
best-effort audit copy. Proof still requires the signed sibling and its
authorization parent to remain inside the bounded replay window; branches first
observed after that material is pruned cannot be established locally.

The current provider contract reports an explicit applied membership delta on
both Commit creation and application. The coordinator hashes its strict,
domain-separated canonical encoding into the signed control payload, then
checks action, subject member ID, key-package reference, resulting
tree/transcript commitments, Commit bytes, and Welcome set before persistence.
For the supported one-change form, Add requires one Welcome addressed to the
matching key-package reference; Remove and Update require none. A malicious
provider mismatch rolls the provider back and leaves the accepted chain/store
unchanged in focused tests. This does not reconstruct a role cache, integrate
the document ACL, or prove behavior with an RFC 9420 provider.

Ordinary transitions checkpoint and restore provider state on pre-durability
failure. Provider-exported envelopes and checkpoints are first converted to
independent canonical snapshots. Bootstrap and invitation join require an
authoritatively fresh provider and reject an active provider without relying
on whether encrypted-state export happens to succeed. Restore intentionally
permits replacement of an active provider only after obtaining a complete
checkpoint; a failed replacement restores that checkpoint. When no prior
checkpoint exists, the fresh provider must implement secure
`clearGroupState()` or callers must discard it after a reported
`rollback-unavailable` failure. Failed provider state must never be reused as
accepted coordinator state.

### Exporter-derived document keys and honest guarantees

Each accepted epoch derives a 32-byte content key using the RFC 9420 exporter:

```text
label   = "peerborne/document-content-encryption/v1"
context = deterministicDagCbor({ version, documentId, groupId, epoch })
length  = 32
```

The result is imported as AES-256-GCM. Authenticated data binds format,
document, group, epoch, control head, and object kind; each encrypted object
uses a unique nonce. Raw exporter secrets are not persisted or logged.

History policy is immutable in genesis:

- `full_history` retains old content keys and therefore makes no forward-
  secrecy claim for retained ciphertext.
- `current_only` erases an old key only after delayed content is resolved and
  a verified newer snapshot is durable; obsolete ciphertext is then collected.
- `since_invited` retains an explicit bounded suffix and protects only epochs
  whose keys were neither retained nor re-shared.

The current legacy document-load protocol cannot authenticate a
requester-specific invitation boundary, so its `since_invited` response is
fail-closed to the current key only. The explicit bounded suffix above is the
target coordinator policy, not a capability claim for ordinary load.

JavaScript erasure is best-effort and backups/copies are part of the analysis.
After acceptance, the narrow claims are: a removed member cannot derive keys
for post-removal content, and a current-state compromise does not reveal erased
epoch/message secrets. It still reveals current materialized state and every
deliberately retained key. Post-compromise recovery begins only after fresh
entropy from an uncompromised member is accepted and old state is erased.

### Security-bound initial-load quorum

Security-aware peers vote over a domain-separated canonical tuple:

```text
version
documentId
sortedContentFrontier
controlHeadHash
groupId
groupEpoch
treeHash
confirmedTranscriptHash
```

The encoding carries every sorted frontier key/CID directly with unambiguous
lengths. V4 combines that tuple with a canonical manifest of the complete
state-mutating response plan actually advertised and served: root identity,
canonical node CID/kind/directed edges and serialized inline changes, snapshot
content/metadata, and serialized keychain changes. It does not claim to cover
concurrent branches the responder holds but does not serve.

If a CID appears through multiple paths, compatible sparse cross-link
references are reconciled with its canonical full node-and-descendant
description. Multiple full descriptions must match exactly, and kind or
defined key-identity conflicts are rejected independently of which occurrence
is visited first. Explicit node, occurrence, traversed-edge, and aggregate
inline-payload limits bound diamond/shared-subgraph work. This is strict local
manifest evidence, not a live hostile-network acceptance result.

K-of-Q agreement covers the combined digest. In the target architecture, the
loader recomputes the manifest from the selected response, then independently
verifies genesis and required control links/signatures/group transitions before
any mutation. Quorum is an availability/fork signal, not a substitute for
cryptography. An identical
frontier paired with a different control head, epoch, tree closure, snapshot,
or keychain delta is not an agreeing vote.

The loader pins one local tuple and writer-authority set before its first V4
probe. Every advertisement, full-document response, and snapshot candidate
must match that tuple. Votes are deduplicated by the verified writer's canonical
`AuthProvider.serializePublicKey` value, so one credential presented through
many libp2p PeerIds contributes one vote. This relies on that serialization
being deterministic and collision-resistant and on the application pinning
independently controlled writer authorities; distinct compromised authorities
can still collude.

Each V4 load generates one unpredictable 32-byte challenge. The requester signs
the document ID and challenge together; every quorum advertisement and selected
full/snapshot response must echo the exact challenge inside its writer-signed
envelope. Challenge equality is checked before tallying or staging state, so a
recorded advertisement set and matching full response from an older round are
rejected while Web Crypto randomness and signature verification hold. This is
not a timestamp or durable replay ledger, and it does not stop an authorized or
compromised writer from signing stale state again in the current round. Legacy
V3 wire behavior is unchanged.

The current seam requires exact equality with the captured tuple. It cannot
yet authenticate and replay a newer control suffix from an older checkpoint,
so a stale local checkpoint fails closed instead of using quorum state as a
new trust root.

The repository includes versioned V4 load/advertisement codecs, challenge
binding, complete served-response-manifest recomputation, and strict
pinned-writer bootstrap checks. The current runtime compares the remote tuple
to one locally resolved/captured tuple; it does not yet independently replay an
MLS genesis/control suffix or learn a newer security state from peers. Without
an integrated reviewed provider and live hostile-peer tests, this remains
partial evidence only.

Strict mode does not count the legacy unauthenticated `0xff` “unknown
document” sentinel as a vote. Consequently, a client cannot infer that a name
is safe to create merely because connected peers disclaim it. Creation in an
existing swarm needs an application-authorized create decision or a future
authenticated nonexistence protocol; this is an intentional availability
cost of failing closed.

### Versioning and migration

The proposed MLS family uses distinct bounded protocols:

```text
/collabswarm/mls-keypackage/1.0.0
/collabswarm/mls-control/1.0.0
/collabswarm/mls-welcome/1.0.0
/collabswarm/mls-ack/1.0.0
/collabswarm/doc-load/4.0.0
/collabswarm/snapshot-load/4.0.0
/collabswarm/security-advertise/1.0.0
```

Strict security documents do not serve V3 loads or legacy tip advertisements,
and clients never silently downgrade. BeeKEM documents remain explicitly
legacy. Existing documents do not auto-upgrade; migration requires a later
signed out-of-place or ReInit design with rollback and mixed-client behavior.

### Delivery, replay, and recovery

Control records and Welcome envelopes are content-addressed, idempotent, and
retryable. Receivers deduplicate by record identity, verify before ACK, retain
only bounded future/missing-parent queues, reject stale/replayed/skipped/
conflicting state, and stop on same-parent forks. Durable outbox entries are
strictly decoded and their IDs, signatures, linkage, Commit binding, and
Welcome metadata are revalidated before every retry.

Outbox deletion requires an explicit durable-acceptance value whose exact
32-byte control-record ID and complete unique set of Welcome-recipient
KeyPackage references match the delivery. The send callback may return that
value only after authenticated receiver validation and durable persistence;
transport or callback completion alone is insufficient. The focused tests use
a trusted callback and fake provider. No live authenticated ACK wire protocol,
receiver persistence test, or document-runtime integration currently proves
at-least-once delivery end to end.

A member with an authenticated checkpoint can fetch and replay missing records
in order. A member that lost private group state cannot reconstruct it from the
public log; recovery requires a fresh authenticated join or application backup
policy.

## Acceptance gates

MLS is not integrated until automated evidence covers:

1. RFC vectors plus byte-level interoperability with an independent MLS
   implementation.
2. Alice/Bob/Carol create, sequential add, update, remove, convergence, and
   removed-member exclusion across Node and Chromium.
3. Fail-closed credential substitution, revocation, malformed encodings,
   confirmation/signature failure, replay, reordering, and conflicting Commits.
4. Process and browser crash/restart with encrypted IndexedDB state, pending
   and consumed KeyPackages, derived-key metadata, replay state, and outbox
   recovered atomically, plus a separately protected persistent rollback
   anchor and keystore.
5. Publish/send/ACK/store/rollback failure injection at every transition.
6. Live hostile-peer partition/rejoin and fail-closed ACL/control/group fork
   detection.
7. Bounded delayed-message retention and documented erasure limits.
8. Vite/worker/CSP behavior and bundle, latency, memory, wire-size, and stored-
   state budgets for 2, 3, 32, and 256 members.
9. Security-aware quorum peers independently varying every tuple field.
10. Pinned stable dependency, provenance/license/transitive review, upstream
    maintenance evidence, and independent security review before any
    production-readiness claim.

## Consequences

Content remains available under CRDT semantics while membership becomes a
serialized security control plane. This deliberately trades controller loss or
forks for availability rather than choosing an unauthenticated winner.

The work cannot be completed by swapping BeeKEM for one package call.
Dependency selection, provider isolation, authenticated identity, durable
control state/outbox, versioning, quorum binding, migration, recovery, and
adversarial tests are all part of the security boundary.

## References

- [RFC 9420: The Messaging Layer Security Protocol](https://www.rfc-editor.org/rfc/rfc9420.html)
- [RFC 9750: The Messaging Layer Security Architecture](https://www.rfc-editor.org/rfc/rfc9750.html)
- [ADR 0002: MLS implementation dependency](../0002-mls-implementation-dependency/)
- [ADR 0003: Zero-knowledge membership proofs](../0003-zero-knowledge-membership-proofs/)
