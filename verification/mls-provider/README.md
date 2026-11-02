# Experimental MLS provider

This is the next implementation step for
[#186](https://github.com/peerborne/peerborne/issues/186). It keeps a real RFC
9420 implementation behind an authenticated adapter and Peerborne's encrypted
state envelopes. It is an isolated verification project, not a selected runtime
dependency or a `PeerborneDocument` security mode.

```sh
yarn install --immutable
yarn build
yarn verify:mls-provider:setup
yarn verify:mls-provider:typecheck
yarn exec playwright install chromium
yarn verify:mls-provider
```

Setup installs the separate immutable Yarn toolchain and downloads a pinned
MLS Working Group vector file. The source revision and SHA-256 are checked
before generating the ignored local vector fixture. Linux also needs
Playwright's Chromium system dependencies.

The runner checks native Node Web Crypto, then builds a production Vite fixture
and runs the same checks in an isolated Chromium process under a script CSP.
It writes only result/size/runtime metadata to an ignored `report.json`.
Private state, credentials, keys, and message contents are not reported. The
fixture bundle and downloaded reference data stay ignored; CI uploads only the
result report. There are no external collaboration services or production
application data in these checks.

## Implementation

`MlsProviderSpike` provides:

- Mandatory application credential authentication, with no permissive default.
  The caller binds a device/member identity, its MLS signature key, and the
  application's credential. Tests pin those bindings explicitly. A fixed
  controller identity is configured locally, never elected from incoming data.
- One-time KeyPackages whose signed credential binds the document group,
  member, and request commitment. Package and leaf signatures, lifetime,
  reference, group binding, and application policy are checked before use.
- Stable encrypted pending-package exports, import with private/public key
  verification, encrypted group-state recovery, and local consumed-reference
  markers using Peerborne's existing envelope/protector classes.
- Serialized lifecycle operations, bounded input snapshots, strict framed
  state decoding, canonical MLS-state re-encoding, public-tree validation, and
  private HPKE/signature key checks before state adoption. Failed operations
  leave accepted group state unchanged.
- Controller-authenticated Add/Remove and self-updates, with applied changes
  checked against the resulting verified roster. A self-update rotates keys
  without inventing a membership delta. A removed recipient becomes terminal
  and erases its local state instead of claiming the next epoch's secrets.
- Exporter convergence, zero old-epoch/generation retention, obsolete private
  path cleanup after tree contraction, and encrypted reconstruction of a fresh
  provider instance.

Input framing and local envelopes are experimental formats scoped to this
spike. No old formats or compatibility paths are introduced. Raw private state
remains internal; callers receive public state, protocol messages, or encrypted
envelopes. Exporter-derived material is returned only through the explicit
exporter API and is not persisted or logged by this project.

## Explicit upstream patch

The original unmodified `ts-mls` 1.6.4 rejection remains reproducible with
`yarn verify:mls-candidate`. This project uses a separate, checked-in Yarn patch:

1. Return the computed retained-epoch map and actual deletion list, including
   expired sender-data/resumption material. This fixes the zero-limit slice and
   discarded deletion-list failures.
2. Start the secret-tree deletion collection as an empty array. The upstream
   preallocated array followed by `push` introduced holes that became missing
   entries when the collection was spread into the consumed list.

The adapter also erases private path entries that no longer have a public tree
node after a successful native transition. Restored checkpoints with invalid
paths are rejected. Retained paths are checked against their public HPKE keys.
No TreeKEM, key schedule, signature, KEM, or application cipher is reimplemented.
The report identifies the exact patch hash; patched success does not select or
certify the unmodified stable release.

## Evidence and remaining work

Both environments exercise encrypted pending-package and group-state recovery,
stable exports, pinned credential/controller enforcement, authenticated adds,
self-update key changes, exporter convergence, revocation/removal, tampered and
replayed Commits, malformed wire input, caller-input mutation, corrupt
ciphertext, substituted public commitments, and malformed private-key recovery.
The original delayed-message retention test must now reject the old message.

The same patched dependency also passes 13 suite-1 MLS Working Group
passive-client cases, including 26 received Commit transitions per runtime.
Those reference cases use their fixture-required library credential/retention
policy; the adapter's strict application policy and zero retention are tested
separately. This covers pinned reference data, not live interoperability with
another implementation or every RFC vector family.

Fresh-provider reconstruction in one process is not a browser/process restart,
crash-consistent persistence, a persistent keystore, or rollback resistance.
The local consumed markers do not replace the coordinator's durable tombstones
or an independent monotonic anchor, including before the first group join.

The envelope/coordinator now preserves RFC 9420's empty epoch-zero confirmed
transcript through encrypted persistence and signed genesis restoration.
Post-genesis transcripts and every public tree hash remain nonempty. Native
Node/Chromium checks include fresh-provider reconstruction at epoch zero.

The coordinator accepts an empty membership delta only for an authenticated
self-update whose actor is its subject, with no Welcome and an advance of one
epoch plus both public commitments. Its admission predicate has a checked
formal contract. Node/Chromium integration also exercises signed genesis,
encrypted pending-package join, Add, self-update, exporter rotation and
convergence, replay, and encrypted checkpoint restoration through the real
coordinator. This fixture uses the test JSON codec and in-memory stores/anchors;
it does not exercise network delivery or durable browser storage.

The fixture also exercises `runDocumentOperation` with real exporter-derived
AES-GCM keys and Ed25519 signatures. A test-only envelope binds a document ID,
operation kind, causal-parent list and full group/control context. It rejects
cross-document replay using the same key, a reader signing as a writer, and
tampering. Revoking the pinned credential after preparation rejects the
operation even without a group rekey. Controlled waits prove that rekey and authenticated removal can
complete during content preparation, invalidate its finalizer, and permit a
fresh-context retry after rekey. This pins the controller as the fixture's only
writer; it is not a runtime role engine or a selected document wire protocol.
The report records source and built-artifact hashes and rejects source drift
during a run.

A removed member cannot derive the next epoch's private secrets or verify its
confirmation tag. The adapter reports an authenticated removal and applied
membership delta without inventing next-epoch public/private state. The
coordinator checks the exact signed local-member removal, requires the provider
to have erased its active group, and writes an irreversible removal marker to
the independent rollback-anchor contract. It stops further operations and
rejects reconstruction before reading the older store or importing private
state. Failed/no-op marker writes never acknowledge success or reload the
removed provider's checkpoint. The marker's exact-parent/next-epoch admission
has a formal contract; races, malformed input, and marker readback are checked.

Native Node/Chromium tests remove the joined member through the real
coordinator, reject its exporter, and block its retained older encrypted
checkpoint before import. These remain same-process checks using reference
stores/anchors. The old ciphertext remains in the rollbackable store; persistent
keystore rotation, obsolete ciphertext deletion, and an independently protected
durable anchor backend still need qualification. This is not a secure-erasure
or browser-restart forward-secrecy claim.

Runtime ACL/control-chain authority, verified document-load commitments,
transactional durable delivery/ACKs, independent rollback protection,
partition/rejoin, full resource budgets, and independent security review also
remain required. This project does not complete #186 or establish Peerborne
forward-secrecy or production-readiness claims.


## Production document path

The suite also runs `document-tests.ts` in Node and Chromium. It creates real
`Peerborne`/`PeerborneDocument` instances in coordinated mode and uses native
Automerge and Yjs, MLS exporters, Ed25519 and AES-GCM. Chromium uses the actual
IndexedDB journal driver; Node uses its memory reference store. Pubsub delivery
is an explicit deterministic simulation. Neither result is WebRTC/NAT evidence.

The checks cover concurrent author convergence, a composed change transaction,
mandatory signatures despite the legacy signing toggle, malformed ciphertext,
legacy load/ACL/sync rejection, more than 128 accepted deltas, checkpoint
reconstruction, replay floors and failed-publication retry across document
reconstruction. Production source and built-module hashes are recorded with
the evidence. The test page allows `wasm-unsafe-eval` for Automerge's native Wasm;
its CSP still prohibits external scripts and connections.

See [coordinated document security](../../docs/coordinated-document-security.md)
for setup, formal/runtime boundaries and the remaining content recovery,
physical storage, crypto and performance qualification work.
