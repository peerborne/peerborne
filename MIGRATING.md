# Migrating to Peerborne

The project previously used the Swarmbase product name and a mix of
`@swarmbase/*` and `Collabswarm*` API names. The public surface is now
Peerborne. The library packages were never published to npm, so the rename is a
clean source-level break rather than a registry migration.

## Repository move

The canonical repository is now `https://github.com/Peerborne/peerborne`.
Update an existing clone with:

```sh
git remote set-url origin git@github.com:Peerborne/peerborne.git
```

## Package map

| Previous package | Peerborne package |
| --- | --- |
| `@swarmbase/collabswarm` | `@peerborne/core` |
| `@swarmbase/collabswarm-automerge` | `@peerborne/automerge` |
| `@swarmbase/collabswarm-yjs` | `@peerborne/yjs` |
| `@swarmbase/collabswarm-react` | `@peerborne/react` |
| `@swarmbase/collabswarm-redux` | `@peerborne/redux` |
| `@swarmbase/collabswarm-index` | `@peerborne/index` |

The matching workspace directories are `packages/core`, `packages/automerge`,
`packages/yjs`, `packages/react`, `packages/redux`, and `packages/index`.

## API map

| Previous API | Peerborne API |
| --- | --- |
| `Collabswarm` | `Peerborne` |
| `CollabswarmConfig` | `PeerborneConfig` |
| `CollabswarmDocument` | `PeerborneDocument` |
| `CollabswarmNode` | `PeerborneNode` |
| `CollabswarmPeersHandler` | `PeerbornePeersHandler` |
| `CollabswarmDocumentChangeHandler` | `PeerborneDocumentChangeHandler` |
| `AutomergeSwarmDocumentChangeHandler` | `AutomergeDocumentChangeHandler` |
| `YjsSwarmDocumentChangeHandler` | `YjsDocumentChangeHandler` |
| `useCollabswarm*` | `usePeerborne*` |
| `CollabswarmContext*` | `PeerborneContext*` |
| `CollabswarmActions` | `PeerborneActions` |
| `CollabswarmState` | `PeerborneState` |
| `CollabswarmDocumentState` | `PeerborneDocumentState` |
| `collabswarmReducer` | `peerborneReducer` |
| `CollabswarmIndexIntegration` | `PeerborneIndexIntegration` |

The Automerge and Yjs daemon commands are now `peerborne-automerge-d` and
`peerborne-yjs-d`. No deprecated source aliases are exported.

## Compatibility identifiers that did not change

Branding must not change bytes that existing peers or stored data depend on.
Peerborne therefore retains these historical identifiers:

- libp2p protocol IDs under `/collabswarm/*`
- the `collabswarm-doc-key-v1` HKDF domain-separation label
- the `swarmdb-epoch-v1` epoch label and existing `swarmdb` discovery topics
- the `/collabswarm-blocks` and `/collabswarm-data` IndexedDB locations
- the `collabswarm-index` default index database name
- the `COLLABSWARM_*` Redux action string values

These strings are protocol and persistence boundaries, not current product or
API names. Changing one requires an explicitly versioned dual-read/dual-protocol
migration and focused compatibility tests.

## Configuration snapshot semantics

`Peerborne.initialize()` now validates and captures an effective security
policy. Mutating the object passed to `initialize()` afterward no longer changes
the live signing, initial-load, quorum, trust-resolver, or document-creation
policy. The public `Peerborne.config` getter likewise no longer exposes that
original object: it returns a detached, top-level-frozen view of the effective
configuration, including normalization of options that cannot apply under the
selected policy.

Code that relied on reference equality, mutated `peerborne.config`, or changed
the original configuration object after initialization must instead construct
the complete desired configuration before calling `initialize()`. Treat the
getter as read-only diagnostics; create and initialize a new `Peerborne`
instance to apply a different policy.

## BeeKEM v1 compatibility

Generation-less BeeKEM PathUpdate v1 reception is disabled by default. Setting
`allowInsecureLegacyBeeKEMPathUpdateV1: true` is an explicitly insecure
compatibility mode, not an upgrade protocol: PathUpdate v1 lacks v2 generation,
parent-tree, and replay binding. Current membership operations still send v2
without downgrade. Do not enable this option for a normal deployment. A safe
transition requires an authorized writer that retains the current ratchet state
and each affected member's local identity/KEM binding to perform authenticated
removal and rejoin; otherwise create a fresh group/document. A standalone
Welcome is not a recovery or migration mechanism. After every member has moved
to v2, create a new instance with
`allowInsecureLegacyBeeKEMPathUpdateV1: false` (or omit the option) so v1
PathUpdates are rejected again.

## Deferred change block size limits

Stored deferred change blocks now have symmetric write/read limits: at most
16 MiB of serialized change bytes and at most 16 MiB plus 64 KiB after document
encryption and framing. A custom `AuthProvider` must keep its ciphertext,
key-ID, nonce, and authentication overhead within that allowance. Each remote
initial-load or invitation catch-up candidate also bounds all deferred blocks
to 16 MiB decoded and 32 MiB encrypted. Its prefetch uses at most eight
concurrent streams, while decrypt/apply is sequential so custom decryption
cannot exceed the aggregate plaintext budget through concurrent expansion.
The fetch deadline is cooperative: a custom Helia blockstore must honor the
provided `AbortSignal`. A blockstore that ignores cancellation can leave its
read pending beyond that deadline, although no later decrypt/apply mutation is
allowed after the budget expires.

Previously written blocks above either per-block limit are no longer readable
by this source generation. Before upgrading, use the older source and an
application-specific migration to split or compact that state, or start a fresh
document. Peerborne does not provide an automatic persisted-block migration.

## Encrypted key-ID width

The unpublished alpha source previously used 16-byte, UUID-formatted document
key IDs. Current Yjs and Automerge keychains use 32-byte, lowercase-hex IDs so
random document keys and full BeeKEM epoch identifiers share one fixed width.
This was a source-level wire and persistence break: encrypted blocks, pubsub
messages, direct key updates, and stored keychains created on opposite sides of
the change cannot be decoded together.

There is no dual-width decoder or persisted-state migration. Every peer and
stored replica in a test deployment must use the same source generation. Before
upgrading an older deployment, discard its old encrypted state and create a
fresh authenticated document/group, or implement and separately review an
explicit application migration. An ordinary document load or BeeKEM Welcome is
not a safe cross-width migration mechanism.
