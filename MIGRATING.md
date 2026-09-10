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

## Document GossipSub v3 namespace

The default document GossipSub prefix changed from `/document/` to
`/peerborne/document/v3/`. This is an intentional alpha network break that
keeps predecessor-bound membership transitions away from older peers that use
incompatible document envelopes on the unversioned topic.

Relays admit `/peerborne/document/v3/`, legacy `/document/`, and the
`/documents` publish-notification namespace by default during migration. These
are separate GossipSub topics: the relay does not translate, mirror, or bridge
messages between them. Allowing both document prefixes lets separately
coordinated fleets use one relay; it does not make old and new peers compatible.

Before upgrading a deployment:

1. Stop writers or otherwise coordinate the whole document fleet.
2. Upgrade every peer that shares a document topic.
3. Use the new default, or assign a fresh versioned custom prefix.
4. Resume writers only after all participating peers use the same runtime and
   prefix.

Custom prefixes, including the empty prefix and an explicitly retained
`/document/`, can place incompatible peers on the same topic. Mixed runtime
versions on one custom or unversioned prefix are unsupported. Do not bridge the
old and new document topics.

This change does not alter stored document IDs, the `/documents` announcement
topic, or application routes such as the wiki's `/document/:id` URL.

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
