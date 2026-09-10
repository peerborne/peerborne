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

## Document GossipSub v3 namespaces

The default document GossipSub prefix changed from `/document/` to
`/peerborne/document/v3/`. This is an intentional alpha network break that
keeps default-configured older peers that use incompatible document envelopes
on a separate topic. The default publish-notification topic likewise changed
from `/documents` to `/peerborne/documents/v3` because it carries the evolving
sync-message envelope used by custom pinning integrations.

Relays admit `/peerborne/document/v3/`, `/peerborne/documents/v3`, legacy
`/document/`, and legacy `/documents` by default during migration. These are
separate GossipSub topics: the relay does not translate, mirror, or bridge
messages between them. Allowing both generations lets separately coordinated
fleets use one relay; it does not make old and new peers compatible.

Before upgrading a deployment:

1. Stop writers or otherwise coordinate the whole document fleet.
2. Upgrade every application peer and relay that serves the deployment.
3. Use the new default, or assign a fresh versioned custom prefix.
4. When using a custom prefix, add it to each relay's `TOPIC_ALLOWLIST`. When
   also customizing `pubsubDocumentPublishPath`, set the relay's
   `DOCUMENT_PUBLISH_PATH` to the same value, list it in `EXTRA_TOPICS`, or add
   it to `TOPIC_ALLOWLIST`.
5. Resume writers only after all participating peers use the same runtime and
   topics.

Custom prefixes, including the empty prefix and an explicitly retained
`/document/`, can place incompatible peers on the same topic. Mixed runtime
versions on one custom or unversioned prefix are unsupported. Do not bridge the
old and new document topics.

GossipSub topic names are public routing labels, not authenticated version
negotiation or an authorization boundary. A peer can explicitly subscribe or
publish outside its defaults, so V3 wire decoding, signatures, and admission
checks remain the security boundary.

This change does not alter stored document IDs or application routes such as
the wiki's `/document/:id` URL. Explicitly configured legacy document and
announcement topics remain available only for separately coordinated legacy
fleets.

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
