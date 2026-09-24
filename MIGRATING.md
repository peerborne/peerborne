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

The current document GossipSub prefix is `/peerborne/document/v3/`; the
publish-notification topic is `/peerborne/documents/v3`. Peerborne has no
existing users requiring old-topic compatibility. Relays allow these current
defaults and reject the earlier `/document/` and `/documents` defaults.

Every peer must use the same runtime and topic configuration. To use a custom
document prefix, add its slash-terminated namespace to every relay's
`TOPIC_ALLOWLIST`; a custom notification topic must match
`DOCUMENT_PUBLISH_PATH`, `EXTRA_TOPICS`, or an exact allowlist entry. An empty
prefix requires allowing each concrete document topic or explicitly selecting
unrestricted `*` mode. Custom topics do not negotiate alternate wire formats.

Topic names are public routing labels, not authentication or an authorization
boundary. Signatures, wire decoding, and admission checks remain required.
Stored document IDs and application routes such as `/document/:id` are separate
from the pubsub namespace.

## Context-bound sync-message signatures

Every admitted `CRDTSyncMessage` now carries an exact `signatureContext` tag.
For authenticated handlers, the tag remains in the signature-stripped
serialization, so the writer signature binds otherwise identical bytes to one
receiving operation, such as ordinary sync, a load response, an invitation
bootstrap, or a BeeKEM control message. Receivers derive the expected tag from
the handler and reject missing or different tags before signature
verification; there is no legacy retry. Direct callers of
`PeerborneDocument.sync()` must set `signatureContext: 'ordinary-sync-v1'`.
Custom `SyncMessageSerializer` implementations must encode and decode
`signatureContext` unchanged in its original field position; a serializer that
drops it causes every inbound message to be rejected.

This is an intentional alpha wire break. Stop writers, upgrade every peer that
shares a document, and use an isolated versioned GossipSub prefix while
upgrading. Do not treat mixed-version rejection as a migration boundary:
legacy serializers can discard the unknown tag, and legacy receivers can
accept some messages whenever application verification is bypassed. That
includes signing-disabled traffic, first-load bootstrap paths that do not yet
have trusted writer keys, and unauthenticated document-publish notifications.
Mandatory membership-control paths and post-load verified paths reject mixed
versions, but the exact behavior is route-dependent. Coordinate upgrades of
direct peers instead of relying on protocol negotiation. Stored document IDs,
CRDT state, and keychain entries are unchanged.

## UCAN ACL identity codecs

`UCANACL` and `UCANACLProvider` now take a third `deserializePublicKey`
argument, and it is required whenever identities are objects or functions,
such as `CryptoKey`. Without it, every membership, capability, listing, and
entry operation on such an identity rejects. The deserializer must return a
detached identity whose `serializePublicKey` encoding matches its input:

```ts
import { UCANACLProvider } from '@peerborne/core';
import { YjsACLProvider, deserializeKey, serializeKey } from '@peerborne/yjs';

new UCANACLProvider(
  new YjsACLProvider(),
  serializeKey,
  deserializeKey({ name: 'ECDSA', namedCurve: 'P-384' }, ['verify']),
);
```

Primitive identities such as strings still work with the two-argument form.

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
